# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-09-15

Bug-fix release. Focus on real-world false positives and data-loss safety.

### Fixed
- **`--md FILE` no longer destroys the target file.** The report is now built in
  memory and written atomically (temp file + rename) only after a successful
  audit, so a run that aborts (for example, a domain that does not resolve)
  leaves an existing file untouched. The write no longer truncated the file up
  front.
- **`--json` and `--md FILE` now work together.** Both outputs are produced:
  JSON on stdout and the markdown report in the file. Previously the markdown
  file was left empty when `--json` was set. The "Saved markdown report" notice
  now goes to stderr so it never pollutes JSON on stdout.
- **SPF `redirect=` is recognised.** A record such as
  `v=spf1 redirect=icann.org` (as IANA publishes) is reported as a valid
  delegation instead of "present but no `-all`". Uppercase `-ALL` is also
  handled.
- **Security headers survive an apex-to-www redirect.** Headers are read from
  the final page after following one same-site redirect (apex to `www.`, http to
  https), instead of reading the bare 301 and reporting HSTS/CSP/X-Frame-Options
  as missing. Off-site redirects are not trusted.
- **Certificate trust no longer fails open on a timeout.** A `ssl_verify_result`
  of 0 with no completed handshake is reported as "could not verify" rather than
  "trusted".
- **Port scan skips private/loopback A records.** A domain resolving to
  127/8, ::1, RFC 1918, link-local or IPv6 ULA is marked "not testable" instead
  of scanning the local machine or network.
- **Normal customer sign-in pages are no longer flagged.** Only admin-specific
  paths (`/wp-admin`, `/administrator`, `/phpmyadmin`, `/manager`...) count; a
  bare `/login` or `/signin` no longer trips "Admin login pages reachable".
- **Alpine/busybox certificate dates parse correctly.** Added a
  busybox-compatible fallback so `date` that understands neither GNU `-d` nor
  BSD `-j -f` no longer yields a false "could not read certificate". `hostname -I`
  now falls back to `ip addr`/`ifconfig` for the self-host guard.

### Changed
- Certificate verify codes are mapped to human-readable text (self-signed, name
  mismatch, expired, untrusted chain) instead of a raw number.
- An expired certificate is counted once, not twice (was flagged by both the
  validity and the trust check).
- DMARC `p=reject`/`quarantine` with `pct` below 100 is flagged as weakened
  coverage rather than treated as full-strength.
- Empty option values (`--md=`, `--fail-under=`, `--timeout=`) are rejected with
  exit code 2 instead of being silently ignored. A mixed-case scheme
  (`Https://`) is stripped correctly rather than rejected with the wrong reason.
- macOS dependency hint reconciled between the script and the README (Bash 4.4+
  and coreutils' `gtimeout`). Documented that `--timeout` is per request.

## [1.0.0] - 2026-09-15

First public release.

### Added
- External checkup of a domain: A/MX (including RFC 7505 null MX), SPF,
  DKIM on common selectors, DMARC policy and reporting, HTTPS availability and
  http->https redirect, certificate expiry and trust, HSTS, clickjacking
  protection, X-Content-Type-Options, Content-Security-Policy,
  Referrer-Policy, Server/X-Powered-By version leaks, cookie Secure/HttpOnly
  flags, risky open TCP ports, exposed sensitive files, admin login paths,
  WordPress xmlrpc.php and www. consistency.
- Score out of 100 with a letter grade (A-F).
- Three output formats: coloured terminal report, markdown (`--md FILE`,
  `--md -` for stdout) and JSON (`--json`).
- `--fail-under N` for CI pipelines and cron jobs (exit code 1 below N).
- `--no-ports`, `--timeout SEC`, `--color` / `--no-color` (honours `NO_COLOR`),
  `--help`, `--version`.
- Documented exit codes: 0 ok, 1 below threshold, 2 usage, 3 missing
  dependency, 4 domain does not resolve.
- Dependency check with install hints for Debian/Ubuntu, RHEL/Fedora and macOS.
- Strict input validation: URLs with paths, ports, credentials, IP addresses,
  shell metacharacters and non-punycode IDNs are rejected.
- False-positive guards:
  - the scanning machine auditing itself (loopback bypasses the firewall);
  - CDN edges (Cloudflare, CloudFront, Fastly, Akamai, Vercel, Netlify) that
    answer on ports which do not belong to the site;
  - catch-all sites that return 200 for every URL: exposed files and login
    pages must match a content signature, not just a status code;
  - SPF `+all`, multiple SPF records and revoked (empty `p=`) DKIM keys are
    classified correctly.
- Remote values are stripped of control characters before they reach the
  terminal, markdown or JSON output.
- Port probes run in parallel (about 3 s worst case instead of about 75 s).
- Offline test suite (`tests/run.sh`) with fixture-driven audits under
  `set -euo pipefail`, plus an opt-in live smoke test (`LIVE=1`).
- ShellCheck-clean sources and a GitHub Actions workflow.
