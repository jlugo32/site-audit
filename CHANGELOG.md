# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
