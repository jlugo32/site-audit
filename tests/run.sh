#!/usr/bin/env bash
# Offline test suite for site-audit. Plain bash, no framework, no network.
#
#   tests/run.sh           unit + fixture + CLI tests
#   LIVE=1 tests/run.sh    additionally run one live smoke test against example.com
#
# How it works: the script is sourced (its main-guard keeps it from running),
# helpers are unit-tested directly, and the network layer (dns_query, http_*,
# tls_*, probe_port, local_addresses) is replaced with stubs that replay the
# files in tests/fixtures/. Full audits then run under `set -euo pipefail`.

# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317,SC2329  # scenario_* and stub functions are invoked indirectly (SC2317 on shellcheck <0.10, SC2329 on >=0.10)
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$TESTS_DIR")"
FIX="$TESTS_DIR/fixtures"
SCRIPT="$ROOT/site-audit"

# shellcheck source=../site-audit
source "$SCRIPT"

PASS=0; FAIL=0; SKIP=0
if [[ -t 1 ]]; then G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'; else G=""; R=""; Y=""; N=""; fi

section() { printf '\n%s\n' "$1"; }
pass() { PASS=$((PASS + 1)); printf '  %sok%s    %s\n' "$G" "$N" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  %sFAIL%s  %s\n' "$R" "$N" "$1"; [[ -n "${2:-}" ]] && printf '        %s\n' "$2"; }
skip() { SKIP=$((SKIP + 1)); printf '  %sskip%s  %s\n' "$Y" "$N" "$1"; }

assert_eq() {  # expected actual description
  if [[ "$1" == "$2" ]]; then pass "$3"; else fail "$3" "expected [$1] got [$2]"; fi
}
assert_ok()   { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d" "command returned non-zero: $*"; fi; }
assert_fail() { local d="$1"; shift; if "$@"; then fail "$d" "command unexpectedly succeeded: $*"; else pass "$d"; fi; }
assert_contains() {  # haystack needle description
  if [[ "$1" == *"$2"* ]]; then pass "$3"; else fail "$3" "missing [$2]"; fi
}
assert_not_contains() {
  if [[ "$1" != *"$2"* ]]; then pass "$3"; else fail "$3" "unexpected [$2]"; fi
}

# Option globals normally set by parse_args; read by the sourced functions.
# shellcheck disable=SC2034
OPT_TIMEOUT=12; OPT_PORTS=1; OPT_COLOR=never; OPT_JSON=0; OPT_MD=""; OPT_FAIL_UNDER=""

# ------------------------------------------------------------------ unit tests
section "scoring and grades"
assert_eq 100 "$(compute_score 0 0)"  "no findings scores 100"
assert_eq 85  "$(compute_score 1 0)"  "one critical costs 15"
assert_eq 95  "$(compute_score 0 1)"  "one warning costs 5"
assert_eq 55  "$(compute_score 1 6)"  "mixed findings add up"
assert_eq 0   "$(compute_score 9 9)"  "score never goes below 0"
assert_eq A "$(grade_for_score 100)" "100 is A"
assert_eq A "$(grade_for_score 90)"  "90 is A (boundary)"
assert_eq B "$(grade_for_score 89)"  "89 is B"
assert_eq B "$(grade_for_score 75)"  "75 is B (boundary)"
assert_eq C "$(grade_for_score 60)"  "60 is C (boundary)"
assert_eq D "$(grade_for_score 40)"  "40 is D (boundary)"
assert_eq F "$(grade_for_score 39)"  "39 is F"
assert_eq 15 "$(penalty_for CRITICAL)" "critical penalty"
assert_eq 0  "$(penalty_for INFO)"     "info has no penalty"

section "domain validation"
assert_eq example.com     "$(normalize_domain example.com)"                 "bare domain accepted"
assert_eq example.com     "$(normalize_domain https://www.Example.COM/)"    "scheme, www, case and trailing slash normalised"
assert_eq example.com     "$(normalize_domain 'example.com.')"              "trailing root dot removed"
assert_eq shop.example.co.uk "$(normalize_domain shop.example.co.uk)"       "multi-label subdomain accepted"
assert_eq xn--bcher-kva.example "$(normalize_domain xn--bcher-kva.example)" "punycode label accepted"
# shellcheck disable=SC2016  # the literal $(id) is the point of the test
for bad in "https://example.com/admin" "example.com?x=1" "example.com:8080" "user@example.com" \
           "192.0.2.1" "localhost" "exa mple.com" 'example.com;id' '$(id).example.com' \
           "-example.com" "example-.com" "example..com" "bücher.example" ""; do
  assert_fail "rejects [$bad]" normalize_domain "$bad" 2>/dev/null
done

section "integer option parsing"
assert_ok   "75 is within 0-100"  is_int_between 75 0 100
assert_ok   "leading zero is not octal" is_int_between 08 0 100
assert_fail "101 is out of range" is_int_between 101 0 100
assert_fail "text rejected"       is_int_between abc 0 100
assert_fail "negative rejected"   is_int_between -5 0 100

section "SPF parsing"
assert_eq "v=spf1 include:_spf.example.net ip4:192.0.2.10 -all" "$(spf_records <"$FIX/dns-txt-apex.txt")" \
  "split TXT chunks are joined and non-SPF TXT ignored"
assert_eq strict   "$(spf_all_qualifier 'v=spf1 mx -all')"   "-all is strict"
assert_eq soft     "$(spf_all_qualifier 'v=spf1 mx ~all')"   "~all is soft"
assert_eq neutral  "$(spf_all_qualifier 'v=spf1 mx ?all')"   "?all is neutral"
assert_eq pass-all "$(spf_all_qualifier 'v=spf1 +all')"      "+all passes everyone"
assert_eq pass-all "$(spf_all_qualifier 'v=spf1 a all')"     "bare all defaults to +all"
assert_eq none     "$(spf_all_qualifier 'v=spf1 include:x')" "no all mechanism"
assert_eq none     "$(spf_all_qualifier 'v=spf1 include:mall.example.net')" "'all' inside a hostname is not a mechanism"

section "DMARC parsing"
assert_eq reject "$(dmarc_tag 'v=DMARC1; p=reject; rua=mailto:r@example.com' p)" "p= read"
assert_eq none   "$(dmarc_tag 'v=DMARC1; sp=reject; p=none' p)" "sp= does not shadow p="
assert_eq quarantine "$(dmarc_tag 'v=DMARC1;P=Quarantine' p)"   "tags and values are case-insensitive, no spaces needed"
assert_eq ""     "$(dmarc_tag 'v=DMARC1; p=reject' rua)"          "missing tag yields empty"
assert_eq ""     "$(dmarc_tag 'v=DMARC1; p=*; rua=*' pct)"        "glob characters are not expanded"
assert_eq "v=DMARC1; p=reject" "$(printf '"v=DMARC1; " "p=reject"\n' | dmarc_record)" "quoted DMARC TXT is unquoted"

section "DKIM / MX parsing"
assert_eq active  "$(unquote_txt <"$FIX/dns-txt-dkim.txt" | dkim_key_state)" "split DKIM1 key recognised as active"
assert_eq revoked "$(echo 'v=DKIM1; p=' | dkim_key_state)"      "empty p= is a revoked key, not an active one"
assert_eq revoked "$(echo 'v=DKIM1; p=; t=s' | dkim_key_state)" "empty p= followed by more tags is revoked"
assert_eq none    "$(echo 'v=spf1 -all' | dkim_key_state)"      "SPF text is not a DKIM key"
assert_eq none    "$(printf '' | dkim_key_state)"               "no record"
assert_eq null "$(mx_summary '0 .')" "RFC 7505 null MX detected"
assert_eq 2    "$(mx_summary $'10 mx1.example.com.\n20 mx2.example.com.')" "MX records counted"
assert_eq 0    "$(mx_summary '')" "no MX"

section "HTTP header parsing"
H_HARD="$(cat "$FIX/headers-hardened.txt")"; H_WEAK="$(cat "$FIX/headers-weak.txt")"
assert_eq "max-age=31536000; includeSubDomains; preload" "$(header_get "$H_HARD" strict-transport-security)" "header value read"
assert_eq "Apache/2.4.41 (Ubuntu)" "$(header_get "$H_WEAK" SERVER)" "header name is case-insensitive"
assert_eq "" "$(header_get "$H_WEAK" strict-transport-security)" "absent header is empty"
assert_eq "nginx" "$(header_get "$(printf 'Server: nginx\r\n')" server)" "CRLF stripped"
assert_eq "max-age=63072000" "$(last_header_block <"$FIX/headers-redirect-chain.txt" | header_get "$(cat)" strict-transport-security)" \
  "only the final response of a redirect chain is used"
assert_eq Cloudflare "$(detect_cdn "$(cat "$FIX/headers-cloudflare.txt")")" "Cloudflare detected"
assert_eq Cloudflare "$(detect_cdn $'HTTP/2 200\nCF-RAY: abc-IAD')"  "Cloudflare detected via cf-ray alone"
assert_eq CloudFront "$(detect_cdn $'HTTP/2 200\nx-amz-cf-id: abc')" "CloudFront detected"
assert_eq Fastly     "$(detect_cdn $'HTTP/2 200\nx-served-by: cache-iad-1')" "Fastly detected"
assert_eq ""         "$(detect_cdn "$H_HARD")" "plain origin is not a CDN"
assert_ok   "version number detected" has_version_number "Apache/2.4.41"
assert_fail "no version in bare name" has_version_number "nginx"
assert_eq "2 0 0" "$(cookie_flag_counts "$H_HARD")" "hardened cookies all flagged"
assert_eq "3 2 2" "$(cookie_flag_counts "$H_WEAK")" "cookie named secure_token is not counted as Secure"

section "TLS helpers"
assert_eq "SSL Corporation" "$(parse_cert_issuer 'issuer=C=US, O=SSL Corporation, CN=Example TLS Issuing CA')" "issuer organisation (OpenSSL 3 format)"
assert_eq "Let's Encrypt"   "$(parse_cert_issuer "issuer=C = US, O = Let's Encrypt, CN = R11")" "issuer organisation (OpenSSL 1.1 format)"
assert_eq "Self Signed Root" "$(parse_cert_issuer 'issuer=CN = Self Signed Root')" "falls back to CN"
NOW="$(to_epoch 'Jan  1 00:00:00 2030 GMT')"
assert_eq 30  "$(days_until 'Jan 31 00:00:00 2030 GMT' "$NOW")" "days until expiry"
assert_eq -31 "$(days_until 'Dec  1 00:00:00 2029 GMT' "$NOW")" "negative when expired"

section "exposed-file signatures (false-positive guards)"
assert_ok   ".env body recognised"                  body_matches_signature .env "$FIX/body-env.txt"
assert_fail "catch-all HTML is not a .env"          body_matches_signature .env "$FIX/body-spa-catchall.html"
assert_fail "catch-all HTML is not a .git/HEAD"     body_matches_signature .git/HEAD "$FIX/body-spa-catchall.html"
assert_fail "catch-all HTML is not package.json"    body_matches_signature package.json "$FIX/body-spa-catchall.html"
assert_fail "catch-all HTML is not a login page"    body_matches_signature wp-login.php "$FIX/body-spa-catchall.html"
assert_ok   "real login form recognised"            body_matches_signature wp-login.php "$FIX/body-login.html"
TMP_T="$(mktemp -d)"; trap 'rm -rf "$TMP_T"' EXIT
printf 'ref: refs/heads/main\n' >"$TMP_T/head"
assert_ok   ".git/HEAD recognised"                  body_matches_signature .git/HEAD "$TMP_T/head"
printf 'PK\003\004rest' >"$TMP_T/zip"
assert_ok   "zip magic recognised"                  body_matches_signature backup.zip "$TMP_T/zip"
: >"$TMP_T/empty"
assert_fail "empty body never matches"              body_matches_signature .env "$TMP_T/empty"

section "port helpers"
assert_eq MySQL "$(port_name 3306)" "port name lookup"
assert_ok   "3306 is risky" is_risky_port 3306
assert_fail "22 is not flagged risky" is_risky_port 22
assert_fail "partial match 330 is not risky" is_risky_port 330

section "output safety"
assert_eq 'a\"b\\c\nd\te' "$(json_escape $'a"b\\c\nd\te')" "JSON escaping of quotes, backslashes, newlines, tabs"
assert_eq "evil[31mred" "$(sanitize $'evil\e[31mred')" "ESC control character stripped from remote data"
assert_eq "ab" "$(sanitize $'a\r\nb')" "CR/LF stripped from remote data"

# ------------------------------------------------------------- fixture audits
# Stubbed network layer. Each scenario sets the STUB_* variables.
reset_stubs() {
  STUB_A="192.0.2.10"; STUB_MX="10 mail.example.org."; STUB_TXT=""; STUB_DMARC=""; STUB_DKIM_SELECTOR=""
  STUB_HTTPS=200; STUB_HTTP=301; STUB_LOCATION="https://example.org/"; STUB_WWW=200
  STUB_HEADERS="$FIX/headers-hardened.txt"; STUB_CERT_END="Jan  1 00:00:00 2099 GMT"; STUB_VERIFY=0
  STUB_OPEN_PORTS=""; STUB_LOCAL_IPS="10.0.0.5"; STUB_DEFAULT_BODY="404"; STUB_XMLRPC="404"
  declare -gA STUB_BODIES=()
  DOMAIN="example.org"
}
dns_query() {
  case "$1 $2" in
    "A $DOMAIN")                         printf '%s\n' "$STUB_A" ;;
    "MX $DOMAIN")                        printf '%s\n' "$STUB_MX" ;;
    "TXT $DOMAIN")                       printf '%s\n' "$STUB_TXT" ;;
    "TXT _dmarc.$DOMAIN")                printf '%s\n' "$STUB_DMARC" ;;
    "TXT $STUB_DKIM_SELECTOR._domainkey.$DOMAIN") [[ -n "$STUB_DKIM_SELECTOR" ]] && cat "$FIX/dns-txt-dkim.txt" ;;
  esac
  return 0
}
http_code() {
  case "$1" in
    "https://$DOMAIN/")     echo "$STUB_HTTPS" ;;
    "http://$DOMAIN/")      echo "$STUB_HTTP" ;;
    "https://www.$DOMAIN/") echo "$STUB_WWW" ;;
    *)                      echo 404 ;;
  esac
}
http_headers() {
  case "$1" in
    https://*) cat "$STUB_HEADERS" ;;
    http://*)  printf 'HTTP/1.1 %s Moved\nLocation: %s\n' "$STUB_HTTP" "$STUB_LOCATION" ;;
  esac
}
http_body_to() {  # url outfile max
  local path="${1#https://"$DOMAIN"/}" spec code file
  spec="${STUB_BODIES[$path]:-$STUB_DEFAULT_BODY}"
  code="${spec%% *}"; file="${spec#* }"
  if [[ "$file" != "$spec" ]]; then cat "$FIX/$file" >"$2"; else : >"$2"; fi
  echo "$code"
}
http_post_body_to() {
  if [[ "$STUB_XMLRPC" == 200 ]]; then printf '<?xml version="1.0"?><methodResponse><fault/></methodResponse>' >"$2"; else : >"$2"; fi
  echo "$STUB_XMLRPC"
}
tls_cert_info()     { printf 'notAfter=%s\nissuer=C=US, O=Example Test CA, CN=Test R1\n' "$STUB_CERT_END"; }
tls_verify_result() { echo "$STUB_VERIFY"; }
probe_port()        { [[ -n "${STUB_PROBE_MARKER:-}" ]] && : >"$STUB_PROBE_MARKER"; [[ " $STUB_OPEN_PORTS " == *" $2 "* ]]; }
local_addresses()   { echo "$STUB_LOCAL_IPS"; }

dump_findings() {
  local i
  echo "SCORE=$SCORE GRADE=$GRADE CRIT=$N_CRIT WARN=$N_WARN RESOLVED=$RESOLVED"
  for i in "${!F_SEV[@]}"; do echo "${F_SEV[$i]}|${F_CHECK[$i]}|${F_RESULT[$i]}"; done
}

# run_scenario SETUP_FN -> findings dump on stdout; fails when strict mode aborts
run_scenario() {
  (
    set -euo pipefail
    reset_stubs
    "$1"
    TMPDIR_AUDIT="$(mktemp -d)"
    run_audit
    dump_findings
    rm -rf "$TMPDIR_AUDIT"
  )
}

scenario_hardened() {
  STUB_TXT="$(cat "$FIX/dns-txt-apex.txt")"
  STUB_DMARC='"v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.org"'
  STUB_DKIM_SELECTOR="selector1"
  STUB_OPEN_PORTS="22 25"
  STUB_BODIES[.well-known/security.txt]="200 security.txt"
}

scenario_weak() {
  STUB_MX=""; STUB_HTTP=200; STUB_HEADERS="$FIX/headers-weak.txt"
  STUB_CERT_END="Jan  1 00:00:00 2001 GMT"; STUB_VERIFY=10
  STUB_OPEN_PORTS="21 22 3306"; STUB_WWW=000; STUB_XMLRPC=200
  STUB_BODIES[.env]="200 body-env.txt"
  STUB_BODIES[wp-login.php]="200 body-login.html"
}

scenario_cdn_catchall() {
  STUB_MX="0 ."; STUB_TXT='"v=spf1 -all"'; STUB_DMARC='"v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"'
  STUB_HTTP=200; STUB_HEADERS="$FIX/headers-cloudflare.txt"
  STUB_OPEN_PORTS="2082 2083 8080 8443"
  STUB_DEFAULT_BODY="200 body-spa-catchall.html"; STUB_XMLRPC=200
  STUB_PROBE_MARKER="$TMP_T/probed"
  # a catch-all site answers xmlrpc.php with HTML, not an XML-RPC response
  http_post_body_to() { cat "$FIX/body-spa-catchall.html" >"$2"; echo 200; }
}

scenario_self_hosted() {
  STUB_TXT='"v=spf1 mx ~all"'; STUB_DMARC='"v=DMARC1; p=quarantine; rua=mailto:r@example.org"'
  STUB_LOCAL_IPS="10.0.0.5 192.0.2.10"; STUB_OPEN_PORTS="$PROBE_PORTS"
}

scenario_no_resolve() { STUB_A=""; }

scenario_spf_variants_multi() { STUB_TXT=$'"v=spf1 mx -all"\n"v=spf1 include:example.net ~all"'; }
scenario_spf_plus_all()      { STUB_TXT='"v=spf1 +all"'; }
scenario_redirect_http()     { STUB_LOCATION="http://www.example.org/"; }
scenario_expiring()          { STUB_CERT_END="$(date -u -d '+5 days' '+%b %e %H:%M:%S %Y GMT' 2>/dev/null || date -u -v+5d '+%b %e %H:%M:%S %Y GMT')"; }
scenario_dkim_revoked()      { dns_query() { case "$1 $2" in "A $DOMAIN") echo "$STUB_A" ;; "TXT "*._domainkey.*) echo '"v=DKIM1; p="' ;; esac; return 0; }; }
scenario_no_https()          { STUB_HTTPS=000; STUB_TXT='"v=spf1 -all"'; STUB_DMARC='"v=DMARC1; p=reject; rua=mailto:r@example.org"'; }

check_scenario() {  # name setup expected_header_line [expected finding lines...] [--absent line...]
  local name="$1" setup="$2" header="$3" out status line mode=present
  shift 3
  out="$(run_scenario "$setup")"; status=$?
  if ((status != 0)); then fail "$name: audit aborted under set -euo pipefail (exit $status)" "$out"; return; fi
  assert_eq "$header" "$(printf '%s\n' "$out" | sed -n 1p)" "$name: score line"
  for line in "$@"; do
    if [[ "$line" == --absent ]]; then mode=absent; continue; fi
    if [[ "$mode" == present ]]; then assert_contains "$out" $'\n'"$line" "$name: has [$line]"
    else assert_not_contains "$out" $'\n'"$line" "$name: no [$line]"; fi
  done
}

section "fixture audit: hardened site"
check_scenario hardened scenario_hardened "SCORE=100 GRADE=A CRIT=0 WARN=0 RESOLVED=1" \
  "OK|SPF record|present, strict (-all)" \
  "OK|DKIM signing key|found (selector: selector1)" \
  "OK|DMARC policy|p=reject" \
  "OK|Forces HTTPS|http -> 301 -> https" \
  "OK|Certificate valid|" \
  "OK|Cookies marked Secure|all 2 Secure" \
  "OK|Risky ports open to the internet|none of the common ones" \
  "INFO|All open ports found|22/SSH 25/SMTP" \
  "OK|security.txt published|present" \
  --absent "WARNING|" "CRITICAL|"

section "fixture audit: neglected site"
check_scenario weak scenario_weak "SCORE=0 GRADE=F CRIT=7 WARN=10 RESOLVED=1" \
  "CRITICAL|SPF record|missing" \
  "CRITICAL|DMARC policy|missing" \
  "CRITICAL|Forces HTTPS|plain http serves the full site" \
  "CRITICAL|Certificate valid|EXPIRED" \
  "CRITICAL|Certificate trusted|verify result 10" \
  "CRITICAL|Risky ports open to the internet|21/FTP 3306/MySQL" \
  "CRITICAL|Sensitive files exposed|.env" \
  "WARNING|Software version hidden|leaks: Server: Apache/2.4.41 (Ubuntu) X-Powered-By: PHP/7.4.3" \
  "WARNING|Cookies marked Secure|2 of 3 cookie(s) without Secure" \
  "WARNING|Cookies marked HttpOnly|2 of 3 cookie(s) without HttpOnly" \
  "WARNING|Admin login pages reachable|/wp-login.php" \
  "WARNING|WordPress xmlrpc.php|enabled" \
  "INFO|www. version|returns 000" \
  "INFO|Email (MX) configured|none"

section "fixture audit: CDN-fronted catch-all site (false-positive guards)"
check_scenario cdn scenario_cdn_catchall "SCORE=55 GRADE=D CRIT=1 WARN=6 RESOLVED=1" \
  "INFO|Email (MX) configured|null MX (accepts no mail)" \
  "OK|DMARC policy|p=reject" \
  "WARNING|DMARC reporting|no rua= address" \
  "INFO|Open ports|behind Cloudflare - origin server is hidden" \
  "OK|Sensitive files exposed|none of the common ones" \
  "OK|Admin login pages reachable|none at common paths" \
  --absent "WARNING|WordPress xmlrpc.php" "CRITICAL|Risky ports"
if [[ -e "$TMP_T/probed" ]]; then fail "cdn: no TCP probes sent to a CDN edge"; else pass "cdn: no TCP probes sent to a CDN edge"; fi

section "fixture audit: target is the scanning machine"
check_scenario self scenario_self_hosted "SCORE=95 GRADE=A CRIT=0 WARN=1 RESOLVED=1" \
  "WARNING|DKIM signing key|none found on common selectors" \
  "OK|SPF record|present, soft (~all)" \
  "OK|DMARC policy|p=quarantine" \
  "INFO|Open ports|not testable - target is this machine" \
  --absent "CRITICAL|Risky ports"

section "fixture audit: edge cases"
check_scenario no-resolve scenario_no_resolve "SCORE=85 GRADE=B CRIT=1 WARN=0 RESOLVED=0" \
  "CRITICAL|Domain resolves|no A record" --absent "OK|" "WARNING|"
check_scenario spf-multi scenario_spf_variants_multi "SCORE=75 GRADE=B CRIT=1 WARN=2 RESOLVED=1" \
  "WARNING|SPF record|2 SPF records published"
check_scenario spf-plus-all scenario_spf_plus_all "SCORE=65 GRADE=C CRIT=2 WARN=1 RESOLVED=1" \
  "CRITICAL|SPF record|allows every server (+all)"
check_scenario redirect-to-http scenario_redirect_http "SCORE=60 GRADE=C CRIT=2 WARN=2 RESOLVED=1" \
  "WARNING|Forces HTTPS|http redirects, but not to https"
check_scenario expiring-cert scenario_expiring "SCORE=60 GRADE=C CRIT=2 WARN=2 RESOLVED=1" \
  "WARNING|Certificate valid|expires in"
check_scenario dkim-revoked scenario_dkim_revoked "SCORE=70 GRADE=C CRIT=2 WARN=0 RESOLVED=1" \
  "INFO|DKIM signing key|only empty/revoked keys (p=)" --absent "OK|DKIM" "WARNING|DKIM"
check_scenario no-https scenario_no_https "SCORE=80 GRADE=B CRIT=1 WARN=1 RESOLVED=1" \
  "CRITICAL|HTTPS available|site does not answer on https" \
  --absent "OK|Certificate" "OK|HSTS" "OK|Sensitive files"

# ------------------------------------------------------------------ CLI tests
section "command line (no network needed)"
run_cli() { CLI_OUT="$("$@" 2>&1)"; CLI_STATUS=$?; }

run_cli bash "$SCRIPT" --help
assert_eq 0 "$CLI_STATUS" "--help exits 0"; assert_contains "$CLI_OUT" "--fail-under N" "--help documents --fail-under"
run_cli bash "$SCRIPT" --version
assert_eq "site-audit $SITE_AUDIT_VERSION" "$CLI_OUT" "--version prints version"
run_cli bash "$SCRIPT"
assert_eq 2 "$CLI_STATUS" "no domain exits 2"
run_cli bash "$SCRIPT" "https://example.com/wp-admin"
assert_eq 2 "$CLI_STATUS" "URL with a path exits 2"
run_cli bash "$SCRIPT" 'example.com;reboot'
assert_eq 2 "$CLI_STATUS" "shell metacharacters exit 2"
run_cli bash "$SCRIPT" example.com --bogus
assert_eq 2 "$CLI_STATUS" "unknown option exits 2"
run_cli bash "$SCRIPT" example.com --fail-under 150
assert_eq 2 "$CLI_STATUS" "--fail-under out of range exits 2"
run_cli bash "$SCRIPT" example.com example.org
assert_eq 2 "$CLI_STATUS" "two domains exit 2"
run_cli bash "$SCRIPT" example.com --md /nonexistent-dir/report.md
assert_eq 2 "$CLI_STATUS" "unwritable --md path exits 2"

FAKEBIN="$TMP_T/bin"; mkdir -p "$FAKEBIN"
for c in bash curl openssl timeout awk sed tr date mktemp; do
  if command -v "$c" >/dev/null; then ln -s "$(command -v "$c")" "$FAKEBIN/$c"; fi
done
run_cli env PATH="$FAKEBIN" "$FAKEBIN/bash" "$SCRIPT" example.com
assert_eq 3 "$CLI_STATUS" "missing dig exits 3"
assert_contains "$CLI_OUT" "missing required command(s): dig" "missing dependency is named"

section "end-to-end main() with stubbed network"
main_stubbed() {  # setup_fn args... -> runs main in a strict subshell
  local setup="$1"; shift
  ( reset_stubs; "$setup"; set -euo pipefail; main "$@" )
}
JSON_OUT="$(main_stubbed scenario_cdn_catchall example.org --json 2>/dev/null)"; st=$?
assert_eq 0 "$st" "--json run exits 0"
if command -v python3 >/dev/null; then
  if printf '%s' "$JSON_OUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["score"]==55 and d["grade"]=="D" and d["summary"]["critical"]==1 and len(d["findings"])>5 and all({"severity","check","result","why","penalty"}<=set(f) for f in d["findings"])'; then
    pass "JSON parses and carries score, grade, summary and findings"
  else
    fail "JSON parses and carries score, grade, summary and findings" "$JSON_OUT"
  fi
else
  skip "JSON validation (python3 not installed)"
fi

main_stubbed scenario_cdn_catchall example.org --no-ports --fail-under 60 >/dev/null 2>&1; st=$?
assert_eq 1 "$st" "--fail-under 60 exits 1 when score is 55"
main_stubbed scenario_cdn_catchall example.org --no-ports --fail-under 50 >/dev/null 2>&1; st=$?
assert_eq 0 "$st" "--fail-under 50 exits 0 when score is 55"
NR_OUT="$(main_stubbed scenario_no_resolve example.org --json 2>/dev/null)"; st=$?
assert_eq 4 "$st" "unresolvable domain exits 4"
assert_contains "$NR_OUT" '"error": "domain does not resolve"' "unresolvable domain still emits JSON"

TERM_OUT="$(main_stubbed scenario_weak example.org --no-color --md "$TMP_T/r.md" 2>&1)"
assert_contains "$TERM_OUT" "Score: 0/100" "terminal report shows score"
assert_not_contains "$TERM_OUT" $'\e[' "--no-color output has no ANSI escapes"
assert_contains "$TERM_OUT" "Saved markdown report: $TMP_T/r.md" "--md confirms the saved path"
MD="$(cat "$TMP_T/r.md" 2>/dev/null)"
assert_contains "$MD" "| Check | Result | Why it matters |" "markdown report has a findings table"
assert_contains "$MD" "**Grade:** F" "markdown report has the grade"
COLOR_OUT="$(main_stubbed scenario_hardened example.org --color 2>&1)"
assert_contains "$COLOR_OUT" $'\e[32m' "--color forces ANSI colours"

scenario_hostile_headers() {
  printf 'HTTP/2 200\nserver: evil\e]0;pwned\a\e[2J\nreferrer-policy: a|b\n' >"$TMP_T/hostile.txt"
  STUB_HEADERS="$TMP_T/hostile.txt"
}
HOSTILE_OUT="$(main_stubbed scenario_hostile_headers example.org --no-color --md - 2>&1)"
assert_not_contains "$HOSTILE_OUT" $'\e' "escape sequences in remote headers are stripped"
assert_contains "$HOSTILE_OUT" 'a\|b' "pipe characters are escaped in markdown tables"

# ------------------------------------------------------------------ live smoke
section "live smoke test"
if [[ "${LIVE:-0}" == 1 ]]; then
  LIVE_OUT="$(bash "$SCRIPT" example.com --json --no-ports 2>&1)"; st=$?
  assert_eq 0 "$st" "live: example.com audit exits 0"
  assert_contains "$LIVE_OUT" '"domain": "example.com"' "live: JSON names the domain"
  assert_contains "$LIVE_OUT" '"check": "HTTPS available"' "live: HTTPS check ran"
else
  skip "live example.com audit (set LIVE=1 to enable)"
fi

# ------------------------------------------------------------------ summary
printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
((FAIL == 0))
