#!/usr/bin/env bash
#
# mayhem/test.sh — keepalived's functional checks, on binaries mayhem/build.sh built with the
# project's NORMAL flags (mayhem/out/auth_hmac_test, mayhem/out/keepalived-test). Never compiles.
#
#  1. upstream's test/auth_hmac_test: the VRRP auth_hmac wire-level known-answer vectors (each
#     "PASS <check>" line is one test; any "FAIL" line, or a missing "all tests passed", fails).
#  2. `keepalived --config-test` known answers: a valid configuration must be accepted (exit 0, no
#     config errors), and broken ones must be rejected with exit 5 and the exact error messages
#     the parser produces for them.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

OUT="$SRC/mayhem/out"
for b in auth_hmac_test keepalived-test; do
  [ -x "$OUT/$b" ] || { echo "missing $OUT/$b — mayhem/build.sh must build it" >&2; emit_ctrf keepalived-tests 0 1; exit 1; }
done

passed=0 failed=0
ok()   { echo "PASS $1"; passed=$((passed + 1)); }
fail() { echo "FAIL $1"; failed=$((failed + 1)); }

# --- 1. auth_hmac known-answer vectors ----------------------------------------------------------
ah_out="$("$OUT/auth_hmac_test" 2>&1)"; ah_rc=$?
echo "$ah_out"
ah_pass=$(grep -c '^PASS ' <<<"$ah_out")
ah_fail=$(grep -c '^FAIL ' <<<"$ah_out")
passed=$((passed + ah_pass)); failed=$((failed + ah_fail))
if [ "$ah_rc" -eq 0 ] && [ "$ah_pass" -ge 20 ] && grep -qx 'all tests passed' <<<"$ah_out"; then
  ok "auth_hmac_test: exit 0, $ah_pass vectors, 'all tests passed'"
else
  fail "auth_hmac_test: rc=$ah_rc pass=$ah_pass fail=$ah_fail"
fi

# --- 2. config-test known answers ---------------------------------------------------------------
work="$(mktemp -d "${TMPDIR:-/tmp}/ka-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

config_test() {   # config_test <file> -> sets ct_rc and ct_out
  ct_out="$(cd "$work" && "$OUT/keepalived-test" --config-test -n -l -f "$1" 2>&1)"; ct_rc=$?
}
expect_line() {   # expect_line <name> <exact line>
  if grep -qxF -- "$2" <<<"$ct_out"; then ok "$1: '$2'"; else fail "$1: missing '$2'"; echo "$ct_out" | sed 's/^/    | /'; fi
}

cat > "$work/good.conf" <<'EOF'
global_defs {
  router_id fuzz_test
  dynamic_interfaces
}
$VIP_BASE=192.168.77
vrrp_instance VI_1 {
  state BACKUP
  interface fz0
  virtual_router_id 51
  priority 100
  advert_int 1
  authentication {
    auth_type PASS
    auth_pass s3cr3tpw
  }
  virtual_ipaddress {
    ${VIP_BASE}.1/24
    ${VIP_BASE}.2/24
  }
}
virtual_server 10.10.10.2 1358 {
  delay_loop 6
  lb_algo rr
  lb_kind NAT
  protocol TCP
  real_server 192.168.200.2 1358 {
    weight 1
    TCP_CHECK {
      connect_timeout 3
    }
  }
}
EOF
config_test "$work/good.conf"
if [ "$ct_rc" -eq 0 ]; then ok "valid config accepted (exit 0)"; else fail "valid config: exit $ct_rc"; echo "$ct_out" | sed 's/^/    | /'; fi
if grep -q 'Unknown keyword\|outside range\|not valid' <<<"$ct_out"; then fail "valid config produced config errors"; else ok "valid config: no config errors"; fi

cat > "$work/bad.conf" <<'EOF'
global_defs {
  bogus_keyword 1
}
vrrp_instance V {
  state BACKUP
  interface fz0
  virtual_router_id 300
  priority 100
  virtual_ipaddress {
    192.168.1.1
  }
}
EOF
config_test "$work/bad.conf"
if [ "$ct_rc" -eq 5 ]; then ok "invalid config rejected (exit 5)"; else fail "invalid config: exit $ct_rc, expected 5"; fi
expect_line "unknown keyword" "(Line 2) Unknown keyword 'bogus_keyword'"
expect_line "VRID range" "($work/bad.conf: Line 7) number '300' outside range [1, 255]"
expect_line "VRID check" "($work/bad.conf: Line 7) (V): VRID '300' not valid - must be between 1 & 255"
expect_line "missing interface" "($work/bad.conf: Line 6) WARNING - interface fz0 for vrrp_instance V doesn't exist"
expect_line "missing interface fatal" "Non-existent interface specified in configuration"

emit_ctrf keepalived-tests "$passed" "$failed"
