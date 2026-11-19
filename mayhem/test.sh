#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# Upstream's unit tests (tests/unit, tests/test_harness.h), built by mayhem/build.sh with the
# project's normal flags. Each executable prints "PASS: <test>" / "FAIL: <test>" per test case and
# ends with "<n> tests, <m> failures". A test case counts as passed only if it printed PASS and the
# executable's summary line agrees; an executable that prints no summary (crashed, or did nothing)
# counts as one failure, so a no-op build cannot pass.
TEST_DIR="$SRC/build/mayhem-tests"
TESTS="dns_poller_watchers_test dns_truncate_test resolver_update_test dns_listener_tcp_test
       https_client_limits_test doh_proxy_resolver_test outbound_interface_test options_test"

passed=0
failed=0
for t in $TESTS; do
  bin="$TEST_DIR/$t"
  if [ ! -x "$bin" ]; then
    echo "missing test executable $bin (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1))
    continue
  fi
  out="$(cd "$TEST_DIR" && timeout 120 "$bin" 2>&1)"
  rc=$?
  printf '%s\n' "$out" | sed "s|^|[$t] |"
  p=$(printf '%s\n' "$out" | grep -c '^PASS: ')
  f=$(printf '%s\n' "$out" | grep -c '^FAIL: ')
  summary=$(printf '%s\n' "$out" | sed -n 's/^\([0-9][0-9]*\) tests, \([0-9][0-9]*\) failures$/\1 \2/p' | tail -1)
  if [ -z "$summary" ]; then
    echo "[$t] no test summary line (rc=$rc)" >&2
    failed=$((failed + 1 + f))
    continue
  fi
  set -- $summary
  if [ "$1" -ne $((p + f)) ] || [ "$2" -ne "$f" ] || { [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; } || [ "$1" -eq 0 ]; then
    echo "[$t] summary '$summary' disagrees with PASS/FAIL lines ($p/$f) or exit code $rc" >&2
    failed=$((failed + 1 + f))
    continue
  fi
  passed=$((passed + p))
  failed=$((failed + f))
done

# Upstream's offline integration test `tcp_lifecycle` (CMakeLists.txt registers it as
# `python3 tests/integration/test_tcp_lifecycle.py --binary <https_dns_proxy> --openssl <openssl>`):
# it runs the real daemon against a local TLS DoH server on 127.0.0.1 and checks shutdown grace and
# drain, bounded outstanding TCP/UDP fetches and slow-reader isolation, comparing the DNS answers
# byte for byte. unittest (verbosity 2) prints one "<test> (__main__.<class>.<test>) ... " line per
# case, "Ran N tests", and a final "OK" or "FAILED (failures=a, errors=b)". The result words
# ("ok"/"FAIL"/"ERROR") are not counted per line: the DoH server threads print tracebacks for the
# transfers the shutdown tests cancel on purpose, and those land in the middle of a case's line.
# Passed = N - a - b. The run counts as one failure if the daemon is missing, there is no "Ran N"
# or final status line, N is 0, N differs from the number of case lines, anything was skipped, or
# the exit code disagrees with the status.
it_bin="$TEST_DIR/https_dns_proxy"
it_script="$SRC/tests/integration/test_tcp_lifecycle.py"
if [ ! -x "$it_bin" ] || [ ! -f "$it_script" ] || ! command -v python3 >/dev/null || ! command -v openssl >/dev/null; then
  echo "[tcp_lifecycle] missing $it_bin, $it_script, python3 or openssl" >&2
  failed=$((failed + 1))
else
  out="$(cd "$TEST_DIR" && timeout 120 python3 "$it_script" --binary "$it_bin" --openssl "$(command -v openssl)" 2>&1)"
  rc=$?
  printf '%s\n' "$out" | sed "s|^|[tcp_lifecycle] |"
  h=$(printf '%s\n' "$out" | grep -cE '^test_[A-Za-z0-9_]+ \(__main__\.[A-Za-z0-9_.]+\) \.\.\. ')
  n=$(printf '%s\n' "$out" | sed -n 's/^Ran \([0-9][0-9]*\) tests\{0,1\} in .*/\1/p' | tail -1)
  status=$(printf '%s\n' "$out" | grep -E '^(OK|FAILED)( \(.*\))?$' | tail -1)
  fa=$(printf '%s\n' "$status" | sed -n 's/.*failures=\([0-9][0-9]*\).*/\1/p'); fa=${fa:-0}
  er=$(printf '%s\n' "$status" | sed -n 's/.*errors=\([0-9][0-9]*\).*/\1/p'); er=${er:-0}
  f=$((fa + er))
  if [ -z "$n" ] || [ -z "$status" ] || [ "$n" -eq 0 ] || [ "$n" -ne "$h" ] || [ "$f" -gt "$n" ] \
     || printf '%s\n' "$status" | grep -qE 'skipped=|expected failures=|unexpected successes=' \
     || { [ "${status%% *}" = OK ] && { [ "$rc" -ne 0 ] || [ "$f" -ne 0 ]; }; } \
     || { [ "${status%% *}" = FAILED ] && { [ "$rc" -eq 0 ] || [ "$f" -eq 0 ]; }; }; then
    echo "[tcp_lifecycle] 'Ran ${n:-?} tests' / '${status:-no status}' disagrees with $h case lines or exit code $rc" >&2
    failed=$((failed + 1 + f))
  else
    echo "[tcp_lifecycle] $n tests, $f failures"
    passed=$((passed + n - f))
    failed=$((failed + f))
  fi
fi

emit_ctrf "https_dns_proxy-tests" "$passed" "$failed" 0
