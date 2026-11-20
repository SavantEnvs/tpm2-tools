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

T="$SRC/mayhem/build-test"
TPM2="$T/tools/tpm2"
FIX="$SRC/test/integration/fixtures"
[ -x "$TPM2" ] && [ -f "$T/unit-tests.list" ] || { echo "oracle build missing: run mayhem/build.sh" >&2; emit_ctrf cmocka 0 1; exit 1; }

passed=0 failed=0

# (a) Upstream's cmocka unit suite: run each binary and read cmocka's own summary line, so a binary
#     that produces no "[  PASSED  ] N test(s)." line (crashed / neutered) counts as failed.
while read -r u; do
  [ -n "$u" ] || continue
  out=$(cd "$T" && "./$u" 2>&1); rc=$?
  n=$(printf '%s\n' "$out" | sed -n 's/^\[  PASSED  \] \([0-9]*\) test(s)\./\1/p' | tail -1)
  f=$(printf '%s\n' "$out" | sed -n 's/^\[  FAILED  \] \([0-9]*\) test(s).*/\1/p' | tail -1)
  if [ "$rc" -eq 0 ] && [ -n "$n" ] && [ "$n" -gt 0 ] && [ -z "$f" ]; then
    passed=$((passed + n)); echo "PASS $u ($n)"
  else
    failed=$((failed + ${f:-1})); echo "FAIL $u (rc=$rc)"; printf '%s\n' "$out" | tail -20
  fi
done < "$T/unit-tests.list"

# (b) Known-answer probes through the real CLI: upstream's golden YAML for its event-log fixtures
#     (the same comparisons its system test test/integration/tests/eventlog.sh makes).
for f in event.bin specid-vendordata.bin specid-vendordata-1.05.bin specid-vendordata-1.06.bin; do
  if "$TPM2" eventlog "$FIX/$f" 2>/dev/null | diff -q - "$FIX/$f.yaml" >/dev/null; then
    passed=$((passed + 1)); echo "PASS eventlog $f"
  else
    failed=$((failed + 1)); echo "FAIL eventlog $f"
  fi
done

emit_ctrf cmocka+kat "$passed" "$failed" 0
