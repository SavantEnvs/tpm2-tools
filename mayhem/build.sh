#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# ./bootstrap runs `git describe` (VERSION) and autoreconf. Allow git to read the repo whatever uid
# owns it (the PATCH re-run identity may differ from the image's). configure & friends are gitignored,
# so a `git clean -ffdX`-ed tree simply bootstraps again.
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*'
[ -x configure ] && [ -f VERSION ] && [ -f src_vars.mk ] || ./bootstrap

# Options both builds share. The cmocka unit suite (--enable-unit) also gates on the system-test
# tooling (tpm2-abrmd, a TPM simulator, expect, ss, xxd); those tests never run here, so the probes
# are answered through configure's own cache variables instead of installing a TPM stack.
COMMON_OPTS=(--disable-fapi --disable-hardening --without-efivar)
UNIT_CACHE=(ac_cv_prog_tpm2_abrmd=yes ac_cv_prog_swtpm=yes ac_cv_prog_XXD=yes ac_cv_prog_SS=yes
            ac_cv_prog_EXPECT=yes ac_cv_prog_OPENSSL=yes)

# 1) Fuzz build: the whole `tpm2` multi-call tool, compiled with afl-clang-fast (AFL edge coverage
#    on every project object) + ASan/UBSan (halting) + DWARF 3. Every Mayhemfile runs this binary as
#    an `afl: true` file-input target, one tool/sub-command each. The tools exit() on bad input and
#    keep per-tool static state, so the CLI process (one input per exec) is the faithful harness.
#    Out-of-tree build under mayhem/build-afl (gitignored by mayhem/.gitignore).
B="$SRC/mayhem/build-afl"
mkdir -p "$B"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"
( cd "$B"
  [ -f config.status ] || "$SRC/configure" "${COMMON_OPTS[@]}" \
      CC=afl-clang-fast CFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS" \
      LDFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" LIBS="$B/lsan_off.o"
  AFL_QUIET=1 make -j"$MAYHEM_JOBS" tools/tpm2 )
# Targets run $B/tools/tpm2 in place: the tool dispatches on argv[0]'s basename, so it must stay `tpm2`.

# 2) Oracle build: the project's normal flags (clang, no sanitizers, no AFL), plus the upstream
#    cmocka unit-test binaries; mayhem/test.sh only RUNS them (and KAT probes through this tpm2).
T="$SRC/mayhem/build-test"
mkdir -p "$T"
( cd "$T"
  [ -f config.status ] || "$SRC/configure" "${COMMON_OPTS[@]}" --enable-unit "${UNIT_CACHE[@]}" \
      CFLAGS="-O2 -g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
  make -j"$MAYHEM_JOBS" tools/tpm2
  # Upstream's `make check` also wants pandoc (man pages) and runs the TPM system tests; build only
  # the unit-test programs (automake's own check_PROGRAMS list).
  units=$(printf 'print-units:\n\t@echo $(check_PROGRAMS)\n' | make -s -f Makefile -f - print-units)
  # shellcheck disable=SC2086
  make -j"$MAYHEM_JOBS" $units
  printf '%s\n' $units > "$T/unit-tests.list" )
