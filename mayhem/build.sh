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

# Everything this script writes lives under build/ (gitignored upstream), so `git clean -ffdX`
# resets it and a re-run on a built tree just rebuilds in place.
FUZZ_DIR="$SRC/build/mayhem-fuzz"
TEST_DIR="$SRC/build/mayhem-tests"
mkdir -p "$FUZZ_DIR/obj"

# 1) The project itself, sanitized: every src/*.c except main.c (the daemon's main()), compiled
#    with $SANITIZER_FLAGS $DEBUG_FLAGS into a static archive the harnesses link. Upstream's CMake
#    only builds the executable, so the objects are compiled here the way it compiles them
#    (C11, -Isrc, per-file __FILENAME__ for the LOG macros).
# SanCov for libFuzzer: the fuzzer-no-link form of $LIB_FUZZING_ENGINE on every compile, so the
# project objects and harnesses are coverage-instrumented (the engine is linked only at the end).
COV_FLAGS="${LIB_FUZZING_ENGINE//fuzzer/fuzzer-no-link}"
PROJ_CFLAGS="-std=gnu11 -I$SRC/src $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -O1"
LIBS="-lcares -lcurl -lev -lresolv -lm"
objs=()
for src in "$SRC"/src/*.c; do
  name="$(basename "$src" .c)"
  [ "$name" = main ] && continue
  $CC $PROJ_CFLAGS -D__FILENAME__="\"$name.c\"" -c "$src" -o "$FUZZ_DIR/obj/$name.o"
  objs+=("$FUZZ_DIR/obj/$name.o")
done
rm -f "$FUZZ_DIR/libhttps_dns_proxy.a"
ar rcs "$FUZZ_DIR/libhttps_dns_proxy.a" "${objs[@]}"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$FUZZ_DIR/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_DIR/standalone_main.o"

# 2) Each harness twice: the libFuzzer target /mayhem/<name> and the run-once reproducer
#    /mayhem/<name>-standalone.
for h in dns_tcp_listener dns_udp_listener dns_truncate dns_poller options; do
  hsrc="$SRC/mayhem/harnesses/fuzz_$h.c"
  $CC $PROJ_CFLAGS -D__FILENAME__="\"fuzz_$h.c\"" -c "$hsrc" -o "$FUZZ_DIR/fuzz_$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$FUZZ_DIR/fuzz_$h.o" \
      "$FUZZ_DIR/lsan_off.o" "$FUZZ_DIR/libhttps_dns_proxy.a" $LIBS -o "$SRC/fuzz_$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$FUZZ_DIR/standalone_main.o" "$FUZZ_DIR/fuzz_$h.o" \
      "$FUZZ_DIR/lsan_off.o" "$FUZZ_DIR/libhttps_dns_proxy.a" $LIBS -o "$SRC/fuzz_$h-standalone"
done

# 3) Upstream's tests, with the project's normal flags (its own CMake, Release), for
#    mayhem/test.sh: the eight unit-labelled executables, plus the daemon itself (https_dns_proxy)
#    for the offline `tcp_lifecycle` integration test (tests/integration/test_tcp_lifecycle.py:
#    stdlib python3 + the openssl CLI, a local TLS DoH server on 127.0.0.1, resolver given as an IP
#    literal, so no network or root). Not built/run: `robot` (needs the pip robotframework package
#    and dig/network), `outbound_interface_linux` (needs root/CAP_NET_RAW), and the valgrind
#    `memcheck` variants (no valgrind in the image; they rerun the same tests).
env -u CFLAGS -u LDFLAGS cmake -S "$SRC" -B "$TEST_DIR" -DBUILD_TESTING=ON -DUSE_CLANG_TIDY=OFF \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build "$TEST_DIR" -j"$MAYHEM_JOBS" --target \
    dns_poller_watchers_test dns_truncate_test resolver_update_test dns_listener_tcp_test \
    https_client_limits_test doh_proxy_resolver_test outbound_interface_test options_test \
    https_dns_proxy
