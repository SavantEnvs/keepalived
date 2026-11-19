#!/usr/bin/env bash
#
# mayhem/build.sh — build keepalived's fuzz targets and its functional test.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem; also re-run offline by the
# PATCH tier on an already-built tree, or on a `git clean -ffdX`-ed one. Everything it writes lives in
# gitignored directories (mayhem/.gitignore + upstream's .gitignore for the autotools outputs).
#
#   mayhem/build-fuzz/   out-of-tree autotools build with $SANITIZER_FLAGS + SanCov ->
#                        keepalived/keepalived and the static libs the in-process harnesses link
#   mayhem/build-afl/    the same sanitized build compiled by afl-clang-fast -> keepalived-afl (the
#                        `config` file-input target)
#   mayhem/build-test/   out-of-tree autotools build with the project's NORMAL flags ->
#                        keepalived/keepalived + upstream's test/auth_hmac_test (run by mayhem/test.sh)
#   mayhem/out/          the targets: keepalived-afl (config), fuzz_<name> + fuzz_<name>-standalone,
#                        keepalived-test, auth_hmac_test
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT" mayhem/build-fuzz mayhem/build-test

# Feature set shared by both builds: VRRP + LVS checkers (defaults) plus BFD, HTTP regex and JSON.
# systemd integration off (no systemd in the image); configure's own hardening flags off so they
# don't fight the sanitizers.
CONFIGURE_OPTS=(--disable-systemd --disable-hardening --enable-bfd --enable-regex --enable-json)

# 0) autotools bootstrap (configure and the Makefile.in's are gitignored upstream)
[ -x configure ] || ./autogen.sh

# 1) Sanitized + SanCov build of the whole project. -D_WITH_SANITIZE_UNDEFINED_ is upstream's own
#    switch for UBSan builds (what --enable-sanitize-undefined defines): it marks
#    init_check_keywords() no_sanitize("null") for its `&check_data->ssl` address-of-member on a NULL
#    base (check_parser.c, commented upstream) and lib/memory.c's allocator no_sanitize("alignment").
#    Nothing else changes; every other UBSan check and ASan stay on and halting.
#    SanCov (-fsanitize=fuzzer-no-link) instruments the project for the libFuzzer harnesses; its
#    callbacks come from the sanitizer/libFuzzer runtimes, so a no-sanitizer build
#    (SANITIZER_FLAGS empty) leaves it out and everything still links without a runtime.
#    The keepalived binary also links lsan_off.o (LeakSanitizer off; ASan/UBSan untouched), from an
#    archive that -Wl,--undefined pulls in exactly once (automake repeats LDFLAGS on the link line,
#    and configure.ac discards LIBS).
SANCOV_FLAGS=-fsanitize=fuzzer-no-link
[ -n "$SANITIZER_FLAGS" ] || SANCOV_FLAGS=
FUZZ_CFLAGS="$SANITIZER_FLAGS $SANCOV_FLAGS $DEBUG_FLAGS"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
rm -f "$OUT/libmayhem_hooks.a"
"${AR:-ar}" rcs "$OUT/libmayhem_hooks.a" "$OUT/lsan_off.o"
HOOK_LDFLAGS="-Wl,--undefined=__lsan_is_turned_off $OUT/libmayhem_hooks.a"
if [ ! -f mayhem/build-fuzz/config.status ]; then
  (cd mayhem/build-fuzz && ../../configure "${CONFIGURE_OPTS[@]}" \
      CC="$CC" CPPFLAGS="-D_WITH_SANITIZE_UNDEFINED_=1" \
      CFLAGS="$FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS $HOOK_LDFLAGS")
fi
make -C mayhem/build-fuzz -j"$MAYHEM_JOBS"
# bin/keepalived is a stripped copy; keep the linked binary (with its DWARF)
cp mayhem/build-fuzz/keepalived/keepalived "$OUT/keepalived"

# 1b) AFL++-instrumented build of the same sanitized keepalived for the `config` target (Mayhemfile
#     `afl: true`, `keepalived --config-test -f @@`): the configuration parser calls exit() on bad
#     input, so it stays a file-input target, and AFL's coverage map makes it a guided one. Same
#     sanitizer/debug flags and lsan_off hook as step 1; AFL's own pass replaces SanCov here.
#     It also links mayhem/conf_mode_shim.c with -Wl,--wrap=stat: keepalived skips a config file
#     that has an execute bit set, and Mayhem may stage the test case with one, which made every
#     execution a no-op (0 edges). The shim clears those bits for the -f file only.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/conf_mode_shim.c -o "$OUT/conf_mode_shim.o"
rm -f "$OUT/libmayhem_afl_hooks.a"
"${AR:-ar}" rcs "$OUT/libmayhem_afl_hooks.a" "$OUT/lsan_off.o" "$OUT/conf_mode_shim.o"
AFL_HOOK_LDFLAGS="-Wl,--wrap=stat -Wl,--undefined=__lsan_is_turned_off -Wl,--undefined=__wrap_stat $OUT/libmayhem_afl_hooks.a"
if [ ! -f mayhem/build-afl/config.status ] || ! grep -q libmayhem_afl_hooks mayhem/build-afl/config.status; then
  rm -rf mayhem/build-afl
  mkdir -p mayhem/build-afl
  (cd mayhem/build-afl && ../../configure "${CONFIGURE_OPTS[@]}" \
      CC=afl-clang-fast CPPFLAGS="-D_WITH_SANITIZE_UNDEFINED_=1" \
      CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" LDFLAGS="$SANITIZER_FLAGS $AFL_HOOK_LDFLAGS")
fi
AFL_QUIET=1 make -C mayhem/build-afl -j"$MAYHEM_JOBS"
cp mayhem/build-afl/keepalived/keepalived "$OUT/keepalived-afl"

# 2) In-process libFuzzer harnesses over the sanitized archives (+ run-once standalone reproducers).
B=mayhem/build-fuzz
KA_LIBS=( $B/keepalived/core/libcore.a $B/keepalived/check/libcheck.a $B/keepalived/vrrp/libvrrp.a
          $B/keepalived/bfd/libbfd.a $B/keepalived/core/libcore.a $B/keepalived/trackers/libtracker.a
          $B/lib/liblib.a )
SYS_LIBS=( -lm -lssl -lcrypto -lnl-3 -lnl-genl-3 -lmagic -lnftnl -lmnl -lpcre2-8 )
INC=( -DHAVE_CONFIG_H -D_GNU_SOURCE -D_WITH_SANITIZE_UNDEFINED_=1 -I/usr/include/libnl3
      -I$B/lib -Ilib -Ikeepalived/include -Ikeepalived/vrrp -Ikeepalived/core -Imayhem/harnesses )

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# The harness TU is SanCov-instrumented too: fuzz_vrrp_packet compiles a project source
# (vrrp_scheduler.c) into it.
build_harness() {   # build_harness <name> [extra link flags...]
  local name="$1"; shift
  $CC $SANITIZER_FLAGS $SANCOV_FLAGS $DEBUG_FLAGS -O1 "${INC[@]}" -c "mayhem/harnesses/$name.c" -o "$OUT/$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$OUT/lsan_off.o" "$@" \
      -Wl,--start-group "${KA_LIBS[@]}" -Wl,--end-group "${SYS_LIBS[@]}" -o "$OUT/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$name.o" \
      "$OUT/lsan_off.o" "$@" \
      -Wl,--start-group "${KA_LIBS[@]}" -Wl,--end-group "${SYS_LIBS[@]}" -o "$OUT/$name-standalone"
}
build_harness fuzz_vrrp_packet
build_harness fuzz_netlink -Wl,--wrap=recvmsg
build_harness fuzz_track_process -Wl,--wrap=opendir -Wl,--wrap=open

# 3) Test build with the project's normal flags (independent of the sanitized tree).
if [ ! -f mayhem/build-test/config.status ]; then
  (cd mayhem/build-test && env -u CFLAGS -u LDFLAGS ../../configure "${CONFIGURE_OPTS[@]}" CC="$CC" \
      CFLAGS="-O2 -g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS")
fi
make -C mayhem/build-test -j"$MAYHEM_JOBS"
cp mayhem/build-test/keepalived/keepalived "$OUT/keepalived-test"
T=mayhem/build-test
$CC -O2 -g $COVERAGE_FLAGS -DHAVE_CONFIG_H -D_GNU_SOURCE -I/usr/include/libnl3 -I$T/lib -Ilib \
    -Ikeepalived/include test/auth_hmac_test.c \
    -Wl,--start-group $T/keepalived/core/libcore.a $T/keepalived/check/libcheck.a \
    $T/keepalived/vrrp/libvrrp.a $T/keepalived/bfd/libbfd.a $T/keepalived/trackers/libtracker.a \
    $T/lib/liblib.a -Wl,--end-group "${SYS_LIBS[@]}" $COVERAGE_FLAGS -o "$OUT/auth_hmac_test"

ls -l "$OUT"
