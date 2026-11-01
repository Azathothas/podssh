#!/bin/sh
# scripts/fuzz.sh [SECONDS [TARGET...]]: each fuzz target of fuzz/ (T-198),
# or the TARGETs named, for SECONDS each (120 by default), with cargo-fuzz and
# libFuzzer on a pinned nightly Rust, seeded by scripts/fuzz-seeds.py.
#
# The workflow fuzz.yml runs it weekly and by hand; on this machine, in a
# glibc image through the build image's script:
#   PODSSH_BUILD_IMAGE=docker.io/library/rust:1-trixie \
#       sh scripts/dev.sh run -- 'sh /work/scripts/fuzz.sh 120'
# It is no step of the gate: the gate builds on stable Rust, and libFuzzer is
# C++.
#
# Linux with glibc only, with the address sanitizer. On Windows, libFuzzer's
# coverage needs the runtime of MSVC's address sanitizer, which the build
# tools may lack. On musl (the build image), each target died of a signal
# within five inputs, the empty one included (2026-10-11), so the script
# refuses musl with 69.
#
# Exit 0 when each target ran its time with no crash; else 1, and the input of
# each crash is printed in hex and stays in fuzz/artifacts/TARGET/.

set -u

NIGHTLY=nightly-2026-10-01
CARGO_FUZZ_VERSION=0.13.2

RUN_FOR=${1:-120}
[ $# -gt 0 ] && shift
case $RUN_FOR in
'' | *[!0-9]*)
    echo "fuzz.sh: SECONDS must be a whole number, not '$RUN_FOR'" >&2
    exit 64
    ;;
esac

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE/.." || exit 1

if ldd --version 2>&1 | grep -qi musl; then
    echo "fuzz.sh: libFuzzer on musl dies of a signal at once; run it with glibc, as the header says" >&2
    exit 69
fi

# retry3 COMMAND...: a download, tried three times, 10 s and then 20 s apart,
# as the gate tries its own.
retry3() {
    _try=1
    until "$@"; do
        if [ "$_try" -ge 3 ]; then
            return 1
        fi
        echo "fuzz.sh: try $_try of 3 failed: $*; again in $((_try * 10)) s" >&2
        sleep $((_try * 10))
        _try=$((_try + 1))
    done
}

# A C++ compiler for libFuzzer, and Python for the seeds: the build image has
# a C compiler only.
for need in c++:g++ python3:python3; do
    command -v "${need%%:*}" >/dev/null 2>&1 && continue
    if command -v apk >/dev/null 2>&1; then
        retry3 apk add --no-cache "${need#*:}" >/dev/null || exit 1
    elif command -v apt-get >/dev/null 2>&1; then
        { retry3 apt-get update -q && retry3 apt-get install -y -q "${need#*:}"; } >/dev/null || exit 1
    else
        echo "fuzz.sh: ${need%%:*} is missing" >&2
        exit 1
    fi
done
retry3 rustup toolchain install "$NIGHTLY" --profile minimal >/dev/null || exit 1
if ! cargo fuzz --version 2>/dev/null | grep -q " $CARGO_FUZZ_VERSION\$"; then
    retry3 cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked || exit 1
fi
SANITIZER=address
# This host's own target: cargo-fuzz builds for the platform that it was
# built for, and a release binary of it is musl's, where the sanitizer does
# not work (the first run in CI, 2026-10-11).
TARGET=$(rustc +"$NIGHTLY" -vV | sed -n 's/^host: //p')
[ -n "$TARGET" ] || exit 1

python3 scripts/fuzz-seeds.py || exit 1
if [ $# -eq 0 ]; then
    set -- $(cargo +"$NIGHTLY" fuzz list) || exit 1
fi
echo "fuzz.sh: $# targets, $RUN_FOR s each, sanitizer $SANITIZER, $NIGHTLY, $TARGET"
timeout 3600 cargo +"$NIGHTLY" fuzz build -s "$SANITIZER" --target "$TARGET" || exit 1

failed=0
for target in "$@"; do
    echo
    echo "== $target"
    # The readers of the quick tunnel and of WARP's capsules (T-403): one
    # allocation of 64 MiB from an input of some KiB is a defect, as a list
    # of 2^23 elements of no size was. Each other target: the RSS limit's.
    case $target in
    capnp_message | quick_connect_request | quick_control | warp_capsule) malloc_limit=64 ;;
    *) malloc_limit=512 ;;
    esac
    timeout $((RUN_FOR + 300)) cargo +"$NIGHTLY" fuzz run -s "$SANITIZER" --target "$TARGET" "$target" -- \
        -max_total_time="$RUN_FOR" -rss_limit_mb=512 -malloc_limit_mb="$malloc_limit" -print_final_stats=1 \
        >"fuzz/$target.log" 2>&1
    rc=$?
    grep -E '^(Done|stat::number_of_executed_units|stat::new_units_added)' "fuzz/$target.log"
    if [ "$rc" -ne 0 ]; then
        failed=1
        echo "FAIL  $target: exit $rc"
        tail -40 "fuzz/$target.log"
        for input in fuzz/artifacts/"$target"/*; do
            [ -f "$input" ] || continue
            echo "input $input:"
            od -An -tx1 "$input" | head -20
        done
    else
        echo "ok    $target"
    fi
    rm -f "fuzz/$target.log"
done
exit $failed
