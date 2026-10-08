#!/bin/sh
# The podssh build gate, as the build image (rust:1-alpine) runs it.
#
# `sh scripts/dev.sh check` runs this in a container on a developer machine and
# CI runs it in the same image; neither re-implements any of it. Plain POSIX sh,
# no arguments, the tree at /work, PODSSH_TARGET read if set.
#
# Every exit code is read from the process that produced it, never through a
# pipe (a pipe reports the last command's status, so a failed build reads as
# success).

set -u
cd /work || exit 71

TARGET=${PODSSH_TARGET:-x86_64-unknown-linux-musl}
failed=0

# Cap parallelism. Cargo defaults to one job per CPU, and on 2026-10-07 three
# uncapped builds at once nearly exhausted a 64 GB developer machine through
# an uncapped WSL VM. Allow one job per 3 GiB of available memory, between 1
# and 8, unless the caller chose a value.
if [ -z "${CARGO_BUILD_JOBS:-}" ]; then
    mem_kb=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo 2>/dev/null)
    jobs=$(( ${mem_kb:-0} / 3145728 ))
    [ "$jobs" -lt 1 ] && jobs=1
    [ "$jobs" -gt 8 ] && jobs=8
    CARGO_BUILD_JOBS=$jobs
fi
export CARGO_BUILD_JOBS
export CARGO_INCREMENTAL=0

# run <label> <command...>: run it, report its own exit code. A failing step
# prints its whole log; a passing one prints its last lines.
run() {
    _label=$1
    shift
    printf '\n== %s\n' "$_label"
    "$@" >/tmp/podssh-step.out 2>&1
    _rc=$?
    if [ "$_rc" -ne 0 ]; then
        cat /tmp/podssh-step.out
        failed=1
    else
        tail -3 /tmp/podssh-step.out
    fi
    printf 'exit=%s\n' "$_rc"
    return $_rc
}

echo "== toolchain"
rustc --version
cargo --version
echo "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS"

# The default members (everything except the Tailscale adapter) must build
# with no C compiler. The image ships a working `cc`, so `CC=/nonexistent` is
# what enforces the rule; `scripts/plant.sh` proves it is load-bearing.
run "default members build with no C compiler" \
    env CC=/nonexistent cargo build --locked

run "default members: tests" \
    env CC=/nonexistent cargo test --locked --no-fail-fast

# The Tailscale adapter (feature `ts`) links the vendored tailscale-rs fork,
# which needs cc and cmake (aws-lc-sys). Built and tested on its own.
run "Tailscale adapter (feature ts, needs cc): tests" \
    cargo test --locked --no-fail-fast -p podssh-ts -p podssh-cli --features podssh-cli/ts

# The shipped artefact: a static musl binary from the default (pure-Rust)
# build.
run "static musl release, no C compiler" \
    env CC=/nonexistent RUSTFLAGS=-Ctarget-feature=+crt-static \
        cargo build --locked --release --target "$TARGET" -p podssh-cli

echo
echo "== the artefact"
B="target/$TARGET/release/podssh"
if [ ! -f "$B" ]; then
    echo "ARTEFACT MISSING: $B"
    failed=1
elif ! command -v readelf >/dev/null 2>&1; then
    # A check that cannot run is not a pass.
    echo "readelf is missing from the build image; the linkage check did not run"
    failed=1
else
    ls -la "$B"
    readelf -d "$B" >/tmp/podssh-dyn.out 2>&1
    dyn_rc=$?
    readelf -l "$B" >/tmp/podssh-phdr.out 2>&1
    phdr_rc=$?
    if [ "$dyn_rc" -ne 0 ] || [ "$phdr_rc" -ne 0 ]; then
        echo "FAIL: readelf could not read the binary"
        cat /tmp/podssh-dyn.out /tmp/podssh-phdr.out
        failed=1
    elif grep -qi 'NEEDED' /tmp/podssh-dyn.out; then
        echo "FAIL: the binary has dynamic dependencies:"
        grep -i 'NEEDED' /tmp/podssh-dyn.out
        failed=1
    elif grep -q 'INTERP' /tmp/podssh-phdr.out; then
        echo "FAIL: the binary asks for a program interpreter, so it is not static"
        failed=1
    else
        echo "static: no NEEDED entries and no program interpreter"
        readelf -h "$B" | grep -E 'Type:'
    fi
fi

echo
if [ "$failed" -eq 0 ]; then
    echo "podssh: gate green."
else
    echo "podssh: gate FAILED."
fi
exit $failed
