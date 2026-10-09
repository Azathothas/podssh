#!/bin/sh
# The podssh build gate, as the build image (rust:1-alpine) runs it.
#
# `sh scripts/dev.sh check` runs this in a container on a developer machine and
# CI runs it in the same image; neither re-implements any of it. Plain POSIX sh,
# the tree at /work, PODSSH_TARGET read if set.
#
# With no argument, each step runs, in order. Given the names of steps, the
# gate runs those, in the order given. CI runs each step in a job of its own,
# at the same time, from the names that `--list` prints
# (.github/workflows/build.yml): so CI and a developer run the same steps.
#
# Every exit code is read from the process that produced it, never through a
# pipe (a pipe reports the last command's status, so a failed build reads as
# success).

set -u

# The steps, in the order of a full run. A step that is not in this list runs
# nowhere: not here, and not in CI.
STEPS="lint libs msrv msrv_ssh msrv_ts record ssh ts release"

if [ "$#" -eq 1 ] && [ "$1" = --list ]; then
    for _s in $STEPS; do
        echo "$_s"
    done
    exit 0
fi
for _s in "$@"; do
    case " $STEPS " in
        *" $_s "*) ;;
        *)
            echo "gate.sh: no step '$_s'; the steps are: $STEPS (or --list)" >&2
            exit 64
            ;;
    esac
done
if [ "$#" -eq 0 ]; then
    # shellcheck disable=SC2086  # $STEPS is a list of names
    set -- $STEPS
fi

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
echo "steps: $*"

# Each package of the workspace, by name: `cargo fmt --all` would also format
# the fork in vendor/, which keeps its own format and its patches.
PKGS="-p podssh-cli -p podssh-ssh -p podssh-relay -p podssh-ws -p podssh-core -p podssh-terminal -p podssh-probe -p podssh-ts -p podssh-todo"

# The library crates must build with no C compiler. The image ships a working
# `cc`, so `CC=/nonexistent` is what enforces the rule, and `CXX=/nonexistent`
# does the same for C++ (the `cc` crate reads CXX for C++ files, so CC alone
# lets a C++ dependency through on a host with `c++`). `scripts/plant.sh`
# proves both are load-bearing. The binary itself needs cc since 2026-10-08: the
# native SSH client is russh with aws-lc-rs (operator decision).
LIBS="-p podssh-ws -p podssh-relay -p podssh-core -p podssh-terminal -p podssh-probe"

# The format of the code (rustfmt.toml) and clippy's lints: the format needs
# no build. The image has the minimal profile of rustup, so the two
# components are added at each run.
step_lint() {
    run "rustfmt and clippy: the components" rustup component add rustfmt clippy
    # shellcheck disable=SC2086  # $PKGS is a list of flags
    run "the format of the code" cargo fmt $PKGS -- --check
    # shellcheck disable=SC2086
    run "clippy: no warning in any target" cargo clippy --locked --all-targets $PKGS -- -D warnings
    run "clippy: no warning with the Tailscale feature" \
        cargo clippy --locked --all-targets -p podssh-cli -p podssh-ts --features podssh-cli/ts -- -D warnings
}

# The feature `blocking` of podssh-relay (the facade for podbox, T-081) brings
# `pair` and the runners of the reverse road.
step_libs() {
    # shellcheck disable=SC2086  # $LIBS is a list of flags
    run "library crates build with no C compiler" \
        env CC=/nonexistent CXX=/nonexistent cargo build --locked $LIBS --features podssh-relay/blocking

    # shellcheck disable=SC2086
    run "library crates: tests, no C compiler" \
        env CC=/nonexistent CXX=/nonexistent cargo test --locked --no-fail-fast $LIBS --features podssh-relay/blocking

    # The plain ws:// to the loopback (T-068) is behind the feature `plain-ws`:
    # its tests run with the feature, and the binary must never enable it.
    run "plain ws:// to the loopback: test (feature plain-ws, no C compiler)" \
        env CC=/nonexistent CXX=/nonexistent cargo test --locked --no-fail-fast -p podssh-ws --features plain-ws --test plain_loopback
    run "the blocking facade against a stand-in relay (features blocking, plain-ws, no C compiler)" \
        env CC=/nonexistent CXX=/nonexistent cargo test --locked --no-fail-fast -p podssh-relay --features blocking,plain-ws --test blocking_plain
    run "the binary does not enable plain-ws" sh scripts/no-plain-ws.sh
}

# The declared minimum Rust of each crate, checked so that each number stays
# true. Each is read from its manifest, and rustup fetches that toolchain at
# each run into this image, so the C toolchain of aws-lc is the gate's own.
# rust_version MANIFEST sets RV to the version that MANIFEST declares, in this
# shell (a command substitution would lose `failed`). An empty one, or one
# that is not 1.x, fails: `cargo +` with no version would run the default
# toolchain, a false pass.
rust_version() {
    RV=$(tr -d '\r' < "$1" | sed -n 's/^rust-version = "\([0-9.]*\)"$/\1/p')
    case "$RV" in
        1.*) ;;
        *)
            echo "FAIL the rust-version of $1 could not be read"
            failed=1
            RV=unreadable
            ;;
    esac
}

# The workspace's version (podbox's minimum, T-081), for the library crates
# and podssh-todo.
step_msrv() {
    rust_version Cargo.toml
    MSRV=$RV
    run "Rust $MSRV, the declared minimum of the library crates: install" \
        rustup toolchain install "$MSRV" --profile minimal
    # shellcheck disable=SC2086
    run "library crates and podssh-todo: check on Rust $MSRV (no C compiler)" \
        env CC=/nonexistent CXX=/nonexistent cargo "+$MSRV" check --locked $LIBS -p podssh-todo \
            --features podssh-relay/blocking,podssh-relay/plain-ws --all-targets
}

# russh's minimum, which the SSH client and the CLI declare, each on its own.
step_msrv_ssh() {
    rust_version crates/podssh-ssh/Cargo.toml
    SSH_RUST=$RV
    rust_version crates/podssh-cli/Cargo.toml
    CLI_RUST=$RV
    run "Rust $SSH_RUST, the declared minimum of podssh-ssh: install" \
        rustup toolchain install "$SSH_RUST" --profile minimal
    run "podssh-ssh: check on Rust $SSH_RUST" cargo "+$SSH_RUST" check --locked --all-targets -p podssh-ssh
    run "Rust $CLI_RUST, the declared minimum of podssh-cli: install" \
        rustup toolchain install "$CLI_RUST" --profile minimal
    run "podssh-cli: check on Rust $CLI_RUST" cargo "+$CLI_RUST" check --locked --all-targets -p podssh-cli
}

# The fork's minimum, which the Tailscale adapter declares; the CLI with the
# feature `ts` too, which brings the adapter in.
step_msrv_ts() {
    rust_version crates/podssh-ts/Cargo.toml
    TS_RUST=$RV
    run "Rust $TS_RUST, the declared minimum of podssh-ts: install" \
        rustup toolchain install "$TS_RUST" --profile minimal
    run "podssh-ts and podssh-cli with the feature ts: check on Rust $TS_RUST" \
        cargo "+$TS_RUST" check --locked --all-targets -p podssh-ts -p podssh-cli --features podssh-cli/ts
}

# The work record (TODO/): the checker's own tests, where each planted
# disagreement must be found, then the record of this tree. A count, a status
# or a cited line that disagrees fails the gate. Pure Rust, no C.
step_record() {
    run "the work record: the checker's tests (plants included)" \
        env CC=/nonexistent CXX=/nonexistent cargo test --locked --no-fail-fast -p podssh-todo
    # The record's checker reads AGENTS.md for the ids it names, and would pass
    # with the file missing: a copy of the tree without it fails here first.
    run "the tree has AGENTS.md" test -f AGENTS.md
    run "the work record: TODO/ agrees with itself" \
        env CC=/nonexistent CXX=/nonexistent cargo run --locked -q -p podssh-todo -- check
}

step_ssh() {
    run "the SSH client and the CLI (need cc): tests" \
        cargo test --locked --no-fail-fast -p podssh-ssh -p podssh-cli
}

# The Tailscale adapter (feature `ts`) links the vendored tailscale-rs fork,
# which needs cc and cmake (aws-lc-sys). Built and tested on its own.
step_ts() {
    run "Tailscale adapter (feature ts, needs cc): tests" \
        cargo test --locked --no-fail-fast -p podssh-ts -p podssh-cli --features podssh-cli/ts
}

# The shipped artefact, a static musl binary; then the binary against real
# servers, and its man page.
step_release() {
    run "static musl release" \
        env RUSTFLAGS=-Ctarget-feature=+crt-static \
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

    # The binary against real OpenSSH and Dropbear servers (installed with apk
    # into this throwaway container).
    if [ -f "$B" ]; then
        run "interop: OpenSSH and Dropbear" sh scripts/interop.sh "$B"
        cat /tmp/podssh-step.out | grep -E '^(ok|FAIL|skip) |^interop:' | tail -80
    fi

    # The man page against groff and mandoc (installed with apk the same way).
    if [ -f "$B" ]; then
        run "man page: groff and mandoc" sh scripts/interop-man.sh "$B"
        grep -E '^(ok|FAIL) ' /tmp/podssh-step.out
    fi
}

for _s in "$@"; do
    printf '\n=== step %s\n' "$_s"
    "step_$_s"
done

echo
if [ "$failed" -eq 0 ]; then
    echo "podssh: gate green ($*)."
else
    echo "podssh: gate FAILED ($*)."
fi
exit $failed
