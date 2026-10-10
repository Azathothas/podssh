#!/bin/sh
# The acceptance of the Tailscale adapter over DERP. Run it in the build image, through the wrapper:
#   sh scripts/dev.sh run -- 'sh /work/scripts/ts-derp-prove.sh'
#
# Run it through the wrapper rather than directly. The example bounds its own
# 30 s handshake, but the cargo build phase has no bound of its own and
# `dev.sh run`'s `--timeout 30m` is what stops a hung build or a hung network
# call; nothing here can bound itself POSIXly.
#
# The vendored fork under vendor/tailscale-rs is its own cargo workspace;
# podssh's gate does not build it, so this script is the one place its proofs
# run. Every exit code is echoed on its own line, never through a pipe.
#
# **Three outcomes, not two.** The example distinguishes 0 (expected), 1
# (wrong outcome) and 3 (`????` — the relay answered 429/503 or nothing, so no
# result was obtained). Flattening 3 into 1 reports a rate-limited relay as a
# failed proof and sends the next session hunting a defect that is not there.
# This script's exit codes are therefore the example's: 0 all green, 1 a real
# failure, 3 inconclusive.
set -u

# **The verdict is a function so that it has a failure test.**
#
# `--verdict-only A B C` runs it over three exit codes with no cargo and no
# network, which is the only way this branch can be proven on a host that cannot
# build the vendored fork. MEASURED 2026-10-05, this machine, Git Bash on
# Windows: `dash scripts/ts-derp-prove.sh --verdict-only 0 3 0` prints the
# inconclusive message and exits 3, `--verdict-only 0 1 0` exits 1, and
# `--verdict-only 0 0 0` exits 0.
verdict() {
    _m1=$1
    _m3=$2
    _neg=$3
    _failed=0
    _inconclusive=0
    for _rc in "$_m1" "$_m3" "$_neg"; do
        [ "$_rc" -eq 0 ] && continue
        if [ "$_rc" -eq 3 ]; then
            _inconclusive=1
        else
            _failed=1
        fi
    done
    # A real failure outranks an inconclusive step: a wrong outcome is a
    # defect whether or not another proof could not be read.
    if [ "$_failed" -eq 1 ]; then
        echo "ts-derp-prove: at least one proof failed" >&2
        return 1
    fi
    if [ "$_inconclusive" -eq 1 ]; then
        echo "ts-derp-prove: INCONCLUSIVE - a live step answered 429/503 or nothing, so" >&2
        echo "ts-derp-prove: no result was obtained. This is not a failure and it is not a" >&2
        echo "ts-derp-prove: pass; re-run when the relay is available." >&2
        return 3
    fi
    echo "ts-derp-prove: all green"
    return 0
}

if [ "${1:-}" = "--verdict-only" ]; then
    verdict "${2:-}" "${3:-}" "${4:-}"
    exit $?
fi

# Cap parallelism: this builds the whole vendored fork (aws-lc-sys included),
# and uncapped cargo builds have nearly exhausted the developer machine's
# memory before (2026-10-07).
: "${CARGO_BUILD_JOBS:=4}"
export CARGO_BUILD_JOBS

if ! command -v cmake >/dev/null 2>&1; then
    # aws-lc-sys (via ts_tls_util) needs cmake; the build image is rust:1-alpine.
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache cmake make perl >/dev/null || exit 71
    else
        echo "ts-derp-prove: cmake is missing and there is no apk to install it." >&2
        echo "ts-derp-prove: this script expects the build image (.github/images/build/Dockerfile)." >&2
        exit 71
    fi
fi

cd "${TS_PROVE_WORK:-/work}/vendor/tailscale-rs" || exit 71

echo "== M1: the ClientInfo wire bytes the relay's mesh check depends on =="
cargo test -p ts_derp --test wire_compat
m1=$?
echo "M1_EXIT=$m1"

# Offline too, so a failure is a failure of M1: the DERP dial over WebSocket
# goes through the proxy, and the proxy's no_proxy list and credentials are
# read as podssh reads them (podssh T-103, patch 0017).
echo "== M1b: the DERP dial over WebSocket through a fake proxy =="
cargo test -p ts_derp --test ws_proxy_dial
m1b=$?
echo "M1B_EXIT=$m1b"
cargo test -p ts_http_util --test proxy
m1c=$?
echo "M1C_EXIT=$m1c"
if [ "$m1b" -ne 0 ] || [ "$m1c" -ne 0 ]; then
    m1=1
fi

echo "== M3: live DERP-over-WebSocket handshake (expect close 1008 not authorized) =="
cargo run -p ts_derp --example ws_handshake -- --host tcp.ts.relay.ajam.dev
m3=$?
echo "M3_EXIT=$m3"

echo "== M3 negative control: no derp subprotocol (expect HTTP 426) =="
cargo run -p ts_derp --example ws_handshake -- --host tcp.ts.relay.ajam.dev --no-subprotocol
neg=$?
echo "NEG_EXIT=$neg"

verdict "$m1" "$m3" "$neg"
exit $?
