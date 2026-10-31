#!/bin/sh
# scripts/interop-derp.sh - the DERP road of podssh-relay (T-349) through
# Tailscale's derper, a DERP server that podssh did not write, in Podman:
# DERP's handshake over its WebSocket and 8 MiB each way over one link with
# equal digests; a client that gives up on a key that is not on the server;
# and a session of the resumable layer, echoed whole.
#
#   sh scripts/interop-derp.sh
#
# derper is built from its tag with Go, in the image that
# images/derper/Dockerfile pins, and serves TLS on the loopback with the
# certificate that it makes for an IP address (cmd/derper/cert.go, its
# manual mode); the tests trust that certificate alone, and use no proxy.
# Run it on a host with podman, not in the gate's container: a rootless
# podman there stopped the distribution that ran it (2026-10-13). The tests
# build natively, with CARGO_BUILD_JOBS=4 unless it is set. Each check
# prints ok or FAIL; the exit code is 1 when one failed. The planted defect
# of the adapter is in T-349's Done: derper drops nothing here, and the
# stand-in with drops of `--test derp_link` is the test that fails on it.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

TAILSCALE=v1.104.4
IMAGE=localhost/podssh-derper:1.104.4
NAME=podssh-derp-interop
PORT=${PODSSH_DERP_PORT:-45343}
: "${CARGO_BUILD_JOBS:=4}"
export CARGO_BUILD_JOBS

die() {
    echo "interop-derp: $*" >&2
    exit 1
}
image_of() {
    _ref=$(tr -d '\r' <"$1" 2>/dev/null | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in
        *@sha256:*) printf '%s\n' "$_ref" ;;
        *)
            echo "interop-derp: $1 names no image pinned to a digest" >&2
            return 1
            ;;
    esac
}
command -v podman >/dev/null 2>&1 || die "podman is not on PATH"
command -v timeout >/dev/null 2>&1 || die "timeout is not on PATH: every wait here needs a bound"
command -v cargo >/dev/null 2>&1 || die "cargo is not on PATH"
GO_IMAGE=$(image_of "$REPO/images/derper/Dockerfile") || exit 78

W=$(mktemp -d 2>/dev/null || echo "/tmp/podssh-derp-$$")
mkdir -p "$W/certs" || die "cannot use the work directory $W"
remove() {
    podman rm -f "$NAME" >/dev/null 2>&1
}
trap 'remove; rm -rf "$W"' EXIT
timeout 60 podman info >/dev/null 2>&1 || die "podman does not answer"
remove

echo "== derper $TAILSCALE, built from its tag"
printf 'FROM %s\nRUN CGO_ENABLED=0 go install tailscale.com/cmd/derper@%s\n' "$GO_IMAGE" "$TAILSCALE" >"$W/Containerfile"
timeout 1800 podman build -q -t "$IMAGE" -f "$W/Containerfile" "$W" >"$W/build.log" 2>&1 ||
    { cat "$W/build.log"; die "derper did not build"; }

echo "== derper on 127.0.0.1:$PORT, TLS with its own certificate for the address"
timeout 60 podman run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" -v "$W/certs:/certs:Z" "$IMAGE" \
    /go/bin/derper -a :8443 --certmode manual --certdir /certs --hostname 127.0.0.1 \
    --stun=false --http-port=-1 -c /certs/derper.key >"$W/run.log" 2>&1 ||
    { cat "$W/run.log"; die "derper did not start"; }
CA="$W/certs/127.0.0.1.crt"
tries=0
while [ ! -s "$CA" ]; do
    tries=$((tries + 1))
    if [ "$tries" -ge 60 ]; then
        podman logs "$NAME" 2>&1 | tail -20
        die "derper wrote no certificate within 30 s"
    fi
    sleep 0.5
done
wait_port "$PORT"

echo "== the tests, built once"
cd "$REPO" || die "no repository at $REPO"
timeout 1800 cargo test -q -p podssh-relay --features derp --test derp_link --no-run >"$W/cargo.log" 2>&1 ||
    { tail -40 "$W/cargo.log"; die "the tests of the DERP road did not build"; }

# through NAME: the ignored test NAME of derp_link against this derper; its
# exit code, its output in $W/NAME.log.
through() {
    timeout 300 env PODSSH_DERP_TEST_SERVER="127.0.0.1:$PORT" PODSSH_DERP_TEST_CA="$CA" \
        cargo test -q -p podssh-relay --features derp --test derp_link -- --ignored --exact "$1" \
        >"$W/$1.log" 2>&1
}

echo "== the DERP road through derper"
through through_derper_eight_mib_go_both_ways
rc=$?
[ "$rc" = 0 ] && ok derp.transfer "8 MiB each way over one link through derper, with equal digests" ||
    bad derp.transfer "exit $rc" "$W/through_derper_eight_mib_go_both_ways.log"
through through_derper_a_node_that_is_not_there_is_not_answered
rc=$?
[ "$rc" = 0 ] && ok derp.absent "a client gives up on a key that is not on derper, within its limit" ||
    bad derp.absent "exit $rc" "$W/through_derper_a_node_that_is_not_there_is_not_answered.log"
through through_derper_a_session_of_the_layer_echoes_two_mib
rc=$?
[ "$rc" = 0 ] && ok derp.layer "a session of the resumable layer through derper, 2 MiB echoed whole" ||
    bad derp.layer "exit $rc" "$W/through_derper_a_session_of_the_layer_echoes_two_mib.log"

podman logs "$NAME" >"$W/derper.log" 2>&1
echo "interop-derp: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
