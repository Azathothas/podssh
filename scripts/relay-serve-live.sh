#!/bin/sh
# The live check of `podssh relay serve` (T-169), on a GitHub runner: the
# role on the runner's loopback with a certificate of a CA of this run, then
# GitHub's SSH banner through it (tests/proxy_live.rs, which reads
# PODSSH_RELAY, PODSSH_RELAY_ADDR and SSL_CERT_FILE as the binary does), and
# `podssh doctor` against it. The role dials public targets alone and mints a
# token for this run's clients; no token is printed.
#
# With `reverse` (T-427): the role's reverse road instead, the tests of
# tests/node_live.rs that need no long run against it (PODSSH_LIVE_RELAY),
# and, when PODSSH_OLD names the binary of an earlier release, that client's
# `podssh operator` reads GitHub's banner through a node of the role's pair.
#
# With `drops` (T-255): the drops of reverse sockets through the role on
# this runner, by tests/reverse_drops_live.rs until PODSSH_DROPS_UNTIL, where
# no platform restarts the relay's objects: a drop with no Close is the
# path's.
#
# With `layer` (T-173): the role's forward road in the resumable layer, to
# the runner's own sshd at PODSSH_LAYER_SSHD (127.0.0.1:PORT), which takes
# the key of PODSSH_LAYER_KEY: OpenSSH's ssh with podssh proxy as its
# ProxyCommand, then podssh ssh, each with PODSSH_RELAY_LAYER=yes and its
# link through scripts/fake-proxy.py, which cuts each open tunnel every few
# seconds (scripts/relay-serve-layer.sh).
#
# Usage: sh scripts/relay-serve-live.sh PODSSH [reverse|drops|layer]
set -eu

PODSSH=${1:?usage: relay-serve-live.sh PODSSH [reverse|drops|layer]}
MODE=${2:-forward}
HERE=$(cd "$(dirname "$0")" && pwd)
FK=$(mktemp -d)
SAN="DNS:relay-a.test"
ROLE=
PROXY=
cleanup() {
    [ -n "$ROLE" ] && kill "$ROLE" 2>/dev/null
    [ -n "$PROXY" ] && kill "$PROXY" 2>/dev/null
    rm -rf "$FK"
}
trap cleanup EXIT INT TERM

. "$HERE/interop-faults-certs.sh"
[ "$FAULT_CERTS" = made ] || { echo "relay-serve-live: the test certificates were not made" >&2; exit 2; }

# The road in the layer dials the runner's own sshd on the loopback, and
# keeps a lost session for 5 minutes.
EXTRA=
if [ "$MODE" = layer ]; then
    EXTRA="--allow-private --resume-deadline 5m"
fi
# shellcheck disable=SC2086  # $EXTRA is a list of flags
"$PODSSH" relay serve --listen 127.0.0.1:0 --cert "$FK/relay.pem" --key "$FK/relay.key" \
    --port-file "$FK/port" --mint anyone $EXTRA >"$FK/events" 2>"$FK/role.log" &
ROLE=$!
i=0
while [ ! -s "$FK/port" ]; do
    i=$((i + 1))
    [ "$i" -le 100 ] || { echo "relay-serve-live: the role did not start" >&2; cat "$FK/role.log" >&2; exit 1; }
    sleep 0.1
done
PORT=$(cat "$FK/port")
echo "relay-serve-live: podssh relay serve at relay-a.test:$PORT"

if [ "$MODE" = layer ]; then
    . "$HERE/relay-serve-layer.sh"
    exit 0
fi

if [ "$MODE" = drops ]; then
    export PODSSH_LIVE_RELAY="relay-a.test:$PORT" PODSSH_LIVE_RELAY_ADDR="relay-a.test=127.0.0.1" SSL_CERT_FILE="$FK/ca.pem"
    rc=0
    cargo test --locked -p podssh-relay --features pair --test reverse_drops_live -- --ignored --nocapture || rc=$?
    echo "relay-serve-live: the role's last events: $(tail -n 40 "$FK/events" | tr '\n' ' ')"
    [ "$rc" = 0 ] || { echo "relay-serve-live: the drops' run failed (exit $rc)" >&2; cat "$FK/role.log" >&2; exit 1; }
    echo "relay-serve-live: ok"
    exit 0
fi

if [ "$MODE" = reverse ]; then
    export PODSSH_LIVE_RELAY="relay-a.test:$PORT" PODSSH_LIVE_RELAY_ADDR="relay-a.test=127.0.0.1" SSL_CERT_FILE="$FK/ca.pem"
    cargo test --locked -p podssh-cli --test node_live -- --ignored --nocapture --test-threads 1 \
        node_command_serves_a_tcp_target ssh_to_a_node
    if [ -n "${PODSSH_OLD:-}" ]; then
        # An earlier release's client, in a home of its own: the pair that
        # this binary made, its node in front of GitHub's SSH port, and the
        # old `podssh operator`, which must read the server's banner.
        (
            export HOME="$FK/old-home" XDG_CACHE_HOME="$FK/old-home/cache" PODSSH_RELAY_ADDR="relay-a.test=127.0.0.1" PODSSH_TRANSIT=no
            mkdir -p "$HOME"
            "$PODSSH" relay pair old --relay-host "relay-a.test:$PORT" >/dev/null
            "$PODSSH" node old github.com:22 2>"$FK/node.log" &
            NODE=$!
            i=0
            until grep -q online "$FK/node.log"; do
                i=$((i + 1))
                [ "$i" -le 300 ] || { cat "$FK/node.log" >&2; kill "$NODE"; exit 1; }
                sleep 0.1
            done
            rc=0
            (sleep 8) | timeout 60 "$PODSSH_OLD" operator old >"$FK/banner" 2>"$FK/old.log" || rc=$?
            kill "$NODE" 2>/dev/null || true
            "$PODSSH" relay revoke old >/dev/null || true
            if ! head -c 8 "$FK/banner" | grep -q '^SSH-2.0'; then
                echo "relay-serve-live: $("$PODSSH_OLD" --version)'s operator read no banner (exit $rc):" >&2
                cat "$FK/old.log" "$FK/node.log" >&2
                exit 1
            fi
            echo "relay-serve-live: $("$PODSSH_OLD" --version)'s operator read $(head -n 1 "$FK/banner" | tr -d '\r') through a node of the role"
        )
    fi
    echo "relay-serve-live: the role's events: $(tr '\n' ' ' <"$FK/events")"
    echo "relay-serve-live: ok"
    exit 0
fi

export PODSSH_RELAY="relay-a.test:$PORT" PODSSH_RELAY_ADDR="relay-a.test=127.0.0.1" SSL_CERT_FILE="$FK/ca.pem"
cargo test --locked -p podssh-cli --test proxy_live -- --ignored --nocapture
# doctor's relay section: its other checks trust the test's CA alone here
# (--ca-file replaces each root), so the public DERP servers fail them, as
# they would behind such a CA anywhere; the role's own lines must each be ok.
"$PODSSH" doctor --relay-host "relay-a.test:$PORT" --relay-addr relay-a.test=127.0.0.1 --ca-file "$FK/ca.pem" \
    >"$FK/doctor" 2>&1 || true
for check in relay token forward clock; do
    grep -Eq "^  ok +$check " "$FK/doctor" || { cat "$FK/doctor"; echo "relay-serve-live: doctor's $check is not ok" >&2; exit 1; }
done
grep -E "^  (ok|FAIL|\?\?\?\?) +(relay|token|forward|clock) " "$FK/doctor"
echo "relay-serve-live: the role's events: $(tr '\n' ' ' <"$FK/events")"
echo "relay-serve-live: ok"
