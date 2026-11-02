#!/bin/sh
# The live check of `podssh relay serve` (T-169), on a GitHub runner: the
# role on the runner's loopback with a certificate of a CA of this run, then
# GitHub's SSH banner through it (tests/proxy_live.rs, which reads
# PODSSH_RELAY, PODSSH_RELAY_ADDR and SSL_CERT_FILE as the binary does), and
# `podssh doctor` against it. The role dials public targets alone and mints a
# token for this run's clients; no token is printed.
#
# Usage: sh scripts/relay-serve-live.sh PODSSH
set -eu

PODSSH=${1:?usage: relay-serve-live.sh PODSSH}
HERE=$(cd "$(dirname "$0")" && pwd)
FK=$(mktemp -d)
SAN="DNS:relay-a.test"
ROLE=
cleanup() {
    [ -n "$ROLE" ] && kill "$ROLE" 2>/dev/null
    rm -rf "$FK"
}
trap cleanup EXIT INT TERM

. "$HERE/interop-faults-certs.sh"
[ "$FAULT_CERTS" = made ] || { echo "relay-serve-live: the test certificates were not made" >&2; exit 2; }

"$PODSSH" relay serve --listen 127.0.0.1:0 --cert "$FK/relay.pem" --key "$FK/relay.key" \
    --port-file "$FK/port" --mint anyone >"$FK/events" 2>"$FK/role.log" &
ROLE=$!
i=0
while [ ! -s "$FK/port" ]; do
    i=$((i + 1))
    [ "$i" -le 100 ] || { echo "relay-serve-live: the role did not start" >&2; cat "$FK/role.log" >&2; exit 1; }
    sleep 0.1
done
PORT=$(cat "$FK/port")
echo "relay-serve-live: podssh relay serve at relay-a.test:$PORT"

export PODSSH_RELAY="relay-a.test:$PORT" PODSSH_RELAY_ADDR="relay-a.test=127.0.0.1" SSL_CERT_FILE="$FK/ca.pem"
cargo test --locked -p podssh-cli --test proxy_live -- --ignored --nocapture
"$PODSSH" doctor --relay-host "relay-a.test:$PORT" --relay-addr relay-a.test=127.0.0.1 --ca-file "$FK/ca.pem" \
    >"$FK/doctor" 2>&1 || { cat "$FK/doctor"; echo "relay-serve-live: doctor failed" >&2; exit 1; }
grep -i "relay" "$FK/doctor"
echo "relay-serve-live: the role's events: $(tr '\n' ' ' <"$FK/events")"
echo "relay-serve-live: ok"
