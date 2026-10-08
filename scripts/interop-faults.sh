# Faults between podssh and the relay, with real OpenSSH behind them. Sourced
# by scripts/interop.sh once the servers run; uses its ok, bad, $W, $T, $K,
# $KH, $HERE and $BIN. The relay is scripts/fake-relay.py, one instance per
# fault, and the proxy scripts/fake-proxy.py; podssh verifies their TLS
# against a CA made here, exactly as it verifies the real relay's.

echo
echo "== faults (a stand-in relay and proxy, OpenSSH behind them)"
FK="$W/faults"
mkdir -p "$FK"
NAMES="relay-a relay-r503 relay-silent relay-hole relay-dead relay-stall relay-close relay-cap relay-kill"
SAN=$(for n in $NAMES; do printf 'DNS:%s.test,' "$n"; done)
PINS=$(for n in $NAMES; do printf '%s.test=127.0.0.1,' "$n"; done)
SAN=${SAN%,}
PINS=${PINS%,}
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
    "$SAN" >"$FK/ext"
# A config of its own, so no host's default openssl.cnf adds extensions (Git
# for Windows' adds one its own openssl cannot parse).
printf '[req]\ndistinguished_name = dn\n[dn]\n' >"$FK/req.cnf"
if openssl req -config "$FK/req.cnf" -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
        -subj /CN=podssh-test-ca -addext basicConstraints=critical,CA:TRUE \
        -addext keyUsage=critical,keyCertSign,cRLSign -keyout "$FK/ca.key" -out "$FK/ca.pem" >"$FK/openssl.log" 2>&1 \
    && openssl req -config "$FK/req.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=relay.test \
        -keyout "$FK/relay.key" -out "$FK/relay.csr" >>"$FK/openssl.log" 2>&1 \
    && openssl x509 -req -in "$FK/relay.csr" -CA "$FK/ca.pem" -CAkey "$FK/ca.key" -CAcreateserial \
        -days 2 -extfile "$FK/ext" -out "$FK/relay.pem" >>"$FK/openssl.log" 2>&1; then
    :
else
    bad "faults: the test certificates could not be made" "$FK/openssl.log"
fi

for spec in a:normal r503:refuse:503 silent:silent hole:blackhole dead:normal stall:stall:12 \
        close:close:300000:1011 cap:close:1:1009 kill:normal; do
    name=${spec%%:*}
    python3 "$HERE/fake-relay.py" --cert "$FK/relay.pem" --key "$FK/relay.key" --keepalive 2 \
        --port-file "$FK/$name.port" --mode "${spec#*:}" >"$FK/$name.log" 2>&1 &
    echo $! >"$FK/$name.pid"
done
port() { cat "$FK/$1.port" 2>/dev/null; }
tries=0
while [ "$tries" -lt 30 ]; do
    missing=0
    for n in a r503 silent hole dead stall close cap kill; do [ -s "$FK/$n.port" ] || missing=1; done
    [ "$missing" = 0 ] && break
    sleep 1
    tries=$((tries + 1))
done
[ "$missing" = 0 ] || bad "faults: the stand-in relays did not start" "$FK/a.log"
# A relay host that has died: its port now refuses connections.
kill "$(cat "$FK/dead.pid")" 2>/dev/null
python3 "$HERE/fake-proxy.py" --port-file "$FK/proxy.port" --log "$FK/proxy.log" \
    --map "relay-a.test=127.0.0.1:$(port a)" --answer relay-bad.test=502 >"$FK/proxy.out" 2>&1 &
echo $! >"$FK/proxy.pid"
tries=0
while [ ! -s "$FK/proxy.port" ] && [ "$tries" -lt 30 ]; do sleep 1; tries=$((tries + 1)); done

# r RELAYS [ssh arguments...]: podssh ssh through the stand-ins to the
# OpenSSH server on port 2201; $RP, when set, is the proxy to go through.
RP=
RC=
r() {
    _relays=$1
    shift
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY ${RP:+https_proxy=$RP} \
        ${RC:+XDG_CACHE_HOME=$RC} \
        HOME="$W" "$BIN" ssh --relay-host "$_relays" --relay-addr "$PINS" --ca-file "$FK/ca.pem" -p 2201 \
        -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes "$@"
}

# The control: without it, every failover below could pass for a wrong reason.
r "relay-a.test:$(port a)" "$T" 'echo through-the-stand-in' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$FK/out")" = through-the-stand-in ] \
    && ok "faults: the stand-in relay carries a session (control)" || bad "faults: the control: exit $rc" "$FK/err"

files() { n=0; for f in "$@"; do [ -e "$f" ] && n=$((n + 1)); done; echo "$n"; }
for spec in "dead:a relay host that is down" "r503:a relay host answering 503" \
        "silent:a relay host that never answers after TLS" "hole:a relay host that never starts TLS"; do
    name=${spec%%:*}
    # After the dead host, relay-a.test mints the token; a cache of its own
    # shows where the token is filed (GitHub #3).
    RC=
    if [ "$name" = dead ]; then RC="$FK/cache-dead"; fi
    start=$(date +%s)
    r "relay-$name.test:$(port "$name"),relay-a.test:$(port a)" "$T" 'echo failed-over' >"$FK/out" 2>"$FK/err" </dev/null
    rc=$?
    took=$(( $(date +%s) - start ))
    [ "$rc" = 0 ] && [ "$(cat "$FK/out")" = failed-over ] && [ "$took" -lt 60 ] \
        && ok "faults: ${spec#*:}: failed over to the next host (${took}s)" \
        || bad "faults: ${spec#*:}: exit $rc after ${took}s" "$FK/err"
    if [ "$name" = dead ]; then
        on_dead=$(files "$RC/podssh"/relay-token-relay-dead.test*)
        on_a=$(files "$RC/podssh"/relay-token-relay-a.test*)
        [ "$on_dead" = 0 ] && [ "$on_a" = 1 ] \
            && ok "faults: the token minted by the second host is cached for that host, not the first" \
            || bad "faults: token files after the failover: $on_dead for the dead host, $on_a for relay-a.test" "$FK/err"
    fi
done
RC=

RP="http://127.0.0.1:$(port proxy)"
r "relay-bad.test:443,relay-a.test:$(port a)" "$T" 'echo via-the-proxy' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
grep -q "^502 CONNECT relay-bad.test:443" "$FK/proxy.log" && grep -q "^200 CONNECT relay-a.test" "$FK/proxy.log" \
    && [ "$rc" = 0 ] && [ "$(cat "$FK/out")" = via-the-proxy ] \
    && ok "faults: a proxy answering 502 for one relay host: failed over to the next, through the proxy" \
    || bad "faults: proxy 502: exit $rc" "$FK/err"
r "relay-bad.test:443" "$T" true >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
[ "$rc" = 255 ] && grep -q "502" "$FK/err" \
    && ok "faults: with every host behind a 502, exit 255 and the proxy's answer is shown" \
    || bad "faults: only a 502 host: exit $rc" "$FK/err"
RP=

r "relay-close.test:$(port close)" "$T" 'head -c 5000000 /dev/zero' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
got=$(wc -c <"$FK/out")
[ "$rc" = 255 ] && grep -q "1011" "$FK/err" && grep -q "write failed: fault injection" "$FK/err" \
    && [ "$got" -lt 5000000 ] \
    && ok "faults: closed mid-transfer with 1011: exit 255 with the relay's reason ($got of 5000000 bytes arrived)" \
    || bad "faults: closed mid-transfer: exit $rc, $got bytes" "$FK/err"

env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY HOME="$W" "$BIN" proxy --relay-host "relay-cap.test:$(port cap)" \
    --relay-addr "$PINS" --ca-file "$FK/ca.pem" 127.0.0.1 2201 </dev/null >"$FK/out" 2>"$FK/err"
rc=$?
[ "$rc" = 69 ] && grep -q "1009 session byte cap" "$FK/err" \
    && ok "faults: podssh proxy, closed with 1009: exit 69 with the relay's reason" \
    || bad "faults: podssh proxy and 1009: exit $rc" "$FK/err"

start=$(date +%s)
r "relay-stall.test:$(port stall)" "$T" 'sleep 120' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
took=$(( $(date +%s) - start ))
[ "$rc" = 255 ] && grep -q "pings unanswered" "$FK/err" && [ "$took" -ge 25 ] && [ "$took" -lt 80 ] \
    && ok "faults: a relay that stalls (no frames, no pongs) is declared dead by the ping watcher (${took}s)" \
    || bad "faults: a stalled relay: exit $rc after ${took}s" "$FK/err"

start=$(date +%s)
r "relay-kill.test:$(port kill)" "$T" 'sleep 60' >"$FK/out" 2>"$FK/err" </dev/null &
session=$!
sleep 5
kill "$(cat "$FK/kill.pid")" 2>/dev/null
wait "$session"
rc=$?
took=$(( $(date +%s) - start ))
[ "$rc" = 255 ] && [ "$took" -lt 30 ] && grep -qi "relay" "$FK/err" \
    && ok "faults: the relay host killed mid-session: exit 255 after ${took}s, and the relay is named" \
    || bad "faults: a relay killed mid-session: exit $rc after ${took}s" "$FK/err"

for f in "$FK"/*.pid; do
    kill "$(cat "$f")" 2>/dev/null
done
