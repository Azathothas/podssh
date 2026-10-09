# podssh cp goes on after a broken connection (T-136). Sourced by
# scripts/interop-cp.sh while its servers run (2201 with SFTP, 2207 with no
# SFTP), after scripts/interop-faults.sh made its CA and certificate ($FK,
# $PINS). Two stand-in relays end each session after 1,500,000 bytes: one
# counts the bytes from the target, and one both ways, as the relay counts
# its cap. A third behaves, for a copy that SIGINT stops. Uses ok, bad, sum,
# $W, $T, $K, $KH, $BIN, $HERE, $CW and $RD.

echo
echo "== cp goes on after a broken connection"
RW="$CW/resume"
mkdir -p "$RW/cache" "$RW/down"
# The fourth, under the certificate's name relay-kill, ends each session at
# 4,000,000 bytes both ways with 1009, as the relay's cap does (T-137).
for spec in close:close:1500000:1011 cap:closeall:1500000:1011 a:normal kill:closeall:4000000:1009; do
    name=${spec%%:*}
    python3 "$HERE/fake-relay.py" --cert "$FK/relay.pem" --key "$FK/relay.key" --keepalive 2 \
        --port-file "$RW/$name.port" --mode "${spec#*:}" >"$RW/$name.log" 2>&1 &
    echo $! >"$RW/$name.pid"
done
tries=0
while [ "$tries" -lt 30 ]; do
    [ -s "$RW/close.port" ] && [ -s "$RW/cap.port" ] && [ -s "$RW/a.port" ] && [ -s "$RW/kill.port" ] && break
    sleep 1
    tries=$((tries + 1))
done

# rcp RELAY PORT [cp arguments...]: podssh cp through the stand-in relay
# RELAY to the server on PORT, with a cache of its own for the side files.
rcp() {
    _relay=$1
    _port=$2
    shift 2
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY XDG_CACHE_HOME="$RW/cache" \
        HOME="$W" "$BIN" cp --relay-host "relay-$_relay.test:$(cat "$RW/$_relay.port")" --relay-addr "$PINS" \
        --ca-file "$FK/ca.pem" -P "$_port" -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes $K --timeout 300s "$@"
}
# went FILE: how many times -v said that a copy went on at an offset.
went() { grep -c "continuing .* at byte [1-9]" "$1"; }

# Down, then up, of 5,000,000 bytes, on each road: 4 sessions or more, and
# -v names each offset.
for port in 2201 2207; do
    src=f5000000
    [ "$port" = 2207 ] && src=x2207-5000000
    rcp close "$port" -v "$T:cp/$src" "$RW/down/d$port" >/dev/null 2>"$RW/err"
    rc=$?
    n=$(went "$RW/err")
    [ "$rc" = 0 ] && [ "$(sum "$RD/$src")" = "$(sum "$RW/down/d$port")" ] && [ "$n" -ge 3 ] \
        && ok "cp down on port $port through a relay that cuts each 1.5 MB: equal digests, $n continuations" \
        || bad "cp down on port $port through a relay that cuts: exit $rc, $n continuations" "$RW/err"
    head -c 5000000 /dev/urandom >"$RW/u$port"
    rcp cap "$port" -v "$RW/u$port" "$T:cp/r-up$port" >/dev/null 2>"$RW/err"
    rc=$?
    n=$(went "$RW/err")
    [ "$rc" = 0 ] && [ "$(sum "$RW/u$port")" = "$(sum "$RD/r-up$port")" ] && [ "$n" -ge 3 ] \
        && ok "cp up on port $port through a relay that cuts each 1.5 MB both ways: equal digests, $n continuations" \
        || bad "cp up on port $port through a relay that cuts: exit $rc, $n continuations" "$RW/err"
done

# A copy up that SIGINT stops goes on when the same command runs again. A
# job that sh starts in the background ignores SIGINT, so python3 puts its
# default back and becomes podssh; a second python3 sends the SIGINT once the
# side file holds an offset.
head -c 50000000 /dev/urandom >"$RW/big"
# shellcheck disable=SC2086
python3 -c 'import os, signal, sys; signal.signal(signal.SIGINT, signal.SIG_DFL); os.execvp(sys.argv[1], sys.argv[1:])' \
    env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY XDG_CACHE_HOME="$RW/cache" \
    HOME="$W" "$BIN" cp --relay-host "relay-a.test:$(cat "$RW/a.port")" --relay-addr "$PINS" \
    --ca-file "$FK/ca.pem" -P 2201 -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new \
    -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes $K --timeout 300s \
    "$RW/big" "$T:cp/r-big" >/dev/null 2>"$RW/err1" &
copier=$!
python3 - "$copier" "$RW/cache/podssh" <<'EOF'
import glob, os, re, signal, sys, time
pid, cache = int(sys.argv[1]), sys.argv[2]
deadline = time.time() + 120
while time.time() < deadline:
    for name in glob.glob(os.path.join(cache, "podssh-cp-*.resume")):
        try:
            with open(name) as f:
                if re.search('"offset":[1-9]', f.read()):
                    os.kill(pid, signal.SIGINT)
                    sys.exit(0)
        except OSError:
            pass
    time.sleep(0.05)
sys.exit(1)
EOF
wait "$copier"
first=$?
rcp a 2201 -v "$RW/big" "$T:cp/r-big" >/dev/null 2>"$RW/err2"
rc=$?
[ "$first" != 0 ] && [ "$rc" = 0 ] && [ "$(went "$RW/err2")" -ge 1 ] && [ "$(sum "$RW/big")" = "$(sum "$RD/r-big")" ] \
    && ok "cp stopped by SIGINT (exit $first) goes on at an offset when run again: equal digests" \
    || bad "cp stopped by SIGINT and run again: exit $first, then $rc" "$RW/err2"

# Before the relay's limits (T-137): with a budget of 3,000,000 bytes, 10,000,000
# go up and down through the relay that ends each session at 4,000,000 with
# 1009, in new sessions that podssh opens first: no break, and no wait.
head -c 10000000 /dev/urandom >"$RW/b10"
export PODSSH_SESSION_BUDGET=3000000
rcp kill 2201 -v "$RW/b10" "$T:cp/r-b10" >/dev/null 2>"$RW/err"
rc=$?
n=$(grep -c "near its limits" "$RW/err")
[ "$rc" = 0 ] && [ "$(sum "$RW/b10")" = "$(sum "$RD/r-b10")" ] && [ "$n" -ge 3 ] && ! grep -q "a new connection in" "$RW/err" \
    && ok "cp up under a budget of 3,000,000 bytes: $n new sessions before the cap, no break" \
    || bad "cp up under a budget: exit $rc, $n new sessions" "$RW/err"
rcp kill 2201 -v "$T:cp/r-b10" "$RW/down/b10" >/dev/null 2>"$RW/err"
rc=$?
n=$(grep -c "near its limits" "$RW/err")
[ "$rc" = 0 ] && [ "$(sum "$RW/b10")" = "$(sum "$RW/down/b10")" ] && [ "$n" -ge 3 ] && ! grep -q "a new connection in" "$RW/err" \
    && ok "cp down under a budget of 3,000,000 bytes: $n new sessions before the cap, no break" \
    || bad "cp down under a budget: exit $rc, $n new sessions" "$RW/err"
unset PODSSH_SESSION_BUDGET

# A key that a passphrase opens is asked for once, however many sessions the
# copy takes (T-137): each later session uses the key kept for the run.
printf '#!/bin/sh\necho x >>"%s"\necho "open sesame"\n' "$RW/asked" >"$RW/askpass-count"
chmod 700 "$RW/askpass-count"
: >"$RW/asked"
env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY XDG_CACHE_HOME="$RW/cache" HOME="$W" \
    SSH_ASKPASS="$RW/askpass-count" SSH_ASKPASS_REQUIRE=force "$BIN" cp \
    --relay-host "relay-close.test:$(cat "$RW/close.port")" --relay-addr "$PINS" --ca-file "$FK/ca.pem" -P 2201 \
    -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes \
    -i "$W/id_enc" --timeout 300s -v "$T:cp/f5000000" "$RW/down/enc" </dev/null >/dev/null 2>"$RW/err"
rc=$?
asked=$(wc -l <"$RW/asked")
[ "$rc" = 0 ] && [ "$asked" = 1 ] && [ "$(went "$RW/err")" -ge 3 ] && [ "$(sum "$RD/f5000000")" = "$(sum "$RW/down/enc")" ] \
    && ok "cp over sessions that the relay cuts asks for a key's passphrase once" \
    || bad "cp with an encrypted key over sessions that the relay cuts: exit $rc, asked $asked times" "$RW/err"

# Nothing stays behind: no temporary file, and no side file.
if find "$RD" "$RW/down" -name '*.podssh-*.part' | grep -q . || ls "$RW"/cache/podssh/podssh-cp-*.resume >/dev/null 2>&1; then
    bad "cp went on: a temporary or side file stayed"
    find "$RD" "$RW/down" "$RW/cache" -name '*.part' -o -name '*.resume'
else
    ok "cp went on: no temporary file and no side file stayed"
fi
for name in close cap a kill; do
    [ -f "$RW/$name.pid" ] && kill "$(cat "$RW/$name.pid")" 2>/dev/null
done
