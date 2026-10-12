# Faults between podssh and the relay, with real OpenSSH behind them. Sourced
# by scripts/interop.sh once the servers run; uses its ok, bad, $W, $T, $K,
# $KH, $HERE and $BIN. The relay is scripts/fake-relay.py, one instance per
# fault, and the proxy scripts/fake-proxy.py; podssh verifies their TLS
# against a CA made here, exactly as it verifies the real relay's.

echo
echo "== faults (a stand-in relay and proxy, OpenSSH behind them)"
FK="$W/faults"
mkdir -p "$FK"
NAMES="relay-a relay-r503 relay-silent relay-hole relay-dead relay-stall relay-close relay-cap relay-kill relay-hshake
relay-delay relay-jitter relay-rate relay-cut relay-persist relay-dropfirst relay-dropafter relay-tls12 relay-tunnel"
SAN=$(for n in $NAMES; do printf 'DNS:%s.test,' "$n"; done)
PINS=$(for n in $NAMES; do printf '%s.test=127.0.0.1,' "$n"; done)
SAN=${SAN%,}
PINS=${PINS%,}
# Two hosts of the default relay's deployment, which share one token (T-220).
DEPLOYED="tcp-test-a.ssh.relay.ajam.dev tcp-test-b.ssh.relay.ajam.dev"
for n in $DEPLOYED; do
    SAN="$SAN,DNS:$n"
    PINS="$PINS,$n=127.0.0.1"
done
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
    ok faults.certs "the test certificates are made"
else
    bad faults.certs "the test certificates could not be made" "$FK/openssl.log"
fi

# The shapes of T-203: 2 s each way, a jitter of 0 to 1.5 s, 64 KiB/s, and
# the connection ended with no Close after 1,000,000 bytes.
for spec in a:normal r503:refuse:503 silent:silent hole:blackhole dead:normal stall:stall:12 \
        close:close:300000:1011 cap:close:1:1009 kill:normal hshake:close:1:1011 \
        delay:delay:2000 jitter:jitter:0:1500:7 rate:rate:65536 cut:cut:1000000 persist:normal \
        dropfirst:dropfirst:20:1011 dropafter:dropfirstat:3:1011 tls12:tls12 slowopen:slowopen:500 tunnel:normal; do
    name=${spec%%:*}
    python3 "$HERE/fake-relay.py" --cert "$FK/relay.pem" --key "$FK/relay.key" --keepalive 2 \
        --port-file "$FK/$name.port" --mode "${spec#*:}" >"$FK/$name.log" 2>&1 &
    echo $! >"$FK/$name.pid"
done
port() { cat "$FK/$1.port" 2>/dev/null; }
tries=0
while [ "$tries" -lt 30 ]; do
    missing=0
    for n in a r503 silent hole dead stall close cap kill hshake delay jitter rate cut persist dropfirst dropafter tls12 \
            slowopen tunnel; do
        [ -s "$FK/$n.port" ] || missing=1
    done
    [ "$missing" = 0 ] && break
    sleep 1
    tries=$((tries + 1))
done
[ "$missing" = 0 ] && ok faults.standins "the stand-in relays started" \
    || bad faults.standins "the stand-in relays did not start" "$FK/a.log"
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
    ${as_job:-} env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY ${RP:+https_proxy=$RP} \
        ${RC:+XDG_CACHE_HOME=$RC} \
        HOME="$W" "$BIN" ssh --relay-host "$_relays" --relay-addr "$PINS" --ca-file "$FK/ca.pem" -p 2201 \
        -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes "$@"
}

# The control: without it, every failover below could pass for a wrong reason.
r "relay-a.test:$(port a)" "$T" 'echo through-the-stand-in' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$FK/out")" = through-the-stand-in ] \
    && ok faults.control "the stand-in relay carries a session (control)" \
    || bad faults.control "the control: exit $rc" "$FK/err"

# T-067: a relay host behind a proxy that speaks only TLS 1.2.
r "relay-tls12.test:$(port tls12)" "$T" 'echo over-tls12' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$FK/out")" = over-tls12 ] \
    && ok faults.tls12 "a stand-in relay that speaks only TLS 1.2 carries a session" \
    || bad faults.tls12 "TLS 1.2: exit $rc" "$FK/err"

files() { n=0; for f in "$@"; do [ -e "$f" ] && n=$((n + 1)); done; echo "$n"; }
for spec in "dead:a relay host that is down" "r503:a relay host answering 503"; do
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
        && ok "faults.failover.${spec%%:*}" "${spec#*:}: failed over to the next host (${took}s)" \
        || bad "faults.failover.${spec%%:*}" "${spec#*:}: exit $rc after ${took}s" "$FK/err"
    if [ "$name" = dead ]; then
        on_dead=$(files "$RC/podssh"/relay-token-relay-dead.test*)
        on_a=$(files "$RC/podssh"/relay-token-relay-a.test*)
        [ "$on_dead" = 0 ] && [ "$on_a" = 1 ] \
            && ok faults.failover.token_cache \
                "the token minted by the second host is cached for that host, not the first" \
            || bad faults.failover.token_cache \
                "token files after the failover: $on_dead for the dead host, $on_a for relay-a.test" "$FK/err"
    fi
done
RC=

# T-220: a first host that says nothing, in each mode of failover. The next
# host starts after 2 s (staggered), at once (parallel), or when the first
# host's step of 5 s ends (serial). Each run has a cache of its own: a host
# that failed in a run before would be tried last (T-059).
for spec in staggered:5 parallel:5 serial:10; do
    mode=${spec%%:*}
    for case in silent hole; do
        RC="$FK/cache-$mode-$case"
        start=$(date +%s)
        r "relay-$case.test:$(port "$case"),relay-a.test:$(port a)" --relay-failover "$mode" "$T" 'echo failed-over' \
            >"$FK/out" 2>"$FK/err" </dev/null
        rc=$?
        took=$(( $(date +%s) - start ))
        [ "$rc" = 0 ] && [ "$(cat "$FK/out")" = failed-over ] && [ "$took" -lt "${spec#*:}" ] \
            && ok "faults.failover_mode.${spec%%:*}.${case}" "$mode, a $case first host: the next host in ${took}s" \
            || bad "faults.failover_mode.${spec%%:*}.${case}" "$mode, a $case first host: exit $rc after ${took}s" \
                "$FK/err"
    done
done
RC=

# T-059: a host that failed is tried last in the next run, also in a list
# that the user named, with a note; one alone in its list is still tried.
RC="$FK/cache-recorded"
for run in first second; do
    start=$(date +%s)
    r "relay-silent.test:$(port silent),relay-a.test:$(port a)" --relay-failover serial "$T" 'echo failed-over' \
        >"$FK/out" 2>"$FK/err" </dev/null
    rc=$?
    took=$(( $(date +%s) - start ))
    [ "$rc" = 0 ] || break
done
[ "$run" = second ] && [ "$rc" = 0 ] && [ "$took" -lt 3 ] && grep -q "trying relay-silent.test last: it failed" "$FK/err" \
    && ok faults.recorded.reorder "a silent host that failed is tried last by the next run, which took ${took}s" \
    || bad faults.recorded.reorder "the $run run: exit $rc after ${took}s" "$FK/err"
r "relay-dead.test:$(port dead),relay-a.test:$(port a)" "$T" true >"$FK/out" 2>"$FK/err" </dev/null
r "relay-dead.test:$(port dead)" "$T" true >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
[ "$rc" = 255 ] && grep -q "could not connect to relay-dead.test" "$FK/err" && ! grep -q " last: it failed" "$FK/err" \
    && ok faults.recorded.still_tried "a host that failed, alone in its list, is still tried" \
    || bad faults.recorded.still_tried "the recorded host alone: exit $rc" "$FK/err"
RC=

# Two hosts of one deployment, in parallel, the first opening 500 ms after
# the second: one token is minted for both, the first is kept, and the
# second gets a Close. An empty cache of its own makes the run mint.
events() { grep -c "^$1" "$FK/slowopen.log" "$FK/a.log" | awk -F: '{n += $NF} END {print n + 0}'; }
mints=$(events mint)
closes=$(grep -c '^close ' "$FK/a.log")
RC="$FK/cache-deployed"
r "tcp-test-a.ssh.relay.ajam.dev:$(port slowopen),tcp-test-b.ssh.relay.ajam.dev:$(port a)" --relay-failover parallel \
    "$T" 'echo one-session' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
RC=
sleep 1
mints=$(( $(events mint) - mints ))
closes=$(( $(grep -c '^close ' "$FK/a.log") - closes ))
[ "$rc" = 0 ] && [ "$(cat "$FK/out")" = one-session ] && [ "$mints" = 1 ] && [ "$closes" = 1 ] \
    && ok faults.failover_mode.one_mint "parallel, two hosts of one deployment: one mint, and the other session closed" \
    || bad faults.failover_mode.one_mint "parallel, one deployment: exit $rc, $mints mints, $closes closes" "$FK/err"

RP="http://127.0.0.1:$(port proxy)"
r "relay-bad.test:443,relay-a.test:$(port a)" "$T" 'echo via-the-proxy' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
grep -q "^502 CONNECT relay-bad.test:443" "$FK/proxy.log" && grep -q "^200 CONNECT relay-a.test" "$FK/proxy.log" \
    && [ "$rc" = 0 ] && [ "$(cat "$FK/out")" = via-the-proxy ] \
    && ok faults.proxy_502.failover \
        "a proxy answering 502 for one relay host: failed over to the next, through the proxy" \
    || bad faults.proxy_502.failover "proxy 502: exit $rc" "$FK/err"
r "relay-bad.test:443" "$T" true >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
[ "$rc" = 255 ] && grep -q "502" "$FK/err" \
    && ok faults.proxy_502.every_host "with every host behind a 502, exit 255 and the proxy's answer is shown" \
    || bad faults.proxy_502.every_host "only a 502 host: exit $rc" "$FK/err"
RP=

r "relay-close.test:$(port close)" "$T" 'head -c 5000000 /dev/zero' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
got=$(wc -c <"$FK/out")
[ "$rc" = 255 ] && grep -q "1011" "$FK/err" && grep -q "write failed: fault injection" "$FK/err" \
    && [ "$got" -lt 5000000 ] \
    && ok faults.close_1011.transfer \
        "closed mid-transfer with 1011: exit 255 with the relay's reason ($got of 5000000 bytes arrived)" \
    || bad faults.close_1011.transfer "closed mid-transfer: exit $rc, $got bytes" "$FK/err"

# A drop during the SSH handshake (GitHub #17): the first line names the hop
# that broke, and keeps the relay's code and reason as the relay wrote them.
r "relay-hshake.test:$(port hshake)" "$T" true >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
first=$(head -n 1 "$FK/err")
want="the relay lost its connection to 127.0.0.1:2201 (relay close 1011: write failed: fault injection)"
case $first in *"$want"*) named=yes ;; *) named=no ;; esac
[ "$rc" = 255 ] && [ "$named" = yes ] && ! grep -q "closed unexpectedly" "$FK/err" \
    && ok faults.close_1011.handshake \
        "closed with 1011 during the handshake: the first line names the relay's link to the target" \
    || bad faults.close_1011.handshake "closed during the handshake: exit $rc; first line: $first" "$FK/err"

env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY HOME="$W" "$BIN" proxy --relay-host "relay-cap.test:$(port cap)" \
    --relay-addr "$PINS" --ca-file "$FK/ca.pem" 127.0.0.1 2201 </dev/null >"$FK/out" 2>"$FK/err"
rc=$?
[ "$rc" = 69 ] && grep -q "1009 session byte cap" "$FK/err" \
    && ok faults.close_1009.podssh_proxy "podssh proxy, closed with 1009: exit 69 with the relay's reason" \
    || bad faults.close_1009.podssh_proxy "podssh proxy and 1009: exit $rc" "$FK/err"

start=$(date +%s)
r "relay-stall.test:$(port stall)" "$T" 'sleep 120' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
took=$(( $(date +%s) - start ))
[ "$rc" = 255 ] && grep -q "pings unanswered" "$FK/err" && [ "$took" -ge 25 ] && [ "$took" -lt 80 ] \
    && ok faults.stall "a relay that stalls (no frames, no pongs) is declared dead by the ping watcher (${took}s)" \
    || bad faults.stall "a stalled relay: exit $rc after ${took}s" "$FK/err"

start=$(date +%s)
r "relay-kill.test:$(port kill)" "$T" 'sleep 60' >"$FK/out" 2>"$FK/err" </dev/null &
session=$!
sleep 5
kill "$(cat "$FK/kill.pid")" 2>/dev/null
wait "$session"
rc=$?
took=$(( $(date +%s) - start ))
[ "$rc" = 255 ] && [ "$took" -lt 30 ] && grep -qi "relay" "$FK/err" \
    && ok faults.kill "the relay host killed mid-session: exit 255 after ${took}s, and the relay is named" \
    || bad faults.kill "a relay killed mid-session: exit $rc after ${took}s" "$FK/err"

# --persist (T-178): the first relay host dies under a tmux session; podssh
# connects again through the next host and attaches the same session, whose
# variable is still set. Then, with tmux off PATH, it refuses and names it.
_term=${TERM-}
TERM=xterm
export TERM
{
    sleep 4
    printf 'MARK=kept\n'
    sleep 2
    kill "$(cat "$FK/persist.pid")" 2>/dev/null
    sleep 12
    # shellcheck disable=SC2016  # $MARK is the far shell's
    printf 'echo M=$MARK\n'
    sleep 3
    printf 'tmux kill-session\n'
    sleep 3
} | r "relay-persist.test:$(port persist),relay-a.test:$(port a)" --persist "$T" >"$FK/out" 2>"$FK/err"
rc=$?
[ "$rc" = 0 ] && grep -q 'M=kept' "$FK/out" && grep -q 'connecting again' "$FK/err" \
    && ok faults.persist.reattach \
        "--persist: a relay host killed under tmux, and the same session attached through the next" \
    || bad faults.persist.reattach "--persist after a killed relay host: exit $rc" "$FK/err"
tmuxbin=$(command -v tmux)
if [ -n "$tmuxbin" ] && mv "$tmuxbin" "$tmuxbin.off"; then
    r "relay-a.test:$(port a)" --persist "$T" </dev/null >"$FK/out" 2>"$FK/err"
    rc=$?
    mv "$tmuxbin.off" "$tmuxbin"
    [ "$rc" = 255 ] && grep -q 'no tmux on PATH' "$FK/err" \
        && ok faults.persist.no_tmux "--persist with tmux off PATH: exit 255, and tmux is named" \
        || bad faults.persist.no_tmux "--persist with no tmux: exit $rc" "$FK/err"
else
    bad faults.persist.no_tmux "--persist: tmux is not in the image" /dev/null
fi
if [ -n "$_term" ]; then TERM=$_term; else unset TERM; fi

# --persist -N (T-042): the first relay host dies under a session that only
# carries a -R; podssh connects again through the next host and asks for it
# again, and OpenSSH's port 2290 (the one PermitListen allows) reaches
# Dropbear through the new connection.
# tunnel_banner SECONDS: the first line of a connection to port 2290, tried
# every 0.2 s until it is Dropbear's or the time is up.
tunnel_banner() {
    timeout $(($1 + 10)) python3 - "$1" <<'EOF'
import socket, sys, time
limit = time.time() + int(sys.argv[1])
line = ""
while time.time() < limit:
    try:
        s = socket.create_connection(("127.0.0.1", 2290), 2)
        s.settimeout(5)
        line = s.recv(256).decode(errors="replace").strip()
        s.close()
    except OSError:
        line = ""
    if line.startswith("SSH-2.0-dropbear"):
        break
    time.sleep(0.2)
print(line)
EOF
}
# As one process, so that kill ends podssh (see p in scripts/interop.sh).
(as_job=exec r "relay-tunnel.test:$(port tunnel),relay-a.test:$(port a)" --persist -N -R 127.0.0.1:2290:127.0.0.1:2203 \
    "$T") </dev/null >"$FK/out" 2>"$FK/tunnel.err" &
tunnel=$!
first=$(tunnel_banner 30)
kill "$(cat "$FK/tunnel.pid")" 2>/dev/null
second=$(tunnel_banner 60)
kill "$tunnel" 2>/dev/null
wait "$tunnel" 2>/dev/null
case $first in SSH-2.0-dropbear*) ;; *) first="" ;; esac
case $second in SSH-2.0-dropbear*) ;; *) second="" ;; esac
[ -n "$first" ] && [ -n "$second" ] && grep -q 'connecting again' "$FK/tunnel.err" \
    && grep -q 'again; its forwards serve again' "$FK/tunnel.err" \
    && ok faults.persist.tunnel \
        "--persist -N -R: a relay host killed under the forward, and port 2290 reaches Dropbear through the next" \
    || bad faults.persist.tunnel "--persist -N -R: before the kill '$first', after it '$second'" "$FK/tunnel.err"

# A server that stalls after the key exchange (T-236): the stand-in passes
# OpenSSH's bytes up to its NEWKEYS, then drops them. On --direct nothing
# else ends the wait: each answer during the login has the ConnectTimeout
# limit. `timeout 90` ends a podssh that has none.
python3 "$HERE/fake-stall.py" --target 127.0.0.1:2201 --port-file "$FK/kexstall.port" \
    >"$FK/kexstall.log" 2>&1 &
echo $! >"$FK/kexstall.pid"
tries=0
while [ ! -s "$FK/kexstall.port" ] && [ "$tries" -lt 30 ]; do sleep 1; tries=$((tries + 1)); done
start=$(date +%s)
# shellcheck disable=SC2086
timeout 90 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p "$(port kexstall)" \
    -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o IdentityAgent=none \
    -o IdentitiesOnly=yes $K -o BatchMode=yes -o ConnectTimeout=10 "$T" true >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
took=$(( $(date +%s) - start ))
[ "$rc" = 255 ] && [ "$took" -lt 60 ] && grep -q "did not answer the first request to log in within 10 s" "$FK/err" \
    && ok faults.kex_stall \
        "a server that stalls after the key exchange: exit 255 after ${took}s, and the wait is named" \
    || bad faults.kex_stall "a server that stalls after the key exchange: exit $rc after ${took}s" "$FK/err"

# The shapes of the traffic (T-203). Each check shows that its fault was
# there: the planted control of the delay fails with a limit of 5 s, the
# rate takes near the time computed, and the cut ends the session.
r "relay-delay.test:$(port delay)" "$T" 'echo late' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$FK/out")" = late ] \
    && ok faults.delay.session "2 s each way: a command and its exit status come back" \
    || bad faults.delay.session "2 s each way: exit $rc" "$FK/err"
r "relay-delay.test:$(port delay)" -o ConnectTimeout=5 "$T" 'echo late' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
[ "$rc" = 255 ] && grep -q "did not finish within 5 s" "$FK/err" \
    && ok faults.delay.control "the planted control: with a limit of 5 s, the delayed handshake does not finish" \
    || bad faults.delay.control "the planted control of the delay: exit $rc" "$FK/err"

head -c 5000000 /dev/urandom >"$FK/sent"
r "relay-jitter.test:$(port jitter)" "$T" 'cat' >"$FK/out" 2>"$FK/err" <"$FK/sent"
rc=$?
[ "$rc" = 0 ] && cmp -s "$FK/sent" "$FK/out" \
    && ok faults.jitter "a jitter of 0 to 1.5 s: 5,000,000 bytes up and back, unchanged" \
    || bad faults.jitter "a jitter of 0 to 1.5 s: exit $rc, $(wc -c <"$FK/out") bytes back" "$FK/err"

start=$(date +%s)
r "relay-rate.test:$(port rate)" "$T" 'head -c 2000000 /dev/zero' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
took=$(( $(date +%s) - start ))
got=$(wc -c <"$FK/out")
# 2,000,000 bytes at 65,536 a second: 30.5 s, and 46 s with half again.
[ "$rc" = 0 ] && [ "$got" = 2000000 ] && [ "$took" -ge 27 ] && [ "$took" -le 46 ] \
    && ok faults.rate "at 64 KiB/s, 2,000,000 bytes in ${took}s, where 30.5 s is computed" \
    || bad faults.rate "at 64 KiB/s: exit $rc, $got bytes in ${took}s" "$FK/err"

r "relay-cut.test:$(port cut)" "$T" 'head -c 5000000 /dev/zero' >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
got=$(wc -c <"$FK/out")
[ "$rc" = 255 ] && [ "$got" -lt 5000000 ] && grep -q "relay" "$FK/err" \
    && ok faults.cut "the connection to the relay ended with no Close: exit 255, and the relay is named" \
    || bad faults.cut "a cut: exit $rc, $got bytes" "$FK/err"

# A stall below SSH with --direct (T-227): the forwarder passes the handshake,
# then reads nothing more from podssh; the write fails after 60 s.
python3 "$HERE/stall-forward.py" --listen 2297 --to 127.0.0.1:2201 --after 65536 >"$FK/stall.log" 2>&1 &
echo $! >"$FK/stall-forward.pid"
sleep 1
head -c 20000000 /dev/zero >"$FK/twenty"
start=$(date +%s)
# shellcheck disable=SC2086
timeout 300 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2297 -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K "$T" 'cat >/dev/null' \
    <"$FK/twenty" >"$FK/out" 2>"$FK/err"
rc=$?
took=$(( $(date +%s) - start ))
[ "$rc" = 255 ] && [ "$took" -le 90 ] && grep -q "no progress" "$FK/err" \
    && ok faults.stuck_write "a stuck write with --direct ends with 255 in ${took}s, and says so" \
    || bad faults.stuck_write "a stuck write with --direct: exit $rc in ${took}s" "$FK/err"

# T-025: a drop of the relay before any request is tried again, once, and
# the command runs once; a drop after the command started is not.
RAN=/home/podtest/t025-ran
rm -f "$RAN" "$RAN-after"
r "relay-dropfirst.test:$(port dropfirst)" "$T" "echo ran >> $RAN; exit 5" >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
runs=$(grep -c . "$RAN" 2>/dev/null)
[ "$rc" = 5 ] && [ "$(grep -c 'so podssh tries once more' "$FK/err")" = 1 ] && [ "$runs" = 1 ] \
    && ok faults.drop.handshake "a drop during the handshake is tried once more, and the command runs once (exit 5)" \
    || bad faults.drop.handshake "a drop during the handshake: exit $rc, ${runs:-0} runs" "$FK/err"
r "relay-dropafter.test:$(port dropafter)" "$T" "echo ran >> $RAN-after; sleep 30" >"$FK/out" 2>"$FK/err" </dev/null
rc=$?
runs=$(grep -c . "$RAN-after" 2>/dev/null)
[ "$rc" = 255 ] && ! grep -q "so podssh tries" "$FK/err" && [ "$runs" = 1 ] \
    && ok faults.drop.after_start "a drop after the command started is not tried again (exit 255, one run)" \
    || bad faults.drop.after_start "a drop after the request: exit $rc, ${runs:-0} runs" "$FK/err"

# shellcheck source=scripts/interop-ping.sh
. "$HERE/interop-ping.sh"
# shellcheck source=scripts/interop-relay.sh
. "$HERE/interop-relay.sh"
# shellcheck source=scripts/interop-socks.sh
. "$HERE/interop-socks.sh"
# shellcheck source=scripts/interop-roost.sh
. "$HERE/interop-roost.sh"
# shellcheck source=scripts/interop-upgrade.sh
. "$HERE/interop-upgrade.sh"

for f in "$FK"/*.pid; do
    kill "$(cat "$f")" 2>/dev/null
done
