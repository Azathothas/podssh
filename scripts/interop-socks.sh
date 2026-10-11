# podssh through a SOCKS5 proxy for the egress (T-070): OpenSSH's own SOCKS5
# server, ssh -D to the test's sshd, carries a session to the stand-in relay.
# Sourced by scripts/interop-faults.sh while its stand-ins run; uses its ok,
# bad, port, $FK, $W, $T, $K, $KH and $BIN.

echo
echo "== a SOCKS5 proxy for the egress (OpenSSH's ssh -D)"

# podssh sends the relay's name, and the proxy resolves it, as a real one
# does: this throwaway container's hosts file names the stand-in. A direct
# connection would resolve it too, so the proof that the proxy carried the
# session is ssh's own log of each SOCKS5 request.
grep -q ' relay-a.test$' /etc/hosts || echo "127.0.0.1 relay-a.test" >>/etc/hosts \
    || bad "socks5: /etc/hosts could not name relay-a.test" /etc/hosts

SX="$FK/socks"
mkdir -p "$SX"
# 2292: a port that no other case takes.
ssh -vv -E "$SX/ssh.log" -N -D 127.0.0.1:2292 -p 2201 -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ExitOnForwardFailure=yes -o IdentityAgent=none \
    -i "$W/id_ed25519" "$T" </dev/null >"$SX/ssh.out" 2>"$SX/ssh.err" &
SX_PID=$!
timeout 20 python3 -c 'import socket, sys, time
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", 2292), 2).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)' || bad "socks5: OpenSSH's ssh -D did not listen on 127.0.0.1:2292" "$SX/ssh.log"

# The lines of ssh's log for a SOCKS5 request to the stand-in by its name:
# OpenSSH 10.3p1 writes "channel N: dynamic request: socks5 host NAME port
# PORT command 1" at -vv. An address in its place would say that podssh
# resolved the name.
socks_requests() {
    grep -c "dynamic request: socks5 host relay-a.test port $(port a) " "$SX/ssh.log" 2>/dev/null
}

# The proxy URL has a password, which OpenSSH's proxy does not ask for and
# which no output may show, -v included.
PROXY_URL="socks5h://podssh:pw-never-shown@127.0.0.1:2292"

before=$(socks_requests)
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy ALL_PROXY="$PROXY_URL" HOME="$W" "$BIN" ssh -v \
    --relay-host "relay-a.test:$(port a)" --ca-file "$FK/ca.pem" -p 2201 -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes \
    "$T" 'echo through-socks5' >"$SX/out" 2>"$SX/err" </dev/null
rc=$?
after=$(socks_requests)
[ "$rc" = 0 ] && [ "$(cat "$SX/out")" = through-socks5 ] && [ "${after:-0}" -gt "${before:-0}" ] \
    && ! grep -q pw-never-shown "$SX/out" "$SX/err" \
    && ok "socks5: OpenSSH's ssh -D carries a session to the relay by its name, and the proxy's password is never shown" \
    || bad "socks5: a session through ssh -D: exit $rc, ${before:-0} then ${after:-0} requests: $(cat "$SX/out")" \
        "$SX/err"

before=$(socks_requests)
env -u https_proxy -u HTTPS_PROXY -u all_proxy ALL_PROXY="$PROXY_URL" HOME="$W" "$BIN" relay status \
    --relay-host "relay-a.test:$(port a)" --ca-file "$FK/ca.pem" >"$SX/out" 2>"$SX/err" </dev/null
rc=$?
after=$(socks_requests)
[ "$rc" = 0 ] && grep -q "opened SOCKS5 CONNECT relay-a.test:$(port a) through 127.0.0.1:2292" "$SX/out" \
    && [ "${after:-0}" -gt "${before:-0}" ] && ! grep -q pw-never-shown "$SX/out" "$SX/err" \
    && ok "socks5: relay status reads /health through ssh -D, and names the proxy" \
    || bad "socks5: relay status through ssh -D: exit $rc, ${before:-0} then ${after:-0} requests: $(cat "$SX/out")" \
        "$SX/err"

kill "$SX_PID" 2>/dev/null
wait "$SX_PID" 2>/dev/null
[ "${after:-0}" -gt 0 ] || cat "$SX/ssh.log"
