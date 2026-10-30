# A roost (T-166): podssh node --sshd in front of OpenSSH (2201) and
# Dropbear (2203), through the stand-in relay's reverse road. The roost's
# first line names each server's version line; podssh ssh node:// logs in
# through it, and the session survives a cut of the client's link to the
# relay, which a stand-in proxy makes during the remote command. Before it
# registers, a roost in front of a port with nothing on it, and one in front
# of a server that answers HTTP first, exit and name TARGET. Sourced by
# scripts/interop-faults.sh while its stand-ins run; uses its ok, bad,
# port, $FK, $PINS, $W, $K, $KH, $HERE and $BIN.

echo
echo "== a roost in front of OpenSSH and Dropbear (the stand-in relay's reverse road)"
RO="$FK/roost"
mkdir -p "$RO"

# ro [podssh arguments...]: podssh with this harness's cache, and no proxy
# unless $RX names one. With as_job=exec, podssh takes the place of the
# shell that runs ro, so that kill ends podssh.
RX=
ro() {
    ${as_job:-} env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY ${RX:+https_proxy=$RX} \
        XDG_CACHE_HOME="$RO/cache" HOME="$W" "$BIN" "$@"
}
# waitfor FILE TEXT: up to 30 s for TEXT in FILE.
waitfor() {
    _tries=0
    while [ "$_tries" -lt 300 ]; do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
        _tries=$((_tries + 1))
    done
    return 1
}

# A server that sends an HTTP status line first, for the preflight.
cat >"$RO/http.py" <<'EOF'
import socket, sys, threading
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(8)
with open(sys.argv[1], "w") as f:
    f.write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    threading.Timer(5, c.close).start()
EOF
python3 "$RO/http.py" "$RO/http.port" >/dev/null 2>&1 &
echo $! >"$RO/http.pid"
waitfor "$RO/http.port" .

for srv in openssh:2201 dropbear:2203; do
    sport=${srv#*:}
    label="roost-${srv%%:*}"
    ro relay pair "$label" --relay-host "relay-a.test:$(port a)" --relay-addr "$PINS" --ca-file "$FK/ca.pem" \
        >"$RO/$label.pair" 2>&1 </dev/null
    (as_job=exec ro node "$label" "127.0.0.1:$sport" --sshd --relay-addr "$PINS" --ca-file "$FK/ca.pem" \
        </dev/null >/dev/null 2>"$RO/$label.node") &
    echo $! >"$RO/$label.pid"
    waitfor "$RO/$label.node" online
    grep -q "serving the sshd 127.0.0.1:$sport (SSH-2.0-" "$RO/$label.node" \
        && ok "roost.version.${srv%%:*}" "the roost's first line names the version line of port $sport" \
        || bad "roost.version.${srv%%:*}" "no version line of port $sport in the roost's lines" "$RO/$label.node"

    # The cut: 1 s after the remote command makes the start file, the proxy
    # ends each tunnel open then with RST, as a relay host that stops; the
    # layer resumes on a new tunnel, and the command's output comes after.
    START=/home/podtest/roost-start-${srv%%:*}
    rm -f "$START" "$RO/$label.proxy.port"
    python3 "$HERE/fake-proxy.py" --port-file "$RO/$label.proxy.port" --log "$RO/$label.proxy.log" \
        --map "relay-a.test=127.0.0.1:$(port a)" --start-file "$START" --stop-after 1 >/dev/null 2>&1 &
    echo $! >"$RO/$label.proxy.pid"
    waitfor "$RO/$label.proxy.port" .
    RX="http://127.0.0.1:$(cat "$RO/$label.proxy.port")"
    # No pin: the proxy's map names relay-a.test, and a pin to the loopback
    # would go around the proxy and its cut (T-318).
    # shellcheck disable=SC2086
    ro ssh --ca-file "$FK/ca.pem" -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes \
        "node://podtest@$label" "touch $START; sleep 4; echo roost-survived" >"$RO/out" 2>"$RO/err" </dev/null
    rc=$?
    RX=
    [ "$rc" = 0 ] && [ "$(cat "$RO/out")" = roost-survived ] && grep -q "resuming the session" "$RO/err" \
        && grep -q "the session resumed" "$RO/err" \
        && ok "roost.cut.${srv%%:*}" "through a roost in front of port $sport, a cut link resumed and the command ended" \
        || bad "roost.cut.${srv%%:*}" "through a roost in front of port $sport, with a cut link: exit $rc" "$RO/err"
    kill "$(cat "$RO/$label.proxy.pid")" 2>/dev/null
    kill "$(cat "$RO/$label.pid")" 2>/dev/null
    rm -f "$START"
done

# The preflight: nothing on port 2299, then the HTTP server; each exits
# before it registers, and names TARGET.
ro node roost-openssh 127.0.0.1:2299 --sshd --relay-addr "$PINS" --ca-file "$FK/ca.pem" \
    </dev/null >/dev/null 2>"$RO/err"
rc=$?
[ "$rc" = 69 ] && grep -q "TARGET 127.0.0.1:2299" "$RO/err" && ! grep -q online "$RO/err" \
    && ok roost.preflight.closed "a roost in front of a closed port exits 69, and names TARGET" \
    || bad roost.preflight.closed "a roost in front of a closed port: exit $rc" "$RO/err"
hport=$(cat "$RO/http.port")
ro node roost-openssh "127.0.0.1:$hport" --sshd --relay-addr "$PINS" --ca-file "$FK/ca.pem" \
    </dev/null >/dev/null 2>"$RO/err"
rc=$?
[ "$rc" = 78 ] && grep -q "TARGET 127.0.0.1:$hport is not an SSH server" "$RO/err" \
    && grep -q '"HTTP/1.1 400 Bad Request"' "$RO/err" && ! grep -q online "$RO/err" \
    && ok roost.preflight.other "a roost in front of an HTTP server exits 78, and names TARGET and its line" \
    || bad roost.preflight.other "a roost in front of an HTTP server: exit $rc" "$RO/err"
kill "$(cat "$RO/http.pid")" 2>/dev/null
for label in roost-openssh roost-dropbear; do
    ro relay revoke "$label" --relay-host "relay-a.test:$(port a)" --relay-addr "$PINS" --ca-file "$FK/ca.pem" \
        >/dev/null 2>&1 </dev/null
done
