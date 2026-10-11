# -L and -D (T-038). Sourced by scripts/interop.sh once its servers run;
# uses ok, bad, expect_rc, $W, $BIN, $KH, $K and $T. podssh ssh -N listens
# here, and each connection goes on from OpenSSH's sshd: Dropbear's banner
# through a port and a socket of -L, and curl through -D with SOCKS5 and
# SOCKS4a. PODSSH_LISTEN=no refuses -L before anything connects (78).

echo
echo "== -L and -D (T-038)"
LF="$W/lfwd"
mkdir -p "$LF"
# lf ARGS...: podssh ssh -N to OpenSSH's sshd, in the background.
lf() {
    env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o BatchMode=yes \
        -i "$W/id_ed25519" -N "$@" "$T" </dev/null >"$LF/out" 2>"$LF/err" &
    LF_PID=$!
}
# banner WHERE: Dropbear's first line from a port of 127.0.0.1 or a socket
# path, once something listens there (10 s at most).
banner() {
    timeout 20 python3 - "$1" <<'EOF'
import socket, sys, time
where = sys.argv[1]
for _ in range(100):
    try:
        if where.startswith("/"):
            s = socket.socket(socket.AF_UNIX)
            s.connect(where)
        else:
            s = socket.create_connection(("127.0.0.1", int(where)), 2)
        break
    except OSError:
        time.sleep(0.1)
else:
    sys.exit("nothing listened on " + where)
s.settimeout(10)
print(s.recv(256).decode(errors="replace").splitlines()[0])
EOF
}
stop() {
    kill "$LF_PID" 2>/dev/null
    wait "$LF_PID" 2>/dev/null
}

lf -L 127.0.0.1:2280:127.0.0.1:2203
got=$(banner 2280)
case $got in
SSH-2.0-dropbear*) ok local.l.port "-L 127.0.0.1:2280:127.0.0.1:2203 gives Dropbear's banner ($got)" ;;
*) bad local.l.port "-L on a port gave '$got'" "$LF/err" ;;
esac
stop

lf -L "$LF/l.sock:127.0.0.1:2203"
got=$(banner "$LF/l.sock")
case $got in
SSH-2.0-dropbear*) ok local.l.socket "-L PATH:127.0.0.1:2203 gives Dropbear's banner on the socket" ;;
*) bad local.l.socket "-L on a socket gave '$got'" "$LF/err" ;;
esac
[ "$(stat -c %a "$LF/l.sock" 2>/dev/null)" = 600 ] && ok local.l.socket_mode "the socket of -L is mode 0600" ||
    bad local.l.socket_mode "the socket of -L is mode $(stat -c %a "$LF/l.sock" 2>/dev/null)" "$LF/err"
stop

lf -D 127.0.0.1:2281
banner 2281 >/dev/null 2>&1
# LABEL:FLAG, as a flag that starts with - is no part of an id.
for spec in socks5h:--socks5-hostname socks4a:--socks4a; do
    flag=${spec#*:}
    timeout 20 curl -s --max-time 3 "$flag" 127.0.0.1:2281 telnet://127.0.0.1:2203 </dev/null >"$LF/curl" 2>&1
    grep -q "SSH-2.0-dropbear" "$LF/curl" &&
        ok "local.d.${spec%%:*}" "curl $flag through -D 127.0.0.1:2281 reaches Dropbear" ||
        bad "local.d.${spec%%:*}" "curl $flag through -D did not reach Dropbear" "$LF/curl"
done
stop

timeout 20 env -u SSH_AUTH_SOCK PODSSH_LISTEN=no HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
    -o IdentityAgent=none -o BatchMode=yes -i "$W/id_ed25519" -N -L 127.0.0.1:2282:127.0.0.1:2203 "$T" \
    </dev/null >"$LF/out" 2>"$LF/err"
expect_rc local.listen_no "PODSSH_LISTEN=no refuses -L before anything connects" 78 $? "$LF/err"
