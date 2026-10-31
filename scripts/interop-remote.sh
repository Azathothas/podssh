# The socket and SOCKS forms of -R (T-365), against OpenSSH on 2202, whose
# PermitListen takes each port, and Dropbear on 2203 as the target. Sourced
# by scripts/interop.sh after the -R of T-035; uses its p, ok, bad, $W, $T
# and $K.

echo
echo "== -R with a socket path, a socket here, and SOCKS (T-365)"

# `podssh ssh -N -R SPEC` in the background, its pid in $rpid; a forward
# that sshd refuses ends it (ExitOnForwardFailure), and its words are in
# $W/rerr.
remote_start() {
    # shellcheck disable=SC2086
    (as_job=exec p 2202 $K -o BatchMode=yes -o ExitOnForwardFailure=yes -N -R "$1" "$T") \
        </dev/null >"$W/out" 2>"$W/rerr" &
    rpid=$!
}
remote_stop() {
    kill "$rpid" 2>/dev/null
    wait "$rpid" 2>/dev/null
}

# A socket path on the server: sshd makes it, and each connection to it
# reaches Dropbear's port through podssh.
rsock="/tmp/podssh-r-$$.sock"
rm -f "$rsock"
remote_start "$rsock:127.0.0.1:2203"
banner=$(python3 - "$rsock" <<'EOF'
import socket, sys, time
for _ in range(50):
    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(2)
        s.connect(sys.argv[1])
        print(s.recv(32).decode(errors="replace").strip())
        break
    except OSError:
        time.sleep(0.2)
EOF
)
remote_stop
rm -f "$rsock"
case $banner in
    SSH-2.0-dropbear*) ok remote.path "-R PATH:HOST:PORT: OpenSSH's socket reaches Dropbear's banner through podssh" ;;
    *) bad remote.path "-R PATH:HOST:PORT: the socket gave '$banner'" "$W/rerr" ;;
esac

# The SOCKS form: OpenSSH listens on 2292, and a SOCKS5 client there names
# Dropbear's port, which podssh dials from this host, then answers.
remote_start "127.0.0.1:2292"
banner=$(python3 - <<'EOF'
import socket, struct, time
for _ in range(50):
    try:
        s = socket.create_connection(("127.0.0.1", 2292), timeout=2)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise OSError("no method")
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 2203))
        reply = s.recv(10)
        if reply[:2] != b"\x05\x00":
            print("refused %r" % reply)
            break
        print(s.recv(32).decode(errors="replace").strip())
        break
    except OSError:
        time.sleep(0.2)
EOF
)
remote_stop
case $banner in
    SSH-2.0-dropbear*) ok remote.socks "-R PORT: a SOCKS5 request on OpenSSH's port reaches Dropbear through podssh" ;;
    *) bad remote.socks "-R PORT (SOCKS): '$banner'" "$W/rerr" ;;
esac

# A socket on this host as the target: OpenSSH listens on 2293, and each
# connection reaches a one-shot server on a socket here.
lsock="$W/local-$$.sock"
python3 - "$lsock" <<'EOF' &
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen(1)
s.settimeout(30)
c, _ = s.accept()
c.sendall(b"podssh-local-socket\n")
c.close()
EOF
lpid=$!
remote_start "127.0.0.1:2293:$lsock"
line=$(python3 - <<'EOF'
import socket, time
for _ in range(50):
    try:
        s = socket.create_connection(("127.0.0.1", 2293), timeout=2)
        got = s.recv(64).decode(errors="replace").strip()
        if got:
            print(got)
            break
    except OSError:
        pass
    time.sleep(0.2)
EOF
)
remote_stop
kill "$lpid" 2>/dev/null
wait "$lpid" 2>/dev/null
rm -f "$lsock"
case $line in
    podssh-local-socket) ok remote.socket "-R PORT:LOCAL_SOCKET: OpenSSH's port reaches a socket on this host" ;;
    *) bad remote.socket "-R PORT:LOCAL_SOCKET: '$line'" "$W/rerr" ;;
esac
