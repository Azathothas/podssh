# -W /PATH (T-040): a Unix socket on the server, through OpenSSH's sshd,
# which opens it as direct-streamlocal@openssh.com: a Python echo server on
# the socket answers what podssh's stdin sends; a socket that is not there
# is refused, with the server's reason. Sourced by scripts/interop.sh once
# its servers run; uses ok, bad, p, $W, $K and $T.

echo
echo "== -W /PATH: a Unix socket on the server (T-040)"
rm -f "$W/echo.sock"
python3 -c '
import os
import socket
import sys

path = sys.argv[1]
server = socket.socket(socket.AF_UNIX)
server.bind(path)
os.chmod(path, 0o777)
server.listen(1)
conn, _ = server.accept()
while True:
    data = conn.recv(4096)
    if not data:
        break
    conn.sendall(data)
conn.close()
' "$W/echo.sock" &
ECHO=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S "$W/echo.sock" ] && break
    sleep 0.2
done
# shellcheck disable=SC2086
out=$(printf ping | p 2201 $K -o BatchMode=yes -W "$W/echo.sock" "$T" 2>"$W/err")
rc=$?
[ "$rc" = 0 ] && [ "$out" = ping ] \
    && ok stdio.socket "-W /PATH: the server's Unix socket answers on stdin and stdout" \
    || bad stdio.socket "-W /PATH: exit $rc, output '$out'" "$W/err"
kill "$ECHO" 2>/dev/null
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -W "$W/no-such.sock" "$T" </dev/null >"$W/out" 2>"$W/err"
rc=$?
[ "$rc" = 255 ] && grep -q 'could not open a connection to the socket' "$W/err" \
    && ok stdio.socket_refused "-W /PATH to no socket: 255, with the server's reason" \
    || bad stdio.socket_refused "-W /PATH to no socket: exit $rc" "$W/err"
