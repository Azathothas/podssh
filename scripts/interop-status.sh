# The exit codes of a session with no exit status (T-026), as OpenSSH's own
# client gives them. Sourced by scripts/interop.sh once its servers run;
# uses ok, bad, expect_rc, sshd_conf, $W, $BIN, $KH, $K and $T. Its own sshd
# is on port 2210, and stops after the block: the ports from 2205 belong to
# scripts/interop-cp.sh.

echo
echo "== exit codes with no status, as OpenSSH's own client gives them (T-026)"
# within CLIENT PORT [arguments...]: one run of podssh (p) or OpenSSH (o),
# ended at 60 s: a case that hangs is a failure that names itself (124).
within() {
    _client=$1
    _port=$2
    shift 2
    case $_client in
        p) timeout 60 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p "$_port" -o UserKnownHostsFile="$KH" \
               -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes "$@" ;;
        o) timeout 60 env -u SSH_AUTH_SOCK HOME="$W" ssh -F /dev/null -p "$_port" -o UserKnownHostsFile="$KH" \
               -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes "$@" ;;
    esac
}
# wait_ports PORT...: each listens on 127.0.0.1 within 5 s, or the run says so.
wait_ports() {
    python3 -c '
import socket, sys, time
for port in map(int, sys.argv[1:]):
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 1).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise SystemExit(f"port {port} never listened")
' "$@"
}
# A server that ends each unused connection after 2 s, for -N.
sshd_conf 2210 "KbdInteractiveAuthentication no" "UnusedConnectionTimeout 2"
/usr/sbin/sshd -f "$W/sshd-2210.conf" -E "$W/sshd-2210.log" || cat "$W/sshd-2210.log"
wait_ports 2210 || cat "$W/sshd-2210.log"
# A TCP service on 2298 that streams until it is closed, and one on 2299 that
# says one line and closes; each takes one client, then the next.
python3 -c '
import socket, threading
def serve(port, stream):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(8)
    while True:
        c, _ = s.accept()
        try:
            if stream:
                while True: c.sendall(b"y" * 65536)
            else:
                c.sendall(b"bye\n")
        except OSError:
            pass
        c.close()
for port, stream in ((2298, True), (2299, False)):
    threading.Thread(target=serve, args=(port, stream), daemon=True).start()
threading.Event().wait()
' >"$W/tcp-services.log" 2>&1 &
TCP_SERVICES=$!
wait_ports 2298 2299 || cat "$W/tcp-services.log"
# The code of each client, read from a file, never through a pipe.
for client in p o; do
    # shellcheck disable=SC2086
    within $client 2210 $K -N "$T" >/dev/null 2>"$W/err-n-$client" </dev/null
    echo $? >"$W/rc-n-$client"
    # shellcheck disable=SC2086
    { within $client 2201 $K "$T" yes 2>"$W/err-yes-$client" </dev/null; echo $? >"$W/rc-yes-$client"; } |
        head -c 1 >/dev/null
    # shellcheck disable=SC2086
    within $client 2201 $K -W 127.0.0.1:2299 "$T" >/dev/null 2>"$W/err-wfar-$client" </dev/null
    echo $? >"$W/rc-wfar-$client"
    # shellcheck disable=SC2086
    { within $client 2201 $K -W 127.0.0.1:2298 "$T" 2>"$W/err-wout-$client" </dev/null; echo $? >"$W/rc-wout-$client"; } |
        head -c 1 >/dev/null
done
kill "$TCP_SERVICES" 2>/dev/null
# Port 2205 and its neighbours belong to the copies of interop-cp.sh.
kill "$(cat "$W/sshd-2210.pid")" 2>/dev/null
for case in n yes wfar wout; do
    want=$(cat "$W/rc-$case-o")
    got=$(cat "$W/rc-$case-p")
    expect_rc "T-026: '$case' as OpenSSH's client" "$want" "$got" "$W/err-$case-p"
    echo "T-026: '$case': podssh $got, OpenSSH $want" >>"$W/t026.txt"
done
for case in n yes; do
    got=$(cat "$W/rc-$case-p")
    [ "$got" != 0 ] && ok "T-026: '$case' with no status is no success (exit $got)" ||
        bad "T-026: '$case' gave 0 with no status" "$W/err-$case-p"
done
cat "$W/t026.txt"
