# podssh pipe (T-174, T-175). Sourced by scripts/interop.sh once its servers
# run, after scripts/interop-faults.sh, whose CA and relay certificate it
# uses; uses ok, bad, expect_rc, $W, $HERE, $BIN, $KH, $K and $T. The child
# is on a socketpair here, as the build image allows one.

echo
echo "== pipe"
PD="$W/pipe"
mkdir -p "$PD"

# Both ways through a program, and the end of input as a half-close.
head -c 5000000 /dev/urandom >"$PD/in"
"$BIN" pipe stdio exec:cat <"$PD/in" >"$PD/out" 2>"$PD/err"
rc=$?
[ "$rc" = 0 ] && cmp -s "$PD/in" "$PD/out" \
    && ok "pipe stdio exec:cat: 5,000,000 bytes back, unchanged" || bad "pipe stdio exec:cat: exit $rc" "$PD/err"

# A descriptor that the caller opened.
printf 'from a descriptor\n' >"$PD/fd3"
"$BIN" pipe fd:3 stdio 3<"$PD/fd3" </dev/null >"$PD/out" 2>"$PD/err"
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$PD/out")" = "from a descriptor" ] \
    && ok "pipe fd:3 stdio reads the descriptor" || bad "pipe fd:3 stdio: exit $rc" "$PD/err"

# The program's status, as a shell gives it.
"$BIN" pipe stdio "exec:sh -c 'exit 7'" </dev/null >/dev/null 2>"$PD/err"
expect_rc "pipe gives the program's status" 7 $? "$PD/err"
"$BIN" pipe stdio "exec:sh -c 'kill -TERM \$\$'" </dev/null >/dev/null 2>"$PD/err"
expect_rc "pipe gives 128 + the signal that ended the program" 143 $? "$PD/err"

# The remote ends (T-175): a target that answers 1 s after it accepts, one
# that reads to the end of its input and answers with its SHA-256, and a
# stand-in relay.
cat >"$PD/late.py" <<'PY'
import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(4)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    time.sleep(1)
    c.sendall(b"the late reply\n")
    c.close()
PY
cat >"$PD/digest.py" <<'PY'
import hashlib, socket, sys
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(4)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    h = hashlib.sha256()
    while True:
        d = c.recv(65536)
        if not d:
            break
        h.update(d)
    c.sendall(h.hexdigest().encode() + b"\n")
    c.close()
PY
python3 "$PD/late.py" "$PD/late.port" >/dev/null 2>&1 &
late_pid=$!
python3 "$PD/digest.py" "$PD/digest.port" >/dev/null 2>&1 &
digest_pid=$!
python3 "$HERE/fake-relay.py" --cert "$W/faults/relay.pem" --key "$W/faults/relay.key" \
    --port-file "$PD/relay.port" --mode normal >"$PD/relay.log" 2>&1 &
relay_pid=$!
tries=0
while [ "$tries" -lt 30 ] && ! { [ -s "$PD/late.port" ] && [ -s "$PD/digest.port" ] && [ -s "$PD/relay.port" ]; }; do
    sleep 1
    tries=$((tries + 1))
done

# Through the relay, no Close goes out at the end of input: the late reply
# still comes. podssh proxy runs the same pipe.
RP="--relay-host relay-a.test:$(cat "$PD/relay.port") --relay-addr relay-a.test=127.0.0.1 --ca-file $W/faults/ca.pem"
# shellcheck disable=SC2086
"$BIN" pipe $RP stdio "relay:127.0.0.1:$(cat "$PD/late.port")" </dev/null >"$PD/out" 2>"$PD/err"
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$PD/out")" = "the late reply" ] \
    && ok "pipe relay: a reply after the end of input comes back" || bad "pipe relay: late reply: exit $rc" "$PD/err"
# shellcheck disable=SC2086
"$BIN" proxy $RP 127.0.0.1 "$(cat "$PD/late.port")" </dev/null >"$PD/out" 2>"$PD/err"
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$PD/out")" = "the late reply" ] \
    && ok "proxy, on the same pipe: the late reply comes back" || bad "proxy: late reply: exit $rc" "$PD/err"

# Through OpenSSH, as -W asks: the end of input passes on as a half-close,
# and the digest server's answer comes back.
want=$(sha256sum <"$PD/in" | cut -c1-64)
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" pipe --direct -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K \
    stdio "ssh:$T:2201,127.0.0.1:$(cat "$PD/digest.port")" <"$PD/in" >"$PD/out" 2>"$PD/err"
rc=$?
got=$(cut -c1-64 <"$PD/out")
[ "$rc" = 0 ] && [ "$got" = "$want" ] \
    && ok "pipe ssh: through OpenSSH: 5,000,000 bytes, and the far end's digest is equal" \
    || bad "pipe ssh: exit $rc, digest '$got'" "$PD/err"
kill "$late_pid" "$digest_pid" "$relay_pid" 2>/dev/null
rm -rf "$PD"
