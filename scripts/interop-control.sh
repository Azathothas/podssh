# Connection sharing (T-039). Sourced by scripts/interop.sh once its servers
# run; uses ok, bad, expect_rc, $W, $BIN, $KH and $T. Both ways against
# OpenSSH 10.3p1: its `ssh -O check`, its client and its `-O exit` with a
# podssh master; podssh's client, `-O check` and `-O exit` with an OpenSSH
# master.

echo
echo "== connection sharing (T-039)"
CW="$W/control"
mkdir -p "$CW"
# pc ARGS...: podssh ssh to OpenSSH's sshd with id_ed25519.
pc() {
    timeout 30 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o BatchMode=yes -i "$W/id_ed25519" "$@"
}
# A podssh master, in the background.
pc -M -N -S "$CW/ctl" "$T" </dev/null >"$CW/master.out" 2>"$CW/master.err" &
MASTER=$!
tries=0
until timeout 5 ssh -S "$CW/ctl" -O check x >"$CW/check" 2>&1 || [ "$tries" -ge 100 ]; do
    sleep 0.1
    tries=$((tries + 1))
done
grep -q "Master running" "$CW/check" &&
    ok control.podssh_master.check "OpenSSH's ssh -O check: a podssh master is running" ||
    bad control.podssh_master.check "OpenSSH's ssh -O check found no podssh master" "$CW/check"
timeout 30 ssh -S "$CW/ctl" -p 2201 "$T" 'exit 3' </dev/null >"$CW/out" 2>"$CW/err"
expect_rc control.podssh_master.status "OpenSSH's client through a podssh master: the status" 3 $? "$CW/err"
got=$(timeout 30 ssh -S "$CW/ctl" -tt -p 2201 "$T" tty </dev/null 2>"$CW/err" | tr -d '\r')
case $got in
/dev/pts/*) ok control.podssh_master.pty "OpenSSH's client gets a pty through a podssh master ($got)" ;;
*) bad control.podssh_master.pty "no pty through the podssh master: '$got'" "$CW/err" ;;
esac
got=$(pc -S "$CW/ctl" "$T" 'echo via-master' </dev/null 2>"$CW/err")
[ "$got" = via-master ] && ok control.podssh_master.podssh_client "podssh's client through a podssh master" ||
    bad control.podssh_master.podssh_client "podssh's client gave '$got'" "$CW/err"
banner=$(pc -S "$CW/ctl" -W 127.0.0.1:2203 "$T" </dev/null 2>"$CW/err" | head -c 20)
case $banner in
SSH-2.0-dropbear*) ok control.podssh_master.stdio_forward "-W through a podssh master reaches Dropbear" ;;
*) bad control.podssh_master.stdio_forward "-W through the podssh master gave '$banner'" "$CW/err" ;;
esac
timeout 10 ssh -S "$CW/ctl" -O exit x >"$CW/exit" 2>&1
expect_rc control.podssh_master.exit "OpenSSH's ssh -O exit to a podssh master" 0 $? "$CW/exit"
tries=0
while kill -0 "$MASTER" 2>/dev/null && [ "$tries" -lt 100 ]; do
    sleep 0.1
    tries=$((tries + 1))
done
wait "$MASTER" 2>/dev/null
rc=$?
[ "$rc" = 0 ] && [ ! -e "$CW/ctl" ] &&
    ok control.podssh_master.ended "the podssh master ended at -O exit (exit 0), and its socket went" ||
    bad control.podssh_master.ended "the podssh master gave $rc at -O exit, or left its socket" "$CW/master.err"

# An OpenSSH master: -f puts it in the background once logged in.
timeout 30 ssh -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
    -i "$W/id_ed25519" -p 2201 -M -N -f -S "$CW/octl" "$T" </dev/null >"$CW/omaster" 2>&1
expect_rc control.openssh_master.start "an OpenSSH master starts" 0 $? "$CW/omaster"
pc -S "$CW/octl" -O check "$T" </dev/null >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && grep -q "Master running" "$CW/err" &&
    ok control.openssh_master.check "podssh's -O check: an OpenSSH master is running" ||
    bad control.openssh_master.check "podssh's -O check gave $rc" "$CW/err"
pc -S "$CW/octl" "$T" 'exit 4' </dev/null >"$CW/out" 2>"$CW/err"
expect_rc control.openssh_master.status "podssh's client through an OpenSSH master: the status" 4 $? "$CW/err"
got=$(pc -S "$CW/octl" "$T" 'echo via-openssh' </dev/null 2>"$CW/err")
[ "$got" = via-openssh ] && ok control.openssh_master.output "podssh's client output through an OpenSSH master" ||
    bad control.openssh_master.output "podssh's client through OpenSSH gave '$got'" "$CW/err"
pc -S "$CW/octl" -O exit "$T" </dev/null >"$CW/out" 2>"$CW/err"
expect_rc control.openssh_master.exit "podssh's -O exit to an OpenSSH master" 0 $? "$CW/err"
sleep 1
timeout 5 ssh -S "$CW/octl" -O check x >"$CW/check" 2>&1
expect_rc control.openssh_master.gone "the OpenSSH master is gone after podssh's -O exit" 255 $? "$CW/check"
