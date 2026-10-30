# The broadcast, podssh each --interactive (T-185), against OpenSSH on port
# 2201 and Dropbear on port 2203 at once, the lines from a pipe: a line
# reaches both shells; after :only 127.0.0.1:2203 a line reaches
# Dropbear's alone; and after kill -QUIT, the emergency stop as Ctrl-\
# sends it, the line touch /tmp/podssh-after-stop makes no file, and :all
# then starts the broadcast again (the planted defect, SIGQUIT ignored,
# fails it). Sourced by scripts/interop-each.sh; uses ok, bad, $BIN, $W, $K,
# $T and $KH.

echo
echo "== podssh each --interactive (T-185, OpenSSH and Dropbear at once)"
BW="$W/broadcast"
mkdir -p "$BW"
rm -f "$BW/in" /tmp/podssh-after-stop
mkfifo "$BW/in"
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" each --interactive --direct -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K "$T:2201,$T:2203" \
    <"$BW/in" >"$BW/out" 2>"$BW/err" &
BPID=$!
exec 3>"$BW/in"
# shows TEXT FILE: whether FILE holds TEXT within 30 s.
shows() {
    tries=0
    until grep -qF -- "$1" "$2"; do
        tries=$((tries + 1))
        [ "$tries" -ge 300 ] && return 1
        sleep 0.1
    done
}
echo 'echo both' >&3
shows "$T:2201: both" "$BW/out" && shows "$T:2203: both" "$BW/out" \
    && ok broadcast.both "a line from the pipe reached the shells of OpenSSH and Dropbear" \
    || bad broadcast.both "no line came back from each host" "$BW/err"
printf ':only 127.0.0.1:2203\necho only-one\n' >&3
shows "$T:2203: only-one" "$BW/out" && ! grep -qF "$T:2201: only-one" "$BW/out" \
    && ok broadcast.only ":only 127.0.0.1:2203: the line reached the shell of Dropbear alone" \
    || bad broadcast.only "the line after :only 127.0.0.1:2203" "$BW/out"
kill -QUIT "$BPID"
shows "broadcast stopped; :all starts it again" "$BW/err"
stopped=$?
echo 'touch /tmp/podssh-after-stop' >&3
printf ':all\necho after-all\n' >&3
shows "$T:2201: after-all" "$BW/out" && shows "$T:2203: after-all" "$BW/out"
again=$?
exec 3>&-
tries=0
while kill -0 "$BPID" 2>/dev/null && [ "$tries" -lt 300 ]; do
    sleep 0.1
    tries=$((tries + 1))
done
kill -9 "$BPID" 2>/dev/null
wait "$BPID"
rc=$?
made=absent
[ -e /tmp/podssh-after-stop ] && made=made
[ "$stopped" = 0 ] && [ "$made" = absent ] && [ "$again" = 0 ] && [ "$rc" = 0 ] \
    && ok broadcast.stop "kill -QUIT: the next line made no file, and :all started the broadcast again" \
    || bad broadcast.stop "stopped $stopped, :all $again, exit $rc, /tmp/podssh-after-stop $made" "$BW/err"
rm -f "$BW/in" /tmp/podssh-after-stop
