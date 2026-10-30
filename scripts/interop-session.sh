# podssh session (T-186) against OpenSSH on port 2201 and Dropbear on port
# 2203: start, a line typed, 2 s of quiet, and the screen that holds what
# the shell printed; a text in the output since the send, a limit that
# passes first (75), the raw bytes, the list, the status of a shell that
# exited (69, and its screen still read), stop, and the socket's modes. Then
# PODSSH_LISTEN=no (78, nothing made), and a client of another user, which
# is closed while this user's is served: the abstract namespace has no file
# to guard it, so the check of the user does. The planted defect, that
# check skipped, fails session.other_user. Sourced by scripts/interop-each.sh;
# uses ok, bad, expect_rc, $BIN, $W, $K, $T and $KH.

echo
echo "== podssh session (T-186, OpenSSH and Dropbear)"
SW="$W/session"
mkdir -p "$SW"
# s [podssh session arguments...]: with the run's home, so the sockets are
# in $W/.cache/podssh/sessions, no agent and nothing on stdin.
s() {
    timeout 90 env -u SSH_AUTH_SOCK -u PODSSH_LISTEN HOME="$W" "$BIN" session "$@" </dev/null
}
# The connection flags of a start: this run's key and known_hosts.
conn() {
    echo "--direct -p $1 -o UserKnownHostsFile=$KH -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K"
}

# shellcheck disable=SC2046
s start o $(conn 2201) "$T" >"$SW/start.out" 2>"$SW/start.err"
rc=$?
sock=$(cat "$SW/start.out")
[ "$rc" = 0 ] && [ -S "$sock" ] && ok session.start "start: ready, its socket at $sock" ||
    bad session.start "start: exit $rc, socket '$sock'" "$SW/start.err"
[ "$(stat -c %a "$sock" 2>/dev/null)" = 600 ] && [ "$(stat -c %a "$(dirname "$sock")" 2>/dev/null)" = 700 ] \
    && ok session.socket_mode "the socket is mode 0600, in a directory of mode 0700" \
    || bad session.socket_mode "modes $(stat -c %a "$sock" 2>&1) and $(stat -c %a "$(dirname "$sock")" 2>&1)"

s send o 'echo hi' >"$SW/out" 2>"$SW/err" && s wait o --idle 2s >"$SW/wait" 2>>"$SW/err" \
    && s capture o >"$SW/screen" 2>>"$SW/err"
rc=$?
[ "$rc" = 0 ] && grep -qx hi "$SW/screen" && [ "$(cat "$SW/wait")" = idle ] \
    && ok session.screen "send 'echo hi', 2 s of quiet, and the screen has a row hi" \
    || bad session.screen "exit $rc; the screen:" "$SW/screen"
s capture --raw o >"$SW/raw" 2>"$SW/err"
rc=$?
[ "$rc" = 0 ] && grep -q "$(printf 'hi\r')" "$SW/raw" && ok session.raw "capture --raw: the bytes as they came, hi and CR LF" ||
    bad session.raw "capture --raw: exit $rc" "$SW/err"
# The echo of the line holds the sum, which the shell prints as mark-42.
# shellcheck disable=SC2016
s send o 'echo mark-$((6*7))' >/dev/null 2>"$SW/err" && s wait o --match mark-42 --timeout 20s >"$SW/wait" 2>>"$SW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$SW/wait")" = match ] && ok session.match "wait --match: a text that came after the send" ||
    bad session.match "wait --match: exit $rc" "$SW/err"
s wait o --match never-printed --timeout 2s >/dev/null 2>"$SW/err"
expect_rc session.timeout "wait --match with a text that never comes: the limit first" 75 $? "$SW/err"
s list >"$SW/list" 2>"$SW/err"
want=$(printf 'o\trunning\t%s' "$T")
grep -qxF "$want" "$SW/list" && ok session.list "list: o, running, $T" || bad session.list "list" "$SW/list"
s send o 'exit 3' >/dev/null 2>"$SW/err"
s wait o --idle 2s >/dev/null 2>"$SW/err"
rc=$?
s capture o >"$SW/screen" 2>/dev/null
src=$?
[ "$rc" = 69 ] && grep -q "status 3" "$SW/err" && [ "$src" = 0 ] && grep -q 'exit 3' "$SW/screen" \
    && ok session.status "a shell that exited 3: wait gives 69 and the status, and the screen is still read" \
    || bad session.status "wait: exit $rc, capture: exit $src" "$SW/err"
s stop o >/dev/null 2>"$SW/err"
rc=$?
tries=0
while [ -e "$sock" ] && [ "$tries" -lt 50 ]; do sleep 0.1; tries=$((tries + 1)); done
s send o 'echo late' >/dev/null 2>&1
lrc=$?
[ "$rc" = 0 ] && [ ! -e "$sock" ] && [ "$lrc" = 69 ] && ok session.stop "stop: the socket goes, and a later send gives 69" ||
    bad session.stop "stop: exit $rc, then send: exit $lrc" "$SW/err"

# shellcheck disable=SC2046
s start d $(conn 2203) "$T" >"$SW/start.out" 2>"$SW/err" && s send d 'echo hi' >/dev/null 2>>"$SW/err" \
    && s wait d --idle 2s >/dev/null 2>>"$SW/err" && s capture d >"$SW/screen" 2>>"$SW/err"
rc=$?
s stop d >/dev/null 2>&1
[ "$rc" = 0 ] && grep -qx hi "$SW/screen" && ok session.dropbear "Dropbear: start, send, wait and a screen with hi" ||
    bad session.dropbear "Dropbear: exit $rc" "$SW/err"

# shellcheck disable=SC2046
timeout 30 env -u SSH_AUTH_SOCK PODSSH_LISTEN=no HOME="$W" "$BIN" session start n $(conn 2201) "$T" </dev/null \
    >/dev/null 2>"$SW/err"
rc=$?
[ "$rc" = 78 ] && [ ! -e "$(dirname "$sock")/n.sock" ] && ok session.listen_off "PODSSH_LISTEN=no: 78, and no socket" ||
    bad session.listen_off "PODSSH_LISTEN=no: exit $rc" "$SW/err"

# A client of another user, at a name of Linux's abstract namespace.
cp "$BIN" /tmp/podssh-session-other && chmod 755 /tmp/podssh-session-other
name="@podssh-session-$$"
# shellcheck disable=SC2046
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" session serve u --socket "$name" $(conn 2201) "$T" </dev/null \
    >"$SW/serve.out" 2>"$SW/serve.err" &
spid=$!
tries=0
while ! grep -q '"ready":true' "$SW/serve.out" 2>/dev/null && [ "$tries" -lt 100 ]; do sleep 0.2; tries=$((tries + 1)); done
other=$(timeout 30 su podtest -s /bin/sh -c "/tmp/podssh-session-other session capture --socket $name u" 2>"$SW/other.err")
orc=$?
s capture --socket "$name" u >/dev/null 2>"$SW/err"
mrc=$?
s stop --socket "$name" u >/dev/null 2>&1
wait "$spid"
rm -f /tmp/podssh-session-other
grep -q "closed a client of uid" "$SW/serve.err" && [ "$orc" = 69 ] && [ -z "$other" ] && [ "$mrc" = 0 ] \
    && ok session.other_user "a client of another user is closed with no answer, and this user's is served" \
    || bad session.other_user "another user: exit $orc, '$other'; this user: exit $mrc" "$SW/serve.err"
