#!/bin/sh
# TEMPORARY (T-415): why a read of the box's dead /dev/tty outlives SIGKILL
# on GitHub's runner. Runs as root on the runner, each variant bounded.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
F=/tmp/diag-tty.path
rm -f "$F"
(setsid nohup python3 "$HERE/deadtty.py" 600 "$F" >/dev/null 2>&1 </dev/null &)
for i in 1 2 3 4 5 6 7 8 9 10; do [ -s "$F" ] && break; sleep 1; done
SLAVE=$(cat "$F")
echo "slave: $SLAVE; kernel: $(uname -r); podman: $(podman --version)"
aa-status 2>/dev/null | head -5
INNER='dd if=/dev/tty of=/dev/null bs=1 count=1 2>/tmp/dd.err & p=$!; sleep 3
echo "inner: dd pid $p; state: $(grep -E "^(State|SigIgn|SigBlk|SigPnd|ShdPnd)" /proc/$p/status | tr "\n" " ")"
echo "inner: wchan $(cat /proc/$p/wchan 2>&1); syscall $(cut -d" " -f1-3 /proc/$p/syscall 2>&1)"
echo "inner: fd0 $(readlink /proc/$p/fd/0 2>&1); ctty $(cut -d" " -f7 /proc/$p/stat)"
kill -KILL $p; echo "inner: kill rc=$?"; sleep 2
if [ -d /proc/$p ]; then echo "inner: after SIGKILL: $(grep State /proc/$p/status)"; else echo "inner: dd gone after SIGKILL"; fi
sleep 8; [ -d /proc/$p ] && echo "inner: still there after 10 s: $(grep State /proc/$p/status)"; echo "inner: end"'
variant() {
    name=$1; shift
    echo "== $name"
    podman rm -f diag >/dev/null 2>&1
    timeout 60 podman run -d --name diag "$@" --mount "type=bind,source=$SLAVE,target=/dev/tty" \
        docker.io/library/alpine:3 sh -c "$INNER" >/dev/null || { echo "podman run failed"; return; }
    sleep 2
    hp=$(podman top diag hpid comm 2>/dev/null | awk '$2 == "dd" { print $1 }' | head -1)
    echo "host: dd host pid ${hp:-none}"
    if [ -n "$hp" ]; then
        echo "host: wchan $(cat /proc/$hp/wchan); stack:"; cat /proc/$hp/stack 2>&1 | head -12
    fi
    timeout 30 podman wait diag >/dev/null 2>&1
    timeout 10 podman logs diag 2>&1
    if [ -n "$hp" ] && [ -d "/proc/$hp" ]; then
        echo "host: dd still alive after the box's kill; host kill -9"; kill -9 "$hp"; sleep 2
        [ -d "/proc/$hp" ] && { echo "host: alive after host SIGKILL: $(grep State /proc/$hp/status)"; cat /proc/$hp/stack; }
    fi
    timeout 30 podman rm -f diag >/dev/null 2>&1
}
SEC="$HERE/seccomp.json"
variant "as the box: cap-drop, no-new-privileges, seccomp, mask=/dev/pts" --cap-drop all --security-opt no-new-privileges --security-opt "seccomp=$SEC" --security-opt mask=/dev/pts
variant "no mask=/dev/pts" --cap-drop all --security-opt no-new-privileges --security-opt "seccomp=$SEC"
variant "no seccomp file" --cap-drop all --security-opt no-new-privileges --security-opt mask=/dev/pts
variant "plain" 
variant "apparmor unconfined" --cap-drop all --security-opt no-new-privileges --security-opt "seccomp=$SEC" --security-opt mask=/dev/pts --security-opt apparmor=unconfined
rm -f "$F"
