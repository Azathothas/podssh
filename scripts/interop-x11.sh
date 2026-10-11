# -X and -Y (T-037): X11 forwarding through OpenSSH's sshd, with
# X11Forwarding and xauth, to an Xvfb on :9 of this container whose cookie
# only its authority file holds. Sourced by scripts/interop.sh once its
# servers run; uses ok, bad, unmet, sshd_conf, wait_ports, $W, $BIN, $KH, $K
# and $T. Its sshd is on port 2213, and it and the Xvfb stop after the block.

echo
echo "== -X and -Y: X11 forwarding to an Xvfb (T-037)"
X11_COOKIE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
: >"$W/xauthority"
xauth -f "$W/xauthority" add :9 MIT-MAGIC-COOKIE-1 "$X11_COOKIE"
Xvfb :9 -auth "$W/xauthority" -nolisten tcp >"$W/xvfb.log" 2>&1 &
XVFB=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S /tmp/.X11-unix/X9 ] && break
    sleep 0.5
done
sshd_conf 2213 "X11Forwarding yes" "X11UseLocalhost yes" "XAuthLocation /usr/bin/xauth"
/usr/sbin/sshd -f "$W/sshd-2213.conf" -E "$W/sshd-2213.log" || cat "$W/sshd-2213.log"
wait_ports 2213 || cat "$W/sshd-2213.log"
x11_run() { # FLAG COMMAND: podssh with FLAG to port 2213, DISPLAY=:9
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK HOME="$W" DISPLAY=:9 XAUTHORITY="$W/xauthority" "$BIN" ssh --direct -p 2213 \
        -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o IdentityAgent=none \
        -o IdentitiesOnly=yes $K -o BatchMode=yes "$1" "$T" "$2" </dev/null >"$W/out" 2>"$W/err"
}
x11_run -Y 'xdpyinfo >/dev/null && echo x11-ok'
rc=$?
[ "$rc" = 0 ] && grep -qx x11-ok "$W/out" \
    && ok x11.trusted "-Y: xdpyinfo on the server reaches the Xvfb of this host" \
    || bad x11.trusted "-Y: exit $rc, output '$(cat "$W/out")'" "$W/err"
x11_run -Y 'xauth list'
rc=$?
[ "$rc" = 0 ] && grep -q MIT-MAGIC-COOKIE-1 "$W/out" && ! grep -q "$X11_COOKIE" "$W/out" \
    && ok x11.spoofed "-Y: the server holds a spoofed cookie, never the real one" \
    || bad x11.spoofed "-Y: exit $rc; the server's cookies: $(cat "$W/out")" "$W/err"
# Whether this Xvfb takes an untrusted cookie of xauth at all, without
# podssh: when it does not, -X cannot work here, and the check is env.
rm -f "$W/xauth-untrusted"
XAUTHORITY="$W/xauthority" xauth -f "$W/xauth-untrusted" generate :9 MIT-MAGIC-COOKIE-1 untrusted timeout 120 \
    >"$W/untrusted.log" 2>&1 && XAUTHORITY="$W/xauth-untrusted" xdpyinfo >/dev/null 2>>"$W/untrusted.log"
direct=$?
x11_run -X 'xdpyinfo >/dev/null && echo x11-ok'
rc=$?
if [ "$direct" != 0 ]; then
    unmet x11.untrusted "-X: this Xvfb takes no untrusted cookie of xauth, even with no podssh: $(tr '\n' ' ' <"$W/untrusted.log")"
elif [ "$rc" = 0 ] && grep -qx x11-ok "$W/out"; then
    ok x11.untrusted "-X: an untrusted cookie of xauth, and xdpyinfo reaches the Xvfb"
else
    bad x11.untrusted "-X: exit $rc, output '$(cat "$W/out")', where the Xvfb takes the cookie with no podssh" "$W/err"
fi
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK -u DISPLAY HOME="$W" "$BIN" ssh --direct -p 2213 -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes \
    -Y "$T" true </dev/null >"$W/out" 2>"$W/err"
rc=$?
[ "$rc" = 255 ] && grep -q 'DISPLAY is not set' "$W/err" \
    && ok x11.no_display "-Y with no DISPLAY: refused before the connection, by name" \
    || bad x11.no_display "-Y with no DISPLAY: exit $rc" "$W/err"
kill "$(cat "$W/sshd-2213.pid")" 2>/dev/null
kill "$XVFB" 2>/dev/null
