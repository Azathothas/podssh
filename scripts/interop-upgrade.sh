# podssh ssh --upgrade (T-167) against OpenSSH (2201) and Dropbear (2203),
# through the stand-in relay. With no podssh on the server's PATH, the
# session stays on the first connection, with one note: a client that
# started a node with no probe would say another thing. With one (a wrapper
# in /usr/bin that runs the binary under test with the stand-in's trust and
# pins), the session moves to a temporary node, and survives a cut of its
# link to the relay, which a stand-in proxy makes during the remote command.
# Sourced by scripts/interop-faults.sh after scripts/interop-roost.sh; uses
# their ok, bad, port, waitfor, $FK, $PINS, $W, $K, $KH, $HERE and $BIN.

echo
echo "== podssh ssh --upgrade (OpenSSH and Dropbear, the stand-in relay's reverse road)"
UP="$FK/upgrade"
mkdir -p "$UP"

# up PORT [ssh arguments...]: podssh ssh --upgrade through relay-a.test to
# the server on PORT, with this harness's cache; through the proxy $UPX when
# it is set.
UPX=
up() {
    _port=$1
    shift
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY ${UPX:+https_proxy=$UPX} \
        XDG_CACHE_HOME="$UP/cache" HOME="$W" "$BIN" ssh --upgrade --relay-host "relay-a.test:$(port a)" \
        --relay-addr "$PINS" --ca-file "$FK/ca.pem" -p "$_port" -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes "$@"
}

if command -v podssh >/dev/null 2>&1; then
    bad upgrade.none "a podssh is on this host's PATH already: $(command -v podssh)"
else
    up 2201 podtest@127.0.0.1 'echo stayed' >"$UP/out" 2>"$UP/err" </dev/null
    rc=$?
    [ "$rc" = 0 ] && [ "$(cat "$UP/out")" = stayed ] && [ "$(grep -c 'no podssh answers there' "$UP/err")" = 1 ] \
        && ok upgrade.none "with no podssh on the server, the session stays on its connection, with one note" \
        || bad upgrade.none "with no podssh on the server: exit $rc" "$UP/err"
fi

# The server's podssh: the binary under test, which the test user can run,
# with the stand-in's trust and pins.
cp "$BIN" "$UP/podssh-under-test"
chmod 755 "$UP" "$UP/podssh-under-test"
cat >/usr/bin/podssh <<EOF
#!/bin/sh
exec env SSL_CERT_FILE="$FK/ca.pem" PODSSH_RELAY="relay-a.test:$(port a)" PODSSH_RELAY_ADDR="$PINS" \
    "$UP/podssh-under-test" "\$@"
EOF
chmod 755 /usr/bin/podssh

for srv in openssh:2201 dropbear:2203; do
    sport=${srv#*:}
    name=${srv%%:*}
    # 1 s after the remote command makes the start file, the proxy ends each
    # tunnel open then with RST; the first connection closed already, once
    # the login through the node was done.
    START=/home/podtest/upgrade-start-$name
    rm -f "$START" "$UP/$name.proxy.port"
    python3 "$HERE/fake-proxy.py" --port-file "$UP/$name.proxy.port" --log "$UP/$name.proxy.log" \
        --map "relay-a.test=127.0.0.1:$(port a)" --start-file "$START" --stop-after 1 >/dev/null 2>&1 &
    echo $! >"$UP/$name.proxy.pid"
    waitfor "$UP/$name.proxy.port" .
    UPX="http://127.0.0.1:$(cat "$UP/$name.proxy.port")"
    up "$sport" -v podtest@127.0.0.1 "touch $START; sleep 4; echo upgrade-survived" >"$UP/out" 2>"$UP/err" </dev/null
    rc=$?
    UPX=
    [ "$rc" = 0 ] && [ "$(cat "$UP/out")" = upgrade-survived ] && grep -q "the temporary node took the session" "$UP/err" \
        && grep -q "resuming the session" "$UP/err" && grep -q "the session resumed" "$UP/err" \
        && ok "upgrade.cut.${srv%%:*}" "port $sport: the session moved to a temporary node, and resumed after a cut link" \
        || bad "upgrade.cut.${srv%%:*}" "port $sport, --upgrade with a cut link: exit $rc" "$UP/err"
    kill "$(cat "$UP/$name.proxy.pid")" 2>/dev/null
    rm -f "$START"
done
rm -f /usr/bin/podssh
