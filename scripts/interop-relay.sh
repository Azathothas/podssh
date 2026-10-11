# podssh relay status, info and trace (T-058) through the stand-in relay,
# with real OpenSSH as the target of a trace. Sourced by
# scripts/interop-faults.sh while its stand-ins run; uses its ok, bad, port,
# $FK, $PINS, $W and $BIN.

echo
echo "== relay status, info and trace (the stand-in relay, OpenSSH behind it)"

# rl [relay arguments...]: podssh relay through relay-a.test.
rl() {
    env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u PODSSH_RELAY_TOKEN \
        HOME="$W" "$BIN" relay "$@" --relay-host "relay-a.test:$(port a)" --relay-addr "$PINS" --ca-file "$FK/ca.pem"
}

rl status >"$FK/relay.out" 2>"$FK/relay.err" </dev/null
rc=$?
[ "$rc" = 0 ] && grep -q '^relay-a.test: tcp-ssh-relay fake at edge TEST, ' "$FK/relay.out" \
    && ok relay.status "the stand-in's /health, verified" \
    || bad relay.status "exit $rc: $(cat "$FK/relay.out")" "$FK/relay.err"

rl info 127.0.0.1 2201 >"$FK/relay.out" 2>"$FK/relay.err" </dev/null
rc=$?
[ "$rc" = 0 ] && grep -q '^pool, best first: 1 hosts$' "$FK/relay.out" \
    && grep -q "^for 127.0.0.1:2201: wss://relay-a.test:$(port a)/connect/127.0.0.1/2201$" "$FK/relay.out" \
    && ok relay.info "the pool, and the URL for a target" \
    || bad relay.info "exit $rc: $(cat "$FK/relay.out")" "$FK/relay.err"

# The stand-in dials only with the token in its header, as the relay does.
rl trace 127.0.0.1 2201 >"$FK/relay.out" 2>"$FK/relay.err" </dev/null
rc=$?
[ "$rc" = 0 ] && grep -q '^banner: SSH-2.0-OpenSSH' "$FK/relay.out" \
    && ok relay.trace.banner "OpenSSH's banner through the stand-in, the token in its header" \
    || bad relay.trace.banner "exit $rc: $(cat "$FK/relay.out")" "$FK/relay.err"

rl trace 'a&b' 22 >"$FK/relay.out" 2>"$FK/relay.err" </dev/null
rc=$?
[ "$rc" = 64 ] && ok relay.trace.bad_host "a HOST of a&b exits 64" \
    || bad relay.trace.bad_host "a&b: exit $rc" "$FK/relay.err"
