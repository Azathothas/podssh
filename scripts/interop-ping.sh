# podssh ping (T-053) through the stand-in relay, with real OpenSSH behind
# it. Sourced by scripts/interop-faults.sh while its stand-ins run; uses its
# ok, bad, port, $FK, $PINS, $W, $T, $K, $KH and $BIN. The relay leg's
# target is the OpenSSH server too, whose configuration here sets
# PerSourcePenalties no: a leg sends no SSH bytes to it.

echo
echo "== ping (the stand-in relay, OpenSSH behind it)"

# ping_via [ping arguments...]: podssh ping through relay-a.test; not `p`,
# which would replace interop.sh's own for each harness sourced after this.
ping_via() {
    env -u SSH_AUTH_SOCK -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY HOME="$W" "$BIN" ping \
        --relay-host "relay-a.test:$(port a)" --relay-addr "$PINS" --ca-file "$FK/ca.pem" \
        --target 127.0.0.1:2201 "$@"
}

ping_via --count 10 >"$FK/ping.out" 2>"$FK/ping.err" </dev/null
rc=$?
[ "$rc" = 0 ] && grep -q '; 10 pings: min ' "$FK/ping.out" && ! grep -q lost "$FK/ping.out" \
    && ok ping.relay_leg "a pong for each of 10 pings through the stand-in relay" \
    || bad ping.relay_leg "the relay leg: exit $rc: $(cat "$FK/ping.out")" "$FK/ping.err"

# The default size, 8 MiB, each way.
# shellcheck disable=SC2086
ping_via -p 2201 -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o IdentityAgent=none \
    -o IdentitiesOnly=yes $K -o BatchMode=yes "$T" >"$FK/ping.out" 2>"$FK/ping.err" </dev/null
rc=$?
[ "$rc" = 0 ] && grep -q "^ssh $T: login " "$FK/ping.out" && grep -q '^echo (cat), 10 bytes: ' "$FK/ping.out" \
    && grep -q '^down (head -c 8388608 /dev/zero): 8.0 MiB in ' "$FK/ping.out" \
    && grep -q '^up (cat > /dev/null): 8.0 MiB in ' "$FK/ping.out" \
    && ok ping.openssh "OpenSSH through the stand-in: the login, the echo, and 8 MiB each way (exit 0)" \
    || bad ping.openssh "OpenSSH through the stand-in: exit $rc: $(cat "$FK/ping.out")" "$FK/ping.err"

# --json: one document, with the same measures.
# shellcheck disable=SC2086
ping_via --size 1M -p 2201 -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o IdentityAgent=none \
    -o IdentitiesOnly=yes $K -o BatchMode=yes "$T" --json >"$FK/ping.json" 2>"$FK/ping.err" </dev/null
rc=$?
[ "$rc" = 0 ] && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["exit"] == 0 and d["destination"]["down"]["bytes"] == 1048576 and d["relays"][0]["pings_lost"] == 0, d' "$FK/ping.json" 2>>"$FK/ping.err" \
    && ok ping.json "--json through the stand-in to OpenSSH is one document" \
    || bad ping.json "--json: exit $rc" "$FK/ping.err"
