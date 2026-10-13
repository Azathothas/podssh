# podssh each (T-183) against OpenSSH on port 2201 and Dropbear on port
# 2203 at once: a line for each host with its label, the largest status as
# the exit in each order of the hosts (the planted defect, the first host's
# status, fails the order 0, 3), a closed port named with 255, the files of
# --output-dir, a host key that no question can accept, and --fail-fast.
# Sourced by scripts/interop.sh; uses ok, bad, expect_rc, $BIN, $W, $K, $T
# and $KH.

echo
echo "== podssh each (T-183, OpenSSH and Dropbear at once)"
EW="$W/each"
mkdir -p "$EW"
# e [podssh each arguments...]: podssh each as p() runs ssh.
e() {
    # shellcheck disable=SC2086
    timeout 120 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" each --direct -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K "$@" </dev/null
}
BOTH="$T:2201,$T:2203"

e "$BOTH" -- 'echo out; exit 3' >"$EW/out" 2>"$EW/err"
rc=$?
[ "$rc" = 3 ] && grep -qx "$T:2201: out" "$EW/out" && grep -qx "$T:2203: out" "$EW/out" \
    && [ "$(wc -l <"$EW/out")" -eq 2 ] \
    && ok each.lines "echo out; exit 3 on both: exit 3, and one line for each host with its label" \
    || bad each.lines "exit $rc" "$EW/out"
# SSH_CONNECTION ends with the server's port: 0 from OpenSSH, 3 from Dropbear.
# shellcheck disable=SC2016
by_port='case "$SSH_CONNECTION" in *" 2203") exit 3 ;; esac; exit 0'
e "$T:2201,$T:2203" -- "$by_port" >"$EW/out" 2>"$EW/err"
expect_rc each.order.0_3 "the statuses 0, then 3: the largest" 3 $? "$EW/err"
e "$T:2203,$T:2201" -- "$by_port" >"$EW/out" 2>"$EW/err"
expect_rc each.order.3_0 "the statuses 3, then 0: the largest" 3 $? "$EW/err"
e "$BOTH,$T:2299" -- true >"$EW/out" 2>"$EW/err"
rc=$?
[ "$rc" = 255 ] && grep -q "^podssh each: .*$T:2299 .*255, no session" "$EW/err" \
    && ok each.closed "a closed port beside two good hosts: exit 255, and the summary names it" \
    || bad each.closed "exit $rc" "$EW/err"
e --output-dir "$EW/dir" "$BOTH" -- 'printf "a\\r\\nb"; printf x >&2; exit 3' >"$EW/out" 2>"$EW/err"
rc=$?
f="$EW/dir/podtest@127.0.0.1%3A2203"
[ "$rc" = 3 ] && [ ! -s "$EW/out" ] && [ "$(od -An -c "$f.out" | tr -d ' \n')" = 'a\r\nb' ] \
    && [ "$(cat "$f.err")" = x ] && [ "$(cat "$f.status")" = 3 ] \
    && ok each.output_dir "--output-dir: the bytes unchanged in HOST.out and HOST.err, the status in HOST.status" \
    || bad each.output_dir "exit $rc; $(od -An -c "$f.out" 2>&1 | head -2)" "$EW/err"
# shellcheck disable=SC2086
timeout 120 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" each --direct -o UserKnownHostsFile="$EW/none" \
    -o IdentityAgent=none $K "$T:2201" -- true </dev/null >"$EW/out" 2>"$EW/err"
rc=$?
[ "$rc" = 255 ] && grep -q "^podssh: $T:2201: .*BatchMode" "$EW/err" && grep -q "accept-new" "$EW/err" \
    && [ ! -e "$EW/none" ] \
    && ok each.host_key "an unknown host key refuses its host with no question, and names accept-new" \
    || bad each.host_key "exit $rc" "$EW/err"
rm -f /tmp/podssh-each-ran
e --parallel 1 --fail-fast "$T:2299,$T:2201" -- 'touch /tmp/podssh-each-ran' >"$EW/out" 2>"$EW/err"
rc=$?
[ "$rc" = 255 ] && [ ! -e /tmp/podssh-each-ran ] && grep -q "not started (--fail-fast)" "$EW/err" \
    && ok each.fail_fast "--fail-fast with one at once: after the closed port, no host started" \
    || bad each.fail_fast "exit $rc" "$EW/err"

# podssh session (T-186), with the same servers and helpers; sourced here so
# that scripts/interop.sh stays within 500 lines.
# shellcheck source=scripts/interop-session.sh
. "$HERE/interop-session.sh"
