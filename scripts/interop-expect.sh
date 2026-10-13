# LocalCommand and the expect rules of podssh ssh (T-191) against OpenSSH on
# port 2201 and Dropbear on port 2203: PermitLocalCommand=yes runs
# LocalCommand with its % tokens, and =no runs nothing (the planted
# defect, a LocalCommand run with no PermitLocalCommand, fails
# expect.local_command_no); its output comes before the session's, in the
# order of OpenSSH's own ssh; with -tt, --expect '$ ' --send 'echo EXP\r'
# --expect EXP --send 'exit 4\r' in a login shell exits 4, and a rule that
# sees no match ends the session with 255 within its time and a little more.
# Sourced by scripts/interop-each.sh; uses ok, bad, expect_rc, p, $BIN, $W,
# $K, $T and $KH.

echo
echo "== podssh ssh: LocalCommand and the expect rules (T-191)"
XW="$W/expect"
mkdir -p "$XW"
rm -f /tmp/lc-127.0.0.1
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -o PermitLocalCommand=no -o LocalCommand='touch /tmp/lc-%h' "$T" true \
    </dev/null >"$XW/out" 2>"$XW/err"
rc=$?
[ "$rc" = 0 ] && [ ! -e /tmp/lc-127.0.0.1 ] \
    && ok expect.local_command_no "PermitLocalCommand=no: LocalCommand does not run" \
    || bad expect.local_command_no "exit $rc; /tmp/lc-127.0.0.1 $( [ -e /tmp/lc-127.0.0.1 ] && echo is || echo is not) there" "$XW/err"
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -o PermitLocalCommand=yes -o LocalCommand='touch /tmp/lc-%h' "$T" true \
    </dev/null >"$XW/out" 2>"$XW/err"
rc=$?
[ "$rc" = 0 ] && [ -e /tmp/lc-127.0.0.1 ] \
    && ok expect.local_command "PermitLocalCommand=yes: LocalCommand='touch /tmp/lc-%h' made /tmp/lc-127.0.0.1" \
    || bad expect.local_command "exit $rc; no /tmp/lc-127.0.0.1" "$XW/err"
rm -f /tmp/lc-127.0.0.1
# The order of LocalCommand's output and the session's, by podssh and by
# OpenSSH's own ssh, which the image has for ssh -G.
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -o PermitLocalCommand=yes -o LocalCommand='echo LOCAL' "$T" 'echo REMOTE' \
    </dev/null >"$XW/podssh" 2>"$XW/err"
env -u SSH_AUTH_SOCK HOME="$W" timeout 60 ssh -F /dev/null -p 2201 -i "$W/id_ed25519" -o IdentitiesOnly=yes \
    -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
    -o PermitLocalCommand=yes -o LocalCommand='echo LOCAL' "$T" 'echo REMOTE' </dev/null >"$XW/openssh" 2>"$XW/err2"
[ "$(cat "$XW/podssh")" = "$(printf 'LOCAL\nREMOTE')" ] && [ "$(cat "$XW/openssh")" = "$(cat "$XW/podssh")" ] \
    && ok expect.local_order "LocalCommand's output, then the session's, as OpenSSH's ssh gives them" \
    || bad expect.local_order "podssh: $(tr '\n' ' ' <"$XW/podssh"); OpenSSH: $(tr '\n' ' ' <"$XW/openssh")" "$XW/err2"
for srv in openssh:2201 dropbear:2203; do
    # shellcheck disable=SC2086
    p "${srv#*:}" $K -o BatchMode=yes -tt --expect '$ ' --send 'echo EXP\r' --expect EXP --send 'exit 4\r' "$T" \
        </dev/null >"$XW/out" 2>"$XW/err"
    expect_rc "expect.rules.${srv%%:*}" "-tt, a login shell: --expect '\$ ' --send 'echo EXP\\r' --expect EXP --send 'exit 4\\r'" \
        4 $? "$XW/err"
done
start=$(date +%s)
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -tt --expect NEVER --send x --expect-timeout 2s "$T" </dev/null >"$XW/out" 2>"$XW/err"
rc=$?
took=$(($(date +%s) - start))
[ "$rc" = 255 ] && [ "$took" -le 5 ] && grep -q 'expect 1 ("NEVER") saw no match within 2 s' "$XW/err" \
    && ok expect.timeout "--expect NEVER --expect-timeout 2s: exit 255 in ${took} s, the rule named" \
    || bad expect.timeout "exit $rc in ${took} s" "$XW/err"
