# --sudo (T-032): a command as root through OpenSSH's sshd, with sudo -S and
# the password from SSH_ASKPASS, whose program logs each question. With a
# rule that needs a password: one question and the command runs; a wrong
# password ends with sudo's refusal; with a NOPASSWD rule, no question.
# Sourced by scripts/interop.sh once its servers run; uses ok, bad, $W, $BIN,
# $KH, $K, $T and $PW, the password of podtest.

echo
echo "== --sudo: a command as root, the password from SSH_ASKPASS (T-032)"
cat >"$W/askpass-sudo" <<'EOF'
#!/bin/sh
echo "$1" >>"$PODSSH_TEST_ASKED"
printf '%s\n' "$PODSSH_TEST_PW"
EOF
chmod 700 "$W/askpass-sudo"
grep -q '^[@#]includedir /etc/sudoers.d' /etc/sudoers || echo '@includedir /etc/sudoers.d' >>/etc/sudoers
mkdir -p /etc/sudoers.d
sudo_rule() { # RULE: the only rule of podtest
    printf 'podtest ALL=(ALL) %s\n' "$1" >/etc/sudoers.d/podtest
    chmod 440 /etc/sudoers.d/podtest
}
sudo_run() { # PASSWORD: --sudo 'id -u', its password from the askpass program
    : >"$W/asked"
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK HOME="$W" SSH_ASKPASS="$W/askpass-sudo" SSH_ASKPASS_REQUIRE=force \
        PODSSH_TEST_ASKED="$W/asked" PODSSH_TEST_PW="$1" "$BIN" ssh --direct -p 2201 \
        -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o IdentityAgent=none \
        -o IdentitiesOnly=yes $K --sudo "$T" 'id -u' </dev/null >"$W/out" 2>"$W/err"
}
sudo_rule ALL
sudo_run "$PW"
rc=$?
asked=$(grep -c . "$W/asked")
[ "$rc" = 0 ] && [ "$(cat "$W/out")" = 0 ] && [ "$asked" = 1 ] \
    && ok sudo.password "--sudo: one question through SSH_ASKPASS, and id -u gives 0" \
    || bad sudo.password "--sudo: exit $rc, output '$(cat "$W/out")', $asked questions" "$W/err"
sudo_run wrong-password
rc=$?
[ "$rc" = 1 ] && grep -q 'the password was refused' "$W/err" && [ ! -s "$W/out" ] \
    && ok sudo.wrong "--sudo with a wrong password: sudo refuses it, and podssh says so" \
    || bad sudo.wrong "--sudo with a wrong password: exit $rc" "$W/err"
sudo_rule 'NOPASSWD: ALL'
sudo_run "$PW"
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/out")" = 0 ] && [ ! -s "$W/asked" ] \
    && ok sudo.nopass "--sudo with a NOPASSWD rule: no question, and id -u gives 0" \
    || bad sudo.nopass "--sudo with a NOPASSWD rule: exit $rc, output '$(cat "$W/out")', asked: $(cat "$W/asked")" "$W/err"
rm -f /etc/sudoers.d/podtest
