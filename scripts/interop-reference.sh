# Each exit code against OpenSSH's own client (T-225). Each case of the
# matrix of exit statuses and of the refusals of scripts/interop.sh runs
# OpenSSH's ssh first, with the same server, port, key, known_hosts,
# BatchMode and command (p_ref and direct_ref, scripts/interop-lib.sh), then
# podssh. Its check ssh.ID keeps the literal, the promise; its expect_rc
# records both codes in $W/refs, and here the case gets a second check,
# ref.ID: podssh's code must be OpenSSH's, or the row of the table below that
# names the case. Sourced by scripts/interop.sh after its host keys; uses ok,
# bad, unmet, $W and $PAM_SSHD.

echo
echo "== each exit code against OpenSSH's own client (T-225; ssh.ID keeps the literal)"

# differs ID: the difference on purpose that names the case ID, if any: the
# row's name in $row, OpenSSH's code, podssh's code and the reason. A
# difference that no row names fails; a row that the run does not meet fails
# as broken, so that a change of either client is seen. Read in OpenSSH's
# source (openssh-portable, 2026-10-12), measured by the gate.
differs() {
    row=
    row_openssh=
    row_podssh=
    row_why=
    case $1 in
        ssh.exit.openssh.143 | ssh.exit.dropbear.143)
            row=signal row_openssh=255 row_podssh=143
            row_why="podssh gives 128 plus the signal's number and names the signal; OpenSSH's client reads no exit-signal and gives 255 (docs/cli.md, Exit codes)"
            ;;
        ssh.hostkey.changed_refused)
            row=changed_key row_openssh=0 row_podssh=255
            row_why="podssh refuses a changed host key under each StrictHostKeyChecking; OpenSSH's no warns, turns off passwords and forwarding, and logs in with a key (docs/cli.md, Prompts and time limits)"
            ;;
        ssh.hostkey.unreadable_refused)
            row=unreadable_known_hosts row_openssh=0 row_podssh=255
            row_why="podssh refuses a key that it cannot verify while a known_hosts file cannot be read (T-028); OpenSSH reads a directory there as empty, fails to add the key, and logs in"
            ;;
    esac
}

# judge ID: 0 when the case ssh.ID meets OpenSSH's code, or the row of
# differs that names it; else 1. The codes, and on a failure OpenSSH's
# command line, are in $why.
judge() {
    # A tab itself, not `\t`, which not each awk reads as a tab in -F.
    _rec=$(awk -F "$(printf '\t')" -v id="ssh.$1" '$1 == id { r = $0 } END { print r }' "$W/refs" 2>/dev/null)
    r_want=$(printf '%s\n' "$_rec" | cut -f 2)
    r_got=$(printf '%s\n' "$_rec" | cut -f 3)
    r_ref=$(printf '%s\n' "$_rec" | cut -f 4)
    r_text=$(printf '%s\n' "$_rec" | cut -f 5)
    r_cmd=$(printf '%s\n' "$_rec" | cut -f 6)
    codes="OpenSSH $r_ref, podssh $r_got, the literal $r_want"
    differs "ssh.$1"
    if [ -z "$_rec" ]; then
        why="no run of ssh.$1 recorded OpenSSH's code: its site does not call p_ref or direct_ref"
        return 1
    fi
    if [ "$r_ref" = none ]; then
        why="$r_text: no reference, as OpenSSH's ssh is not in this image"
        return 1
    fi
    if [ -n "$row" ]; then
        if [ "$r_ref" = "$row_openssh" ] && [ "$r_got" = "$row_podssh" ]; then
            why="$r_text: $codes: the difference on purpose '$row': $row_why"
            return 0
        fi
        why="$r_text: the row '$row' is broken: $codes, where it says OpenSSH $row_openssh and podssh $row_podssh; $r_cmd"
        return 1
    fi
    # A reference that passes a case that must fail is broken, whatever
    # podssh gave: OpenSSH's run did not test what the case names.
    if [ "$r_ref" = 0 ] && [ "$r_want" != 0 ]; then
        why="$r_text: OpenSSH gave 0 to a case that must fail, so the reference is broken: $codes; $r_cmd"
        return 1
    fi
    if [ "$r_ref" = "$r_got" ]; then
        why="$r_text: $codes"
        return 0
    fi
    why="$r_text: differs from OpenSSH, and no row names it: $codes; $r_cmd"
    return 1
}

command -v ssh >/dev/null 2>&1 && ok ref.client "OpenSSH's client: $(command -v ssh), $(ssh -V 2>&1)" \
    || bad ref.client "no ssh in this image (openssh-client-default): each reference below fails"
# Not here: -J (OpenSSH gives a hop of -J none of the -o options; the -F form
# is ssh.config.jump_alias, which compares the two), and podssh's own flags
# (--host-key-fingerprint).
for id in exit.openssh.3 exit.openssh.0 exit.openssh.1 exit.openssh.127 exit.openssh.143 \
        exit.dropbear.3 exit.dropbear.0 exit.dropbear.1 exit.dropbear.127 exit.dropbear.143 \
        auth.key.rsa auth.key.ecdsa auth.encrypted_askpass auth.encrypted_batch \
        auth.password.openssh auth.password.dropbear auth.wrong_password.openssh auth.wrong_password.dropbear \
        auth.password_batch auth.kbdint_pam \
        hostkey.strict_known hostkey.changed_refused hostkey.unreadable_refused hostkey.unrecordable_connects \
        hostkey.cert_accepted; do
    if [ "$id" = auth.kbdint_pam ] && [ -z "$PAM_SSHD" ]; then
        unmet "ref.${id}" "keyboard-interactive: sshd.pam is not in this image"
    elif judge "$id"; then
        ok "ref.${id}" "$why"
    else
        r_log=/dev/null
        if [ -f "$W/ref.ssh.$id.err" ]; then
            r_log="$W/ref.ssh.$id.err"
        fi
        bad "ref.${id}" "$why" "$r_log"
    fi
done
