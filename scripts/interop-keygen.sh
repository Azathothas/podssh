# podssh keygen against OpenSSH. Sourced by scripts/interop.sh once the
# servers run; uses its ok, bad, expect_rc and p, and $W, $H, $T and $BIN.
# OpenSSH's own ssh-keygen must read every key podssh makes and print the
# same fingerprint line, and sshd must accept the keys for login.

echo
echo "== keygen (checked by OpenSSH's ssh-keygen and sshd)"
KG="$W/keygen"
mkdir -p "$KG"
for spec in ed25519: ecdsa:384 rsa:3072; do
    t=${spec%%:*}
    b=${spec#*:}
    key="$KG/id_$t"
    if [ -n "$b" ]; then
        "$BIN" keygen -t "$t" -b "$b" -N '' -C "kg-$t" -q -f "$key" >"$KG/out" 2>"$KG/err"
    else
        "$BIN" keygen -t "$t" -N '' -C "kg-$t" -q -f "$key" >"$KG/out" 2>"$KG/err"
    fi
    expect_rc "keygen.make.${spec%%:*}" "keygen -t $t${b:+ -b $b}" 0 $? "$KG/err"
    [ ! -s "$KG/out" ] && ok "keygen.quiet.${spec%%:*}" "keygen -q -t $t printed nothing to stdout" \
        || bad "keygen.quiet.${spec%%:*}" "keygen -q -t $t printed to stdout" "$KG/out"
    want=$(cut -d' ' -f1,2 "$key.pub")
    theirs=$(ssh-keygen -y -f "$key" 2>"$KG/err" | cut -d' ' -f1,2)
    [ -n "$theirs" ] && [ "$theirs" = "$want" ] \
        && ok "keygen.openssh_reads.${spec%%:*}" \
            "keygen $t: OpenSSH's ssh-keygen -y reads the private key and derives the .pub key" \
        || bad "keygen.openssh_reads.${spec%%:*}" "keygen $t: ssh-keygen -y gave '$theirs'" "$KG/err"
    theirs=$(ssh-keygen -l -f "$key.pub" 2>&1)
    ours=$("$BIN" keygen -l -f "$key.pub" 2>&1)
    [ "$theirs" = "$ours" ] && ok "keygen.fingerprint.${spec%%:*}" "keygen -l $t: the line ssh-keygen -l prints ($ours)" \
        || bad "keygen.fingerprint.${spec%%:*}" "keygen -l $t: '$ours'; ssh-keygen -l: '$theirs'"
    ours=$("$BIN" keygen -y -f "$key" 2>"$KG/err" | cut -d' ' -f1,2)
    [ "$ours" = "$want" ] && ok "keygen.derive_pub.${spec%%:*}" "keygen -y $t gives the .pub key" \
        || bad "keygen.derive_pub.${spec%%:*}" "keygen -y $t: '$ours'" "$KG/err"
    cat "$key.pub" >>"$H/.ssh/authorized_keys"
    p 2201 -i "$key" -o BatchMode=yes "$T" true >"$KG/out" 2>"$KG/err" </dev/null
    expect_rc "keygen.login.${spec%%:*}" "keygen $t: sshd accepts the key for login" 0 $? "$KG/err"
done
[ "$(stat -c %a "$KG/id_ed25519")" = 600 ] && [ "$(stat -c %a "$KG/id_ed25519.pub")" = 644 ] \
    && ok keygen.modes "keygen: the private key is mode 600, the public key 644" \
    || bad keygen.modes "keygen: modes $(stat -c %a "$KG/id_ed25519") and $(stat -c %a "$KG/id_ed25519.pub")"

# A passphrase from SSH_ASKPASS: OpenSSH decrypts the key with it, refuses
# another, and the encrypted key logs in.
SSH_ASKPASS="$W/askpass-passphrase" SSH_ASKPASS_REQUIRE=force \
    "$BIN" keygen -C kg-enc -q -f "$KG/id_enc" </dev/null >"$KG/out" 2>"$KG/err"
expect_rc keygen.enc.make "keygen with a passphrase from SSH_ASKPASS" 0 $? "$KG/err"
want=$(cut -d' ' -f1,2 "$KG/id_enc.pub")
theirs=$(ssh-keygen -y -P 'open sesame' -f "$KG/id_enc" 2>"$KG/err" | cut -d' ' -f1,2)
[ -n "$theirs" ] && [ "$theirs" = "$want" ] \
    && ok keygen.enc.openssh_decrypts "keygen: OpenSSH decrypts the key with its passphrase" \
    || bad keygen.enc.openssh_decrypts "keygen: ssh-keygen -y -P gave '$theirs'" "$KG/err"
! ssh-keygen -y -P 'not it' -f "$KG/id_enc" >/dev/null 2>&1 \
    && ok keygen.enc.wrong_passphrase "keygen: OpenSSH refuses a wrong passphrase" \
    || bad keygen.enc.wrong_passphrase "keygen: OpenSSH decrypted the key with a wrong passphrase"
ours=$(SSH_ASKPASS="$W/askpass-passphrase" SSH_ASKPASS_REQUIRE=force \
    "$BIN" keygen -y -f "$KG/id_enc" </dev/null 2>"$KG/err" | cut -d' ' -f1,2)
[ "$ours" = "$want" ] && ok keygen.enc.derive_pub "keygen -y decrypts with SSH_ASKPASS" \
    || bad keygen.enc.derive_pub "keygen -y, encrypted: '$ours'" "$KG/err"
cat "$KG/id_enc.pub" >>"$H/.ssh/authorized_keys"
SSH_ASKPASS="$W/askpass-passphrase" SSH_ASKPASS_REQUIRE=force \
    p 2201 -i "$KG/id_enc" "$T" true </dev/null >"$KG/out" 2>"$KG/err"
expect_rc keygen.enc.login "keygen: the encrypted key logs in" 0 $? "$KG/err"

# Refusals leave nothing behind.
before=$(sha256sum <"$KG/id_ed25519")
"$BIN" keygen -N '' -q -f "$KG/id_ed25519" >"$KG/out" 2>"$KG/err"
expect_rc keygen.refuse.overwrite "keygen refuses to overwrite a key" 1 $? "$KG/err"
[ "$(sha256sum <"$KG/id_ed25519")" = "$before" ] \
    && ok keygen.refuse.overwrite_unchanged "keygen: the existing key is unchanged" \
    || bad keygen.refuse.overwrite_unchanged "keygen changed an existing key"
"$BIN" keygen -N 'secret words' -q -f "$KG/id_argv" >"$KG/out" 2>"$KG/err"
expect_rc keygen.refuse.argv_passphrase "keygen refuses a passphrase on the command line" 64 $? "$KG/err"
[ ! -e "$KG/id_argv" ] && ok keygen.refuse.argv_nothing_written "keygen: nothing was written for the refused -N" \
    || bad keygen.refuse.argv_nothing_written "keygen wrote a key despite refusing -N"
