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

# -p and -c (T-018): OpenSSH opens the same key with the new passphrase and
# not with the old one, reads the new comment, and sshd still accepts the key.
printf '#!/bin/sh\ncase "$1" in\n  "Enter old passphrase: ") echo "open sesame" ;;\n  *) echo "new words" ;;\nesac\n' \
    >"$W/askpass-change"
chmod 700 "$W/askpass-change"
SSH_ASKPASS="$W/askpass-change" SSH_ASKPASS_REQUIRE=force \
    "$BIN" keygen -p -q -f "$KG/id_enc" </dev/null >"$KG/out" 2>"$KG/err"
expect_rc keygen.change.passphrase "keygen -p: the old passphrase asked, then the new one" 0 $? "$KG/err"
theirs=$(ssh-keygen -y -P 'new words' -f "$KG/id_enc" 2>"$KG/err" | cut -d' ' -f1,2)
[ -n "$theirs" ] && [ "$theirs" = "$want" ] \
    && ok keygen.change.openssh_decrypts "keygen -p: OpenSSH opens the same key with the new passphrase" \
    || bad keygen.change.openssh_decrypts "keygen -p: ssh-keygen -y -P gave '$theirs'" "$KG/err"
! ssh-keygen -y -P 'open sesame' -f "$KG/id_enc" >/dev/null 2>&1 \
    && ok keygen.change.old_refused "keygen -p: the old passphrase no longer opens the key" \
    || bad keygen.change.old_refused "keygen -p: OpenSSH opened the key with the old passphrase"
[ "$(stat -c %a "$KG/id_enc")" = 600 ] && ok keygen.change.mode "keygen -p: the key is still mode 600" \
    || bad keygen.change.mode "keygen -p: mode $(stat -c %a "$KG/id_enc")"
SSH_ASKPASS="$W/askpass-change" SSH_ASKPASS_REQUIRE=force \
    p 2201 -i "$KG/id_enc" "$T" true </dev/null >"$KG/out" 2>"$KG/err"
expect_rc keygen.change.login "keygen -p: sshd accepts the key, opened with the new passphrase" 0 $? "$KG/err"
"$BIN" keygen -c -C kg-renamed -q -f "$KG/id_ed25519" </dev/null >"$KG/out" 2>"$KG/err"
expect_rc keygen.change.comment "keygen -c -C: the comment of a key with no passphrase" 0 $? "$KG/err"
theirs=$(ssh-keygen -y -f "$KG/id_ed25519" 2>"$KG/err")
[ "${theirs##* }" = kg-renamed ] && [ "$(cut -d' ' -f3 "$KG/id_ed25519.pub")" = kg-renamed ] \
    && ok keygen.change.openssh_comment "keygen -c: OpenSSH reads the new comment, and the .pub has it" \
    || bad keygen.change.openssh_comment "keygen -c: ssh-keygen -y gave '$theirs'" "$KG/id_ed25519.pub"

# Keys of PEM and of PKCS#8 that OpenSSH encrypted (T-287): podssh asks for
# the passphrase and logs in with each, and -p writes the same key in the
# format of OpenSSH.
printf '#!/bin/sh\ncase "$1" in\n  "Enter new passphrase"*|"Enter same passphrase"*) echo "" ;;\n  *) echo "pem words" ;;\nesac\n' \
    >"$W/askpass-pem"
chmod 700 "$W/askpass-pem"
# ssh-keygen reads the name of -m in any case.
for l in pem pkcs8; do
    f="$KG/id_$l"
    ssh-keygen -q -t ecdsa -m "$l" -N 'pem words' -C "kg-$l" -f "$f"
    want=$(cut -d' ' -f1,2 "$f.pub")
    cat "$f.pub" >>"$H/.ssh/authorized_keys"
    SSH_ASKPASS="$W/askpass-pem" SSH_ASKPASS_REQUIRE=force \
        p 2201 -i "$f" "$T" true </dev/null >"$KG/out" 2>"$KG/err"
    expect_rc "keygen.formats.login_${l}" "an ecdsa key of $l that OpenSSH encrypted logs in, its passphrase asked" \
        0 $? "$KG/err"
    SSH_ASKPASS="$W/askpass-pem" SSH_ASKPASS_REQUIRE=force \
        "$BIN" keygen -p -q -f "$f" </dev/null >"$KG/out" 2>"$KG/err"
    expect_rc "keygen.formats.convert_${l}" "keygen -p opens an encrypted key of $l" 0 $? "$KG/err"
    theirs=$(ssh-keygen -y -P '' -f "$f" 2>"$KG/err" | cut -d' ' -f1,2)
    [ "$(head -1 "$f")" = "-----BEGIN OPENSSH PRIVATE KEY-----" ] && [ -n "$theirs" ] && [ "$theirs" = "$want" ] \
        && ok "keygen.formats.same_key_${l}" "keygen -p of $l: OpenSSH reads the same key, in its own format" \
        || bad "keygen.formats.same_key_${l}" "keygen -p of $l: ssh-keygen -y gave '$theirs'" "$KG/err"
done

# known_hosts (T-019): keygen -F prints what ssh-keygen -F prints; OpenSSH
# finds each host that keygen -H hashed, and keygen each that ssh-keygen -H
# hashed; keygen -R leaves the file that ssh-keygen -R leaves.
KH="$KG/known_hosts"
k1=$(cut -d' ' -f1,2 "$KG/id_ed25519.pub")
k2=$(cut -d' ' -f1,2 "$KG/id_ecdsa.pub")
printf '# hosts\none.example %s\ntwo.example,192.0.2.2 %s a comment\n[three.example]:2222 %s\n*.wild.example %s\n@revoked one.example %s\n' \
    "$k1" "$k2" "$k1" "$k2" "$k2" >"$KH.plain"
ours=$(for h in one.example 192.0.2.2 '[three.example]:2222' x.wild.example missing.example; do
    "$BIN" keygen -F "$h" -f "$KH.plain"; echo "exit $?"; done 2>&1)
theirs=$(for h in one.example 192.0.2.2 '[three.example]:2222' x.wild.example missing.example; do
    ssh-keygen -F "$h" -f "$KH.plain"; echo "exit $?"; done 2>&1)
[ "$ours" = "$theirs" ] && ok keygen.known_hosts.find_output "keygen -F prints the lines and the codes of ssh-keygen -F" \
    || bad keygen.known_hosts.find_output "keygen -F: '$ours'; ssh-keygen -F: '$theirs'"
cp "$KH.plain" "$KH"
"$BIN" keygen -H -f "$KH" >"$KG/out" 2>"$KG/err"
expect_rc keygen.known_hosts.hash "keygen -H hashes the file" 0 $? "$KG/err"
found=0
for h in one.example two.example 192.0.2.2 '[three.example]:2222'; do
    ssh-keygen -F "$h" -f "$KH" >/dev/null 2>&1 && found=$((found + 1))
done
[ "$found" = 4 ] && ! grep -q 'two\.example' "$KH" \
    && ok keygen.known_hosts.openssh_finds_hashed "ssh-keygen -F finds each host that keygen -H hashed" \
    || bad keygen.known_hosts.openssh_finds_hashed "ssh-keygen -F found $found of 4 hosts that keygen -H hashed" "$KH"
cp "$KH.plain" "$KH.theirs"
ssh-keygen -H -f "$KH.theirs" >/dev/null 2>&1
found=0
for h in one.example two.example 192.0.2.2 '[three.example]:2222'; do
    "$BIN" keygen -F "$h" -f "$KH.theirs" >/dev/null 2>&1 && found=$((found + 1))
done
[ "$found" = 4 ] && ok keygen.known_hosts.finds_openssh_hashed "keygen -F finds each host that ssh-keygen -H hashed" \
    || bad keygen.known_hosts.finds_openssh_hashed "keygen -F found $found of 4 hosts that ssh-keygen -H hashed" "$KH.theirs"
cp "$KH.plain" "$KH.ours"
cp "$KH.plain" "$KH.openssh"
"$BIN" keygen -R two.example -f "$KH.ours" >"$KG/out" 2>"$KG/err"
expect_rc keygen.known_hosts.remove "keygen -R removes a host" 0 $? "$KG/err"
ssh-keygen -R two.example -f "$KH.openssh" >/dev/null 2>&1
cmp -s "$KH.ours" "$KH.openssh" && cmp -s "$KH.ours.old" "$KH.plain" \
    && ok keygen.known_hosts.removed_as_openssh "keygen -R leaves the file that ssh-keygen -R leaves, and FILE.old" \
    || bad keygen.known_hosts.removed_as_openssh "keygen -R left another file than ssh-keygen -R" "$KH.ours"

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
