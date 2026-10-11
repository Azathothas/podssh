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

# SSH signatures (T-020): OpenSSH's ssh-keygen -Y verify accepts each
# signature of keygen -Y sign, keygen -Y verify each of OpenSSH's, and both
# refuse changed data and another namespace.
printf 'signed data\n' >"$KG/data"
printf 'changed data\n' >"$KG/changed"
for t in ed25519 ecdsa rsa; do
    key="$KG/id_$t"
    printf 'signer@example.com %s\n' "$(cut -d' ' -f1,2 "$key.pub")" >"$KG/allowed_$t"
    rm -f "$KG/data.sig"
    "$BIN" keygen -q -Y sign -f "$key" -n git "$KG/data" >"$KG/out" 2>"$KG/err"
    expect_rc "keygen.sign.make.${t}" "keygen -Y sign with an $t key" 0 $? "$KG/err"
    mv "$KG/data.sig" "$KG/ours_$t.sig"
    ssh-keygen -q -Y sign -f "$key" -n git "$KG/data" >/dev/null 2>&1
    mv "$KG/data.sig" "$KG/theirs_$t.sig"
    ssh-keygen -Y verify -f "$KG/allowed_$t" -I signer@example.com -n git -s "$KG/ours_$t.sig" \
        <"$KG/data" >"$KG/out" 2>&1
    expect_rc "keygen.sign.openssh_verifies.${t}" "ssh-keygen -Y verify accepts the $t signature of keygen -Y sign" \
        0 $? "$KG/out"
    "$BIN" keygen -Y verify -f "$KG/allowed_$t" -I signer@example.com -n git -s "$KG/theirs_$t.sig" \
        <"$KG/data" >"$KG/out" 2>&1
    expect_rc "keygen.sign.verifies_openssh.${t}" "keygen -Y verify accepts the $t signature of ssh-keygen -Y sign" \
        0 $? "$KG/out"
    refused=0
    ssh-keygen -Y verify -f "$KG/allowed_$t" -I signer@example.com -n git -s "$KG/ours_$t.sig" \
        <"$KG/changed" >/dev/null 2>&1 || refused=$((refused + 1))
    ssh-keygen -Y verify -f "$KG/allowed_$t" -I signer@example.com -n file -s "$KG/ours_$t.sig" \
        <"$KG/data" >/dev/null 2>&1 || refused=$((refused + 1))
    "$BIN" keygen -Y verify -f "$KG/allowed_$t" -I signer@example.com -n git -s "$KG/theirs_$t.sig" \
        <"$KG/changed" >/dev/null 2>&1 || refused=$((refused + 1))
    "$BIN" keygen -Y verify -f "$KG/allowed_$t" -I signer@example.com -n file -s "$KG/theirs_$t.sig" \
        <"$KG/data" >/dev/null 2>&1 || refused=$((refused + 1))
    [ "$refused" = 4 ] \
        && ok "keygen.sign.both_refuse.${t}" "each tool refuses changed data and another namespace, $t" \
        || bad "keygen.sign.both_refuse.${t}" "$refused of 4 refusals of changed data or another namespace, $t"
done

# Certificates (T-021): ssh-keygen -L reads each certificate of keygen -s;
# an sshd that trusts the CAs of keygen (TrustedUserCAKeys, and no
# authorized_keys) lets OpenSSH's ssh in with a user certificate of each, and
# refuses one that has expired or names another principal.
"$BIN" keygen -q -t ed25519 -N '' -C interop-user-ca -f "$KG/user_ca" >/dev/null 2>&1
"$BIN" keygen -q -t rsa -N '' -C interop-user-ca-rsa -f "$KG/user_ca_rsa" >/dev/null 2>&1
cat "$KG/user_ca.pub" "$KG/user_ca_rsa.pub" >"$KG/trusted_cas"
sshd_conf 2212 "KbdInteractiveAuthentication no" "TrustedUserCAKeys $KG/trusted_cas" "AuthorizedKeysFile none"
/usr/sbin/sshd -f "$W/sshd-2212.conf" -E "$W/sshd-2212.log" || cat "$W/sshd-2212.log"
tries=0
while ! python3 -c 'import socket; socket.create_connection(("127.0.0.1", 2212), 1).close()' 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -ge 50 ] && break
    sleep 0.1
done
cert_login() { # KEY: OpenSSH's ssh with KEY, and KEY-cert.pub beside it
    ssh -F /dev/null -p 2212 -i "$1" -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$T" true </dev/null >"$KG/out" 2>&1
}
for ca in user_ca user_ca_rsa; do
    key="$KG/certkey_$ca"
    "$BIN" keygen -q -t ed25519 -N '' -f "$key" >/dev/null 2>&1
    "$BIN" keygen -q -s "$KG/$ca" -I "interop-$ca" -n podtest -V -5m:+1h "$key.pub" >"$KG/out" 2>"$KG/err"
    expect_rc "keygen.cert.make.${ca}" "keygen -s with the CA $ca" 0 $? "$KG/err"
    ssh-keygen -L -f "$key-cert.pub" >"$KG/out" 2>&1 && grep -q "Key ID: \"interop-$ca\"" "$KG/out" \
        && grep -q '^ *podtest$' "$KG/out" \
        && ok "keygen.cert.openssh_reads.${ca}" "ssh-keygen -L reads the certificate of keygen -s ($ca)" \
        || bad "keygen.cert.openssh_reads.${ca}" "ssh-keygen -L did not read the certificate ($ca)" "$KG/out"
    cert_login "$key"
    expect_rc "keygen.cert.login.${ca}" "sshd lets OpenSSH's ssh in with a user certificate of keygen -s ($ca)" \
        0 $? "$KG/out"
done
key="$KG/certkey_user_ca"
# Each refusal counts only once its certificate is made: with none, the login
# fails for want of one.
"$BIN" keygen -q -s "$KG/user_ca" -I expired -n podtest -V -2h:-1h "$key.pub" >"$KG/out" 2>&1 && made=yes || made=no
cert_login "$key" && expired=took || expired=refused
[ "$made" = yes ] && [ "$expired" = refused ] \
    && ok keygen.cert.expired_refused "sshd refuses a certificate of keygen -s that has expired" \
    || bad keygen.cert.expired_refused "made: $made; sshd's answer: $expired" "$KG/out"
"$BIN" keygen -q -s "$KG/user_ca" -I other -n someone-else -V -5m:+1h "$key.pub" >"$KG/out" 2>&1 && made=yes || made=no
cert_login "$key" && other=took || other=refused
[ "$made" = yes ] && [ "$other" = refused ] \
    && ok keygen.cert.principal_refused "sshd refuses a certificate of keygen -s for another principal" \
    || bad keygen.cert.principal_refused "made: $made; sshd's answer: $other" "$KG/out"
"$BIN" keygen -q -t ed25519 -N '' -f "$KG/hostkey_cert" >/dev/null 2>&1
"$BIN" keygen -q -s "$KG/user_ca" -I host-cert -h -n 127.0.0.1 "$KG/hostkey_cert.pub" >/dev/null 2>&1
ssh-keygen -L -f "$KG/hostkey_cert-cert.pub" 2>&1 | grep -q 'host certificate' \
    && ok keygen.cert.host_openssh_reads "ssh-keygen -L reads a host certificate of keygen -s -h" \
    || bad keygen.cert.host_openssh_reads "ssh-keygen -L did not read the host certificate" "$KG/hostkey_cert-cert.pub"
kill "$(cat "$W/sshd-2212.pid")" 2>/dev/null

# Formats of other systems (T-022): OpenSSH's ssh-keygen -i reads what
# keygen -e writes, and keygen -i what ssh-keygen -e writes (PKCS8 for ECDSA
# and RSA, RFC 4716 for Ed25519); keygen -y reads the key that ssh-keygen
# -m PEM wrote; OpenSSH reads each key that keygen -m writes.
for t in ecdsa rsa; do
    key="$KG/id_$t"
    want=$(cut -d' ' -f1,2 "$key.pub")
    "$BIN" keygen -e -m PKCS8 -f "$key.pub" >"$KG/ours.pkcs8" 2>"$KG/err"
    theirs=$(ssh-keygen -i -m PKCS8 -f "$KG/ours.pkcs8" 2>"$KG/err" | cut -d' ' -f1,2)
    [ -n "$theirs" ] && [ "$theirs" = "$want" ] \
        && ok "keygen.convert.openssh_imports.${t}" "ssh-keygen -i -m PKCS8 reads keygen -e -m PKCS8 ($t)" \
        || bad "keygen.convert.openssh_imports.${t}" "ssh-keygen -i -m PKCS8 gave '$theirs' ($t)" "$KG/err"
    ssh-keygen -e -m PKCS8 -f "$key.pub" >"$KG/theirs.pkcs8" 2>/dev/null
    ours=$("$BIN" keygen -i -m PKCS8 -f "$KG/theirs.pkcs8" 2>"$KG/err" | cut -d' ' -f1,2)
    [ -n "$ours" ] && [ "$ours" = "$want" ] \
        && ok "keygen.convert.imports_openssh.${t}" "keygen -i -m PKCS8 reads ssh-keygen -e -m PKCS8 ($t)" \
        || bad "keygen.convert.imports_openssh.${t}" "keygen -i -m PKCS8 gave '$ours' ($t)" "$KG/err"
    ssh-keygen -q -t "$t" -m PEM -N '' -f "$KG/pem_$t"
    ours=$("$BIN" keygen -y -f "$KG/pem_$t" 2>"$KG/err" | cut -d' ' -f1,2)
    theirs=$(ssh-keygen -y -f "$KG/pem_$t" 2>/dev/null | cut -d' ' -f1,2)
    [ -n "$ours" ] && [ "$ours" = "$theirs" ] \
        && ok "keygen.convert.y_of_pem.${t}" "keygen -y prints the key of a PEM key of ssh-keygen -m PEM ($t)" \
        || bad "keygen.convert.y_of_pem.${t}" "keygen -y gave '$ours' ($t)" "$KG/err"
done
key="$KG/id_ed25519"
want=$(cut -d' ' -f1,2 "$key.pub")
"$BIN" keygen -e -f "$key.pub" >"$KG/ours.rfc" 2>"$KG/err"
theirs=$(ssh-keygen -i -f "$KG/ours.rfc" 2>/dev/null | cut -d' ' -f1,2)
ssh-keygen -e -f "$key.pub" >"$KG/theirs.rfc" 2>/dev/null
ours=$("$BIN" keygen -i -f "$KG/theirs.rfc" 2>>"$KG/err" | cut -d' ' -f1,2)
[ -n "$ours" ] && [ "$ours" = "$want" ] && [ "$theirs" = "$want" ] \
    && ok keygen.convert.rfc4716_both "each tool reads the other's RFC 4716 export of an Ed25519 key" \
    || bad keygen.convert.rfc4716_both "RFC 4716: ssh-keygen -i gave '$theirs', keygen -i '$ours'" "$KG/err"
for f in pem pkcs8; do
    SSH_ASKPASS="$W/askpass-passphrase" SSH_ASKPASS_REQUIRE=force \
        "$BIN" keygen -q -t rsa -m "$f" -f "$KG/m_$f" </dev/null >"$KG/out" 2>"$KG/err"
    expect_rc "keygen.convert.m_make.${f}" "keygen -m $f makes an RSA key with a passphrase" 0 $? "$KG/err"
    want=$(cut -d' ' -f1,2 "$KG/m_$f.pub")
    theirs=$(ssh-keygen -y -P 'open sesame' -f "$KG/m_$f" 2>"$KG/err" | cut -d' ' -f1,2)
    [ -n "$theirs" ] && [ "$theirs" = "$want" ] \
        && ok "keygen.convert.openssh_reads_m.${f}" "ssh-keygen -y reads the key of keygen -m $f, with its passphrase" \
        || bad "keygen.convert.openssh_reads_m.${f}" "ssh-keygen -y gave '$theirs' for keygen -m $f" "$KG/err"
done

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
