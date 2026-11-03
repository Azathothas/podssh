# The keywords of a restriction (T-505): podssh's lists against an OpenSSH
# sshd limited to one cipher, at LogLevel DEBUG2, so that its log names what
# each connection negotiated. Sourced by scripts/interop.sh once its
# servers run; uses ok, bad, sshd_conf, wait_port, expect_rc, $W, $BIN, $KH,
# $K and $T. Its sshd is on port 2214, and it stops after the block.

echo
echo "== the keywords of a restriction, against an sshd of one cipher (T-505)"
sshd_conf 2214 "KbdInteractiveAuthentication no" "Ciphers aes128-ctr" "LogLevel DEBUG2"
/usr/sbin/sshd -f "$W/sshd-2214.conf" -E "$W/sshd-2214.log" || cat "$W/sshd-2214.log"
wait_port 2214
# alg KNOWN_HOSTS WORDS...: podssh to port 2214, `exit 7`; the lines that
# sshd logged for it go to $W/alg.log.
alg() {
    _kh=$1
    shift
    _before=$(wc -l <"$W/sshd-2214.log")
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2214 -o UserKnownHostsFile="$_kh" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes \
        "$@" "$T" 'exit 7' </dev/null >"$W/out" 2>"$W/err"
    _rc=$?
    sleep 0.5
    tail -n +"$((_before + 1))" "$W/sshd-2214.log" >"$W/alg.log"
    return $_rc
}

alg "$KH"
expect_rc algorithms.own_list "podssh's own ciphers meet the one of sshd" 7 $? "$W/err"
alg "$KH" -o Ciphers=aes128-ctr
rc=$?
[ "$rc" = 7 ] && grep -q 'cipher: aes128-ctr' "$W/alg.log" \
    && ok algorithms.cipher_one "-o Ciphers=aes128-ctr: sshd's log names that cipher" \
    || bad algorithms.cipher_one "-o Ciphers=aes128-ctr: exit $rc" "$W/err"
alg "$KH" -o Ciphers=aes256-ctr
rc=$?
[ "$rc" = 255 ] && grep -q 'in common' "$W/err" \
    && ok algorithms.cipher_none_in_common "-o Ciphers=aes256-ctr against an sshd of aes128-ctr: 255, no cipher in common" \
    || bad algorithms.cipher_none_in_common "-o Ciphers=aes256-ctr: exit $rc" "$W/err"
alg "$KH" -o KexAlgorithms=curve25519-sha256
rc=$?
[ "$rc" = 7 ] && grep -q 'kex: algorithm: curve25519-sha256' "$W/alg.log" \
    && ok algorithms.kex_one "-o KexAlgorithms=curve25519-sha256: sshd's log names that exchange" \
    || bad algorithms.kex_one "-o KexAlgorithms=curve25519-sha256: exit $rc" "$W/alg.log"
: >"$W/kh_alg_rsa"
alg "$W/kh_alg_rsa" -o HostKeyAlgorithms=rsa-sha2-512
rc=$?
[ "$rc" = 7 ] && grep -q 'host key algorithm: rsa-sha2-512' "$W/alg.log" && grep -q 'ssh-rsa' "$W/kh_alg_rsa" \
    && ok algorithms.hostkey_rsa "-o HostKeyAlgorithms=rsa-sha2-512: sshd signs with its RSA key, which is recorded" \
    || bad algorithms.hostkey_rsa "-o HostKeyAlgorithms=rsa-sha2-512: exit $rc" "$W/alg.log"
alg "$W/kh_alg_rsa" -o HostKeyAlgorithms=rsa-sha2-512 -o RequiredRSASize=4096
rc=$?
[ "$rc" = 255 ] && grep -q 'RSA key of 3072 bits, under RequiredRSASize 4096' "$W/err" \
    && ok algorithms.rsa_size "RequiredRSASize=4096 against sshd's RSA host key of 3072 bits: 255, named" \
    || bad algorithms.rsa_size "RequiredRSASize=4096: exit $rc" "$W/err"
alg "$KH" -v -o PubkeyAcceptedAlgorithms=rsa-sha2-512
rc=$?
[ "$rc" = 255 ] && grep -q 'ssh-ed25519 is not in PubkeyAcceptedAlgorithms' "$W/err" \
    && ok algorithms.pubkey_left_out "PubkeyAcceptedAlgorithms=rsa-sha2-512: the Ed25519 key is not offered, and -v says why" \
    || bad algorithms.pubkey_left_out "PubkeyAcceptedAlgorithms=rsa-sha2-512: exit $rc" "$W/err"
alg "$KH" -i "$W/id_rsa" -o PubkeyAcceptedAlgorithms=rsa-sha2-256
rc=$?
# sshd's userauth_pubkey names the signature's algorithm at DEBUG2.
[ "$rc" = 7 ] && grep -Eq 'public key rsa-sha2-256|pkalg rsa-sha2-256' "$W/alg.log" \
    && ok algorithms.pubkey_rsa_256 "PubkeyAcceptedAlgorithms=rsa-sha2-256: the RSA key signs with SHA-256" \
    || bad algorithms.pubkey_rsa_256 "PubkeyAcceptedAlgorithms=rsa-sha2-256: exit $rc" "$W/alg.log"
alg "$KH" -o Ciphers=3des-cbc
rc=$?
[ "$rc" = 64 ] && [ ! -s "$W/alg.log" ] && grep -q 'leaves no cipher that podssh speaks' "$W/err" \
    && ok algorithms.empty_list "-o Ciphers=3des-cbc: refused with 64 before anything connects" \
    || bad algorithms.empty_list "-o Ciphers=3des-cbc: exit $rc" "$W/err"
ssh -F /dev/null -G -o RequiredRSASize=2048 example.org </dev/null >"$W/ssh-G" 2>/dev/null
env HOME="$W" PODSSH_OFFLINE=1 "$BIN" ssh -F none -G -o RequiredRSASize=2048 -o Ciphers=+aes128-cbc example.org \
    </dev/null >"$W/podssh-G" 2>"$W/err"
rc=$?
[ "$rc" = 0 ] && grep -qx 'requiredrsasize 2048' "$W/ssh-G" && grep -qx 'requiredrsasize 2048' "$W/podssh-G" \
    && grep -Eq '^ciphers .*,aes128-cbc$' "$W/podssh-G" \
    && ok algorithms.g_lines "-G: requiredrsasize as OpenSSH prints it, and the list with + as podssh offers it" \
    || bad algorithms.g_lines "-G: exit $rc" "$W/podssh-G"
kill "$(cat "$W/sshd-2214.pid")" 2>/dev/null
