# podssh scp and podssh sftp with OpenSSH's command lines (T-139). Sourced by
# scripts/interop-cp.sh while its servers run (2201: OpenSSH with its
# sftp-server). Uses ok, bad, sum, $W, $T, $K, $KH, $BIN, $CW and $RD.

echo
echo "== scp and sftp"
SW="$CW/sftp"
mkdir -p "$SW"
# o PROGRAM [arguments...]: podssh scp or sftp to 2201 as OpenSSH's are run,
# with no --timeout.
o() {
    _verb=$1
    shift
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK HOME="$W" "$BIN" "$_verb" --direct -P 2201 -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K "$@"
}

# scp: -B is BatchMode, and a URI names its own port.
head -c 262145 /dev/urandom >"$SW/s1"
o scp -B "$SW/s1" "$T:cp/scp1" </dev/null >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$SW/s1")" = "$(sum "$RD/scp1")" ] \
    && ok "scp -B copies up with equal digests" || bad "scp up: exit $rc" "$CW/err"
o scp "scp://${T}:2201/cp/scp1" "$SW/s2" </dev/null >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$SW/s1")" = "$(sum "$SW/s2")" ] \
    && ok "scp from a scp:// URI copies down with equal digests" || bad "scp down from a URI: exit $rc" "$CW/err"

# sftp -b: each kind of command, and what it leaves on both sides.
cat >"$SW/batch" <<EOF
mkdir -p sftpdir/inner
cd sftpdir
put $SW/s1 a
rename a b
chmod 600 b
ls -l
get b $SW/back
-rm nothing-here
@rm b
cd ..
rmdir sftpdir/inner
rmdir sftpdir
pwd
bye
EOF
o sftp -b "$SW/batch" "$T" </dev/null >"$SW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$SW/s1")" = "$(sum "$SW/back")" ] && [ ! -e /home/podtest/sftpdir ] \
    && grep -q "^sftp> put" "$SW/out" && ! grep -q "^sftp> rm b" "$SW/out" && grep -q "^-rw------- " "$SW/out" \
    && ok "sftp -b runs each command, echoes each line but @, and goes on past -rm" \
    || bad "sftp -b: exit $rc" "$SW/out"
# A command that fails ends the batch, with no later command run.
printf 'rm nothing-here\nmkdir never\n' | o sftp -b - "$T" >"$SW/out" 2>"$CW/err"
rc=$?
[ "$rc" != 0 ] && [ ! -e /home/podtest/never ] \
    && ok "sftp -b - ends the batch at a failed command (exit $rc)" || bad "sftp -b -: exit $rc" "$CW/err"
# A destination that names a file is fetched at once.
(cd "$SW" && o sftp "$T:cp/scp1" </dev/null >/dev/null 2>"$CW/err")
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$SW/s1")" = "$(sum "$SW/scp1")" ] \
    && ok "sftp host:file fetches the file" || bad "sftp host:file: exit $rc" "$CW/err"
