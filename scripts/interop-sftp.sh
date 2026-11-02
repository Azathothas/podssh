# podssh scp and podssh sftp with OpenSSH's command lines (T-139), and sftp's
# ls beside OpenSSH's own sftp (T-471). Sourced by scripts/interop-cp.sh
# while its servers run (2201: OpenSSH with its sftp-server). Uses ok, bad,
# sum, $W, $T, $K, $KH, $BIN, $CW and $RD.

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
    && ok sftp.scp.up "scp -B copies up with equal digests" || bad sftp.scp.up "scp up: exit $rc" "$CW/err"
o scp "scp://${T}:2201/cp/scp1" "$SW/s2" </dev/null >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$SW/s1")" = "$(sum "$SW/s2")" ] \
    && ok sftp.scp.down_uri "scp from a scp:// URI copies down with equal digests" \
    || bad sftp.scp.down_uri "scp down from a URI: exit $rc" "$CW/err"

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
    && ok sftp.batch.each_command "sftp -b runs each command, echoes each line but @, and goes on past -rm" \
    || bad sftp.batch.each_command "sftp -b: exit $rc" "$SW/out"
# A command that fails ends the batch, with no later command run.
printf 'rm nothing-here\nmkdir never\n' | o sftp -b - "$T" >"$SW/out" 2>"$CW/err"
rc=$?
[ "$rc" != 0 ] && [ ! -e /home/podtest/never ] \
    && ok sftp.batch.ends_at_failure "sftp -b - ends the batch at a failed command (exit $rc)" \
    || bad sftp.batch.ends_at_failure "sftp -b -: exit $rc" "$CW/err"
# A destination that names a file is fetched at once.
(cd "$SW" && o sftp "$T:cp/scp1" </dev/null >/dev/null 2>"$CW/err")
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$SW/s1")" = "$(sum "$SW/scp1")" ] \
    && ok sftp.fetch_file "sftp host:file fetches the file" || bad sftp.fetch_file "sftp host:file: exit $rc" "$CW/err"

# ls (T-471): one batch through OpenSSH's sftp and through podssh sftp, in
# UTC, against one server: each line of stdout must be equal. A tree of each
# kind: files of their own sizes and times (an hour, a month and more than
# half a year old), a set-id file, a sticky directory, a link and a FIFO.
# The orders by time and by size run in ord/, whose files differ in both:
# OpenSSH sorts with qsort, which musl's libc does not keep stable, so two
# entries of one time or one size could come in either order.
LR=/home/podtest/lsref
rm -rf "$LR"
mkdir -p "$LR/sub" "$LR/tmp" "$LR/ord"
now=$(date +%s)
head -c 10 /dev/urandom >"$LR/a.txt"
head -c 3000 /dev/urandom >"$LR/b.txt"
head -c 1600000 /dev/urandom >"$LR/big"
printf 'x' >"$LR/sub/inner"
printf 's' >"$LR/setuid"
printf '.' >"$LR/.hidden"
touch -m -d "@$((now - 3600))" "$LR/a.txt"
touch -m -d "@$((now - 30 * 86400))" "$LR/b.txt"
touch -m -d "@$((now - 400 * 86400))" "$LR/big"
for f in o1:100:7200 o2:50:432000 o3:7000:5184000 o4:9:25920000; do
    name=${f%%:*}
    rest=${f#*:}
    head -c "${rest%%:*}" /dev/urandom >"$LR/ord/$name"
    touch -m -d "@$((now - ${rest#*:}))" "$LR/ord/$name"
done
ln -s a.txt "$LR/link"
mkfifo "$LR/fifo"
chown -hR podtest:podtest "$LR"
chmod 4755 "$LR/setuid"
chmod 1777 "$LR/tmp"
printf '%s\n' 'cd lsref' ls 'ls -1' 'ls -l' 'ls -la' 'ls -lr' 'ls -lh' 'ls -l a.txt' 'ls -l *.txt' 'ls -l sub' \
    'ls -1f' 'ls -1 -a sub' 'ls -lt ord' 'ls -lS ord' 'ls -ltr ord' 'ls -lSr ord' 'ls -1 .*' >"$SW/ls.batch"
# Both read the times in UTC: the zone of the lines is the client's.
if command -v sftp >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    timeout 60 env -u SSH_AUTH_SOCK HOME="$W" TZ=UTC sftp -F /dev/null -P 2201 -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes $K \
        -b "$SW/ls.batch" "$T" </dev/null >"$SW/ls.openssh" 2>"$CW/err.openssh"
    rc_o=$?
else
    rc_o=none
fi
(TZ=UTC; export TZ; o sftp -b "$SW/ls.batch" "$T" </dev/null >"$SW/ls.podssh" 2>"$CW/err")
rc=$?
[ "$rc_o" = 0 ] && [ "$rc" = 0 ] && cmp -s "$SW/ls.openssh" "$SW/ls.podssh" \
    && ok sftp.ls.same_as_openssh "sftp's ls, -l, -a, -t, -S, -r, -h, -1, -f and patterns: each line as OpenSSH's sftp's" \
    || { diff "$SW/ls.openssh" "$SW/ls.podssh" >"$SW/ls.diff" 2>&1
         bad sftp.ls.same_as_openssh "sftp's ls beside OpenSSH's: exit $rc_o and $rc" "$SW/ls.diff"; }
# -n gives the numbers, as OpenSSH 10.4p1 and later do; 10.2p1 and 10.3p1
# still named them where the server could (users-groups-by-id), so this
# line is not compared with the image's OpenSSH, whichever it is.
printf 'ls -ln lsref\n' >"$SW/ls.n.batch"
o sftp -b "$SW/ls.n.batch" "$T" </dev/null >"$SW/ls.n" 2>"$CW/err"
rc=$?
uid=$(id -u podtest)
[ "$rc" = 0 ] && grep -q ' lsref/a\.txt$' "$SW/ls.n" \
    && [ -z "$(grep -v '^sftp> ' "$SW/ls.n" | awk -v u="$uid" '$3 != u')" ] \
    && ok sftp.ls.numeric "sftp's ls -ln: the owner by number on each line" \
    || bad sftp.ls.numeric "sftp's ls -ln: exit $rc" "$SW/ls.n"
