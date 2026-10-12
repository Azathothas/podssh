# podssh cp --inplace (T-147). Sourced by scripts/interop-cp.sh while its
# servers run: 2201 (SFTP), 2205 (its sftp subsystem flips one data byte each
# way) and 2207 (no SFTP: by exec). Uses ok, bad, sum and c, and $T, $CW and
# $RD; runs as root, and the far user is podtest.

echo
echo "== cp --inplace"
IW="$CW/inplace"
mkdir -p "$IW"

# Up and down on each road, over a longer old file: the destination keeps
# its inode, the digests agree, and the notice comes first.
for srv in sftp:2201 exec:2207; do
    port=${srv#*:}
    head -c 300000 /dev/urandom >"$IW/new$port"
    head -c 500000 /dev/urandom >"$RD/in$port"
    chown podtest:podtest "$RD/in$port"
    ino=$(stat -c %i "$RD/in$port")
    c "$port" --inplace "$IW/new$port" "$T:cp/in$port" >/dev/null 2>"$CW/err"
    rc=$?
    [ "$rc" = 0 ] && [ "$(stat -c %i "$RD/in$port")" = "$ino" ] && [ "$(sum "$IW/new$port")" = "$(sum "$RD/in$port")" ] \
        && head -n 1 "$CW/err" | grep -q "inplace writes into each destination itself" \
        && ok "inplace.up.${srv%%:*}" "cp --inplace up on port $port: the same inode, the digests agree" \
        || bad "inplace.up.${srv%%:*}" "cp --inplace up on port $port: exit $rc" "$CW/err"
    head -c 400000 /dev/urandom >"$IW/old$port"
    ino=$(stat -c %i "$IW/old$port")
    c "$port" --inplace "$T:cp/in$port" "$IW/old$port" >/dev/null 2>"$CW/err"
    rc=$?
    [ "$rc" = 0 ] && [ "$(stat -c %i "$IW/old$port")" = "$ino" ] && [ "$(sum "$RD/in$port")" = "$(sum "$IW/old$port")" ] \
        && ok "inplace.down.${srv%%:*}" "cp --inplace down on port $port: the same inode, the digests agree" \
        || bad "inplace.down.${srv%%:*}" "cp --inplace down on port $port: exit $rc" "$CW/err"
done
# A flipped byte: exit 70, and the destination is said to be damaged, never
# to be as it was.
printf 'the old content\n' >"$RD/damaged"
chown podtest:podtest "$RD/damaged"
c 2205 --inplace "$CW/up/f262145" "$T:cp/damaged" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 70 ] && grep -q "is damaged: --inplace wrote into it" "$CW/err" && ! grep -q "was not changed" "$CW/err" \
    && ok inplace.damaged "a flipped byte with --inplace: exit 70, and the destination said to be damaged" \
    || bad inplace.damaged "a flipped byte with --inplace: exit $rc" "$CW/err"
# A destination that is a link: 64, and nothing goes through it.
printf real >"$RD/real"
ln -sf real "$RD/link"
chown -h podtest:podtest "$RD/real" "$RD/link"
c 2201 --inplace "$CW/up/f1" "$T:cp/link" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 64 ] && [ "$(cat "$RD/real")" = real ] && grep -q "a symbolic link" "$CW/err" \
    && ok inplace.link "cp --inplace onto a link: exit 64, and the file it names as it was" \
    || bad inplace.link "cp --inplace onto a link: exit $rc" "$CW/err"
