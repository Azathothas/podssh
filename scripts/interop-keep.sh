# What a copy keeps besides the bytes (T-146). Sourced by
# scripts/interop-cp.sh while its servers run: 2201 (SFTP) and 2207 (no
# SFTP: by exec). Uses ok, bad, sum and c, and $T, $CW and $RD; runs as
# root, and the far user is podtest.

echo
echo "== cp: what a copy keeps"
KW="$CW/keep"
mkdir -p "$KW"

# stamp FILE: mode 640, the access time 1000000060 and the modification
# time 1000000000 (2001-09-09).
stamp() {
    chmod 640 "$1"
    touch -a -d @1000000060 "$1"
    touch -m -d @1000000000 "$1"
}
want_stamp="640 1000000060 1000000000"

# -p up and down, on each road: stat gives the mode and both times. The
# copy by exec sets them with chmod and touch -t, and reads them with stat.
for srv in sftp:2201 exec:2207; do
    port=${srv#*:}
    head -c 300000 /dev/urandom >"$KW/p$port"
    stamp "$KW/p$port"
    c "$port" -p "$KW/p$port" "$T:cp/p$port" >/dev/null 2>"$CW/err"
    rc=$?
    got=$(stat -c '%a %X %Y' "$RD/p$port")
    [ "$rc" = 0 ] && [ "$got" = "$want_stamp" ] && [ "$(sum "$KW/p$port")" = "$(sum "$RD/p$port")" ] \
        && ok "keep.times.up.${srv%%:*}" "cp -p up on port $port: mode and times $got" \
        || bad "keep.times.up.${srv%%:*}" "cp -p up on port $port: exit $rc, $got" "$CW/err"
    stamp "$RD/p$port"
    c "$port" -p "$T:cp/p$port" "$KW/d$port" >/dev/null 2>"$CW/err"
    rc=$?
    got=$(stat -c '%a %X %Y' "$KW/d$port")
    [ "$rc" = 0 ] && [ "$got" = "$want_stamp" ] && [ "$(sum "$RD/p$port")" = "$(sum "$KW/d$port")" ] \
        && ok "keep.times.down.${srv%%:*}" "cp -p down on port $port: mode and times $got" \
        || bad "keep.times.down.${srv%%:*}" "cp -p down on port $port: exit $rc, $got" "$CW/err"
done
# Without -p, the copy has its own times.
c 2201 "$KW/p2201" "$T:cp/plain" >/dev/null 2>"$CW/err"
rc=$?
got=$(stat -c %Y "$RD/plain")
[ "$rc" = 0 ] && [ "$got" != 1000000000 ] \
    && ok keep.times.without "cp without -p: the copy's own modification time, $got" \
    || bad keep.times.without "cp without -p: exit $rc, $got" "$CW/err"
# -r -p: each directory's time, set after its files.
mkdir -p "$KW/tree/sub"
printf f >"$KW/tree/sub/f"
touch -m -d @1000000002 "$KW/tree/sub"
touch -m -d @1000000003 "$KW/tree"
c 2201 -r -p "$KW/tree" "$T:cp/ktree" >/dev/null 2>"$CW/err"
rc=$?
got="$(stat -c %Y "$RD/ktree/sub") $(stat -c %Y "$RD/ktree")"
[ "$rc" = 0 ] && [ "$got" = "1000000002 1000000003" ] \
    && ok keep.times.dirs "cp -r -p: the times of the directories, $got" \
    || bad keep.times.dirs "cp -r -p: exit $rc, the times of the directories $got" "$CW/err"

# Holes: a sparse file of 100 MiB with 1 MiB of data uses less than 2 MiB
# on the far side, with no flag; with --sparse, here too.
truncate -s 100M "$KW/sparse"
dd if=/dev/urandom of="$KW/sparse" bs=1048576 count=1 seek=50 conv=notrunc 2>/dev/null
c 2201 "$KW/sparse" "$T:cp/sparse" >/dev/null 2>"$CW/err"
rc=$?
used=$(du -k "$RD/sparse" | cut -f1)
[ "$rc" = 0 ] && [ "$used" -lt 2048 ] && [ "$(sum "$KW/sparse")" = "$(sum "$RD/sparse")" ] \
    && ok keep.sparse.up "a sparse file of 100 MiB up: $used KiB on the far side, the digests agree" \
    || bad keep.sparse.up "a sparse file of 100 MiB up: exit $rc, $used KiB" "$CW/err"
c 2201 --sparse "$T:cp/sparse" "$KW/sparse-down" >/dev/null 2>"$CW/err"
rc=$?
used=$(du -k "$KW/sparse-down" | cut -f1)
[ "$rc" = 0 ] && [ "$used" -lt 2048 ] && [ "$(sum "$RD/sparse")" = "$(sum "$KW/sparse-down")" ] \
    && ok keep.sparse.down "cp --sparse down: $used KiB here, the digests agree" \
    || bad keep.sparse.down "cp --sparse down: exit $rc, $used KiB" "$CW/err"

# Two hard-linked names arrive as one inode with two names.
mkdir -p "$KW/hl/d"
head -c 70000 /dev/urandom >"$KW/hl/a"
ln "$KW/hl/a" "$KW/hl/d/b"
c 2201 -r "$KW/hl" "$T:cp/hl" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(stat -c %i "$RD/hl/a")" = "$(stat -c %i "$RD/hl/d/b")" ] && [ "$(stat -c %h "$RD/hl/a")" = 2 ] \
    && [ "$(sum "$KW/hl/a")" = "$(sum "$RD/hl/d/b")" ] \
    && ok keep.hardlink "cp -r: two hard-linked names arrived as one inode" \
    || bad keep.hardlink "cp -r of two hard-linked names: exit $rc" "$CW/err"

# --owner: up, the far user is not root, and the note says so; down, this
# side is root, and the copy is the far file's owner's.
c 2201 --owner "$KW/p2201" "$T:cp/own" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(stat -c %U "$RD/own")" = podtest ] && grep -q "the owner was not kept" "$CW/err" \
    && ok keep.owner.up "cp --owner up as podtest: the owner not kept, and said" \
    || bad keep.owner.up "cp --owner up: exit $rc" "$CW/err"
c 2201 --owner "$T:cp/own" "$KW/own" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(stat -c %U "$KW/own")" = podtest ] \
    && ok keep.owner.down "cp --owner down as root: the copy is podtest's" \
    || bad keep.owner.down "cp --owner down: exit $rc, $(stat -c %U "$KW/own")" "$CW/err"
