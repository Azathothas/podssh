# podssh mv (T-138). Sourced by scripts/interop-cp.sh while its servers run:
# 2201 (SFTP), 2205 (its sftp subsystem flips one data byte each way) and
# 2207 (no SFTP: by exec). Uses ok, bad, expect_rc, sum and no_part, and
# $W, $T, $K, $KH, $BIN, $CW and $RD.

echo
echo "== mv"
MW="$CW/mv"
mkdir -p "$MW"

# m PORT [mv arguments...]: podssh mv as c() runs cp.
m() {
    _port=$1
    shift
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK HOME="$W" "$BIN" mv --direct -P "$_port" \
        -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes $K --timeout 120s "$@"
}
# far NAME: a far file of podtest's, of 70000 random bytes.
far() {
    head -c 70000 /dev/urandom >"$RD/$1"
    chown podtest:podtest "$RD/$1"
}

# Up and down on each road: the source goes only after equal digests, and
# the notice is the first line on stderr, before the first of -v.
for port in 2201 2207; do
    head -c 300000 /dev/urandom >"$MW/u$port"
    want=$(sum "$MW/u$port")
    m "$port" -v "$MW/u$port" "$T:cp/mv$port" >/dev/null 2>"$CW/err"
    rc=$?
    [ "$rc" = 0 ] && [ ! -e "$MW/u$port" ] && [ "$(sum "$RD/mv$port")" = "$want" ] \
        && ok "mv up on port $port: the source went after equal digests" || bad "mv up on port $port: exit $rc" "$CW/err"
    head -n 1 "$CW/err" | grep -q "are on different hosts" \
        && ok "mv up on port $port: the notice is the first line on stderr" || bad "mv up on port $port: the notice is not first" "$CW/err"
    m "$port" "$T:cp/mv$port" "$MW/d$port" >/dev/null 2>"$CW/err"
    rc=$?
    [ "$rc" = 0 ] && [ ! -e "$RD/mv$port" ] && [ "$(sum "$MW/d$port")" = "$want" ] \
        && ok "mv down on port $port: the far source went after equal digests" || bad "mv down on port $port: exit $rc" "$CW/err"
done

# Within one server the server renames: no byte moves, and no notice. One
# file under two spellings is refused (64) by the server's own answer.
for port in 2201 2207; do
    far "r$port"
    want=$(sum "$RD/r$port")
    m "$port" -v "$T:cp/r$port" "$T:cp/r$port-moved" >/dev/null 2>"$CW/err"
    rc=$?
    [ "$rc" = 0 ] && [ ! -e "$RD/r$port" ] && [ "$(sum "$RD/r$port-moved")" = "$want" ] \
        && grep -q "renamed on the server" "$CW/err" && ! grep -q "different hosts" "$CW/err" \
        && ok "mv within one server on port $port: a rename, and no notice" || bad "mv within one server on port $port: exit $rc" "$CW/err"
    m "$port" "$T:cp/r$port-moved" "$T:cp/./r$port-moved" >/dev/null 2>"$CW/err"
    rc=$?
    [ "$rc" = 64 ] && [ "$(sum "$RD/r$port-moved")" = "$want" ] \
        && ok "mv of one file named twice on port $port: exit 64, the file as it was" || bad "mv of one file named twice on port $port: exit $rc" "$CW/err"
done

# Through the server that flips a byte: 70, and the source stays, each way.
head -c 262145 /dev/urandom >"$MW/flip"
cp "$MW/flip" "$MW/flip.orig"
m 2205 "$MW/flip" "$T:cp/flipped" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 70 ] && cmp -s "$MW/flip" "$MW/flip.orig" \
    && ok "mv up through a flipped byte: exit 70, the source stays" || bad "mv up through a flipped byte: exit $rc" "$CW/err"
cp "$MW/flip.orig" "$RD/flipsrc"
chown podtest:podtest "$RD/flipsrc"
m 2205 "$T:cp/flipsrc" "$MW/flipdown" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 70 ] && cmp -s "$RD/flipsrc" "$MW/flip.orig" && [ ! -e "$MW/flipdown" ] \
    && ok "mv down through a flipped byte: exit 70, the source stays" || bad "mv down through a flipped byte: exit $rc" "$CW/err"

# A source that grows during the move: the copy finds it (66), and it stays.
head -c 50000000 /dev/urandom >"$MW/grow"
(while :; do printf x >>"$MW/grow"; done) &
grower=$!
m 2201 "$MW/grow" "$T:cp/grown" >/dev/null 2>"$CW/err"
rc=$?
kill "$grower" 2>/dev/null
wait "$grower" 2>/dev/null
[ "$rc" = 66 ] && [ "$(wc -c <"$MW/grow")" -gt 50000000 ] && [ ! -e "$RD/grown" ] \
    && ok "mv of a source that grows: exit 66, the source stays" || bad "mv of a source that grows: exit $rc" "$CW/err"
rm -f "$MW/grow"

# A verified copy whose source cannot be removed: 70, and the data is in
# both places, never in none.
mkdir -p "$RD/ro"
far ro/f2201
far ro/f2207
chown podtest:podtest "$RD/ro"
chmod 555 "$RD/ro"
for port in 2201 2207; do
    m "$port" "$T:cp/ro/f$port" "$MW/ro$port" >/dev/null 2>"$CW/err"
    rc=$?
    [ "$rc" = 70 ] && [ -e "$RD/ro/f$port" ] && cmp -s "$RD/ro/f$port" "$MW/ro$port" \
        && grep -q "the copy is complete and verified" "$CW/err" \
        && ok "mv down of a source that cannot be removed, port $port: exit 70, the data in both places" \
        || bad "mv down of a source that cannot be removed, port $port: exit $rc" "$CW/err"
done
chmod 755 "$RD/ro"

# Server to server: down, up, then a third connection removes the source.
far xa
want=$(sum "$RD/xa")
m 2201 "$T:cp/xa" "podtest@localhost:cp/xb" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ ! -e "$RD/xa" ] && [ "$(sum "$RD/xb")" = "$want" ] && head -n 1 "$CW/err" | grep -q "different hosts" \
    && ok "mv from server to server: through this host, then the source removed" || bad "mv from server to server: exit $rc" "$CW/err"

# --jsonl: one done object that says that the source is gone.
far j
m 2201 --jsonl "$T:cp/j" "$MW/j" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(wc -l <"$CW/out")" = 1 ] && grep -q '"source_removed":true' "$CW/out" \
    && ok "mv --jsonl: one done object, and the source removed" || bad "mv --jsonl: exit $rc" "$CW/out"
no_part "mv"
