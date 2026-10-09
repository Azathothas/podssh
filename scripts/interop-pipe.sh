# podssh pipe with the local addresses (T-174). Sourced by scripts/interop.sh;
# uses ok, bad, expect_rc, $W and $BIN. The child is on a socketpair here,
# as the build image allows one.

echo
echo "== pipe"
PD="$W/pipe"
mkdir -p "$PD"

# Both ways through a program, and the end of input as a half-close.
head -c 5000000 /dev/urandom >"$PD/in"
"$BIN" pipe stdio exec:cat <"$PD/in" >"$PD/out" 2>"$PD/err"
rc=$?
[ "$rc" = 0 ] && cmp -s "$PD/in" "$PD/out" \
    && ok "pipe stdio exec:cat: 5,000,000 bytes back, unchanged" || bad "pipe stdio exec:cat: exit $rc" "$PD/err"

# A descriptor that the caller opened.
printf 'from a descriptor\n' >"$PD/fd3"
"$BIN" pipe fd:3 stdio 3<"$PD/fd3" </dev/null >"$PD/out" 2>"$PD/err"
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$PD/out")" = "from a descriptor" ] \
    && ok "pipe fd:3 stdio reads the descriptor" || bad "pipe fd:3 stdio: exit $rc" "$PD/err"

# The program's status, as a shell gives it.
"$BIN" pipe stdio "exec:sh -c 'exit 7'" </dev/null >/dev/null 2>"$PD/err"
expect_rc "pipe gives the program's status" 7 $? "$PD/err"
"$BIN" pipe stdio "exec:sh -c 'kill -TERM \$\$'" </dev/null >/dev/null 2>"$PD/err"
expect_rc "pipe gives 128 + the signal that ended the program" 143 $? "$PD/err"
rm -rf "$PD"
