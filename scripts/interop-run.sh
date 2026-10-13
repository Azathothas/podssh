# podssh run (T-192) against OpenSSH on port 2201: a project that holds
# run.sh (exit 6) and target/big.bin. The run exits 6 and copies run.sh;
# target/ is not on the server (the planted defect, no default excludes,
# copies it); a second run sends no file. Sourced by
# scripts/interop-each.sh; uses ok, bad, $BIN, $W, $K, $T, $KH and p.

echo
echo "== podssh run (T-192, OpenSSH)"
RW="$W/run"
rm -rf "$RW"
mkdir -p "$RW/proj/target" "$RW/proj/src"
printf 'exit 6\n' >"$RW/proj/run.sh"
printf 'a\n' >"$RW/proj/src/a.txt"
head -c 1048576 /dev/zero >"$RW/proj/target/big.bin"
# r [podssh run arguments...]: podssh run as p() runs ssh.
r() {
    # shellcheck disable=SC2086
    timeout 120 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" run --direct -p 2201 -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K "$@" </dev/null
}
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes "$T" 'rm -rf .podssh/run/proj' </dev/null >/dev/null 2>&1
r -v --from "$RW/proj" "$T" -- sh run.sh >"$RW/out" 2>"$RW/err"
rc=$?
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes "$T" 'ls -a .podssh/run/proj' </dev/null >"$RW/ls" 2>&1
[ "$rc" = 6 ] && grep -qx run.sh "$RW/ls" && grep -qx src "$RW/ls" \
    && ok run.status "run to OpenSSH: the project is there, and run.sh gave its exit 6" \
    || bad run.status "exit $rc" "$RW/err"
[ "$rc" = 6 ] && [ -s "$RW/ls" ] && ! grep -qx target "$RW/ls" \
    && ok run.excludes "target/ stayed here" \
    || bad run.excludes "target/ is on the server, or the run failed" "$RW/ls"
r -v --from "$RW/proj" "$T" -- sh run.sh >"$RW/out" 2>"$RW/err"
rc=$?
[ "$rc" = 6 ] && grep -q ": files sent 0, unchanged 2" "$RW/err" \
    && ok run.again "a second run: no file sent, and the exit 6 again" \
    || bad run.again "exit $rc" "$RW/err"
