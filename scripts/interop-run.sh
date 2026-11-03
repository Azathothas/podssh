# podssh run (T-192) against OpenSSH on port 2201: a project that holds
# run.sh (exit 6) and target/big.bin. The run exits 6 and copies run.sh;
# target/ is not on the server (the planted defect, no default excludes,
# copies it); a second run sends no file, and its summary counts target/ as
# left out; after a change, --dry-run plans that file alone and the command,
# and changes and runs nothing (T-475). Sourced by
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
# With no -v: the summary is at the default level (T-472).
r --from "$RW/proj" "$T" -- sh run.sh >"$RW/out" 2>"$RW/err"
rc=$?
[ "$rc" = 6 ] && grep -q "^podssh: 0 copied, 2 unchanged, 1 left out, in " "$RW/err" \
    && ok run.again "a second run: no file sent, target/ left out, the summary says so, and the exit 6 again" \
    || bad run.again "exit $rc" "$RW/err"
# --dry-run (T-475): after one change, the plan is that file and the
# command; the far file stays as it was, and the command does not run.
printf 'a, and more\n' >"$RW/proj/src/a.txt"
r --dry-run --from "$RW/proj" "$T" -- touch ran >"$RW/out" 2>"$RW/err"
rc=$?
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes "$T" 'cat .podssh/run/proj/src/a.txt; ls .podssh/run/proj' </dev/null >"$RW/ls" 2>&1
[ "$rc" = 0 ] && [ "$(grep -c '' "$RW/out")" = 2 ] \
    && grep -qxF "copy $RW/proj/src/a.txt -> .podssh/run/proj/src/a.txt" "$RW/out" \
    && [ "$(tail -n 1 "$RW/out")" = "run cd '.podssh/run/proj' && touch ran" ] \
    && grep -qx a "$RW/ls" && ! grep -qx ran "$RW/ls" \
    && ok run.dry_run "a dry run to OpenSSH: the changed file and the command, nothing changed there or run" \
    || bad run.dry_run "exit $rc" "$RW/out"
