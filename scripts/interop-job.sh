# podssh job (T-193) against OpenSSH on port 2201 and Dropbear on port
# 2203, with tmux in the image: two jobs `sleep 300` start and the list shows
# both running; a stop of one ends its tmux session and leaves the other
# running (the planted defect, a stop of each session named podssh-job-,
# ends both); the log gives the output of a job that printed and ended, and
# the list its status; with tmux off PATH, start exits 255 and names tmux.
# Sourced by scripts/interop-each.sh; uses ok, bad, $BIN, $W, $K, $T, $KH
# and p.

echo
echo "== podssh job (T-193, OpenSSH and Dropbear)"
JW="$W/job"
mkdir -p "$JW"
# j [podssh job arguments...]: podssh job as p() runs ssh.
j() {
    # shellcheck disable=SC2086
    timeout 60 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" job --direct -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K "$@" </dev/null
}
for srv in openssh:2201 dropbear:2203; do
    port=${srv#*:}
    H="$T:$port"
    a=$(j start "$H" -- sleep 300 2>"$JW/err")
    b=$(j start "$H" -- sleep 300 2>>"$JW/err")
    j list "$H" >"$JW/list" 2>>"$JW/err"
    [ "${#a}" = 8 ] && [ "${#b}" = 8 ] && grep -q "^$a  running .*sleep 300\$" "$JW/list" \
        && grep -q "^$b  running .*sleep 300\$" "$JW/list" \
        && ok "job.${srv%%:*}.start" "two jobs sleep 300 started: two IDs, each running in the list" \
        || bad "job.${srv%%:*}.start" "the IDs '$a' and '$b'" "$JW/list"
    j stop "$H" "$a" >"$JW/out" 2>"$JW/err"
    rc=$?
    j list "$H" >"$JW/list" 2>>"$JW/err"
    # shellcheck disable=SC2086
    p "$port" $K -o BatchMode=yes "$T" "tmux has-session -t =podssh-job-$a" </dev/null >/dev/null 2>&1
    there=$?
    [ "$rc" = 0 ] && [ "$there" != 0 ] && ! grep -q "^$a " "$JW/list" && grep -q "^$b  running" "$JW/list" \
        && ok "job.${srv%%:*}.stop" "a stop of one ends its tmux session, and the other runs on" \
        || bad "job.${srv%%:*}.stop" "exit $rc; has-session of the stopped one: $there" "$JW/list"
    c=$(j start "$H" -- "printf 'J\\n'; exit 5" 2>"$JW/err")
    n=0
    while [ "$n" -lt 30 ] && ! j list "$H" 2>/dev/null | grep -q "^$c  done"; do
        sleep 1
        n=$((n + 1))
    done
    j log "$H" "$c" >"$JW/log" 2>>"$JW/err"
    rc=$?
    j list "$H" >"$JW/list" 2>>"$JW/err"
    [ "$rc" = 0 ] && [ "$(cat "$JW/log")" = J ] && grep -q "^$c  done  *5  " "$JW/list" \
        && ok "job.${srv%%:*}.log" "a job that printed J and exited 5: its log is J, and the list gives 5" \
        || bad "job.${srv%%:*}.log" "exit $rc; the log: $(head -c 200 "$JW/log")" "$JW/list"
    j stop "$H" "$b" >/dev/null 2>&1
    j stop "$H" "$c" >/dev/null 2>&1
done
tmuxbin=$(command -v tmux)
if [ -n "$tmuxbin" ] && mv "$tmuxbin" "$tmuxbin.off"; then
    j start "$T:2201" -- sleep 300 >"$JW/out" 2>"$JW/err"
    rc=$?
    mv "$tmuxbin.off" "$tmuxbin"
    [ "$rc" = 255 ] && [ ! -s "$JW/out" ] && grep -q 'has no tmux on PATH' "$JW/err" \
        && ok job.no_tmux "start with tmux off PATH: exit 255, tmux named, and no ID" \
        || bad job.no_tmux "exit $rc" "$JW/err"
else
    bad job.no_tmux "tmux is not in the image" /dev/null
fi
