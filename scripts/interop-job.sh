# podssh job (T-193) against OpenSSH on port 2201 and Dropbear on port
# 2203, with tmux in the image: two jobs `sleep 300` start and the list shows
# both running; a stop of one ends its tmux session and leaves the other
# running (the planted defect, a stop of each session named podssh-job-,
# ends both); the log gives the output of a job that printed and ended, and
# the list its status; log --follow gives five ticks once each, then the
# status (T-485); with tmux off PATH, start exits 255 and names tmux,
# and both start and ssh --persist name apk's command for it (T-481); then
# the jobs of --no-tmux on each server, with tmux still off PATH: two run,
# a stop of one leaves the other, and a third gives J and 5 (T-481). Then
# the queue of T-197, below. Sourced by scripts/interop-each.sh; uses ok,
# bad, $BIN, $W, $K, $T, $KH and p.

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
    # log --follow (T-485): five ticks, each once and in order, then 3.
    t=$(j start "$H" -- 'for i in 1 2 3 4 5; do echo tick $i; sleep 1; done; exit 3' 2>"$JW/err")
    j log --follow "$H" "$t" >"$JW/log" 2>>"$JW/err"
    rc=$?
    [ "$rc" = 3 ] && [ "$(cat "$JW/log")" = "$(printf 'tick %s\n' 1 2 3 4 5)" ] \
        && ok "job.${srv%%:*}.follow" "log --follow of five ticks: each once, in order, then exit 3" \
        || bad "job.${srv%%:*}.follow" "exit $rc; the log: $(head -c 200 "$JW/log")" "$JW/err"
    j stop "$H" "$b" >/dev/null 2>&1
    j stop "$H" "$c" >/dev/null 2>&1
    j stop "$H" "$t" >/dev/null 2>&1
done
tmuxbin=$(command -v tmux)
if [ -n "$tmuxbin" ] && mv "$tmuxbin" "$tmuxbin.off"; then
    j start "$T:2201" -- sleep 300 >"$JW/out" 2>"$JW/err"
    rc=$?
    # The image is Alpine's: the refusal names apk's command (T-481).
    [ "$rc" = 255 ] && [ ! -s "$JW/out" ] && grep -q 'has no tmux on PATH' "$JW/err" \
        && grep -q 'apk add tmux' "$JW/err" && grep -q -- '--no-tmux' "$JW/err" \
        && ok job.no_tmux "start with tmux off PATH: exit 255, tmux, apk add tmux and --no-tmux named, and no ID" \
        || bad job.no_tmux "exit $rc" "$JW/err"
    # shellcheck disable=SC2086
    p 2201 $K -o BatchMode=yes --persist "$T" </dev/null >"$JW/out" 2>"$JW/err"
    rc=$?
    [ "$rc" = 255 ] && grep -q 'has no tmux on PATH; --persist needs it; to install it' "$JW/err" \
        && grep -q 'apk add tmux' "$JW/err" \
        && ok job.persist_no_tmux "ssh --persist with tmux off PATH: exit 255, and apk add tmux named" \
        || bad job.persist_no_tmux "exit $rc" "$JW/err"
    # Jobs with no tmux (T-481), on each server: two jobs, a stop of one,
    # and the status and output of a third.
    for srv in openssh:2201 dropbear:2203; do
        H="$T:${srv#*:}"
        a=$(j start --no-tmux "$H" -- sleep 300 2>"$JW/err")
        b=$(j start --no-tmux "$H" -- sleep 300 2>>"$JW/err")
        j list "$H" >"$JW/list" 2>>"$JW/err"
        [ "${#a}" = 8 ] && [ "${#b}" = 8 ] && grep -q "^$a  running .*sleep 300\$" "$JW/list" \
            && grep -q "^$b  running .*sleep 300\$" "$JW/list" \
            && ok "job.plain.${srv%%:*}.start" "two jobs with --no-tmux: two IDs, each running in the list" \
            || bad "job.plain.${srv%%:*}.start" "the IDs '$a' and '$b'" "$JW/list"
        j stop "$H" "$a" >"$JW/out" 2>"$JW/err"
        rc=$?
        j list "$H" >"$JW/list" 2>>"$JW/err"
        [ "$rc" = 0 ] && ! grep -q "^$a " "$JW/list" && grep -q "^$b  running" "$JW/list" \
            && ok "job.plain.${srv%%:*}.stop" "a stop of one job with no tmux ends it, and the other runs on" \
            || bad "job.plain.${srv%%:*}.stop" "exit $rc" "$JW/list"
        c=$(j start --no-tmux "$H" -- "printf 'J\\n'; exit 5" 2>"$JW/err")
        n=0
        while [ "$n" -lt 30 ] && ! j list "$H" 2>/dev/null | grep -q "^$c  done"; do
            sleep 1
            n=$((n + 1))
        done
        j log "$H" "$c" >"$JW/log" 2>>"$JW/err"
        rc=$?
        j list "$H" >"$JW/list" 2>>"$JW/err"
        [ "$rc" = 0 ] && [ "$(cat "$JW/log")" = J ] && grep -q "^$c  done  *5  " "$JW/list" \
            && ok "job.plain.${srv%%:*}.log" "a job with no tmux that printed J and exited 5: J, and 5 in the list" \
            || bad "job.plain.${srv%%:*}.log" "exit $rc; the log: $(head -c 200 "$JW/log")" "$JW/list"
        j stop "$H" "$b" >/dev/null 2>&1
        j stop "$H" "$c" >/dev/null 2>&1
    done
    mv "$tmuxbin.off" "$tmuxbin"
else
    bad job.no_tmux "tmux is not in the image" /dev/null
fi

# The queue (T-197), on OpenSSH: three jobs with one slot, `sleep 2; echo J`
# twice, then `exit 5`. Right after the submits one runs and two wait (the
# planted defect, a runner that ignores the slots, runs more); wait on the
# last exits 5 within 30 s; fetch gets an out that holds J; and a submit to
# two hosts goes to the one with fewer jobs queued or running (the planted
# defect, a choice of the first host, fails it).
H="$T:2201"
q1=$(j submit "$H" --slots 1 -- 'sleep 2; echo J' 2>"$JW/err")
q2=$(j submit "$H" --slots 1 -- 'sleep 2; echo J' 2>>"$JW/err")
q3=$(j submit "$H" --slots 1 -- 'exit 5' 2>>"$JW/err")
j list "$H" >"$JW/list" 2>>"$JW/err"
n=0
while [ "$n" -lt 10 ] && ! grep -q "  running " "$JW/list"; do
    j list "$H" >"$JW/list" 2>>"$JW/err"
    n=$((n + 1))
done
r=$(grep -c "  running " "$JW/list")
w=$(grep -c "  queued " "$JW/list")
[ "$r" = 1 ] && [ "$w" = 2 ] \
    && ok job.queue.slots "three jobs with one slot: one runs and two are queued" \
    || bad job.queue.slots "running $r, queued $w" "$JW/list"
began=$(date +%s)
j wait "$H" "$q3" --timeout 30s >"$JW/out" 2>"$JW/err"
rc=$?
took=$(($(date +%s) - began))
[ "$rc" = 5 ] && [ "$took" -le 30 ] \
    && ok job.queue.wait "wait on the last job: exit 5, in $took s" \
    || bad job.queue.wait "exit $rc after $took s" "$JW/err"
rm -rf "$JW/got"
j fetch "$H" "$q1" "$JW/got" >"$JW/out" 2>"$JW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$JW/got/out" 2>/dev/null)" = J ] \
    && ok job.queue.fetch "fetch of the first job: its out holds J" \
    || bad job.queue.fetch "exit $rc" "$JW/err"
# Both servers run as podtest, so they read one queue in one home, and
# their counts tie: the second host of the list is Dropbear as a user of its
# own, with podtest's keys and an empty queue.
adduser -D -s /bin/sh podjob >/dev/null 2>&1 || true
echo "podjob:$PW" | chpasswd >/dev/null 2>&1
mkdir -p /home/podjob/.ssh
cp /home/podtest/.ssh/authorized_keys /home/podjob/.ssh/authorized_keys
chown -R podjob:podjob /home/podjob/.ssh
chmod 700 /home/podjob/.ssh
chmod 600 /home/podjob/.ssh/authorized_keys
U2=podjob@127.0.0.1
s1=$(j submit "$H" -- sleep 60 2>"$JW/err")
got=$(j submit "$T:2201,$U2:2203" -- sleep 60 2>>"$JW/err")
[ "${got% *}" = "$U2:2203" ] && [ "${#s1}" = 8 ] \
    && ok job.queue.choose "a submit to two hosts goes to the one with no job, Dropbear's podjob: $got" \
    || bad job.queue.choose "the answer '$got'" "$JW/err"
for id in "$q1" "$q2" "$q3" "$s1"; do
    j stop "$H" "$id" >/dev/null 2>&1
done
j stop "$U2:2203" "${got#* }" >/dev/null 2>&1
