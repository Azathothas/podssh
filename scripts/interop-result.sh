# --result-file (T-054) against OpenSSH's sshd on port 2201 and Dropbear on
# port 2203: the remote status, a signal, 5,000,000 bytes each way, and a
# refused login, each in the JSON object of the run, while stdout stays as
# it is; a run through a podssh control master (T-039); and the program of
# PODSSH_ERROR_PROGRAM (T-195), which a remote status never starts.
# Sourced by scripts/interop.sh; uses ok, bad, p, $W, $K and $T.

echo
echo "== --result-file (T-054, OpenSSH, then Dropbear)"
RW="$W/result"
mkdir -p "$RW"
# result_of FILE EXPR: whether the object in FILE meets the Python EXPR on r.
result_of() {
    python3 -c 'import json, sys; r = json.load(open(sys.argv[1])); sys.exit(0 if eval(sys.argv[2]) else 1)' "$1" "$2" \
        2>/dev/null
}
head -c 5000000 /dev/urandom >"$RW/blob"
want=$(sha256sum <"$RW/blob" | cut -c1-64)
for srv in openssh:2201 dropbear:2203; do
    port=${srv#*:}
    # shellcheck disable=SC2086
    p "$port" $K -o BatchMode=yes --result-file "$RW/exit.json" "$T" 'echo out; exit 3' </dev/null \
        >"$RW/out" 2>"$RW/err"
    rc=$?
    [ "$rc" = 3 ] && [ "$(cat "$RW/out")" = out ] && result_of "$RW/exit.json" \
        'r["exit"] == 3 and r["status"] == 3 and r["end"] == "status" and r["bytes"]["stdout"] == 4' \
        && ok "result.${srv%%:*}.status" "port $port: exit 3 gives the status 3, and 4 bytes of stdout" \
        || bad "result.${srv%%:*}.status" "port $port: exit $rc, $(cat "$RW/exit.json" 2>/dev/null)" "$RW/err"
    # shellcheck disable=SC2016,SC2086
    p "$port" $K -o BatchMode=yes --result-file "$RW/kill.json" "$T" 'kill -TERM $$' </dev/null \
        >"$RW/out" 2>"$RW/err"
    rc=$?
    [ "$rc" = 143 ] && result_of "$RW/kill.json" \
        'r["exit"] == 143 and r["status"] is None and r["end"] == "signal" and r["signal"]["name"] == "TERM"' \
        && ok "result.${srv%%:*}.signal" "port $port: kill -TERM gives the signal TERM and exit 143" \
        || bad "result.${srv%%:*}.signal" "port $port: exit $rc, $(cat "$RW/kill.json" 2>/dev/null)" "$RW/err"
    # shellcheck disable=SC2086
    p "$port" $K -o BatchMode=yes --result-file "$RW/bytes.json" "$T" cat <"$RW/blob" >"$RW/out" 2>"$RW/err"
    rc=$?
    got=$(sha256sum <"$RW/out" | cut -c1-64)
    [ "$rc" = 0 ] && [ "$got" = "$want" ] && result_of "$RW/bytes.json" \
        'r["bytes"] == {"stdin": 5000000, "stdout": 5000000, "stderr": 0}' \
        && ok "result.${srv%%:*}.bytes" "port $port: 5,000,000 bytes up and back, the same digest, and counted" \
        || bad "result.${srv%%:*}.bytes" "port $port: exit $rc, $got, $(cat "$RW/bytes.json" 2>/dev/null)" "$RW/err"
    p "$port" -o BatchMode=yes -o PasswordAuthentication=no --result-file "$RW/auth.json" "$T" true </dev/null \
        >"$RW/out" 2>"$RW/err"
    rc=$?
    [ "$rc" = 255 ] && result_of "$RW/auth.json" 'r["exit"] == 255 and r["end"] == "failed" and r["failure"] == "auth"' \
        && ok "result.${srv%%:*}.auth" "port $port: a login that no key opens gives the end failed and the class auth" \
        || bad "result.${srv%%:*}.auth" "port $port: exit $rc, $(cat "$RW/auth.json" 2>/dev/null)" "$RW/err"
done
# Through a podssh control master: the master tells the exit code alone,
# and carries the bytes.
# shellcheck disable=SC2086
(as_job=exec p 2201 $K -o BatchMode=yes -M -N -S "$RW/ctl" "$T" </dev/null >"$RW/master.out" 2>"$RW/master.err") &
master=$!
tries=0
until [ -S "$RW/ctl" ] || [ "$tries" -ge 100 ]; do
    sleep 0.1
    tries=$((tries + 1))
done
p 2201 -S "$RW/ctl" --result-file "$RW/shared.json" "$T" 'echo out; exit 3' </dev/null >"$RW/out" 2>"$RW/err"
rc=$?
[ "$rc" = 3 ] && [ "$(cat "$RW/out")" = out ] && result_of "$RW/shared.json" \
    'r["exit"] == 3 and r["end"] == "shared" and r["status"] is None and r["bytes"] is None and r["failure"] is None' \
    && ok result.shared "through a podssh control master: exit 3, the end shared, and the bytes null" \
    || bad result.shared "through a control master: exit $rc, $(cat "$RW/shared.json" 2>/dev/null)" "$RW/err"
p 2201 -S "$RW/ctl" -O exit "$T" </dev/null >/dev/null 2>&1
kill "$master" 2>/dev/null
wait "$master" 2>/dev/null
# The session log (T-056): a line for the run, and never its command.
SL="$RW/sessions.jsonl"
export PODSSH_SESSION_LOG="$SL"
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes "$T" 'echo SECRET-WORD' </dev/null >"$RW/out" 2>"$RW/err"
rc=$?
unset PODSSH_SESSION_LOG
[ "$rc" = 0 ] && [ "$(wc -l <"$SL")" -eq 1 ] && ! grep -q SECRET-WORD "$SL" \
    && python3 -c 'import json, sys
r = json.loads(open(sys.argv[1]).readline())
sys.exit(0 if (r["verb"], r["port"], r["via"], r["exit"], r["end"]) == ("ssh", 2201, "direct", 0, "status") else 1)' "$SL" \
    && ok result.session_log "PODSSH_SESSION_LOG: one line for a run of echo SECRET-WORD, and no SECRET-WORD in it" \
    || bad result.session_log "the session log after exit $rc" "$SL"
# PODSSH_ERROR_PROGRAM (T-195): a remote exit 3 starts no program, on each
# server; a login that no key opens hands one report to it. The planted
# defect, a program for each exit that is not 0, fails the first check.
cat >"$RW/triage" <<EOF
#!/bin/sh
cat >>"$RW/reports"
EOF
chmod 700 "$RW/triage"
rm -f "$RW/reports"
export PODSSH_ERROR_PROGRAM="$RW/triage"
for srv in openssh:2201 dropbear:2203; do
    port=${srv#*:}
    # shellcheck disable=SC2086
    p "$port" $K -o BatchMode=yes "$T" 'echo out; exit 3' </dev/null >"$RW/out" 2>"$RW/err"
    rc=$?
    [ "$rc" = 3 ] && [ ! -e "$RW/reports" ] \
        && ok "result.error_program.${srv%%:*}" "port $port: a remote exit 3 starts no program" \
        || bad "result.error_program.${srv%%:*}" "port $port: exit $rc; $(cat "$RW/reports" 2>/dev/null)" "$RW/err"
done
p 2201 -o BatchMode=yes -o PasswordAuthentication=no "$T" true </dev/null >"$RW/out" 2>"$RW/err"
rc=$?
unset PODSSH_ERROR_PROGRAM
[ "$rc" = 255 ] && [ "$(wc -l <"$RW/reports")" -eq 1 ] && python3 -c 'import json, sys
r = json.loads(open(sys.argv[1]).readline())
sys.exit(0 if (r["verb"], r["exit"], r["schema"]) == ("ssh", 255, 1) and r["messages"] else 1)' "$RW/reports" \
    && ok result.error_program.failure "a login that no key opens: exit 255, and one report with its messages" \
    || bad result.error_program.failure "exit $rc; $(cat "$RW/reports" 2>/dev/null)" "$RW/err"
