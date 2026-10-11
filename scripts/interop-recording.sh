# --record and podssh play (T-033): a session of OpenSSH's sshd recorded as
# asciicast v2, each of its lines read by Python's json, the file of mode 600
# and never written over, and played again. Sourced by scripts/interop.sh
# once its servers run; uses ok, bad, p, $W, $BIN, $K and $T.

echo
echo "== --record and podssh play (T-033)"
rm -f "$W/s.cast"
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -tt --record "$W/s.cast" "$T" 'printf hi; exit 3' </dev/null >"$W/out" 2>"$W/err"
rc=$?
python3 - "$W/s.cast" >"$W/cast.check" 2>&1 <<'EOF'
import json
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
header = json.loads(lines[0])
events = [json.loads(line) for line in lines[1:]]
shown = "".join(event[2] for event in events if event[1] == "o")
assert header["version"] == 2 and "hi" in shown, (header, shown)
print("read", len(events), "events")
EOF
read_ok=$?
mode=$(stat -c %a "$W/s.cast" 2>/dev/null)
[ "$rc" = 3 ] && [ "$read_ok" = 0 ] && [ "$mode" = 600 ] \
    && ok recording.session "--record: exit 3, each line JSON of asciicast v2, the file of mode 600" \
    || bad recording.session "--record: exit $rc, JSON check $read_ok, mode $mode" "$W/cast.check"
cp "$W/s.cast" "$W/s.cast.before"
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -tt --record "$W/s.cast" "$T" 'printf again' </dev/null >"$W/out" 2>"$W/err"
rc=$?
[ "$rc" = 255 ] && cmp -s "$W/s.cast" "$W/s.cast.before" \
    && ok recording.no_overwrite "--record onto a file that exists: refused, and the file is as it was" \
    || bad recording.no_overwrite "--record onto a file that exists: exit $rc" "$W/err"
"$BIN" play --speed 100 "$W/s.cast" >"$W/out" 2>"$W/err"
rc=$?
[ "$rc" = 0 ] && grep -q hi "$W/out" \
    && ok recording.play "podssh play shows the recording again" \
    || bad recording.play "podssh play: exit $rc" "$W/err"
