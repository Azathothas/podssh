# cp --delta where the server has no copy-data (T-470), as GitHub #87's Go
# server has none: OpenSSH's sftp-server behind a wrapper that drops
# copy-data from its version reply. On 2214 the wrapper is the subsystem and
# commands run, so one command makes the temporary file from the old one and
# one block of five goes; on 2216 it is the ForceCommand too, so no command
# runs, the whole file goes, and one line says why with no -v. Sourced by
# scripts/interop-cp.sh while its servers run; uses ok, bad, c, sum, $W, $T,
# $CW and $RD.

echo
echo "== cp --delta with no copy-data"
cat >"$CW/nocopy.py" <<'EOF'
import subprocess, sys, threading
child = subprocess.Popen(["/usr/lib/ssh/sftp-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def exact(f, n):
    out = b""
    while len(out) < n:
        part = f.read(n - len(out))
        if not part:
            return None
        out += part
    return out
def without_copy_data(body):
    # VERSION (2): the version, then pairs of strings, a name and its data.
    if body[0] != 2:
        return body
    out, at = bytearray(body[:5]), 5
    while at + 4 <= len(body):
        n = int.from_bytes(body[at:at + 4], "big")
        name, at = body[at + 4:at + 4 + n], at + 4 + n
        m = int.from_bytes(body[at:at + 4], "big")
        data, at = body[at + 4:at + 4 + m], at + 4 + m
        if name != b"copy-data":
            out += len(name).to_bytes(4, "big") + name + len(data).to_bytes(4, "big") + data
    return bytes(out)
def up():
    while True:
        part = sys.stdin.buffer.read1(65536)
        if not part:
            break
        child.stdin.write(part)
        child.stdin.flush()
    child.stdin.close()
threading.Thread(target=up, daemon=True).start()
first = True
while True:
    head = exact(child.stdout, 4)
    body = head and exact(child.stdout, int.from_bytes(head, "big"))
    if not body:
        break
    if first:
        body, first = without_copy_data(body), False
    sys.stdout.buffer.write(len(body).to_bytes(4, "big") + body)
    sys.stdout.buffer.flush()
EOF
chmod 644 "$CW/nocopy.py"
for spec in "2214:Subsystem sftp /usr/bin/python3 $CW/nocopy.py" "2216:ForceCommand /usr/bin/python3 $CW/nocopy.py"; do
    port=${spec%%:*}
    {
        echo "Port $port"
        echo "ListenAddress 127.0.0.1"
        echo "HostKey $W/host_ed25519"
        echo "PidFile $W/sshd-$port.pid"
        echo "StrictModes no"
        echo "KbdInteractiveAuthentication no"
        echo "PerSourcePenalties no"
        # A subsystem request is refused before ForceCommand when no line names it.
        [ "$port" = 2216 ] && echo "Subsystem sftp /usr/bin/python3 $CW/nocopy.py"
        echo "${spec#*:}"
    } >"$CW/sshd-$port.conf"
done
for srv in nocopy:2214 nocopy_forced:2216; do
    port=${srv#*:}
    /usr/sbin/sshd -f "$CW/sshd-$port.conf" -E "$CW/sshd-$port.log" \
        && ok "delta.sshd.${srv%%:*}" "sshd on $port started" \
        || bad "delta.sshd.${srv%%:*}" "sshd on $port did not start" "$CW/sshd-$port.log"
done
sleep 1

# delta_of FILE: the delta of the done object of FILE, as compact JSON with
# its keys sorted.
delta_of() {
    python3 -c 'import json, sys
for line in open(sys.argv[1]):
    o = json.loads(line)
    if o.get("event") == "done":
        print(json.dumps(o.get("delta"), sort_keys=True, separators=(",", ":")))' "$1"
}
# The older version there, of 5 MiB; then 13 bytes of its fourth block
# changed here, as the issue changed them.
head -c 5242880 /dev/urandom >"$CW/d5.old"
cp "$CW/d5.old" "$CW/up/d5"
printf 'thirteen byte' | dd of="$CW/up/d5" bs=1 seek=3145828 conv=notrunc 2>/dev/null
delta_old() { cp "$CW/d5.old" "$RD/d5-$1" && chown podtest:podtest "$RD/d5-$1"; }

delta_old 2214
c 2214 --delta -v --jsonl "$CW/up/d5" "$T:cp/d5-2214" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$CW/up/d5")" = "$(sum "$RD/d5-2214")" ] \
    && grep -q 'no copy-data: a command there copies the old file' "$CW/err" \
    && grep -q 'delta: 1 of 5 blocks sent, 1048576 bytes' "$CW/err" \
    && [ "$(delta_of "$CW/out")" = '{"blocks":5,"bytes":1048576,"sent":1}' ] \
    && ok delta.command "cp --delta with no copy-data: a command copies the old file there, and 1 block of 5 goes" \
    || bad delta.command "cp --delta with no copy-data: exit $rc" "$CW/err"

why='the server has no copy-data and runs no command'
delta_old 2216
c 2216 --delta "$CW/up/d5" "$T:cp/d5-2216" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$CW/up/d5")" = "$(sum "$RD/d5-2216")" ] && [ "$(grep -c "$why" "$CW/err")" = 1 ] \
    && ok delta.no_command "cp --delta with no copy-data and no command: the whole file, exit 0, one line with no -v" \
    || bad delta.no_command "cp --delta with no copy-data and no command: exit $rc" "$CW/err"
delta_old 2216
c 2216 --delta -q "$CW/up/d5" "$T:cp/d5-2216" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$CW/up/d5")" = "$(sum "$RD/d5-2216")" ] && [ ! -s "$CW/err" ] \
    && ok delta.no_command.quiet "cp --delta -q with no copy-data and no command: the whole file, nothing on stderr" \
    || bad delta.no_command.quiet "cp --delta -q with no copy-data and no command: exit $rc" "$CW/err"
delta_old 2216
c 2216 --delta --jsonl "$CW/up/d5" "$T:cp/d5-2216" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(delta_of "$CW/out")" = '{"full":"no-copy-data"}' ] \
    && ok delta.no_command.jsonl "cp --delta --jsonl: the done object says why the whole file went" \
    || bad delta.no_command.jsonl "cp --delta --jsonl with no copy-data and no command: exit $rc" "$CW/out"

for port in 2214 2216; do
    [ -f "$W/sshd-$port.pid" ] && kill "$(cat "$W/sshd-$port.pid")" 2>/dev/null
done
rm -f "$RD/d5-2214" "$RD/d5-2216"
