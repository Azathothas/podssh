# podssh mcp (T-055) against OpenSSH on port 2201 and Dropbear on port 2203:
# the lines of an MCP client on its stdin, as a client of the revision
# 2025-06-18 sends them, and ssh_exec to each server and to a host outside
# --allow-host. Sourced by scripts/interop.sh; uses ok, bad, $BIN, $W and $KH.

echo
echo "== podssh mcp (T-055)"
MW="$W/mcp"
mkdir -p "$MW"
cat >"$MW/config" <<EOF
Host openssh
    HostName 127.0.0.1
    Port 2201
Host dropbear
    HostName 127.0.0.1
    Port 2203
Host *
    IdentityFile $W/id_ed25519
    IdentitiesOnly yes
    IdentityAgent none
    UserKnownHostsFile $KH
EOF
# The client: each request, then each answer until all came, then the end of
# its input; the server's stdout is kept line for line.
env -u SSH_AUTH_SOCK HOME="$W" timeout 120 python3 - "$BIN" "$MW/config" "$MW/out.jsonl" <<'EOF'
import json, subprocess, sys

binary, config, out = sys.argv[1:4]
argv = [binary, "mcp", "--allow-host", "openssh", "--allow-host", "dropbear", "-F", config, "--direct"]
server = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open(out + ".err", "wb"))


def send(message):
    server.stdin.write((json.dumps(message) + "\n").encode())
    server.stdin.flush()


def ssh_exec(id, destination, command):
    arguments = {"destination": destination, "command": command}
    send({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "ssh_exec", "arguments": arguments}})


send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "interop", "version": "1"}}})
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
ssh_exec(2, "podtest@openssh", "echo hi; exit 3")
ssh_exec(3, "podtest@dropbear", "echo hi; exit 3")
ssh_exec(4, "podtest@127.0.0.1", "true")
wanted = {1, 2, 3, 4}
with open(out, "wb") as kept:
    while wanted:
        line = server.stdout.readline()
        if not line:
            break
        kept.write(line)
        try:
            wanted.discard(json.loads(line).get("id"))
        except ValueError:
            pass
server.stdin.close()
server.wait(timeout=30)
sys.exit(1 if wanted else server.returncode)
EOF
rc=$?
# answer_of ID EXPR: whether the result of the answer to ID meets the Python
# EXPR on r.
answer_of() {
    python3 -c 'import json, sys
for line in open(sys.argv[1]):
    m = json.loads(line)
    if m.get("id") == int(sys.argv[2]):
        r = m.get("result", {})
        sys.exit(0 if eval(sys.argv[3]) else 1)
sys.exit(1)' "$MW/out.jsonl" "$1" "$2" 2>/dev/null
}
for srv in openssh:2 dropbear:3; do
    answer_of "${srv#*:}" \
        'not r["isError"] and r["structuredContent"]["status"] == 3 and r["structuredContent"]["stdout"] == "hi\n"' \
        && ok "mcp.${srv%%:*}.exec" "ssh_exec to ${srv%%:*} through podssh mcp: the status 3 and the stdout hi" \
        || bad "mcp.${srv%%:*}.exec" "ssh_exec to ${srv%%:*}: $(grep "\"id\":${srv#*:}," "$MW/out.jsonl" | cut -c1-300)" \
            "$MW/out.jsonl.err"
done
answer_of 4 'r["isError"] and "not allowed" in r["content"][0]["text"]' \
    && ok mcp.refused "ssh_exec to a host outside --allow-host: an error result, which says why" \
    || bad mcp.refused "ssh_exec outside --allow-host: $(grep '"id":4,' "$MW/out.jsonl" | cut -c1-300)" "$MW/out.jsonl.err"
python3 -c 'import json, sys
for line in open(sys.argv[1]):
    m = json.loads(line)
    assert m["jsonrpc"] == "2.0" and "id" in m and ("result" in m) != ("error" in m), line' "$MW/out.jsonl" \
    && [ "$rc" = 0 ] \
    && ok mcp.lines "each line on podssh mcp's stdout is one JSON-RPC answer, and it ended at the end of its input" \
    || bad mcp.lines "podssh mcp's stdout (exit $rc)" "$MW/out.jsonl"
