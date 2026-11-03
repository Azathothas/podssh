# podssh mcp (T-055) against OpenSSH on port 2201 and Dropbear on port 2203:
# the lines of an MCP client on its stdin, as a client of the revision
# 2025-06-18 sends them, and ssh_exec to each server and to a host outside
# --allow-host; then (T-488) cp_put of a file's bytes to OpenSSH and cp_get
# of it back into the directory of --allow-dir, and job_start and job_stop
# there, each call after the one before. Sourced by scripts/interop.sh; uses
# ok, bad, $BIN, $W and $KH.

echo
echo "== podssh mcp (T-055, T-488)"
MW="$W/mcp"
mkdir -p "$MW/dir"
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
env -u SSH_AUTH_SOCK HOME="$W" timeout 240 python3 - "$BIN" "$MW/config" "$MW/out.jsonl" "$MW/dir" <<'EOF'
import base64, json, subprocess, sys

binary, config, out, allowed = sys.argv[1:5]
argv = [binary, "mcp", "--allow-host", "openssh", "--allow-host", "dropbear", "--allow-dir", allowed,
        "-F", config, "--direct"]
server = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open(out + ".err", "wb"))
kept = open(out, "wb")
answers = {}


def send(message):
    server.stdin.write((json.dumps(message) + "\n").encode())
    server.stdin.flush()


def call(id, name, arguments):
    send({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": arguments}})


def wait_for(*ids):
    """Read the answers until each of ids came; False at the end of stdout."""
    while not all(i in answers for i in ids):
        line = server.stdout.readline()
        if not line:
            return False
        kept.write(line)
        try:
            message = json.loads(line)
            answers[message.get("id")] = message
        except ValueError:
            pass
    return True


send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "interop", "version": "1"}}})
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
call(2, "ssh_exec", {"destination": "podtest@openssh", "command": "echo hi; exit 3"})
call(3, "ssh_exec", {"destination": "podtest@dropbear", "command": "echo hi; exit 3"})
call(4, "ssh_exec", {"destination": "podtest@127.0.0.1", "command": "true"})
done = wait_for(1, 2, 3, 4)
# The copies and the job, each after the one before: the calls run at once.
content = base64.b64encode(b"hello from mcp\n").decode()
call(5, "cp_put", {"destination": "podtest@openssh", "path": "mcp-note.txt", "content": content})
done = done and wait_for(5)
call(6, "cp_get", {"destination": "podtest@openssh", "path": "mcp-note.txt", "local_path": "back.txt"})
done = done and wait_for(6)
call(7, "job_start", {"destination": "podtest@openssh", "command": "true"})
done = done and wait_for(7)
job = ((answers.get(7) or {}).get("result") or {}).get("structuredContent", {}).get("id") or "00000000"
call(8, "job_stop", {"destination": "podtest@openssh", "id": job})
done = done and wait_for(8)
kept.close()
server.stdin.close()
server.wait(timeout=30)
sys.exit(server.returncode if done else 1)
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
answer_of 5 'not r["isError"] and r["structuredContent"]["exit"] == 0' \
    && answer_of 6 'not r["isError"] and r["structuredContent"]["exit"] == 0' \
    && [ "$(cat "$MW/dir/back.txt" 2>/dev/null)" = "hello from mcp" ] \
    && ok mcp.cp "cp_put of a file's bytes to OpenSSH, and cp_get of it back into --allow-dir, the same bytes" \
    || bad mcp.cp "cp_put and cp_get: $(grep -E '"id":(5|6),' "$MW/out.jsonl" | cut -c1-300)" "$MW/out.jsonl.err"
answer_of 7 'not r["isError"] and len(r["structuredContent"]["id"]) == 8' \
    && answer_of 8 'not r["isError"]' \
    && ok mcp.job "job_start on OpenSSH gave a job's id, and job_stop removed the job" \
    || bad mcp.job "job_start and job_stop: $(grep -E '"id":(7|8),' "$MW/out.jsonl" | cut -c1-300)" "$MW/out.jsonl.err"
python3 -c 'import json, sys
for line in open(sys.argv[1]):
    m = json.loads(line)
    assert m["jsonrpc"] == "2.0" and "id" in m and ("result" in m) != ("error" in m), line' "$MW/out.jsonl" \
    && [ "$rc" = 0 ] \
    && ok mcp.lines "each line on podssh mcp's stdout is one JSON-RPC answer, and it ended at the end of its input" \
    || bad mcp.lines "podssh mcp's stdout (exit $rc)" "$MW/out.jsonl"
