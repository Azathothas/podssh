# podssh agent (T-034). Sourced by scripts/interop.sh once its servers run;
# uses ok, bad, expect_rc, $W, $BIN, $KH and $T. OpenSSH's ssh-add lists the
# key that podssh agent took, and podssh ssh logs in with it, with no -i;
# after a kill, the socket and its directory are gone.

echo
echo "== podssh agent (T-034)"
AG="$W/agent"
mkdir -p "$AG"
# An askpass program that says the passphrase of id_enc.
printf '#!/bin/sh\necho "open sesame"\n' >"$AG/askpass"
chmod 700 "$AG/askpass"
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" agent >"$AG/env" 2>"$AG/err" &
AGENT_PID=$!
tries=0
while ! grep -q SSH_AUTH_SOCK "$AG/env" 2>/dev/null && [ "$tries" -lt 50 ]; do
    sleep 0.1
    tries=$((tries + 1))
done
sock=$(sed -n 's/^SSH_AUTH_SOCK=\([^;]*\);.*/\1/p' "$AG/env")
if [ -n "$sock" ] && [ -S "$sock" ]; then
    ok "podssh agent serves on $sock"
    [ "$(stat -c %a "$sock")" = 600 ] && ok "the agent's socket is mode 0600" ||
        bad "the agent's socket is mode $(stat -c %a "$sock")" "$AG/err"
    [ "$(stat -c %a "$(dirname "$sock")")" = 700 ] && ok "its directory is mode 0700" ||
        bad "its directory is mode $(stat -c %a "$(dirname "$sock")")" "$AG/err"
    timeout 20 env SSH_AUTH_SOCK="$sock" SSH_ASKPASS="$AG/askpass" SSH_ASKPASS_REQUIRE=force HOME="$W" \
        "$BIN" agent add "$W/id_enc" </dev/null >"$AG/out" 2>"$AG/err2"
    expect_rc "podssh agent add takes id_enc with its passphrase from SSH_ASKPASS" 0 $? "$AG/err2"
    timeout 20 env SSH_AUTH_SOCK="$sock" ssh-add -l >"$AG/list" 2>&1
    expect_rc "OpenSSH's ssh-add -l lists the key that podssh agent holds" 0 $? "$AG/list"
    want=$(ssh-keygen -l -f "$W/id_enc.pub" | awk '{print $2}')
    grep -q "$want" "$AG/list" && ok "the key listed is id_enc's ($want)" ||
        bad "ssh-add -l did not list $want" "$AG/list"
    timeout 30 env SSH_AUTH_SOCK="$sock" HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$T" true </dev/null >"$AG/out" 2>"$AG/err3"
    expect_rc "podssh ssh logs in through podssh agent, with no -i" 0 $? "$AG/err3"
else
    bad "podssh agent did not say SSH_AUTH_SOCK" "$AG/err"
fi
kill "$AGENT_PID" 2>/dev/null
wait "$AGENT_PID" 2>/dev/null
if [ -n "$sock" ] && [ ! -e "$sock" ] && [ ! -e "$(dirname "$sock")" ]; then
    ok "after a kill, the agent's socket and its directory are gone"
else
    bad "after a kill, the agent's socket or its directory stayed: $sock" "$AG/err"
fi
