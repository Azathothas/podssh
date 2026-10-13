# podssh agent (T-034) and -A (T-036). Sourced by scripts/interop.sh once
# its servers run, after interop-keygen.sh (whose $KG/sk_file it takes);
# uses ok, bad, expect_rc, $W, $H, $BIN, $KH and $T. OpenSSH's
# ssh-add lists the key that podssh agent took, and podssh ssh logs in with
# it, with no -i, and forwards it with -A; after a kill, the socket and its
# directory are gone. Then OpenSSH's ssh-agent, forwarded: ssh-add -l on the
# server lists its key with -A, through -J too, and finds no agent without;
# bound to the server's host key (T-279), it hides a key that ssh-add -h
# keeps for another host.

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
    ok agent.serve "podssh agent serves on $sock"
    [ "$(stat -c %a "$sock")" = 600 ] && ok agent.socket_mode "the agent's socket is mode 0600" ||
        bad agent.socket_mode "the agent's socket is mode $(stat -c %a "$sock")" "$AG/err"
    [ "$(stat -c %a "$(dirname "$sock")")" = 700 ] && ok agent.dir_mode "its directory is mode 0700" ||
        bad agent.dir_mode "its directory is mode $(stat -c %a "$(dirname "$sock")")" "$AG/err"
    timeout 20 env SSH_AUTH_SOCK="$sock" SSH_ASKPASS="$AG/askpass" SSH_ASKPASS_REQUIRE=force HOME="$W" \
        "$BIN" agent add "$W/id_enc" </dev/null >"$AG/out" 2>"$AG/err2"
    expect_rc agent.add "podssh agent add takes id_enc with its passphrase from SSH_ASKPASS" 0 $? "$AG/err2"
    timeout 20 env SSH_AUTH_SOCK="$sock" ssh-add -l >"$AG/list" 2>&1
    expect_rc agent.list "OpenSSH's ssh-add -l lists the key that podssh agent holds" 0 $? "$AG/list"
    want=$(ssh-keygen -l -f "$W/id_enc.pub" | awk '{print $2}')
    grep -q "$want" "$AG/list" && ok agent.list_key "the key listed is id_enc's ($want)" ||
        bad agent.list_key "ssh-add -l did not list $want" "$AG/list"
    timeout 30 env SSH_AUTH_SOCK="$sock" HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$T" true </dev/null >"$AG/out" 2>"$AG/err3"
    expect_rc agent.login "podssh ssh logs in through podssh agent, with no -i" 0 $? "$AG/err3"
    timeout 30 env SSH_AUTH_SOCK="$sock" HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
        -o BatchMode=yes -A "$T" 'ssh-add -l' </dev/null >"$AG/out" 2>"$AG/err4"
    expect_rc agent.forward "podssh ssh -A forwards podssh agent: ssh-add -l on the server" 0 $? "$AG/err4"
    grep -q "$want" "$AG/out" && ok agent.forward_key "the server sees id_enc ($want) through the forward" ||
        bad agent.forward_key "the forward of podssh agent did not list $want" "$AG/out"

    # T-228: podtest's password, from stdin, kept by the agent. podssh ssh
    # logs in with it under BatchMode with no SSH_ASKPASS, and no argv of
    # the run and no line of -vvv holds it.
    printf '%s\n' "$PW" | timeout 20 env SSH_AUTH_SOCK="$sock" HOME="$W" "$BIN" agent add-password "$T:2201" \
        >"$AG/out" 2>"$AG/err5"
    expect_rc agent.store.add_password "podssh agent add-password takes the password from stdin" 0 $? "$AG/err5"
    rm -f "$AG/rc6"
    (
        timeout 30 env -u SSH_ASKPASS SSH_AUTH_SOCK="$sock" HOME="$W" "$BIN" ssh -vvv --direct -p 2201 \
            -o UserKnownHostsFile="$KH" -o PubkeyAuthentication=no -o BatchMode=yes "$T" 'sleep 2; echo stored-login' \
            </dev/null >"$AG/out" 2>"$AG/err6"
        echo $? >"$AG/rc6"
    ) &
    in_argv=0
    while [ ! -s "$AG/rc6" ]; do
        ps -ef 2>/dev/null | grep -F -- "$PW" | grep -v grep >/dev/null && in_argv=1
        sleep 0.2
    done
    rc=$(cat "$AG/rc6")
    [ "$rc" = 0 ] && [ "$(cat "$AG/out")" = stored-login ] && [ "$in_argv" = 0 ] && ! grep -qF -- "$PW" "$AG/err6" \
        && grep -q "the password for podtest@127.0.0.1:2201 from podssh agent" "$AG/err6" \
        && ok agent.store.password \
            "BatchMode and no SSH_ASKPASS: the password that podssh agent keeps logs in, in no argv and not in -vvv" \
        || bad agent.store.password "the kept password: exit $rc, seen in an argv: $in_argv" "$AG/err6"

    # T-228: id_enc's passphrase, kept by the agent, which then holds no key:
    # podssh ssh -i opens the file with it under BatchMode.
    timeout 20 env SSH_AUTH_SOCK="$sock" HOME="$W" "$BIN" agent remove --all </dev/null >/dev/null 2>&1
    printf 'open sesame\n' | timeout 20 env SSH_AUTH_SOCK="$sock" HOME="$W" "$BIN" agent add-passphrase "$W/id_enc" \
        >"$AG/out" 2>"$AG/err7"
    expect_rc agent.store.add_passphrase "podssh agent add-passphrase takes id_enc's passphrase from stdin" 0 $? \
        "$AG/err7"
    timeout 30 env -u SSH_ASKPASS SSH_AUTH_SOCK="$sock" HOME="$W" "$BIN" ssh -v --direct -p 2201 \
        -o UserKnownHostsFile="$KH" -o BatchMode=yes -o IdentitiesOnly=yes -i "$W/id_enc" "$T" true \
        </dev/null >"$AG/out" 2>"$AG/err8"
    rc=$?
    [ "$rc" = 0 ] && grep -q "the passphrase for $W/id_enc from podssh agent" "$AG/err8" \
        && ok agent.store.passphrase "BatchMode: the passphrase that podssh agent keeps opens id_enc" \
        || bad agent.store.passphrase "the kept passphrase: exit $rc" "$AG/err8"

    # T-284: a key for a confirmation of each use is refused as it is added:
    # nobody can confirm, and russh's agent server would sign with it unasked.
    timeout 20 env SSH_AUTH_SOCK="$sock" ssh-add -c "$W/id_ed25519" </dev/null >"$AG/out" 2>&1
    rc=$?
    confirmed=$(ssh-keygen -l -f "$W/id_ed25519.pub" | awk '{print $2}')
    timeout 20 env SSH_AUTH_SOCK="$sock" ssh-add -l >"$AG/list2" 2>&1
    [ "$rc" != 0 ] && ! grep -q "$confirmed" "$AG/list2" \
        && ok agent.confirm_refused "OpenSSH's ssh-add -c: podssh agent refuses the key, and holds none" \
        || bad agent.confirm_refused "ssh-add -c: exit $rc" "$AG/list2"

    # T-229: the key of a security key of interop-keygen.sh, as OpenSSH's
    # ssh-add gives it (with sk-provider@openssh.com): podssh agent keeps it
    # and ssh-add -l lists it; with no device the agent does not sign, so
    # sshd refuses the signature that stands in, and the login ends with 255.
    timeout 20 env SSH_AUTH_SOCK="$sock" ssh-add "$KG/sk_file" </dev/null >"$AG/out" 2>"$AG/err9"
    expect_rc agent.sk.ssh_add "OpenSSH's ssh-add gives podssh agent a key of a security key" 0 $? "$AG/err9"
    timeout 20 env SSH_AUTH_SOCK="$sock" ssh-add -l >"$AG/list3" 2>&1
    grep -q '(ED25519-SK)' "$AG/list3" && ok agent.sk.listed "ssh-add -l lists the key of a security key" ||
        bad agent.sk.listed "ssh-add -l did not list the key of a security key" "$AG/list3"
    cat "$KG/sk_file.pub" >>"$H/.ssh/authorized_keys"
    # The agent still keeps podtest's password: publickey only.
    timeout 60 env -u SSH_ASKPASS SSH_AUTH_SOCK="$sock" HOME="$W" "$BIN" ssh -v --direct -p 2201 \
        -o UserKnownHostsFile="$KH" -o BatchMode=yes -o PreferredAuthentications=publickey "$T" true \
        </dev/null >"$AG/out" 2>"$AG/err10"
    rc=$?
    [ "$rc" = 255 ] && grep -q "the agent could not sign" "$AG/err10" \
        && ok agent.sk.no_device "the agent's key of a security key and no device: no signature, and 255" \
        || bad agent.sk.no_device "a login through the agent's key of a security key: exit $rc" "$AG/err10"
    timeout 20 env SSH_AUTH_SOCK="$sock" ssh-add -d "$KG/sk_file" </dev/null >"$AG/out" 2>"$AG/err11"
    expect_rc agent.sk.removed "ssh-add -d takes the key of a security key back" 0 $? "$AG/err11"
else
    bad agent.serve "podssh agent did not say SSH_AUTH_SOCK" "$AG/err"
fi
kill "$AGENT_PID" 2>/dev/null
wait "$AGENT_PID" 2>/dev/null
if [ -n "$sock" ] && [ ! -e "$sock" ] && [ ! -e "$(dirname "$sock")" ]; then
    ok agent.kill_cleanup "after a kill, the agent's socket and its directory are gone"
else
    bad agent.kill_cleanup "after a kill, the agent's socket or its directory stayed: $sock" "$AG/err"
fi

echo
echo "== agent forwarding, -A (T-036)"
FA="$W/fwd-agent"
mkdir -p "$FA"
ssh-agent -a "$FA/agent.sock" >"$FA/env" 2>&1
FA_PID=$(sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p' "$FA/env")
timeout 20 env SSH_AUTH_SOCK="$FA/agent.sock" ssh-add "$W/id_rsa" >"$FA/add" 2>&1
expect_rc agent.openssh.add "OpenSSH's ssh-add takes id_rsa into OpenSSH's ssh-agent" 0 $? "$FA/add"
want=$(ssh-keygen -l -f "$W/id_rsa.pub" | awk '{print $2}')
# fa ENV [podssh ssh arguments...]: log in with id_ed25519, never with the
# agent, and list the agent's keys on the server.
fa() {
    _env=$1
    shift
    # shellcheck disable=SC2086
    timeout 30 env $_env HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o IdentitiesOnly=yes -i "$W/id_ed25519" \
        "$@" </dev/null >"$FA/out" 2>"$FA/err"
}
fa "SSH_AUTH_SOCK=$FA/agent.sock" -A "$T" 'ssh-add -l'
expect_rc agent.openssh.forward "with -A, ssh-add -l on the server reaches OpenSSH's agent" 0 $? "$FA/err"
grep -q "$want" "$FA/out" && ok agent.openssh.forward_key "it lists id_rsa ($want)" ||
    bad agent.openssh.forward_key "ssh-add -l did not list $want" "$FA/out"
fa "SSH_AUTH_SOCK=$FA/agent.sock" "$T" 'ssh-add -l'
expect_rc agent.openssh.no_forward "without -A, ssh-add -l on the server finds no agent" 2 $? "$FA/err"
fa "SSH_AUTH_SOCK=$FA/agent.sock" -A -a "$T" 'ssh-add -l'
expect_rc agent.openssh.last_wins "-A -a: the last wins, and the server finds no agent" 2 $? "$FA/err"
fa "-u SSH_AUTH_SOCK" -o ForwardAgent="$FA/agent.sock" "$T" 'ssh-add -l'
expect_rc agent.openssh.forward_path "ForwardAgent=PATH forwards that agent, with no SSH_AUTH_SOCK here" 0 $? "$FA/err"
grep -q "$want" "$FA/out" && ok agent.openssh.forward_path_key "ForwardAgent=PATH: the server lists id_rsa" ||
    bad agent.openssh.forward_path_key "ForwardAgent=PATH: ssh-add -l did not list $want" "$FA/out"
fa "SSH_AUTH_SOCK=$FA/agent.sock" -A -J "$T:2201" "$T" 'ssh-add -l'
expect_rc agent.openssh.jump "with -A and -J, the destination reaches the agent" 0 $? "$FA/err"

# T-279: id_ecdsa, which ssh-add -h keeps for another host (any key stands
# for that host's key). podssh binds the forwarded agent to the host key of
# 2201 (session-bind@openssh.com), so OpenSSH's agent hides id_ecdsa from
# that server; id_rsa, with no limit, it still lists. With no bind, the agent
# takes the connection as local use, and lists both.
printf 'elsewhere.invalid %s\n' "$(cut -d' ' -f1,2 "$W/id_ed25519.pub")" >"$FA/elsewhere_hosts"
timeout 20 env SSH_AUTH_SOCK="$FA/agent.sock" ssh-add -H "$FA/elsewhere_hosts" -h elsewhere.invalid "$W/id_ecdsa" \
    </dev/null >"$FA/add_h" 2>&1
expect_rc agent.openssh.add_h "ssh-add -h elsewhere.invalid takes id_ecdsa for that host only" 0 $? "$FA/add_h"
limited=$(ssh-keygen -l -f "$W/id_ecdsa.pub" | awk '{print $2}')
fa "SSH_AUTH_SOCK=$FA/agent.sock" -A "$T" 'ssh-add -l'
expect_rc agent.openssh.bound "with -A and a limited key, ssh-add -l on the server still lists" 0 $? "$FA/err"
grep -q "$want" "$FA/out" && ! grep -q "$limited" "$FA/out" &&
    ok agent.openssh.bound_key "bound to 2201's host key: the server sees id_rsa, and not id_ecdsa ($limited)" ||
    bad agent.openssh.bound_key "the server listed id_ecdsa ($limited), which ssh-add -h keeps, or not id_rsa" "$FA/out"
kill "$FA_PID" 2>/dev/null
