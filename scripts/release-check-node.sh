# The reverse road and the iroh road of the release check (T-251), sourced
# by scripts/release-check.sh: an OpenSSH server of this host on the
# loopback, a node of the live relay in front of it, and the binary as each
# end. The pair, its tokens and the keys are throwaways of the scratch
# directory; the pair is revoked at the end, also at an early exit.

NODE_PORT=${PODSSH_RC_PORT:-45391}

# A session through the node: ssh_node LOG [ssh arguments...].
ssh_node() {
    _sn_log=$1
    shift
    timeout -k 10 120 $PENV "$W/bin/$PRIMARY" ssh -T -i "$N/id" -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$N/known_hosts" -o BatchMode=yes \
        --pair-file "$N/op.json" "$@" </dev/null >"$_sn_log" 2>&1
}

# copy_node LOG FROM TO: podssh cp through the node, the same options.
copy_node() {
    timed 1800 "$1" $PENV "$W/bin/$PRIMARY" cp --timeout 28m -i "$N/id" -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$N/known_hosts" -o BatchMode=yes \
        --pair-file "$N/op.json" "$2" "$3"
}

# wait_line FILE TEXT SECONDS: 0 once FILE holds TEXT.
wait_line() {
    _wl=0
    while [ "$_wl" -lt "$3" ]; do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 1
        _wl=$((_wl + 1))
    done
    return 1
}

# sshd_up: OpenSSH's server on 127.0.0.1:NODE_PORT for this user, with a
# host key and an authorized key of this run. Sets SSHD_WHY on a failure.
sshd_up() {
    SSHD_WHY=
    _sshd=$(command -v sshd 2>/dev/null)
    [ -n "$_sshd" ] || { [ -x /usr/sbin/sshd ] && _sshd=/usr/sbin/sshd; }
    [ -n "$_sshd" ] || { SSHD_WHY="no sshd here (sh scripts/cloud-setup.sh installs openssh-server)"; return 1; }
    USER_NAME=$(id -un 2>/dev/null)
    [ -n "$USER_NAME" ] || { SSHD_WHY="uid $(id -u) has no name, so no login can name it"; return 1; }
    if command -v ssh-keygen >/dev/null 2>&1; then
        ssh-keygen -q -t ed25519 -N '' -C release-check-host -f "$N/host_key" </dev/null >/dev/null 2>&1
    else
        $PENV "$W/bin/$PRIMARY" keygen -q -t ed25519 -N '' -C release-check-host -f "$N/host_key" </dev/null >/dev/null 2>&1
    fi
    timeout -k 5 60 $PENV "$W/bin/$PRIMARY" keygen -q -t ed25519 -N '' -C release-check -f "$N/id" </dev/null >/dev/null 2>&1
    [ -s "$N/host_key" ] && [ -s "$N/id.pub" ] || { SSHD_WHY="no keys were made"; return 1; }
    cp "$N/id.pub" "$N/authorized_keys"
    cat >"$N/sshd_config" <<EOF
ListenAddress 127.0.0.1
Port $NODE_PORT
HostKey $N/host_key
AuthorizedKeysFile $N/authorized_keys
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PidFile none
Subsystem sftp internal-sftp
EOF
    # The directory of privilege separation, which a server of root needs,
    # its test of the settings too.
    [ "$(id -u)" != 0 ] || mkdir -p /run/sshd
    # OpenSSH 9.8 and later penalise a source of many sessions; older ones
    # do not know the keyword.
    "$_sshd" -t -f "$N/sshd_config" -o PerSourcePenalties=no >/dev/null 2>&1 && echo "PerSourcePenalties no" >>"$N/sshd_config"
    "$_sshd" -t -f "$N/sshd_config" >"$LOGS/sshd.test.log" 2>&1 || { SSHD_WHY="sshd -t refused its settings: $(tail -n 1 "$LOGS/sshd.test.log")"; return 1; }
    timeout -k 5 7200 "$_sshd" -D -e -f "$N/sshd_config" >"$LOGS/sshd.log" 2>&1 &
    echo "$!" >>"$W/pids"
    wait_line "$LOGS/sshd.log" "listening on" 15 || { SSHD_WHY="sshd did not listen within 15 s"; return 1; }
}

# node_up: a pair of the live relay and its node in front of the sshd. Sets
# NODE_WHY on a failure.
node_up() {
    NODE_WHY= NAME=rc$(rand_hex 4)
    timed 60 "$LOGS/pair.log" $PENV "$W/bin/$PRIMARY" relay pair "$NAME" --operator-file "$N/op.json"
    [ "$RC" = 0 ] || { NODE_WHY="relay pair: $(why): $(tail -n 1 "$LOGS/pair.log")"; return 1; }
    echo "$W/bin/$PRIMARY $NAME" >>"$W/pairs"
    timeout -k 10 7200 $PENV "$W/bin/$PRIMARY" node "$NAME" "127.0.0.1:$NODE_PORT" </dev/null >/dev/null 2>"$LOGS/node.log" &
    NODE_PID=$!
    echo "$NODE_PID" >>"$W/pids"
    wait_line "$LOGS/node.log" "serving" 60 || { NODE_WHY="the node said no 'serving' within 60 s: $(tail -n 1 "$LOGS/node.log")"; return 1; }
}

# c_reverse_two: one session, which records the host key, then two at once.
c_reverse_two() {
    _t0=$(date +%s)
    ssh_node "$LOGS/reverse.0.log" "node://$USER_NAME@$NAME" 'exit 3'
    _r0=$?
    ssh_node "$LOGS/reverse.1.log" "node://$USER_NAME@$NAME" 'exit 3' &
    _p1=$!
    ssh_node "$LOGS/reverse.2.log" "node://$USER_NAME@$NAME" 'exit 3' &
    _p2=$!
    wait "$_p1"
    _r1=$?
    wait "$_p2"
    _r2=$?
    _secs=$(($(date +%s) - _t0))
    if [ "$_r0/$_r1/$_r2" = 3/3/3 ]; then
        row PASS reverse.two "$PRIMARY" "$_secs" "exit 3 alone, then 3 and 3 at once, through the node of $NAME"
    else
        row FAIL reverse.two "$PRIMARY" "$_secs" "exits $_r0, then $_r1 and $_r2 at once; wanted 3 each"
        show "$LOGS/reverse.1.log"
        show "$LOGS/node.log"
    fi
}

# c_cp: 200 MiB up and down through the node, more than the relay's 64 MiB
# of a session (T-137, T-155), with the digests of both ends.
c_cp() {
    mkdir -p "$N/far"
    head -c 209715200 /dev/urandom >"$N/big"
    _want=$(digest "$N/big")
    copy_node "$LOGS/cp.up.log" "$N/big" "node://$USER_NAME@$NAME:$N/far/up.bin"
    _rup=$RC _sup=$SECS
    copy_node "$LOGS/cp.down.log" "node://$USER_NAME@$NAME:$N/big" "$N/down.bin"
    _rdown=$RC _sdown=$SECS
    _dup=$(digest "$N/far/up.bin") _ddown=$(digest "$N/down.bin")
    if [ "$_rup/$_rdown" = 0/0 ] && [ "$_dup" = "$_want" ] && [ "$_ddown" = "$_want" ]; then
        row PASS cp.200mib "$PRIMARY" "$((_sup + _sdown))" "200 MiB up in $_sup s, down in $_sdown s, sha256 equal at both ends"
    else
        row FAIL cp.200mib "$PRIMARY" "$((_sup + _sdown))" "up: exit $_rup, sha256 equal: $([ "$_dup" = "$_want" ] && echo yes || echo no); down: exit $_rdown, equal: $([ "$_ddown" = "$_want" ] && echo yes || echo no)"
        show "$LOGS/cp.up.log"
        show "$LOGS/cp.down.log"
    fi
    rm -f "$N/big" "$N/far/up.bin" "$N/down.bin"
}

# c_iroh: a node of the iroh road alone, through n0's relays (Q50): the
# client's key is refused and named, then the node's allowlist takes it.
c_iroh() {
    _t0=$(date +%s)
    printf '# the client keys of the release check\n' >"$N/allow"
    timeout -k 10 900 $PENV "$W/bin/$PRIMARY" node "${NAME:-rc$(rand_hex 4)}i" "127.0.0.1:$NODE_PORT" --iroh \
        --iroh-allow "$N/allow" --iroh-key "$N/iroh_node.key" </dev/null >/dev/null 2>"$LOGS/iroh.node.log" &
    echo "$!" >>"$W/pids"
    if ! wait_line "$LOGS/iroh.node.log" "ticket iroh:" 90; then
        row FAIL iroh.n0 "$PRIMARY" "$(($(date +%s) - _t0))" "the node said no ticket within 90 s"
        show "$LOGS/iroh.node.log"
        return
    fi
    _ticket=$(grep 'ticket iroh:' "$LOGS/iroh.node.log" | head -n 1 | sed 's/.*\(iroh:[^[:space:]]*\).*/\1/')
    _ssh="ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$N/known_iroh -i $N/id"
    # shellcheck disable=SC2086  # the options, with no space in a value
    timed 120 "$LOGS/iroh.refused.log" $PENV "$W/bin/$PRIMARY" $_ssh -o IdentitiesOnly=yes \
        --iroh-key "$N/iroh_client.key" "$USER_NAME@$_ticket" 'exit 3'
    _r1=$RC
    _key=$(sed -n "s/.*refused this client's key \(SHA256:[A-Za-z0-9+/]\{43\}\).*/\1/p" "$LOGS/iroh.refused.log" | head -n 1)
    [ -z "$_key" ] || printf '%s the release check\n' "$_key" >>"$N/allow"
    sleep 1
    # shellcheck disable=SC2086
    timed 120 "$LOGS/iroh.log" $PENV "$W/bin/$PRIMARY" $_ssh -o IdentitiesOnly=yes \
        --iroh-key "$N/iroh_client.key" "$USER_NAME@$_ticket" 'exit 3'
    _r2=$RC
    if [ "$_r1" = 255 ] && [ -n "$_key" ] && [ "$_r2" = 3 ]; then
        row PASS iroh.n0 "$PRIMARY" "$(($(date +%s) - _t0))" "refused (255) and named, then let in: exit 3"
    else
        row FAIL iroh.n0 "$PRIMARY" "$(($(date +%s) - _t0))" "first exit $_r1, key named: ${_key:+yes}; then exit $_r2; wanted 255, yes, 3"
        show "$LOGS/iroh.log"
        show "$LOGS/iroh.node.log"
    fi
}

checks_node() {
    _want_node=
    for _id in reverse.two cp.200mib iroh.n0; do wanted "$_id" && _want_node=1; done
    [ -n "$_want_node" ] || return 0
    N=$W/node
    mkdir -p "$N"
    if ! sshd_up; then
        for _id in reverse.two cp.200mib iroh.n0; do
            wanted "$_id" && row FAIL "$_id" "$PRIMARY" 0 "$SSHD_WHY"
        done
        return 0
    fi
    if { wanted reverse.two || wanted cp.200mib; } && ! node_up; then
        for _id in reverse.two cp.200mib; do
            wanted "$_id" && row FAIL "$_id" "$PRIMARY" 0 "$NODE_WHY"
        done
        show "$LOGS/node.log"
    elif wanted reverse.two || wanted cp.200mib; then
        wanted reverse.two && c_reverse_two
        wanted cp.200mib && c_cp
        # The node ends on SIGTERM, and the pair goes with the scratch.
        kill "$NODE_PID" 2>/dev/null
        wait "$NODE_PID" 2>/dev/null
    fi
    wanted iroh.n0 && c_iroh
    return 0
}
