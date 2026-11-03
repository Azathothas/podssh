# podssh health (T-189) against OpenSSH on port 2201 and Dropbear on port
# 2203: the facts as one JSON object, whose available memory is within 5 %
# of MemAvailable read over exec just after and nearer it than MemFree (the
# planted defect, MemFree in its place, fails it), and one line for each
# fact. Its effective CPUs and memory (T-480) agree with what
# scripts/cgroup-effective.py reads of the cgroup that a session of the
# same server runs in, as cat /proc/self/cgroup names it there: the servers
# run in the gate's own container, whose view of /sys/fs/cgroup this shell
# shares; the limits of a container of their own are interop-cgroup.sh's.
# With --preflight (T-482): OpenSSH as it is allows each probe, and OpenSSH
# with AllowTcpForwarding no and Dropbear with -j -k refuse both forwards,
# each a FAIL that names what it stops, with exit 1.
# Sourced by scripts/interop-each.sh, the harness of the commands on other
# hosts, as scripts/interop.sh has no line to spare; uses ok, bad, p,
# sshd_conf, $BIN, $W, $K, $T and $KH.

echo
echo "== podssh health (T-189, T-480, OpenSSH, then Dropbear)"
HW="$W/health"
mkdir -p "$HW"
# health_of PORT [podssh health arguments...]: podssh health as p() runs ssh.
health_of() {
    _port=$1
    shift
    # shellcheck disable=SC2086
    timeout 120 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" health --direct -p "$_port" -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K "$@" </dev/null
}
for srv in openssh:2201 dropbear:2203; do
    port=${srv#*:}
    health_of "$port" --json "$T" >"$HW/facts.json" 2>"$HW/err"
    rc=$?
    # shellcheck disable=SC2086
    p "$port" $K -o BatchMode=yes "$T" 'cat /proc/meminfo' </dev/null >"$HW/meminfo" 2>>"$HW/err"
    # Within 5 % of MemAvailable, and nearer it than MemFree: on a host with
    # little cache MemFree is within 5 % too, and the planted defect passed.
    [ "$rc" = 0 ] && python3 -c 'import json, sys
d = json.load(open(sys.argv[1]))
info = {l.split(":")[0]: int(l.split()[1]) for l in open(sys.argv[2]) if l.split(":")[0] in ("MemAvailable", "MemFree")}
real, free = info["MemAvailable"], info["MemFree"]
got = d["memory"]["available_kib"]
near = abs(got - real) <= real * 0.05
apart = abs(got - real) < abs(got - free) or abs(real - free) < 16384
sys.exit(0 if d["exit"] == 0 and not d["memory"]["available_estimated"] and near and apart else 1)' \
        "$HW/facts.json" "$HW/meminfo" 2>>"$HW/err" \
        && ok "health.${srv%%:*}.memory" "port $port: --json, and the available memory is MemAvailable, not MemFree" \
        || bad "health.${srv%%:*}.memory" "port $port: exit $rc; $(head -c 300 "$HW/facts.json")" "$HW/err"
    # shellcheck disable=SC2086
    p "$port" $K -o BatchMode=yes "$T" 'cat /proc/self/cgroup' </dev/null >"$HW/self-cgroup" 2>>"$HW/err"
    [ "$rc" = 0 ] && python3 "$HERE/cgroup-effective.py" "$HW/facts.json" "$HW/self-cgroup" 2>>"$HW/err" \
        && ok "health.${srv%%:*}.effective" "port $port: the effective CPUs and memory are those of the session's cgroup" \
        || bad "health.${srv%%:*}.effective" "port $port: exit $rc; $(head -c 300 "$HW/self-cgroup")" "$HW/err"
    health_of "$port" "$T" >"$HW/out" 2>"$HW/err"
    rc=$?
    # A load line names the CPUs, and where a cgroup limits, whose they are.
    [ "$rc" = 0 ] && grep -q '^load .* CPUs' "$HW/out" && grep -q '^memory .* available of ' "$HW/out" \
        && grep -q '^disk /: ' "$HW/out" && grep -q '^processes [0-9][0-9]*$' "$HW/out" \
        && ok "health.${srv%%:*}.lines" "port $port: one line for each fact, the root's disk among them" \
        || bad "health.${srv%%:*}.lines" "port $port: exit $rc" "$HW/out"
done

echo
echo "== podssh health --preflight (T-482, OpenSSH, then the two that refuse forwards)"
# 2202 is OpenSSH as it is: the PermitListen of 2201 refuses a forward of
# port 0. sshd takes the first value of a keyword, so 2217's is replaced.
sshd_conf 2217 "KbdInteractiveAuthentication no"
sed -i 's/^AllowTcpForwarding yes$/AllowTcpForwarding no/' "$W/sshd-2217.conf"
/usr/sbin/sshd -f "$W/sshd-2217.conf" -E "$W/sshd-2217.log" || cat "$W/sshd-2217.log"
dropbear -p 127.0.0.1:2218 -r "$W/dropbear_ed25519" -P "$W/dropbear-2218.pid" -j -k 2>"$W/dropbear-2218.log" \
    || cat "$W/dropbear-2218.log"
python3 -c 'import socket, time
for port in (2217, 2218):
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 1).close()
            break
        except OSError:
            time.sleep(0.1)'
health_of 2202 --preflight "$T" >"$HW/pre-2202" 2>"$HW/err"
rc=$?
[ "$rc" = 0 ] && grep -q '^  ok    remote forward .*-R works on this host$' "$HW/pre-2202" \
    && grep -q '^  ok    jump  .*through this host work$' "$HW/pre-2202" \
    && grep -q '^  ok    keepalive  ' "$HW/pre-2202" && grep -q '^9 ok, 0 FAIL, 0 ???? ' "$HW/pre-2202" \
    && ok health.preflight.openssh "port 2202: --preflight, each check ok, both forwards and the keepalive among them" \
    || bad health.preflight.openssh "port 2202: exit $rc" "$HW/pre-2202"
for srv in noforward:2217 dropbear:2218; do
    port=${srv#*:}
    health_of "$port" --preflight "$T" >"$HW/pre-$port" 2>"$HW/err"
    rc=$?
    [ "$rc" = 1 ] && grep -q '^  FAIL  remote forward .*-R cannot work on this host$' "$HW/pre-$port" \
        && grep -q '^  FAIL  jump  .*through this host cannot work$' "$HW/pre-$port" \
        && grep -q '^7 ok, 2 FAIL, 0 ???? ' "$HW/pre-$port" \
        && ok "health.preflight.${srv%%:*}" "port $port: --preflight, both forwards FAIL with what they stop, exit 1" \
        || bad "health.preflight.${srv%%:*}" "port $port: exit $rc" "$HW/pre-$port"
done
kill "$(cat "$W/sshd-2217.pid")" "$(cat "$W/dropbear-2218.pid")" 2>/dev/null
