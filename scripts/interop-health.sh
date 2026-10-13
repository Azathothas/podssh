# podssh health (T-189) against OpenSSH on port 2201 and Dropbear on port
# 2203: the facts as one JSON object, whose available memory is within 5 %
# of MemAvailable read over exec just after and nearer it than MemFree (the
# planted defect, MemFree in its place, fails it), and one line for each
# fact. Sourced by scripts/interop-each.sh, the harness of the commands on
# other hosts, as scripts/interop.sh has no line to spare; uses ok, bad, p,
# $BIN, $W, $K, $T and $KH.

echo
echo "== podssh health (T-189, OpenSSH, then Dropbear)"
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
    health_of "$port" "$T" >"$HW/out" 2>"$HW/err"
    rc=$?
    [ "$rc" = 0 ] && grep -q '^load .* CPUs$' "$HW/out" && grep -q '^memory .* available of ' "$HW/out" \
        && grep -q '^disk /: ' "$HW/out" && grep -q '^processes [0-9][0-9]*$' "$HW/out" \
        && ok "health.${srv%%:*}.lines" "port $port: one line for each fact, the root's disk among them" \
        || bad "health.${srv%%:*}.lines" "port $port: exit $rc" "$HW/out"
done
