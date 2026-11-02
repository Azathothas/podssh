#!/bin/sh
# scripts/interop-cgroup.sh - podssh health in containers that a cgroup
# limits (T-480, GitHub #88): OpenSSH's sshd in images/box's Alpine, run by
# the host's engine with --cpus 1.5 --memory 1g, with --cpuset-cpus 0 alone,
# with no limit, and with --cpus 1.5 --memory 1g in the host's cgroup
# namespace (--cgroupns host), where /proc/self/cgroup names the
# container's cgroup by its path in the host's tree. 1.5 CPUs is never a
# host's count, so the quota is always below it, and its line shows a part.
#
#   sh scripts/interop-cgroup.sh PODSSH_BINARY
#
# The checks: effective.cpus 1.5 of the quota and effective.memory_total_kib
# 1048576 of the limit, with this host's CPUs (getconf) as cpus; the lines
# of the limits; 1 CPU of the cpuset; the host's facts with no limit; the
# same limits read at the container's path in the host's namespace. Each
# prints a line of scripts/interop-lib.sh; the exit code is 0 when each
# passed, else 1, and 71 when the host lacks what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), python3, getconf and
# timeout, 2 CPUs or more, and the ports PODSSH_CGROUP_PORT (18460) to
# PODSSH_CGROUP_PORT+3 of the loopback free.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-cgroup.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_CGROUP_PORT:-18460}
NAMES="podssh-cg-limited podssh-cg-cpuset podssh-cg-free podssh-cg-hostns"

die() {
    echo "interop-cgroup: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in python3 getconf timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done
HOST_CPUS=$(getconf _NPROCESSORS_ONLN) || die "getconf gave no count of the CPUs"
[ "$HOST_CPUS" -ge 2 ] || die "this host has $HOST_CPUS CPU: a quota of 1.5 needs 2"

W=$(mktemp -d) || die "no directory for the run"
# Each container on its own: podman's rm stops at a name that is missing.
remove_all() {
    for _c in $NAMES; do
        timeout 60 "$ENGINE" rm -f "$_c" >/dev/null 2>&1
    done
}
cleanup() {
    remove_all
    rm -rf "$W"
}
trap cleanup EXIT INT TERM
remove_all

# image_of DOCKERFILE: the image that its FROM line pins to a digest.
image_of() {
    _ref=$(tr -d '\r' <"$1" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in *@sha256:*) PULL_ENGINE=$ENGINE sh "$HERE/pull-image.sh" "$_ref" ;; *) return 1 ;; esac
}
ALPINE=$(image_of "$REPO/images/box/Dockerfile") || die "Alpine's image did not pull"
mkdir -p "$W/key"
timeout 30 "$BIN" keygen -q -t ed25519 -N '' -f "$W/key/id" >/dev/null 2>&1 || die "podssh keygen failed"
chmod 644 "$W/key/id.pub"

# start NAME PORT [ENGINE FLAGS...]: sshd in Alpine, its port 22 on the
# loopback's PORT, root's key the run's.
start() {
    _name=$1
    _port=$2
    shift 2
    timeout 300 "$ENGINE" run -d --name "$_name" -p "127.0.0.1:$_port:22" "$@" -v "$W/key:/k:ro" "$ALPINE" \
        sh -c 'apk add --no-cache openssh-server >/dev/null && ssh-keygen -A >/dev/null && mkdir -p /root/.ssh &&
        cp /k/id.pub /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys &&
        sed -i "s/^root:[^:]*:/root:*:/" /etc/shadow && exec /usr/sbin/sshd -D -e' >/dev/null ||
        die "$_name did not start"
}
# ready NAME PORT: the container runs and the loopback's PORT gives an SSH
# banner within 300 s: an engine's proxy of a published port takes a TCP
# connection with nobody behind it.
ready() {
    _t0=$(date +%s)
    while :; do
        [ "$(timeout 30 "$ENGINE" inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ] || return 1
        timeout 10 python3 -c 'import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
    s.settimeout(5)
    sys.exit(0 if s.recv(4) == b"SSH-" else 1)
except OSError:
    sys.exit(1)' "$2" && return 0
        [ $(($(date +%s) - _t0)) -lt 300 ] || return 1
        sleep 1
    done
}
# facts NAME PORT [health arguments...]: podssh health of root on PORT, with
# no proxy for the loopback, its outputs in $W/NAME.out and $W/NAME.err.
facts() {
    _n=$1
    _p=$2
    shift 2
    timeout 120 env -u SSH_AUTH_SOCK -u HTTPS_PROXY -u https_proxy -u ALL_PROXY -u all_proxy HOME="$W" \
        PODSSH_SSH_CONFIG=none PODSSH_SETTINGS=none "$BIN" health --direct -p "$_p" -i "$W/key/id" \
        -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$W/kh" -o BatchMode=yes -o IdentityAgent=none \
        -o IdentitiesOnly=yes "$@" root@127.0.0.1 </dev/null >"$W/$_n.out" 2>"$W/$_n.err"
}
# holds FILE EXPR: EXPR of Python holds for the object of FILE (d) and its
# effective facts (e); EXPR is this script's own, never a value of the run.
holds() {
    python3 -c 'import json, sys
d = json.load(open(sys.argv[1]))
e = d.get("effective") or {}
host = int(sys.argv[3])
sys.exit(0 if eval(sys.argv[2]) else 1)' "$1" "$2" "$HOST_CPUS" 2>>"$W/python.err"
}

start podssh-cg-limited "$PORT" --cpus 1.5 --memory 1g
start podssh-cg-cpuset "$((PORT + 1))" --cpuset-cpus 0
start podssh-cg-free "$((PORT + 2))"
start podssh-cg-hostns "$((PORT + 3))" --cgroupns host --cpus 1.5 --memory 1g
n=0
for c in $NAMES; do
    ready "$c" "$((PORT + n))" || { timeout 30 "$ENGINE" logs "$c" 2>&1 | tail -20; die "$c gave no SSH banner"; }
    n=$((n + 1))
done

QUOTA='abs(e["cpus"] - 1.5) < 0.01 and e["cpus_from"] in ("cgroup v2 cpu.max", "cgroup v1 cfs_quota_us")'
LIMIT='e["memory_total_kib"] == 1048576 and e["memory_from"] in ("cgroup v2 memory.max", "cgroup v1 memory.limit_in_bytes")'
ROOM='e["memory_available_kib"] is not None and e["memory_available_kib"] <= 1048576'

facts limited "$PORT" --json
rc=$?
[ "$rc" = 0 ] && holds "$W/limited.out" "d[\"exit\"] == 0 and d[\"cpus\"] == host and $QUOTA and $LIMIT and $ROOM" &&
    ok cgroup.limited "--cpus 1.5 --memory 1g: effective 1.5 CPUs and 1048576 KiB, the host's $HOST_CPUS CPUs in cpus" ||
    bad cgroup.limited "--cpus 1.5 --memory 1g: exit $rc; $(head -c 600 "$W/limited.out")" "$W/limited.err"

facts lines "$PORT"
rc=$?
[ "$rc" = 0 ] && grep -q "^cpus 1.5 (cgroup v[12] [a-z_.]*), $HOST_CPUS on the host\$" "$W/lines.out" &&
    grep -q '^memory .* available of 1.0 GiB ([0-9]* %, cgroup v[12] ' "$W/lines.out" &&
    grep -q ": the whole host's\$" "$W/lines.out" &&
    ok cgroup.lines "the lines of the limits: cpus 1.5, the memory of 1.0 GiB, and the load the whole host's" ||
    bad cgroup.lines "the lines of the limits: exit $rc" "$W/lines.out"

facts cpuset "$((PORT + 1))" --json
rc=$?
[ "$rc" = 0 ] && holds "$W/cpuset.out" 'e["cpus"] == 1 and e["cpus_from"] in ("cgroup v2 cpuset", "cgroup v1 cpuset")' &&
    ok cgroup.cpuset "--cpuset-cpus 0: effective 1 CPU of the cpuset" ||
    bad cgroup.cpuset "--cpuset-cpus 0: exit $rc; $(head -c 600 "$W/cpuset.out")" "$W/cpuset.err"

facts free "$((PORT + 2))" --json
rc=$?
FREE='e["cpus"] == host and e["cpus_from"] == "host" and e["memory_from"] == "host"'
[ "$rc" = 0 ] && holds "$W/free.out" "$FREE and e[\"memory_total_kib\"] == d[\"memory\"][\"total_kib\"]" &&
    ok cgroup.free "no limit: the host's CPUs and memory, from the host" ||
    bad cgroup.free "no limit: exit $rc; $(head -c 600 "$W/free.out")" "$W/free.err"

facts hostns "$((PORT + 3))" --json
rc=$?
DEEP='len(d["cgroup"]["path"].rstrip("/")) > len("/sys/fs/cgroup")'
[ "$rc" = 0 ] && holds "$W/hostns.out" "$QUOTA and $LIMIT and $DEEP" &&
    ok cgroup.hostns "--cgroupns host: the limits read at the container's path in the host's tree" ||
    bad cgroup.hostns "--cgroupns host: exit $rc; $(head -c 600 "$W/hostns.out")" "$W/hostns.err"

[ -s "$W/python.err" ] && sed 's/^/      | /' "$W/python.err" | head -20
echo "interop-cgroup: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
