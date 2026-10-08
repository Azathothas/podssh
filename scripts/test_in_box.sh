#!/bin/sh
# Build a box like the target sandbox with Podman, check the box against
# the operator's sandprobe report (scripts/box/probe.sh), then measure podssh
# inside it (scripts/sandbox-check.sh).
#
#   sh scripts/test_in_box.sh [PODSSH_LINUX_BINARY]
#
# The binary is a static Linux build (default:
# target/x86_64-unknown-linux-musl/release/podssh, or one from the release
# workflow). Needs podman; on Windows, a running podman machine. Works from
# Git Bash on Windows and from a Linux shell.
#
# The box: an internal network with no route out; one HTTP CONNECT proxy
# (scripts/box/proxy.py) that allows ports 443, 80 and 8443 to public hosts
# only, the only way out; a resolver that is listed and never answers; no
# capabilities and no_new_privs; a seccomp filter that refuses bind and UDP
# (scripts/box/seccomp.json); no /dev/ptmx; uid 0 with no user database
# entry. It does not reproduce the sandbox's EACCES on connect() to some
# ports and to loopback (a Landlock-like rule); the probe says so.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
BIN=${1:-$REPO/target/x86_64-unknown-linux-musl/release/podssh}
NET=podssh-box-net
PROXY=podssh-box-proxy
BOX=podssh-box
IMAGE=localhost/podssh-box:2
BASE_IMAGE=docker.io/library/alpine:3.20
PROXY_IMAGE=docker.io/library/python:3.12-alpine
PORT=45331

die() {
    echo "test_in_box: $*" >&2
    exit 1
}
command -v podman >/dev/null 2>&1 || die "podman is not on PATH"
command -v timeout >/dev/null 2>&1 || die "timeout is not on PATH: every wait here needs a bound"
[ -f "$BIN" ] || die "no podssh binary at $BIN; give a static Linux build as the first argument"
timeout 60 podman info >/dev/null 2>&1 || die "podman does not answer (on Windows: podman machine start)"

# Git Bash must not rewrite container paths such as /box, and podman on
# Windows takes Windows paths for what it mounts.
MSYS2_ARG_CONV_EXCL='*'
export MSYS2_ARG_CONV_EXCL
hostpath() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

remove() {
    podman rm -f "$BOX" "$PROXY" >/dev/null 2>&1
    podman network rm -f "$NET" >/dev/null 2>&1
}
WORK=$(mktemp -d 2>/dev/null || echo "/tmp/podssh-box-$$")
mkdir -p "$WORK"
trap 'remove; rm -rf "$WORK"' EXIT
remove

echo "== the box image: Alpine with OpenSSH's client (the sandbox had one) and curl (for the probe)"
printf 'FROM %s\nRUN apk add --no-cache openssh-client curl\n' "$BASE_IMAGE" >"$WORK/Containerfile"
timeout 900 podman build -q -t "$IMAGE" -f "$(hostpath "$WORK/Containerfile")" "$(hostpath "$WORK")" >"$WORK/build.log" 2>&1
rc=$?
[ "$rc" = 0 ] || { cat "$WORK/build.log"; die "the box image did not build (exit $rc)"; }

echo "== the network: internal, so the box has no route out"
# No DNS server of its own either: musl takes that server's quick "no such
# name" for outside names, which broke the proxy's resolution (measured).
podman network create --internal --disable-dns "$NET" >/dev/null || die "could not create the network $NET"

echo "== the proxy: the only way out"
timeout 600 podman run -d --name "$PROXY" --network podman --network "$NET"     --dns 1.1.1.1 --dns 8.8.8.8 \
    --mount "type=bind,source=$(hostpath "$HERE/box"),target=/box,readonly" \
    "$PROXY_IMAGE" python3 /box/proxy.py --listen "0.0.0.0:$PORT" >/dev/null || die "the proxy did not start"
tries=0
until podman logs "$PROXY" 2>&1 | grep -q '^listening'; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || { podman logs "$PROXY"; die "the proxy did not listen within 30 s"; }
    sleep 1
done
PIP=$(podman inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$PROXY")
[ -n "$PIP" ] || die "the proxy has no address on $NET"
echo "proxy at $PIP:$PORT"

# An empty user and group database: uid 0 gets no name, as in the sandbox.
: >"$WORK/empty"

echo "== in the box"
timeout 1800 podman run --rm --name "$BOX" --network "$NET" \
    --dns 1.1.1.1 --dns 8.8.8.8 --dns 9.9.9.9 --dns-option timeout:1 --dns-option attempts:2 \
    --cap-drop all --security-opt no-new-privileges \
    --security-opt "seccomp=$(hostpath "$HERE/box/seccomp.json")" \
    --security-opt mask=/dev/pts \
    --mount "type=bind,source=$(hostpath "$WORK/empty"),target=/etc/passwd,readonly" \
    --mount "type=bind,source=$(hostpath "$WORK/empty"),target=/etc/group,readonly" \
    --mount "type=bind,source=$(hostpath "$BIN"),target=/in/podssh,readonly" \
    --mount "type=bind,source=$(hostpath "$HERE"),target=/scripts,readonly" \
    --tmpfs /state/home:rw,exec,mode=1777 \
    -e HOME=/state/home -e TERM=xterm \
    -e HTTPS_PROXY="http://$PIP:$PORT" -e https_proxy="http://$PIP:$PORT" \
    -e NO_PROXY="$PIP" -e no_proxy="$PIP" \
    "$IMAGE" sh -c 'install -m 755 /in/podssh /usr/local/bin/podssh &&
        sh /scripts/box/probe.sh && sh /scripts/sandbox-check.sh /usr/local/bin/podssh'
rc=$?

echo
echo "== the proxy's log: every connection it was asked for"
podman logs "$PROXY" 2>&1 | grep -v '^listening' | tail -60
echo
echo "test_in_box: exit $rc"
exit "$rc"
