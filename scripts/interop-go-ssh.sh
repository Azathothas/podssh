#!/bin/sh
# scripts/interop-go-ssh.sh - podssh ssh against a server of Go's
# x/crypto/ssh, the library under gliderlabs/ssh (T-460, GitHub #83 and
# #85), whose replies to a global request carry data after their type: RFC
# 4254, section 4, lets a success carry "response specific data", and Go's
# Request.Reply(false, payload) puts data in a failure too. russh 0.65.0
# ended the whole connection on either; vendor/russh carries the patch that
# drops such data (vendor/patches/russh/).
#
#   sh scripts/interop-go-ssh.sh PODSSH_BINARY
#
# The stand-in, scripts/interop-go-ssh/main.go, is built in images/derper's
# Go against x/crypto at a pinned release, with Go's check of each module
# against its checksum database, and runs on images/box's Alpine, its port
# published on the loopback. It refuses tcpip-forward with the words of
# gliderlabs/ssh (27 bytes), and answers each other global request with 15
# bytes after a failure (the case of #83: a keepalive that the server does
# not know) or after a success; it logs each reply. Four servers, one for
# each session that waits: a failure or a success, each with the default
# keepalive (60 s) and with one each 20 s.
#
# The checks: each server's banner is Go's; a command runs; `sleep 100; echo
# alive` prints alive and exits 0 with each server, its keepalives answered
# with data, as the server's log shows (#83); -N -R that the server refuses
# warns, names no lost connection, and goes on (#85); with
# ExitOnForwardFailure=yes it ends with 255 and the refusal's words. Each
# prints a line of scripts/interop-lib.sh; the exit code is 0 when each
# passed, else 1, and 71 when the host lacks what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), python3 and timeout; the
# ports PODSSH_GO_SSH_PORT (18470) to PODSSH_GO_SSH_PORT+3 of the loopback
# free. The build fetches Go's modules: on a host whose containers reach them
# only through the host's own proxy (a cloud session's),
# PODSSH_GO_SSH_BUILD_NET=host and PODSSH_GO_SSH_BUILD_CA=FILE (that proxy's
# CA) give the build that proxy, from HTTPS_PROXY.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-go-ssh.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_GO_SSH_PORT:-18470}
SERVERS="failure-default failure-interval success-default success-interval"
NAMES="podssh-gossh-build podssh-gossh-failure-default podssh-gossh-failure-interval"
NAMES="$NAMES podssh-gossh-success-default podssh-gossh-success-interval"
# x/crypto's last release, read on 2026-11-02 through proxy.golang.org
# (2026-10-09); its go.mod asks for Go 1.26, below images/derper's 1.27.
XCRYPTO=v0.58.0

die() {
    echo "interop-go-ssh: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in python3 timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done

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
GO=$(image_of "$REPO/images/derper/Dockerfile") || die "Go's image did not pull"

# The stand-in, built first and in the open, so that a failure says why;
# the binary comes out by the engine's cp, as the run's user.
mkdir -p "$W/src" "$W/bin" "$W/home"
cp "$HERE/interop-go-ssh/main.go" "$W/src/main.go" || die "scripts/interop-go-ssh/main.go cannot be read"
chmod 644 "$W/src/main.go"
BUILD_NET=${PODSSH_GO_SSH_BUILD_NET:-}
BUILD_CA=${PODSSH_GO_SSH_BUILD_CA:-}
set -- -e CGO_ENABLED=0 -e GOFLAGS=-p=4 -v "$W/src:/in:ro"
[ -n "$BUILD_NET" ] && set -- "$@" --network "$BUILD_NET" -e HTTPS_PROXY -e https_proxy -e NO_PROXY -e no_proxy
[ -n "$BUILD_CA" ] && set -- "$@" -e SSL_CERT_FILE=/build-ca.pem -v "$BUILD_CA:/build-ca.pem:ro"
timeout 900 "$ENGINE" run --name podssh-gossh-build "$@" "$GO" sh -c "mkdir /src && cd /src && cp /in/main.go . &&
    go mod init podssh.test/gossh && go get golang.org/x/crypto@$XCRYPTO && go mod tidy &&
    grep -q 'golang.org/x/crypto $XCRYPTO' go.mod && go build -o /gossh ." >"$W/build.log" 2>&1 ||
    die "the stand-in did not build against x/crypto $XCRYPTO: $(tail -5 "$W/build.log")"
timeout 60 "$ENGINE" cp podssh-gossh-build:/gossh "$W/bin/gossh" >/dev/null || die "the engine gave no copy of the stand-in"
chmod 755 "$W/bin/gossh"
timeout 60 "$ENGINE" rm -f podssh-gossh-build >/dev/null 2>&1

# port_of SERVER: its port on the loopback.
port_of() {
    _i=0
    for _s in $SERVERS; do
        [ "$_s" = "$1" ] && { echo $((PORT + _i)); return 0; }
        _i=$((_i + 1))
    done
    return 1
}
for s in $SERVERS; do
    timeout 300 "$ENGINE" run -d --name "podssh-gossh-$s" -p "127.0.0.1:$(port_of "$s"):2222" -v "$W/bin:/w:ro" \
        "$ALPINE" /w/gossh -listen 0.0.0.0:2222 -reply "${s%%-*}" >/dev/null || die "the server $s did not start"
done

# banner PORT SECONDS: the server's first line, once it answers within
# SECONDS. A TCP connection alone proves nothing: an engine's own proxy of a
# published port takes it with nobody behind.
banner() {
    timeout $(($2 + 10)) python3 -c 'import socket, sys, time
port, until = int(sys.argv[1]), time.time() + int(sys.argv[2])
while time.time() < until:
    try:
        s = socket.create_connection(("127.0.0.1", port), 5)
        s.settimeout(5)
        line = s.makefile("rb").readline(256)
        if line:
            print(line.decode(errors="replace").strip())
            sys.exit(0)
    except OSError:
        pass
    time.sleep(1)
sys.exit(1)' "$1" "$2"
}
seen=
for s in $SERVERS; do
    b=$(banner "$(port_of "$s")" 120)
    case $b in SSH-2.0-Go*) seen="$seen $s" ;; esac
done
[ "$seen" = " $SERVERS" ] && ok go-ssh.banner "each of the four servers says Go's banner (SSH-2.0-Go)" ||
    bad go-ssh.banner "Go's banner from$seen alone"

# alone: podssh's environment, in a subshell: no configuration, no agent,
# no proxy, and a known_hosts of the run.
alone() {
    unset HTTPS_PROXY https_proxy ALL_PROXY all_proxy SSH_AUTH_SOCK
    export PODSSH_SSH_CONFIG=none PODSSH_SETTINGS=none HOME="$W/home" USERPROFILE="$W/home"
}
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$W/home/known_hosts"
# p PORT ARGS...: podssh ssh to the server on PORT, within 200 s.
p() {
    _port=$1
    shift
    # shellcheck disable=SC2086  # the options are words
    (alone && exec timeout 200 "$BIN" ssh --direct -p "$_port" $SSH_OPTS "$@")
}
# replies SERVER: how many keepalives its log says it answered with data.
replies() {
    timeout 30 "$ENGINE" logs "podssh-gossh-$1" 2>&1 | grep -c 'global request keepalive@openssh.com: replied .* with 15 bytes'
}

echo
echo "== podssh ssh against Go's x/crypto/ssh $XCRYPTO (T-460)"

p "$(port_of failure-default)" u@127.0.0.1 'echo through-go' </dev/null >"$W/command.out" 2>"$W/command.err"
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/command.out")" = through-go ] &&
    ok go-ssh.command "a command through the stand-in of x/crypto/ssh" ||
    bad go-ssh.command "a command: exit $rc" "$W/command.err"

# The four quiet sessions at once, each 100 s with no byte: the default
# keepalive goes out at 60 s, the other each 20 s. Each code is read in its
# own subshell, and kept in a file.
quiet() {
    _opts=
    [ "${1#*-}" = interval ] && _opts="-o ServerAliveInterval=20"
    # shellcheck disable=SC2086  # the options are words
    p "$(port_of "$1")" $_opts u@127.0.0.1 'sleep 100; echo alive' </dev/null >"$W/quiet-$1.out" 2>"$W/quiet-$1.err"
    echo $? >"$W/quiet-$1.rc"
}
for s in $SERVERS; do
    quiet "$s" &
done
wait
for mode in failure success; do
    for keep in default interval; do
        s=$mode-$keep
        rc=$(cat "$W/quiet-$s.rc" 2>/dev/null)
        n=$(replies "$s")
        want=1
        [ "$keep" = interval ] && want=3
        [ "$rc" = 0 ] && [ "$(cat "$W/quiet-$s.out")" = alive ] && [ "${n:-0}" -ge "$want" ] &&
            ok "go-ssh.quiet.${mode}.${keep}" "a quiet session lived 100 s; $n keepalives answered with a $mode and 15 bytes" ||
            bad "go-ssh.quiet.${mode}.${keep}" "a quiet session: exit $rc, ${n:-0} keepalives answered" "$W/quiet-$s.err"
    done
done

# -N -R that the server refuses with words (#85): a warning, and the wait
# of -N goes on.
# Its own subshell execs timeout, so that $! is the process to stop.
FD=$(port_of failure-default)
# shellcheck disable=SC2086  # the options are words
(alone && exec timeout 200 "$BIN" ssh --direct -p "$FD" $SSH_OPTS -N -R 12345:127.0.0.1:9 u@127.0.0.1) \
    </dev/null >"$W/warn.out" 2>"$W/warn.err" &
fpid=$!
sleep 8
up=no
kill -0 "$fpid" 2>/dev/null && up=yes
kill "$fpid" 2>/dev/null
wait "$fpid" 2>/dev/null
refused=$(timeout 30 "$ENGINE" logs podssh-gossh-failure-default 2>&1 | grep -c 'global request tcpip-forward: replied false with 27 bytes')
[ "$up" = yes ] && grep -q 'Warning: remote port forwarding failed for listen port 12345' "$W/warn.err" &&
    ! grep -q 'was lost' "$W/warn.err" && [ "${refused:-0}" -ge 1 ] &&
    ok go-ssh.forward.warn "-R refused with the words of gliderlabs/ssh: a warning, and -N goes on" ||
    bad go-ssh.forward.warn "-R refused: still up after 8 s: $up; $refused refusals in the server's log" "$W/warn.err"

p "$FD" -N -o ExitOnForwardFailure=yes -R 12345:127.0.0.1:9 u@127.0.0.1 </dev/null >"$W/exit.out" 2>"$W/exit.err"
rc=$?
[ "$rc" = 255 ] && grep -q 'Error: remote port forwarding failed for listen port 12345' "$W/exit.err" &&
    ! grep -q 'was lost' "$W/exit.err" &&
    ok go-ssh.forward.exit "-R refused, with ExitOnForwardFailure=yes: 255 and the refusal's words" ||
    bad go-ssh.forward.exit "-R refused, with ExitOnForwardFailure=yes: exit $rc" "$W/exit.err"

echo "interop-go-ssh: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
