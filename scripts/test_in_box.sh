#!/bin/sh
# Build a box like the target sandbox with Podman, check the box against
# the operator's sandprobe report (scripts/box/probe.sh), then measure podssh
# inside it (scripts/sandbox-check.sh).
#
#   sh scripts/test_in_box.sh [PODSSH_LINUX_BINARY]
#   BOX_RUN=tt sh scripts/test_in_box.sh [PODSSH_LINUX_BINARY]
#
# BOX_RUN=tt runs scripts/box/tt-session.sh in place of sandbox-check.sh: an
# interactive session over -tt (T-004) against OpenSSH in a container next
# to the box, reached with --direct through the box's proxy, which lets that
# one target through.
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
# (scripts/box/seccomp.json); no /dev/ptmx; a /dev/tty that opens and never
# answers (scripts/box/deadtty.py); uid 0 with no user database entry. It
# does not reproduce the sandbox's EACCES on connect() to some ports and to
# loopback (a Landlock-like rule); the probe says so.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# The image that a Dockerfile of .github/images/ names on its FROM line: the
# one place that names it, pinned to a digest. A CR is dropped, as a checkout
# on Windows can add one.
image_of() {
    _ref=$(tr -d '\r' <"$1" 2>/dev/null | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in
        *@sha256:*) printf '%s\n' "$_ref" ;;
        *)
            echo "podssh: $1 names no image pinned to a digest" >&2
            return 1
            ;;
    esac
}
BIN=${1:-$REPO/target/x86_64-unknown-linux-musl/release/podssh}
NET=podssh-box-net
PROXY=podssh-box-proxy
BOX=podssh-box
TARGET=podssh-box-target
RUN=${BOX_RUN:-check}
case $RUN in check | tt) ;; *) echo "test_in_box: BOX_RUN is check or tt, not $RUN" >&2; exit 1 ;; esac
IMAGE=localhost/podssh-box:2
BASE_IMAGE=$(image_of "$REPO/.github/images/box/Dockerfile") || exit 78
PROXY_IMAGE=$(image_of "$REPO/.github/images/box-proxy/Dockerfile") || exit 78
PORT=45331

die() {
    echo "test_in_box: $*" >&2
    exit 1
}
command -v podman >/dev/null 2>&1 || die "podman is not on PATH"
command -v timeout >/dev/null 2>&1 || die "timeout is not on PATH: every wait here needs a bound"
[ -f "$BIN" ] || die "no podssh binary at $BIN; give a static Linux build as the first argument"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

# Git Bash must not rewrite container paths such as /box, and podman on
# Windows takes Windows paths for what it mounts.
MSYS2_ARG_CONV_EXCL='*'
export MSYS2_ARG_CONV_EXCL
hostpath() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# podman runs from a work directory of its own: on Windows, its ssh link to
# the podman machine writes the machine's host key to a file named NUL in the
# current directory (measured), which must not be left in the caller's tree.
# The trap leaves the directory first: Windows does not remove a directory
# that a process has as its current one.
WORK=$(mktemp -d 2>/dev/null || echo "/tmp/podssh-box-$$")
{ mkdir -p "$WORK" && cd "$WORK"; } || die "cannot use the work directory $WORK"
trap 'cd /; rm -rf "$WORK"' EXIT
timeout 60 podman info >/dev/null 2>&1 || die "podman does not answer (on Windows: podman machine start)"

# The box's mounts are resolved on the podman host: the podman machine when
# the podman service is remote (Windows, macOS), else this host. The dead
# terminal must be made there.
if [ "$(timeout 60 podman info --format '{{.Host.ServiceIsRemote}}' 2>/dev/null)" = true ]; then
    on_host() { timeout 60 podman machine ssh "$1"; }
else
    on_host() { timeout 60 sh -c "$1"; }
fi
TTYFILE=/tmp/podssh-box-tty.$$
TTY_STARTED=0

remove() {
    podman rm -f "$BOX" "$PROXY" "$TARGET" >/dev/null 2>&1
    podman network rm -f "$NET" >/dev/null 2>&1
    # The holder stops within a second after its path file goes.
    [ "$TTY_STARTED" = 0 ] || on_host "rm -f $TTYFILE $TTYFILE.py" </dev/null >/dev/null 2>&1
}
trap 'remove; cd /; rm -rf "$WORK"' EXIT
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

ALLOW=
mkdir -p "$WORK/tt"
if [ "$RUN" = tt ]; then
    echo "== the SSH server for the session: OpenSSH with less and procps, on the box's network only"
    printf 'FROM %s\nRUN apk add --no-cache openssh-server less procps\n' "$BASE_IMAGE" >"$WORK/Containerfile.target"
    timeout 900 podman build -q -t localhost/podssh-box-target:1 -f "$(hostpath "$WORK/Containerfile.target")" \
        "$(hostpath "$WORK")" >"$WORK/build-target.log" 2>&1 || { cat "$WORK/build-target.log"; die "the server image did not build"; }
    # A throwaway key pair for this run only; the box copies the private key
    # with mode 600, and the work directory goes at the end.
    timeout 120 podman run --rm --mount "type=bind,source=$(hostpath "$WORK/tt"),target=/tt" localhost/podssh-box-target:1 \
        sh -c 'ssh-keygen -q -t ed25519 -N "" -C podssh-tt -f /tt/key && chmod 644 /tt/key' || die "no key pair"
    timeout 120 podman run -d --name "$TARGET" --network "$NET" \
        --mount "type=bind,source=$(hostpath "$WORK/tt"),target=/tt,readonly" localhost/podssh-box-target:1 \
        sh -c 'adduser -D -s /bin/sh tt && sed -i "s/^tt:!/tt:*/" /etc/shadow && mkdir -p /home/tt/.ssh &&
            cp /tt/key.pub /home/tt/.ssh/authorized_keys && chown -R tt:tt /home/tt/.ssh &&
            chmod 700 /home/tt/.ssh && chmod 600 /home/tt/.ssh/authorized_keys && ssh-keygen -A &&
            exec /usr/sbin/sshd -D -e' >/dev/null || die "the SSH server did not start"
    TIP=$(podman inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$TARGET")
    [ -n "$TIP" ] || die "the SSH server has no address on $NET"
    ALLOW="--allow tt.box:22=$TIP:22"
    echo "the SSH server at $TIP:22 is tt.box:22 through the proxy"
fi

echo "== the proxy: the only way out"
# shellcheck disable=SC2086
timeout 600 podman run -d --name "$PROXY" --network podman --network "$NET"     --dns 1.1.1.1 --dns 8.8.8.8 \
    --mount "type=bind,source=$(hostpath "$HERE/box"),target=/box,readonly" \
    "$PROXY_IMAGE" python3 /box/proxy.py --listen "0.0.0.0:$PORT" $ALLOW >/dev/null || die "the proxy did not start"
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

echo "== the terminal: a /dev/tty that opens and never answers, as in the sandbox"
# A pty whose master nobody reads or writes, held by scripts/box/deadtty.py
# for at most 40 minutes (the box's own limit is 30). Its slave is bound at
# /dev/tty, so it is the controlling terminal of no process in the box.
TTY_STARTED=1
on_host "cat >$TTYFILE.py && (setsid nohup python3 $TTYFILE.py 2400 $TTYFILE >/dev/null 2>&1 </dev/null &)" \
    <"$HERE/box/deadtty.py" || die "could not start scripts/box/deadtty.py on the podman host (it needs python3 and setsid)"
SLAVE=
tries=0
until [ -n "$SLAVE" ]; do
    tries=$((tries + 1))
    [ "$tries" -le 15 ] || die "scripts/box/deadtty.py wrote no pty path within 15 tries"
    sleep 1
    SLAVE=$(on_host "cat $TTYFILE 2>/dev/null" </dev/null | tr -d '\r')
done
case $SLAVE in
    /dev/pts/[0-9]*) echo "the pty $SLAVE of the podman host is /dev/tty in the box" ;;
    *) die "scripts/box/deadtty.py gave '$SLAVE', not a /dev/pts path" ;;
esac

echo "== in the box"
timeout 1800 podman run --rm --name "$BOX" --network "$NET" \
    --dns 1.1.1.1 --dns 8.8.8.8 --dns 9.9.9.9 --dns-option timeout:1 --dns-option attempts:2 \
    --cap-drop all --security-opt no-new-privileges \
    --security-opt "seccomp=$(hostpath "$HERE/box/seccomp.json")" \
    --security-opt mask=/dev/pts \
    --mount "type=bind,source=$SLAVE,target=/dev/tty" \
    --mount "type=bind,source=$(hostpath "$WORK/empty"),target=/etc/passwd,readonly" \
    --mount "type=bind,source=$(hostpath "$WORK/empty"),target=/etc/group,readonly" \
    --mount "type=bind,source=$(hostpath "$BIN"),target=/in/podssh,readonly" \
    --mount "type=bind,source=$(hostpath "$HERE"),target=/scripts,readonly" \
    --mount "type=bind,source=$(hostpath "$WORK/tt"),target=/tt,readonly" \
    --tmpfs /state/home:rw,exec,mode=1777 \
    -e HOME=/state/home -e TERM=xterm \
    -e HTTPS_PROXY="http://$PIP:$PORT" -e https_proxy="http://$PIP:$PORT" \
    -e NO_PROXY="$PIP" -e no_proxy="$PIP" \
    -e BOX_RUN="$RUN" \
    "$IMAGE" sh -c 'install -m 755 /in/podssh /usr/local/bin/podssh && sh /scripts/box/probe.sh &&
        if [ "$BOX_RUN" = tt ]; then sh /scripts/box/tt-session.sh /usr/local/bin/podssh;
        else sh /scripts/sandbox-check.sh /usr/local/bin/podssh; fi'
rc=$?

echo
echo "== the proxy's log: every connection it was asked for"
podman logs "$PROXY" 2>&1 | grep -v '^listening' | tail -60
echo
echo "test_in_box: exit $rc"
exit "$rc"
