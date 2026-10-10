#!/bin/sh
# podssh chat between two boxes like the target sandbox (T-099), through the
# live relay. Box B waits as the node of a pair; box A reaches it: a message,
# files of 0, 1 and 5,000,000 bytes, and a file that the user of B did not
# accept. Exit 0 only when the message arrived, each file arrived once with
# an equal SHA-256, and the file with no accept was not written.
#
#   sh scripts/chat-in-boxes.sh [PODSSH_LINUX_BINARY]
#   CHAT_PLANT=accept sh scripts/chat-in-boxes.sh [PODSSH_LINUX_BINARY]
#
# CHAT_PLANT=accept is the planted defect: the side with no accept takes the
# file anyway (it gets --accept-dir), so the script must fail.
#
# The boxes are those of scripts/test_in_box.sh: an internal network, one
# HTTP CONNECT proxy (scripts/box/proxy.py) as the only way out, no
# capabilities and no_new_privs, the seccomp filter that refuses bind and
# UDP, and uid 0 with no user database entry. The operator's part of the
# pair goes from B to A through a directory of the host, as a user would
# send it over a trusted channel; the directory goes at the end, and B
# revokes the pair. Needs podman; on Windows, a running podman machine.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
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
NET=podssh-chat-net
PROXY=podssh-chat-proxy
BOX_A=podssh-chat-a
BOX_B=podssh-chat-b
IMAGE=localhost/podssh-box:2
BASE_IMAGE=$(image_of "$REPO/.github/images/box/Dockerfile") || exit 78
PROXY_IMAGE=$(image_of "$REPO/.github/images/box-proxy/Dockerfile") || exit 78
PORT=45332
PLANT=${CHAT_PLANT:-}
case $PLANT in '' | accept) ;; *) echo "chat-in-boxes: CHAT_PLANT is accept or empty, not $PLANT" >&2; exit 1 ;; esac

die() {
    echo "chat-in-boxes: $*" >&2
    exit 1
}
command -v podman >/dev/null 2>&1 || die "podman is not on PATH"
command -v timeout >/dev/null 2>&1 || die "timeout is not on PATH: every wait here needs a bound"
[ -f "$BIN" ] || die "no podssh binary at $BIN; give a static Linux build as the first argument"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

MSYS2_ARG_CONV_EXCL='*'
export MSYS2_ARG_CONV_EXCL
hostpath() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# podman runs from a work directory of its own (see scripts/test_in_box.sh).
WORK=$(mktemp -d 2>/dev/null || echo "/tmp/podssh-chat-$$")
{ mkdir -p "$WORK/share/in" "$WORK/share/noaccept" "$WORK/share/files" && cd "$WORK"; } ||
    die "cannot use the work directory $WORK"
remove() {
    podman rm -f "$BOX_A" "$BOX_B" "$PROXY" >/dev/null 2>&1
    podman network rm -f "$NET" >/dev/null 2>&1
}
trap 'remove; cd /; rm -rf "$WORK"' EXIT
timeout 60 podman info >/dev/null 2>&1 || die "podman does not answer (on Windows: podman machine start)"
remove

echo "== the box image"
printf 'FROM %s\nRUN apk add --no-cache openssh-client curl\n' "$BASE_IMAGE" >"$WORK/Containerfile"
timeout 900 podman build -q -t "$IMAGE" -f "$(hostpath "$WORK/Containerfile")" "$(hostpath "$WORK")" >"$WORK/build.log" 2>&1 ||
    { cat "$WORK/build.log"; die "the box image did not build"; }

echo "== the network, and the proxy: the only way out"
podman network create --internal --disable-dns "$NET" >/dev/null || die "could not create the network $NET"
timeout 600 podman run -d --name "$PROXY" --network podman --network "$NET" --dns 1.1.1.1 --dns 8.8.8.8 \
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
: >"$WORK/empty"

# The two sides, as each box runs them. B: the pair, then a side that takes
# each file into /share/in until A is done, then a side with no accept in
# /share/noaccept. Each side ends with /quit, which acts while no peer is
# there. A: a message, the three files, then the file with no accept, which
# waits for an answer until its --timeout (75).
NOACCEPT_FLAGS=
[ "$PLANT" = accept ] && NOACCEPT_FLAGS="--accept-dir /share/noaccept"
cat >"$WORK/share/b.sh" <<EOF
set -u
install -m 755 /in/podssh /usr/local/bin/podssh
timeout 60 podssh relay pair chat --operator-file /share/op.json >/share/pair.out 2>/share/pair.err || exit 11
(n=0; while [ ! -f /share/a1.done ] && [ \$n -lt 900 ]; do sleep 1; n=\$((n+1)); done; echo /quit) |
    timeout 960 podssh chat --listen chat --accept-dir /share/in --nick b --timeout 950s >/share/b1.out 2>/share/b1.err
echo \$? >/share/b1.rc
cd /share/noaccept || exit 12
(n=0; while [ ! -f /share/a2.done ] && [ \$n -lt 300 ]; do sleep 1; n=\$((n+1)); done; echo /quit) |
    timeout 360 podssh chat --listen chat --nick b --timeout 350s $NOACCEPT_FLAGS >/share/b2.out 2>/share/b2.err
echo \$? >/share/b2.rc
timeout 60 podssh relay revoke chat >/share/revoke.out 2>/share/revoke.err
echo \$? >/share/revoke.rc
EOF
cat >"$WORK/share/a.sh" <<'EOF'
set -u
install -m 755 /in/podssh /usr/local/bin/podssh
online() {
    n=0
    until grep -q "online:" "$1" 2>/dev/null; do
        n=$((n + 1))
        [ "$n" -lt 120 ] || { echo "no side waits: $1"; return 1; }
        sleep 1
    done
}
run() {
    want=$1
    limit=$2
    shift 2
    start=$(date +%s)
    timeout $((limit + 10)) podssh chat chat --pair-file /share/op.json --nick a --timeout "${limit}s" "$@" \
        >>/share/a.out 2>>/share/a.err
    rc=$?
    echo "$* -> exit $rc in $(($(date +%s) - start)) s (wanted $want)" >>/share/a.log
    [ "$rc" = "$want" ]
}
fail=0
head -c 0 /dev/zero >/share/files/empty.bin
printf x >/share/files/one.bin
head -c 5000000 /dev/urandom >/share/files/big.bin
printf 'never written\n' >/share/files/secret.txt
online /share/b1.err || exit 21
run 0 120 --send "hello from box A" || fail=1
for f in empty.bin one.bin big.bin; do
    run 0 390 --file "/share/files/$f" || fail=1
done
touch /share/a1.done
online /share/b2.err || exit 22
run 75 30 --file /share/files/secret.txt || fail=1
touch /share/a2.done
exit $fail
EOF

box() {
    _name=$1
    shift
    podman run --name "$_name" --network "$NET" \
        --dns 1.1.1.1 --dns-option timeout:1 --dns-option attempts:2 \
        --cap-drop all --security-opt no-new-privileges \
        --security-opt "seccomp=$(hostpath "$HERE/box/seccomp.json")" \
        --mount "type=bind,source=$(hostpath "$WORK/empty"),target=/etc/passwd,readonly" \
        --mount "type=bind,source=$(hostpath "$WORK/empty"),target=/etc/group,readonly" \
        --mount "type=bind,source=$(hostpath "$BIN"),target=/in/podssh,readonly" \
        --mount "type=bind,source=$(hostpath "$WORK/share"),target=/share" \
        --tmpfs /state/home:rw,exec,mode=1777 \
        -e HOME=/state/home -e HTTPS_PROXY="http://$PIP:$PORT" -e https_proxy="http://$PIP:$PORT" \
        -e NO_PROXY="$PIP" -e no_proxy="$PIP" \
        "$@"
}

echo "== box B waits, box A reaches it"
box "$BOX_B" -d "$IMAGE" timeout 1500 sh /share/b.sh >/dev/null || die "box B did not start"
box "$BOX_A" --rm "$IMAGE" timeout 1400 sh /share/a.sh
a_rc=$?
timeout 600 podman wait "$BOX_B" >/dev/null 2>&1 || echo "box B did not end within 600 s"

echo
echo "== what each side said"
for f in a.log a.err b1.err b2.err pair.err revoke.err; do
    [ -f "$WORK/share/$f" ] && { echo "--- $f"; cat "$WORK/share/$f"; }
done

fail=0
[ "$a_rc" = 0 ] || { echo "FAIL: box A exited $a_rc"; fail=1; }
grep -q "^a: hello from box A$" "$WORK/share/b1.out" 2>/dev/null || { echo "FAIL: the message did not arrive"; fail=1; }
for f in empty.bin one.bin big.bin; do
    want=$(sha256sum <"$WORK/share/files/$f" | cut -c1-64)
    got=$(sha256sum <"$WORK/share/in/$f" 2>/dev/null | cut -c1-64)
    if [ -n "$got" ] && [ "$want" = "$got" ]; then
        echo "ok: $f arrived with an equal SHA-256"
    else
        echo "FAIL: $f: $want, received ${got:-nothing}"
        fail=1
    fi
done
extra=$(ls -A "$WORK/share/in" | grep -v -e '^empty.bin$' -e '^one.bin$' -e '^big.bin$')
[ -z "$extra" ] || { echo "FAIL: more than each file once in the inbox: $extra"; fail=1; }
written=$(ls -A "$WORK/share/noaccept")
[ -z "$written" ] || { echo "FAIL: a file was written with no accept: $written"; fail=1; }
[ "$(cat "$WORK/share/revoke.rc" 2>/dev/null)" = 0 ] || { echo "FAIL: the pair was not revoked"; fail=1; }
echo "exit=$fail"
exit $fail
