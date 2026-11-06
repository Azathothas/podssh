#!/bin/sh
# scripts/interop-upterm.sh - `-J upterm://` (T-495), against upterm's own
# uptermd and `upterm host` of a pinned release, in containers on a network
# of the run: uptermd with its WebSocket on the loopback (podssh's
# `upterm+ws://`, as the session's ID crosses no network), an upterm host
# that lets its guests forward to its loopback, and OpenSSH's sshd on that
# loopback as the next hop.
#
#   sh scripts/interop-upterm.sh PODSSH_BINARY
#
# upterm's release is fetched from GitHub and checked by the SHA-256 of its
# checksums.txt (or taken from PODSSH_UPTERM_DIR, a directory with the same
# two archives); its Linux binaries are static, and run on images/box's
# Alpine, which also runs sshd from its packages. uptermd's host key is made
# here, and podssh checks its certificate under an `@cert-authority` line of
# that key, as upterm's README gives one for its community server. The keys
# of the run are made in a directory that the run removes.
#
# The checks: the pinned version runs; a command on the host's sshd with the
# session as the first hop of -J; another authority in known_hosts refused
# (the plant of T-495, uptermd's certificate not checked, fails it); a
# session that uptermd knows not refused in its words (ssh's exit 255); and
# `podssh proxy upterm+ws://...` as OpenSSH's ProxyCommand. Each prints a
# line of scripts/interop-lib.sh; the exit code is 0 when each passed, else
# 1, and 71 when the host lacks what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), curl (unless
# PODSSH_UPTERM_DIR), tar, ssh-keygen, sha256sum and timeout; the port
# PODSSH_UPTERM_PORT (18470) of the loopback free.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-upterm.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_UPTERM_PORT:-18470}
NET=podssh-upterm-net
NAMES="podssh-upterm-check podssh-upterm-d podssh-upterm-host"
# upterm's release read for T-495 (published 2026-11-02), and the SHA-256 of
# each Linux archive, from its release's checksums.txt.
UPTERM_VERSION=0.41.0
SHA_HOST_AMD64=dd40c62e9d585a0cada5b82458c62e171f1ed65a228d2fb4d3a508d5c8e34c5c
SHA_HOST_ARM64=94a54c215405bc604072711f7a719ca387d603c9014fe60e98e47fe4f706a73b
SHA_D_AMD64=0ccb99420998c2ad5b0b758ac7f45941393a590897f792732ad579dd8229cbec
SHA_D_ARM64=3e93da482affbe48087bac55df06f0c132a7d7fce815f44ea1b599e47d5a4350

die() {
    echo "interop-upterm: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in ssh ssh-keygen sha256sum tar timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done
case $(uname -m) in
    x86_64 | amd64) ARCH=amd64 SHA_HOST=$SHA_HOST_AMD64 SHA_D=$SHA_D_AMD64 ;;
    aarch64 | arm64) ARCH=arm64 SHA_HOST=$SHA_HOST_ARM64 SHA_D=$SHA_D_ARM64 ;;
    *) die "no pinned upterm for $(uname -m)" ;;
esac

W=$(mktemp -d) || die "no directory for the run"
remove_all() {
    for _c in $NAMES; do
        timeout 60 "$ENGINE" rm -f "$_c" >/dev/null 2>&1
    done
    timeout 60 "$ENGINE" network rm "$NET" >/dev/null 2>&1
}
cleanup() {
    remove_all
    rm -rf "$W"
}
trap cleanup EXIT INT TERM
remove_all

# Each archive, checked by its pinned digest, unpacked into $W/up.
mkdir -p "$W/up"
for pair in "upterm_linux_$ARCH.tar.gz:$SHA_HOST" "uptermd_linux_$ARCH.tar.gz:$SHA_D"; do
    file=${pair%%:*}
    want=${pair#*:}
    if [ -n "${PODSSH_UPTERM_DIR:-}" ]; then
        cp "$PODSSH_UPTERM_DIR/$file" "$W/$file" || die "PODSSH_UPTERM_DIR has no $file"
    else
        command -v curl >/dev/null 2>&1 || die "curl is missing (or give PODSSH_UPTERM_DIR)"
        url=https://github.com/owenthereal/upterm/releases/download/v$UPTERM_VERSION/$file
        timeout 300 curl -fsSL --retry 3 --max-time 240 -o "$W/$file" "$url" >"$W/fetch.log" 2>&1 ||
            die "$file did not download from $url: $(tail -5 "$W/fetch.log")"
    fi
    got=$(sha256sum "$W/$file" | cut -d' ' -f1)
    [ "$got" = "$want" ] || die "$file has the SHA-256 $got, not the pinned $want"
    tar -xzf "$W/$file" -C "$W/up" || die "$file does not unpack"
done
[ -x "$W/up/upterm" ] && [ -x "$W/up/uptermd" ] || die "the archives hold no upterm and uptermd"

image_of() {
    _ref=$(tr -d '\r' <"$1" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in *@sha256:*) PULL_ENGINE=$ENGINE sh "$HERE/pull-image.sh" "$_ref" ;; *) return 1 ;; esac
}
ALPINE=$(image_of "$REPO/images/box/Dockerfile") || die "Alpine's image did not pull"

# uptermd's key, which signs its host certificate; the user's key, which the
# host's guests and its sshd let in; another authority, for the plant.
mkdir -p "$W/k"
for name in uptermd user other; do
    timeout 30 ssh-keygen -q -t ed25519 -N '' -f "$W/k/$name" >/dev/null 2>&1 || die "ssh-keygen failed"
done
chmod 644 "$W/k/uptermd" "$W/k/user.pub" "$W/k/uptermd.pub"
printf '@cert-authority [127.0.0.1]:%s %s\n' "$PORT" "$(cat "$W/k/uptermd.pub")" >"$W/known_hosts"
printf '@cert-authority [127.0.0.1]:%s %s\n' "$PORT" "$(cat "$W/k/other.pub")" >"$W/known_other"

timeout 120 "$ENGINE" run --name podssh-upterm-check -v "$W/up:/u:ro" "$ALPINE" /u/upterm version \
    >"$W/version.log" 2>&1
grep -q "$UPTERM_VERSION" "$W/version.log" &&
    ok upterm.version "upterm $UPTERM_VERSION runs on Alpine" ||
    bad upterm.version "the pinned upterm did not run" "$W/version.log"

timeout 60 "$ENGINE" network create "$NET" >/dev/null 2>&1 || die "no network for the run"
timeout 120 "$ENGINE" run -d --name podssh-upterm-d --network "$NET" --network-alias uptermd.test \
    -p "127.0.0.1:$PORT:8080" -v "$W/up:/u:ro" -v "$W/k:/k:ro" "$ALPINE" \
    /u/uptermd --ssh-addr 0.0.0.0:2222 --ws-addr 0.0.0.0:8080 --hostname uptermd.test \
    --private-key /k/uptermd >"$W/d.log" 2>&1 || die "uptermd did not start: $(tail -3 "$W/d.log")"

# The host: sshd on its loopback for root by the user's key, and upterm's
# host, detached, whose guests forward to its loopback alone.
cat >"$W/host.sh" <<'EOF'
set -e
apk add --no-cache openssh-server >/dev/null
ssh-keygen -A >/dev/null
mkdir -p /root/.ssh && cp /k/user.pub /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
/usr/sbin/sshd -o ListenAddress=127.0.0.1 -o PasswordAuthentication=no
printf '@cert-authority [uptermd.test]:2222 %s\n' "$(cat /k/uptermd.pub)" >/tmp/known_hosts
/u/upterm host --server ssh://uptermd.test:2222 --known-hosts /tmp/known_hosts --accept \
    --allow-forwarding=loopback --authorized-keys /k/user.pub --detach --output json -- sh >/tmp/session.json
sleep 600
EOF
timeout 120 "$ENGINE" run -d --name podssh-upterm-host --network "$NET" -v "$W/up:/u:ro" -v "$W/k:/k:ro" \
    -v "$W/host.sh:/host.sh:ro" "$ALPINE" sh /host.sh >"$W/host.log" 2>&1 || die "the host did not start"
session=""
for _ in $(seq 1 60); do
    json=$(timeout 30 "$ENGINE" exec podssh-upterm-host cat /tmp/session.json 2>/dev/null) || json=""
    # The SSH line of the session: `ssh ID@uptermd.test -p 2222`; its user is the ID.
    session=$(printf '%s' "$json" | sed -n 's/.*"sshCommand": *"ssh \([^@" ]*\)@.*/\1/p')
    [ -n "$session" ] && break
    sleep 2
done
[ -n "$session" ] ||
    die "the upterm host gave no session: $(timeout 30 "$ENGINE" logs podssh-upterm-host 2>&1 | tail -5)"
# The host's sshd's own key, in each file: only uptermd's is under test, and
# the next hop's is checked as strictly.
sshd_key=$(timeout 30 "$ENGINE" exec podssh-upterm-host cat /etc/ssh/ssh_host_ed25519_key.pub) ||
    die "no key of the host's sshd"
for file in "$W/known_hosts" "$W/known_other"; do
    printf '127.0.0.1 %s\n' "$sshd_key" >>"$file"
done

podssh_to() {
    # podssh_to KNOWN SESSION COMMAND: through the session, to the host's sshd.
    timeout 120 "$BIN" ssh -F none -i "$W/k/user" -o IdentitiesOnly=yes \
        -o UserKnownHostsFile="$1" -o StrictHostKeyChecking=yes \
        -J "upterm+ws://$2@127.0.0.1:$PORT" root@127.0.0.1 "$3" </dev/null
}

podssh_to "$W/known_hosts" "$session" 'echo through-upterm' >"$W/hop.out" 2>"$W/hop.err"
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/hop.out")" = through-upterm ] &&
    ok upterm.hop "a command on the host's sshd, the session the first hop, uptermd's certificate checked" ||
    bad upterm.hop "through the session: exit $rc" "$W/hop.err"

podssh_to "$W/known_other" "$session" 'echo no' >"$W/cert.out" 2>"$W/cert.err"
rc=$?
[ "$rc" = 255 ] && [ ! -s "$W/cert.out" ] &&
    ok upterm.cert "another authority in known_hosts: uptermd's certificate refused (exit 255)" ||
    bad upterm.cert "another authority: exit $rc, not 255" "$W/cert.err"

podssh_to "$W/known_hosts" "no-such-session" 'echo no' >"$W/gone.out" 2>"$W/gone.err"
rc=$?
[ "$rc" = 255 ] && grep -q "knows no session no-such-session" "$W/gone.err" &&
    ok upterm.gone "a session that uptermd knows not: refused in its words (255)" ||
    bad upterm.gone "an unknown session: exit $rc" "$W/gone.err"

timeout 120 ssh -F /dev/null -i "$W/k/user" -o IdentitiesOnly=yes -o UserKnownHostsFile="$W/known_hosts" \
    -o StrictHostKeyChecking=yes -p "$PORT" \
    -o "ProxyCommand=$BIN proxy upterm+ws://$session@127.0.0.1:$PORT" "$session@127.0.0.1" true \
    </dev/null >"$W/proxy.out" 2>"$W/proxy.err"
rc=$?
# The session's own shell takes the command, or uptermd lets the login in and
# the host's terminal answers: OpenSSH's login is what is under test.
grep -q -i "permission denied\|host key verification failed" "$W/proxy.err" &&
    bad upterm.proxy "OpenSSH through podssh proxy: exit $rc" "$W/proxy.err" ||
    ok upterm.proxy "OpenSSH's ProxyCommand podssh proxy upterm+ws://...: logged in to uptermd (exit $rc)"

echo "interop-upterm: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
