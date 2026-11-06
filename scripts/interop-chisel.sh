#!/bin/sh
# scripts/interop-chisel.sh - `--chisel`, a chisel server in place of the
# relay (T-490, the operator's ruling Q66), against jpillora/chisel's own
# server of a pinned release, in a container on a network of the run, with
# OpenSSH's sshd as the target, and a plain squid as the host's own proxy
# (HTTPS_PROXY), which carries the TLS to the server by its name.
#
#   sh scripts/interop-chisel.sh PODSSH_BINARY
#
# chisel's release is fetched from GitHub and checked by the SHA-256 of its
# chisel_1.13.0_checksums.txt (or taken from PODSSH_CHISEL_GZ, a copy of the
# same file); its Linux binary is static, and runs on images/box's Alpine,
# which also runs sshd and squid from its packages. One server over TLS,
# with a key of its own and an authfile that lets the user podssh reach
# sshd.test:22 alone. The CA, the certificate, the key of the session and the
# password are made for the run in a directory that the run removes; the
# password reaches chisel in a mounted file and podssh by the path of its
# file alone, never argv, and no output of podssh may show it.
#
# The checks: the pinned version runs; sshd's banner through `proxy` and a
# session, and 1 MiB each way with equal digests; a wrong password, a wrong
# fingerprint (the plant of T-490, the fingerprint not checked, fails it) and
# a target that the authfile does not allow, each refused with its words and
# exit 77; the host's squid carrying the TLS; and no output holding the
# password. Each prints a line of scripts/interop-lib.sh; the exit code is 0
# when each passed, else 1, and 71 when the host lacks what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), curl (unless
# PODSSH_CHISEL_GZ), gzip, openssl, python3, sha256sum and timeout; the
# ports PODSSH_CHISEL_PORT (18460) and PODSSH_CHISEL_PORT+1 of the loopback
# free.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-chisel.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_CHISEL_PORT:-18460}
TLS_PORT=$PORT
HOP_PORT=$((PORT + 1))
NET=podssh-chisel-net
NAMES="podssh-chisel-check podssh-chisel-sshd podssh-chisel-tls podssh-chisel-hop"
# chisel's release read for T-490 (2026-10-11), and the SHA-256 of each
# Linux binary, from its release's chisel_1.13.0_checksums.txt.
CHISEL_VERSION=1.13.0
SHA_AMD64=902a38e824bfb4d4e428faa45607a9b71fc74ff28bf1392cf8121650061c6971
SHA_ARM64=a23daaa1635741f8ef56a44e0506abcdf97251c03bb42433241bbb6c549814e4

die() {
    echo "interop-chisel: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in gzip openssl python3 sha256sum timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done
case $(uname -m) in
    x86_64 | amd64) ARCH=amd64 SHA=$SHA_AMD64 ;;
    aarch64 | arm64) ARCH=arm64 SHA=$SHA_ARM64 ;;
    *) die "no pinned chisel for $(uname -m)" ;;
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

GZ=chisel_${CHISEL_VERSION}_linux_${ARCH}.gz
URL=https://github.com/jpillora/chisel/releases/download/v$CHISEL_VERSION/$GZ
if [ -n "${PODSSH_CHISEL_GZ:-}" ]; then
    cp "$PODSSH_CHISEL_GZ" "$W/$GZ" || die "PODSSH_CHISEL_GZ cannot be read"
else
    command -v curl >/dev/null 2>&1 || die "curl is missing (or give PODSSH_CHISEL_GZ)"
    timeout 300 curl -fsSL --retry 3 --max-time 240 -o "$W/$GZ" "$URL" >"$W/fetch.log" 2>&1 ||
        die "chisel's release did not download from $URL: $(tail -5 "$W/fetch.log")"
fi
got=$(sha256sum "$W/$GZ" | cut -d' ' -f1)
[ "$got" = "$SHA" ] || die "$GZ has the SHA-256 $got, not the pinned $SHA"
mkdir -p "$W/ch" && gzip -dc "$W/$GZ" >"$W/ch/chisel" || die "$GZ does not unpack"
chmod 755 "$W/ch/chisel"

image_of() {
    _ref=$(tr -d '\r' <"$1" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in *@sha256:*) PULL_ENGINE=$ENGINE sh "$HERE/pull-image.sh" "$_ref" ;; *) return 1 ;; esac
}
ALPINE=$(image_of "$REPO/images/box/Dockerfile") || die "Alpine's image did not pull"

# The CA of the run, and the server's certificate for chisel.test, its name
# on the loopback, and chisel-tls.test, its name on the run's network.
mkdir -p "$W/tls" "$W/key" "$W/hop"
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca_ext' 'prompt = no' '[dn]' \
    'CN = podssh chisel test CA' '[ca_ext]' 'basicConstraints = critical,CA:TRUE' \
    'keyUsage = critical,keyCertSign,cRLSign' 'subjectKeyIdentifier = hash' >"$W/ca.cnf"
printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = chisel.test' '[leaf]' \
    'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature' 'extendedKeyUsage = serverAuth' \
    'subjectAltName = DNS:chisel.test,DNS:chisel-tls.test' 'authorityKeyIdentifier = keyid' >"$W/leaf.cnf"
{
    timeout 60 openssl req -x509 -config "$W/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 &&
        timeout 60 openssl req -new -config "$W/leaf.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$W/tls/chisel.key" -out "$W/chisel.csr" &&
        timeout 60 openssl x509 -req -in "$W/chisel.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
            -days 2 -extfile "$W/leaf.cnf" -extensions leaf -out "$W/tls/chisel.pem"
} >"$W/openssl.log" 2>&1 || die "openssl could not make the certificates: $(tail -3 "$W/openssl.log")"
chmod 644 "$W/tls/chisel.key"

# The password, made here and never printed, in chisel's authfile, which
# lets the user podssh reach sshd.test:22 alone.
umask 077
password=$(openssl rand -hex 16) || die "no password"
printf '%s\n' "$password" >"$W/secret.words"
umask 022
printf '{"podssh:%s": ["^sshd\\\\.test:22$"]}\n' "$password" >"$W/tls/users.json"
chmod 644 "$W/tls/users.json"
timeout 30 "$BIN" keygen -q -t ed25519 -N '' -f "$W/key/id" >/dev/null 2>&1 || die "podssh keygen failed"
chmod 644 "$W/key/id.pub"
printf '%s\n' 'http_port 3128' 'http_access allow all' 'cache deny all' 'access_log stdio:/tmp/access.log' \
    'cache_log /tmp/cache.log' 'pid_filename none' 'logfile_rotate 0' 'coredump_dir /tmp' >"$W/hop/squid.conf"

timeout 120 "$ENGINE" run --name podssh-chisel-check -v "$W/ch:/c:ro" "$ALPINE" /c/chisel --version \
    >"$W/version.log" 2>&1
rc=$?
timeout 60 "$ENGINE" rm -f podssh-chisel-check >/dev/null 2>&1
grep -q "$CHISEL_VERSION" "$W/version.log" &&
    ok chisel.version "chisel $CHISEL_VERSION runs on Alpine: $(head -1 "$W/version.log")" ||
    bad chisel.version "the pinned chisel did not say $CHISEL_VERSION: exit $rc" "$W/version.log"

timeout 60 "$ENGINE" network create "$NET" >/dev/null || die "the network $NET could not be made"
timeout 300 "$ENGINE" run -d --name podssh-chisel-sshd --network "$NET" --network-alias sshd.test \
    -v "$W/key:/k:ro" "$ALPINE" sh -c 'apk add --no-cache openssh-server >/dev/null &&
    ssh-keygen -A >/dev/null && mkdir -p /root/.ssh && cp /k/id.pub /root/.ssh/authorized_keys &&
    chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && sed -i "s/^root:[^:]*:/root:*:/" /etc/shadow &&
    exec /usr/sbin/sshd -D -e' >/dev/null || die "sshd did not start"
# The server's key is made in the container at its start, and its
# fingerprint read from its log, as a user reads it.
timeout 300 "$ENGINE" run -d --name podssh-chisel-tls --network "$NET" --network-alias chisel-tls.test \
    -p "127.0.0.1:$TLS_PORT:8443" -v "$W/ch:/c:ro" -v "$W/tls:/etc/chisel:ro" "$ALPINE" sh -c \
    '/c/chisel server --keygen /tmp/key >/dev/null && exec /c/chisel server --keyfile /tmp/key --port 8443 \
    --tls-cert /etc/chisel/chisel.pem --tls-key /etc/chisel/chisel.key --authfile /etc/chisel/users.json' \
    >/dev/null || die "the chisel server did not start"
timeout 300 "$ENGINE" run -d --name podssh-chisel-hop --network "$NET" -p "127.0.0.1:$HOP_PORT:3128" \
    -v "$W/hop:/etc/podssh-squid:ro" "$ALPINE" \
    sh -c 'apk add --no-cache squid >/dev/null && exec squid -N -f /etc/podssh-squid/squid.conf' >/dev/null ||
    die "the host's squid did not start"

# ready PORT SECONDS: the loopback's PORT answers a TLS handshake with the
# run's CA, or bytes for a request.
ready() {
    _t0=$(date +%s)
    while :; do
        timeout 10 python3 -c 'import socket, ssl, sys
port, mode, ca = int(sys.argv[1]), sys.argv[2], sys.argv[3]
try:
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(5)
    if mode == "tls":
        ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname="chisel.test").close()
    else:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        sys.exit(0 if s.recv(1) else 1)
except (OSError, ssl.SSLError):
    sys.exit(1)' "$1" "$3" "$W/ca.pem" && return 0
        [ $(($(date +%s) - _t0)) -lt "$2" ] || return 1
        sleep 1
    done
}
logs_of() {
    timeout 30 "$ENGINE" logs "$1" 2>&1 | grep -v -F -f "$W/secret.words" | tail -20
}
ready "$TLS_PORT" 300 tls || { logs_of podssh-chisel-tls; die "the chisel server did not answer"; }
ready "$HOP_PORT" 300 http || { logs_of podssh-chisel-hop; die "the host's squid did not answer"; }

print=$(timeout 30 "$ENGINE" logs podssh-chisel-tls 2>&1 | sed -n 's/.*Fingerprint \([A-Za-z0-9+/=]\{44\}\).*/\1/p' | head -1)
[ -n "$print" ] || { logs_of podssh-chisel-tls; die "the chisel server printed no fingerprint"; }
umask 077
printf '# the run of T-490\nauth podssh:%s\nfingerprint %s\n' "$password" "$print" >"$W/auth"
printf 'auth podssh:%s-wrong\nfingerprint %s\n' "$password" "$print" >"$W/auth-wrong-pass"
printf 'auth podssh:%s\nfingerprint %s\n' "$password" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" >"$W/auth-wrong-print"
umask 022

URL_TLS=https://chisel.test:$TLS_PORT
PINS="chisel.test=127.0.0.1"
SSH_OPTS="-i $W/key/id -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$W/kh -o BatchMode=yes"
run() {
    _n=$1
    _v=$2
    shift 2
    env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" "$_v" --ca-file "$W/ca.pem" "$@" \
        </dev/null >"$W/$_n.out" 2>"$W/$_n.err"
}
run_held() {
    _n=$1
    _v=$2
    shift 2
    sleep 3 | env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" "$_v" --ca-file "$W/ca.pem" "$@" \
        >"$W/$_n.out" 2>"$W/$_n.err"
}

echo
echo "== --chisel: chisel $CHISEL_VERSION's own server (T-490)"

run_held banner proxy --chisel "$URL_TLS" --chisel-auth-file "$W/auth" sshd.test 22
rc=$?
case $(head -c 8 "$W/banner.out") in
    SSH-2.0-) ok chisel.banner "podssh proxy --chisel: sshd's banner through chisel (exit $rc)" ;;
    *) bad chisel.banner "no banner through chisel: exit $rc" "$W/banner.err" ;;
esac

# shellcheck disable=SC2086  # the options are words
run session ssh -v --chisel "$URL_TLS" --chisel-auth-file "$W/auth" $SSH_OPTS root@sshd.test 'echo through-chisel'
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/session.out")" = through-chisel ] &&
    grep -q 'the chisel server https://chisel.test:[0-9]* carries the session' "$W/session.err" &&
    ok chisel.session "a session through chisel's server, its key checked by its fingerprint" ||
    bad chisel.session "a session through chisel: exit $rc" "$W/session.err"

head -c 1048576 /dev/urandom >"$W/mib"
want=$(sha256sum <"$W/mib" | cut -d' ' -f1)
# shellcheck disable=SC2086
env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" ssh --ca-file "$W/ca.pem" --chisel "$URL_TLS" \
    --chisel-auth-file "$W/auth" $SSH_OPTS root@sshd.test cat <"$W/mib" >"$W/bulk.out" 2>"$W/bulk.err"
rc=$?
got=$(sha256sum <"$W/bulk.out" | cut -d' ' -f1)
[ "$rc" = 0 ] && [ "$got" = "$want" ] && ok chisel.bulk "1 MiB each way through chisel, equal digests" ||
    bad chisel.bulk "1 MiB through chisel: exit $rc, $(wc -c <"$W/bulk.out") bytes back" "$W/bulk.err"

run wrong-pass proxy --chisel "$URL_TLS" --chisel-auth-file "$W/auth-wrong-pass" sshd.test 22
rc=$?
[ "$rc" = 77 ] && grep -q 'refused the user and password of --chisel-auth-file' "$W/wrong-pass.err" &&
    ok chisel.wrong-password "a wrong password: refused with its words (exit 77)" ||
    bad chisel.wrong-password "a wrong password: exit $rc" "$W/wrong-pass.err"

run wrong-print proxy --chisel "$URL_TLS" --chisel-auth-file "$W/auth-wrong-print" sshd.test 22
rc=$?
[ "$rc" = 77 ] && grep -q "showed the key $print, not the fingerprint" "$W/wrong-print.err" &&
    ok chisel.wrong-fingerprint "a fingerprint that is not the server's: refused before the login (exit 77)" ||
    bad chisel.wrong-fingerprint "a wrong fingerprint: exit $rc" "$W/wrong-print.err"

run denied proxy --chisel "$URL_TLS" --chisel-auth-file "$W/auth" sshd.test 2222
rc=$?
[ "$rc" = 77 ] && grep -q 'refused the tunnel to sshd.test:2222' "$W/denied.err" &&
    ok chisel.denied "a target that the authfile does not allow: refused (exit 77)" ||
    bad chisel.denied "a target that the authfile does not allow: exit $rc" "$W/denied.err"

# shellcheck disable=SC2086
HTTPS_PROXY=http://127.0.0.1:$HOP_PORT timeout 120 "$BIN" ssh -v --chisel https://chisel-tls.test:8443 \
    --chisel-auth-file "$W/auth" --ca-file "$W/ca.pem" $SSH_OPTS root@sshd.test 'echo hop' \
    </dev/null >"$W/hop.out" 2>"$W/hop.err"
rc=$?
asked=$(timeout 30 "$ENGINE" exec podssh-chisel-hop cat /tmp/access.log 2>/dev/null | grep -c 'CONNECT chisel-tls.test:8443')
[ "$rc" = 0 ] && [ "$(cat "$W/hop.out")" = hop ] && [ "${asked:-0}" -gt 0 ] &&
    ok chisel.hop "HTTPS_PROXY carries the TLS to the server by its name; the session runs inside" ||
    bad chisel.hop "through the host's proxy: exit $rc, $asked CONNECTs" "$W/hop.err"

leaked=$(grep -l -F -f "$W/secret.words" "$W"/*.out "$W"/*.err 2>/dev/null | wc -l)
[ "$leaked" = 0 ] && ok chisel.secret "no output of podssh holds the password" ||
    bad chisel.secret "$leaked outputs hold the password"

echo "interop-chisel: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
