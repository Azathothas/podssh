#!/bin/sh
# scripts/interop-wstunnel.sh - `--wstunnel`, a wstunnel server in place of
# the relay (T-441, the operator's ruling Q66), against erebe/wstunnel's own
# server of a pinned release, each in a container on a network of the run,
# with OpenSSH's sshd as the target, and a plain squid as the host's own
# proxy (HTTPS_PROXY), which carries the TLS to the server by its name.
#
#   sh scripts/interop-wstunnel.sh PODSSH_BINARY
#
# wstunnel's release is fetched from GitHub and checked by its SHA-256 (or
# taken from PODSSH_WSTUNNEL_TARBALL, a copy of the same file); its Linux
# binaries are static (musl), and run on images/box's Alpine, which also
# runs sshd and squid from its packages. Three servers: one with wstunnel's
# defaults on ws://, one that applies the mask of each frame
# (--websocket-mask-frame), and one over TLS whose restrictions file holds
# the path prefix and the Basic credentials that a client must give, and the
# one target that it allows. The CA, the server's certificate, the key of
# the session and the secret are made for the run in a directory that the
# run removes; the secret reaches wstunnel in a mounted file and podssh by
# the path of its file alone, never argv, and no output of podssh may show
# it (wstunnel.secret).
#
# The checks: the pinned version runs; sshd's banner and a session through
# the server of the defaults, and 1 MiB each way with equal digests; a
# session through the server that applies masks; the banner and a session
# over TLS with the secret; a wrong secret and none, each refused with the
# words of wstunnel 10 and later and exit 77 (the plant of T-441, on the
# command line), and the server's log names the refusal; the host's squid
# carrying the TLS; and no output holding the secret. Each prints a line of
# scripts/interop-lib.sh; the exit code is 0 when each passed, else 1, and
# 71 when the host lacks what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), curl (unless
# PODSSH_WSTUNNEL_TARBALL), openssl, python3, sha256sum and timeout; the
# ports PODSSH_WSTUNNEL_PORT (18450) to PODSSH_WSTUNNEL_PORT+3 of the
# loopback free.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-wstunnel.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_WSTUNNEL_PORT:-18450}
PLAIN_PORT=$PORT
MASK_PORT=$((PORT + 1))
TLS_PORT=$((PORT + 2))
HOP_PORT=$((PORT + 3))
NET=podssh-wst-net
NAMES="podssh-wst-check podssh-wst-sshd podssh-wst-plain podssh-wst-mask podssh-wst-tls podssh-wst-hop"
# wstunnel's last release, read on 2026-11-02 (2026-10-19), and the SHA-256
# of each Linux archive, from its release's checksums.txt.
WSTUNNEL_VERSION=11.1.0
SHA_AMD64=512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23
SHA_ARM64=148895f957a68be39e2b65d28c5f2065b9c58c4a0cfd48c560b2b3267f398464

die() {
    echo "interop-wstunnel: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in openssl python3 sha256sum timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done
case $(uname -m) in
    x86_64 | amd64) ARCH=amd64 SHA=$SHA_AMD64 ;;
    aarch64 | arm64) ARCH=arm64 SHA=$SHA_ARM64 ;;
    *) die "no pinned wstunnel for $(uname -m)" ;;
esac

W=$(mktemp -d) || die "no directory for the run"
# Each container on its own: podman's rm stops at a name that is missing.
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

# The archive, fetched in the open so that a failure says why, then checked.
TARBALL=wstunnel_${WSTUNNEL_VERSION}_linux_${ARCH}.tar.gz
URL=https://github.com/erebe/wstunnel/releases/download/v$WSTUNNEL_VERSION/$TARBALL
if [ -n "${PODSSH_WSTUNNEL_TARBALL:-}" ]; then
    cp "$PODSSH_WSTUNNEL_TARBALL" "$W/$TARBALL" || die "PODSSH_WSTUNNEL_TARBALL cannot be read"
else
    command -v curl >/dev/null 2>&1 || die "curl is missing (or give PODSSH_WSTUNNEL_TARBALL)"
    timeout 300 curl -fsSL --retry 3 --max-time 240 -o "$W/$TARBALL" "$URL" >"$W/fetch.log" 2>&1 ||
        die "wstunnel's release did not download from $URL: $(tail -5 "$W/fetch.log")"
fi
got=$(sha256sum "$W/$TARBALL" | cut -d' ' -f1)
[ "$got" = "$SHA" ] || die "$TARBALL has the SHA-256 $got, not the pinned $SHA"
mkdir -p "$W/wst" && tar -xzf "$W/$TARBALL" -C "$W/wst" || die "$TARBALL does not unpack"
[ -f "$W/wst/wstunnel" ] || { ls -la "$W/wst" >&2; die "$TARBALL holds no wstunnel at its top"; }
chmod 755 "$W/wst/wstunnel"

# image_of DOCKERFILE: the image that its FROM line pins to a digest.
image_of() {
    _ref=$(tr -d '\r' <"$1" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in *@sha256:*) PULL_ENGINE=$ENGINE sh "$HERE/pull-image.sh" "$_ref" ;; *) return 1 ;; esac
}
ALPINE=$(image_of "$REPO/images/box/Dockerfile") || die "Alpine's image did not pull"

# The CA of the run, and the server's certificate for wst.test, its name on
# the loopback, and wst-tls.test, its name on the run's network.
mkdir -p "$W/tls" "$W/key" "$W/hop"
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca_ext' 'prompt = no' '[dn]' \
    'CN = podssh wstunnel test CA' '[ca_ext]' 'basicConstraints = critical,CA:TRUE' \
    'keyUsage = critical,keyCertSign,cRLSign' 'subjectKeyIdentifier = hash' >"$W/ca.cnf"
printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = wst.test' '[leaf]' \
    'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature' 'extendedKeyUsage = serverAuth' \
    'subjectAltName = DNS:wst.test,DNS:wst-tls.test' 'authorityKeyIdentifier = keyid' >"$W/leaf.cnf"
{
    timeout 60 openssl req -x509 -config "$W/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 &&
        timeout 60 openssl req -new -config "$W/leaf.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$W/tls/wst.key" -out "$W/wst.csr" &&
        timeout 60 openssl x509 -req -in "$W/wst.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
            -days 2 -extfile "$W/leaf.cnf" -extensions leaf -out "$W/tls/wst.pem"
} >"$W/openssl.log" 2>&1 || die "openssl could not make the certificates: $(tail -3 "$W/openssl.log")"
# wstunnel reads the key as the container's user, in a directory of the run.
chmod 644 "$W/tls/wst.key"

# The secret, made here and never printed: a path prefix and a password.
# podssh reads them from a file of mode 0600; wstunnel from its restrictions
# file, which matches the prefix and the Basic of podssh:PASSWORD, and lets
# a tunnel go to sshd.test:22 alone.
umask 077
prefix=$(openssl rand -hex 12) || die "no secret"
password=$(openssl rand -hex 16) || die "no password"
printf '%s\n%s\n' "$prefix" "$password" >"$W/secret.words"
printf '# the run of T-441\npath-prefix %s\ncredentials podssh:%s\n' "$prefix" "$password" >"$W/secret"
printf 'path-prefix %s-wrong\ncredentials podssh:%s\n' "$prefix" "$password" >"$W/secret-wrong"
basic=$(printf 'podssh:%s' "$password" | openssl base64 -A) || die "no Basic"
# A regular expression of it: base64's + is a quantifier there.
basic_re=$(printf '%s' "$basic" | sed 's/+/\\+/g')
umask 022
cat >"$W/tls/restrictions.yaml" <<EOF
restrictions:
  - name: "the run of T-441"
    match:
      - !PathPrefix '^$prefix\$'
      - !Authorization '^Basic $basic_re\$'
    allow:
      - !Tunnel
        protocol:
          - Tcp
        port:
          - 22
        host: ^sshd\\.test\$
EOF
chmod 644 "$W/tls/restrictions.yaml"
timeout 30 "$BIN" keygen -q -t ed25519 -N '' -f "$W/key/id" >/dev/null 2>&1 || die "podssh keygen failed"
chmod 644 "$W/key/id.pub"
printf '%s\n' 'http_port 3128' 'http_access allow all' 'cache deny all' 'access_log stdio:/tmp/access.log' \
    'cache_log /tmp/cache.log' 'pid_filename none' 'logfile_rotate 0' 'coredump_dir /tmp' >"$W/hop/squid.conf"

# The pinned binary runs on Alpine, and is the version of the pin.
timeout 120 "$ENGINE" run --name podssh-wst-check -v "$W/wst:/w:ro" "$ALPINE" /w/wstunnel --version \
    >"$W/version.log" 2>&1
rc=$?
timeout 60 "$ENGINE" rm -f podssh-wst-check >/dev/null 2>&1
grep -q "$WSTUNNEL_VERSION" "$W/version.log" &&
    ok wstunnel.version "wstunnel $WSTUNNEL_VERSION runs on Alpine: $(head -1 "$W/version.log")" ||
    bad wstunnel.version "the pinned wstunnel did not say $WSTUNNEL_VERSION: exit $rc" "$W/version.log"

timeout 60 "$ENGINE" network create "$NET" >/dev/null || die "the network $NET could not be made"
timeout 300 "$ENGINE" run -d --name podssh-wst-sshd --network "$NET" --network-alias sshd.test \
    -v "$W/key:/k:ro" "$ALPINE" sh -c 'apk add --no-cache openssh-server >/dev/null &&
    ssh-keygen -A >/dev/null && mkdir -p /root/.ssh && cp /k/id.pub /root/.ssh/authorized_keys &&
    chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && sed -i "s/^root:[^:]*:/root:*:/" /etc/shadow &&
    exec /usr/sbin/sshd -D -e' >/dev/null || die "sshd did not start"
# wstunnel's servers, as the container's root, each on its port inside.
wst() {
    _name=$1
    _port=$2
    shift 2
    timeout 300 "$ENGINE" run -d --name "$_name" --network "$NET" --network-alias "${_name#podssh-}.test" \
        -p "127.0.0.1:$_port:8443" -v "$W/wst:/w:ro" -v "$W/tls:/etc/wst:ro" "$ALPINE" \
        /w/wstunnel --log-lvl INFO server "$@" >/dev/null || die "the wstunnel of $_name did not start"
}
wst podssh-wst-plain "$PLAIN_PORT" ws://0.0.0.0:8443
wst podssh-wst-mask "$MASK_PORT" --websocket-mask-frame ws://0.0.0.0:8443
wst podssh-wst-tls "$TLS_PORT" --tls-certificate /etc/wst/wst.pem --tls-private-key /etc/wst/wst.key \
    --restrict-config /etc/wst/restrictions.yaml wss://0.0.0.0:8443
timeout 300 "$ENGINE" run -d --name podssh-wst-hop --network "$NET" -p "127.0.0.1:$HOP_PORT:3128" \
    -v "$W/hop:/etc/podssh-squid:ro" "$ALPINE" \
    sh -c 'apk add --no-cache squid >/dev/null && exec squid -N -f /etc/podssh-squid/squid.conf' >/dev/null ||
    die "the host's squid did not start"

# ready NAME PORT SECONDS MODE: the container NAME runs, and the loopback's
# PORT answers within SECONDS: a TLS handshake with the run's CA (tls), or
# bytes back for a request (http). A TCP connection alone proves nothing: an
# engine's own proxy of a published port takes it with nobody behind.
ready() {
    _t0=$(date +%s)
    while :; do
        [ "$(timeout 30 "$ENGINE" inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ] || return 1
        timeout 10 python3 -c 'import socket, ssl, sys
port, mode, ca = int(sys.argv[1]), sys.argv[2], sys.argv[3]
try:
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(5)
    if mode == "tls":
        ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname="wst.test").close()
    else:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        sys.exit(0 if s.recv(1) else 1)
except (OSError, ssl.SSLError):
    sys.exit(1)' "$2" "$4" "$W/ca.pem" && return 0
        [ $(($(date +%s) - _t0)) -lt "$3" ] || return 1
        sleep 1
    done
}
# The log of a container, with no line that holds the secret.
logs_of() {
    timeout 30 "$ENGINE" logs "$1" 2>&1 | grep -v -F -f "$W/secret.words" | tail -20
}
for c in plain:$PLAIN_PORT:http mask:$MASK_PORT:http tls:$TLS_PORT:tls hop:$HOP_PORT:http; do
    n=podssh-wst-${c%%:*}
    p=${c#*:}
    ready "$n" "${p%%:*}" 300 "${p#*:}" || { logs_of "$n"; die "$n did not answer"; }
done

TLS=wss://wst.test:$TLS_PORT
# The server's name is on the loopback, where its port is published; a name
# pinned to the loopback alone goes with no proxy.
PINS="wst.test=127.0.0.1"
SSH_OPTS="-i $W/key/id -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$W/kh -o BatchMode=yes"

# run NAME VERB ARGS...: podssh's VERB with the run's pin and CA, its outputs
# in $W/NAME.out and $W/NAME.err.
run() {
    _n=$1
    _v=$2
    shift 2
    env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" "$_v" --ca-file "$W/ca.pem" "$@" \
        </dev/null >"$W/$_n.out" 2>"$W/$_n.err"
}
# run_held NAME VERB ARGS...: as run, with stdin open for 3 s, as OpenSSH
# keeps a ProxyCommand's: an empty stdin could end the tunnel before the
# target's banner came back.
run_held() {
    _n=$1
    _v=$2
    shift 2
    sleep 3 | env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" "$_v" --ca-file "$W/ca.pem" "$@" \
        >"$W/$_n.out" 2>"$W/$_n.err"
}
banner() {
    case $(head -c 8 "$W/$1.out") in SSH-2.0-) return 0 ;; *) return 1 ;; esac
}

echo
echo "== --wstunnel: wstunnel $WSTUNNEL_VERSION's own server (T-441)"

run_held plain-banner proxy --wstunnel "ws://127.0.0.1:$PLAIN_PORT" sshd.test 22
rc=$?
banner plain-banner && ok wstunnel.banner "podssh proxy --wstunnel: sshd's banner through wstunnel (exit $rc)" ||
    bad wstunnel.banner "no banner through wstunnel: exit $rc" "$W/plain-banner.err"

# shellcheck disable=SC2086  # the options are words
run plain-ssh ssh -v --wstunnel "ws://127.0.0.1:$PLAIN_PORT" $SSH_OPTS root@sshd.test 'echo through-wstunnel'
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/plain-ssh.out")" = through-wstunnel ] &&
    grep -q 'the wstunnel server ws://127.0.0.1:[0-9]* carries the session' "$W/plain-ssh.err" &&
    ok wstunnel.session "a session through the server of wstunnel's defaults" ||
    bad wstunnel.session "a session through wstunnel: exit $rc" "$W/plain-ssh.err"

# 1 MiB each way: the frames of 32 KiB that podssh sends, and the larger
# ones of wstunnel, whose bytes must come back as they went.
head -c 1048576 /dev/urandom >"$W/mib"
want=$(sha256sum <"$W/mib" | cut -d' ' -f1)
# shellcheck disable=SC2086
env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" ssh --wstunnel "ws://127.0.0.1:$PLAIN_PORT" $SSH_OPTS \
    root@sshd.test cat <"$W/mib" >"$W/bulk.out" 2>"$W/bulk.err"
rc=$?
got=$(sha256sum <"$W/bulk.out" | cut -d' ' -f1)
[ "$rc" = 0 ] && [ "$got" = "$want" ] && ok wstunnel.bulk "1 MiB each way through wstunnel, equal digests" ||
    bad wstunnel.bulk "1 MiB through wstunnel: exit $rc, $(wc -c <"$W/bulk.out") bytes back" "$W/bulk.err"

# shellcheck disable=SC2086
run mask-ssh ssh --wstunnel "ws://127.0.0.1:$MASK_PORT" $SSH_OPTS root@sshd.test 'echo masked'
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/mask-ssh.out")" = masked ] &&
    ok wstunnel.mask "a session through a server that applies masks (--websocket-mask-frame)" ||
    bad wstunnel.mask "a session through the server that applies masks: exit $rc" "$W/mask-ssh.err"

run_held tls-banner proxy --wstunnel "$TLS" --wstunnel-secret-file "$W/secret" sshd.test 22
rc=$?
banner tls-banner && ok wstunnel.tls.banner "sshd's banner over wss:// with the path prefix and the credentials" ||
    bad wstunnel.tls.banner "no banner over wss://: exit $rc" "$W/tls-banner.err"

# shellcheck disable=SC2086
run tls-ssh ssh --wstunnel "$TLS" --wstunnel-secret-file "$W/secret" $SSH_OPTS root@sshd.test 'echo over-tls'
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/tls-ssh.out")" = over-tls ] &&
    ok wstunnel.tls.session "a session over wss://, checked for wst.test, with the secret" ||
    bad wstunnel.tls.session "a session over wss://: exit $rc" "$W/tls-ssh.err"

words='refused the tunnel: 400 Invalid request; the words of wstunnel 10 and later'
run tls-wrong proxy --wstunnel "$TLS" --wstunnel-secret-file "$W/secret-wrong" sshd.test 22
rc=$?
[ "$rc" = 77 ] && grep -q "$words" "$W/tls-wrong.err" &&
    ok wstunnel.wrong "a wrong path prefix: the server's 400, said in its version's words (exit 77)" ||
    bad wstunnel.wrong "a wrong path prefix: exit $rc" "$W/tls-wrong.err"

run tls-none proxy --wstunnel "$TLS" sshd.test 22
rc=$?
[ "$rc" = 77 ] && grep -q "$words" "$W/tls-none.err" &&
    ok wstunnel.none "no secret: the server's 400, said in its version's words (exit 77)" ||
    bad wstunnel.none "no secret: exit $rc" "$W/tls-none.err"

# The server's own log names the cause that its 400 does not.
logs_of podssh-wst-tls >"$W/tls-server.log"
grep -q 'Rejecting connection' "$W/tls-server.log" &&
    ok wstunnel.server-log "wstunnel's log names the refusal that podssh could only quote" ||
    bad wstunnel.server-log "no refusal in wstunnel's log" "$W/tls-server.log"

# The host's proxy carries the TLS to the server by its name, which the
# engine's network gives; no pin, so the proxy is asked.
# shellcheck disable=SC2086
HTTPS_PROXY=http://127.0.0.1:$HOP_PORT timeout 120 "$BIN" ssh -v --wstunnel wss://wst-tls.test:8443 \
    --wstunnel-secret-file "$W/secret" --ca-file "$W/ca.pem" $SSH_OPTS root@sshd.test 'echo hop' \
    </dev/null >"$W/hop.out" 2>"$W/hop.err"
rc=$?
asked=$(timeout 30 "$ENGINE" exec podssh-wst-hop cat /tmp/access.log 2>/dev/null | grep -c 'CONNECT wst-tls.test:8443')
[ "$rc" = 0 ] && [ "$(cat "$W/hop.out")" = hop ] && [ "${asked:-0}" -gt 0 ] &&
    ok wstunnel.hop "HTTPS_PROXY carries the TLS to the server by its name; the session runs inside" ||
    bad wstunnel.hop "through the host's proxy: exit $rc, $asked CONNECTs" "$W/hop.err"

leaked=$(grep -l -F -f "$W/secret.words" "$W"/*.out "$W"/*.err 2>/dev/null | wc -l)
[ "$leaked" = 0 ] && ok wstunnel.secret "no output of podssh holds the path prefix or the password" ||
    bad wstunnel.secret "$leaked outputs hold the secret"

echo "interop-wstunnel: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
