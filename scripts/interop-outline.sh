#!/bin/sh
# scripts/interop-outline.sh - `--shadowsocks` with an Outline access key
# (T-493, the operator's ruling Q66), against OutlineFoundation's own
# outline-ss-server of a pinned release, its listener websocket-stream on a
# path made for the run, behind nginx with TLS as Outline's documents put
# Caddy in front of it; nginx also serves the access keys (`ssconf://`) over
# HTTPS; a plain squid is the host's own proxy (HTTPS_PROXY).
#
#   sh scripts/interop-outline.sh PODSSH_BINARY
#
# The release is fetched from GitHub and checked by the SHA-256 of its
# checksums.txt (or taken from PODSSH_OUTLINE_TGZ, a copy of the same
# file); its Linux binary is static, and runs on images/box's Alpine, which
# also runs nginx and squid from its packages. outline-ss-server dials no
# private address (`onet.RequirePublicIP`, service/tcp.go at v1.9.2), so the
# target is GitHub's SSH endpoint, whose banner comes back; a private target
# is refused by the server, and podssh names that. The CA, the certificate,
# the secret and the path are made for the run in a directory that the run
# removes; podssh reads the keys by their URLs alone, and no output may
# show the secret or the path.
#
# The checks: the pinned version runs; GitHub's banner through `proxy` in
# the WebSocket; a private target refused; a wrong path (404), an upgrade
# that the front refuses (403) and a wrong secret, each named; the host's
# squid carrying the key's fetch and the WebSocket by their name; and no
# output holding the secret or the path. Each prints a line of
# scripts/interop-lib.sh; the exit code is 0 when each passed, else 1, and
# 71 when the host lacks what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), curl (unless
# PODSSH_OUTLINE_TGZ), tar, openssl, python3, sha256sum and timeout; the
# ports PODSSH_OUTLINE_PORT (18470) and PODSSH_OUTLINE_PORT+1 of the
# loopback free; and a way out to github.com:22 from the containers.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-outline.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_OUTLINE_PORT:-18470}
TLS_PORT=$PORT
HOP_PORT=$((PORT + 1))
NET=podssh-outline-net
NAMES="podssh-outline-check podssh-outline-ss podssh-outline-tls podssh-outline-hop"
# outline-ss-server's release read for T-493 (2026-11-06), and the SHA-256
# of each Linux archive, from its release's checksums.txt.
OUTLINE_VERSION=1.9.2
SHA_AMD64=6166cb676334e9f8a3296621d6a29b0e0cce36e4b0a72600b3309b07a21f5b8c
SHA_ARM64=2c1a7b6230263be398c779df4b7fb4e76427c23a0c351b6e67750e7d9a860c26

die() {
    echo "interop-outline: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in tar openssl python3 sha256sum timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done
case $(uname -m) in
    x86_64 | amd64) ARCH=x86_64 SHA=$SHA_AMD64 ;;
    aarch64 | arm64) ARCH=arm64 SHA=$SHA_ARM64 ;;
    *) die "no pinned outline-ss-server for $(uname -m)" ;;
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

TGZ=outline-ss-server_${OUTLINE_VERSION}_linux_${ARCH}.tar.gz
URL=https://github.com/OutlineFoundation/outline-ss-server/releases/download/v$OUTLINE_VERSION/$TGZ
if [ -n "${PODSSH_OUTLINE_TGZ:-}" ]; then
    cp "$PODSSH_OUTLINE_TGZ" "$W/$TGZ" || die "PODSSH_OUTLINE_TGZ cannot be read"
else
    command -v curl >/dev/null 2>&1 || die "curl is missing (or give PODSSH_OUTLINE_TGZ)"
    timeout 300 curl -fsSL --retry 3 --max-time 240 -o "$W/$TGZ" "$URL" >"$W/fetch.log" 2>&1 ||
        die "outline-ss-server's release did not download from $URL: $(tail -5 "$W/fetch.log")"
fi
got=$(sha256sum "$W/$TGZ" | cut -d' ' -f1)
[ "$got" = "$SHA" ] || die "$TGZ has the SHA-256 $got, not the pinned $SHA"
mkdir -p "$W/o" && tar -xzf "$W/$TGZ" -C "$W/o" outline-ss-server || die "$TGZ does not unpack"
chmod 755 "$W/o/outline-ss-server"

image_of() {
    _ref=$(tr -d '\r' <"$1" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in *@sha256:*) PULL_ENGINE=$ENGINE sh "$HERE/pull-image.sh" "$_ref" ;; *) return 1 ;; esac
}
ALPINE=$(image_of "$REPO/images/box/Dockerfile") || die "Alpine's image did not pull"

# The CA of the run, and nginx's certificate for outline.test, its name on
# the loopback, and outline-tls.test, its name on the run's network.
mkdir -p "$W/tls" "$W/conf" "$W/keys" "$W/hop" "$W/cache"
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca_ext' 'prompt = no' '[dn]' \
    'CN = podssh outline test CA' '[ca_ext]' 'basicConstraints = critical,CA:TRUE' \
    'keyUsage = critical,keyCertSign,cRLSign' 'subjectKeyIdentifier = hash' >"$W/ca.cnf"
printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = outline.test' '[leaf]' \
    'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature' 'extendedKeyUsage = serverAuth' \
    'subjectAltName = DNS:outline.test,DNS:outline-tls.test' 'authorityKeyIdentifier = keyid' >"$W/leaf.cnf"
{
    timeout 60 openssl req -x509 -config "$W/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 &&
        timeout 60 openssl req -new -config "$W/leaf.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$W/tls/outline.key" -out "$W/outline.csr" &&
        timeout 60 openssl x509 -req -in "$W/outline.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
            -days 2 -extfile "$W/leaf.cnf" -extensions leaf -out "$W/tls/outline.pem"
} >"$W/openssl.log" 2>&1 || die "openssl could not make the certificates: $(tail -3 "$W/openssl.log")"
chmod 644 "$W/tls/outline.key"

# The secret and the path, made here and never printed.
secret=$(openssl rand -hex 16) || die "no secret"
path=$(openssl rand -hex 12) || die "no path"
printf '%s\n%s\n' "$secret" "$path" >"$W/secret.words"
printf '%s\n' 'web:' '  servers:' '    - id: web' '      listen:' '        - "0.0.0.0:8000"' 'services:' \
    '  - listeners:' '      - type: websocket-stream' '        web_server: web' "        path: \"/$path/tcp\"" \
    '    keys:' '      - id: podssh' '        cipher: chacha20-ietf-poly1305' "        secret: $secret" \
    >"$W/conf/config.yml"
chmod 644 "$W/conf/config.yml"
# key NAME HOST PATH SECRET: an access key of Outline's YAML, served by nginx.
key() {
    printf '%s\n' 'transport:' '  $type: tcpudp' '  tcp:' '    $type: shadowsocks' '    endpoint:' \
        '      $type: websocket' "      url: wss://$2/$3/tcp" '    cipher: chacha20-ietf-poly1305' \
        "    secret: $4" >"$W/keys/$1.yml"
    chmod 644 "$W/keys/$1.yml"
}
key good "outline.test:$TLS_PORT" "$path" "$secret"
key wrong-path "outline.test:$TLS_PORT" wrong "$secret"
key refused "outline.test:$TLS_PORT" forbidden "$secret"
key wrong-secret "outline.test:$TLS_PORT" "$path" "$secret-wrong"
key hop outline-tls.test:8443 "$path" "$secret"
cat >"$W/conf/nginx.conf" <<'EOF'
worker_processes 1;
error_log /tmp/error.log;
pid /tmp/nginx.pid;
events {}
http {
    access_log /tmp/access.log;
    server {
        listen 8443 ssl;
        ssl_certificate /etc/podssh-outline/tls/outline.pem;
        ssl_certificate_key /etc/podssh-outline/tls/outline.key;
        location /keys/ { root /srv; }
        location /forbidden/ { return 403; }
        location / {
            proxy_pass http://outline-ss.test:8000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 300s;
        }
    }
}
EOF
chmod 644 "$W/conf/nginx.conf"
printf '%s\n' 'http_port 3128' 'http_access allow all' 'cache deny all' 'access_log stdio:/tmp/access.log' \
    'cache_log /tmp/cache.log' 'pid_filename none' 'logfile_rotate 0' 'coredump_dir /tmp' >"$W/hop/squid.conf"

timeout 120 "$ENGINE" run --name podssh-outline-check -v "$W/o:/o:ro" "$ALPINE" /o/outline-ss-server -version \
    >"$W/version.log" 2>&1
rc=$?
timeout 60 "$ENGINE" rm -f podssh-outline-check >/dev/null 2>&1
grep -q "$OUTLINE_VERSION" "$W/version.log" &&
    ok outline.version "outline-ss-server $OUTLINE_VERSION runs on Alpine: $(head -1 "$W/version.log")" ||
    bad outline.version "the pinned outline-ss-server did not say $OUTLINE_VERSION: exit $rc" "$W/version.log"

timeout 60 "$ENGINE" network create "$NET" >/dev/null || die "the network $NET could not be made"
timeout 300 "$ENGINE" run -d --name podssh-outline-ss --network "$NET" --network-alias outline-ss.test \
    -v "$W/o:/o:ro" -v "$W/conf:/etc/podssh-outline:ro" "$ALPINE" \
    /o/outline-ss-server -config /etc/podssh-outline/config.yml >/dev/null || die "outline-ss-server did not start"
timeout 300 "$ENGINE" run -d --name podssh-outline-tls --network "$NET" --network-alias outline-tls.test \
    -p "127.0.0.1:$TLS_PORT:8443" -v "$W/conf:/etc/podssh-outline:ro" -v "$W/tls:/etc/podssh-outline/tls:ro" \
    -v "$W/keys:/srv/keys:ro" "$ALPINE" sh -c 'apk add --no-cache nginx >/dev/null &&
    exec nginx -c /etc/podssh-outline/nginx.conf -g "daemon off;"' >/dev/null || die "nginx did not start"
timeout 300 "$ENGINE" run -d --name podssh-outline-hop --network "$NET" -p "127.0.0.1:$HOP_PORT:3128" \
    -v "$W/hop:/etc/podssh-squid:ro" "$ALPINE" \
    sh -c 'apk add --no-cache squid >/dev/null && exec squid -N -f /etc/podssh-squid/squid.conf' >/dev/null ||
    die "the host's squid did not start"

# ready PORT SECONDS MODE: the loopback's PORT answers a TLS handshake with
# the run's CA, or bytes for a request.
ready() {
    _t0=$(date +%s)
    while :; do
        timeout 10 python3 -c 'import socket, ssl, sys
port, mode, ca = int(sys.argv[1]), sys.argv[2], sys.argv[3]
try:
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(5)
    if mode == "tls":
        ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname="outline.test").close()
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
ready "$TLS_PORT" 300 tls || { logs_of podssh-outline-tls; die "nginx did not answer"; }
ready "$HOP_PORT" 300 http || { logs_of podssh-outline-hop; die "the host's squid did not answer"; }

umask 077
for name in good wrong-path refused wrong-secret; do
    printf '# the run of T-493\nssconf://outline.test:%s/keys/%s.yml#%s\n' "$TLS_PORT" "$name" "$name" >"$W/$name.list"
done
printf 'ssconf://outline-tls.test:8443/keys/hop.yml#hop\n' >"$W/hop.list"
umask 022

PINS="outline.test=127.0.0.1"
# run NAME LIST TARGET PORT: podssh proxy through the key of LIST, its stdin
# held open a while, as an SSH client's is until the banner comes.
run() {
    sleep 3 | env PODSSH_RELAY_ADDR="$PINS" PODSSH_CACHE_DIR="$W/cache" PODSSH_SETTINGS=none timeout 120 \
        "$BIN" proxy --ca-file "$W/ca.pem" --shadowsocks "$W/$2.list" "$3" "$4" >"$W/$1.out" 2>"$W/$1.err"
}

echo
echo "== --shadowsocks: an Outline key, outline-ss-server $OUTLINE_VERSION in a WebSocket (T-493)"

run banner good github.com 22
rc=$?
case $(head -c 8 "$W/banner.out") in
    SSH-2.0-) ok outline.banner "github.com:22's banner through outline-ss-server's WebSocket (exit $rc)" ;;
    *) bad outline.banner "no banner through the WebSocket: exit $rc" "$W/banner.err" ;;
esac

run private good 127.0.0.1 22
rc=$?
[ "$rc" = 69 ] && grep -q 'cannot reach 127.0.0.1:22' "$W/private.err" &&
    ok outline.private "a private target: the server dials none, and podssh names the cause (exit 69)" ||
    bad outline.private "a private target: exit $rc" "$W/private.err"

run wrong-path wrong-path github.com 22
rc=$?
[ "$rc" = 69 ] && grep -q "has no WebSocket at the key's path (HTTP 404)" "$W/wrong-path.err" &&
    ok outline.wrong-path "a path that is not the server's: named, its path not shown (exit 69)" ||
    bad outline.wrong-path "a wrong path: exit $rc" "$W/wrong-path.err"

run refused refused github.com 22
rc=$?
[ "$rc" = 69 ] && grep -q 'refused the upgrade: HTTP 403' "$W/refused.err" &&
    ok outline.refused "an upgrade that the TLS front refuses: named (exit 69)" ||
    bad outline.refused "a refused upgrade: exit $rc" "$W/refused.err"

run wrong-secret wrong-secret github.com 22
rc=$?
[ "$rc" = 69 ] && grep -q "the password or the method may not be the server's" "$W/wrong-secret.err" &&
    ok outline.wrong-secret "a secret that is not the server's: named (exit 69)" ||
    bad outline.wrong-secret "a wrong secret: exit $rc" "$W/wrong-secret.err"

sleep 3 | env HTTPS_PROXY="http://127.0.0.1:$HOP_PORT" PODSSH_CACHE_DIR="$W/cache-hop" PODSSH_SETTINGS=none \
    timeout 120 "$BIN" proxy --ca-file "$W/ca.pem" --shadowsocks "$W/hop.list" github.com 22 \
    >"$W/hop.out" 2>"$W/hop.err"
rc=$?
asked=$(timeout 30 "$ENGINE" exec podssh-outline-hop cat /tmp/access.log 2>/dev/null | grep -c 'CONNECT outline-tls.test:8443')
[ "$(head -c 8 "$W/hop.out")" = SSH-2.0- ] && [ "${asked:-0}" -ge 2 ] &&
    ok outline.hop "HTTPS_PROXY carries the key's fetch and the WebSocket by their name; the banner comes back" ||
    bad outline.hop "through the host's proxy: exit $rc, $asked CONNECTs" "$W/hop.err"

leaked=$(grep -l -F -f "$W/secret.words" "$W"/*.out "$W"/*.err 2>/dev/null | wc -l)
[ "$leaked" = 0 ] && ok outline.secret "no output of podssh holds the secret or the path" ||
    bad outline.secret "$leaked outputs hold the secret or the path"

echo "interop-outline: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
