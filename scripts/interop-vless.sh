#!/bin/sh
# scripts/interop-vless.sh - `--vless`, VLESS servers in place of the relay
# (T-440, the operator's ruling Q66), against servers that podssh did not
# write, each in a container on a network of the run: Xray-core (VLESS over
# a WebSocket, and over XHTTP's three modes on HTTP/2), shoes (the same, in
# Rust), nginx in front of Xray-core as a front end that does not pass the
# WebSocket upgrade, OpenSSH's sshd as the target, and a plain squid as the
# host's own proxy (HTTPS_PROXY), which carries the TCP to a server by name.
#
#   sh scripts/interop-vless.sh PODSSH_BINARY
#
# Xray-core and shoes are their projects' own release binaries, pinned by
# version and SHA-256 and fetched first, in the open, so that a failure says
# why; each checks its configuration before it runs. images/box's Alpine runs
# them, and nginx, squid and sshd from its packages. The CA, the certificate
# of each server, the key of the session and the users' ID are made for the
# run in a directory that the run removes; the ID goes to podssh in files of
# mode 0600 alone, and no output may show it (vless.secret).
#
# The checks: a session over each transport of Xray-core, and over a
# WebSocket, packet-up and stream-one of shoes; sshd's banner through
# `podssh proxy`; another ID, said as the server's refusal (the plant of
# T-440, on the command line); a server of HTTP/1.1 alone, over packet-up on
# two connections, and its refusal of stream-one (T-456);
# behind nginx, the upgrade refused with the words that name XHTTP, and a
# session over packet-up; a session through the host's proxy; and the lines
# of `podssh doctor --vless`. Each prints a line of scripts/interop-lib.sh;
# the exit code is 0 when each passed, else 1, and 71 when the host lacks
# what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), openssl, python3, curl,
# tar and timeout; the ports PODSSH_VLESS_PORT (18460) to PODSSH_VLESS_PORT+6
# of the loopback free; and the releases on GitHub, through HTTPS_PROXY when
# it is set.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-vless.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_VLESS_PORT:-18460}
XRAY_WS=$PORT
XRAY_XH=$((PORT + 1))
XRAY_H1=$((PORT + 2))
SHOES_WS=$((PORT + 3))
SHOES_XH=$((PORT + 4))
NGINX=$((PORT + 5))
HOP=$((PORT + 6))
NET=podssh-vless-net
NAMES="podssh-vless-sshd podssh-vless-xray podssh-vless-shoes podssh-vless-nginx podssh-vless-hop"
# Xray-core's release of 2026-10-21, and the SHA-256 that its release lists
# for Xray-linux-64.zip (and its .dgst file), read on 2026-11-02.
XRAY_RELEASE=v26.10.21
XRAY_SHA256=0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978
# shoes's release of 2026-10-27, its static build for Linux, read the same day.
SHOES_RELEASE=v0.3.6
SHOES_SHA256=d09a9f5915ae8c3fc933bd86c025f2d8878d45e1dee8f0e2bb404c920de8c707

die() {
    echo "interop-vless: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in openssl python3 curl tar timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done

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

# image_of DOCKERFILE: the image that its FROM line pins to a digest.
image_of() {
    _ref=$(tr -d '\r' <"$1" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in *@sha256:*) PULL_ENGINE=$ENGINE sh "$HERE/pull-image.sh" "$_ref" ;; *) return 1 ;; esac
}
ALPINE=$(image_of "$REPO/images/box/Dockerfile") || die "Alpine's image did not pull"

# fetch URL SHA256 FILE: the release's file, whose digest must be the pin's.
fetch() {
    timeout 300 curl -fsSL --retry 2 -o "$3" "$1" >"$W/fetch.log" 2>&1 ||
        die "$1 did not come: $(tail -3 "$W/fetch.log")"
    _got=$(python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$3")
    [ "$_got" = "$2" ] || die "$1 has the SHA-256 $_got, not the pinned $2"
}
mkdir -p "$W/xray" "$W/shoes" "$W/nginx" "$W/hop" "$W/key" "$W/dl"
fetch "https://github.com/XTLS/Xray-core/releases/download/$XRAY_RELEASE/Xray-linux-64.zip" "$XRAY_SHA256" "$W/dl/xray.zip"
python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract("xray", sys.argv[2])' "$W/dl/xray.zip" "$W/xray" ||
    die "the zip of Xray-core holds no xray"
fetch "https://github.com/cfal/shoes/releases/download/$SHOES_RELEASE/shoes-x86_64-unknown-linux-musl.tar.gz" \
    "$SHOES_SHA256" "$W/dl/shoes.tar.gz"
tar -xzf "$W/dl/shoes.tar.gz" -C "$W/dl" shoes || die "the archive of shoes holds no shoes"
cp "$W/dl/shoes" "$W/shoes/shoes"
chmod 755 "$W/xray/xray" "$W/shoes/shoes"

# The CA of the run, and one certificate for each server's name.
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca_ext' 'prompt = no' '[dn]' \
    'CN = podssh vless test CA' '[ca_ext]' 'basicConstraints = critical,CA:TRUE' \
    'keyUsage = critical,keyCertSign,cRLSign' 'subjectKeyIdentifier = hash' >"$W/ca.cnf"
printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = xray.test' '[leaf]' \
    'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature' 'extendedKeyUsage = serverAuth' \
    'subjectAltName = DNS:xray.test,DNS:shoes.test,DNS:nginx.test' 'authorityKeyIdentifier = keyid' >"$W/leaf.cnf"
{
    timeout 60 openssl req -x509 -config "$W/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 &&
        timeout 60 openssl req -new -config "$W/leaf.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$W/server.key" -out "$W/server.csr" &&
        timeout 60 openssl x509 -req -in "$W/server.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
            -days 2 -extfile "$W/leaf.cnf" -extensions leaf -out "$W/server.pem"
} >"$W/openssl.log" 2>&1 || die "openssl could not make the certificates: $(tail -3 "$W/openssl.log")"
for d in xray shoes nginx; do cp "$W/server.pem" "$W/server.key" "$W/$d/"; done
# The servers read the key as their own users, in a directory of the run.
chmod 644 "$W/xray/server.key" "$W/shoes/server.key" "$W/nginx/server.key"

# The users' ID, made here and never printed, and another for the refusal.
umask 077
python3 -I -c 'import uuid; print(uuid.uuid4())' >"$W/id" || die "no ID"
python3 -I -c 'import uuid; print(uuid.uuid4())' >"$W/other-id" || die "no second ID"
ID=$(cat "$W/id")
umask 022
timeout 30 "$BIN" keygen -q -t ed25519 -N '' -f "$W/key/id" >/dev/null 2>&1 || die "podssh keygen failed"
chmod 644 "$W/key/id.pub"

# Xray-core: VLESS over a WebSocket and over XHTTP with TLS, XHTTP with
# HTTP/1.1 alone, and both with no TLS for nginx in front.
python3 -I - "$W/id" "$W/xray/config.json" <<'EOF'
import json, sys
uid, out = open(sys.argv[1]).read().strip(), sys.argv[2]
tls = lambda alpn: {"alpn": alpn, "certificates": [{"certificateFile": "/etc/xray/server.pem", "keyFile": "/etc/xray/server.key"}]}
def inbound(port, network, security, settings, alpn=None):
    stream = {"network": network, "security": security, network + "Settings": settings}
    if security == "tls":
        stream["tlsSettings"] = tls(alpn)
    return {"listen": "0.0.0.0", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": uid}], "decryption": "none"}, "streamSettings": stream}
# Xray-core's freedom blackholes a private address for a VLESS inbound
# unless a final rule allows it (proxy/freedom/freedom.go); sshd.test is one.
private = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
freedom = {"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": private}]}}
config = {"log": {"loglevel": "warning"}, "outbounds": [freedom], "inbounds": [
    inbound(8443, "ws", "tls", {"path": "/ws"}, ["http/1.1"]),
    inbound(8444, "xhttp", "tls", {"path": "/xh", "mode": "auto"}, ["h2", "http/1.1"]),
    inbound(8447, "xhttp", "tls", {"path": "/xh"}, ["http/1.1"]),
    inbound(8445, "xhttp", "none", {"path": "/xh"}),
    inbound(8446, "ws", "none", {"path": "/ws"}),
]}
json.dump(config, open(out, "w"), indent=1)
EOF
# shoes: a WebSocket and XHTTP, each inside TLS.
cat >"$W/shoes/config.yaml" <<EOF
- address: "0.0.0.0:9443"
  protocol:
    type: tls
    default_target:
      cert: /etc/shoes/server.pem
      key: /etc/shoes/server.key
      protocol:
        type: ws
        targets:
          - matching_path: /ws
            protocol:
              type: vless
              user_id: "$ID"
- address: "0.0.0.0:9444"
  protocol:
    type: tls
    default_target:
      cert: /etc/shoes/server.pem
      key: /etc/shoes/server.key
      alpn_protocols: [h2, http/1.1]
      protocol:
        type: xhttp
        path: /xh
        mode: auto
        protocol:
          type: vless
          user_id: "$ID"
EOF
# nginx over TLS and HTTP/2 in front of Xray-core's servers with no TLS. Its
# /ws does not pass the upgrade (no Upgrade header goes on), as a front end
# that proxies HTTP alone; its /xh/ streams the answers and the bodies.
cat >"$W/nginx/nginx.conf" <<'EOF'
worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/nginx.pid;
events { worker_connections 64; }
http {
    access_log /dev/stdout;
    server {
        listen 8443 ssl;
        http2 on;
        server_name nginx.test;
        ssl_certificate /etc/podssh-nginx/server.pem;
        ssl_certificate_key /etc/podssh-nginx/server.key;
        location /xh/ {
            proxy_pass http://xray.test:8445;
            proxy_http_version 1.1;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_read_timeout 300s;
        }
        location /ws {
            proxy_pass http://xray.test:8446;
            proxy_http_version 1.1;
        }
    }
}
EOF
chmod 644 "$W/xray/config.json" "$W/shoes/config.yaml" "$W/nginx/nginx.conf"
# Squid writes its logs as its own user: they go to /tmp, and `exec cat` reads them.
printf '%s\n' 'http_port 3128' 'http_access allow all' 'cache deny all' 'access_log stdio:/tmp/access.log' \
    'cache_log /tmp/cache.log' 'pid_filename none' 'logfile_rotate 0' 'coredump_dir /tmp' >"$W/hop/squid.conf"
chmod 644 "$W/hop/squid.conf"

# Each server checks its configuration first, in the open, so that a
# failure prints why.
timeout 120 "$ENGINE" run --rm -v "$W/xray:/etc/xray:ro" "$ALPINE" /etc/xray/xray run -test -c /etc/xray/config.json \
    >"$W/xray-test.log" 2>&1 || die "Xray-core refused its configuration: $(tail -8 "$W/xray-test.log")"
timeout 120 "$ENGINE" run --rm -v "$W/shoes:/etc/shoes:ro" "$ALPINE" /etc/shoes/shoes --dry-run /etc/shoes/config.yaml \
    >"$W/shoes-test.log" 2>&1 || die "shoes refused its configuration: $(tail -8 "$W/shoes-test.log")"

timeout 60 "$ENGINE" network create "$NET" >/dev/null || die "the network $NET could not be made"
timeout 300 "$ENGINE" run -d --name podssh-vless-sshd --network "$NET" --network-alias sshd.test \
    -v "$W/key:/k:ro" "$ALPINE" sh -c 'apk add --no-cache openssh-server >/dev/null &&
    ssh-keygen -A >/dev/null && mkdir -p /root/.ssh && cp /k/id.pub /root/.ssh/authorized_keys &&
    chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && sed -i "s/^root:[^:]*:/root:*:/" /etc/shadow &&
    exec /usr/sbin/sshd -D -e' >/dev/null || die "sshd did not start"
timeout 300 "$ENGINE" run -d --name podssh-vless-xray --network "$NET" --network-alias xray.test \
    -p "127.0.0.1:$XRAY_WS:8443" -p "127.0.0.1:$XRAY_XH:8444" -p "127.0.0.1:$XRAY_H1:8447" \
    -v "$W/xray:/etc/xray:ro" "$ALPINE" /etc/xray/xray run -c /etc/xray/config.json >/dev/null ||
    die "Xray-core did not start"
timeout 300 "$ENGINE" run -d --name podssh-vless-shoes --network "$NET" --network-alias shoes.test \
    -p "127.0.0.1:$SHOES_WS:9443" -p "127.0.0.1:$SHOES_XH:9444" -v "$W/shoes:/etc/shoes:ro" "$ALPINE" \
    /etc/shoes/shoes --no-reload /etc/shoes/config.yaml >/dev/null || die "shoes did not start"
timeout 300 "$ENGINE" run -d --name podssh-vless-hop --network "$NET" -p "127.0.0.1:$HOP:3128" \
    -v "$W/hop:/etc/podssh-squid:ro" "$ALPINE" sh -c 'apk add --no-cache squid >/dev/null &&
    exec squid -N -f /etc/podssh-squid/squid.conf' >/dev/null || die "the host's squid did not start"

# ready NAME PORT SECONDS MODE: the container NAME runs, and the loopback's
# PORT answers within SECONDS: a TLS handshake with the run's CA (tls), or
# bytes back for a request (http). A TCP connection alone proves nothing: an
# engine's own proxy of a published port takes it with nobody behind.
ready() {
    _t0=$(date +%s)
    while :; do
        [ "$(timeout 30 "$ENGINE" inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ] || return 1
        timeout 10 python3 -I -c 'import socket, ssl, sys
port, mode, ca = int(sys.argv[1]), sys.argv[2], sys.argv[3]
try:
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(5)
    if mode == "tls":
        ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname="xray.test").close()
    else:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        sys.exit(0 if s.recv(1) else 1)
except (OSError, ssl.SSLError):
    sys.exit(1)' "$2" "$4" "$W/ca.pem" && return 0
        [ $(($(date +%s) - _t0)) -lt "$3" ] || return 1
        sleep 1
    done
}
logs() {
    timeout 30 "$ENGINE" logs "$1" 2>&1 | tail -20
}
for p in "$XRAY_WS" "$XRAY_XH" "$XRAY_H1"; do
    ready podssh-vless-xray "$p" 120 tls || { logs podssh-vless-xray; die "Xray-core did not answer TLS on $p"; }
done
for p in "$SHOES_WS" "$SHOES_XH"; do
    ready podssh-vless-shoes "$p" 120 tls || { logs podssh-vless-shoes; die "shoes did not answer TLS on $p"; }
done
# nginx resolves Xray-core's name as it starts, so it starts once Xray-core answers.
timeout 300 "$ENGINE" run -d --name podssh-vless-nginx --network "$NET" --network-alias nginx.test \
    -p "127.0.0.1:$NGINX:8443" -v "$W/nginx:/etc/podssh-nginx:ro" "$ALPINE" sh -c 'apk add --no-cache nginx >/dev/null &&
    exec nginx -c /etc/podssh-nginx/nginx.conf -g "daemon off;"' >/dev/null || die "nginx did not start"
ready podssh-vless-nginx "$NGINX" 300 tls || { logs podssh-vless-nginx; die "nginx did not answer TLS"; }
ready podssh-vless-hop "$HOP" 300 http ||
    { timeout 30 "$ENGINE" exec podssh-vless-hop cat /tmp/cache.log 2>/dev/null | tail -20; die "squid did not answer"; }

# The servers' names are on the loopback, where their ports are published;
# a name pinned to the loopback alone goes with no proxy.
PINS="xray.test=127.0.0.1,shoes.test=127.0.0.1,nginx.test=127.0.0.1"
SSH_OPTS="-i $W/key/id -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$W/kh -o BatchMode=yes"

# links NAME ID HOST:PORT QUERY: a file of one share link, of mode 0600.
links() {
    umask 077
    printf 'vless://%s@%s?security=tls&%s#%s\n' "$2" "$3" "$4" "$1" >"$W/$1.links"
    umask 022
}
links xray-ws "$ID" "xray.test:$XRAY_WS" 'type=ws&path=%2Fws'
links xray-packet-up "$ID" "xray.test:$XRAY_XH" 'type=xhttp&path=%2Fxh&mode=packet-up'
links xray-stream-up "$ID" "xray.test:$XRAY_XH" 'type=xhttp&path=%2Fxh&mode=stream-up'
links xray-stream-one "$ID" "xray.test:$XRAY_XH" 'type=xhttp&path=%2Fxh&mode=stream-one'
links xray-auto "$ID" "xray.test:$XRAY_XH" 'type=xhttp&path=%2Fxh'
links xray-http1 "$ID" "xray.test:$XRAY_H1" 'type=xhttp&path=%2Fxh'
links xray-http1-one "$ID" "xray.test:$XRAY_H1" 'type=xhttp&path=%2Fxh&mode=stream-one'
links xray-other "$(cat "$W/other-id")" "xray.test:$XRAY_WS" 'type=ws&path=%2Fws'
links shoes-ws "$ID" "shoes.test:$SHOES_WS" 'type=ws&path=%2Fws'
links shoes-packet-up "$ID" "shoes.test:$SHOES_XH" 'type=xhttp&path=%2Fxh&mode=packet-up'
links shoes-stream-one "$ID" "shoes.test:$SHOES_XH" 'type=xhttp&path=%2Fxh&mode=stream-one'
links nginx-ws "$ID" "nginx.test:$NGINX" 'type=ws&path=%2Fws'
links nginx-packet-up "$ID" "nginx.test:$NGINX" 'type=xhttp&path=%2Fxh&mode=packet-up'
links hop "$ID" "xray.test:8444" 'type=xhttp&path=%2Fxh&mode=packet-up'

# session NAME: podssh ssh through the link NAME, its outputs in $W/NAME.*.
session() {
    # shellcheck disable=SC2086  # the options are words
    env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" ssh -v --ca-file "$W/ca.pem" --vless "$W/$1.links" $SSH_OPTS \
        root@sshd.test "echo through-$1" </dev/null >"$W/$1.out" 2>"$W/$1.err"
}
# carried NAME HOW: the session of NAME ran, and -v named HOW.
carried() {
    session "$1"
    _rc=$?
    [ "$_rc" = 0 ] && [ "$(cat "$W/$1.out")" = "through-$1" ] && grep -q "carries the session to sshd.test:22 over $2" \
        "$W/$1.err"
}

echo
echo "== --vless: Xray-core, shoes, and nginx in front (T-440)"

carried xray-ws 'a WebSocket' && ok vless.xray.ws "a session to Xray-core over a WebSocket" ||
    bad vless.xray.ws "a session over a WebSocket" "$W/xray-ws.err"
carried xray-stream-one 'XHTTP stream-one over HTTP/2' &&
    ok vless.xray.stream-one "a session to Xray-core over XHTTP stream-one on HTTP/2" ||
    bad vless.xray.stream-one "a session over stream-one" "$W/xray-stream-one.err"
carried xray-stream-up 'XHTTP stream-up over HTTP/2' &&
    ok vless.xray.stream-up "a session to Xray-core over XHTTP stream-up on HTTP/2" ||
    bad vless.xray.stream-up "a session over stream-up" "$W/xray-stream-up.err"
carried xray-packet-up 'XHTTP packet-up over HTTP/2' &&
    ok vless.xray.packet-up "a session to Xray-core over XHTTP packet-up on HTTP/2" ||
    bad vless.xray.packet-up "a session over packet-up" "$W/xray-packet-up.err"

# As OpenSSH keeps a ProxyCommand's stdin open, so does this pipe, for 3 s.
sleep 3 | env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" proxy --ca-file "$W/ca.pem" --vless "$W/xray-ws.links" \
    sshd.test 22 >"$W/banner.out" 2>"$W/banner.err"
rc=$?
case $(head -c 8 "$W/banner.out") in SSH-2.0-) b=yes ;; *) b=no ;; esac
[ "$b" = yes ] && ok vless.xray.banner "podssh proxy --vless: sshd's banner through Xray-core (exit $rc)" ||
    bad vless.xray.banner "no banner through Xray-core: exit $rc" "$W/banner.err"

session xray-other
rc=$?
# ssh exits 255 for a first hop that it did not reach, as OpenSSH does; the
# line says why.
[ "$rc" = 255 ] && grep -q "before VLESS's answer: it refused the ID" "$W/xray-other.err" &&
    ok vless.xray.wrong-id "another ID: Xray-core's refusal is said (exit 255)" ||
    bad vless.xray.wrong-id "another ID: exit $rc" "$W/xray-other.err"

# A server of HTTP/1.1 alone carries packet-up on two connections (Q67,
# T-456), and refuses stream-one with its words.
carried xray-http1 'XHTTP packet-up over HTTP/1.1 on two connections' &&
    ok vless.xray.http1 "a session to Xray-core of HTTP/1.1 alone over packet-up on two connections" ||
    bad vless.xray.http1 "a session to a server of HTTP/1.1 alone" "$W/xray-http1.err"
session xray-http1-one
rc=$?
[ "$rc" = 255 ] && grep -q 'stream-one cannot go over HTTP/1.1' "$W/xray-http1-one.err" &&
    ok vless.xray.http1-one "stream-one to a server of HTTP/1.1 alone is refused with its words (exit 255)" ||
    bad vless.xray.http1-one "stream-one to a server of HTTP/1.1 alone: exit $rc" "$W/xray-http1-one.err"

carried shoes-ws 'a WebSocket' && ok vless.shoes.ws "a session to shoes over a WebSocket" ||
    bad vless.shoes.ws "a session to shoes over a WebSocket" "$W/shoes-ws.err"
carried shoes-packet-up 'XHTTP packet-up over HTTP/2' &&
    ok vless.shoes.packet-up "a session to shoes over XHTTP packet-up on HTTP/2" ||
    bad vless.shoes.packet-up "a session to shoes over packet-up" "$W/shoes-packet-up.err"
carried shoes-stream-one 'XHTTP stream-one over HTTP/2' &&
    ok vless.shoes.stream-one "a session to shoes over XHTTP stream-one on HTTP/2" ||
    bad vless.shoes.stream-one "a session to shoes over stream-one" "$W/shoes-stream-one.err"

session nginx-ws
rc=$?
[ "$rc" = 255 ] && grep -q 'type=xhttp passes where the upgrade does not' "$W/nginx-ws.err" &&
    ok vless.nginx.upgrade-refused "behind nginx, the refused upgrade names XHTTP as the way past it (exit 255)" ||
    bad vless.nginx.upgrade-refused "the upgrade through nginx: exit $rc" "$W/nginx-ws.err"
carried nginx-packet-up 'XHTTP packet-up over HTTP/2' &&
    ok vless.nginx.packet-up "behind nginx, which refuses the upgrade, a session over packet-up" ||
    bad vless.nginx.packet-up "a session over packet-up through nginx" "$W/nginx-packet-up.err"

# The host's proxy carries the TCP to Xray-core by its name, which the
# engine's names give inside the network; no pin, so the proxy is asked.
# shellcheck disable=SC2086
HTTPS_PROXY=http://127.0.0.1:$HOP timeout 120 "$BIN" ssh -v --ca-file "$W/ca.pem" --vless "$W/hop.links" $SSH_OPTS \
    root@sshd.test 'echo hop' </dev/null >"$W/hop.out" 2>"$W/hop.err"
rc=$?
asked=$(timeout 30 "$ENGINE" exec podssh-vless-hop cat /tmp/access.log 2>/dev/null | grep -c 'CONNECT xray.test:8444')
[ "$rc" = 0 ] && [ "$(cat "$W/hop.out")" = hop ] && [ "${asked:-0}" -gt 0 ] &&
    ok vless.hop "HTTPS_PROXY carries the TCP to Xray-core by its name; packet-up runs inside" ||
    bad vless.hop "through the host's proxy: exit $rc, $asked CONNECTs" "$W/hop.err"

env PODSSH_RELAY_ADDR="$PINS" timeout 300 "$BIN" doctor --ca-file "$W/ca.pem" --vless "$W/xray-auto.links" \
    </dev/null >"$W/doctor.out" 2>"$W/doctor.err"
n=$(grep 'over XHTTP \(packet-up\|stream-up\|stream-one\) over HTTP/2, answered in' "$W/doctor.out" |
    grep -c "one of GitHub's published keys")
if [ "${n:-0}" = 3 ]; then
    ok vless.doctor "podssh doctor --vless names each mode of XHTTP that carried a session to GitHub"
elif grep -q 'could not reach the target' "$W/doctor.out"; then
    unmet vless.doctor "Xray-core has no route to github.com:22, which doctor's lines ask for"
else
    bad vless.doctor "not a line for each mode of the section vless" "$W/doctor.out"
fi

leaked=$(grep -l -F -f "$W/id" "$W"/*.out "$W"/*.err 2>/dev/null | wc -l)
[ "$leaked" = 0 ] && ok vless.secret "no output of podssh holds the users' ID" ||
    bad vless.secret "$leaked outputs hold the ID"

echo "interop-vless: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
