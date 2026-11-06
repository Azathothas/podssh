#!/bin/sh
# scripts/interop-trojan.sh - `--trojan`, Trojan servers in place of the
# relay (T-491, the operator's ruling Q66), against servers that podssh did
# not write, each in a container on a network of the run: Xray-core's own
# trojan inbound in TLS alone and in a WebSocket over TLS, OpenSSH's sshd as
# the target, and a plain squid as the host's own proxy (HTTPS_PROXY), which
# carries the TCP to a server by name. trojan-gfw's and trojan-go's own servers
# are T-693's, once their releases' SHA-256 are read from their pages.
#
#   sh scripts/interop-trojan.sh PODSSH_BINARY
#
# Xray-core is the release that scripts/interop-vless.sh pins, by its
# SHA-256. images/box's Alpine runs it, and squid and sshd from its packages.
# The CA, the certificate, the key of the session and the password are made
# for the run in a directory that the run removes; the password goes to
# podssh in files of mode 0600 alone, and no output may show it or its hash
# (trojan.secret).
#
# The checks: a session in TLS alone and in a WebSocket, each with -v naming
# what carried it; sshd's banner through `podssh proxy`; another password,
# which Xray-core ends with no fallback (the plant of T-491, the hash in
# upper case, fails the sessions); a wrong path, the upgrade's 404; a session
# through the host's proxy; and no output with the password. Each prints a
# line of scripts/interop-lib.sh; the exit code is 0 when each passed, else
# 1, and 71 when the host lacks what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), openssl, python3, curl and
# timeout; the ports PODSSH_TROJAN_PORT (18470) to PODSSH_TROJAN_PORT+4 of
# the loopback free; and the releases on GitHub, through HTTPS_PROXY when it
# is set.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-trojan.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_TROJAN_PORT:-18470}
XRAY_TLS=$PORT
XRAY_WS=$((PORT + 1))
HOP=$((PORT + 2))
NET=podssh-trojan-net
NAMES="podssh-trojan-sshd podssh-trojan-xray podssh-trojan-hop"
# The release of Xray-core that interop-vless.sh pins, read from it.
XRAY_RELEASE=$(sed -n 's/^XRAY_RELEASE=//p' "$HERE/interop-vless.sh")
XRAY_SHA256=$(sed -n 's/^XRAY_SHA256=//p' "$HERE/interop-vless.sh")

die() {
    echo "interop-trojan: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in openssl python3 curl timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done
[ -n "$XRAY_RELEASE" ] && [ -n "$XRAY_SHA256" ] || die "scripts/interop-vless.sh pins no Xray-core"

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
mkdir -p "$W/xray" "$W/hop" "$W/key" "$W/dl"
fetch "https://github.com/XTLS/Xray-core/releases/download/$XRAY_RELEASE/Xray-linux-64.zip" "$XRAY_SHA256" "$W/dl/xray.zip"
python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract("xray", sys.argv[2])' "$W/dl/xray.zip" "$W/xray" ||
    die "the zip of Xray-core holds no xray"
chmod 755 "$W/xray/xray"

# The CA of the run, and a certificate for the server's name.
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca_ext' 'prompt = no' '[dn]' \
    'CN = podssh trojan test CA' '[ca_ext]' 'basicConstraints = critical,CA:TRUE' \
    'keyUsage = critical,keyCertSign,cRLSign' 'subjectKeyIdentifier = hash' >"$W/ca.cnf"
printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = trojan.test' '[leaf]' \
    'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature' 'extendedKeyUsage = serverAuth' \
    'subjectAltName = DNS:trojan.test' 'authorityKeyIdentifier = keyid' >"$W/leaf.cnf"
{
    timeout 60 openssl req -x509 -config "$W/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 &&
        timeout 60 openssl req -new -config "$W/leaf.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$W/server.key" -out "$W/server.csr" &&
        timeout 60 openssl x509 -req -in "$W/server.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
            -days 2 -extfile "$W/leaf.cnf" -extensions leaf -out "$W/server.pem"
} >"$W/openssl.log" 2>&1 || die "openssl could not make the certificates: $(tail -3 "$W/openssl.log")"
cp "$W/server.pem" "$W/server.key" "$W/xray/"
chmod 644 "$W/xray/server.key"

# The password, made here and never printed, and another for the refusal;
# each is URL-safe, so a link holds it as it is.
umask 077
python3 -I -c 'import secrets; print(secrets.token_urlsafe(18))' >"$W/password" || die "no password"
python3 -I -c 'import secrets; print(secrets.token_urlsafe(18))' >"$W/other" || die "no second password"
umask 022
timeout 30 "$BIN" keygen -q -t ed25519 -N '' -f "$W/key/id" >/dev/null 2>&1 || die "podssh keygen failed"
chmod 644 "$W/key/id.pub"

# Xray-core: Trojan in TLS alone and in a WebSocket over TLS; no fallback, so
# a wrong password ends the connection.
python3 -I - "$W/password" "$W/xray/config.json" <<'EOF'
import json, sys
password, out = open(sys.argv[1]).read().strip(), sys.argv[2]
tls = {"alpn": ["http/1.1"], "certificates": [{"certificateFile": "/etc/xray/server.pem", "keyFile": "/etc/xray/server.key"}]}
def inbound(port, network, settings):
    stream = {"network": network, "security": "tls", "tlsSettings": tls}
    if settings is not None:
        stream[network + "Settings"] = settings
    return {"listen": "0.0.0.0", "port": port, "protocol": "trojan",
            "settings": {"clients": [{"password": password}]}, "streamSettings": stream}
# Xray-core's freedom blackholes a private address for an inbound unless a
# final rule allows it (proxy/freedom/freedom.go); sshd.test is one.
private = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
freedom = {"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": private}]}}
config = {"log": {"loglevel": "warning"}, "outbounds": [freedom], "inbounds": [
    inbound(8443, "tcp", None),
    inbound(8444, "ws", {"path": "/tr"}),
]}
json.dump(config, open(out, "w"), indent=1)
EOF
chmod 644 "$W/xray/config.json"
printf '%s\n' 'http_port 3128' 'http_access allow all' 'cache deny all' 'access_log stdio:/tmp/access.log' \
    'cache_log /tmp/cache.log' 'pid_filename none' 'logfile_rotate 0' 'coredump_dir /tmp' >"$W/hop/squid.conf"
chmod 644 "$W/hop/squid.conf"

timeout 120 "$ENGINE" run --rm -v "$W/xray:/etc/xray:ro" "$ALPINE" /etc/xray/xray run -test -c /etc/xray/config.json \
    >"$W/xray-test.log" 2>&1 || die "Xray-core refused its configuration: $(tail -8 "$W/xray-test.log")"
timeout 60 "$ENGINE" network create "$NET" >/dev/null || die "the network $NET could not be made"
timeout 300 "$ENGINE" run -d --name podssh-trojan-sshd --network "$NET" --network-alias sshd.test \
    -v "$W/key:/k:ro" "$ALPINE" sh -c 'apk add --no-cache openssh-server >/dev/null &&
    ssh-keygen -A >/dev/null && mkdir -p /root/.ssh && cp /k/id.pub /root/.ssh/authorized_keys &&
    chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && sed -i "s/^root:[^:]*:/root:*:/" /etc/shadow &&
    exec /usr/sbin/sshd -D -e' >/dev/null || die "sshd did not start"
timeout 300 "$ENGINE" run -d --name podssh-trojan-xray --network "$NET" --network-alias trojan.test \
    -p "127.0.0.1:$XRAY_TLS:8443" -p "127.0.0.1:$XRAY_WS:8444" \
    -v "$W/xray:/etc/xray:ro" "$ALPINE" /etc/xray/xray run -c /etc/xray/config.json >/dev/null ||
    die "Xray-core did not start"
timeout 300 "$ENGINE" run -d --name podssh-trojan-hop --network "$NET" -p "127.0.0.1:$HOP:3128" \
    -v "$W/hop:/etc/podssh-squid:ro" "$ALPINE" sh -c 'apk add --no-cache squid >/dev/null &&
    exec squid -N -f /etc/podssh-squid/squid.conf' >/dev/null || die "the host's squid did not start"

# ready NAME PORT SECONDS MODE: the container runs, and PORT answers within
# SECONDS: a TLS handshake with the run's CA (tls), or bytes back (http).
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
        ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname="trojan.test").close()
    else:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        sys.exit(0 if s.recv(1) else 1)
except (OSError, ssl.SSLError):
    sys.exit(1)' "$2" "$4" "$W/ca.pem" && return 0
        [ $(($(date +%s) - _t0)) -lt "$3" ] || return 1
        sleep 1
    done
}
for p in "$XRAY_TLS" "$XRAY_WS"; do
    ready podssh-trojan-xray "$p" 120 tls ||
        { timeout 30 "$ENGINE" logs podssh-trojan-xray 2>&1 | tail -20; die "Xray-core did not answer TLS on $p"; }
done
ready podssh-trojan-hop "$HOP" 300 http || die "squid did not answer"

PINS="trojan.test=127.0.0.1"
SSH_OPTS="-i $W/key/id -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$W/kh -o BatchMode=yes"

# links NAME PASSWORD HOST:PORT QUERY: a file of one share link, of mode 0600.
links() {
    umask 077
    printf 'trojan://%s@%s?security=tls&%s#%s\n' "$2" "$3" "$4" "$1" >"$W/$1.links"
    umask 022
}
links xray-tls "$(cat "$W/password")" "trojan.test:$XRAY_TLS" 'type=tcp'
links xray-ws "$(cat "$W/password")" "trojan.test:$XRAY_WS" 'type=ws&path=%2Ftr'
links xray-other "$(cat "$W/other")" "trojan.test:$XRAY_TLS" 'type=tcp'
links xray-path "$(cat "$W/password")" "trojan.test:$XRAY_WS" 'type=ws&path=%2Fnot-tr'
links hop "$(cat "$W/password")" "trojan.test:8443" 'type=tcp'

# session NAME: podssh ssh through the link NAME, its outputs in $W/NAME.*.
session() {
    # shellcheck disable=SC2086  # the options are words
    env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" ssh -v --ca-file "$W/ca.pem" --trojan "$W/$1.links" $SSH_OPTS \
        root@sshd.test "echo through-$1" </dev/null >"$W/$1.out" 2>"$W/$1.err"
}
# carried NAME HOW: the session of NAME ran, and -v named HOW.
carried() {
    session "$1"
    _rc=$?
    [ "$_rc" = 0 ] && [ "$(cat "$W/$1.out")" = "through-$1" ] && grep -q "carries the session to sshd.test:22 in $2" \
        "$W/$1.err"
}

echo
echo "== --trojan: Xray-core (T-491)"

carried xray-tls 'TLS' && ok trojan.xray.tls "a session to Xray-core in TLS alone" ||
    bad trojan.xray.tls "a session in TLS alone" "$W/xray-tls.err"
carried xray-ws 'a WebSocket over TLS' && ok trojan.xray.ws "a session to Xray-core in a WebSocket over TLS" ||
    bad trojan.xray.ws "a session in a WebSocket" "$W/xray-ws.err"

# As OpenSSH keeps a ProxyCommand's stdin open, so does this pipe, for 3 s.
sleep 3 | env PODSSH_RELAY_ADDR="$PINS" timeout 120 "$BIN" proxy --ca-file "$W/ca.pem" --trojan "$W/xray-tls.links" \
    sshd.test 22 >"$W/banner.out" 2>"$W/banner.err"
rc=$?
case $(head -c 8 "$W/banner.out") in SSH-2.0-) b=yes ;; *) b=no ;; esac
[ "$b" = yes ] && ok trojan.xray.banner "podssh proxy --trojan: sshd's banner through Xray-core (exit $rc)" ||
    bad trojan.xray.banner "no banner through Xray-core: exit $rc" "$W/banner.err"

# Xray-core with no fallback ends a connection whose password it does not
# know; ssh exits 255 for a first hop that it did not reach.
session xray-other
rc=$?
[ "$rc" = 255 ] && grep -q 'ended the session before the target said anything' "$W/xray-other.err" &&
    ok trojan.xray.wrong-password "another password: Xray-core's end is said (exit 255)" ||
    bad trojan.xray.wrong-password "another password: exit $rc" "$W/xray-other.err"

session xray-path
rc=$?
[ "$rc" = 255 ] && grep -q 'refused the WebSocket upgrade at /not-tr' "$W/xray-path.err" &&
    ok trojan.xray.path "another path: the upgrade's refusal is said (exit 255)" ||
    bad trojan.xray.path "another path: exit $rc" "$W/xray-path.err"

# The host's proxy carries the TCP to Xray-core by its name, which the
# engine's names give inside the network; no pin, so the proxy is asked.
# shellcheck disable=SC2086
HTTPS_PROXY=http://127.0.0.1:$HOP timeout 120 "$BIN" ssh -v --ca-file "$W/ca.pem" --trojan "$W/hop.links" $SSH_OPTS \
    root@sshd.test 'echo hop' </dev/null >"$W/hop.out" 2>"$W/hop.err"
rc=$?
asked=$(timeout 30 "$ENGINE" exec podssh-trojan-hop cat /tmp/access.log 2>/dev/null | grep -c 'CONNECT trojan.test:8443')
[ "$rc" = 0 ] && [ "$(cat "$W/hop.out")" = hop ] && [ "${asked:-0}" -gt 0 ] &&
    ok trojan.hop "HTTPS_PROXY carries the TCP to Xray-core by its name; Trojan runs inside" ||
    bad trojan.hop "through the host's proxy: exit $rc, $asked CONNECTs" "$W/hop.err"

# trojan-gfw and trojan-go are T-693's: their releases' digests are not read yet.

# Neither the password nor its hash in any output of podssh.
python3 -I -c 'import hashlib, sys; print(hashlib.sha224(open(sys.argv[1]).read().strip().encode()).hexdigest())' \
    "$W/password" >"$W/hash"
cat "$W/password" >>"$W/hash"
leaked=$(grep -l -F -f "$W/hash" "$W"/*.out "$W"/*.err 2>/dev/null | wc -l)
[ "$leaked" = 0 ] && ok trojan.secret "no output of podssh holds the password or its hash" ||
    bad trojan.secret "$leaked outputs hold the password or its hash"

echo "interop-trojan: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
