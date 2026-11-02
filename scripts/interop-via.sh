#!/bin/sh
# scripts/interop-via.sh - `--via`, a forward proxy over TLS in place of the
# relay (T-439, the operator's ruling Q66), against servers that podssh did
# not write, each in a container on a network of the run: Caddy with its
# forwardproxy plugin (HTTP/2 and HTTP/1.1), squid's https_port (HTTP/1.1),
# OpenSSH's sshd as the target, and a plain squid as the host's own proxy
# (HTTPS_PROXY), which carries the TLS to the second proxy by its name.
#
#   sh scripts/interop-via.sh PODSSH_BINARY
#
# The images are the ones that images/ pins, through scripts/pull-image.sh:
# images/derper's Go builds Caddy with forwardproxy at a pinned commit, as
# xcaddy builds it (the module has no command of its own), and images/box's
# Alpine runs that Caddy, and squid and sshd from its packages. The CA, the
# certificate of both proxies, the key of the session and the proxies'
# password are made for the run in a directory that the run removes; the
# password goes to podssh by the path of its file alone, and to squid as a
# hash, and no output may show it (via.secret).
#
# The checks: the target's banner and a session through each proxy, HTTP/2
# with Caddy, and HTTP/1.1 with squid and with Caddy when PODSSH_VIA_HTTP=1.1
# asks; two sessions of `podssh each` on one HTTP/2
# connection; both through the host's proxy; the 407 of each proxy, said
# with its words, when the credential is left out (the plant of T-439, on
# the command line); and the line of `podssh doctor --via`. Each prints a
# line of scripts/interop-lib.sh; the exit code is 0 when each passed, else
# 1, and 71 when the host lacks what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), openssl, python3 and
# timeout; the ports PODSSH_VIA_PORT (18440) to PODSSH_VIA_PORT+2 of the
# loopback free. Caddy's build fetches Go's modules: on a host whose
# containers reach them only through the host's own proxy (a cloud
# session's), PODSSH_VIA_BUILD_NET=host and PODSSH_VIA_BUILD_CA=FILE (that
# proxy's CA) give the build that proxy, from HTTPS_PROXY.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-via.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_VIA_PORT:-18440}
CADDY_PORT=$PORT
SQUID_PORT=$((PORT + 1))
HOP_PORT=$((PORT + 2))
NET=podssh-via-net
NAMES="podssh-via-build podssh-via-sshd podssh-via-caddy podssh-via-squid podssh-via-hop"
# forwardproxy's last commit, read on 2026-11-02 ("Add :443 to the quickstart").
FORWARDPROXY=0aab84dad4fc2830789f34e27b4d7bc22a40889e
# Caddy's last release, read on 2026-11-02: the 2.8.4 that forwardproxy's
# go.mod names panics at its start when Go 1.27 builds it (a ModuleMap that
# it does not recognize).
CADDY_RELEASE=v2.11.7

die() {
    echo "interop-via: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in openssl python3 timeout; do
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
GO=$(image_of "$REPO/images/derper/Dockerfile") || die "Go's image did not pull"

# The CA of the run, and one certificate for both proxies' names.
mkdir -p "$W/caddy" "$W/caddysrc" "$W/squid" "$W/hop" "$W/key"
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca_ext' 'prompt = no' '[dn]' \
    'CN = podssh via test CA' '[ca_ext]' 'basicConstraints = critical,CA:TRUE' \
    'keyUsage = critical,keyCertSign,cRLSign' 'subjectKeyIdentifier = hash' >"$W/ca.cnf"
printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = via-caddy.test' '[leaf]' \
    'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature' 'extendedKeyUsage = serverAuth' \
    'subjectAltName = DNS:via-caddy.test,DNS:via-squid.test' 'authorityKeyIdentifier = keyid' >"$W/leaf.cnf"
{
    timeout 60 openssl req -x509 -config "$W/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 &&
        timeout 60 openssl req -new -config "$W/leaf.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$W/proxy.key" -out "$W/proxy.csr" &&
        timeout 60 openssl x509 -req -in "$W/proxy.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
            -days 2 -extfile "$W/leaf.cnf" -extensions leaf -out "$W/proxy.pem"
} >"$W/openssl.log" 2>&1 || die "openssl could not make the certificates: $(tail -3 "$W/openssl.log")"
for d in caddy squid; do cp "$W/proxy.pem" "$W/proxy.key" "$W/$d/"; done
# The proxies read the key as their own users, in a directory of the run.
chmod 644 "$W/caddy/proxy.key" "$W/squid/proxy.key"

# The proxies' password, made here and never printed; podssh reads it from
# files of mode 0600, in both forms.
umask 077
openssl rand -hex 16 >"$W/password" || die "no password"
printf 'podssh:%s\n' "$(cat "$W/password")" >"$W/auth"
cp "$W/password" "$W/auth-password-only"
umask 022
hash=$(timeout 30 openssl passwd -apr1 -stdin <"$W/password") || die "openssl made no hash of the password"
printf 'podssh:%s\n' "$hash" >"$W/squid/passwd"
chmod 644 "$W/squid/passwd"
timeout 30 "$BIN" keygen -q -t ed25519 -N '' -f "$W/key/id" >/dev/null 2>&1 || die "podssh keygen failed"
chmod 644 "$W/key/id.pub"

cat >"$W/caddy/Caddyfile" <<EOF
{
	order forward_proxy first
	auto_https off
	admin off
}
:8443 {
	tls /etc/caddy/proxy.pem /etc/caddy/proxy.key
	forward_proxy {
		basic_auth podssh $(cat "$W/password")
		acl {
			allow all
		}
	}
}
EOF
chmod 644 "$W/caddy/Caddyfile"
# Squid writes its logs as its own user, which may not open the
# container's stdout: they go to /tmp, and `exec cat` reads them.
squid_conf() {
    printf '%s\n' "$1" 'cache deny all' 'access_log stdio:/tmp/access.log' 'cache_log /tmp/cache.log' \
        'pid_filename none' 'logfile_rotate 0' 'coredump_dir /tmp' "$2" "$3" "$4" "$5"
}
squid_conf 'https_port 3129 tls-cert=/etc/podssh-squid/proxy.pem tls-key=/etc/podssh-squid/proxy.key' \
    'auth_param basic program @NCSA@ /etc/podssh-squid/passwd' 'auth_param basic realm podssh' \
    'acl authed proxy_auth REQUIRED' 'http_access allow authed' >"$W/squid/squid.conf"
printf '%s\n' 'http_access deny all' >>"$W/squid/squid.conf"
squid_conf 'http_port 3128' 'http_access allow all' '' '' '' >"$W/hop/squid.conf"
# Squid's helper is where Alpine's package puts it.
SQUID_RUN='apk add --no-cache squid >/dev/null &&
    h=$(ls /usr/lib/squid/basic_ncsa_auth /usr/libexec/squid/basic_ncsa_auth 2>/dev/null | head -1) &&
    sed "s|@NCSA@|$h|" /etc/podssh-squid/squid.conf >/tmp/squid.conf && exec squid -N -f /tmp/squid.conf'

# Caddy with forwardproxy, built first and in the open, so that a failure
# says why: a main of Caddy's command with the plugin, at forwardproxy's
# pinned commit and Caddy's pinned release. The binary comes out
# by the engine's cp, as the run's user, and runs on Alpine.
printf '%s\n' 'package main' '' 'import (' '	caddycmd "github.com/caddyserver/caddy/v2/cmd"' \
    '	_ "github.com/caddyserver/caddy/v2/modules/standard"' '	_ "github.com/caddyserver/forwardproxy"' ')' '' \
    'func main() { caddycmd.Main() }' >"$W/caddysrc/main.go"
chmod 644 "$W/caddysrc/main.go"
BUILD_NET=${PODSSH_VIA_BUILD_NET:-}
BUILD_CA=${PODSSH_VIA_BUILD_CA:-}
set -- -e CGO_ENABLED=0 -e GOFLAGS=-p=4 -v "$W/caddysrc:/in:ro"
[ -n "$BUILD_NET" ] && set -- "$@" --network "$BUILD_NET" -e HTTPS_PROXY -e https_proxy -e NO_PROXY -e no_proxy
[ -n "$BUILD_CA" ] && set -- "$@" -e SSL_CERT_FILE=/build-ca.pem -v "$BUILD_CA:/build-ca.pem:ro"
timeout 900 "$ENGINE" run --name podssh-via-build "$@" "$GO" sh -c "mkdir /src && cd /src && cp /in/main.go . &&
    go mod init podssh.test/caddy && go get github.com/caddyserver/forwardproxy@$FORWARDPROXY github.com/caddyserver/caddy/v2@$CADDY_RELEASE &&
    go mod tidy &&
    go build -o /caddy . && /caddy list-modules | grep -qx http.handlers.forward_proxy" >"$W/caddy-build.log" 2>&1 ||
    die "Caddy with forwardproxy did not build: $(tail -5 "$W/caddy-build.log")"
timeout 60 "$ENGINE" cp podssh-via-build:/caddy "$W/caddy/caddy" >/dev/null || die "the engine gave no copy of Caddy"
chmod 755 "$W/caddy/caddy"
timeout 60 "$ENGINE" rm -f podssh-via-build >/dev/null 2>&1

timeout 60 "$ENGINE" network create "$NET" >/dev/null || die "the network $NET could not be made"
timeout 300 "$ENGINE" run -d --name podssh-via-sshd --network "$NET" --network-alias sshd.test \
    --network-alias sshd-b.test -v "$W/key:/k:ro" "$ALPINE" sh -c 'apk add --no-cache openssh-server >/dev/null &&
    ssh-keygen -A >/dev/null && mkdir -p /root/.ssh && cp /k/id.pub /root/.ssh/authorized_keys &&
    chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && sed -i "s/^root:[^:]*:/root:*:/" /etc/shadow &&
    exec /usr/sbin/sshd -D -e' >/dev/null || die "sshd did not start"
timeout 300 "$ENGINE" run -d --name podssh-via-caddy --network "$NET" --network-alias via-caddy.test \
    -p "127.0.0.1:$CADDY_PORT:8443" -v "$W/caddy:/etc/caddy:ro" "$ALPINE" \
    /etc/caddy/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null || die "Caddy did not start"
timeout 300 "$ENGINE" run -d --name podssh-via-squid --network "$NET" --network-alias via-squid.test \
    -p "127.0.0.1:$SQUID_PORT:3129" -v "$W/squid:/etc/podssh-squid:ro" "$ALPINE" sh -c "$SQUID_RUN" >/dev/null ||
    die "squid did not start"
timeout 300 "$ENGINE" run -d --name podssh-via-hop --network "$NET" -p "127.0.0.1:$HOP_PORT:3128" \
    -v "$W/hop:/etc/podssh-squid:ro" "$ALPINE" sh -c "$SQUID_RUN" >/dev/null || die "the host's squid did not start"

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
        ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname="via-caddy.test").close()
    else:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        sys.exit(0 if s.recv(1) else 1)
except (OSError, ssl.SSLError):
    sys.exit(1)' "$2" "$4" "$W/ca.pem" && return 0
        [ $(($(date +%s) - _t0)) -lt "$3" ] || return 1
        sleep 1
    done
}
squid_log() {
    timeout 30 "$ENGINE" exec "$1" cat "/tmp/$2.log" 2>/dev/null
}
ready podssh-via-caddy "$CADDY_PORT" 120 tls ||
    { timeout 30 "$ENGINE" logs podssh-via-caddy 2>&1 | grep -v syslog | head -25; die "Caddy did not answer TLS"; }
ready podssh-via-squid "$SQUID_PORT" 300 tls || { squid_log podssh-via-squid cache | tail -20; die "squid did not answer TLS"; }
ready podssh-via-hop "$HOP_PORT" 300 http ||
    { squid_log podssh-via-hop cache | tail -20; die "the host's squid did not answer"; }

CADDY=https://via-caddy.test:$CADDY_PORT
SQUID=https://podssh@via-squid.test:$SQUID_PORT
# The proxies' names are on the loopback, where their ports are published;
# a name pinned to the loopback alone goes with no proxy.
PINS="via-caddy.test=127.0.0.1,via-squid.test=127.0.0.1"
SSH_OPTS="-i $W/key/id -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$W/kh -o BatchMode=yes"

# run NAME VERB ARGS...: podssh's VERB with the run's pins and CA, and
# PODSSH_VIA_HTTP=$VIA_HTTP, its outputs in $W/NAME.out and $W/NAME.err.
VIA_HTTP=
run() {
    _n=$1
    _v=$2
    shift 2
    env PODSSH_RELAY_ADDR="$PINS" PODSSH_VIA_HTTP="$VIA_HTTP" timeout 120 "$BIN" "$_v" --ca-file "$W/ca.pem" "$@" \
        </dev/null >"$W/$_n.out" 2>"$W/$_n.err"
}
# run_held NAME VERB ARGS...: as run, with stdin open for 3 s, as OpenSSH
# keeps a ProxyCommand's: squid ends a tunnel at the client's TLS close,
# which an empty stdin would send before the target's banner came back.
run_held() {
    _n=$1
    _v=$2
    shift 2
    sleep 3 | env PODSSH_RELAY_ADDR="$PINS" PODSSH_VIA_HTTP="$VIA_HTTP" timeout 120 "$BIN" "$_v" --ca-file "$W/ca.pem" \
        "$@" >"$W/$_n.out" 2>"$W/$_n.err"
}

echo
echo "== --via: Caddy's forwardproxy and squid over TLS (T-439)"

run_held caddy-banner proxy --via "$CADDY" --via-auth-file "$W/auth" sshd.test 22
rc=$?
case $(head -c 8 "$W/caddy-banner.out") in SSH-2.0-) b=yes ;; *) b=no ;; esac
[ "$b" = yes ] && ok via.caddy.banner "podssh proxy --via: sshd's banner through Caddy (exit $rc)" ||
    bad via.caddy.banner "no banner through Caddy: exit $rc" "$W/caddy-banner.err"

# shellcheck disable=SC2086  # the options are words
run caddy-h2 ssh -v --via "$CADDY" --via-auth-file "$W/auth" $SSH_OPTS root@sshd.test 'echo through-caddy'
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/caddy-h2.out")" = through-caddy ] && grep -q 'over HTTP/2' "$W/caddy-h2.err" &&
    ok via.caddy.h2 "a session through Caddy over HTTP/2's CONNECT" ||
    bad via.caddy.h2 "a session through Caddy over HTTP/2: exit $rc" "$W/caddy-h2.err"

VIA_HTTP=1.1
# shellcheck disable=SC2086
run caddy-h1 ssh -v --via "$CADDY" --via-auth-file "$W/auth" $SSH_OPTS root@sshd.test 'echo h1'
rc=$?
VIA_HTTP=
[ "$rc" = 0 ] && [ "$(cat "$W/caddy-h1.out")" = h1 ] && grep -q 'over HTTP/1.1' "$W/caddy-h1.err" &&
    ok via.caddy.h1 "PODSSH_VIA_HTTP=1.1: a session through Caddy over HTTP/1.1's CONNECT" ||
    bad via.caddy.h1 "a session through Caddy over HTTP/1.1: exit $rc" "$W/caddy-h1.err"

# shellcheck disable=SC2086
run caddy-each each -v --via "$CADDY" --via-auth-file "$W/auth" $SSH_OPTS 'root@sshd.test,root@sshd-b.test' \
    -- echo shared
rc=$?
[ "$rc" = 0 ] && [ "$(grep -c ': shared$' "$W/caddy-each.out")" = 2 ] &&
    grep -q 'a new stream on the connection that an earlier tunnel opened' "$W/caddy-each.err" &&
    ok via.caddy.shared "podssh each: two sessions on one HTTP/2 connection to Caddy" ||
    bad via.caddy.shared "two sessions on one connection: exit $rc" "$W/caddy-each.err"

run caddy-407 proxy --via "$CADDY" sshd.test 22
rc=$?
[ "$rc" = 77 ] && grep -q '407 .*it asks for Basic, and podssh sent none' "$W/caddy-407.err" &&
    ok via.caddy.407 "the credential left out: Caddy's 407 is said with its words (exit 77)" ||
    bad via.caddy.407 "Caddy's 407: exit $rc" "$W/caddy-407.err"

run_held squid-banner proxy --via "$SQUID" --via-auth-file "$W/auth-password-only" sshd.test 22
rc=$?
case $(head -c 8 "$W/squid-banner.out") in SSH-2.0-) b=yes ;; *) b=no ;; esac
[ "$b" = yes ] && ok via.squid.banner "podssh proxy --via: sshd's banner through squid, the URL's user (exit $rc)" ||
    bad via.squid.banner "no banner through squid: exit $rc" "$W/squid-banner.err"

# shellcheck disable=SC2086
run squid-h1 ssh -v --via "$SQUID" --via-auth-file "$W/auth-password-only" $SSH_OPTS root@sshd.test 'echo squid'
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/squid-h1.out")" = squid ] && grep -q 'over HTTP/1.1' "$W/squid-h1.err" &&
    ok via.squid.h1 "a session through squid's https_port over HTTP/1.1's CONNECT" ||
    bad via.squid.h1 "a session through squid: exit $rc" "$W/squid-h1.err"

run squid-407 proxy --via "https://via-squid.test:$SQUID_PORT" sshd.test 22
rc=$?
[ "$rc" = 77 ] && grep -q '407 .*it asks for Basic, and podssh sent none' "$W/squid-407.err" &&
    ok via.squid.407 "the credential left out: squid's 407 is said with its words (exit 77)" ||
    bad via.squid.407 "squid's 407: exit $rc" "$W/squid-407.err"

# The host's proxy carries the TLS to each second proxy by its name, which
# Docker's names give inside the network; no pin, so the proxy is asked.
for p in caddy:8443 squid:3129; do
    # shellcheck disable=SC2086
    HTTPS_PROXY=http://127.0.0.1:$HOP_PORT timeout 120 "$BIN" ssh -v --via "https://via-${p%%:*}.test:${p#*:}" \
        --via-auth-file "$W/auth" --ca-file "$W/ca.pem" $SSH_OPTS root@sshd.test 'echo hop' \
        </dev/null >"$W/hop-${p%%:*}.out" 2>"$W/hop-${p%%:*}.err"
    rc=$?
    asked=$(squid_log podssh-via-hop access | grep -c "CONNECT via-${p%%:*}.test:${p#*:}")
    [ "$rc" = 0 ] && [ "$(cat "$W/hop-${p%%:*}.out")" = hop ] && [ "${asked:-0}" -gt 0 ] &&
        ok "via.hop.${p%%:*}" "HTTPS_PROXY carries the TLS to ${p%%:*} by its name; the session runs inside" ||
        bad "via.hop.${p%%:*}" "through the host's proxy to ${p%%:*}: exit $rc, $asked CONNECTs" \
            "$W/hop-${p%%:*}.err"
done

run doctor doctor --via "$CADDY" --via-auth-file "$W/auth"
if grep -q 'through https://via-caddy.test:[0-9]*: TLS, then CONNECT over HTTP/2' "$W/doctor.out"; then
    ok via.doctor "podssh doctor --via names Caddy and HTTP/2"
elif grep -q 'refused CONNECT github.com:22' "$W/doctor.out"; then
    unmet via.doctor "Caddy has no route to github.com:22, which doctor's line asks for"
else
    bad via.doctor "no line of the section via" "$W/doctor.out"
fi

leaked=$(grep -l -F -f "$W/password" "$W"/*.out "$W"/*.err 2>/dev/null | wc -l)
[ "$leaked" = 0 ] && ok via.secret "no output of podssh holds the proxies' password" ||
    bad via.secret "$leaked outputs hold the password"

echo "interop-via: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
