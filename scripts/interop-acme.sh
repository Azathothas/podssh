#!/bin/sh
# scripts/interop-acme.sh - `podssh relay serve --acme NAME` (T-447) against
# Pebble, Let's Encrypt's ACME server for tests, which validates TLS-ALPN-01
# on the role's own listener, with the names that pebble-challtestsrv's DNS
# gives; and OpenSSL's s_client as a client of the role that podssh did not
# write.
#
#   sh scripts/interop-acme.sh PODSSH_BINARY
#
# Pebble and pebble-challtestsrv are their project's release binaries,
# pinned by version and SHA-256 and fetched first, in the open; each runs in
# images/box's Alpine, on the host's network, so that Pebble reaches the role
# on the loopback. The run makes a CA of its own for Pebble's directory (the
# trust that --ca-file names) and a cache of its own for the role, and
# removes both, and each container, at the end. Pebble's default profile
# issues certificates of 180 s here, so that the role renews one in the run
# (at a third of its life left); it refuses 15 % of good nonces, so that the
# role's retry of badNonce runs in each run; and it runs -strict.
#
# The checks, each a line of scripts/interop-lib.sh: the first certificate,
# ordered and said; its state private (the directory 0700, account.key and
# NAME.pem 0600); podssh relay status through the role, trusting Pebble's
# root alone; s_client's check of the chain to that root for NAME; SIGHUP,
# which reads the file kept again; a second start that serves the
# certificate kept and orders nothing; its renewal in the role, with a new
# serial; and a role whose port Pebble cannot reach, which stops with 69 and
# Pebble's reason. The exit code is 0 when each passed, else 1, and 71 when
# the host lacks what the run needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), openssl, python3, curl,
# tar and timeout; the ports PODSSH_ACME_PORT (18470) to PODSSH_ACME_PORT+5
# of the loopback free; and the releases on GitHub, through HTTPS_PROXY when
# it is set.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-acme.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_ACME_PORT:-18470}
WFE=$PORT
MGMT=$((PORT + 1))
DNS=$((PORT + 2))
CHALL=$((PORT + 3))
# The role listens here, and Pebble validates TLS-ALPN-01 here.
ROLE_PORT=$((PORT + 4))
OTHER_PORT=$((PORT + 5))
NAME=relay.podssh.test
NAMES="podssh-acme-pebble podssh-acme-dns"
# Pebble's release of 2026-04-20, and the SHA-256 of each file that its
# release lists, read on 2026-11-02.
PEBBLE_RELEASE=v2.10.1
PEBBLE_SHA256=4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed
CHALL_SHA256=e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92

die() {
    echo "interop-acme: $*" >&2
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
ROLE=
stop_role() {
    if [ -n "$ROLE" ]; then
        kill "$ROLE" 2>/dev/null
        wait "$ROLE" 2>/dev/null
        ROLE=
    fi
}
# Each container on its own: podman's rm stops at a name that is missing.
remove_all() {
    for _c in $NAMES; do
        timeout 60 "$ENGINE" rm -f "$_c" >/dev/null 2>&1
    done
}
cleanup() {
    stop_role
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
mkdir -p "$W/bin" "$W/pebble" "$W/dl" "$W/cache" "$W/home"
URL=https://github.com/letsencrypt/pebble/releases/download/$PEBBLE_RELEASE
fetch "$URL/pebble-linux-amd64.tar.gz" "$PEBBLE_SHA256" "$W/dl/pebble.tar.gz"
fetch "$URL/pebble-challtestsrv-linux-amd64.tar.gz" "$CHALL_SHA256" "$W/dl/chall.tar.gz"
tar -xzf "$W/dl/pebble.tar.gz" -C "$W/dl" pebble-linux-amd64/linux/amd64/pebble ||
    die "the archive of Pebble holds no pebble"
tar -xzf "$W/dl/chall.tar.gz" -C "$W/dl" pebble-challtestsrv-linux-amd64/linux/amd64/pebble-challtestsrv ||
    die "the archive of pebble-challtestsrv holds no pebble-challtestsrv"
cp "$W/dl/pebble-linux-amd64/linux/amd64/pebble" "$W/dl/pebble-challtestsrv-linux-amd64/linux/amd64/pebble-challtestsrv" \
    "$W/bin/"
chmod 755 "$W/bin/pebble" "$W/bin/pebble-challtestsrv"

# The CA of the run, and Pebble's certificate of it for 127.0.0.1, which
# serves its directory and its management.
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca_ext' 'prompt = no' '[dn]' \
    'CN = podssh acme test CA' '[ca_ext]' 'basicConstraints = critical,CA:TRUE' \
    'keyUsage = critical,keyCertSign,cRLSign' 'subjectKeyIdentifier = hash' >"$W/ca.cnf"
printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = pebble' '[leaf]' \
    'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature' 'extendedKeyUsage = serverAuth' \
    'subjectAltName = IP:127.0.0.1,DNS:localhost' 'authorityKeyIdentifier = keyid' >"$W/leaf.cnf"
{
    timeout 60 openssl req -x509 -config "$W/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 &&
        timeout 60 openssl req -new -config "$W/leaf.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$W/pebble/wfe.key" -out "$W/wfe.csr" &&
        timeout 60 openssl x509 -req -in "$W/wfe.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
            -days 2 -extfile "$W/leaf.cnf" -extensions leaf -out "$W/pebble/wfe.pem"
} >"$W/openssl.log" 2>&1 || die "openssl could not make the certificates: $(tail -3 "$W/openssl.log")"
chmod 644 "$W/pebble/wfe.key"

cat >"$W/pebble/config.json" <<EOF
{
  "pebble": {
    "listenAddress": "127.0.0.1:$WFE",
    "managementListenAddress": "127.0.0.1:$MGMT",
    "certificate": "/etc/pebble/wfe.pem",
    "privateKey": "/etc/pebble/wfe.key",
    "httpPort": $OTHER_PORT,
    "tlsPort": $ROLE_PORT,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "domainBlocklist": ["blocked-domain.example"],
    "retryAfter": {"authz": 1, "order": 1},
    "keyAlgorithm": "ecdsa",
    "profiles": {"default": {"description": "180 s, so that the role renews in the run", "validityPeriod": 180}}
  }
}
EOF
chmod 644 "$W/pebble/config.json"

# Every name is the loopback's, and no AAAA comes, so that Pebble dials the
# role's IPv4 listener.
timeout 300 "$ENGINE" run -d --name podssh-acme-dns --network host -v "$W/bin:/opt/pebble:ro" "$ALPINE" \
    /opt/pebble/pebble-challtestsrv -defaultIPv4 127.0.0.1 -defaultIPv6 "" -dnsserver "127.0.0.1:$DNS" \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" -management "127.0.0.1:$CHALL" >/dev/null ||
    die "pebble-challtestsrv did not start"
timeout 300 "$ENGINE" run -d --name podssh-acme-pebble --network host -e PEBBLE_VA_NOSLEEP=1 \
    -e PEBBLE_WFE_NONCEREJECT=15 -v "$W/bin:/opt/pebble:ro" -v "$W/pebble:/etc/pebble:ro" "$ALPINE" \
    /opt/pebble/pebble -config /etc/pebble/config.json -dnsserver "127.0.0.1:$DNS" -strict >/dev/null ||
    die "Pebble did not start"
logs() {
    timeout 30 "$ENGINE" logs "$1" 2>&1 | tail -20
}
# Pebble's directory answers over the run's CA, within 60 s.
i=0
until timeout 10 curl -fsS --noproxy '*' --cacert "$W/ca.pem" -o "$W/dir.json" "https://127.0.0.1:$WFE/dir" \
    2>/dev/null; do
    i=$((i + 1))
    [ "$i" -le 60 ] || { logs podssh-acme-pebble; die "Pebble's directory did not answer"; }
    sleep 1
done

# role NAME PORT TAG: podssh relay serve --acme NAME on PORT, its stderr in
# TAG.log; with no proxy, as Pebble is on the loopback.
role() {
    env -u HTTPS_PROXY -u https_proxy -u ALL_PROXY -u all_proxy HOME="$W/home" PODSSH_CACHE_DIR="$W/cache" \
        "$BIN" relay serve --listen "127.0.0.1:$2" --acme "$1" --acme-directory "https://127.0.0.1:$WFE/dir" \
        --ca-file "$W/ca.pem" --mint anyone --allow-private </dev/null >"$W/$3.events" 2>"$W/$3.log" &
    ROLE=$!
}
# said TAG TEXT SECONDS: TAG.log holds TEXT within SECONDS, while the role runs.
said() {
    _t=0
    while ! grep -qF "$2" "$W/$1.log" 2>/dev/null; do
        kill -0 "$ROLE" 2>/dev/null || return 1
        _t=$((_t + 1))
        [ "$_t" -le "$3" ] || return 1
        sleep 1
    done
}
mode_of() {
    python3 -I -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$1" 2>/dev/null
}
# serial FILE: the serial of the first certificate that s_client printed.
serial() {
    timeout 30 openssl x509 -in "$1" -noout -serial 2>/dev/null
}
# s_client TAG: the role's chain, checked to Pebble's root for NAME.
s_client() {
    timeout 30 openssl s_client -connect "127.0.0.1:$ROLE_PORT" -servername "$NAME" -CAfile "$W/root.pem" \
        -verify_return_error -verify_hostname "$NAME" </dev/null >"$W/$1.s_client" 2>&1
}

echo
echo "== podssh relay serve --acme: Pebble (T-447)"

role "$NAME" "$ROLE_PORT" first
said first "a certificate from 127.0.0.1 for $NAME" 120 &&
    ok acme.issued "Pebble validated TLS-ALPN-01 on the role's listener, and the role says its certificate" ||
    bad acme.issued "no certificate from Pebble" "$W/first.log"

STATE=$(find "$W/cache/acme" -mindepth 1 -maxdepth 1 -type d -name '127.0.0.1-*' 2>/dev/null | head -1)
modes="$(mode_of "$STATE") $(mode_of "$STATE/account.key") $(mode_of "$STATE/$NAME.pem")"
[ "$modes" = "700 600 600" ] && ok acme.private "the state is private: the directory 0700, account.key and $NAME.pem 0600" ||
    bad acme.private "the modes of the state: $modes"

timeout 30 curl -fsS --noproxy '*' --cacert "$W/ca.pem" -o "$W/root.pem" "https://127.0.0.1:$MGMT/roots/0" ||
    die "Pebble gave no root"
env -u HTTPS_PROXY -u https_proxy -u ALL_PROXY -u all_proxy HOME="$W/home" PODSSH_CACHE_DIR="$W/client" \
    timeout 60 "$BIN" relay status --json --relay-host "$NAME:$ROLE_PORT" --relay-addr "$NAME=127.0.0.1" \
    --ca-file "$W/root.pem" </dev/null >"$W/status.out" 2>"$W/status.err"
rc=$?
[ "$rc" = 0 ] && grep -q '"ok":true' "$W/status.out" &&
    ok acme.status "podssh relay status reads the role, trusting Pebble's root alone" ||
    bad acme.status "podssh relay status: exit $rc" "$W/status.err"

s_client first
rc=$?
FIRST_SERIAL=$(serial "$W/first.s_client")
[ "$rc" = 0 ] && grep -q 'Verify return code: 0 (ok)' "$W/first.s_client" && [ -n "$FIRST_SERIAL" ] &&
    ok acme.s-client "openssl s_client verifies the role's chain to Pebble's root for $NAME" ||
    bad acme.s-client "openssl s_client: exit $rc" "$W/first.s_client"

kill -HUP "$ROLE" 2>/dev/null
said first "SIGHUP: read " 10 && kill -0 "$ROLE" 2>/dev/null &&
    ok acme.sighup "SIGHUP reads the file kept again, and the role goes on" ||
    bad acme.sighup "no line of SIGHUP, or the role ended" "$W/first.log"
stop_role

# A second start, soon: the certificate kept is served, and nothing ordered.
role "$NAME" "$ROLE_PORT" second
said second "with the certificate from ACME at 127.0.0.1 for $NAME" 30 && s_client second &&
    [ "$(serial "$W/second.s_client")" = "$FIRST_SERIAL" ] && ! grep -q 'a new account' "$W/second.log" &&
    ok acme.kept "a second start serves the certificate kept, and orders nothing" ||
    bad acme.kept "the second start did not serve the certificate kept" "$W/second.log"

# Its life is 180 s: the role renews it 60 s before its end, in place.
said second "a certificate from 127.0.0.1 for $NAME" 240 && s_client renewed &&
    [ "$(serial "$W/renewed.s_client")" != "$FIRST_SERIAL" ] &&
    ok acme.renewed "the role renewed the certificate before its end, and serves the new one" ||
    bad acme.renewed "no renewal within 240 s" "$W/second.log"
stop_role

# Pebble validates on the role's port, where nothing listens now.
role other.podssh.test "$OTHER_PORT" refused
i=0
while kill -0 "$ROLE" 2>/dev/null && [ "$i" -le 120 ]; do
    i=$((i + 1))
    sleep 1
done
# A role that still runs is ended, and its 143 is no pass.
kill "$ROLE" 2>/dev/null
wait "$ROLE" 2>/dev/null
rc=$?
ROLE=
[ "$rc" = 69 ] && grep -q 'Failed to connect to' "$W/refused.log" &&
    ok acme.refused "a role that Pebble cannot reach stops with 69 and Pebble's reason" ||
    bad acme.refused "the unreachable role: exit $rc" "$W/refused.log"

leaked=$(grep -l -e 'BEGIN PRIVATE KEY' -e 'BEGIN EC PRIVATE KEY' "$W"/*.log "$W"/*.events "$W"/*.out "$W"/*.err \
    2>/dev/null | wc -l)
[ "$leaked" = 0 ] || bad acme.issued "$leaked outputs of the role hold a private key"

echo "interop-acme: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
