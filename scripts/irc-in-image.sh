#!/bin/sh
# The IRC client and podssh chat --irc against a real server, ngircd, on the
# loopback of the build image (T-091 to T-097, T-252): plain text on 6667,
# and TLS on 6697 with a certificate of a test CA made here.
#
#   sh scripts/irc-in-image.sh            # in the build image, with the tree at /work
#   IRC_PLANT=plaintext sh scripts/irc-in-image.sh
#
# IRC_PLANT=plaintext is the planted defect of T-252: each chat run skips
# its TLS, and the chat test must fail at the handshake; the script then
# exits 0 only when it did fail. Needs apk (Alpine) and the network for it.

set -u
cd /work 2>/dev/null || cd "$(dirname "$0")/.." || exit 71
: "${CARGO_BUILD_JOBS:=4}"
export CARGO_BUILD_JOBS

die() {
    echo "irc-in-image: $*" >&2
    exit 1
}
command -v apk >/dev/null 2>&1 || die "apk is not on PATH: this script runs in the build image"
timeout 300 apk add --no-cache ngircd openssl >/tmp/irc-apk.log 2>&1 || { cat /tmp/irc-apk.log; die "apk add failed"; }

D=$(mktemp -d)
trap 'kill "$IRCD" 2>/dev/null; rm -rf "$D"' EXIT
cd "$D" || die "no work directory"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=podssh test CA" -keyout ca.key -out ca.pem \
    >/dev/null 2>&1 || die "no test CA"
openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" -keyout server.key -out server.csr >/dev/null 2>&1 ||
    die "no server key"
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' >ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out server.pem \
    >/dev/null 2>&1 || die "no server certificate"
cat >ngircd.conf <<EOF
[Global]
Name = irc.podssh.test
Info = the IRC server of podssh's tests
Listen = 127.0.0.1
Ports = 6667
[Options]
PAM = no
[SSL]
CertFile = $D/server.pem
KeyFile = $D/server.key
Ports = 6697
EOF
ngircd -n -f "$D/ngircd.conf" >"$D/ngircd.log" 2>&1 &
IRCD=$!
n=0
until grep -q 6697 "$D/ngircd.log" 2>/dev/null && grep -q "Now listening" "$D/ngircd.log" 2>/dev/null; do
    n=$((n + 1))
    [ "$n" -lt 30 ] || { cat "$D/ngircd.log"; die "ngircd did not listen within 30 s"; }
    sleep 1
done
cd /work 2>/dev/null || cd "$(dirname "$0")/.." || die "no tree"

fail=0
if [ "${IRC_PLANT:-}" = plaintext ]; then
    PODSSH_IRC_TLS_SERVER=127.0.0.1:6697 PODSSH_IRC_CA="$D/ca.pem" PODSSH_IRC_PLANT=plaintext \
        timeout 900 cargo test --locked -p podssh-cli --test chat_irc_server -- --ignored --test-threads 1 \
        a_message_and_a_file
    rc=$?
    echo "the plant: exit $rc (wanted a failure)"
    [ "$rc" != 0 ] || fail=1
    exit $fail
fi
PODSSH_IRC_SERVER=127.0.0.1:6667 timeout 900 cargo test --locked -p podssh-core --test irc_server --test transfer_server \
    -- --ignored --test-threads 1 || fail=1
PODSSH_IRC_TLS_SERVER=127.0.0.1:6697 PODSSH_IRC_CA="$D/ca.pem" timeout 900 cargo test --locked -p podssh-cli \
    --test chat_irc_server -- --ignored --test-threads 1 || fail=1
echo "exit=$fail"
exit $fail
