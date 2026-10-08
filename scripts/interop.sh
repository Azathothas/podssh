#!/bin/sh
# podssh against real SSH servers: OpenSSH and Dropbear on 127.0.0.1, in the
# build image (rust:1-alpine). Run by scripts/gate.sh after the static build;
# by hand: sh scripts/interop.sh target/x86_64-unknown-linux-musl/release/podssh
#
# Every case prints `ok` or `FAIL` with what was expected and what came back;
# the script exits non-zero if any case failed. Servers, keys and the test
# user's password are created here and live only in this container.

set -u
BIN=${1:?usage: sh scripts/interop.sh PATH_TO_PODSSH}
case $BIN in /*) ;; *) BIN=$(pwd)/$BIN ;; esac
[ -x "$BIN" ] || { echo "interop: $BIN is not an executable"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
W=/tmp/podssh-interop
rm -rf "$W"
mkdir -p "$W"
pass=0
fail=0
skip=0

ok() { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; [ $# -gt 1 ] && sed 's/^/      | /' "$2" | head -20; }
skipped() { skip=$((skip + 1)); printf 'skip  %s\n' "$1"; }
# expect_rc NAME WANT GOT [LOG]
expect_rc() {
    if [ "$3" = "$2" ]; then ok "$1 (exit $3)"; else bad "$1: wanted exit $2, got $3" "${4:-/dev/null}"; fi
}

echo "== servers"
apk add --no-cache openssh-server openssh-server-pam openssh-keygen openssh-sftp-server \
    dropbear python3 linux-pam openssl >"$W/apk.log" 2>&1 || { cat "$W/apk.log"; exit 1; }
PW=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
adduser -D -s /bin/sh podtest >/dev/null 2>&1 || true
echo "podtest:$PW" | chpasswd >/dev/null 2>&1 || { echo "interop: chpasswd failed"; exit 1; }
H=/home/podtest
mkdir -p "$H/.ssh"
for k in ed25519 rsa ecdsa; do
    ssh-keygen -q -t "$k" -N '' -C "interop-$k" -f "$W/id_$k"
done
ssh-keygen -q -t ed25519 -N 'open sesame' -C interop-enc -f "$W/id_enc"
cat "$W"/id_*.pub >"$H/.ssh/authorized_keys"
chown -R podtest:podtest "$H/.ssh"
chmod 700 "$H/.ssh"
chmod 600 "$H/.ssh/authorized_keys"
chmod 755 "$H"
ssh-keygen -q -t ed25519 -N '' -f "$W/host_ed25519"
ssh-keygen -q -t rsa -b 3072 -N '' -f "$W/host_rsa"
printf '#!/bin/sh\necho "%s"\n' "$PW" >"$W/askpass-password"
printf '#!/bin/sh\necho "open sesame"\n' >"$W/askpass-passphrase"
printf '#!/bin/sh\necho "not the password"\n' >"$W/askpass-wrong"
chmod 700 "$W"/askpass-*

sshd_conf() { # port extra-line...
    _port=$1
    shift
    {
        echo "Port $_port"
        echo "ListenAddress 127.0.0.1"
        echo "HostKey $W/host_ed25519"
        echo "HostKey $W/host_rsa"
        echo "PidFile $W/sshd-$_port.pid"
        echo "PasswordAuthentication yes"
        echo "PermitRootLogin no"
        echo "StrictModes no"
        echo "AcceptEnv PODSSH_TEST_*"
        echo "AllowTcpForwarding yes"
        echo "Subsystem sftp /usr/lib/ssh/sftp-server"
        for line in "$@"; do echo "$line"; done
    } >"$W/sshd-$_port.conf"
}
sshd_conf 2201 "KbdInteractiveAuthentication no"
sshd_conf 2202 "KbdInteractiveAuthentication no" "PermitTTY no"
sshd_conf 2204 "KbdInteractiveAuthentication yes" "PasswordAuthentication no" "UsePAM yes"
/usr/sbin/sshd -f "$W/sshd-2201.conf" -E "$W/sshd-2201.log" || { cat "$W/sshd-2201.log"; exit 1; }
/usr/sbin/sshd -f "$W/sshd-2202.conf" -E "$W/sshd-2202.log" || { cat "$W/sshd-2202.log"; exit 1; }
PAM_SSHD=
if [ -x /usr/sbin/sshd.pam ]; then
    /usr/sbin/sshd.pam -f "$W/sshd-2204.conf" -E "$W/sshd-2204.log" && PAM_SSHD=yes
fi
dropbearkey -t ed25519 -f "$W/dropbear_ed25519" >/dev/null 2>&1
dropbear -p 127.0.0.1:2203 -r "$W/dropbear_ed25519" -P "$W/dropbear.pid" 2>"$W/dropbear.log" \
    || { cat "$W/dropbear.log"; exit 1; }
python3 - <<'EOF' || { echo "interop: the servers did not start"; exit 1; }
import socket, time
for port in (2201, 2202, 2203):
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 1).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise SystemExit(f"port {port} never listened")
EOF
apk info -v openssh-server dropbear 2>/dev/null | sed 's/^/server: /'

# p PORT [podssh ssh arguments...]: podssh with a fresh environment: no
# agent, test keys only, this run's known_hosts, never a prompt on a terminal.
KH="$W/known_hosts"
p() {
    _port=$1
    shift
    env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p "$_port" \
        -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes "$@"
}
T=podtest@127.0.0.1
K="-i $W/id_ed25519"

echo
echo "== exit status (OpenSSH, then Dropbear)"
for port in 2201 2203; do
    for spec in "3:exit 3" "0:true" "1:false" "127:no-such-command-here" "143:kill -TERM \$\$"; do
        want=${spec%%:*}
        cmd=${spec#*:}
        # shellcheck disable=SC2086
        p "$port" $K -o BatchMode=yes "$T" "$cmd" >"$W/out" 2>"$W/err" </dev/null
        expect_rc "port $port: '$cmd'" "$want" $? "$W/err"
    done
done
grep -q "killed by signal TERM" "$W/err" && ok "a remote signal is named on stderr" || bad "no signal message" "$W/err"

echo
echo "== streams"
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes "$T" 'echo to-stdout; echo to-stderr >&2' >"$W/out" 2>"$W/err" </dev/null
[ "$(cat "$W/out")" = to-stdout ] && grep -q to-stderr "$W/err" && ! grep -q to-stderr "$W/out" \
    && ok "stdout and stderr stay apart" || bad "streams mixed" "$W/out"
for size in 262144 262145 5000000; do
    head -c "$size" /dev/urandom >"$W/blob"
    want=$(sha256sum <"$W/blob" | cut -c1-64)
    for port in 2201 2203; do
        # shellcheck disable=SC2086
        got=$(p "$port" $K -o BatchMode=yes "$T" sha256sum <"$W/blob" 2>"$W/err" | cut -c1-64)
        [ "$got" = "$want" ] && ok "port $port: $size bytes up" || bad "port $port: $size bytes up: $got != $want" "$W/err"
        # shellcheck disable=SC2086
        p "$port" $K -o BatchMode=yes "$T" "cat > /tmp/b && cat /tmp/b" <"$W/blob" >"$W/back" 2>"$W/err"
        got=$(sha256sum <"$W/back" | cut -c1-64)
        [ "$got" = "$want" ] && ok "port $port: $size bytes up and back" || bad "port $port: $size bytes round trip" "$W/err"
    done
done

echo
echo "== authentication"
for k in rsa ecdsa; do
    p 2201 -i "$W/id_$k" -o BatchMode=yes "$T" true </dev/null >"$W/out" 2>"$W/err"
    expect_rc "$k key" 0 $? "$W/err"
done
SSH_ASKPASS="$W/askpass-passphrase" SSH_ASKPASS_REQUIRE=force p 2201 -i "$W/id_enc" "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc "encrypted key, passphrase from SSH_ASKPASS" 0 $? "$W/err"
p 2201 -i "$W/id_enc" -o BatchMode=yes "$T" true </dev/null >"$W/out" 2>"$W/err"
rc=$?
expect_rc "encrypted key, nobody to ask" 255 $rc "$W/err"
grep -q "skipped encrypted key" "$W/err" && ok "the refusal names the skipped key" || bad "no note about the encrypted key" "$W/err"
for port in 2201 2203; do
    SSH_ASKPASS="$W/askpass-password" SSH_ASKPASS_REQUIRE=force \
        p "$port" -o PubkeyAuthentication=no "$T" 'exit 4' </dev/null >"$W/out" 2>"$W/err"
    expect_rc "port $port: password from SSH_ASKPASS" 4 $? "$W/err"
    SSH_ASKPASS="$W/askpass-wrong" SSH_ASKPASS_REQUIRE=force \
        p "$port" -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 "$T" true </dev/null >"$W/out" 2>"$W/err"
    expect_rc "port $port: wrong password" 255 $? "$W/err"
done
grep -q "Permission denied" "$W/err" && ok "a wrong password says Permission denied" || bad "no Permission denied" "$W/err"
p 2201 -o PubkeyAuthentication=no -o BatchMode=yes "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc "password with BatchMode" 255 $? "$W/err"
grep -q "password authentication was skipped" "$W/err" && ok "BatchMode names the skipped password" || bad "no note" "$W/err"
# Keys were turned off, so the refusal does not send the user to -i FILE (GitHub #7).
grep -q "publickey was not tried: -o PubkeyAuthentication=no" "$W/err" && ! grep -q "no key was offered" "$W/err" \
    && ok "keys turned off: the refusal says so and does not name -i" || bad "keys turned off: the wrong note" "$W/err"
if [ -n "$PAM_SSHD" ]; then
    SSH_ASKPASS="$W/askpass-password" SSH_ASKPASS_REQUIRE=force \
        p 2204 -o PubkeyAuthentication=no "$T" 'exit 6' </dev/null >"$W/out" 2>"$W/err"
    expect_rc "keyboard-interactive (PAM) from SSH_ASKPASS" 6 $? "$W/err"
else
    skipped "keyboard-interactive: sshd.pam is not in this image"
fi

echo
echo "== host keys"
grep -c . "$KH" >/dev/null && ok "keys were recorded with accept-new ($(grep -c . "$KH") lines)" || bad "known_hosts is empty"
# shellcheck disable=SC2086
p 2201 $K -o StrictHostKeyChecking=yes -o BatchMode=yes "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc "a recorded key is accepted under StrictHostKeyChecking=yes" 0 $? "$W/err"
sed 's/^\(\[127.0.0.1\]:2201 ssh-ed25519 \).*/\1AAAAC3NzaC1lZDI1NTE5AAAAIBXkNYHrJ3fDOpgDDGbs1lnK9rmzEHaN7Jbn9jC7Wjlx/' "$KH" >"$W/kh_changed"
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$W/kh_changed" \
    -o StrictHostKeyChecking=no -o IdentityAgent=none $K "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc "a changed key is refused even with StrictHostKeyChecking=no" 255 $? "$W/err"
grep -q "HAS CHANGED" "$W/err" && ok "the changed-key warning is shown" || bad "no warning" "$W/err"

echo
echo "== forwarding, jump hosts, subsystems, environment"
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -W 127.0.0.1:2203 "$T" </dev/null >"$W/out" 2>"$W/err"
head -c 16 "$W/out" | grep -q "SSH-2.0-dropbear" && ok "-W reaches Dropbear's banner through OpenSSH" || bad "-W" "$W/err"
# shellcheck disable=SC2086
p 2203 $K -o BatchMode=yes -J "$T:2201" "$T" 'exit 5' </dev/null >"$W/out" 2>"$W/err"
expect_rc "-J through OpenSSH to Dropbear" 5 $? "$W/err"
printf '\000\000\000\005\001\000\000\000\003' >"$W/fxp_init"
# stdin stays open a moment: OpenSSH's sftp-server exits on end of input
# without flushing its reply (measured 2026-10-08 on a Debian host, without
# podssh: `printf INIT | sftp-server` prints nothing), as a real client would.
# shellcheck disable=SC2086
(cat "$W/fxp_init"; sleep 2) | p 2201 $K -o BatchMode=yes -s "$T" sftp >"$W/out" 2>"$W/err"
fxp=$(python3 -c 'import sys; d = open(sys.argv[1], "rb").read(); print(d[4] if len(d) > 4 else -1)' "$W/out")
[ "$fxp" = 2 ] && ok "-s sftp answers SSH_FXP_VERSION" || bad "-s sftp: packet type $fxp" "$W/err"
# shellcheck disable=SC2086
out=$(p 2201 $K -o BatchMode=yes -o SetEnv=PODSSH_TEST_X=hello "$T" 'echo $PODSSH_TEST_X' </dev/null 2>"$W/err")
[ "$out" = hello ] && ok "SetEnv reaches the server" || bad "SetEnv: got '$out'" "$W/err"
start=$(date +%s)
# shellcheck disable=SC2086
timeout 3 env HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" -o IdentityAgent=none \
    $K -N "$T" </dev/null >"$W/out" 2>"$W/err"
rc=$?
took=$(( $(date +%s) - start ))
[ "$rc" -ne 0 ] && [ "$took" -ge 3 ] && ok "-N stays connected until stopped (${took}s, exit $rc)" \
    || bad "-N ended by itself: exit $rc after ${took}s" "$W/err"

echo
echo "== pseudo-terminals without a local terminal (pipes only, as on a host with no /dev/ptmx)"
# shellcheck disable=SC2086
out=$(p 2201 $K -o BatchMode=yes -tt "$T" 'tty' </dev/null 2>"$W/err" | tr -d '\r')
case $out in /dev/pts/*) ok "-tt allocates a remote pty ($out)" ;; *) bad "-tt: got '$out'" "$W/err" ;; esac
# shellcheck disable=SC2086
out=$(p 2202 $K -o BatchMode=yes -tt "$T" 'test -t 0 && echo pty || echo nopty' </dev/null 2>"$W/err" | tr -d '\r')
[ "$out" = nopty ] && grep -q "did not grant" "$W/err" && ok "PermitTTY=no: runs without a pty, and says so" \
    || bad "PermitTTY=no: got '$out'" "$W/err"
# Ctrl-C as a byte through a pipe, into a remote pty: the remote sleep dies.
start=$(date +%s)
# shellcheck disable=SC2086
(sleep 1; printf 'sleep 30\n'; sleep 1; printf '\003'; sleep 1; printf 'echo AFTER-$((2+3))\nexit 9\n') \
    | p 2201 $K -o BatchMode=yes -tt "$T" >"$W/out" 2>"$W/err"
rc=$?
took=$(( $(date +%s) - start ))
grep -q "AFTER-5" "$W/out" && [ "$rc" = 9 ] && [ "$took" -lt 15 ] \
    && ok "Ctrl-C through a pipe interrupts the remote command (${took}s, exit $rc)" \
    || bad "Ctrl-C through a pipe: exit $rc after ${took}s" "$W/out"
# A full-screen editor through pipes: vi writes a file the next command reads.
# shellcheck disable=SC2086
(sleep 1; printf 'rm -f /tmp/pipe-vi; vi /tmp/pipe-vi\n'; sleep 2; printf 'ithrough a pipe\033'; sleep 1
 printf ':wq\n'; sleep 1; printf 'cat /tmp/pipe-vi; exit 0\n') \
    | p 2201 $K -o BatchMode=yes -tt "$T" >"$W/out" 2>"$W/err"
rc=$?
# shellcheck disable=SC2086
saved=$(p 2201 $K -o BatchMode=yes "$T" 'cat /tmp/pipe-vi' </dev/null 2>/dev/null)
[ "$rc" = 0 ] && [ "$saved" = "through a pipe" ] && ok "vi through pipes edits and saves a file" \
    || bad "vi through pipes: exit $rc, file holds '$saved'" "$W/out"

# shellcheck source=scripts/interop-keygen.sh
. "$HERE/interop-keygen.sh"
# shellcheck source=scripts/interop-faults.sh
. "$HERE/interop-faults.sh"

echo
echo "== an interactive terminal (a local pty, driven by scripts/interop-pty.py)"
env -u SSH_AUTH_SOCK HOME="$W" python3 "$HERE/interop-pty.py" "$BIN" "$KH" "$W/id_ed25519" >"$W/pty.log" 2>&1
rc=$?
cat "$W/pty.log"
pass=$((pass + $(grep -c '^ok ' "$W/pty.log")))
fail=$((fail + $(grep -c '^FAIL' "$W/pty.log")))
[ "$rc" -eq 0 ] || [ "$(grep -c '^FAIL' "$W/pty.log")" -gt 0 ] || { fail=$((fail + 1)); echo "FAIL  the pty driver exited $rc"; }

for f in "$W"/sshd-*.pid "$W/dropbear.pid"; do
    [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null
done
echo
echo "interop: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
