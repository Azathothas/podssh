#!/bin/sh
# podssh against real SSH servers: OpenSSH and Dropbear on 127.0.0.1, in the
# build image (rust:1-alpine). Run by scripts/gate.sh after the static build;
# by hand: sh scripts/interop.sh target/x86_64-unknown-linux-musl/release/podssh
#
# Every case prints `ok ID` or `FAIL ID` with what was expected and what came
# back (scripts/interop-lib.sh, T-199; the ids are in
# scripts/interop-baseline.txt); the script exits non-zero if any case failed. Servers, keys and the test
# user's password are created here and live only in this container.

set -u
BIN=${1:?usage: sh scripts/interop.sh PATH_TO_PODSSH}
case $BIN in /*) ;; *) BIN=$(pwd)/$BIN ;; esac
[ -x "$BIN" ] || { echo "interop: $BIN is not an executable"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
W=/tmp/podssh-interop
rm -rf "$W"
mkdir -p "$W"
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

echo "== servers"
# openssh-client-default is ssh itself, for the % tokens of `ssh -G`.
apk add --no-cache openssh-server openssh-server-pam openssh-keygen openssh-sftp-server openssh-client-default \
    dropbear python3 linux-pam openssl tmux curl >"$W/apk.log" 2>&1 || { cat "$W/apk.log"; exit 1; }
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
        # OpenSSH 9.8 and later refuse a source for a while after failed
        # logins, which these tests make on purpose: a later login of the
        # run would fail at random.
        echo "PerSourcePenalties no"
        for line in "$@"; do echo "$line"; done
    } >"$W/sshd-$_port.conf"
}
# PermitListen: the one port that -R may take on 2201, so that another is
# refused by sshd itself, whatever ports the kernel lets a user bind.
sshd_conf 2201 "KbdInteractiveAuthentication no" "PermitListen 2290"
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
for srv in openssh:2201 dropbear:2203; do
    port=${srv#*:}
    for spec in "3:exit 3" "0:true" "1:false" "127:no-such-command-here" "143:kill -TERM \$\$"; do
        want=${spec%%:*}
        cmd=${spec#*:}
        # shellcheck disable=SC2086
        p "$port" $K -o BatchMode=yes "$T" "$cmd" >"$W/out" 2>"$W/err" </dev/null
        expect_rc "ssh.exit.${srv%%:*}.${spec%%:*}" "port $port: '$cmd'" "$want" $? "$W/err"
    done
done
grep -q "killed by signal TERM" "$W/err" && ok ssh.exit.signal_named "a remote signal is named on stderr" \
    || bad ssh.exit.signal_named "no signal message" "$W/err"

. "$HERE/interop-status.sh"

echo
echo "== streams"
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes "$T" 'echo to-stdout; echo to-stderr >&2' >"$W/out" 2>"$W/err" </dev/null
[ "$(cat "$W/out")" = to-stdout ] && grep -q to-stderr "$W/err" && ! grep -q to-stderr "$W/out" \
    && ok ssh.stream.apart "stdout and stderr stay apart" || bad ssh.stream.apart "streams mixed" "$W/out"
for size in 262144 262145 5000000; do
    head -c "$size" /dev/urandom >"$W/blob"
    want=$(sha256sum <"$W/blob" | cut -c1-64)
    for srv in openssh:2201 dropbear:2203; do
        port=${srv#*:}
        # shellcheck disable=SC2086
        got=$(p "$port" $K -o BatchMode=yes "$T" sha256sum <"$W/blob" 2>"$W/err" | cut -c1-64)
        [ "$got" = "$want" ] && ok "ssh.stream.${srv%%:*}.${size}.up" "port $port: $size bytes up" \
            || bad "ssh.stream.${srv%%:*}.${size}.up" "port $port: $size bytes up: $got != $want" "$W/err"
        # shellcheck disable=SC2086
        p "$port" $K -o BatchMode=yes "$T" "cat > /tmp/b && cat /tmp/b" <"$W/blob" >"$W/back" 2>"$W/err"
        got=$(sha256sum <"$W/back" | cut -c1-64)
        [ "$got" = "$want" ] && ok "ssh.stream.${srv%%:*}.${size}.roundtrip" "port $port: $size bytes up and back" \
            || bad "ssh.stream.${srv%%:*}.${size}.roundtrip" "port $port: $size bytes round trip" "$W/err"
    done
done
# The memory of a session whose output nobody reads (T-201).
# shellcheck source=scripts/interop-limits.sh
. "$HERE/interop-limits.sh"

echo
echo "== authentication"
for k in rsa ecdsa; do
    p 2201 -i "$W/id_$k" -o BatchMode=yes "$T" true </dev/null >"$W/out" 2>"$W/err"
    expect_rc "ssh.auth.key.${k}" "$k key" 0 $? "$W/err"
done
SSH_ASKPASS="$W/askpass-passphrase" SSH_ASKPASS_REQUIRE=force p 2201 -i "$W/id_enc" "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.auth.encrypted_askpass "encrypted key, passphrase from SSH_ASKPASS" 0 $? "$W/err"
p 2201 -i "$W/id_enc" -o BatchMode=yes "$T" true </dev/null >"$W/out" 2>"$W/err"
rc=$?
expect_rc ssh.auth.encrypted_batch "encrypted key, nobody to ask" 255 $rc "$W/err"
grep -q "skipped encrypted key" "$W/err" && ok ssh.auth.encrypted_named "the refusal names the skipped key" \
    || bad ssh.auth.encrypted_named "no note about the encrypted key" "$W/err"
for srv in openssh:2201 dropbear:2203; do
    port=${srv#*:}
    SSH_ASKPASS="$W/askpass-password" SSH_ASKPASS_REQUIRE=force \
        p "$port" -o PubkeyAuthentication=no "$T" 'exit 4' </dev/null >"$W/out" 2>"$W/err"
    expect_rc "ssh.auth.password.${srv%%:*}" "port $port: password from SSH_ASKPASS" 4 $? "$W/err"
    SSH_ASKPASS="$W/askpass-wrong" SSH_ASKPASS_REQUIRE=force \
        p "$port" -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 "$T" true </dev/null >"$W/out" 2>"$W/err"
    expect_rc "ssh.auth.wrong_password.${srv%%:*}" "port $port: wrong password" 255 $? "$W/err"
done
grep -q "Permission denied" "$W/err" && ok ssh.auth.permission_denied "a wrong password says Permission denied" \
    || bad ssh.auth.permission_denied "no Permission denied" "$W/err"
p 2201 -o PubkeyAuthentication=no -o BatchMode=yes "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.auth.password_batch "password with BatchMode" 255 $? "$W/err"
grep -q "password authentication was skipped" "$W/err" && ok ssh.auth.password_batch_named "BatchMode names the skipped password" \
    || bad ssh.auth.password_batch_named "no note" "$W/err"
# Keys were turned off, so the refusal does not send the user to -i FILE (GitHub #7).
grep -q "publickey was not tried: -o PubkeyAuthentication=no" "$W/err" && ! grep -q "no key was offered" "$W/err" \
    && ok ssh.auth.keys_off_note "keys turned off: the refusal says so and does not name -i" \
    || bad ssh.auth.keys_off_note "keys turned off: the wrong note" "$W/err"
if [ -n "$PAM_SSHD" ]; then
    SSH_ASKPASS="$W/askpass-password" SSH_ASKPASS_REQUIRE=force \
        p 2204 -o PubkeyAuthentication=no "$T" 'exit 6' </dev/null >"$W/out" 2>"$W/err"
    expect_rc ssh.auth.kbdint_pam "keyboard-interactive (PAM) from SSH_ASKPASS" 6 $? "$W/err"
else
    unmet ssh.auth.kbdint_pam "keyboard-interactive: sshd.pam is not in this image"
fi

echo
echo "== host keys"
grep -c . "$KH" >/dev/null && ok ssh.hostkey.recorded "keys were recorded with accept-new ($(grep -c . "$KH") lines)" \
    || bad ssh.hostkey.recorded "known_hosts is empty"
# shellcheck disable=SC2086
p 2201 $K -o StrictHostKeyChecking=yes -o BatchMode=yes "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.hostkey.strict_known "a recorded key is accepted under StrictHostKeyChecking=yes" 0 $? "$W/err"
sed 's/^\(\[127.0.0.1\]:2201 ssh-ed25519 \).*/\1AAAAC3NzaC1lZDI1NTE5AAAAIBXkNYHrJ3fDOpgDDGbs1lnK9rmzEHaN7Jbn9jC7Wjlx/' "$KH" >"$W/kh_changed"
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$W/kh_changed" \
    -o StrictHostKeyChecking=no -o IdentityAgent=none $K "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.hostkey.changed_refused "a changed key is refused even with StrictHostKeyChecking=no" 255 $? "$W/err"
grep -q "HAS CHANGED" "$W/err" && ok ssh.hostkey.changed_warning "the changed-key warning is shown" \
    || bad ssh.hostkey.changed_warning "no warning" "$W/err"
# T-028: a user file that cannot be read is no empty file under accept-new,
# and a key that cannot be recorded is said to hold for this connection only.
mkdir -p "$W/kh_dir"
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$W/kh_dir" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes "$T" true \
    </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.hostkey.unreadable_refused "T-028: accept-new refuses a key when the user file cannot be read" 255 $? "$W/err"
grep -q "kh_dir" "$W/err" && grep -q "cannot be verified" "$W/err" \
    && ok ssh.hostkey.unreadable_named "T-028: the refusal names the file that cannot be read" \
    || bad ssh.hostkey.unreadable_named "T-028: the file is not named" "$W/err"
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile=/proc/podssh-known-hosts \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes "$T" true \
    </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.hostkey.unrecordable_connects "T-028: accept-new connects when the key cannot be recorded" 0 $? "$W/err"
grep -q "not recorded" "$W/err" && grep -q "for this connection only" "$W/err" \
    && ok ssh.hostkey.unrecordable_note "T-028: the note says that the key was not recorded" \
    || bad ssh.hostkey.unrecordable_note "T-028: no note" "$W/err"
# T-031: the fingerprints of the server's two keys, as ssh-keygen prints them,
# are the only keys accepted, and nothing is recorded; another is refused.
fp=$(ssh-keygen -l -E sha256 -f "$W/host_ed25519.pub" | awk '{print $2}')
fp="$fp,$(ssh-keygen -l -E sha256 -f "$W/host_rsa.pub" | awk '{print $2}')"
: >"$W/kh_pinned"
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$W/kh_pinned" \
    -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes \
    --host-key-fingerprint "$fp" "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.hostkey.pinned_connects "T-031: the named fingerprint connects with an empty known_hosts" 0 $? "$W/err"
[ ! -s "$W/kh_pinned" ] && ok ssh.hostkey.pinned_unrecorded "T-031: nothing was recorded" \
    || bad ssh.hostkey.pinned_unrecorded "T-031: the key was recorded" "$W/kh_pinned"
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$W/kh_pinned" \
    -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes \
    --host-key-fingerprint SHA256:JfDOvc6FaJOB34ANs+ou385/Kh+mMQhnUx0gHXVAfUI "$T" true </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.hostkey.pinned_other_refused "T-031: another fingerprint is refused" 255 $? "$W/err"
# T-027: OpenSSH's host certificate, signed by a CA that known_hosts names,
# under strict checking; nothing is recorded. Its own sshd, on port 2211.
ssh-keygen -q -t ed25519 -N '' -C interop-ca -f "$W/ca_t027"
ssh-keygen -q -s "$W/ca_t027" -I podssh-t027 -h -n 127.0.0.1 -V -5m:+1h "$W/host_ed25519.pub"
sshd_conf 2211 "KbdInteractiveAuthentication no" "HostCertificate $W/host_ed25519-cert.pub"
/usr/sbin/sshd -f "$W/sshd-2211.conf" -E "$W/sshd-2211.log" || cat "$W/sshd-2211.log"
tries=0
while ! python3 -c 'import socket; socket.create_connection(("127.0.0.1", 2211), 1).close()' 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -ge 50 ] && break
    sleep 0.1
done
printf '@cert-authority [127.0.0.1]:2211 %s\n' "$(cat "$W/ca_t027.pub")" >"$W/kh_ca"
cp "$W/kh_ca" "$W/kh_ca.before"
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2211 -o UserKnownHostsFile="$W/kh_ca" \
    -o StrictHostKeyChecking=yes -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes "$T" true \
    </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.hostkey.cert_accepted "T-027: a host certificate from a CA of known_hosts, under StrictHostKeyChecking=yes" 0 $? "$W/err"
cmp -s "$W/kh_ca" "$W/kh_ca.before" && ok ssh.hostkey.cert_unrecorded "T-027: nothing was recorded" \
    || bad ssh.hostkey.cert_unrecorded "T-027: known_hosts changed" "$W/kh_ca"
kill "$(cat "$W/sshd-2211.pid")" 2>/dev/null

echo
echo "== % tokens, against OpenSSH's own expansion (ssh -G)"
# podssh records the host key in the file that UserKnownHostsFile names, so
# the file's name is podssh's expansion; ssh -G prints OpenSSH's for the same
# tokens in ControlPath. %u is the local user, %r the remote one (T-238).
TOK="$W/tok"
mkdir -p "$TOK"
spec='%C-%L-%l-%i-%u-%r-%h-%p-%n-%j-%k'
want=$(ssh -F /dev/null -G -o ControlPath="$TOK/$spec" -p 2201 "$T" </dev/null 2>/dev/null | sed -n 's/^controlpath //p')
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$TOK/$spec" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes "$T" true \
    </dev/null >"$W/out" 2>"$W/err"
rc=$?
got=$(ls -d "$TOK"/* 2>/dev/null)
[ "$rc" = 0 ] && [ -n "$want" ] && [ "$got" = "$want" ] \
    && ok ssh.config.tokens "% tokens: podssh expands %C %L %l %i %u %r %h %p %n %j %k as ssh -G does" \
    || bad ssh.config.tokens "% tokens: exit $rc; podssh wrote ${got:-nothing}; ssh -G gives ${want:-nothing}" "$W/err"

# podssh ssh -G (T-046): each line that podssh prints is one of OpenSSH's,
# but for the defaults that differ on purpose. HOME is the one that OpenSSH
# reads from the user database.
home=$(awk -F: -v u="$(id -un)" '$1 == u {print $6}' /etc/passwd)
for spec in "short:-p 2222 -l alice example.org" \
        "long:-l alice -o ServerAliveInterval=30 -o ConnectTimeout=7 -o StrictHostKeyChecking=accept-new -o SendEnv=LANG -o LogLevel=VERBOSE -e % -4 -J u@b:2200,c -o RemoteCommand=uptime -o IdentityAgent=none EXAMPLE.org"; do
    args=${spec#*:}
    # shellcheck disable=SC2086
    ssh -F /dev/null -G $args </dev/null >"$W/ssh-G" 2>/dev/null
    # shellcheck disable=SC2086
    env HOME="$home" PODSSH_OFFLINE=1 "$BIN" ssh -F none -G $args </dev/null >"$W/podssh-G" 2>"$W/err"
    rc=$?
    extra=$(grep -v -E '^(serveraliveinterval|connecttimeout) ' "$W/podssh-G" | grep -vxF -f "$W/ssh-G" | tr '\n' ';')
    [ "$rc" = 0 ] && [ -s "$W/podssh-G" ] && [ -z "$extra" ] && [ ! -s "$W/err" ] \
        && ok "ssh.config.g.${spec%%:*}" "ssh -G: each line that podssh prints is OpenSSH's ($args)" \
        || bad "ssh.config.g.${spec%%:*}" "ssh -G ($args): exit $rc; not OpenSSH's: ${extra:-nothing}" "$W/err"
done

# ssh_config (T-043): a Host alias of a -F file takes each server's HostName,
# Port, User and IdentityFile from the file, and podssh's -G for the alias
# holds OpenSSH's lines, but for the defaults that differ on purpose.
printf 'Host %s\n  HostName 127.0.0.1\n  Port %s\n  User podtest\n  IdentityFile %s\n' \
    openssh-alias 2201 "$W/id_ed25519" dropbear-alias 2203 "$W/id_ed25519" >"$W/ssh_config"
for alias in openssh-alias dropbear-alias; do
    env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -F "$W/ssh_config" -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o BatchMode=yes "$alias" 'exit 4' \
        </dev/null >"$W/out" 2>"$W/err"
    expect_rc "ssh.config.alias.${alias}" "-F FILE: the alias $alias reaches its server" 4 $? "$W/err"
    ssh -F "$W/ssh_config" -G "$alias" </dev/null >"$W/ssh-G" 2>/dev/null
    env HOME="$home" PODSSH_OFFLINE=1 "$BIN" ssh -F "$W/ssh_config" -G "$alias" </dev/null >"$W/podssh-G" 2>"$W/err"
    rc=$?
    extra=$(grep -v -E '^(serveraliveinterval|connecttimeout) ' "$W/podssh-G" | grep -vxF -f "$W/ssh-G" | tr '\n' ';')
    [ "$rc" = 0 ] && [ -s "$W/podssh-G" ] && [ -z "$extra" ] \
        && ok "ssh.config.g_file.${alias}" "ssh -G -F FILE: each line that podssh prints is OpenSSH's ($alias)" \
        || bad "ssh.config.g_file.${alias}" "ssh -G -F FILE ($alias): exit $rc; not OpenSSH's: ${extra:-nothing}" "$W/err"
done

# Include and Match final all (T-044): the hosts of a file come from an
# Include glob, read in sorted order, and Match final all fills what is unset.
mkdir -p "$W/inc/d1" "$W/inc/d2"
printf 'Host inc-alias\n  Port 2401\n  User podtest\n' >"$W/inc/d1/a.conf"
printf 'Host inc-alias\n  Port 2400\n' >"$W/inc/d2/a.conf"
printf 'Include %s/inc/d*/a.conf\nMatch final all\n  ConnectTimeout 9\n  User nobody\n' "$W" >"$W/inc/main"
ssh -F "$W/inc/main" -G inc-alias </dev/null >"$W/ssh-G" 2>/dev/null
env HOME="$home" PODSSH_OFFLINE=1 "$BIN" ssh -F "$W/inc/main" -G inc-alias </dev/null >"$W/podssh-G" 2>"$W/err"
rc=$?
extra=$(grep -v -E '^serveraliveinterval ' "$W/podssh-G" | grep -vxF -f "$W/ssh-G" | tr '\n' ';')
[ "$rc" = 0 ] && [ -z "$extra" ] && grep -qx 'port 2401' "$W/podssh-G" && grep -qx 'user podtest' "$W/podssh-G" \
    && grep -qx 'connecttimeout 9' "$W/podssh-G" \
    && ok ssh.config.include "ssh -G with Include and Match final all: each line that podssh prints is OpenSSH's" \
    || bad ssh.config.include "ssh -G with Include and Match final all: exit $rc; not OpenSSH's: ${extra:-nothing}" "$W/err"

echo
echo "== forwarding, jump hosts, subsystems, environment"
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -W 127.0.0.1:2203 "$T" </dev/null >"$W/out" 2>"$W/err"
head -c 16 "$W/out" | grep -q "SSH-2.0-dropbear" && ok ssh.forward.w_banner "-W reaches Dropbear's banner through OpenSSH" \
    || bad ssh.forward.w_banner "-W" "$W/err"
# shellcheck disable=SC2086
p 2203 $K -o BatchMode=yes -J "$T:2201" "$T" 'exit 5' </dev/null >"$W/out" 2>"$W/err"
expect_rc ssh.forward.jump "-J through OpenSSH to Dropbear" 5 $? "$W/err"
# shellcheck source=scripts/interop-hostkeys.sh
. "$HERE/interop-hostkeys.sh"
printf '\000\000\000\005\001\000\000\000\003' >"$W/fxp_init"
# stdin stays open a moment: OpenSSH's sftp-server exits on end of input
# without flushing its reply (measured 2026-10-08 on a Debian host, without
# podssh: `printf INIT | sftp-server` prints nothing), as a real client would.
# shellcheck disable=SC2086
(cat "$W/fxp_init"; sleep 2) | p 2201 $K -o BatchMode=yes -s "$T" sftp >"$W/out" 2>"$W/err"
fxp=$(python3 -c 'import sys; d = open(sys.argv[1], "rb").read(); print(d[4] if len(d) > 4 else -1)' "$W/out")
[ "$fxp" = 2 ] && ok ssh.forward.subsystem_sftp "-s sftp answers SSH_FXP_VERSION" \
    || bad ssh.forward.subsystem_sftp "-s sftp: packet type $fxp" "$W/err"
# shellcheck disable=SC2086
out=$(p 2201 $K -o BatchMode=yes -o SetEnv=PODSSH_TEST_X=hello "$T" 'echo $PODSSH_TEST_X' </dev/null 2>"$W/err")
[ "$out" = hello ] && ok ssh.forward.setenv "SetEnv reaches the server" || bad ssh.forward.setenv "SetEnv: got '$out'" "$W/err"
start=$(date +%s)
# shellcheck disable=SC2086
timeout 3 env HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" -o IdentityAgent=none \
    $K -N "$T" </dev/null >"$W/out" 2>"$W/err"
rc=$?
took=$(( $(date +%s) - start ))
[ "$rc" -ne 0 ] && [ "$took" -ge 3 ] && ok ssh.forward.no_command "-N stays connected until stopped (${took}s, exit $rc)" \
    || bad ssh.forward.no_command "-N ended by itself: exit $rc after ${took}s" "$W/err"
# -R (T-035): OpenSSH listens on 2290 for podssh, and each connection that it
# takes reaches Dropbear's port from this host, through podssh.
# shellcheck disable=SC2086
p 2201 $K -o BatchMode=yes -N -R 127.0.0.1:2290:127.0.0.1:2203 "$T" </dev/null >"$W/out" 2>"$W/rerr" &
rpid=$!
banner=""
i=0
while [ $i -lt 50 ]; do
    banner=$(python3 -c '
import socket
s = socket.create_connection(("127.0.0.1", 2290), timeout=2)
print(s.recv(32).decode(errors="replace").strip())
' 2>/dev/null)
    case $banner in SSH-2.0-dropbear*) break ;; esac
    i=$((i + 1))
    sleep 0.2
done
kill "$rpid" 2>/dev/null
wait "$rpid" 2>/dev/null
case $banner in
    SSH-2.0-dropbear*) ok ssh.forward.remote "-R: OpenSSH's port 2290 reaches Dropbear's banner through podssh" ;;
    *) bad ssh.forward.remote "-R: port 2290 gave '$banner'" "$W/rerr" ;;
esac
# A port that sshd refuses (PermitListen), with ExitOnForwardFailure. Not a
# port under 1024: a kernel that lets a user bind one (Docker's default)
# gave the forward, and the run waited for its time limit.
# shellcheck disable=SC2086
timeout 20 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
    -o IdentityAgent=none $K -o BatchMode=yes -o ExitOnForwardFailure=yes -N -R 2291:127.0.0.1:2203 "$T" \
    </dev/null >"$W/out" 2>"$W/err"
rc=$?
[ "$rc" = 255 ] && grep -q "remote port forwarding failed for listen port 2291" "$W/err" \
    && ok ssh.forward.remote_refused "-R to a port that OpenSSH refuses, with ExitOnForwardFailure: exit 255, named" \
    || bad ssh.forward.remote_refused "-R refused: exit $rc" "$W/err"

echo
echo "== pseudo-terminals without a local terminal (pipes only, as on a host with no /dev/ptmx)"
# shellcheck disable=SC2086
out=$(p 2201 $K -o BatchMode=yes -tt "$T" 'tty' </dev/null 2>"$W/err" | tr -d '\r')
case $out in /dev/pts/*) ok ssh.pty.tt "-tt allocates a remote pty ($out)" ;; *) bad ssh.pty.tt "-tt: got '$out'" "$W/err" ;; esac
# shellcheck disable=SC2086
out=$(p 2202 $K -o BatchMode=yes -tt "$T" 'test -t 0 && echo pty || echo nopty' </dev/null 2>"$W/err" | tr -d '\r')
[ "$out" = nopty ] && grep -q "did not grant" "$W/err" && ok ssh.pty.permittty_no "PermitTTY=no: runs without a pty, and says so" \
    || bad ssh.pty.permittty_no "PermitTTY=no: got '$out'" "$W/err"
# Ctrl-C as a byte through a pipe, into a remote pty: the remote sleep dies.
start=$(date +%s)
# shellcheck disable=SC2086
(sleep 1; printf 'sleep 30\n'; sleep 1; printf '\003'; sleep 1; printf 'echo AFTER-$((2+3))\nexit 9\n') \
    | p 2201 $K -o BatchMode=yes -tt "$T" >"$W/out" 2>"$W/err"
rc=$?
took=$(( $(date +%s) - start ))
grep -q "AFTER-5" "$W/out" && [ "$rc" = 9 ] && [ "$took" -lt 15 ] \
    && ok ssh.pty.ctrl_c "Ctrl-C through a pipe interrupts the remote command (${took}s, exit $rc)" \
    || bad ssh.pty.ctrl_c "Ctrl-C through a pipe: exit $rc after ${took}s" "$W/out"
# A full-screen editor through pipes: vi writes a file the next command reads.
# shellcheck disable=SC2086
(sleep 1; printf 'rm -f /tmp/pipe-vi; vi /tmp/pipe-vi\n'; sleep 2; printf 'ithrough a pipe\033'; sleep 1
 printf ':wq\n'; sleep 1; printf 'cat /tmp/pipe-vi; exit 0\n') \
    | p 2201 $K -o BatchMode=yes -tt "$T" >"$W/out" 2>"$W/err"
rc=$?
# shellcheck disable=SC2086
saved=$(p 2201 $K -o BatchMode=yes "$T" 'cat /tmp/pipe-vi' </dev/null 2>/dev/null)
[ "$rc" = 0 ] && [ "$saved" = "through a pipe" ] && ok ssh.pty.vi "vi through pipes edits and saves a file" \
    || bad ssh.pty.vi "vi through pipes: exit $rc, file holds '$saved'" "$W/out"

# shellcheck source=scripts/interop-keygen.sh
. "$HERE/interop-keygen.sh"
# shellcheck source=scripts/interop-agent.sh
. "$HERE/interop-agent.sh"
# shellcheck source=scripts/interop-local.sh
. "$HERE/interop-local.sh"
# shellcheck source=scripts/interop-control.sh
. "$HERE/interop-control.sh"
# shellcheck source=scripts/interop-faults.sh
. "$HERE/interop-faults.sh"
# shellcheck source=scripts/interop-cp.sh
. "$HERE/interop-cp.sh"
# shellcheck source=scripts/interop-pipe.sh
. "$HERE/interop-pipe.sh"

echo
echo "== an interactive terminal (a local pty, driven by scripts/interop-pty.py)"
env -u SSH_AUTH_SOCK HOME="$W" python3 "$HERE/interop-pty.py" "$BIN" "$KH" "$W/id_ed25519" >"$W/pty.log" 2>&1
rc=$?
cat "$W/pty.log"
pass=$((pass + $(grep -c '^ok ' "$W/pty.log")))
fail=$((fail + $(grep -c '^FAIL' "$W/pty.log")))
{ [ "$rc" -eq 0 ] || [ "$(grep -c '^FAIL' "$W/pty.log")" -gt 0 ]; } && ok ssh.pty.driver "the pty driver ran (exit $rc)" \
    || bad ssh.pty.driver "the pty driver exited $rc with no result line"

for f in "$W"/sshd-*.pid "$W/dropbear.pid"; do
    [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null
done
echo
echo "interop: $pass passed, $fail failed, $skip skipped, $unmet env"
[ "$fail" -eq 0 ]
