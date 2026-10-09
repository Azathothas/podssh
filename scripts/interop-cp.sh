# podssh cp against OpenSSH's sftp-server (T-134). Sourced by
# scripts/interop.sh once its servers run; uses its ok, bad, expect_rc, $W,
# $T, $K, $KH and $BIN. Two more sshd run here: one whose sftp subsystem
# flips one data byte each way (the planted defect: a copy must exit 70 and
# leave the destination as it was), and one with ForceCommand internal-sftp,
# where no digest command runs and the far digest comes from a second read.
# Three more have no SFTP, for the copy by exec (T-135): a plain one, one
# whose ForceCommand prints a banner first, and one that turns each \r of
# the output into \n, so that the bytes must go through base64.

echo
echo "== cp (OpenSSH's sftp-server)"
CW="$W/cp"
mkdir -p "$CW/up" "$CW/down"
RD=/home/podtest/cp
mkdir -p "$RD"
chown podtest:podtest "$RD"

# c PORT [cp arguments...]: podssh cp as p() runs ssh.
c() {
    _port=$1
    shift
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK HOME="$W" "$BIN" cp --direct -P "$_port" \
        -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes $K --timeout 120s "$@"
}
sum() { sha256sum "$1" | cut -d' ' -f1; }
# No temporary file stays behind, here or on the server.
no_part() {
    if find "$RD" "$CW/down" -name '*.podssh-*.part' | grep -q .; then
        bad "$1: a temporary file stayed" ; find "$RD" "$CW/down" -name '*.podssh-*.part'
    else
        ok "$1: no temporary file stayed"
    fi
}

for n in 0 1 262145 5000000; do
    head -c "$n" /dev/urandom >"$CW/up/f$n"
    c 2201 "$CW/up/f$n" "$T:cp/f$n" >"$CW/out" 2>"$CW/err"
    rc=$?
    [ "$rc" = 0 ] && [ "$(sum "$CW/up/f$n")" = "$(sum "$RD/f$n")" ] \
        && ok "cp up, $n bytes: the digests agree" || bad "cp up, $n bytes: exit $rc" "$CW/err"
    c 2201 "$T:cp/f$n" "$CW/down/f$n" >"$CW/out" 2>"$CW/err"
    rc=$?
    [ "$rc" = 0 ] && [ "$(sum "$RD/f$n")" = "$(sum "$CW/down/f$n")" ] \
        && ok "cp down, $n bytes: the digests agree" || bad "cp down, $n bytes: exit $rc" "$CW/err"
done

# Over an existing file, each way; then several sources into a directory.
head -c 70000 /dev/urandom >"$CW/up/new"
c 2201 "$CW/up/new" "$T:cp/f262145" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$CW/up/new")" = "$(sum "$RD/f262145")" ] \
    && ok "cp up over an existing file replaces it" || bad "cp up over a file: exit $rc" "$CW/err"
c 2201 "$T:cp/f1" "$CW/down/f262145" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$RD/f1")" = "$(sum "$CW/down/f262145")" ] \
    && ok "cp down over an existing file replaces it" || bad "cp down over a file: exit $rc" "$CW/err"
mkdir -p "$RD/many"
chown podtest:podtest "$RD/many"
c 2201 "$CW/up/f1" "$CW/up/new" "$T:cp/many" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ -f "$RD/many/f1" ] && [ "$(sum "$CW/up/new")" = "$(sum "$RD/many/new")" ] \
    && ok "cp up of two files into a directory" || bad "cp up into a directory: exit $rc" "$CW/err"

# --jsonl: one object, with the digest that sha256sum gives.
c 2201 --jsonl "$CW/up/f1" "$T:cp/j1" >"$CW/out" 2>"$CW/err"
rc=$?
want=$(sum "$CW/up/f1")
[ "$rc" = 0 ] && [ "$(wc -l <"$CW/out")" = 1 ] && grep -q '"event":"done"' "$CW/out" \
    && grep -q "\"sha256\":\"$want\"" "$CW/out" && grep -q '"verified_by":"sha256sum"' "$CW/out" \
    && ok "cp --jsonl prints one done object with the SHA-256" || bad "cp --jsonl: exit $rc" "$CW/out"

# On one server, copy-data: no byte comes through here.
c 2201 --jsonl "$T:cp/f262145" "$T:cp/within" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$RD/f262145")" = "$(sum "$RD/within")" ] && grep -q '"verified_by":"sha256sum"' "$CW/out" \
    && ok "cp within one server, by copy-data" || bad "cp within one server: exit $rc" "$CW/err"
# Two names of this server are two servers: the copy goes through here.
c 2201 "$T:cp/f1" "podtest@localhost:cp/across" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$RD/f1")" = "$(sum "$RD/across")" ] \
    && ok "cp from server to server, through this host" || bad "cp from server to server: exit $rc" "$CW/err"

# The exit codes of a missing source and of a destination that cannot be made.
c 2201 "$CW/up/missing" "$T:cp/x" >/dev/null 2>"$CW/err"
expect_rc "cp up of a missing source" 66 $? "$CW/err"
c 2201 "$T:cp/missing" "$CW/down/x" >/dev/null 2>"$CW/err"
expect_rc "cp down of a missing source" 66 $? "$CW/err"
c 2201 "$CW/up/f1" "$T:/nonexistent-dir/x" >/dev/null 2>"$CW/err"
expect_rc "cp up into a directory that does not exist" 73 $? "$CW/err"
no_part "cp, each case above"

# The planted defect: a subsystem that flips one data byte each way.
cat >"$CW/flip.py" <<'EOF'
import subprocess, sys, threading
child = subprocess.Popen(["/usr/lib/ssh/sftp-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def exact(f, n):
    out = b""
    while len(out) < n:
        part = f.read(n - len(out))
        if not part:
            return None
        out += part
    return out
def data_at(body):
    # WRITE (6): id, handle, offset, data; DATA (103): id, data.
    if body[0] == 6:
        return 9 + int.from_bytes(body[5:9], "big") + 8
    return 5 if body[0] == 103 else None
def pump(src, dst, kind):
    flipped = False
    while True:
        head = exact(src, 4)
        body = head and exact(src, int.from_bytes(head, "big"))
        if not body:
            break
        body = bytearray(body)
        at = data_at(body)
        if not flipped and body[0] == kind and at is not None and int.from_bytes(body[at:at + 4], "big") > 0:
            body[-1] ^= 1
            flipped = True
        dst.write(head + bytes(body))
        dst.flush()
    dst.close()
threading.Thread(target=pump, args=(sys.stdin.buffer, child.stdin, 6), daemon=True).start()
pump(child.stdout, sys.stdout.buffer, 103)
EOF
chmod 644 "$CW/flip.py"
for spec in "2205:Subsystem sftp /usr/bin/python3 $CW/flip.py" "2206:ForceCommand internal-sftp"; do
    port=${spec%%:*}
    {
        echo "Port $port"
        echo "ListenAddress 127.0.0.1"
        echo "HostKey $W/host_ed25519"
        echo "PidFile $W/sshd-$port.pid"
        echo "StrictModes no"
        echo "KbdInteractiveAuthentication no"
        [ "$port" = 2206 ] && echo "Subsystem sftp internal-sftp"
        echo "${spec#*:}"
    } >"$CW/sshd-$port.conf"
    /usr/sbin/sshd -f "$CW/sshd-$port.conf" -E "$CW/sshd-$port.log" || bad "sshd on $port did not start" "$CW/sshd-$port.log"
done
sleep 1

printf 'the old content\n' >"$CW/old"
cp "$CW/old" "$RD/kept"
chown podtest:podtest "$RD/kept"
c 2205 "$CW/up/f262145" "$T:cp/kept" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 70 ] && cmp -s "$CW/old" "$RD/kept" && grep -q "the digests differ" "$CW/err" \
    && ok "a flipped byte up: exit 70, the destination as it was" || bad "a flipped byte up: exit $rc" "$CW/err"
cp "$CW/old" "$CW/down/kept"
c 2205 "$T:cp/f262145" "$CW/down/kept" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 70 ] && cmp -s "$CW/old" "$CW/down/kept" && grep -q "the digests differ" "$CW/err" \
    && ok "a flipped byte down: exit 70, the destination as it was" || bad "a flipped byte down: exit $rc" "$CW/err"
no_part "cp through the flipping subsystem"

# No exec (ForceCommand internal-sftp): the far digest is a second read.
c 2206 --jsonl "$CW/up/f262145" "$T:cp/r2" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$CW/up/f262145")" = "$(sum "$RD/r2")" ] && grep -q '"verified_by":"read again"' "$CW/out" \
    && ok "cp with no exec verifies by a second read" || bad "cp with no exec: exit $rc" "$CW/out"

# The copy by exec (T-135): no Subsystem line, so each step is a command.
# 2208's ForceCommand prints a line before each command, as a login's
# start-up file can: the marker must keep it out of the data. 2209's turns
# each \r of the output into \n: the check of the 256 byte values must find
# it, and the bytes then go through base64.
for port in 2207 2208 2209; do
    cat >"$CW/sshd-$port.conf" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $W/host_ed25519
PidFile $W/sshd-$port.pid
StrictModes no
KbdInteractiveAuthentication no
EOF
done
cat >>"$CW/sshd-2208.conf" <<'EOF'
ForceCommand printf 'podssh test banner\n'; sh -c "$SSH_ORIGINAL_COMMAND"
EOF
cat >>"$CW/sshd-2209.conf" <<'EOF'
ForceCommand sh -c "$SSH_ORIGINAL_COMMAND" | tr '\r' '\n'
EOF
for port in 2207 2208 2209; do
    /usr/sbin/sshd -f "$CW/sshd-$port.conf" -E "$CW/sshd-$port.log" || bad "sshd on $port did not start" "$CW/sshd-$port.log"
done
sleep 1

# Each size both ways, on OpenSSH with no SFTP, with the banner, with the
# changed \r, and on Dropbear (which may find an sftp-server: the case names
# the road it took).
for port in 2207 2208 2209 2203; do
    how="raw through cat"
    [ "$port" = 2209 ] && how="through base64"
    for n in 0 1 5000000; do
        c "$port" -v "$CW/up/f$n" "$T:cp/x$port-$n" >/dev/null 2>"$CW/err"
        rc=$?
        road=sftp
        grep -q "by exec" "$CW/err" && road=exec
        [ "$rc" = 0 ] && [ "$(sum "$CW/up/f$n")" = "$(sum "$RD/x$port-$n")" ] \
            && ok "cp up on port $port, $n bytes, by $road: the digests agree" || bad "cp up on port $port, $n bytes: exit $rc" "$CW/err"
        [ "$port" = 2203 ] || { [ "$road" = exec ] && grep -q "the bytes go $how" "$CW/err"; } \
            || bad "cp up on port $port did not name the exec road and '$how'" "$CW/err"
        c "$port" -v "$T:cp/x$port-$n" "$CW/down/x$port-$n" >/dev/null 2>"$CW/err"
        rc=$?
        [ "$rc" = 0 ] && [ "$(sum "$RD/x$port-$n")" = "$(sum "$CW/down/x$port-$n")" ] \
            && ok "cp down on port $port, $n bytes, by $road: the digests agree" || bad "cp down on port $port, $n bytes: exit $rc" "$CW/err"
    done
done

# Within one server with no SFTP: through this host, down and then up.
c 2207 "$T:cp/x2207-5000000" "$T:cp/within-exec" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$RD/x2207-5000000")" = "$(sum "$RD/within-exec")" ] \
    && ok "cp within one server by exec, through this host" || bad "cp within one server by exec: exit $rc" "$CW/err"

# Names that a far shell must get as one word: a space, a quote, a leading -.
for name in "a b" "it's" "-lead"; do
    cp "$CW/up/f262145" "$CW/up/$name"
    c 2207 "$CW/up/$name" "$T:cp/" >/dev/null 2>"$CW/err"
    rc=$?
    c 2207 "$T:cp/$name" "$CW/down/" >/dev/null 2>>"$CW/err"
    rc2=$?
    [ "$rc" = 0 ] && [ "$rc2" = 0 ] && [ "$(sum "$CW/up/$name")" = "$(sum "$RD/$name")" ] \
        && [ "$(sum "$CW/up/$name")" = "$(sum "$CW/down/$name")" ] \
        && ok "cp by exec of the name '$name', both ways" || bad "cp by exec of '$name': exit $rc and $rc2" "$CW/err"
done
# A name that is not UTF-8 is refused before anything connects.
c 2207 "$CW/up/$(printf 'n\377')" "$T:cp/" >/dev/null 2>"$CW/err"
expect_rc "cp of a name that is not UTF-8" 64 $? "$CW/err"
# A directory where the file would go: 73 on both roads, and nothing goes
# into it (mv would move the file inside).
mkdir -p "$RD/d2/f1"
chown -R podtest:podtest "$RD/d2"
for port in 2201 2207; do
    c "$port" "$CW/up/f1" "$T:cp/d2/" >/dev/null 2>"$CW/err"
    expect_rc "cp up onto the name of a directory, port $port" 73 $? "$CW/err"
done
[ -z "$(ls -A "$RD/d2/f1")" ] && ok "cp put nothing into the directory of that name" \
    || bad "cp put a file into the directory of that name"
# A far file that the login cannot read is a source that cannot be read: 66
# on both roads, as a missing one.
cp "$CW/up/f1" "$RD/noread"
chown podtest:podtest "$RD/noread"
chmod 000 "$RD/noread"
for port in 2201 2207; do
    c "$port" "$T:cp/noread" "$CW/down/noread$port" >/dev/null 2>"$CW/err"
    expect_rc "cp down of a far file that cannot be read, port $port" 66 $? "$CW/err"
done
no_part "cp by exec"

# podssh mv, while these servers run (T-138).
# shellcheck source=scripts/interop-mv.sh
. "$HERE/interop-mv.sh"
# podssh scp and podssh sftp (T-139).
# shellcheck source=scripts/interop-sftp.sh
. "$HERE/interop-sftp.sh"
# A copy that goes on after a broken connection (T-136).
# shellcheck source=scripts/interop-resume.sh
. "$HERE/interop-resume.sh"

for port in 2205 2206 2207 2208 2209; do
    [ -f "$W/sshd-$port.pid" ] && kill "$(cat "$W/sshd-$port.pid")" 2>/dev/null
done
