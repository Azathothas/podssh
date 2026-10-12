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
# no_part ID TEXT: no temporary file stays behind, here or on the server.
no_part() {
    if find "$RD" "$CW/down" -name '*.podssh-*.part' | grep -q .; then
        bad "$1" "$2: a temporary file stayed" ; find "$RD" "$CW/down" -name '*.podssh-*.part'
    else
        ok "$1" "$2: no temporary file stayed"
    fi
}

for n in 0 1 262145 5000000; do
    head -c "$n" /dev/urandom >"$CW/up/f$n"
    c 2201 "$CW/up/f$n" "$T:cp/f$n" >"$CW/out" 2>"$CW/err"
    rc=$?
    [ "$rc" = 0 ] && [ "$(sum "$CW/up/f$n")" = "$(sum "$RD/f$n")" ] \
        && ok "cp.sftp.up.${n}" "cp up, $n bytes: the digests agree" \
        || bad "cp.sftp.up.${n}" "cp up, $n bytes: exit $rc" "$CW/err"
    c 2201 "$T:cp/f$n" "$CW/down/f$n" >"$CW/out" 2>"$CW/err"
    rc=$?
    [ "$rc" = 0 ] && [ "$(sum "$RD/f$n")" = "$(sum "$CW/down/f$n")" ] \
        && ok "cp.sftp.down.${n}" "cp down, $n bytes: the digests agree" \
        || bad "cp.sftp.down.${n}" "cp down, $n bytes: exit $rc" "$CW/err"
done

# -l (T-145): 8000 Kbit/s takes 5000000 bytes in 4.5 s or more; with the
# progress line on, stdout, a file here, gets nothing.
now() { python3 -c 'import time; print(time.time())'; }
start=$(now)
export PODSSH_PROGRESS=line
c 2201 -l 8000 "$CW/up/f5000000" "$T:cp/limited" >"$CW/out" 2>"$CW/err"
rc=$?
unset PODSSH_PROGRESS
took=$(python3 -c "print(round($(now) - $start, 1))")
[ "$rc" = 0 ] && python3 -c "import sys; sys.exit(0 if $took >= 4.5 else 1)" && [ ! -s "$CW/out" ] \
    && grep -q "f5000000  " "$CW/err" && [ "$(sum "$CW/up/f5000000")" = "$(sum "$RD/limited")" ] \
    && ok cp.limit "cp -l 8000, 5000000 bytes: $took s, the line on stderr, nothing on stdout" \
    || bad cp.limit "cp -l 8000: exit $rc, $took s" "$CW/err"
# SIGINT in the middle: 130, the temporary file and the side file named and
# kept; the same command then goes on from them. podssh itself, not a shell,
# gets the signal: env execs it.
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" cp --direct -P 2201 -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes $K \
    --timeout 120s -l 4000 "$CW/up/f5000000" "$T:cp/interrupted" >"$CW/out" 2>"$CW/err" &
pid=$!
sleep 2
kill -INT "$pid"
wait "$pid"
rc=$?
side=$(sed -n 's/.*(its record: \(.*\))$/\1/p' "$CW/err")
[ "$rc" = 130 ] && grep -q "interrupted; the partial copy stays at" "$CW/err" && [ -n "$side" ] && [ -f "$side" ] \
    && find "$RD" -name '.interrupted.podssh-*.part' | grep -q . \
    && c 2201 -v "$CW/up/f5000000" "$T:cp/interrupted" >"$CW/out" 2>"$CW/err2" \
    && grep -q "continuing" "$CW/err2" && [ "$(sum "$CW/up/f5000000")" = "$(sum "$RD/interrupted")" ] \
    && ok cp.interrupt "SIGINT: exit 130, the partial copy and its record kept, and the next run went on" \
    || bad cp.interrupt "SIGINT: exit $rc" "$CW/err"

# --parallel 4 (T-141): a file of three chunks and a part goes up and comes
# down as chunks, four at once, each over an SFTP session of its own.
head -c 25000000 /dev/urandom >"$CW/up/big"
c 2201 --parallel 4 "$CW/up/big" "$T:cp/big" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$CW/up/big")" = "$(sum "$RD/big")" ] \
    && ok cp.parallel.up "cp --parallel 4 up, 25000000 bytes: the digests agree" \
    || bad cp.parallel.up "cp --parallel 4 up: exit $rc" "$CW/err"
c 2201 --parallel 4 "$T:cp/big" "$CW/down/big" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$RD/big")" = "$(sum "$CW/down/big")" ] \
    && ok cp.parallel.down "cp --parallel 4 down, 25000000 bytes: the digests agree" \
    || bad cp.parallel.down "cp --parallel 4 down: exit $rc" "$CW/err"

# -r (T-143): a tree with levels, an empty directory, a name with a space,
# a link and a FIFO goes up and comes down; the lists of digests agree, the
# link stays a link, and the FIFO is skipped with a note (an exit not zero).
# A dry run changes nothing.
lists() { (cd "$1" && find . -type f -exec sha256sum {} + | sort); }
TR="$CW/tree"
mkdir -p "$TR/a/b c" "$TR/empty"
head -c 300000 /dev/urandom >"$TR/a/b c/f one"
printf top >"$TR/top"
ln -s "a/b c/f one" "$TR/link"
mkfifo "$TR/fifo"
c 2201 -r --dry-run "$TR" "$T:cp/tree" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && grep -q "^skip .*fifo" "$CW/out" && grep -q "^link " "$CW/out" && [ ! -e "$RD/tree" ] \
    && ok cp.tree.dry_run "cp -r --dry-run: each action said, and nothing changed" \
    || bad cp.tree.dry_run "cp -r --dry-run: exit $rc" "$CW/out"
c 2201 -r "$TR" "$T:cp/tree" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" != 0 ] && grep -q "fifo: not copied" "$CW/err" && [ "$(lists "$TR")" = "$(lists "$RD/tree")" ] \
    && [ -L "$RD/tree/link" ] && [ -d "$RD/tree/empty" ] \
    && ok cp.tree.up "cp -r up: the digests agree, the link is a link, the FIFO skipped" \
    || bad cp.tree.up "cp -r up: exit $rc" "$CW/err"
c 2201 -r "$T:cp/tree" "$CW/down/" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(lists "$RD/tree")" = "$(lists "$CW/down/tree")" ] && [ -L "$CW/down/tree/link" ] \
    && [ -d "$CW/down/tree/empty" ] \
    && ok cp.tree.down "cp -r down: the digests agree, the link is a link" \
    || bad cp.tree.down "cp -r down: exit $rc" "$CW/err"

# --delete (T-144): the target becomes a mirror: what the source lacks goes,
# and an excluded name and the file that a link names stay. A copy that
# fails (a FIFO in the source) deletes nothing.
rm -f "$TR/fifo"
mkdir -p "$RD/m"
chown podtest:podtest "$RD/m"
c 2201 -r "$TR" "$T:cp/m" >/dev/null 2>"$CW/err"
printf x >"$RD/m/tree/extra"
mkdir -p "$RD/m/tree/old/deep"
printf y >"$RD/m/tree/old/deep/y"
printf log >"$RD/m/tree/kept.log"
printf outside >"$CW/outside"
ln -s "$CW/outside" "$RD/m/tree/out-link"
# What this script made as root in the server's tree is its user's, as
# its own files are.
chown -hR podtest:podtest "$RD/m/tree"
c 2201 -r --delete --exclude '*.log' "$TR" "$T:cp/m" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ ! -e "$RD/m/tree/extra" ] && [ ! -e "$RD/m/tree/old" ] && [ -f "$RD/m/tree/kept.log" ] \
    && [ ! -L "$RD/m/tree/out-link" ] && [ "$(cat "$CW/outside")" = outside ] \
    && [ "$(lists "$TR")" = "$(cd "$RD/m/tree" && find . -type f ! -name kept.log -exec sha256sum {} + | sort)" ] \
    && ok cp.delete.mirror "cp -r --delete: what the source lacks went; the excluded name and the link's file stayed" \
    || bad cp.delete.mirror "cp -r --delete: exit $rc" "$CW/err"
printf z >"$RD/m/tree/extra2"
mkfifo "$TR/fifo2"
c 2201 -r --delete "$TR" "$T:cp/m" >"$CW/out" 2>"$CW/err"
rc=$?
rm -f "$TR/fifo2"
[ "$rc" != 0 ] && grep -q "nothing was deleted" "$CW/err" && [ -f "$RD/m/tree/extra2" ] \
    && ok cp.delete.failed "cp -r --delete after a failed copy: nothing deleted" \
    || bad cp.delete.failed "cp -r --delete after a failed copy: exit $rc" "$CW/err"

# --delta (T-142): over an older version, only the blocks of 1 MiB that
# changed go: -v says how many bytes, and no full copy follows.
# delta_sent: the bytes that -v says the delta sent.
delta_sent() { sed -n 's/.*delta: [0-9]* of [0-9]* blocks sent, \([0-9]*\) bytes.*/\1/p' "$CW/err"; }
head -c 20971520 /dev/urandom >"$CW/up/d20"
c 2201 "$CW/up/d20" "$T:cp/d20" >/dev/null 2>"$CW/err"
dd if=/dev/urandom of="$CW/up/d20" bs=1048576 seek=7 count=1 conv=notrunc 2>/dev/null
c 2201 --delta -v "$CW/up/d20" "$T:cp/d20" >"$CW/out" 2>"$CW/err"
rc=$?
sent=$(delta_sent)
[ "$rc" = 0 ] && [ "$(sum "$CW/up/d20")" = "$(sum "$RD/d20")" ] && [ -n "$sent" ] && [ "$sent" -lt 3145728 ] \
    && ! grep -q "a full copy follows" "$CW/err" \
    && ok cp.delta.up "cp --delta up, 1 MiB of 20 changed: $sent bytes sent, the digests agree" \
    || bad cp.delta.up "cp --delta up: exit $rc, ${sent:-no} bytes sent" "$CW/err"
cp "$RD/d20" "$CW/down/d20"
dd if=/dev/urandom of="$RD/d20" bs=1048576 seek=3 count=1 conv=notrunc 2>/dev/null
c 2201 --delta -v "$T:cp/d20" "$CW/down/d20" >"$CW/out" 2>"$CW/err"
rc=$?
sent=$(delta_sent)
[ "$rc" = 0 ] && [ "$(sum "$RD/d20")" = "$(sum "$CW/down/d20")" ] && [ -n "$sent" ] && [ "$sent" -lt 3145728 ] \
    && ! grep -q "a full copy follows" "$CW/err" \
    && ok cp.delta.down "cp --delta down, 1 MiB of 20 changed: $sent bytes fetched, the digests agree" \
    || bad cp.delta.down "cp --delta down: exit $rc, ${sent:-no} bytes fetched" "$CW/err"

# Over an existing file, each way; then several sources into a directory.
head -c 70000 /dev/urandom >"$CW/up/new"
c 2201 "$CW/up/new" "$T:cp/f262145" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$CW/up/new")" = "$(sum "$RD/f262145")" ] \
    && ok cp.over.up "cp up over an existing file replaces it" || bad cp.over.up "cp up over a file: exit $rc" "$CW/err"
c 2201 "$T:cp/f1" "$CW/down/f262145" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$RD/f1")" = "$(sum "$CW/down/f262145")" ] \
    && ok cp.over.down "cp down over an existing file replaces it" || bad cp.over.down "cp down over a file: exit $rc" "$CW/err"
mkdir -p "$RD/many"
chown podtest:podtest "$RD/many"
c 2201 "$CW/up/f1" "$CW/up/new" "$T:cp/many" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ -f "$RD/many/f1" ] && [ "$(sum "$CW/up/new")" = "$(sum "$RD/many/new")" ] \
    && ok cp.many_into_dir "cp up of two files into a directory" \
    || bad cp.many_into_dir "cp up into a directory: exit $rc" "$CW/err"

# --jsonl: one object, with the digest that sha256sum gives.
c 2201 --jsonl "$CW/up/f1" "$T:cp/j1" >"$CW/out" 2>"$CW/err"
rc=$?
want=$(sum "$CW/up/f1")
[ "$rc" = 0 ] && [ "$(wc -l <"$CW/out")" = 1 ] && grep -q '"event":"done"' "$CW/out" \
    && grep -q "\"sha256\":\"$want\"" "$CW/out" && grep -q '"verified_by":"sha256sum"' "$CW/out" \
    && ok cp.jsonl "cp --jsonl prints one done object with the SHA-256" || bad cp.jsonl "cp --jsonl: exit $rc" "$CW/out"

# On one server, copy-data: no byte comes through here.
c 2201 --jsonl "$T:cp/f262145" "$T:cp/within" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$RD/f262145")" = "$(sum "$RD/within")" ] && grep -q '"verified_by":"sha256sum"' "$CW/out" \
    && ok cp.within.copy_data "cp within one server, by copy-data" \
    || bad cp.within.copy_data "cp within one server: exit $rc" "$CW/err"
# Two names of this server are two servers: the copy goes through here.
c 2201 "$T:cp/f1" "podtest@localhost:cp/across" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$RD/f1")" = "$(sum "$RD/across")" ] \
    && ok cp.server_to_server "cp from server to server, through this host" \
    || bad cp.server_to_server "cp from server to server: exit $rc" "$CW/err"

# The exit codes of a missing source and of a destination that cannot be made.
c 2201 "$CW/up/missing" "$T:cp/x" >/dev/null 2>"$CW/err"
expect_rc cp.missing_source.up "cp up of a missing source" 66 $? "$CW/err"
c 2201 "$T:cp/missing" "$CW/down/x" >/dev/null 2>"$CW/err"
expect_rc cp.missing_source.down "cp down of a missing source" 66 $? "$CW/err"
c 2201 "$CW/up/f1" "$T:/nonexistent-dir/x" >/dev/null 2>"$CW/err"
expect_rc cp.missing_dir "cp up into a directory that does not exist" 73 $? "$CW/err"
no_part cp.no_part.sftp "cp, each case above"

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
        # No refusal of a source after failed logins (OpenSSH 9.8 and later).
        echo "PerSourcePenalties no"
        [ "$port" = 2206 ] && echo "Subsystem sftp internal-sftp"
        echo "${spec#*:}"
    } >"$CW/sshd-$port.conf"
done
# Started in a loop of literal words, which the ids name (the words above
# hold $CW).
for srv in flip:2205 internal_sftp:2206; do
    port=${srv#*:}
    /usr/sbin/sshd -f "$CW/sshd-$port.conf" -E "$CW/sshd-$port.log" \
        && ok "cp.sshd.${srv%%:*}" "sshd on $port started" \
        || bad "cp.sshd.${srv%%:*}" "sshd on $port did not start" "$CW/sshd-$port.log"
done
sleep 1

printf 'the old content\n' >"$CW/old"
cp "$CW/old" "$RD/kept"
chown podtest:podtest "$RD/kept"
c 2205 "$CW/up/f262145" "$T:cp/kept" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 70 ] && cmp -s "$CW/old" "$RD/kept" && grep -q "the digests differ" "$CW/err" \
    && ok cp.flip.up "a flipped byte up: exit 70, the destination as it was" \
    || bad cp.flip.up "a flipped byte up: exit $rc" "$CW/err"
cp "$CW/old" "$CW/down/kept"
c 2205 "$T:cp/f262145" "$CW/down/kept" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 70 ] && cmp -s "$CW/old" "$CW/down/kept" && grep -q "the digests differ" "$CW/err" \
    && ok cp.flip.down "a flipped byte down: exit 70, the destination as it was" \
    || bad cp.flip.down "a flipped byte down: exit $rc" "$CW/err"
# In chunks too (T-141): the digest of the whole file catches the byte.
c 2205 --parallel 4 "$CW/up/big" "$T:cp/kept" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 70 ] && cmp -s "$CW/old" "$RD/kept" && grep -q "the digests differ" "$CW/err" \
    && ok cp.parallel.flip "a flipped byte in a chunk: exit 70, the destination as it was" \
    || bad cp.parallel.flip "a flipped byte in a chunk: exit $rc" "$CW/err"
no_part cp.no_part.flip "cp through the flipping subsystem"

# No exec (ForceCommand internal-sftp): the far digest is a second read.
c 2206 --jsonl "$CW/up/f262145" "$T:cp/r2" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$CW/up/f262145")" = "$(sum "$RD/r2")" ] && grep -q '"verified_by":"read again"' "$CW/out" \
    && ok cp.read_again "cp with no exec verifies by a second read" || bad cp.read_again "cp with no exec: exit $rc" "$CW/out"

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
PerSourcePenalties no
EOF
done
cat >>"$CW/sshd-2208.conf" <<'EOF'
ForceCommand printf 'podssh test banner\n'; sh -c "$SSH_ORIGINAL_COMMAND"
EOF
cat >>"$CW/sshd-2209.conf" <<'EOF'
ForceCommand sh -c "$SSH_ORIGINAL_COMMAND" | tr '\r' '\n'
EOF
for srv in exec:2207 banner:2208 cr:2209; do
    port=${srv#*:}
    /usr/sbin/sshd -f "$CW/sshd-$port.conf" -E "$CW/sshd-$port.log" \
        && ok "cp.sshd.${srv%%:*}" "sshd on $port started" \
        || bad "cp.sshd.${srv%%:*}" "sshd on $port did not start" "$CW/sshd-$port.log"
done
sleep 1

# Each size both ways, on OpenSSH with no SFTP, with the banner, with the
# changed \r, and on Dropbear (which may find an sftp-server: the case names
# the road it took).
for srv in exec:2207 banner:2208 cr:2209 dropbear:2203; do
    port=${srv#*:}
    how="raw through cat"
    [ "$port" = 2209 ] && how="through base64"
    for n in 0 1 5000000; do
        c "$port" -v "$CW/up/f$n" "$T:cp/x$port-$n" >/dev/null 2>"$CW/err"
        rc=$?
        road=sftp
        grep -q "by exec" "$CW/err" && road=exec
        [ "$rc" = 0 ] && [ "$(sum "$CW/up/f$n")" = "$(sum "$RD/x$port-$n")" ] \
            && ok "cp.${srv%%:*}.up.${n}" "cp up on port $port, $n bytes, by $road: the digests agree" \
            || bad "cp.${srv%%:*}.up.${n}" "cp up on port $port, $n bytes: exit $rc" "$CW/err"
        [ "$port" = 2203 ] || { [ "$road" = exec ] && grep -q "the bytes go $how" "$CW/err"; } \
            || bad "cp.${srv%%:*}.up.${n}" "cp up on port $port did not name the exec road and '$how'" "$CW/err"
        c "$port" -v "$T:cp/x$port-$n" "$CW/down/x$port-$n" >/dev/null 2>"$CW/err"
        rc=$?
        [ "$rc" = 0 ] && [ "$(sum "$RD/x$port-$n")" = "$(sum "$CW/down/x$port-$n")" ] \
            && ok "cp.${srv%%:*}.down.${n}" "cp down on port $port, $n bytes, by $road: the digests agree" \
            || bad "cp.${srv%%:*}.down.${n}" "cp down on port $port, $n bytes: exit $rc" "$CW/err"
    done
done

# Within one server with no SFTP: through this host, down and then up.
c 2207 "$T:cp/x2207-5000000" "$T:cp/within-exec" >/dev/null 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$RD/x2207-5000000")" = "$(sum "$RD/within-exec")" ] \
    && ok cp.within.exec "cp within one server by exec, through this host" \
    || bad cp.within.exec "cp within one server by exec: exit $rc" "$CW/err"

# Names that a far shell must get as one word: a space, a quote, a leading -.
for spec in "space:a b" "quote:it's" "dash:-lead"; do
    name=${spec#*:}
    cp "$CW/up/f262145" "$CW/up/$name"
    c 2207 "$CW/up/$name" "$T:cp/" >/dev/null 2>"$CW/err"
    rc=$?
    c 2207 "$T:cp/$name" "$CW/down/" >/dev/null 2>>"$CW/err"
    rc2=$?
    [ "$rc" = 0 ] && [ "$rc2" = 0 ] && [ "$(sum "$CW/up/$name")" = "$(sum "$RD/$name")" ] \
        && [ "$(sum "$CW/up/$name")" = "$(sum "$CW/down/$name")" ] \
        && ok "cp.exec.name.${spec%%:*}" "cp by exec of the name '$name', both ways" \
        || bad "cp.exec.name.${spec%%:*}" "cp by exec of '$name': exit $rc and $rc2" "$CW/err"
done
# A name that is not UTF-8 is refused before anything connects.
c 2207 "$CW/up/$(printf 'n\377')" "$T:cp/" >/dev/null 2>"$CW/err"
expect_rc cp.not_utf8 "cp of a name that is not UTF-8" 64 $? "$CW/err"
# A directory where the file would go: 73 on both roads, and nothing goes
# into it (mv would move the file inside).
mkdir -p "$RD/d2/f1"
chown -R podtest:podtest "$RD/d2"
for srv in sftp:2201 exec:2207; do
    port=${srv#*:}
    c "$port" "$CW/up/f1" "$T:cp/d2/" >/dev/null 2>"$CW/err"
    expect_rc "cp.onto_dir.${srv%%:*}" "cp up onto the name of a directory, port $port" 73 $? "$CW/err"
done
[ -z "$(ls -A "$RD/d2/f1")" ] && ok cp.onto_dir.untouched "cp put nothing into the directory of that name" \
    || bad cp.onto_dir.untouched "cp put a file into the directory of that name"
# A far file that the login cannot read is a source that cannot be read: 66
# on both roads, as a missing one.
cp "$CW/up/f1" "$RD/noread"
chown podtest:podtest "$RD/noread"
chmod 000 "$RD/noread"
for srv in sftp:2201 exec:2207; do
    port=${srv#*:}
    c "$port" "$T:cp/noread" "$CW/down/noread$port" >/dev/null 2>"$CW/err"
    expect_rc "cp.unreadable.${srv%%:*}" "cp down of a far file that cannot be read, port $port" 66 $? "$CW/err"
done
# A source that grows during the copy: the copy reads what the source held
# at the start, then stops with 66, on each road and each way, and leaves no
# copy (T-267). A copy that followed it would not end while it grows.
head -c 5000000 /dev/urandom >"$CW/up/grow"
(while :; do printf x >>"$CW/up/grow"; done) &
grower=$!
for srv in sftp:2201 exec:2207; do
    port=${srv#*:}
    c "$port" "$CW/up/grow" "$T:cp/grown$port" >/dev/null 2>"$CW/err"
    rc=$?
    [ "$rc" = 66 ] && [ ! -e "$RD/grown$port" ] && grep -q "changed while it was read" "$CW/err" \
        && ok "cp.grow.up.${srv%%:*}" "cp up of a source that grows, port $port: exit 66, and no copy" \
        || bad "cp.grow.up.${srv%%:*}" "cp up of a source that grows, port $port: exit $rc" "$CW/err"
done
kill "$grower" 2>/dev/null
wait "$grower" 2>/dev/null
head -c 5000000 /dev/urandom >"$RD/growfar"
chown podtest:podtest "$RD/growfar"
(while :; do printf x >>"$RD/growfar"; done) &
grower=$!
for srv in sftp:2201 internal_sftp:2206 exec:2207 cr:2209; do
    port=${srv#*:}
    c "$port" "$T:cp/growfar" "$CW/down/grown$port" >/dev/null 2>"$CW/err"
    rc=$?
    [ "$rc" = 66 ] && [ ! -e "$CW/down/grown$port" ] && grep -q "changed while it was read" "$CW/err" \
        && ok "cp.grow.down.${srv%%:*}" "cp down of a far file that grows, port $port: exit 66, and no copy" \
        || bad "cp.grow.down.${srv%%:*}" "cp down of a far file that grows, port $port: exit $rc" "$CW/err"
done
kill "$grower" 2>/dev/null
wait "$grower" 2>/dev/null
rm -f "$CW/up/grow" "$RD/growfar"
no_part cp.no_part.exec "cp by exec"

# What a copy keeps besides the bytes (T-146).
# shellcheck source=scripts/interop-keep.sh
. "$HERE/interop-keep.sh"
# cp --inplace (T-147).
# shellcheck source=scripts/interop-inplace.sh
. "$HERE/interop-inplace.sh"
# podssh mv, while these servers run (T-138).
# shellcheck source=scripts/interop-mv.sh
. "$HERE/interop-mv.sh"
# podssh scp and podssh sftp (T-139).
# shellcheck source=scripts/interop-sftp.sh
. "$HERE/interop-sftp.sh"
# A copy that goes on after a broken connection (T-136).
# shellcheck source=scripts/interop-resume.sh
. "$HERE/interop-resume.sh"
# podssh edit, over SFTP on 2201 and by exec on 2207 (T-149).
# shellcheck source=scripts/interop-edit.sh
. "$HERE/interop-edit.sh"

for port in 2205 2206 2207 2208 2209; do
    [ -f "$W/sshd-$port.pid" ] && kill "$(cat "$W/sshd-$port.pid")" 2>/dev/null
done
