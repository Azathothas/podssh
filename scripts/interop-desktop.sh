# Desktop streams and Telnet through podssh (T-179), in each form of the table
# "Other TCP protocols" of README.md: (a) OpenSSH listens and podssh proxy
# carries; (b) podssh pipe listens, on a TCP port or a Unix socket; (c) a
# client runs podssh as its transport, and nothing listens. The servers:
# TigerVNC's Xvnc on display :21 (port 5921, local connections only, no
# password), and BusyBox's telnetd on port 2323, which runs /bin/sh; each is
# reached through OpenSSH's sshd on port 2201. TigerVNC's viewer runs on an
# Xvfb of its own, :22. Sourced by scripts/interop.sh after
# scripts/interop-pipe.sh; uses ok, bad, wait_ports, $W, $HERE, $BIN, $KH, $K
# and $T, and the CA and relay certificate of scripts/interop-faults.sh. Each
# server stops after the block.

echo
echo "== desktop streams and Telnet (T-179)"
DK="$W/desktop"
mkdir -p "$DK/home"
SSHO="-o UserKnownHostsFile=$KH -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K"

# rfb.py line PORT: the first 12 bytes of the server at PORT, the RFB version
# line. rfb.py init COMMAND...: a client that runs COMMAND as its transport,
# as ssvncviewer's exec= does: the version, the security type None, then
# ClientInit and the server's ServerInit; it prints the version, the
# desktop's size and name, and the command's exit status.
cat >"$DK/rfb.py" <<'PY'
import socket, struct, subprocess, sys

def need(read, n):
    data = b""
    while len(data) < n:
        part = read(n - len(data))
        if not part:
            raise SystemExit(f"the stream ended after {len(data)} of {n} bytes")
        data += part
    return data

if sys.argv[1] == "line":
    s = socket.create_connection(("127.0.0.1", int(sys.argv[2])), 10)
    s.settimeout(20)
    print(need(s.recv, 12).decode("ascii", "replace").strip())
    s.close()
    sys.exit(0)
p = subprocess.Popen(sys.argv[2:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
read = p.stdout.read
version = need(read, 12)
p.stdin.write(b"RFB 003.008\n")
p.stdin.flush()
types = need(read, need(read, 1)[0])
if 1 not in types:
    raise SystemExit(f"no security type None among {list(types)}")
p.stdin.write(b"\x01")
p.stdin.flush()
if struct.unpack("!I", need(read, 4))[0] != 0:
    raise SystemExit("the security type None failed")
p.stdin.write(b"\x01")
p.stdin.flush()
width, height = struct.unpack("!HH", need(read, 4))
need(read, 16)
name = need(read, struct.unpack("!I", need(read, 4))[0]).decode("utf-8", "replace")
p.stdin.close()
p.stdout.read()
print(f"{version.decode('ascii', 'replace').strip()} {width}x{height} {name} exit {p.wait(30)}")
PY

# meter.py PORTFILE TARGET LOG: a TCP relay on the server's side, from a free
# port to TARGET, one connection at a time. For each connection it writes a
# line to LOG: the bytes to the client, those of them after its first 5 s,
# the seconds that it lasted, and the bytes from the client.
cat >"$DK/meter.py" <<'PY'
import socket, sys, threading, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(4)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    t = socket.create_connection(("127.0.0.1", int(sys.argv[2])), 10)
    start = time.monotonic()
    n = {"down": 0, "late": 0, "up": 0}

    def up():
        while True:
            try:
                d = c.recv(65536)
            except OSError:
                break
            if not d:
                break
            n["up"] += len(d)
            t.sendall(d)
        try:
            t.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    th = threading.Thread(target=up, daemon=True)
    th.start()
    while True:
        try:
            d = t.recv(65536)
        except OSError:
            break
        if not d:
            break
        n["down"] += len(d)
        if time.monotonic() - start >= 5:
            n["late"] += len(d)
        try:
            c.sendall(d)
        except OSError:
            break
    th.join(5)
    with open(sys.argv[3], "a") as log:
        log.write(f"{n['down']} {n['late']} {time.monotonic() - start:.1f} {n['up']}\n")
    c.close()
    t.close()
PY

# desktop_listening ERR: the listener's line is in ERR, 10 s at most.
desktop_listening() {
    _tries=0
    while ! grep -q "listening on" "$1" 2>/dev/null && [ "$_tries" -lt 50 ]; do
        sleep 0.2
        _tries=$((_tries + 1))
    done
}

Xvnc :21 -rfbport 5921 -localhost -SecurityTypes None -geometry 1024x768 -depth 24 -desktop podssh-desktop \
    >"$DK/xvnc.log" 2>&1 &
xvnc_pid=$!
busybox-extras telnetd -F -K -b 127.0.0.1:2323 -l /bin/sh >"$DK/telnetd.log" 2>&1 &
telnetd_pid=$!
python3 "$DK/meter.py" "$DK/meter.port" 5921 "$DK/meter.log" >"$DK/meter.err" 2>&1 &
meter_pid=$!
python3 "$HERE/fake-relay.py" --cert "$W/faults/relay.pem" --key "$W/faults/relay.key" \
    --port-file "$DK/relay.port" --mode normal >"$DK/relay.log" 2>&1 &
relay_pid=$!
tries=0
while [ "$tries" -lt 30 ] && ! { [ -s "$DK/meter.port" ] && [ -s "$DK/relay.port" ]; }; do
    sleep 1
    tries=$((tries + 1))
done
wait_ports 5921 2323 || cat "$DK/xvnc.log" "$DK/telnetd.log"
RP="--relay-host relay-a.test:$(cat "$DK/relay.port") --relay-addr relay-a.test=127.0.0.1 --ca-file $W/faults/ca.pem"

# (a) OpenSSH listens on 5931 and forwards to the VNC server; podssh proxy,
# its ProxyCommand, carries the SSH session through the stand-in relay.
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" ssh -F /dev/null -p 2201 $SSHO -o BatchMode=yes \
    -o ProxyCommand="$BIN proxy $RP %h %p" -o ExitOnForwardFailure=yes -N -L 127.0.0.1:5931:127.0.0.1:5921 "$T" \
    </dev/null >"$DK/a.out" 2>"$DK/a.err" &
apid=$!
# The login comes first, through the stand-in relay: 20 s at most.
for _ in 1 2 3 4; do
    wait_ports 5931 2>/dev/null && break
done
line=$(timeout 30 python3 "$DK/rfb.py" line 5931 2>>"$DK/a.err")
kill "$apid" 2>/dev/null
wait "$apid" 2>/dev/null
case $line in
    "RFB 003."*) ok desktop.vnc.proxy_command "(a) ssh -L, podssh proxy its ProxyCommand: '$line' at the local port" ;;
    *) bad desktop.vnc.proxy_command "(a) ssh -L with podssh proxy: got '$line'" "$DK/a.err" ;;
esac

# (b) podssh pipe listens on a TCP port, and its other side is the VNC
# server through OpenSSH, as -W reaches it.
# shellcheck disable=SC2086
timeout 60 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" pipe --direct $SSHO tcp-listen:127.0.0.1:0 \
    "ssh:$T:2201,127.0.0.1:5921" 2>"$DK/b.err" &
bpid=$!
desktop_listening "$DK/b.err"
at=$(sed -n 's/.*listening on \([^ ]*\): .*/\1/p' "$DK/b.err" | head -n 1)
line=$(timeout 30 python3 "$DK/rfb.py" line "${at##*:}" 2>>"$DK/b.err")
wait "$bpid"
brc=$?
case $line in
    "RFB 003."*) [ "$brc" = 0 ] \
        && ok desktop.vnc.pipe_tcp_listen "(b) pipe tcp-listen: to ssh: '$line' at the listener" \
        || bad desktop.vnc.pipe_tcp_listen "(b) pipe tcp-listen: '$line', listener exit $brc" "$DK/b.err" ;;
    *) bad desktop.vnc.pipe_tcp_listen "(b) pipe tcp-listen: got '$line', listener exit $brc" "$DK/b.err" ;;
esac

# (c) No listener: the client runs podssh pipe as its transport, through the
# stand-in relay and OpenSSH, to the server's ServerInit.
# shellcheck disable=SC2086
line=$(timeout 60 env -u SSH_AUTH_SOCK HOME="$W" python3 "$DK/rfb.py" init "$BIN" pipe $RP $SSHO stdio \
    "ssh:$T:2201,127.0.0.1:5921" 2>"$DK/c.err")
case $line in
    "RFB 003."*" 1024x768 podssh-desktop exit 0")
        ok desktop.vnc.command "(c) a client with podssh pipe stdio as its transport: '$line'" ;;
    *) bad desktop.vnc.command "(c) a client with podssh pipe stdio as its transport: got '$line'" "$DK/c.err" ;;
esac

# (b) for a host that refuses a TCP bind and allows an AF_UNIX one, as
# sandbox A: TigerVNC's viewer takes a Unix socket's path. The far side is
# the meter, so that the bytes of a real viewer are counted: 20 s of an idle
# desktop, then 20 s of one whose whole screen is new noise 4 times a second
# (two random bitmaps of 1024x768, set in turn as the root window's pattern).
Xvfb :22 -nolisten tcp >"$DK/xvfb.log" 2>&1 &
xvfb_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S /tmp/.X11-unix/X22 ] && break
    sleep 0.5
done
python3 - "$DK" <<'PY'
import os, sys
for name in ("a", "b"):
    bits = os.urandom(1024 * 768 // 8)
    with open(os.path.join(sys.argv[1], name + ".xbm"), "w") as f:
        f.write(f"#define {name}_width 1024\n#define {name}_height 768\nstatic char {name}_bits[] = {{\n")
        f.write(",".join(f"0x{b:02x}" for b in bits))
        f.write("};\n")
PY
desktop_view() { # NAME: 20 s of TigerVNC's viewer at a unix-listen: socket, through the meter
    rm -f "$DK/vnc.sock"
    # shellcheck disable=SC2086
    timeout 60 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" pipe --direct $SSHO "unix-listen:$DK/vnc.sock" \
        "ssh:$T:2201,127.0.0.1:$(cat "$DK/meter.port")" 2>"$DK/listen-$1.err" &
    _vpid=$!
    desktop_listening "$DK/listen-$1.err"
    DISPLAY=:22 HOME="$DK/home" timeout 20 vncviewer "$DK/vnc.sock" >"$DK/viewer-$1.log" 2>&1
    wait "$_vpid"
}
# desktop_metered N: the meter writes a connection's line when it ends, up
# to 5 s after the viewer's: wait for its Nth line, 15 s at most. A run that
# read the log first saw no line of the busy view, and failed at random.
desktop_metered() {
    _tries=0
    while [ "$(wc -l 2>/dev/null <"$DK/meter.log" || echo 0)" -lt "$1" ] && [ "$_tries" -lt 75 ]; do
        sleep 0.2
        _tries=$((_tries + 1))
    done
}
desktop_view idle
desktop_metered 1
(
    end=$(($(date +%s) + 30))
    while [ "$(date +%s)" -lt "$end" ]; do
        DISPLAY=:21 xsetroot -bitmap "$DK/a.xbm"
        sleep 0.25
        DISPLAY=:21 xsetroot -bitmap "$DK/b.xbm"
        sleep 0.25
    done
) >"$DK/busy.log" 2>&1 &
busy_pid=$!
desktop_view busy
kill "$busy_pid" 2>/dev/null
wait "$busy_pid" 2>/dev/null
desktop_metered 2
seen=$(grep -m 1 "Using RFB protocol version" "$DK/viewer-idle.log" | sed 's/^ *//')
[ -n "$seen" ] && [ -s "$DK/meter.log" ] \
    && ok desktop.vnc.viewer_unix_listen "(b) TigerVNC's viewer at a unix-listen: socket: '$seen'" \
    || bad desktop.vnc.viewer_unix_listen "(b) TigerVNC's viewer at a unix-listen: socket: no RFB version in its log" \
        "$DK/viewer-idle.log"
# Each line of the meter: bytes down, those after 5 s, seconds, bytes up. A
# rate is the bytes after the first 5 s (the first full screen), a minute.
rates=$(awk 'NR <= 2 { w = $3 - 5; if (w < 1) w = 1; r[NR] = int($2 * 60 / w) }
    END { if (NR >= 2 && r[2] > 0)
              printf "%d %d %.1f", r[1], r[2], 67108864 / r[2] }' "$DK/meter.log" 2>/dev/null)
read -r idle_rate busy_rate busy_min <<EOF
$rates
EOF
if [ -n "$busy_min" ] && [ "$busy_rate" -gt "$idle_rate" ]; then
    ok desktop.vnc.rate \
        "TigerVNC's viewer, loopback: idle $idle_rate bytes a minute, busy $busy_rate; 64 MiB lasts $busy_min min busy"
else
    bad desktop.vnc.rate "the bytes of a desktop: '$rates' from the meter" "$DK/meter.log"
fi

# Telnet: the bytes pass, and the first is an option (IAC, 255), which a
# person cannot answer: a client must.
# shellcheck disable=SC2086
(sleep 2) | timeout 30 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" pipe --direct $SSHO stdio \
    "ssh:$T:2201,127.0.0.1:2323" >"$DK/telnet.raw" 2>"$DK/telnet.err"
rc=$?
first=$(od -An -tu1 -N1 "$DK/telnet.raw" | tr -d ' ')
[ "$rc" = 0 ] && [ "$first" = 255 ] \
    && ok desktop.telnet.options "pipe stdio to telnetd: its first byte is IAC (255), an option for a client" \
    || bad desktop.telnet.options "pipe stdio to telnetd: exit $rc, first byte '$first'" "$DK/telnet.err"

# (b) and a Telnet client: a shell's arithmetic comes back through telnetd.
# shellcheck disable=SC2086
timeout 60 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" pipe --direct $SSHO tcp-listen:127.0.0.1:0 \
    "ssh:$T:2201,127.0.0.1:2323" 2>"$DK/t.err" &
tpid=$!
desktop_listening "$DK/t.err"
at=$(sed -n 's/.*listening on \([^ ]*\): .*/\1/p' "$DK/t.err" | head -n 1)
# shellcheck disable=SC2016
(sleep 2; printf 'echo TELNET-$((6*7))\n'; sleep 2; printf 'exit\n'; sleep 2) \
    | timeout 30 busybox-extras telnet 127.0.0.1 "${at##*:}" >"$DK/telnet.out" 2>&1
wait "$tpid"
trc=$?
grep -q "TELNET-42" "$DK/telnet.out" && [ "$trc" = 0 ] \
    && ok desktop.telnet.client "(b) pipe tcp-listen: and BusyBox's telnet: the shell's answer came back" \
    || bad desktop.telnet.client "(b) pipe tcp-listen: and telnet: listener exit $trc" "$DK/telnet.out"

kill "$xvnc_pid" "$xvfb_pid" "$telnetd_pid" "$meter_pid" "$relay_pid" 2>/dev/null
rm -rf "$DK"
