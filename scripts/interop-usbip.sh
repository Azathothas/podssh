# USB/IP through podssh pipe (T-182): the recipe of README.md, "Other TCP
# protocols", as far as the list of a server's devices, which needs no kernel
# module. podssh pipe listens on 127.0.0.1:3240, USB/IP's port, and its other
# side is a stand-in of usbipd behind OpenSSH's sshd on port 2201; the client
# is the real usbip of Linux's tools. The stand-in answers OP_REQ_DEVLIST as
# usbipd does (tools/usb/usbip/src/usbip_network.h and usbip_list.c of
# Linux): a header of version 0x0111, code 0x0005 and status 0, the count,
# one device of 312 bytes, and its interface. The attach, a read and the
# detach need the modules usbip-host and vhci-hcd on two hosts, and wait for
# the operator's machines. Sourced by scripts/interop.sh after
# scripts/interop-desktop.sh; uses ok, bad, $W, $BIN, $KH, $K and $T.

echo
echo "== USB/IP through podssh pipe (T-182)"
UD="$W/usbip"
mkdir -p "$UD"
cat >"$UD/usbipd.py" <<'PY'
import socket, struct, sys
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(4)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
device = (b"/sys/devices/podssh-stand-in/usb1/1-1".ljust(256, b"\0") + b"1-1".ljust(32, b"\0")
          + struct.pack("!IIIHHHBBBBBB", 1, 2, 3, 0x1D6B, 0x0104, 0x0100, 0, 0, 0, 1, 1, 1))
while True:
    c, _ = s.accept()
    request = b""
    while len(request) < 8:
        d = c.recv(8 - len(request))
        if not d:
            break
        request += d
    with open(sys.argv[2], "a") as log:
        log.write(request.hex() + "\n")
    if request == struct.pack("!HHI", 0x0111, 0x8005, 0):
        # A mass storage interface: class 8, subclass 6 (SCSI), protocol 80.
        c.sendall(struct.pack("!HHII", 0x0111, 0x0005, 0, 1) + device + bytes([8, 6, 80, 0]))
    c.close()
PY
python3 "$UD/usbipd.py" "$UD/port" "$UD/requests" >"$UD/usbipd.err" 2>&1 &
usbipd_pid=$!
tries=0
while [ ! -s "$UD/port" ] && [ "$tries" -lt 50 ]; do
    sleep 0.2
    tries=$((tries + 1))
done

# The recipe: podssh listens on the local port that usbip dials, and reaches
# the server's usbipd through SSH, so that the relay would see SSH only.
# shellcheck disable=SC2086
timeout 60 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" pipe --direct -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K \
    tcp-listen:127.0.0.1:3240 "ssh:$T:2201,127.0.0.1:$(cat "$UD/port")" 2>"$UD/listen.err" &
lpid=$!
tries=0
while ! grep -q "listening on" "$UD/listen.err" 2>/dev/null && [ "$tries" -lt 50 ]; do
    sleep 0.2
    tries=$((tries + 1))
done
timeout 30 usbip list -r 127.0.0.1 >"$UD/list.out" 2>"$UD/list.err"
rc=$?
wait "$lpid"
lrc=$?
cat "$UD/list.out" "$UD/list.err" "$UD/listen.err" >"$UD/all.log" 2>/dev/null
[ "$rc" = 0 ] && [ "$lrc" = 0 ] && grep -q "1-1:" "$UD/list.out" && grep -q "podssh-stand-in" "$UD/list.out" \
    && grep -qx 0111800500000000 "$UD/requests" \
    && ok usbip.list_remote "usbip list -r through pipe tcp-listen:127.0.0.1:3240 and ssh: lists the device 1-1" \
    || bad usbip.list_remote "usbip list -r through the pipe: exit $rc, listener exit $lrc" "$UD/all.log"

kill "$usbipd_pid" 2>/dev/null
rm -rf "$UD"
