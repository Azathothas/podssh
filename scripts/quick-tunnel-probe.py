#!/usr/bin/env python3
"""T-300: a visitor of a podssh node's quick tunnel, with Python's standard
library only, as a browser or `podssh ssh cf://` comes: TLS to NAME on port
443, directly or through an HTTP CONNECT proxy (--proxy http://HOST:PORT),
then a WebSocket upgrade. Pass: the answer is 101 with the accept of RFC
6455 for this key, and the first frame is binary and holds the resumable
layer's GREETING (type 0x01, then its length, then `podssh-session`), as a
node sends it first on each new link. The name of a new tunnel takes some
seconds to resolve, so each failure but the last is tried again, for
--limit seconds. Nothing of the answer but its shape is printed.

    python3 scripts/quick-tunnel-probe.py [--proxy URL] [--limit S] NAME
"""

import argparse
import base64
import hashlib
import os
import socket
import ssl
import sys
import time

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAGIC = b"podssh-session"


def read_head(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("closed before the head ended")
        data += chunk
        if len(data) > 64 * 1024:
            raise OSError("a head longer than 64 KiB")
    return data


def connect(host, proxy):
    if not proxy:
        return socket.create_connection((host, 443), timeout=15)
    where = proxy.removeprefix("http://").rstrip("/")
    proxy_host, proxy_port = where.rsplit(":", 1)
    sock = socket.create_connection((proxy_host, int(proxy_port)), timeout=15)
    sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    status = read_head(sock).split(b"\r\n", 1)[0]
    if b" 200" not in status:
        raise OSError(f"the proxy answered {status.decode('latin-1')!r}")
    return sock


def frame(tls, rest):
    """The first frame of the node: its opcode and payload, unmasked."""
    data = rest
    while len(data) < 2:
        data += tls.recv(4096)
    opcode, length = data[0] & 0x0F, data[1] & 0x7F
    if data[1] & 0x80:
        raise SystemExit("FAIL the node's frame is masked, which a server's must not be (RFC 6455, 5.1)")
    at = 2
    if length == 126:
        while len(data) < 4:
            data += tls.recv(4096)
        length, at = int.from_bytes(data[2:4], "big"), 4
    elif length == 127:
        while len(data) < 10:
            data += tls.recv(4096)
        length, at = int.from_bytes(data[2:10], "big"), 10
    while len(data) < at + length:
        chunk = tls.recv(65536)
        if not chunk:
            raise OSError("closed inside the first frame")
        data += chunk
    return opcode, data[at:at + length]


def once(host, proxy):
    raw = connect(host, proxy)
    tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    tls.settimeout(30)
    key = base64.b64encode(os.urandom(16))
    tls.sendall(
        b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\nUser-Agent: podssh-probe/T-300\r\n\r\n"
    )
    head, rest = read_head(tls).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin-1")
    if status.split(" ")[1:2] != ["101"]:
        raise ValueError(f"not 101: {status!r}")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers[name.strip().lower()] = value.strip()
    want = base64.b64encode(hashlib.sha1(key + GUID).digest())
    if headers.get(b"sec-websocket-accept") != want:
        raise SystemExit("FAIL 101, but its Sec-WebSocket-Accept is not the one of this key")
    opcode, payload = frame(tls, rest)
    tls.close()
    return opcode, payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--limit", type=float, default=90.0)
    parser.add_argument("name")
    args = parser.parse_args()
    deadline = time.monotonic() + args.limit
    tries, last = 0, None
    while time.monotonic() < deadline:
        tries += 1
        try:
            opcode, payload = once(args.name, args.proxy)
            break
        except (OSError, ValueError) as e:
            last = e
            time.sleep(3)
    else:
        print(f"FAIL no WebSocket through the name within {args.limit:.0f} s, {tries} tries: {last}")
        return 1
    greeting = opcode == 0x2 and len(payload) >= 19 and payload[0] == 0x01 and payload[5:19] == MAGIC
    shape = f"opcode {opcode}, {len(payload)} bytes, type 0x{payload[0]:02x}" if payload else f"opcode {opcode}, empty"
    if not greeting:
        print(f"FAIL 101 with the accept of its key at try {tries}, but the first frame is no GREETING: {shape}")
        return 1
    print(f"ok    101 with the accept of its key at try {tries}; the first frame is the layer's GREETING ({shape})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
