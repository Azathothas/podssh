#!/usr/bin/env python3
"""Capture the payload of a Close frame that the live relay sends.

A fixture for the Close parser must come from software that podssh did not
write (docs/development.md, "Rules for tests"). This client uses the Python
standard library only. It mints a forward token, which stays in memory and is
never printed. It opens one forward session to HOST:PORT (default
github.com:22), waits for the server's first bytes, and sends a line that is
not SSH, so that the server closes the connection. It then prints the payload
of the relay's Close: the code, the reason and the bytes in hex.

It uses no proxy. Each read has a time limit of 20 s, and the whole run 90 s.

Usage: python scripts/capture-close.py [HOST [PORT]]
Exit 0 when a Close arrived, 1 when none did.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.request

RELAY = "tcp.ssh.relay.ajam.dev"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
READ_LIMIT = 20.0
RUN_LIMIT = 90.0


def mint() -> str:
    request = urllib.request.Request(
        f"https://{RELAY}/v1/mint",
        data=b"{}",
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=READ_LIMIT) as reply:
        return json.loads(reply.read())["token"]


def read_exact(tls: ssl.SSLSocket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = tls.recv(count - len(data))
        if not chunk:
            raise EOFError("the relay ended the connection with no Close")
        data += chunk
    return data


def read_frame(tls: ssl.SSLSocket) -> tuple[int, bytes]:
    head = read_exact(tls, 2)
    opcode = head[0] & 0x0F
    if head[1] & 0x80:
        raise ValueError("a frame from the server is masked (RFC 6455 section 5.1)")
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", read_exact(tls, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", read_exact(tls, 8))[0]
    return opcode, read_exact(tls, length)


def send_frame(tls: ssl.SSLSocket, opcode: int, payload: bytes) -> None:
    # A client masks each frame (RFC 6455 section 5.3).
    mask = os.urandom(4)
    head = bytes([0x80 | opcode])
    if len(payload) < 126:
        head += bytes([0x80 | len(payload)])
    else:
        head += bytes([0x80 | 126]) + struct.pack(">H", len(payload))
    body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    tls.sendall(head + mask + body)


def upgrade(tls: ssl.SSLSocket, host: str, port: int, token: str) -> None:
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET /connect/{host}/{port} HTTP/1.1\r\n"
        f"Host: {RELAY}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"X-Relay-Token: {token}\r\n"
        "\r\n"
    )
    tls.sendall(request.encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += read_exact(tls, 1)
    lines = head.decode("latin-1").split("\r\n")
    if " 101 " not in lines[0] + " ":
        raise RuntimeError(f"no upgrade: {lines[0]}")
    expected = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
    accept = [l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("sec-websocket-accept:")]
    if accept != [expected]:
        raise RuntimeError("Sec-WebSocket-Accept does not match the key")


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "github.com"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    deadline = time.monotonic() + RUN_LIMIT
    token = mint()
    raw = socket.create_connection((RELAY, 443), timeout=READ_LIMIT)
    tls = ssl.create_default_context().wrap_socket(raw, server_hostname=RELAY)
    try:
        upgrade(tls, host, port, token)
        del token
        print(f"upgraded: /connect/{host}/{port}")
        sent = False
        while time.monotonic() < deadline:
            opcode, payload = read_frame(tls)
            if opcode == 0x8:
                code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else None
                print(f"close payload: {len(payload)} bytes: {payload.hex()}")
                print(f"close code: {code}")
                print(f"close reason: {payload[2:].decode('utf-8', 'replace')!r}")
                send_frame(tls, 0x8, payload[:2])
                return 0
            print(f"frame: opcode 0x{opcode:x}, {len(payload)} bytes")
            if opcode == 0x2 and payload and not sent:
                send_frame(tls, 0x2, b"this is not SSH\r\n")
                sent = True
                print("sent: a line that is not SSH")
        print("no Close within the time limit")
        return 1
    finally:
        tls.close()


if __name__ == "__main__":
    sys.exit(main())
