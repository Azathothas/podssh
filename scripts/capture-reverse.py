#!/usr/bin/env python3
"""Capture one session of the reverse road on the live relay, frame by frame.

Bytes for the fixtures of the node runner (T-079) and of the control codecs,
from a client that podssh did not write: the Python standard library only. It
makes a pair, opens the node's socket and an operator's socket, and records
what each side receives: the node's control frames (`hello`, `open`, `close`),
the operator's `ready`, data both ways with the node's 32-character id, and
whether the relay answers a Ping on the node's socket and on the operator's.
It stops the pair at the end. It prints no token; the pair's name is printed
as its shape.

Each read has a time limit of 10 s.

Usage: python scripts/capture-reverse.py
Exit 0 when each step was seen, 1 when one was not.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
import urllib.error
import urllib.request

RELAY = "tcp.ssh.relay.ajam.dev"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
LIMIT = 10.0


def call(method: str, path: str, token: str | None = None, limit: float = LIMIT) -> tuple[int, bytes]:
    headers = {"content-type": "application/json"}
    if token is not None:
        headers["X-Relay-Token"] = token
    request = urllib.request.Request(f"https://{RELAY}{path}", data=b"{}", headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=limit) as reply:
            return reply.status, reply.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def read_exact(tls: ssl.SSLSocket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = tls.recv(count - len(data))
        if not chunk:
            raise EOFError("the relay ended the connection")
        data += chunk
    return data


def read_frame(tls: ssl.SSLSocket) -> tuple[int, bytes]:
    head = read_exact(tls, 2)
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", read_exact(tls, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", read_exact(tls, 8))[0]
    return head[0] & 0x0F, read_exact(tls, length)


def send_frame(tls: ssl.SSLSocket, opcode: int, payload: bytes) -> None:
    mask = os.urandom(4)
    head = bytes([0x80 | opcode])
    head += bytes([0x80 | len(payload)]) if len(payload) < 126 else bytes([0x80 | 126]) + struct.pack(">H", len(payload))
    tls.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def upgrade(path: str, token: str) -> ssl.SSLSocket:
    raw = socket.create_connection((RELAY, 443), timeout=LIMIT)
    tls = ssl.create_default_context().wrap_socket(raw, server_hostname=RELAY)
    key = base64.b64encode(os.urandom(16)).decode()
    tls.sendall(
        (
            f"GET {path} HTTP/1.1\r\nHost: {RELAY}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nX-Relay-Token: {token}\r\n\r\n"
        ).encode()
    )
    head = b""
    while b"\r\n\r\n" not in head:
        head += read_exact(tls, 1)
    status = head.split(b"\r\n", 1)[0].decode("latin-1")
    if " 101 " not in status + " ":
        raise RuntimeError(f"no upgrade: {status}")
    accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
    lines = head.decode("latin-1").split("\r\n")
    got = [l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("sec-websocket-accept:")]
    if got != [accept]:
        raise RuntimeError("Sec-WebSocket-Accept does not match the key")
    return tls


def shown(text: str, name: str) -> str:
    """A control frame with the pair's name replaced by its shape."""
    return text.replace(name, f"<name: {len(name)} chars>")


def main() -> int:
    status, body = call("POST", "/v1/pair")
    if status != 200:
        print(f"pair: {status}")
        return 1
    pair = json.loads(body)
    name = pair["name"]
    seen = {}
    try:
        node = upgrade(f"/v1/node/{name}", pair["node_token"])
        print("node: upgraded")
        node.settimeout(3)
        try:
            opcode, payload = read_frame(node)
            print(f"node first frame: opcode 0x{opcode:x}: {shown(payload.decode('utf-8', 'replace'), name)!r}")
            seen["hello"] = opcode == 0x1 and b'"hello"' in payload
        except (socket.timeout, TimeoutError):
            print("node first frame: none within 3 s")
            seen["hello"] = False
        node.settimeout(LIMIT)
        send_frame(node, 0x9, b"ping-probe")
        node.settimeout(5)
        try:
            opcode, payload = read_frame(node)
            print(f"node after a Ping: opcode 0x{opcode:x}, {payload!r}")
            seen["pong"] = opcode == 0xA and payload == b"ping-probe"
        except (socket.timeout, TimeoutError):
            print("node after a Ping: nothing within 5 s")
            seen["pong"] = False
        node.settimeout(LIMIT)

        operator = upgrade(f"/v1/connect/{name}", pair["connect_token"])
        print("operator: upgraded")
        send_frame(operator, 0x9, b"operator-probe")
        operator.settimeout(5)
        try:
            opcode, payload = read_frame(operator)
            print(f"operator after a Ping: opcode 0x{opcode:x}, {payload!r}")
            seen["operator pong"] = opcode == 0xA and payload == b"operator-probe"
        except (socket.timeout, TimeoutError):
            print("operator after a Ping: nothing within 5 s")
            seen["operator pong"] = False
        operator.settimeout(LIMIT)
        opcode, payload = read_frame(node)
        text = payload.decode("utf-8", "replace")
        print(f"node: opcode 0x{opcode:x}: {shown(text, name)!r}")
        session = json.loads(text)["id"]
        seen["open"] = opcode == 0x1 and re.fullmatch(r"[0-9a-f]{32}", session) is not None

        ready = json.dumps({"type": "ready", "id": session}, separators=(",", ":")).encode()
        send_frame(node, 0x1, ready)
        opcode, payload = read_frame(operator)
        print(f"operator: opcode 0x{opcode:x}: {payload.decode('utf-8', 'replace')!r}")
        seen["ready"] = opcode == 0x1 and b'"ready"' in payload

        send_frame(operator, 0x2, b"from the operator")
        opcode, payload = read_frame(node)
        print(f"node: opcode 0x{opcode:x}: {payload[:32].decode()} + {payload[32:]!r}")
        seen["data in"] = opcode == 0x2 and payload == session.encode() + b"from the operator"

        send_frame(node, 0x2, session.encode() + b"from the node")
        opcode, payload = read_frame(operator)
        print(f"operator: opcode 0x{opcode:x}: {payload!r}")
        seen["data out"] = opcode == 0x2 and payload == b"from the node"

        send_frame(operator, 0x8, struct.pack(">H", 1000))
        while True:
            opcode, payload = read_frame(node)
            print(f"node after the operator's Close: opcode 0x{opcode:x}: {shown(payload.decode('utf-8', 'replace'), name)!r}")
            if opcode == 0x1 and b'"close"' in payload:
                seen["close"] = True
                break
        operator.close()
        send_frame(node, 0x8, struct.pack(">H", 1000))
        node.close()
    finally:
        # The stop was seen to take more than 10 s after a node had been online.
        status, body = call("POST", f"/v1/stop/{name}", pair["stop_token"], limit=60.0)
        print(f"stop: {status} {body.decode('utf-8', 'replace')!r}")
        del pair
    print("seen:", json.dumps(seen))
    return 0 if all(seen.get(k) for k in ["open", "ready", "data in", "data out", "close"]) else 1


if __name__ == "__main__":
    sys.exit(main())
