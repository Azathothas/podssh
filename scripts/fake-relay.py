#!/usr/bin/env python3
"""A stand-in for the relay, for fault injection in the interop harness.

It serves the forward path the way the live relay does (docs/relay.md):
TLS 1.3, `POST /v1/mint`, `GET /health`, and `GET /connect/<host>/<port>`
upgraded to a WebSocket whose binary frames carry the TCP stream, with an
empty binary frame as keepalive and Pings answered. Each instance can be told
to fail in one way, so podssh's failover, liveness and close handling are
tested against real OpenSSH without waiting for the real relay to fail.

Usage: fake-relay.py --cert CERT --key KEY --port-file FILE [--mode MODE]
                     [--keepalive SECONDS]

Modes:
  normal           behave
  refuse:STATUS    answer every upgrade with HTTP STATUS
  blackhole        accept TCP and never start TLS
  silent           finish TLS, then never answer a request
  stall:SECONDS    SECONDS after the upgrade, stop: no frames, no Pongs
  close:BYTES:CODE after BYTES from the target, Close with CODE and the
                   relay's reason for it
"""

import argparse
import asyncio
import base64
import hashlib
import json
import ssl
import struct
import time
from email.utils import formatdate

TOKEN = "fake-relay-token-for-the-interop-harness"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# The relay's own reasons for each code (docs/relay.md, forward path).
REASONS = {
    1001: "idle timeout",
    1009: "session byte cap",
    1011: "write failed: fault injection",
    1013: "target write backlog",
}

args = None


def response(status, reason, body=b"", headers=()):
    head = [f"HTTP/1.1 {status} {reason}", f"Date: {formatdate(usegmt=True)}",
            f"Content-Length: {len(body)}", "Connection: close"]
    head += [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


def frame(opcode, payload=b""):
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 65536:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


def close_frame(code, reason=""):
    return frame(0x8, struct.pack("!H", code) + reason.encode())


async def read_frame(reader):
    b0, b1 = await reader.readexactly(2)
    opcode, n = b0 & 0x0F, b1 & 0x7F
    if n == 126:
        (n,) = struct.unpack("!H", await reader.readexactly(2))
    elif n == 127:
        (n,) = struct.unpack("!Q", await reader.readexactly(8))
    if not b1 & 0x80:
        raise ConnectionError("an unmasked client frame")
    mask = await reader.readexactly(4)
    data = bytearray(await reader.readexactly(n))
    for i in range(n):
        data[i] ^= mask[i % 4]
    return opcode, bytes(data)


async def handle(reader, writer):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        if args.mode == "silent":
            await reader.read()  # until the client gives up
            return
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if method == "POST" and path == "/v1/mint":
            await reader.readexactly(int(headers.get("content-length", "0")))
            body = json.dumps({"token": TOKEN, "expires": int(time.time() * 1000) + 3600_000,
                               "scope": "forward"}).encode()
            writer.write(response(200, "OK", body, [("Content-Type", "application/json")]))
        elif method == "GET" and path == "/health":
            body = json.dumps({"ok": True, "service": "tcp-ssh-relay", "version": "fake",
                               "relay": {"edge_colo": "TEST"}}).encode()
            writer.write(response(200, "OK", body, [("Content-Type", "application/json")]))
        elif method == "GET" and path.startswith("/connect/"):
            await connect(reader, writer, path, headers)
        else:
            writer.write(response(404, "Not Found", f"{path}: not found".encode()))
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, ssl.SSLError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def connect(reader, writer, path, headers):
    if headers.get("x-relay-token") != TOKEN:
        writer.write(response(403, "Forbidden", b"forward: missing or wrong token"))
        return
    if args.mode.startswith("refuse:"):
        status = int(args.mode.split(":")[1])
        writer.write(response(status, "Refused", b"connect: refused by fault injection"))
        return
    parts = path.split("?")[0].split("/")
    host, port = parts[2], int(parts[3])
    try:
        t_reader, t_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    except (OSError, asyncio.TimeoutError) as e:
        writer.write(response(502, "Bad Gateway", f"relay: cannot reach {host}:{port}: {e}".encode()))
        return
    accept = base64.b64encode(hashlib.sha1(headers["sec-websocket-key"].encode() + GUID).digest()).decode()
    writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
    await writer.drain()
    await pump(reader, writer, t_reader, t_writer)


async def pump(reader, writer, t_reader, t_writer):
    stalled = asyncio.Event()
    done = asyncio.Event()

    async def stall_clock():
        if args.mode.startswith("stall:"):
            await asyncio.sleep(float(args.mode.split(":")[1]))
            stalled.set()

    async def keepalive():
        while not done.is_set():
            await asyncio.sleep(args.keepalive)
            if not stalled.is_set() and not done.is_set():
                writer.write(frame(0x2))
                await writer.drain()

    async def up():  # client to target
        while True:
            opcode, data = await read_frame(reader)
            if stalled.is_set():
                continue  # swallowed: a stalled relay answers nothing
            if opcode in (0x0, 0x2):  # binary, or its continuation
                t_writer.write(data)
                await t_writer.drain()
            elif opcode == 0x9:
                writer.write(frame(0xA, data))
                await writer.drain()
            elif opcode == 0x8:
                writer.write(close_frame(1000, "client closed"))
                await writer.drain()
                return
            elif opcode == 0x1:
                writer.write(close_frame(1003, "text frames are not accepted"))
                await writer.drain()
                return

    async def down():  # target to client
        sent = 0
        limit, code = None, None
        if args.mode.startswith("close:"):
            _, limit, code = args.mode.split(":")
            limit, code = int(limit), int(code)
        while True:
            data = await t_reader.read(65536)
            if stalled.is_set():
                await asyncio.Event().wait()  # hold the connection open, silent
            if not data:
                writer.write(close_frame(1000, "target closed"))
                await writer.drain()
                return
            writer.write(frame(0x2, data))
            await writer.drain()
            sent += len(data)
            if limit is not None and sent >= limit:
                writer.write(close_frame(code, REASONS.get(code, "fault injection")))
                await writer.drain()
                return

    tasks = [asyncio.ensure_future(t()) for t in (up, down)]
    extras = [asyncio.ensure_future(t()) for t in (stall_clock, keepalive)]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except Exception:  # noqa: BLE001
        pass
    done.set()
    for t in tasks + extras:
        t.cancel()
    t_writer.close()


async def hold(reader, writer):
    """Blackhole: read whatever comes and never answer."""
    try:
        while await reader.read(65536):
            pass
    except OSError:
        pass
    writer.close()


async def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--mode", default="normal")
    parser.add_argument("--keepalive", type=float, default=25.0)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.cert, args.key)
    if args.mode == "blackhole":
        server = await asyncio.start_server(hold, "127.0.0.1", 0)
    else:
        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    with open(args.port_file, "w", encoding="utf-8") as f:
        f.write(str(server.sockets[0].getsockname()[1]))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
