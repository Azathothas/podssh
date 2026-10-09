#!/usr/bin/env python3
"""A stand-in for the relay, for fault injection in the interop harness.

It serves the forward path the way the live relay does (docs/relay.md):
TLS 1.3, `POST /v1/mint`, `GET /health`, and `GET /connect/<host>/<port>`
upgraded to a WebSocket whose binary frames carry the TCP stream, with an
empty binary frame as keepalive and Pings answered. And the reverse road
(scripts/fake_reverse.py, T-156): pairs, nodes and operators. Each instance can be told
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
  closeall:BYTES:CODE
                   the same after BYTES both ways together, as the relay
                   counts its session byte cap
  delay:MS         each byte, each way, MS milliseconds late
  jitter:MIN:MAX:SEED
                   each chunk, each way, late by MIN to MAX milliseconds,
                   from a generator seeded with SEED, so that a run repeats;
                   a chunk never passes the one before it
  rate:BYTES       each way, BYTES a second at most
  cut:BYTES        after BYTES both ways together, the TCP connection to the
                   client ends, with no Close frame: a host that stops
  pause:AFTER:FOR  AFTER seconds after the upgrade, each byte both ways,
                   Pongs and keepalives too, is held for FOR seconds, then
                   let through: a stall that ends
"""

import argparse
import asyncio
import json
import random
import ssl
import time

import fake_reverse
from fake_ws import close_frame, frame, read_frame, response, upgraded

TOKEN = "fake-relay-token-for-the-interop-harness"
# The relay's own reasons for each code (docs/relay.md, forward path).
REASONS = {
    1001: "idle timeout",
    1009: "session byte cap",
    1011: "write failed: fault injection",
    1013: "target write backlog",
}

args = None


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
        if await fake_reverse.handle(method, path, headers, reader, writer):
            pass
        elif method == "POST" and path == "/v1/mint":
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
    writer.write(upgraded(headers))
    await writer.drain()
    await pump(reader, writer, t_reader, t_writer)


class Shaper:
    """One direction's bytes, sent in order, late or slow as the mode says.
    A bounded queue keeps the sender's flow control."""

    def __init__(self, send, mode, started, seed_offset):
        self.send, self.started = send, started
        self.delay, self.jitter, self.rate, self.pause = 0.0, None, None, None
        kind, _, rest = mode.partition(":")
        if kind == "delay":
            self.delay = int(rest) / 1000
        elif kind == "jitter":
            low, high, seed = rest.split(":")
            self.jitter = (int(low) / 1000, int(high) / 1000, random.Random(int(seed) + seed_offset))
        elif kind == "rate":
            self.rate = int(rest)
        elif kind == "pause":
            after, held = rest.split(":")
            self.pause = (started + float(after), started + float(after) + float(held))
        self.queue = asyncio.Queue(maxsize=64)
        self.last = 0.0
        self.task = asyncio.ensure_future(self.run())

    async def put(self, data):
        await self.queue.put((time.monotonic(), data))

    async def run(self):
        while True:
            arrived, data = await self.queue.get()
            if data is None:
                return
            wait = self.delay
            if self.jitter is not None:
                low, high, rng = self.jitter
                wait = rng.uniform(low, high)
            due = max(arrived + wait, self.last)
            if self.pause is not None and self.pause[0] <= due < self.pause[1]:
                due = self.pause[1]
            self.last = due
            now = time.monotonic()
            if due > now:
                await asyncio.sleep(due - now)
            if self.rate is not None:
                await asyncio.sleep(len(data) / self.rate)
            await self.send(data)

    async def flush(self):
        """Each byte queued, sent: before a Close, or the end."""
        await self.queue.put((time.monotonic(), None))
        await self.task


SHAPED = ("delay:", "jitter:", "rate:", "pause:")


async def pump(reader, writer, t_reader, t_writer):
    stalled = asyncio.Event()
    done = asyncio.Event()
    started = time.monotonic()

    async def write_client(data):
        writer.write(data)
        await writer.drain()

    async def write_target(data):
        t_writer.write(data)
        await t_writer.drain()

    shaped = args.mode.startswith(SHAPED)
    to_client = Shaper(write_client, args.mode, started, 0) if shaped else None
    to_target = Shaper(write_target, args.mode, started, 1) if shaped else None

    async def send_client(data, last=False):
        """A frame to the client, through the shaper when there is one."""
        if to_client is None:
            await write_client(data)
            return
        await to_client.put(data)
        if last:
            await to_client.flush()

    async def send_target(data):
        if to_target is None:
            await write_target(data)
        else:
            await to_target.put(data)

    # cut: the connection to the client ends, with no Close frame.
    cut = int(args.mode.split(":")[1]) if args.mode.startswith("cut:") else None
    # closeall: the bytes of both directions together, as the relay counts
    # its session byte cap.
    both = {"limit": None, "code": None, "count": 0}
    if args.mode.startswith("closeall:"):
        _, limit, code = args.mode.split(":")
        both["limit"], both["code"] = int(limit), int(code)

    async def counted(n):
        """Count n payload bytes; at the limit, close as the relay would,
        or end the connection with no Close."""
        both["count"] += n
        if cut is not None and both["count"] >= cut:
            writer.transport.abort()
            return True
        if both["limit"] is not None and both["count"] >= both["limit"]:
            await send_client(close_frame(both["code"], REASONS.get(both["code"], "fault injection")), last=True)
            return True
        return False

    async def stall_clock():
        if args.mode.startswith("stall:"):
            await asyncio.sleep(float(args.mode.split(":")[1]))
            stalled.set()

    async def keepalive():
        while not done.is_set():
            await asyncio.sleep(args.keepalive)
            if not stalled.is_set() and not done.is_set():
                await send_client(frame(0x2))

    async def up():  # client to target
        while True:
            opcode, data = await read_frame(reader)
            if stalled.is_set():
                continue  # swallowed: a stalled relay answers nothing
            if opcode in (0x0, 0x2):  # binary, or its continuation
                await send_target(data)
                if await counted(len(data)):
                    return
            elif opcode == 0x9:
                await send_client(frame(0xA, data))
            elif opcode == 0x8:
                await send_client(close_frame(1000, "client closed"), last=True)
                return
            elif opcode == 0x1:
                await send_client(close_frame(1003, "text frames are not accepted"), last=True)
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
                await send_client(close_frame(1000, "target closed"), last=True)
                return
            await send_client(frame(0x2, data))
            if await counted(len(data)):
                return
            sent += len(data)
            if limit is not None and sent >= limit:
                await send_client(close_frame(code, REASONS.get(code, "fault injection")), last=True)
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
    # The bytes for the target that the shaper still holds, then the end.
    if to_target is not None:
        try:
            await asyncio.wait_for(to_target.flush(), 30)
        except (asyncio.TimeoutError, OSError):
            pass
    if to_client is not None:
        to_client.task.cancel()
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
