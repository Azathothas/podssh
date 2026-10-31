#!/usr/bin/env python3
"""A stand-in for the relay, for fault injection in the interop harness.

It serves the forward path the way the live relay does (docs/relay.md):
TLS 1.3, `POST /v1/mint`, `GET /health`, and `GET /connect/<host>/<port>`
upgraded to a WebSocket whose binary frames carry the TCP stream, with an
empty binary frame as keepalive and Pings answered. Its diagnostics have the
live relay's shapes (2026-10-11, T-058): `GET /relays.json`, with this
stand-in as its one pool host, and `GET /trace`, whose dial of a target needs
the token in `X-Relay-Token`, as the live relay's does. And the reverse road
(scripts/fake_reverse.py, T-156): pairs, nodes and operators. Each instance can be told
to fail in one way, so podssh's failover, liveness and close handling are
tested against real OpenSSH without waiting for the real relay to fail.

Usage: fake-relay.py --cert CERT --key KEY --port-file FILE [--mode MODE]
                     [--keepalive SECONDS]

Modes:
  normal           behave
  tls12            behave, over TLS 1.2 alone, as a proxy that intercepts
                   TLS can (T-067)
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
  dropfirst:BYTES:CODE
                   the first session only: after BYTES from the target,
                   Close with CODE and its reason (CODE 0: the TCP
                   connection ends with no Close); each later session
                   behaves (T-025)
  dropfirstat:SECONDS:CODE
                   the same, SECONDS after the first session's upgrade
  slowopen:MS      behave, with each upgrade answered MS milliseconds late:
                   a host that opens after another (T-220)
  badaccept        answer each upgrade with a 101 whose Sec-WebSocket-Accept
                   is not the key's, and dial no target: a hop that answers
                   in the relay's place (T-324)
  hangup:MS        answer each upgrade with a valid 101, MS milliseconds
                   later end the TCP connection with no frame, and dial no
                   target: a hop that drops the upgraded stream (T-324)
  backlog:BYTES:RATE
                   to the client at RATE bytes a second, from a queue with
                   no bound, as a relay that reads its target at once; once
                   more than BYTES wait in it, Close 1013 `client receive
                   backlog`, the relay's check of a slow client, and drop
                   what waits (T-062)

Each mint, each upgrade and each Close from the client is a line on stdout
(`mint`, `upgrade`, `close CODE`), so a harness counts them (T-220).
"""

import argparse
import asyncio
import json
import ssl
import time
import urllib.parse

import fake_reverse
from fake_shape import SHAPED, Shaper
from fake_ws import close_frame, frame, read_frame, response, upgraded

TOKEN = "fake-relay-token-for-the-interop-harness"
# The relay's own reasons for each code (docs/relay.md, forward path).
# The sessions upgraded so far, for the modes that drop only the first.
UPGRADED = {"count": 0}

REASONS = {
    1001: "idle timeout",
    1009: "session byte cap",
    1011: "write failed: fault injection",
    1013: "target write backlog",
}

args = None


def event(line):
    """One line on stdout, as it happens, for the harness to count."""
    print(line, flush=True)


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
            event("mint")
            body = json.dumps({"token": TOKEN, "expires": int(time.time() * 1000) + 3600_000,
                               "scope": "forward"}).encode()
            writer.write(response(200, "OK", body, [("Content-Type", "application/json")]))
        elif method == "GET" and path == "/health":
            body = json.dumps({"ok": True, "service": "tcp-ssh-relay", "version": "fake",
                               "relay": {"edge_colo": "TEST"}}).encode()
            writer.write(response(200, "OK", body, [("Content-Type", "application/json")]))
        elif method == "GET" and path.split("?")[0] == "/relays.json":
            body = relays_json(path, headers)
            writer.write(response(200, "OK", body, [("Content-Type", "application/json")]))
        elif method == "GET" and path.split("?")[0] == "/trace":
            await trace(writer, path, headers)
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


def relays_json(path, headers):
    """The live relay's `/relays.json`, with this stand-in as its pool."""
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
    authority = headers.get("host", "relay.test")
    name = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
    target, connect_url = None, None
    if "host" in query and "port" in query:
        target = {"host": query["host"][0], "port": int(query["port"][0]), "bucket": None, "source": "explicit"}
        connect_url = f"wss://{authority}/connect/{target['host']}/{target['port']}"
    doc = {
        "service": "tcp-ssh-relay", "version": "fake", "you": {"edge_colo": "TEST", "bucket": None},
        "target": target, "connect": connect_url, "policy": {"note": "a stand-in relay on the loopback"},
        "pool": [{"rank": 0, "name": "stand-in", "host": name, "bucket": None, "region": None,
                  "client_ms": 0, "target_ms": 0, "score_ms": 0}],
        "limits": {"connect_timeout_ms": 10000, "idle_timeout_ms": 180000, "max_session_ms": 43200000,
                   "max_session_bytes": 67108864, "max_frame_bytes": 262144, "udp": "unsupported"},
    }
    return json.dumps(doc).encode()


async def trace(writer, path, headers):
    """`/trace`: public alone; a dial of `target=HOST:PORT` needs the token in
    its header, never in the URL. The answer has the live relay's shape, and
    names no address or place of the caller."""
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)

    def send(doc):
        writer.write(response(200, "OK", json.dumps(doc).encode(), [("Content-Type", "application/json")]))

    if "token" in query:
        writer.write(response(400, "Bad Request", b"trace: a token belongs in the X-Relay-Token header"))
        return
    doc = {"request": {"edge_colo": "TEST", "path": "/trace"}, "relay": {"name": "stand-in", "version": "fake"}}
    if "target" not in query:
        send(doc)
        return
    if headers.get("x-relay-token") != TOKEN:
        writer.write(response(403, "Forbidden", b"trace: missing or wrong token"))
        return
    wanted = query["target"][0]
    host, _, port = wanted.rpartition(":")
    host = host.strip("[]")
    started = time.monotonic()
    try:
        t_reader, t_writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 10)
    except (OSError, ValueError, asyncio.TimeoutError) as e:
        doc["target"] = {"error": f"refused: cannot reach {wanted}: {e}"}
        send(doc)
        return
    connect_ms = int((time.monotonic() - started) * 1000)
    first_ms, banner, seen = None, None, 0
    try:
        data = await asyncio.wait_for(t_reader.read(4096), 5)
        if data:
            first_ms, seen = int((time.monotonic() - started) * 1000), len(data)
            banner = data.split(b"\n")[0].rstrip(b"\r").decode("utf-8", "replace")
    except asyncio.TimeoutError:
        pass
    t_writer.close()
    doc["target"] = {"host": host, "port": int(port), "ok": True, "road": "loopback", "dialed": host,
                     "dialed_literal": True, "address_family": "4", "connect_ms": connect_ms,
                     "first_byte_ms": first_ms, "bytes_seen": seen,
                     "verdict": "live" if seen else "silent-or-unreachable", "banner": banner}
    send(doc)


async def connect(reader, writer, path, headers):
    if headers.get("x-relay-token") != TOKEN:
        writer.write(response(403, "Forbidden", b"forward: missing or wrong token"))
        return
    if args.mode.startswith("refuse:"):
        status = int(args.mode.split(":")[1])
        writer.write(response(status, "Refused", b"connect: refused by fault injection"))
        return
    if args.mode == "badaccept":
        writer.write(upgraded({"sec-websocket-key": "not the key that the client sent"}))
        await writer.drain()
        event("upgrade")
        return
    if args.mode.startswith("hangup:"):
        writer.write(upgraded(headers))
        await writer.drain()
        event("upgrade")
        await asyncio.sleep(int(args.mode.split(":")[1]) / 1000)
        writer.transport.abort()
        return
    parts = path.split("?")[0].split("/")
    host, port = parts[2], int(parts[3])
    try:
        t_reader, t_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    except (OSError, asyncio.TimeoutError) as e:
        writer.write(response(502, "Bad Gateway", f"relay: cannot reach {host}:{port}: {e}".encode()))
        return
    if args.mode.startswith("slowopen:"):
        await asyncio.sleep(int(args.mode.split(":")[1]) / 1000)
    writer.write(upgraded(headers))
    await writer.drain()
    event("upgrade")
    UPGRADED["count"] += 1
    await pump(reader, writer, t_reader, t_writer, first=UPGRADED["count"] == 1)


async def pump(reader, writer, t_reader, t_writer, first=False):
    stalled = asyncio.Event()
    done = asyncio.Event()
    started = time.monotonic()
    # dropfirst and dropfirstat: the first session ends, as a relay that
    # drops it; the later ones behave.
    drop = {"bytes": None, "seconds": None, "code": None}
    kind, _, rest = args.mode.partition(":")
    if first and kind in ("dropfirst", "dropfirstat"):
        when, code = rest.split(":")
        drop["code"] = int(code)
        drop["bytes" if kind == "dropfirst" else "seconds"] = float(when)

    async def write_client(data):
        writer.write(data)
        await writer.drain()

    async def write_target(data):
        t_writer.write(data)
        await t_writer.drain()

    shaped = args.mode.startswith(SHAPED)
    # backlog: only the bytes to the client wait, as at a slow client.
    backlog = args.mode.startswith("backlog:")
    to_client = Shaper(write_client, args.mode, started, 0) if shaped else None
    to_target = Shaper(write_target, args.mode, started, 1) if shaped and not backlog else None

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

    async def drop_now():
        """End the first session: a Close with the code's reason, or with
        code 0 no Close at all."""
        if drop["code"] == 0:
            writer.transport.abort()
        else:
            await send_client(close_frame(drop["code"], REASONS.get(drop["code"], "fault injection")), last=True)

    async def drop_clock():
        if drop["seconds"] is None:
            await asyncio.Event().wait()  # no clock: it never ends the session
        await asyncio.sleep(drop["seconds"])
        await drop_now()

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
                event(f"close {int.from_bytes(data[:2], 'big') if len(data) >= 2 else 1005}")
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
            if to_client is not None and to_client.over():
                # What waits is dropped; the Close goes after the last
                # whole frame.
                to_client.task.cancel()
                await write_client(close_frame(1013, "client receive backlog"))
                return
            if await counted(len(data)):
                return
            sent += len(data)
            if drop["bytes"] is not None and sent >= drop["bytes"]:
                await drop_now()
                return
            if limit is not None and sent >= limit:
                await send_client(close_frame(code, REASONS.get(code, "fault injection")), last=True)
                return

    tasks = [asyncio.ensure_future(t()) for t in (up, down, drop_clock)]
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
    if args.mode == "tls12":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
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
