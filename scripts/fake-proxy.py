#!/usr/bin/env python3
"""A stand-in for a sandbox's HTTP CONNECT proxy, for fault injection in the
interop harness. It resolves names itself, as the measured egress proxy does
(docs/target-environment.md), so the client sends names and needs no DNS.

Usage: fake-proxy.py --port-file FILE --log FILE
                     [--map NAME=HOST:PORT ...] [--answer NAME=STATUS ...]
                     [--from ADDRESS] [--move SECONDS:ADDRESS]
                     [--stop-after SECONDS] [--pause AFTER:FOR]
                     [--start-file FILE]

`--map` sends `CONNECT NAME:any-port` to HOST:PORT; `--answer` makes the
proxy answer CONNECT to NAME with STATUS (a 5xx, say) instead. Any other name
gets `403 not on the egress allowlist`, and anything but CONNECT gets 405.
Each request is logged as one line: the status, then the request line.

`--from` makes each tunnel leave from ADDRESS (127.0.0.2, say), so the far
end sees the client at another address. `--move` is a client whose address
changes: SECONDS after the first tunnel, each open tunnel goes silent, with
no RST, and each new one leaves from ADDRESS. `--stop-after` is a relay
host that stops: SECONDS after the first tunnel, each open tunnel ends with
RST, and new tunnels go on. `--pause` is a stall that ends: AFTER seconds
after the first tunnel, each byte of each tunnel, both ways, waits until
FOR seconds have passed (T-156). With `--start-file`, these clocks start
when FILE appears, in place of the first tunnel: a test puts a fault in the
middle of a transfer.
"""

import argparse
import asyncio
import os
import time

args = None
# When the clocks of --move, --stop-after and --pause start: the first
# tunnel, or the start file.
first_tunnel = None
# The open tunnels' writers, which --stop-after ends.
tunnels = set()
REASONS = {403: "not on the egress allowlist", 502: "Bad Gateway", 503: "Service Unavailable",
           504: "Gateway Timeout"}


def log(line):
    with open(args.log, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def moved():
    """Whether the client's address has changed (--move)."""
    if args.move is None or first_tunnel is None:
        return False
    return time.monotonic() >= first_tunnel + args.move[0]


async def paused():
    """Wait out the pause, when one holds now (--pause)."""
    if args.pause is None or first_tunnel is None:
        return
    start = first_tunnel + args.pause[0]
    end = start + args.pause[1]
    now = time.monotonic()
    if start <= now < end:
        await asyncio.sleep(end - now)


async def start_when_the_file_appears():
    """--start-file: the clocks of the faults start when the file appears."""
    global first_tunnel
    while not os.path.exists(args.start_file):
        await asyncio.sleep(0.05)
    first_tunnel = time.monotonic()
    log("the faults' clock started (--start-file)")


async def stop_after():
    """--stop-after: each tunnel open at the time ends with RST."""
    while first_tunnel is None:
        await asyncio.sleep(0.1)
    await asyncio.sleep(max(0.0, first_tunnel + args.stop_after - time.monotonic()))
    for writer in list(tunnels):
        writer.transport.abort()
    log("the open tunnels ended with RST (--stop-after)")


async def pipe(reader, writer, old):
    try:
        while data := await reader.read(65536):
            if old and moved():
                # The old address is gone: its bytes go nowhere, and nothing
                # tells either end.
                await asyncio.Event().wait()
            await paused()
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def refuse(writer, status, request_line):
    log(f"{status} {request_line}")
    writer.write(f"HTTP/1.1 {status} {REASONS.get(status, 'Refused')}\r\n\r\n".encode())
    await writer.drain()
    writer.close()


async def handle(reader, writer):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, OSError):
        writer.close()
        return
    request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = request_line.split()
    if len(parts) != 3 or parts[0] != "CONNECT":
        await refuse(writer, 405, request_line)
        return
    name = parts[1].rsplit(":", 1)[0]
    if name in args.answers:
        await refuse(writer, args.answers[name], request_line)
        return
    if name not in args.maps:
        await refuse(writer, 403, request_line)
        return
    host, port = args.maps[name]
    global first_tunnel
    old = not moved()
    source = args.move[1] if not old else args.source
    try:
        local = (source, 0) if source else None
        opening = asyncio.open_connection(host, port, local_addr=local)
        up_reader, up_writer = await asyncio.wait_for(opening, 10)
    except (OSError, asyncio.TimeoutError):
        await refuse(writer, 502, request_line)
        return
    if first_tunnel is None and args.start_file is None:
        first_tunnel = time.monotonic()
    log(f"200 {request_line} from {source or 'the default address'}")
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    # A tunnel opened after the move is from the new address, and stays.
    old = old and args.move is not None
    pair = {writer, up_writer}
    tunnels.update(pair)
    try:
        await asyncio.gather(pipe(reader, up_writer, old), pipe(up_reader, writer, old))
    finally:
        tunnels.difference_update(pair)


async def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--map", action="append", default=[])
    parser.add_argument("--answer", action="append", default=[])
    parser.add_argument("--from", dest="source", default=None)
    parser.add_argument("--move", default=None)
    parser.add_argument("--stop-after", type=float, default=None)
    parser.add_argument("--pause", default=None)
    parser.add_argument("--start-file", default=None)
    args = parser.parse_args()
    if args.pause is not None:
        after, held = args.pause.split(":", 1)
        args.pause = (float(after), float(held))
    if args.move is not None:
        seconds, address = args.move.split(":", 1)
        args.move = (float(seconds), address)
    args.maps = {}
    for item in args.map:
        name, target = item.split("=", 1)
        host, port = target.rsplit(":", 1)
        args.maps[name] = (host, int(port))
    args.answers = {name: int(status) for name, status in (a.split("=", 1) for a in args.answer)}
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    with open(args.port_file, "w", encoding="utf-8") as f:
        f.write(str(server.sockets[0].getsockname()[1]))
    if args.stop_after is not None:
        asyncio.ensure_future(stop_after())
    if args.start_file is not None:
        asyncio.ensure_future(start_when_the_file_appears())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
