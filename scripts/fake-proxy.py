#!/usr/bin/env python3
"""A stand-in for a sandbox's HTTP CONNECT proxy, for fault injection in the
interop harness. It resolves names itself, as the measured egress proxy does
(docs/target-environment.md), so the client sends names and needs no DNS.

Usage: fake-proxy.py --port-file FILE --log FILE
                     [--map NAME=HOST:PORT ...] [--answer NAME=STATUS ...]

`--map` sends `CONNECT NAME:any-port` to HOST:PORT; `--answer` makes the
proxy answer CONNECT to NAME with STATUS (a 5xx, say) instead. Any other name
gets `403 not on the egress allowlist`, and anything but CONNECT gets 405.
Each request is logged as one line: the status, then the request line.
"""

import argparse
import asyncio

args = None
REASONS = {403: "not on the egress allowlist", 502: "Bad Gateway", 503: "Service Unavailable",
           504: "Gateway Timeout"}


def log(line):
    with open(args.log, "a", encoding="utf-8") as f:
        f.write(line + "\n")


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
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
    try:
        up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    except (OSError, asyncio.TimeoutError):
        await refuse(writer, 502, request_line)
        return
    log(f"200 {request_line}")
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))


async def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--map", action="append", default=[])
    parser.add_argument("--answer", action="append", default=[])
    args = parser.parse_args()
    args.maps = {}
    for item in args.map:
        name, target = item.split("=", 1)
        host, port = target.rsplit(":", 1)
        args.maps[name] = (host, int(port))
    args.answers = {name: int(status) for name, status in (a.split("=", 1) for a in args.answer)}
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    with open(args.port_file, "w", encoding="utf-8") as f:
        f.write(str(server.sockets[0].getsockname()[1]))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
