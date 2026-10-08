#!/usr/bin/env python3
"""A stand-in for an SSH server that stalls after the key exchange, for fault
injection in the interop harness (T-236). It forwards each connection to a
real server. The client's bytes always pass. The server's bytes pass until
its SSH_MSG_NEWKEYS, the last packet in clear; after it, they are read and
dropped, so the client waits for an answer that never comes.

Usage: fake-stall.py --target HOST:PORT --port-file FILE
"""

import argparse
import asyncio
import struct

NEWKEYS = 21
args = None


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


async def until_newkeys(reader, writer):
    """Pass the version line and the clear packets, up to NEWKEYS; then drop."""
    try:
        # Lines before the version line are allowed (RFC 4253, 4.2).
        while True:
            line = await reader.readuntil(b"\n")
            writer.write(line)
            if line.startswith(b"SSH-"):
                break
        while True:
            head = await reader.readexactly(6)
            length = struct.unpack(">I", head[:4])[0]
            rest = await reader.readexactly(length - 2)
            writer.write(head + rest)
            await writer.drain()
            if head[5] == NEWKEYS:
                break
        while await reader.read(65536):
            pass
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
        pass


async def handle(reader, writer):
    host, port = args.target.rsplit(":", 1)
    try:
        up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 10)
    except (OSError, asyncio.TimeoutError):
        writer.close()
        return
    await asyncio.gather(pipe(reader, up_writer), until_newkeys(up_reader, writer))


async def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--port-file", required=True)
    args = parser.parse_args()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    with open(args.port_file, "w", encoding="utf-8") as f:
        f.write(str(server.sockets[0].getsockname()[1]))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
