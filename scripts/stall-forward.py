#!/usr/bin/env python3
"""A TCP forwarder that stops reading from its client (T-227).

It passes the bytes both ways until the client has sent --after bytes (the
SSH handshake and the session request take a few KiB), then reads nothing
more from the client, with a small receive buffer: the client's writes stall
below SSH, as with a TCP zero window that never opens. The server's bytes
still reach the client. One client at a time, for as long as it runs.

    stall-forward.py --listen PORT --to HOST:PORT [--after BYTES]
"""

import argparse
import asyncio
import socket


async def server_to_client(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass


async def handle(client_reader, client_writer, target, after):
    host, port = target
    try:
        server_reader, server_writer = await asyncio.open_connection(host, port)
    except OSError:
        client_writer.close()
        return
    back = asyncio.ensure_future(server_to_client(server_reader, client_writer))
    passed = 0
    try:
        while passed < after:
            data = await client_reader.read(min(65536, after - passed))
            if not data:
                break
            passed += len(data)
            server_writer.write(data)
            await server_writer.drain()
        # The stall: no read from the client again, while the server's side
        # goes on.
        await back
    except OSError:
        pass
    finally:
        back.cancel()
        for writer in (server_writer, client_writer):
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--to", required=True)
    parser.add_argument("--after", type=int, default=65536)
    args = parser.parse_args()
    host, _, port = args.to.rpartition(":")
    target = (host, int(port))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # A small receive buffer, which the accepted socket takes: the client's
    # window closes soon after the stall.
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    listener.bind(("127.0.0.1", args.listen))
    listener.listen(8)
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, target, args.after), sock=listener, limit=65536
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
