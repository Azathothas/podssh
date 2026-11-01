#!/usr/bin/env python3
"""Forward each TCP connection of LISTEN to TO, for the box on a host
whose only way out is a proxy on its own loopback, as a cloud session's
(T-251): the box's proxy runs in a container, which cannot reach the host's
loopback, so this listens on the address of the container's bridge on the
host and carries each connection to the host's proxy.

    python3 forward.py LISTEN_HOST:PORT TO_HOST:PORT SECONDS

It stops after SECONDS, so a run that stops early leaves nothing behind
for long.
"""

import asyncio
import sys


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
        except OSError:
            pass


def split(address):
    host, port = address.rsplit(":", 1)
    return host.strip("[]"), int(port)


async def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    listen, to, seconds = split(sys.argv[1]), split(sys.argv[2]), float(sys.argv[3])

    async def carry(reader, writer):
        try:
            up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(*to), 15)
        except (OSError, asyncio.TimeoutError):
            writer.close()
            return
        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))

    server = await asyncio.start_server(carry, *listen)
    print(f"forwarding {sys.argv[1]} to {sys.argv[2]}", flush=True)
    async with server:
        try:
            await asyncio.wait_for(server.serve_forever(), seconds)
        except asyncio.TimeoutError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
