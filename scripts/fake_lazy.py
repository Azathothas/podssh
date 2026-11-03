"""`?dial=lazy` for the stand-in relay (scripts/fake-relay.py, T-608), as the
contract says (docs/relay.md, "Connect options"): the upgrade first, the
target dialed on the client's first data frame alone. Pings are answered
before it, so a probe that sends no byte and only pings reaches no target.
Each end of such a session is a line, with the stand-in's clock in ms:
`lazy closed MS` when it ends with no byte, `lazy dial MS` when its first
byte makes the stand-in dial."""

import asyncio

from fake_ws import close_frame, frame, read_frame, upgraded


async def serve(reader, writer, headers, target, event, clock, pump):
    """The lazy session: `target` is (host, port), `event` writes a line,
    `clock` gives the ms, and `pump` carries the session once dialed."""
    writer.write(upgraded(headers))
    await writer.drain()
    event("upgrade")
    try:
        while True:
            opcode, data = await read_frame(reader)
            if opcode == 0x9:
                writer.write(frame(0xA, data))
                await writer.drain()
            elif opcode == 0x8:
                event(f"lazy closed {clock()}")
                writer.write(close_frame(1000, "client closed"))
                await writer.drain()
                return
            elif opcode in (0x0, 0x2) and data:
                break
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        event(f"lazy closed {clock()}")
        return
    event(f"lazy dial {clock()}")
    host, port = target
    try:
        t_reader, t_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    except (OSError, asyncio.TimeoutError):
        writer.write(close_frame(1011, f"relay: cannot reach {host}:{port}"))
        return
    t_writer.write(data)
    await t_writer.drain()
    await pump(reader, writer, t_reader, t_writer)
