"""The stand-in relay's mode `v6close` (scripts/fake-relay.py, T-253): an
IPv6 target upgraded and dialed never, as the default relay answered one on
2026-10-08."""

from fake_ws import close_frame, read_frame, upgraded


async def close_unreached(reader, writer, headers, event):
    """v6close: the upgrade, then at the client's first payload the default
    relay's Close of 2026-10-08 for an IPv6 target, with no dial."""
    writer.write(upgraded(headers))
    await writer.drain()
    event("upgrade")
    while True:
        opcode, data = await read_frame(reader)
        if opcode in (0x0, 0x2) and data:
            break
        if opcode == 0x8:
            return
    writer.write(close_frame(1011, "target closed before sending anything"))
    await writer.drain()
