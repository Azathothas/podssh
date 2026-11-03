"""The probes of `podssh doctor --stream` in the stand-in relay (T-325), as
podssh's relay role serves them (crates/podssh-relay/src/serve/probe.rs):
GET /v1/probe/drip, go-httpbin's /drip (each byte at its own moment, the
first at once and the last at `duration`, after `delay`), and POST
/v1/probe/anything, a body of its Content-Length read as it comes and
answered with when each part of it came. Their limits go in /relays.json.

The modes play a path between the client and the server, each a fault that
the probes must name:

  buffer           each drip is held until its end, then sent at once, as a
                   path that holds a response until it is whole
  bodybuffer       each body's parts are said to come at once, when its
                   last byte came, as at a server behind a path that holds a
                   request's body until it is whole
  bodycap:BYTES    a body of more than BYTES gets 413 at once, as nginx's
                   client_max_body_size
  idle:SECONDS     a drip with nothing sent for SECONDS ends there: with 504
                   before its head, as nginx's proxy_read_timeout, and with
                   the connection cut after it
"""

import asyncio
import json
import time
import urllib.parse

from fake_ws import response

# The stand-in relay's --mode.
MODE = "normal"
DRIP_MAX = 600.0
DRIP_MAX_BYTES = 64 * 1024
BODY_MAX = 8 << 20
# Reads within this of the one before are one part of a body.
SAME_PART = 0.05
# How long a refused body is read and dropped, so the refusal is not lost.
DRAIN_WAIT = 5.0


def limits():
    """The probes' limits, as the role's /relays.json names them."""
    return {"paths": ["/v1/probe/drip", "/v1/probe/anything"], "drip_max_ms": int(DRIP_MAX * 1000),
            "drip_max_bytes": DRIP_MAX_BYTES, "body_max_bytes": BODY_MAX, "body": "streamed",
            "quiet_max_ms": int(DRIP_MAX * 1000), "at_once": 16}


async def handle(method, path, headers, reader, writer):
    """Serve a probe; False for a path that is not one."""
    route = path.split("?")[0]
    if route == "/v1/probe/drip" and method == "GET":
        await drip(path, writer)
        return True
    if route == "/v1/probe/anything" and method in ("POST", "PUT"):
        await anything(headers, reader, writer)
        return True
    return False


def refused(status, reason, words):
    return response(status, reason, f"{words}\n".encode(), [("Content-Type", "text/plain; charset=utf-8")])


async def drip(path, writer):
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
    try:
        duration = float(query.get("duration", ["2"])[0])
        delay = float(query.get("delay", ["2"])[0])
        count = int(query.get("numbytes", ["10"])[0])
        code = int(query.get("code", ["200"])[0])
    except ValueError:
        writer.write(refused(400, "Bad Request", "/v1/probe/drip: a value that does not read"))
        return
    if not 1 <= count <= DRIP_MAX_BYTES or duration < 0 or delay < 0 or duration + delay > DRIP_MAX:
        writer.write(refused(400, "Bad Request", "/v1/probe/drip: a value out of its range"))
        return
    pause = duration / (count - 1) if count > 1 else 0.0
    head = (f"HTTP/1.1 {code} OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {count}\r\n"
            "Cache-Control: no-store\r\nConnection: close\r\n\r\n").encode()
    # When each byte goes, from the request's end; the head with the first.
    moments = [delay + i * pause for i in range(count)]
    if MODE == "buffer":
        await asyncio.sleep(moments[-1])
        writer.write(head + b"*" * count)
        await writer.drain()
        return
    idle = float(MODE.split(":")[1]) if MODE.startswith("idle:") else None
    started = time.monotonic()
    last, headed = 0.0, False
    for at in moments:
        if idle is not None and at - last > idle:
            # Nothing went for the path's limit: it ends the stream there.
            await asyncio.sleep(max(0.0, started + last + idle - time.monotonic()))
            if headed:
                writer.transport.abort()
            else:
                writer.write(refused(504, "Gateway Timeout", "stand-in: no answer within the path's limit"))
                await writer.drain()
            return
        await asyncio.sleep(max(0.0, started + at - time.monotonic()))
        if not headed:
            writer.write(head)
            headed = True
        writer.write(b"*")
        await writer.drain()
        last = at


async def anything(headers, reader, writer):
    came = time.monotonic()
    if "content-length" not in headers or "transfer-encoding" in headers:
        writer.write(refused(411, "Length Required", "/v1/probe/anything: a body with its Content-Length"))
        return
    length = int(headers["content-length"])
    cap = int(MODE.split(":")[1]) if MODE.startswith("bodycap:") else BODY_MAX
    if length > cap:
        writer.write(refused(413, "Content Too Large", f"/v1/probe/anything: a body of {cap} bytes at most"))
        await writer.drain()
        try:
            await asyncio.wait_for(drop_body(reader, length), DRAIN_WAIT)
        except asyncio.TimeoutError:
            pass
        return
    parts, got = [], 0
    while got < length:
        data = await asyncio.wait_for(reader.read(min(65536, length - got)), 60)
        if not data:
            return
        got += len(data)
        at = time.monotonic() - came
        if parts and at - parts[-1][1] <= SAME_PART:
            parts[-1][1] = at
            parts[-1][2] += len(data)
        else:
            parts.append([at, at, len(data)])
    if MODE == "bodybuffer":
        # The path held the body: it all came once its last byte did.
        end = parts[-1][1] if parts else 0.0
        parts = [[end, end, got]]
    body = json.dumps({"bytes": got, "parts": [{"from_ms": int(a * 1000), "to_ms": int(b * 1000), "bytes": n}
                                               for a, b, n in parts]}).encode()
    writer.write(response(200, "OK", body, [("Content-Type", "application/json")]))


async def drop_body(reader, length):
    left = length
    while left > 0:
        data = await reader.read(min(65536, left))
        if not data:
            return
        left -= len(data)
