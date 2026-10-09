"""The HTTP and WebSocket pieces of the stand-ins of the interop harness:
an HTTP answer, a server's frame, a Close, a client's frame read and
unmasked, and the 101 of an upgrade. Imported by scripts/fake-relay.py and
scripts/fake_reverse.py."""

import base64
import hashlib
import struct
from email.utils import formatdate

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def response(status, reason, body=b"", headers=()):
    head = [f"HTTP/1.1 {status} {reason}", f"Date: {formatdate(usegmt=True)}",
            f"Content-Length: {len(body)}", "Connection: close"]
    head += [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


def frame(opcode, payload=b""):
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 65536:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


def close_frame(code, reason=""):
    return frame(0x8, struct.pack("!H", code) + reason.encode())


def unmask(data, mask):
    """The payload XOR the mask, as one big integer: a loop over each byte
    in Python would cap the stand-in at a few MiB/s."""
    if not data:
        return b""
    key = (mask * (len(data) // 4 + 1))[:len(data)]
    value = int.from_bytes(data, "big") ^ int.from_bytes(key, "big")
    return value.to_bytes(len(data), "big")


async def read_frame(reader):
    b0, b1 = await reader.readexactly(2)
    opcode, n = b0 & 0x0F, b1 & 0x7F
    if n == 126:
        (n,) = struct.unpack("!H", await reader.readexactly(2))
    elif n == 127:
        (n,) = struct.unpack("!Q", await reader.readexactly(8))
    if not b1 & 0x80:
        raise ConnectionError("an unmasked client frame")
    mask = await reader.readexactly(4)
    return opcode, unmask(await reader.readexactly(n), mask)


def upgraded(headers):
    """The 101 that accepts a WebSocket upgrade with these headers."""
    accept = base64.b64encode(hashlib.sha1(headers["sec-websocket-key"].encode() + GUID).digest()).decode()
    return ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode()
