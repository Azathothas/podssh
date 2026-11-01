"""The reverse road of the stand-in relay (T-156), as the live relay showed
it (docs/relay.md, the reverse path): POST /v1/pair; the node's socket at
/v1/node/<name>; the operator's at /v1/connect/<name>; GET /v1/status/<name>
and POST /v1/stop/<name>; each token in X-Relay-Token. The node gets the
text frames hello, open {id} and close {id}, and answers ready {id} or
reject {id, reason}; its binary frames are the session's 32 hex characters,
then the payload. The operator's frames are the payload alone. The state
lives in the process, so a session outlives one connection to it, as on the
relay's control host."""

import asyncio
import json
import os
import secrets
import sys
import time

from fake_ws import close_frame, frame, read_frame, response, upgraded

# name -> Pair
PAIRS = {}
# The stand-in relay's --mode. fault1003: the first socket of each pair's
# node is closed with 1003 "unknown session id" half a second after its
# hello, as the relay closes a node for a frame of an id that it forgot.
# expirefirst:SECONDS: the run's first pair says that it expires in 23 h,
# within the last day in which its next pair may be made, and the relay
# ends it after SECONDS as at its expiry: each socket of the pair gets 1001
# "pair expired", and its tokens a 403 after.
MODE = "normal"
# lenient: a frame of the node for an id that the relay does not know is
# dropped; in each other mode it closes the node's socket with 1003
# "unknown session id", as the live relay does.
# Whether the short pair of expirefirst was made.
SHORT = {"made": False}
# FAKE_RELAY_DEBUG=1: each frame of the reverse road, on stderr.
DEBUG = bool(os.environ.get("FAKE_RELAY_DEBUG"))


def note(text):
    if DEBUG:
        print(f"reverse: {text}", file=sys.stderr, flush=True)
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
JSON = [("Content-Type", "application/json")]


class Socket:
    """One WebSocket of the relay, its writes in order."""

    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.lock = asyncio.Lock()
        self.closed = False

    async def send(self, data):
        if self.closed:
            return
        async with self.lock:
            try:
                self.writer.write(data)
                await self.writer.drain()
            except (ConnectionError, OSError):
                self.closed = True

    async def text(self, message):
        await self.send(frame(0x1, json.dumps(message).encode()))

    async def close(self, code, reason):
        await self.send(close_frame(code, reason))
        self.closed = True


class Pair:
    def __init__(self):
        # 34 characters of [-0-9a-z], and 64 of [0-9a-z] for each token.
        self.name = "p-" + secrets.token_hex(16)
        self.node_token, self.connect_token, self.stop_token = (
            "".join(secrets.choice(ALPHABET) for _ in range(64)) for _ in range(3))
        self.expires = int(time.time() * 1000) + 72 * 3600 * 1000
        # Seconds until the relay ends the pair, for expirefirst.
        self.ends_in = None
        if MODE.startswith("expirefirst:") and not SHORT["made"]:
            SHORT["made"] = True
            self.expires = int(time.time() * 1000) + 23 * 3600 * 1000
            self.ends_in = float(MODE.split(":")[1])
        self.node = None
        # Whether a socket of the node was closed for a fault (fault1003).
        self.faulted = False
        # id -> (the operator's Socket, the Event of the node's ready, which
        # node() sends on to the operator)
        self.sessions = {}


async def handle(method, path, headers, reader, writer):
    """Serve a request of the reverse road; False for any other path."""
    if method == "POST" and path == "/v1/pair":
        await reader.readexactly(int(headers.get("content-length", "0")))
        pair = Pair()
        PAIRS[pair.name] = pair
        if pair.ends_in is not None:
            asyncio.ensure_future(expire(pair))
        body = {"name": pair.name, "node_token": pair.node_token, "connect_token": pair.connect_token,
                "stop_token": pair.stop_token, "expires": pair.expires}
        writer.write(response(200, "OK", json.dumps(body).encode(), JSON))
        return True
    parts = path.split("?")[0].split("/")
    if len(parts) != 4 or parts[1] != "v1" or parts[2] not in ("node", "connect", "status", "stop"):
        return False
    kind, pair = parts[2], PAIRS.get(parts[3])
    wanted = {"node": "node_token", "connect": "connect_token", "status": "connect_token", "stop": "stop_token"}
    if pair is None or headers.get("x-relay-token") != getattr(pair, wanted[kind]):
        writer.write(response(403, "Forbidden", b"reverse: forbidden"))
        return True
    if kind == "status":
        body = {"online": pair.node is not None, "sessions": len(pair.sessions)}
        writer.write(response(200, "OK", json.dumps(body).encode(), JSON))
    elif kind == "stop":
        await reader.readexactly(int(headers.get("content-length", "0")))
        sessions = len(pair.sessions)
        for socket, _ in list(pair.sessions.values()):
            await socket.close(1001, "operator stopped reverse relay")
        if pair.node is not None:
            await pair.node.close(1001, "operator stopped reverse relay")
        PAIRS.pop(pair.name, None)
        writer.write(response(200, "OK", json.dumps({"stopped": True, "sessions": sessions}).encode(), JSON))
    elif kind == "node":
        if pair.node is not None and not pair.node.closed:
            writer.write(response(409, "Conflict", b"reverse: a node is connected"))
            return True
        writer.write(upgraded(headers))
        await writer.drain()
        await node(pair, Socket(reader, writer))
    else:
        writer.write(upgraded(headers))
        await writer.drain()
        await operator(pair, Socket(reader, writer))
    return True


async def expire(pair):
    """End the pair as the relay ends one at its expiry."""
    await asyncio.sleep(pair.ends_in)
    PAIRS.pop(pair.name, None)
    note(f"pair {pair.name} expired")
    for operator_socket, _ in list(pair.sessions.values()):
        await operator_socket.close(1001, "pair expired")
    if pair.node is not None:
        await pair.node.close(1001, "pair expired")


async def node(pair, socket):
    pair.node = socket
    await socket.text({"type": "hello", "version": 1, "maxFrameBytes": 65536, "maxSessions": 64})
    if MODE == "fault1003" and not pair.faulted:
        pair.faulted = True
        await asyncio.sleep(0.5)
        await socket.close(1003, "unknown session id")
        note("node closed for a fault: 1003 unknown session id")
    try:
        while True:
            opcode, data = await read_frame(socket.reader)
            note(f"node frame {opcode:#x}, {len(data)} bytes: {data[:48]!r}")
            if opcode == 0x1:
                message = json.loads(data)
                session = pair.sessions.get(message.get("id"))
                if session is None:
                    continue
                operator_socket, ready = session
                if message.get("type") == "ready":
                    # The operator hears ready before any byte of the
                    # session, as from the relay: the node's next frame can
                    # be in this read's buffer already, and goes on at once.
                    await operator_socket.text({"type": "ready", "id": message["id"]})
                    ready.set()
                elif message.get("type") == "reject":
                    await operator_socket.close(1011, message.get("reason") or "node rejected the session")
                elif message.get("type") == "close":
                    await operator_socket.close(1000, "node closed the session")
            elif opcode in (0x0, 0x2):
                sid = data[:32].decode("ascii", "replace")
                session = pair.sessions.get(sid)
                if session is not None:
                    await session[0].send(frame(0x2, data[32:]))
                elif MODE != "lenient":
                    # As the live relay: a frame of an id that it forgot (a
                    # session that ended) closes the node's whole socket.
                    print(f"reverse: a frame of the node for an unknown id {sid[:8]}: 1003", file=sys.stderr, flush=True)
                    await socket.close(1003, "unknown session id")
                    break
            elif opcode == 0x9:
                await socket.send(frame(0xA, data))
            elif opcode == 0x8:
                break
    except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
        pass
    finally:
        socket.closed = True
        if pair.node is socket:
            pair.node = None
            for operator_socket, _ in list(pair.sessions.values()):
                await operator_socket.close(1011, "node disconnected")


async def operator(pair, socket):
    if pair.node is None or pair.node.closed:
        await socket.close(1011, "node unavailable")
        return
    sid = secrets.token_hex(16)
    ready = asyncio.Event()
    pair.sessions[sid] = (socket, ready)
    try:
        await pair.node.text({"type": "open", "id": sid})
        try:
            await asyncio.wait_for(ready.wait(), 15)
        except asyncio.TimeoutError:
            await socket.close(1013, "node open timeout")
            return
        while not socket.closed:
            opcode, data = await read_frame(socket.reader)
            note(f"operator frame {opcode:#x}, {len(data)} bytes")
            if opcode in (0x0, 0x2):
                if pair.node is None:
                    await socket.close(1011, "node offline")
                    return
                await pair.node.send(frame(0x2, sid.encode() + data))
            elif opcode == 0x1:
                await socket.close(1003, "binary frames required")
                return
            elif opcode == 0x9:
                await socket.send(frame(0xA, data))
            elif opcode == 0x8:
                await socket.close(1000, "")
                return
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        pair.sessions.pop(sid, None)
        if pair.node is not None:
            await pair.node.text({"type": "close", "id": sid})
