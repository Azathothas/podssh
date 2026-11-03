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
# "pair expired", and its tokens a 403 after. noready: each operator's socket
# is taken and never readied, and the relay's 15 s for a node's answer never
# end it (T-589).
MODE = "normal"
# lenient: a frame of the node for an id that the relay does not know is
# dropped; in each other mode it closes the node's socket with 1003
# "unknown session id", as the live relay does.
# strict:RATE (T-443): the bound of the contract for a slow receiver
# (crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt, `1011 relay
# backpressure`): each frame for a socket waits in a queue with no bound, as
# at a relay that reads its sender at once, and goes to an operator at RATE
# bytes a second (0: at once; to a node, at once); a frame that would put
# more than 1 MiB in the queue is dropped, the socket gets Close 1011 "relay
# backpressure", and a line on stderr says so. A Close goes after the frames
# before it.
BOUND = 1 << 20
# Whether the short pair of expirefirst was made.
SHORT = {"made": False}
# Seconds after an operator's link was lost (an error, not its Close) in
# which a frame of the node for that session was already on its way: the
# node learns of the loss only from the relay's close, so such a frame is
# said apart. The socket still gets 1003, as on the live relay.
IN_FLIGHT = 2.0
# lateclose:SECONDS (T-421): the relay tells the node of an operator's lost
# link SECONDS late, as a relay far from its node does, so that the node's
# frames for that session are sure to come after the relay forgot it.
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


class Bounded(Socket):
    """A socket of strict:RATE: its frames in a queue that only BOUND
    limits, sent in order at `rate` bytes a second (None: as fast as the
    socket takes them)."""

    def __init__(self, reader, writer, rate, who):
        super().__init__(reader, writer)
        self.rate, self.who, self.waiting = rate, who, 0
        self.queue = asyncio.Queue()
        self.task = asyncio.ensure_future(self.run())

    async def send(self, data):
        if self.closed:
            return
        if self.waiting + len(data) > BOUND:
            # As the contract's relay: the frame is dropped, and what waits.
            print(f"reverse: {self.waiting + len(data)} bytes would wait for {self.who}: 1011 relay backpressure",
                  file=sys.stderr, flush=True)
            self.task.cancel()
            await super().send(close_frame(1011, "relay backpressure"))
            self.closed = True
            return
        self.waiting += len(data)
        await self.queue.put(data)

    async def close(self, code, reason):
        # After the frames before it, as a relay that closes a session
        # delivers what it holds first.
        await self.queue.put((code, reason))

    async def run(self):
        while True:
            item = await self.queue.get()
            if item is None:
                return
            if isinstance(item, tuple):
                await super().send(close_frame(*item))
                self.closed = True
                return
            if self.rate:
                await asyncio.sleep(len(item) / self.rate)
            await super().send(item)
            self.waiting -= len(item)


async def settled(socket):
    """In strict:RATE, what waits in a socket's queue, its Close too, goes
    out before its handler returns and the connection ends."""
    task = getattr(socket, "task", None)
    if task is None or task.done():
        return
    await socket.queue.put(None)
    try:
        await asyncio.wait_for(task, 60)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        pass


def socket_for(reader, writer, who):
    """The relay's socket of a node or an operator: bounded in strict:RATE."""
    if not MODE.startswith("strict:"):
        return Socket(reader, writer)
    rate = int(MODE.split(":")[1]) if who == "an operator" else 0
    return Bounded(reader, writer, rate or None, who)


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
        # id -> when its operator's link was lost, for IN_FLIGHT.
        self.lost = {}


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
        socket = socket_for(reader, writer, "a node")
        await node(pair, socket)
        await settled(socket)
    else:
        writer.write(upgraded(headers))
        await writer.drain()
        socket = socket_for(reader, writer, "an operator")
        await operator(pair, socket)
        await settled(socket)
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


async def never_ready(socket):
    """noready (T-589): the operator's socket is taken and never readied, as
    a relay whose node never answers, with no limit of its own: Pings are
    answered, and the socket ends with the operator's Close or its loss."""
    try:
        while not socket.closed:
            opcode, data = await read_frame(socket.reader)
            if opcode == 0x9:
                await socket.send(frame(0xA, data))
            elif opcode == 0x8:
                return
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass


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
                    lost = pair.lost.get(sid)
                    if lost is not None and time.monotonic() - lost < IN_FLIGHT:
                        # On its way before the node could hear of the loss.
                        ms = int((time.monotonic() - lost) * 1000)
                        print(f"reverse: a frame of the node for {sid[:8]}, whose operator's link was lost {ms} ms "
                              "before (in flight): 1003", file=sys.stderr, flush=True)
                    else:
                        print(f"reverse: a frame of the node for an unknown id {sid[:8]}: 1003", file=sys.stderr,
                              flush=True)
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
    if MODE == "noready":
        await never_ready(socket)
        return
    if pair.node is None or pair.node.closed:
        await socket.close(1011, "node unavailable")
        return
    sid = secrets.token_hex(16)
    ready = asyncio.Event()
    pair.sessions[sid] = (socket, ready)
    lost = False
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
        # The link was lost, not closed: the node's frames may be on the way.
        lost = True
    finally:
        pair.sessions.pop(sid, None)
        if lost:
            pair.lost[sid] = time.monotonic()
        if lost and MODE.startswith("lateclose:"):
            asyncio.ensure_future(close_late(pair, sid, float(MODE.split(":", 1)[1])))
        elif pair.node is not None:
            await pair.node.text({"type": "close", "id": sid})


async def close_late(pair, sid, seconds):
    """The close of a lost link, `seconds` late (lateclose)."""
    await asyncio.sleep(seconds)
    if pair.node is not None and not pair.node.closed:
        await pair.node.text({"type": "close", "id": sid})
