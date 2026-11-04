"""The shapes of the stand-in relay's traffic: one direction's bytes, late,
slow, held, or queued for a slow client as the relay queues them; and a link
with a rate, a queue, a delay and a loss, in the shapes of osewa's four lab
profiles (T-660). Imported by scripts/fake-relay.py, whose --mode takes each
shape, and by scripts/fake-proxy.py, whose --shape does.

  link:DELAY:RATE:QUEUE:LOSS:SEED
      each way: bytes wait for RATE bytes a second behind those before them,
      then DELAY milliseconds; at most QUEUE bytes wait (0: no bound), and
      past it the reader waits; LOSS segments in a thousand are lost, from a
      generator seeded with SEED
  profile:NAME
      one of PROFILES: far, cellular, wifi or slow
"""

import asyncio
import random
import time

# The modes whose bytes go through a Shaper.
SHAPED = ("delay:", "jitter:", "rate:", "pause:", "backlog:", "link:", "profile:")

# osewa's lab profiles (docs/research/osewa-paper.md, section 3.1) as links,
# each way: the delay is half the round trip. Where osewa names no buffer,
# the queue is netem's default limit, 1000 full packets; its deep buffer is
# 4 s at its rate.
PROFILES = {
    "far": "link:60:6250000:1500000:0:1",  # 120 ms, 50 Mbit/s
    "cellular": "link:30:1250000:5000000:0:1",  # 60 ms, 10 Mbit/s, a deep buffer
    "wifi": "link:10:2500000:1500000:10:1",  # 20 ms, 20 Mbit/s, 1 % loss
    "slow": "link:50:125000:1500000:10:1",  # 100 ms, 1 Mbit/s, 1 % loss
}
# A TCP segment's payload: the unit that a link loses.
SEGMENT = 1448
# The bytes of each step of a link: a key waits behind the bytes queued before
# it, and not behind a whole read of 64 KiB, as on a link of packets.
PIECE = 4096
# Linux's least retransmission timeout, which a lost segment with nothing
# after it waits for.
LEAST_RTO = 0.2


def link_of(mode):
    """The link of a profile, or the mode itself; ValueError for a profile
    that does not exist, so a harness refuses it before it serves."""
    if not mode.startswith("profile:"):
        return mode
    name = mode.split(":", 1)[1]
    if name not in PROFILES:
        raise ValueError(f"profile:{name}: one of {', '.join(sorted(PROFILES))}")
    return PROFILES[name]


class Shaper:
    """One direction's bytes, sent in order, late or slow as the mode says.
    A bounded queue keeps the sender's flow control; the backlog's queue has
    no bound, as a relay that reads its target at once, and counts what
    waits in it. A link's queue is bounded in bytes."""

    def __init__(self, send, mode, started, seed_offset):
        mode = link_of(mode)
        self.send, self.started = send, started
        self.delay, self.jitter, self.rate, self.pause = 0.0, None, None, None
        # backlog: the bytes that may wait, and those that wait now.
        self.limit, self.waiting = None, 0
        # link: the bytes that may wait, in flight too; the loss and its
        # generator; and when the link is free to send the next byte.
        self.room, self.loss, self.free = None, None, 0.0
        kind, _, rest = mode.partition(":")
        if kind == "delay":
            self.delay = int(rest) / 1000
        elif kind == "jitter":
            low, high, seed = rest.split(":")
            self.jitter = (int(low) / 1000, int(high) / 1000, random.Random(int(seed) + seed_offset))
        elif kind == "rate":
            self.rate = int(rest)
        elif kind == "pause":
            after, held = rest.split(":")
            self.pause = (started + float(after), started + float(after) + float(held))
        elif kind == "backlog":
            limit, rate = rest.split(":")
            self.limit, self.rate = int(limit), int(rate)
        elif kind == "link":
            delay, rate, room, loss, seed = rest.split(":")
            self.delay, self.rate, self.room = int(delay) / 1000, int(rate), int(room) or None
            if int(loss):
                self.loss = (int(loss) / 1000, random.Random(int(seed) + seed_offset))
        self.link = kind == "link"
        self.queue = asyncio.Queue(maxsize=0 if self.limit is not None or self.link else 64)
        self.drained = asyncio.Event()
        self.last = 0.0
        self.task = asyncio.ensure_future(self.run_link() if self.link else self.run())
        if self.link:
            # A reader that waits for room wakes when the sender ends too.
            self.task.add_done_callback(lambda _task: self.drained.set())

    async def put(self, data):
        if data is not None and self.link:
            for at in range(0, len(data), PIECE):
                await self.put_piece(data[at:at + PIECE])
            return
        if data is not None:
            self.waiting += len(data)
        await self.queue.put((time.monotonic(), data))

    async def put_piece(self, piece):
        """A piece onto a link: a full queue makes the reader wait, where a
        link would drop and the sender's window would shrink; no byte is
        lost, and the kernel's buffers hold what the window let out, as a
        sender's own buffer holds what it has not sent. A sender that ended
        (its end of the connection closed) ends the reader too."""
        while self.room is not None and self.waiting >= self.room and not self.task.done():
            self.drained.clear()
            await self.drained.wait()
        if self.task.done():
            raise ConnectionResetError("the sender of a shaped way ended")
        self.waiting += len(piece)
        await self.queue.put((time.monotonic(), piece))

    def over(self):
        """Whether more bytes wait than the backlog allows."""
        return self.limit is not None and self.waiting > self.limit

    async def run(self):
        while True:
            arrived, data = await self.queue.get()
            if data is None:
                return
            wait = self.delay
            if self.jitter is not None:
                low, high, rng = self.jitter
                wait = rng.uniform(low, high)
            due = max(arrived + wait, self.last)
            if self.pause is not None and self.pause[0] <= due < self.pause[1]:
                due = self.pause[1]
            self.last = due
            now = time.monotonic()
            if due > now:
                await asyncio.sleep(due - now)
            if self.rate is not None:
                await asyncio.sleep(len(data) / self.rate)
            await self.send(data)
            self.waiting -= len(data)

    async def run_link(self):
        """A link: each piece waits for the rate behind those before it, then
        the delay, and a lost segment its retransmission. The times are of a
        schedule, not of the last sleep, so a timer's coarse wake never slows
        the rate."""
        while True:
            arrived, data = await self.queue.get()
            if data is None:
                return
            self.free = max(arrived, self.free) + len(data) / self.rate
            due = max(self.free + self.delay + self.lost(len(data)), self.last)
            self.last = due
            now = time.monotonic()
            if due > now:
                await asyncio.sleep(due - now)
            await self.send(data)
            self.waiting -= len(data)
            self.drained.set()

    def lost(self, size):
        """What a lost segment of these bytes adds: TCP sends it again a
        round trip later when bytes follow it, whose acknowledgements tell
        the loss, else after its probe or its timeout. Each byte after it
        waits, as in one TCP stream. The halving of the sender's window is
        not shaped, so a lossy link's bulk is faster here than through
        netem."""
        if self.loss is None:
            return 0.0
        chance, rng = self.loss
        segments = -(-size // SEGMENT)
        if not any(rng.random() < chance for _ in range(segments)):
            return 0.0
        trip = 2 * self.delay
        return trip if not self.queue.empty() else max(2 * trip, LEAST_RTO)

    async def flush(self):
        """Each byte queued, sent: before a Close, or the end."""
        await self.queue.put((time.monotonic(), None))
        await self.task
