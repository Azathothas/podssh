"""The shapes of the stand-in relay's traffic: one direction's bytes, late,
slow, held, or queued for a slow client as the relay queues them. Imported by
scripts/fake-relay.py."""

import asyncio
import random
import time

# The modes whose bytes go through a Shaper.
SHAPED = ("delay:", "jitter:", "rate:", "pause:", "backlog:")


class Shaper:
    """One direction's bytes, sent in order, late or slow as the mode says.
    A bounded queue keeps the sender's flow control; the backlog's queue has
    no bound, as a relay that reads its target at once, and counts what
    waits in it."""

    def __init__(self, send, mode, started, seed_offset):
        self.send, self.started = send, started
        self.delay, self.jitter, self.rate, self.pause = 0.0, None, None, None
        # backlog: the bytes that may wait, and those that wait now.
        self.limit, self.waiting = None, 0
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
        self.queue = asyncio.Queue(maxsize=0 if self.limit is not None else 64)
        self.last = 0.0
        self.task = asyncio.ensure_future(self.run())

    async def put(self, data):
        if data is not None:
            self.waiting += len(data)
        await self.queue.put((time.monotonic(), data))

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

    async def flush(self):
        """Each byte queued, sent: before a Close, or the end."""
        await self.queue.put((time.monotonic(), None))
        await self.task
