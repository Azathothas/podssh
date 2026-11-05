"""What SSH's compression saves on a terminal's output (T-669): the bytes
that a session sends to the client, with `-C` and without, through a proxy
on the loopback that counts them, and the CPU time of podssh's process.

    python3 scripts/compress-measure.py BINARY --port 2201 --identity KEY \
        --known-hosts FILE [--user U] [--seconds 60] [--log FILE]

Two workloads: `top` on a pty, refreshed each half second, for --seconds;
and `cat` of a build's log (--log, a file that the server can read). Each
runs once with `-o Compression=no` and once with `-C`; the table gives the
bytes down, the ratio, the bytes of an hour of `top`, and podssh's CPU
time. The default relay ends a session at 64 MiB (docs/relay.md).
"""

import argparse
import asyncio
import os
import resource
import signal
import subprocess
import sys
import threading
import time

HOUR = 3600
SESSION_CAP = 64 << 20


class Counter:
    """A proxy on 127.0.0.1 to TARGET, counting the bytes of each way."""

    def __init__(self, target):
        self.target = target
        self.down = 0
        self.up = 0
        self.port = None
        self.ready = threading.Event()
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self._run, daemon=True).start()
        if not self.ready.wait(10):
            sys.exit("compress-measure: the counting proxy did not start")

    def _run(self):
        asyncio.set_event_loop(self.loop)
        server = self.loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", 0))
        self.port = server.sockets[0].getsockname()[1]
        self.ready.set()
        self.loop.run_forever()

    async def _pump(self, reader, writer, way):
        try:
            while data := await reader.read(65536):
                if way == "down":
                    self.down += len(data)
                else:
                    self.up += len(data)
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def _handle(self, client_r, client_w):
        server_r, server_w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", self.target), 10)
        await asyncio.gather(self._pump(client_r, server_w, "up"), self._pump(server_r, client_w, "down"))

    def reset(self):
        self.down = self.up = 0


def cpu():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def run(args, counter, compression, command, seconds, tty):
    """One session: the bytes down, the bytes up, podssh's CPU seconds."""
    counter.reset()
    argv = [args.binary, "ssh", "--direct", "-p", str(counter.port), "-i", args.identity,
            "-o", f"UserKnownHostsFile={args.known_hosts}", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10", "-o", f"Compression={'yes' if compression else 'no'}"]
    if tty:
        argv.append("-tt")
    argv += [f"{args.user}@127.0.0.1", command]
    env = dict(os.environ, HOME=args.home)
    env.pop("SSH_AUTH_SOCK", None)
    before = cpu()
    child = subprocess.Popen(argv, stdin=subprocess.PIPE if tty else subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
    try:
        child.wait(timeout=seconds if seconds else 600)
    except subprocess.TimeoutExpired:
        child.send_signal(signal.SIGTERM)
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)
    if child.stdin:
        child.stdin.close()
    err = child.stderr.read().decode(errors="replace").strip()
    time.sleep(0.5)
    if not seconds and child.returncode != 0:
        sys.exit(f"compress-measure: {command!r} exited {child.returncode}: {err}")
    return counter.down, counter.up, cpu() - before


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary")
    parser.add_argument("--port", type=int, default=2201)
    parser.add_argument("--user", default=os.environ.get("USER", "root"))
    parser.add_argument("--identity", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--home", default=os.environ.get("HOME", "/tmp"))
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--log", help="a build's log that the server can read")
    args = parser.parse_args()
    counter = Counter(args.port)

    rows = []
    top = "TERM=xterm-256color COLUMNS=120 LINES=40 top -d 0.5"
    for name, command, seconds, tty in [("top", top, args.seconds, True)] + (
        [("build log", f"cat {args.log}", 0, False)] if args.log else []
    ):
        plain = run(args, counter, False, command, seconds, tty)
        packed = run(args, counter, True, command, seconds, tty)
        rows.append((name, seconds, plain, packed))

    print(f"{'workload':<10} {'bytes down':>12} {'with -C':>12} {'ratio':>6} {'an hour':>10} "
          f"{'an hour -C':>11} {'cpu s':>6} {'cpu s -C':>8}")
    for name, seconds, plain, packed in rows:
        ratio = plain[0] / max(packed[0], 1)
        hour = lambda n: f"{n * HOUR / seconds / (1 << 20):.1f} MiB" if seconds else "-"
        print(f"{name:<10} {plain[0]:>12,} {packed[0]:>12,} {ratio:>6.1f} {hour(plain[0]):>10} "
              f"{hour(packed[0]):>11} {plain[2]:>6.2f} {packed[2]:>8.2f}")
    for name, seconds, plain, packed in rows:
        if seconds:
            for label, got in (("without -C", plain[0]), ("with -C", packed[0])):
                cap = SESSION_CAP * seconds / max(got, 1) / HOUR
                print(f"{name} {label}: the relay's 64 MiB lasts {cap:.1f} h")


if __name__ == "__main__":
    main()
