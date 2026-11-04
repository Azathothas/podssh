#!/usr/bin/env python3
"""OpenSSH's client as the reference of scripts/feel-matrix.py (T-660): the
measures of `podssh ping --under-load --connect-runs N`, made with ssh(1)
through the same shaped proxy, in the same JSON. And, run as

    feel_openssh.py --connect-via PROXY_HOST:PORT HOST PORT

the CONNECT of its ProxyCommand, as OpenSSH reads no HTTPS_PROXY.

Each cold connect is `ssh ... true`, from its process's spawn to its exit, as
osewa's `vs` times them. The keys go through `cat` on a ControlMaster, and the
download is `head -c` on the same master beside them: one TCP connection, as
podssh's one SSH connection. Each wait has a limit.
"""

import math
import os
import select
import socket
import subprocess
import sys
import threading
import time

# As podssh ping: the keys, their gap, the warm-up, the download and the
# limit of each wait (crates/podssh-cli/src/ping/keys.rs and load.rs).
KEYS, GAP, WARMUP, STEP = 40, 0.150, 3.0, 60.0
LOAD = 60 * 1024 * 1024
LOAD_COMMAND = f"head -c {LOAD} /dev/zero"


class Failed(Exception):
    """A measure with no figure, and why."""


def ms(seconds):
    return round(seconds * 1000, 3)


def summary(samples):
    """min, p50, p95 and max by the nearest rank, as podssh ping ranks them;
    {} for none."""
    if not samples:
        return {}
    ranked = sorted(samples)

    def rank(p):
        return ranked[min(max(math.ceil(p * len(ranked)), 1), len(ranked)) - 1]

    return {"min_ms": ranked[0], "p50_ms": rank(0.50), "p95_ms": rank(0.95), "max_ms": ranked[-1]}


def connect_via(proxy, host, port):
    """The ProxyCommand: CONNECT through PROXY, then stdin and stdout through
    the tunnel until either end closes."""
    proxy_host, proxy_port = proxy.rsplit(":", 1)
    tunnel = socket.create_connection((proxy_host, int(proxy_port)), timeout=10)
    tunnel.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = tunnel.recv(1)
        if not chunk:
            sys.exit("feel_openssh: the proxy closed before its answer")
        head += chunk
    if head.split(b" ", 2)[1:2] != [b"200"]:
        sys.exit(f"feel_openssh: the proxy answered {head.splitlines()[0]!r}")
    tunnel.settimeout(None)

    def up():
        try:
            while data := os.read(0, 65536):
                tunnel.sendall(data)
        except OSError:
            pass
        try:
            tunnel.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    threading.Thread(target=up, daemon=True).start()
    out = sys.stdout.buffer
    try:
        while data := tunnel.recv(65536):
            out.write(data)
            out.flush()
    except OSError:
        pass


def connects(base, dest, runs):
    """`runs` processes of `ssh DEST true`, each from its spawn to its exit."""
    samples = []
    for run in range(1, runs + 1):
        started = time.monotonic()
        try:
            done = subprocess.run(base + [dest, "true"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE, timeout=STEP, check=False)
        except subprocess.TimeoutExpired as e:
            raise Failed(f"connect run {run} of {runs}: no exit within {STEP:.0f} s") from e
        if done.returncode != 0:
            why = done.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            raise Failed(f"connect run {run} of {runs}: ssh exit {done.returncode}: {why[0]}")
        samples.append(ms(time.monotonic() - started))
    return samples


def typed(cat, count, zero):
    """`count` keys into `cat`, GAP apart, each sent whether or not the one
    before came back; the n-th byte back answers the n-th key."""
    sent, keys = [], []

    def typist():
        first = time.monotonic()
        try:
            for i in range(count):
                pause = first + i * GAP - time.monotonic()
                if pause > 0:
                    time.sleep(pause)
                # Its time is taken before it goes, so its echo always finds it.
                sent.append(time.monotonic())
                cat.stdin.write(b"k")
                cat.stdin.flush()
        except (OSError, ValueError):
            pass

    thread = threading.Thread(target=typist, daemon=True)
    thread.start()
    fd = cat.stdout.fileno()
    while len(keys) < count:
        ready, _, _ = select.select([fd], [], [], STEP)
        if not ready:
            raise Failed(f"cat: no echo within {STEP:.0f} s")
        data = os.read(fd, 4096)
        if not data:
            raise Failed("cat: closed")
        now = time.monotonic()
        for _ in data:
            if len(keys) < len(sent):
                at = sent[len(keys)]
                keys.append({"sent_ms": ms(at - zero), "echo_ms": ms(now - at)})
    thread.join(STEP)
    return keys


class Download:
    """The download beside the keys, read by a thread of its own: its bytes
    so far, and when it ended."""

    def __init__(self, proc):
        self.proc, self.got, self.ended = proc, 0, None
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def read(self):
        fd = self.proc.stdout.fileno()
        try:
            while data := os.read(fd, 65536):
                self.got += len(data)
        except OSError:
            pass
        self.ended = time.monotonic()


def under_load(mux, dest):
    """The keys idle, then beside the download, on the master of `mux`."""
    cat = subprocess.Popen(mux + [dest, "cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, bufsize=0)
    load = None
    try:
        typed(cat, 1, time.monotonic())  # not counted: the first waits for cat to start
        idle = typed(cat, KEYS, time.monotonic())
        load = subprocess.Popen(mux + [dest, LOAD_COMMAND], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        started = time.monotonic()
        download = Download(load)
        time.sleep(max(0.0, started + WARMUP - time.monotonic()))
        loaded, typing = [], (0, 0.0)
        if download.ended is None:
            before, start = download.got, time.monotonic()
            loaded = typed(cat, KEYS, started)
            stop = min(time.monotonic(), download.ended or float("inf"))
            typing = (download.got - before, stop - start)
        ended = None if download.ended is None else ms(download.ended - started)
        for key in loaded:
            key["beside"] = ended is None or key["sent_ms"] + key["echo_ms"] <= ended
        beside = [k["echo_ms"] for k in loaded if k["beside"]]
        return {
            "keys": KEYS, "gap_ms": int(GAP * 1000), "warmup_ms": int(WARMUP * 1000),
            "idle": {**summary([k["echo_ms"] for k in idle]), "samples": idle},
            "loaded": {**summary(beside), "samples": loaded},
            "load": {"command": LOAD_COMMAND, "bytes": download.got, "typing_bytes": typing[0],
                     "typing_seconds": typing[1], "ended_ms": ended},
        }
    finally:
        for proc in (load, cat):
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(STEP)
                except subprocess.TimeoutExpired:
                    proc.kill()


def measure(base, dest, runs, control):
    """The document of one cell: the connects, then the keys on a master at
    the socket `control`; `exit` 0, or 1 with the error of the first that
    failed."""
    far = {"destination": dest, "connect": None, "under_load": None, "error": None}
    doc = {"schema": 1, "client": "openssh", "destination": far, "exit": 0}
    master = None
    try:
        samples = connects(base, dest, runs)
        far["connect"] = {**summary(samples), "runs": runs, "command": "true", "samples_ms": samples}
        mux = base + ["-S", control, "-T"]
        master = subprocess.Popen(base + ["-M", "-S", control, "-N", "-o", "ControlPersist=no", dest],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + STEP
        while subprocess.run(mux + ["-O", "check", dest], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=STEP, check=False).returncode != 0:
            if master.poll() is not None or time.monotonic() > deadline:
                raise Failed(f"the ControlMaster did not start (exit {master.poll()})")
            time.sleep(0.1)
        far["under_load"] = under_load(mux, dest)
    except (Failed, OSError, subprocess.TimeoutExpired) as e:
        far["error"], doc["exit"] = str(e), 1
    finally:
        if master is not None:
            master.terminate()
            try:
                master.wait(STEP)
            except subprocess.TimeoutExpired:
                master.kill()
    return doc


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--connect-via":
        connect_via(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit("usage: feel_openssh.py --connect-via PROXY_HOST:PORT HOST PORT")
