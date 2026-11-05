#!/usr/bin/env python3
"""osewa beside podssh and OpenSSH in scripts/feel-matrix.py --links netem
(T-660; Q99: a reference only, never a road, as osewa runs no public
server): osewa's own release binary serves on this host's loopback, and its
client measures what scripts/feel_openssh.py measures with ssh(1), in the
same JSON: cold connects of `osewa exec HOST -- true`, each from its
process's spawn to its exit, and a key's echo idle and beside a download on
the same connection, 40 keys 150 ms apart after 3 s of the download.

osewa's command line opens one connection for each process, and its server
holds a download to about a round trip and 40 ms of queue only while
someone types on that very connection (a session's key, or an exec's DATA
of at most 256 bytes). So the keys and the download are one exec: the far
end (this file, run with --far) echoes each byte of its stdin on its stdout
and, on the byte L, starts the download on its stderr. Its bytes are random,
as osewa's own bench reads /dev/urandom: osewa's server deflates what it
sends by default, which would make a download of zeros nothing on the link.

The server runs in the foreground for the run alone, each file of it and of
its client under the run's scratch directory (OSEWA_HOME, OSEWA_CONFIG_DIR,
OSEWA_RUN_DIR, XDG_STATE_HOME), and never updates itself: OSEWA_AUTO_UPDATE
is off, and a server with OSEWA_HOME never checks. `osewa login --no-install`
enrolls the run's device through an ssh of this harness, which runs the far
end's command on this host, as sshd would. Each wait has a limit.

    feel_osewa.py --far BYTES    the far end of the keys and the download
"""

import os
import shlex
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import feel_openssh as ref  # noqa: E402

# The roads of osewa, by the carrier that each forces (OSEWA_CARRIER).
CARRIERS = {"osewa-quic": "quic", "osewa-ws": "ws"}
# The host's name in the client's hosts.json, and the device's in the server's.
HOST = "feel"
TRIGGER = b"L"
# osewa's DATA and CHANNEL_DATA carry 32 KiB at most.
CHUNK = 32 * 1024
SETUP = 60
# The ssh of `osewa login`: the far end is this host, so its command runs
# here in the far end's environment, as sshd would run it there. `ssh -G`
# is never asked: login is given --addr.
SSH = """#!/bin/sh
# osewa login's ssh in scripts/feel-matrix.py (T-660): the far end's command, here.
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
[ "$#" -eq 3 ] || {{ echo "feel ssh: want -- TARGET COMMAND" >&2; exit 255; }}
cd {home} || exit 255
exec env {far} PATH={path} sh -c "$3"
"""


class Setup(Exception):
    """osewa's server or its enrollment could not start, and why."""


def private(path):
    """A directory that only this user reads: osewa refuses its files in
    any other."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def free_port():
    """A port of the loopback free for TCP and for UDP: osewa's server binds
    the one number twice, its WebSocket and its QUIC."""
    for _ in range(20):
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise Setup("no port of the loopback free for TCP and UDP both")


def listening(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


class Osewa:
    """osewa's server on 127.0.0.1:PORT, TCP and UDP, and the run's device
    enrolled in it; `spawn` starts a child that the bench stops."""

    def __init__(self, program, work, spawn):
        self.program, self.spawn = program, spawn
        root = private(work / "osewa")
        self.home, self.bin = private(root / "home"), private(root / "bin")
        self.far = {"OSEWA_HOME": str(self.home), "OSEWA_CONFIG_DIR": str(private(root / "server")),
                    "OSEWA_RUN_DIR": str(private(root / "run")), "XDG_STATE_HOME": str(private(root / "state")),
                    "OSEWA_AUTO_UPDATE": "off"}
        self.client = {"OSEWA_CONFIG_DIR": str(private(root / "client")), "OSEWA_AUTO_UPDATE": "off"}
        self.port, self.version = None, None

    @staticmethod
    def env(base, more):
        """`base` with none of its own OSEWA_ variables, and `more`."""
        env = {k: v for k, v in base.items() if not k.startswith("OSEWA_")}
        env.update(more)
        return env

    def start(self, base, log):
        """The server for the run, then the device enrolled; Setup when
        either fails. `log` takes the server's lines and login's."""
        try:
            shown = subprocess.run([self.program, "version"], stdin=subprocess.DEVNULL, capture_output=True,
                                   text=True, env=self.env(base, self.client), timeout=SETUP, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise Setup(f"osewa version: {e}") from e
        self.version = shown.stdout.strip()
        if shown.returncode != 0 or not self.version.startswith("osewa "):
            raise Setup(f"{self.program}: not osewa (exit {shown.returncode})")
        port = self.port = free_port()
        server = self.spawn([self.program, "server", "--listen", f"127.0.0.1:{port}"], log, self.env(base, self.far))
        deadline = time.monotonic() + SETUP
        while not listening(port):
            if server.poll() is not None:
                raise Setup(f"osewa server: exit {server.returncode} (its log: {log.name})")
            if time.monotonic() > deadline:
                raise Setup(f"osewa server: not listening within {SETUP} s")
            time.sleep(0.1)
        self.enroll(base, log)

    def enroll(self, base, log):
        """`osewa login --no-install`: the device's key into the server's
        devices, and the host into the client's hosts.json, after a dial."""
        far = " ".join(f"{k}={shlex.quote(v)}" for k, v in self.far.items())
        path = shlex.quote(f"{self.bin}:/usr/local/bin:/usr/bin:/bin")
        ssh = self.bin / "ssh"
        ssh.write_text(SSH.format(home=shlex.quote(str(self.home)), far=far, path=path), encoding="utf-8")
        ssh.chmod(0o755)
        (self.bin / "osewa").symlink_to(self.program)
        env = self.env(base, {**self.client, "PATH": f"{self.bin}:{base.get('PATH', '/usr/bin:/bin')}"})
        argv = [self.program, "login", "--no-install", "--name", HOST, "--device", HOST,
                "--addr", f"127.0.0.1:{self.port}", f"feel@{HOST}"]
        try:
            done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env,
                                  timeout=SETUP, check=False)
        except subprocess.TimeoutExpired as e:
            raise Setup(f"osewa login: no end within {SETUP} s") from e
        with open(log, "a", encoding="utf-8") as f:
            f.write(f"osewa login: exit {done.returncode}\n{done.stdout}{done.stderr}")
        if done.returncode != 0:
            why = (done.stderr.strip().splitlines() or [""])[-1]
            raise Setup(f"osewa login: exit {done.returncode}: {why}")

    def measure(self, road, base, runs):
        """The document of one cell, in feel_openssh's shape: `exit` 0, or
        1 with the error of the first measure that failed."""
        env = self.env(base, {**self.client, "OSEWA_CARRIER": CARRIERS[road]})
        far = {"destination": f"{HOST} (127.0.0.1:{self.port}, {CARRIERS[road]})", "connect": None,
               "under_load": None, "error": None}
        doc = {"schema": 1, "client": road, "osewa": self.version, "destination": far, "exit": 0}
        try:
            samples = self.connects(env, runs)
            far["connect"] = {**ref.summary(samples), "runs": runs, "command": "true", "samples_ms": samples}
            far["under_load"] = self.under_load(env)
        except (ref.Failed, OSError, subprocess.TimeoutExpired) as e:
            far["error"], doc["exit"] = str(e), 1
        return doc

    def connects(self, env, runs):
        """`runs` processes of `osewa exec HOST -- true`, each from its spawn
        to its exit, as feel_openssh times ssh's."""
        samples = []
        for run in range(1, runs + 1):
            started = time.monotonic()
            try:
                done = subprocess.run([self.program, "exec", HOST, "--", "true"], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
                                      timeout=ref.STEP, check=False)
            except subprocess.TimeoutExpired as e:
                raise ref.Failed(f"connect run {run} of {runs}: no exit within {ref.STEP:.0f} s") from e
            if done.returncode != 0:
                why = done.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
                raise ref.Failed(f"connect run {run} of {runs}: osewa exit {done.returncode}: {why[0]}")
            samples.append(ref.ms(time.monotonic() - started))
        return samples

    def under_load(self, env):
        """The keys idle, then beside the download, on one exec of the far
        end: feel_openssh's under_load, with the download on stderr."""
        argv = [self.program, "exec", HOST, "--", sys.executable, "-I", str(Path(__file__).resolve()),
                "--far", str(ref.LOAD)]
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, bufsize=0)
        try:
            download = Download(proc)
            ref.typed(proc, 1, time.monotonic())  # not counted: the first waits for the far end to start
            idle = ref.typed(proc, ref.KEYS, time.monotonic())
            download.begin()
            proc.stdin.write(TRIGGER)
            proc.stdin.flush()
            started = time.monotonic()
            time.sleep(max(0.0, started + ref.WARMUP - time.monotonic()))
            loaded, typing = [], (0, 0.0)
            if download.ended is None:
                before, start = download.got, time.monotonic()
                loaded = ref.typed(proc, ref.KEYS, started)
                stop = min(time.monotonic(), download.ended or float("inf"))
                typing = (download.got - before, stop - start)
            ended = None if download.ended is None else ref.ms(download.ended - started)
            for key in loaded:
                key["beside"] = ended is None or key["sent_ms"] + key["echo_ms"] <= ended
            beside = [k["echo_ms"] for k in loaded if k["beside"]]
            return {
                "keys": ref.KEYS, "gap_ms": int(ref.GAP * 1000), "warmup_ms": int(ref.WARMUP * 1000),
                "idle": {**ref.summary([k["echo_ms"] for k in idle]), "samples": idle},
                "loaded": {**ref.summary(beside), "samples": loaded},
                "load": {"command": f"{ref.LOAD} random bytes on the exec's stderr", "bytes": download.got,
                         "typing_bytes": typing[0], "typing_seconds": typing[1], "ended_ms": ended},
            }
        finally:
            # Its stdin's end ends the far end, and so the exec.
            try:
                proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(ref.STEP)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(ref.STEP)
                except subprocess.TimeoutExpired:
                    proc.kill()


class Download(ref.Download):
    """The far end's download, read from osewa's stderr from the exec's
    start (its own lines go there too, and a pipe must never fill); its
    bytes since the trigger, and when the last of them came, as the far
    end's stderr stays open after them."""

    def __init__(self, proc):
        self.base = None
        super().__init__(proc)

    def begin(self):
        self.base = self.got

    def read(self):
        fd = self.proc.stderr.fileno()
        try:
            while data := os.read(fd, 65536):
                self.got += len(data)
                if self.base is not None and self.ended is None and self.got - self.base >= ref.LOAD:
                    self.ended = time.monotonic()
        except OSError:
            pass
        if self.base is not None and self.ended is None:
            self.ended = time.monotonic()


def far(total):
    """The far end: each byte of stdin back on stdout as it comes, but
    TRIGGER, which starts `total` random bytes on stderr beside the echo.
    Its stdin's end is its own."""
    begun = threading.Event()

    def load():
        left = total
        try:
            while left > 0:
                left -= os.write(2, os.urandom(min(CHUNK, left)))
        except OSError:
            pass

    while True:
        try:
            data = os.read(0, 4096)
        except OSError:
            break
        if not data:
            break
        if TRIGGER in data and not begun.is_set():
            begun.set()
            threading.Thread(target=load, daemon=True).start()
        echo = data.replace(TRIGGER, b"")
        if echo:
            os.write(1, echo)
    os._exit(0)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--far" and sys.argv[2].isdigit():
        far(int(sys.argv[2]))
    else:
        sys.exit("usage: feel_osewa.py --far BYTES")
