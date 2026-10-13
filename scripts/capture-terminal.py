#!/usr/bin/env python3
"""Capture what full-screen programs write to a terminal (T-221).

    python3 scripts/capture-terminal.py [OUT_DIR]

The tests of where a stream of terminal output may start
(crates/podssh-terminal/tests/grammar_boundary.rs) cut captured sessions at
each offset. less and top write their screens only to a terminal, so each
runs here in a real pty of 24 rows and 80 columns, with
TERM=xterm-256color, and gets a few keys; vi too, which the tests' first
capture ran with output to a file. Each program's bytes go unchanged to
OUT_DIR/NAME.bin (default: crates/podssh-terminal/tests/fixtures):
less.bin, top.bin and vi-pty.bin. A program that is missing gets an `env`
line and no file.

Linux only: Python's pty. In the build image, vi, less and top are
busybox's. Exit 0 when each program ran, 1 when one did not end within its
time, 2 when none could run.
"""

import fcntl
import os
import pty
import select
import shutil
import signal
import struct
import sys
import tempfile
import termios
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "crates", "podssh-terminal", "tests", "fixtures")
ROWS, COLS = 24, 80
# Each program ends within this time after its last key, or is killed.
END_WAIT = 10.0

# A file of UTF-8 text, longer than a screen.
TEXT = "".join(
    f"line {n}: Grüße aus der Kälte, naïve café € 日本語 \U0001f642\n"
    for n in range(1, 201)
)


def capture(argv, keys):
    """Run argv in a pty; send each (pause, bytes) of keys; return the
    output and whether the program ended by itself."""
    pid, fd = pty.fork()
    if pid == 0:
        env = dict(os.environ, TERM="xterm-256color", LANG="C.UTF-8", LC_ALL="C.UTF-8")
        try:
            os.execvpe(argv[0], argv, env)
        finally:
            os._exit(127)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    out = b""

    def read_for(seconds):
        nonlocal out
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select([fd], [], [], max(0.0, end - time.time()))
            if not ready:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return False
            if not chunk:
                return False
            out += chunk
        return True

    for pause, data in keys:
        if not read_for(pause):
            break
        os.write(fd, data)
    end = time.time() + END_WAIT
    ended = False
    while time.time() < end:
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done:
            ended = True
            break
        read_for(0.1)
    if not ended:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    # What the program wrote before it ended.
    read_for(0.2)
    os.close(fd)
    return out, ended


def main():
    if sys.platform != "linux":
        sys.exit("capture-terminal.py needs a pty of Linux")
    os.makedirs(OUT, exist_ok=True)
    work = tempfile.mkdtemp(prefix="capture-terminal-")
    text = os.path.join(work, "sample.txt")
    with open(text, "w", encoding="utf-8") as f:
        f.write(TEXT)
    runs = [
        ("less", ["less", text], [(1.0, b" "), (0.5, b"G"), (0.5, b"g"), (0.5, "/Kälte\r".encode()), (0.5, b"q")]),
        ("top", ["top", "-d", "1"], [(2.5, b"q")]),
        ("vi-pty", ["vi", text], [(1.0, b"G"), (0.5, b"1G"), (0.5, b"ihello \xc3\xa9\x1b"), (0.5, b":q!\r")]),
    ]
    ran = failed = 0
    for name, argv, keys in runs:
        if shutil.which(argv[0]) is None:
            print(f"env   {name}: no {argv[0]} here")
            continue
        out, ended = capture(argv, keys)
        ran += 1
        path = os.path.join(OUT, f"{name}.bin")
        with open(path, "wb") as f:
            f.write(out)
        if ended:
            print(f"ok    {name}: {len(out)} bytes to {path}")
        else:
            failed += 1
            print(f"FAIL  {name}: it did not end within {END_WAIT:.0f} s of its last key; {len(out)} bytes")
    shutil.rmtree(work, ignore_errors=True)
    if ran == 0:
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
