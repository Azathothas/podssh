#!/usr/bin/env python3
"""Whether a terminal keeps a stack of window titles (XTWINOPS 22 and 23),
where `podssh ssh` shows the notice of a silent node (T-302). Run it in the
terminal to measure: on Linux or macOS, or under WSL in Windows Terminal or
in the Windows console.

    python3 scripts/title-stack.py

It sets the title A, saves it on the stack (CSI 22;2t), sets the title B,
takes the saved one back (CSI 23;2t), then asks the terminal for its title
(CSI 21t) and reads the answer for 1 s, in raw mode. Many terminals do not
answer that question (xterm only with allowWindowOps); the script then asks
the person to read the window's title. Exit 0: a stack; 1: no stack; 2: not
told, or not run in a terminal.
"""

import os
import select
import sys
import time

SETUP = "\x1b]2;podssh-title-A\x07\x1b[22;2t\x1b]2;podssh-title-B\x07\x1b[23;2t"


def answer_of(fd):
    """The terminal's answer to CSI 21t within 1 s, in raw mode."""
    import termios
    import tty

    saved = termios.tcgetattr(fd)
    got = b""
    try:
        tty.setraw(fd)
        sys.stdout.write("\x1b[21t")
        sys.stdout.flush()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            got += os.read(fd, 256)
            if got.endswith(b"\x1b\\") or got.endswith(b"\x07"):
                break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    return got


def main():
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("title-stack: run it in the terminal to measure, not in a pipe", file=sys.stderr)
        return 2
    try:
        import termios  # noqa: F401
    except ImportError:
        print("title-stack: this Python has no termios: run it under WSL, in the terminal", file=sys.stderr)
        return 2
    sys.stdout.write(SETUP)
    sys.stdout.flush()
    got = answer_of(sys.stdin.fileno())
    names = [f"{n}={os.environ[n]}" for n in ("TERM", "TERM_PROGRAM", "XTERM_VERSION", "VTE_VERSION",
                                              "WT_SESSION") if os.environ.get(n)]
    print(f"title-stack: {' '.join(names) or 'no variable of a terminal'}")
    if b"podssh-title-A" in got:
        print("title-stack: a stack: the saved title came back")
        return 0
    if b"podssh-title-B" in got:
        print("title-stack: no stack: the title stayed podssh-title-B")
        return 1
    print("title-stack: the terminal does not tell its title. Read the window's title now:")
    print("  podssh-title-A: a stack; podssh-title-B: no stack (then set PODSSH_TITLE_STACK=no)")
    return 2


if __name__ == "__main__":
    sys.exit(main())
