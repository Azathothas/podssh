#!/usr/bin/env python3
"""podssh in a real local pty, against the interop OpenSSH server on port 2201.

Checks raw mode, the window size and a resize, Ctrl-C, full-screen programs
(vi, less, top), the ~. escape, the exit status, and that the local terminal
is restored afterwards. Prints one `ok` or `FAIL` line per check; exits 1 if
any check failed. Called by scripts/interop.sh with: PODSSH KNOWN_HOSTS KEY.
"""

import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time

BIN, KNOWN_HOSTS, KEY = sys.argv[1:4]
SSH = (
    f"'{BIN}' ssh --direct -p 2201 -o UserKnownHostsFile='{KNOWN_HOSTS}' "
    f"-o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes -i '{KEY}' -t podtest@127.0.0.1"
)
# After podssh exits, the local shell reports the terminal's settings and the
# exit status, so a terminal left in raw mode is visible.
WRAPPER = f"{SSH}; rc=$?; echo; echo STTY: $(stty -a | tr '\\n' ' '); echo RC=$rc"
fails = 0


def check(name, condition, detail=b""):
    global fails
    if condition:
        print(f"ok    {name}")
    else:
        fails += 1
        print(f"FAIL  {name}")
        tail = detail[-800:].decode("utf-8", "replace")
        for line in tail.splitlines():
            print(f"      | {line!r}")
    sys.stdout.flush()


class Terminal:
    def __init__(self, rows, cols):
        pid, fd = pty.fork()
        if pid == 0:
            env = dict(os.environ, TERM="xterm-256color")
            os.execve("/bin/sh", ["/bin/sh", "-c", WRAPPER], env)
        self.pid, self.fd, self.buf = pid, fd, b""
        self.resize(rows, cols)

    def resize(self, rows, cols):
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def send(self, data, pause=0.0):
        os.write(self.fd, data)
        if pause:
            time.sleep(pause)

    def _read(self, timeout):
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return True
        try:
            chunk = os.read(self.fd, 65536)
        except OSError:
            return False
        if not chunk:
            return False
        self.buf += chunk
        return True

    def expect(self, needle, timeout=15):
        end = time.time() + timeout
        while needle not in self.buf and time.time() < end:
            if not self._read(min(0.5, max(0.0, end - time.time()))):
                break
        return needle in self.buf

    def finish(self, timeout=15):
        """Wait for the wrapper to exit; return the status podssh exited with."""
        self.expect(b"RC=", timeout)
        self.expect(b"\n", 2)
        end = time.time() + 5
        while time.time() < end:
            pid, _ = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                break
            self._read(0.1)
        else:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        text = self.buf.decode("utf-8", "replace")
        if "RC=" not in text:
            return None
        return int(text.rsplit("RC=", 1)[1].split()[0])

    def restored(self):
        text = self.buf.decode("utf-8", "replace")
        if "STTY:" not in text:
            return False
        stty = " " + text.rsplit("STTY:", 1)[1].split("RC=")[0] + " "
        return " icanon " in stty and " echo " in stty and " -icanon " not in stty


def marker(t, word, a, b):
    """Run `echo WORD-$((a+b))` and wait for the computed value, which the
    echo of the typed line cannot contain."""
    t.send(f"echo {word}-$(({a}+{b}))\r".encode())
    return t.expect(f"{word}-{a + b}".encode())


t = Terminal(40, 100)
check("a shell over a local pty", marker(t, "READY", 1, 2), t.buf)
t.send(b"stty size\r")
check("the window size is sent (40x100)", t.expect(b"40 100"), t.buf)
t.resize(50, 120)
time.sleep(1)
t.send(b"stty size\r")
check("a resize reaches the server (50x120)", t.expect(b"50 120"), t.buf)
t.send(b"sleep 30\r", 1.5)
start = time.time()
t.send(b"\x03")
check("Ctrl-C interrupts the remote command", marker(t, "INT", 3, 4) and time.time() - start < 10, t.buf)
t.send(b"rm -f /tmp/podssh-vi\r", 0.5)
t.send(b"vi /tmp/podssh-vi\r", 1.5)
t.send(b"ihello from vi\x1b", 0.5)
t.send(b":wq\r", 1.0)
t.send(b"cat /tmp/podssh-vi\r")
check("vi edits and saves a file", t.expect(b"hello from vi") and marker(t, "VI", 5, 5), t.buf)
t.send(b"seq 1 500 | less\r", 1.5)
t.send(b"G", 0.5)
t.send(b"q", 0.5)
check("less pages and quits", marker(t, "LESS", 6, 6), t.buf)
t.send(b"top\r", 2.0)
t.send(b"q", 0.5)
check("top draws and quits", marker(t, "TOP", 7, 7), t.buf)
t.send(b"exit 7\r")
status = t.finish()
check("the exit status comes back (7)", status == 7, t.buf)
check("the local terminal is restored", t.restored(), t.buf)

t = Terminal(24, 80)
check("a second session", marker(t, "AGAIN", 2, 2), t.buf)
t.send(b"\r~.")
status = t.finish()
check("~. disconnects (exit 255)", status == 255, t.buf)
check("the terminal is restored after ~.", t.restored(), t.buf)

sys.exit(1 if fails else 0)
