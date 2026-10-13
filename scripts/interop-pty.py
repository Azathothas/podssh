#!/usr/bin/env python3
"""podssh in a real local pty, against the interop OpenSSH server on port 2201.

Checks raw mode, the window size and a resize, Ctrl-C, full-screen programs
(vi, less, top), the ~. and ~# escapes, ~C with -R and -KR, -L and -KL
(T-291), the exit status, and that the local terminal is restored
afterwards; the host picker of a run with no destination (T-188); then
ZMODEM with sz and rz of lrzsz (T-148), or `env` lines when the host has no
lrzsz.
Prints one `ok` or `FAIL` line per check; exits 1 if any check failed.
Called by scripts/interop.sh with: PODSSH KNOWN_HOSTS KEY.
"""

import fcntl
import hashlib
import os
import pty
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import termios
import time

BIN, KNOWN_HOSTS, KEY = sys.argv[1:4]
SSH = (
    f"'{BIN}' ssh --direct -p 2201 -o UserKnownHostsFile='{KNOWN_HOSTS}' "
    f"-o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes -i '{KEY}' -t podtest@127.0.0.1"
)


# After podssh exits, the local shell reports the terminal's settings and the
# exit status, so a terminal left in raw mode is visible. `extra` goes before
# the host: more flags of podssh ssh.
def wrapper(extra=""):
    ssh = SSH.replace(" -t podtest@", f" {extra} -t podtest@") if extra else SSH
    return f"{ssh}; rc=$?; echo; echo STTY: $(stty -a | tr '\\n' ' '); echo RC=$rc"


fails = 0


# check(ID, TEXT, ...): `ok ID TEXT` or `FAIL ID TEXT`, as scripts/interop-lib.sh
# prints them; the ids are in scripts/interop-baseline.txt (T-199).
def check(name, text, condition, detail=b""):
    global fails
    if condition:
        print(f"ok    {name} {text}")
    else:
        fails += 1
        print(f"FAIL  {name} {text}")
        tail = detail[-800:].decode("utf-8", "replace")
        for line in tail.splitlines():
            print(f"      | {line!r}")
    sys.stdout.flush()


# unmet(ID, TEXT): a precondition of the host is missing, as interop-lib.sh's
# unmet prints it; the baseline allows `env` for that ID.
def unmet(name, text):
    print(f"env   {name} {text}")
    sys.stdout.flush()


class Terminal:
    def __init__(self, rows, cols, extra="", command=None):
        pid, fd = pty.fork()
        if pid == 0:
            env = dict(os.environ, TERM="xterm-256color")
            os.execve("/bin/sh", ["/bin/sh", "-c", command or wrapper(extra)], env)
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

    def expect(self, needle, timeout=15, since=0):
        """Wait for `needle` in what came after byte `since` of the output."""
        end = time.time() + timeout
        while needle not in self.buf[since:] and time.time() < end:
            if not self._read(min(0.5, max(0.0, end - time.time()))):
                break
        return needle in self.buf[since:]

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
check("pty.shell", "a shell over a local pty", marker(t, "READY", 1, 2), t.buf)
t.send(b"stty size\r")
check("pty.size", "the window size is sent (40x100)", t.expect(b"40 100"), t.buf)
t.resize(50, 120)
time.sleep(1)
t.send(b"stty size\r")
check("pty.resize", "a resize reaches the server (50x120)", t.expect(b"50 120"), t.buf)
t.send(b"sleep 30\r", 1.5)
start = time.time()
t.send(b"\x03")
check("pty.ctrl_c", "Ctrl-C interrupts the remote command", marker(t, "INT", 3, 4) and time.time() - start < 10, t.buf)
t.send(b"rm -f /tmp/podssh-vi\r", 0.5)
t.send(b"vi /tmp/podssh-vi\r", 1.5)
t.send(b"ihello from vi\x1b", 0.5)
t.send(b":wq\r", 1.0)
t.send(b"cat /tmp/podssh-vi\r")
check("pty.vi", "vi edits and saves a file", t.expect(b"hello from vi") and marker(t, "VI", 5, 5), t.buf)
t.send(b"seq 1 500 | less\r", 1.5)
t.send(b"G", 0.5)
t.send(b"q", 0.5)
check("pty.less", "less pages and quits", marker(t, "LESS", 6, 6), t.buf)
t.send(b"top\r", 2.0)
t.send(b"q", 0.5)
check("pty.top", "top draws and quits", marker(t, "TOP", 7, 7), t.buf)
t.send(b"exit 7\r")
status = t.finish()
check("pty.exit_status", "the exit status comes back (7)", status == 7, t.buf)
check("pty.restore.shell", "the local terminal is restored", t.restored(), t.buf)

t = Terminal(24, 80)
check("pty.second", "a second session", marker(t, "AGAIN", 2, 2), t.buf)
t.send(b"\r~.")
status = t.finish()
check("pty.escape_disconnect", "~. disconnects (exit 255)", status == 255, t.buf)
check("pty.restore.escape", "the terminal is restored after ~.", t.restored(), t.buf)

# ~# lists the forwards of the session, with their counts (T-041).
t = Terminal(24, 80, "-R 127.0.0.1:2290:127.0.0.1:2201")
ready = marker(t, "FWD", 4, 4)
t.send(b"\r~#")
listed = t.expect(b"-R 127.0.0.1:2290:127.0.0.1:2201: 0 connections (0 open, 0 failed)")
check("pty.forwards", "~# lists the forwards of the session", ready and listed, t.buf)
t.send(b"\rexit\r")
t.finish()


def banner(port):
    """What 127.0.0.1:PORT says first, or None when it refuses."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.settimeout(5)
            return s.recv(64)
    except OSError:
        return None


# ~C adds a -R to the running session, and -KR stops it (T-291): port 2290,
# the one that PermitListen allows on 2201, reads the banner of 2201's sshd
# through the forward, then refuses once the server let the forward go.
time.sleep(1)  # the session of ~# above may still hold 2290 for a moment
t = Terminal(24, 80)
ready = marker(t, "CMDLINE", 5, 6)
since = len(t.buf)
t.send(b"\r~C")
asked = t.expect(b"ssh> ", since=since)
t.send(b"-R 127.0.0.1:2290:127.0.0.1:2201\r")
forwarding = t.expect(b"Forwarding port.", since=since)
up = banner(2290)
since = len(t.buf)
t.send(b"\r~C")
t.expect(b"ssh> ", since=since)
t.send(b"-KR 127.0.0.1:2290\r")
cancelled = t.expect(b"Canceled forwarding", since=since)
time.sleep(0.5)
down = banner(2290)
check("pty.command_line", "~C -R makes port 2290 answer, and -KR makes it refuse",
      ready and asked and forwarding and bool(up) and up.startswith(b"SSH-") and cancelled and down is None,
      t.buf + f"\nup={up!r} down={down!r}".encode())


def free_port():
    """A port of 127.0.0.1 that nothing listens on now."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ~C -L listens here in the same session, and -KL closes the listener
# (T-291): a free local port reads the banner of 2201's sshd through the
# session, then refuses.
lport = free_port()
since = len(t.buf)
t.send(b"\r~C")
asked = t.expect(b"ssh> ", since=since)
t.send(f"-L 127.0.0.1:{lport}:127.0.0.1:2201\r".encode())
forwarding = t.expect(b"Forwarding port.", since=since)
up = banner(lport)
since = len(t.buf)
t.send(b"\r~C")
t.expect(b"ssh> ", since=since)
t.send(f"-KL {lport}\r".encode())
cancelled = t.expect(b"Canceled forwarding", since=since)
time.sleep(0.5)
down = banner(lport)
check("pty.command_line.local", "~C -L makes a local port answer, and -KL makes it refuse",
      asked and forwarding and bool(up) and up.startswith(b"SSH-") and cancelled and down is None,
      t.buf + f"\nport={lport} up={up!r} down={down!r}".encode())
t.send(b"\rexit\r")
t.finish()


# The host picker (T-188): no destination, stdin and stdout on the pty, and
# a file of -F with three Host names; 2 logs in to the second, whose
# RemoteCommand prints a marker. With stdout alone a terminal, nothing is
# asked, and the exit is 64.
PICK = "/tmp/podssh-picker.conf"
with open(PICK, "w") as f:
    f.write("Host one\n    HostName 127.0.0.1\n    Port 2299\n"
            "Host two\n    HostName 127.0.0.1\n    Port 2201\n    User podtest\n"
            "    RemoteCommand echo PICKED-$((20+22))\n"
            "Host three *.example.org\n    HostName 127.0.0.1\n    Port 2298\n")
PICKER = (f"'{BIN}' ssh --direct -F {PICK} -o UserKnownHostsFile='{KNOWN_HOSTS}' -o IdentityAgent=none "
          f"-o IdentitiesOnly=yes -o BatchMode=yes -i '{KEY}'")
t = Terminal(24, 80, command=f"{PICKER}; echo RC=$?")
listed = t.expect(b"3  three") and t.expect(b"Host to log in to")
t.send(b"2\r")
status = t.finish()
check("pty.picker.choose", "no destination on a terminal: the Host names, and 2 logs in to two (exit 0)",
      listed and b"PICKED-42" in t.buf and status == 0, t.buf)
t = Terminal(24, 80, command=f"{PICKER} </dev/null; echo RC=$?")
status = t.finish()
check("pty.picker.stdout_alone", "stdin not a terminal: no list, no question, and exit 64",
      status == 64 and b"Host to log in to" not in t.buf and b"missing destination" in t.buf, t.buf)

# ZMODEM (T-148): sz and rz of lrzsz on the server, which is this host.
# Its names are sz and rz, or lsz and lrz where lrzsz keeps its own.
ZLOCAL = "/tmp/podssh-zmodem-here"
ZFAR = "/tmp/podssh-zmodem-far"
ZMODEM_IDS = [
    "pty.zmodem.receive",
    "pty.zmodem.temp",
    "pty.zmodem.refuse",
    "pty.zmodem.send",
    "pty.zmodem.escape",
    "pty.zmodem.no_terminal",
]
SZ = next((n for n in ("sz", "lsz") if shutil.which(n)), None)
RZ = next((n for n in ("rz", "lrz") if shutil.which(n)), None)


def digest(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def zmodem():
    for d in (ZLOCAL, ZFAR):
        shutil.rmtree(d, ignore_errors=True)
    for d in ("in", "pipe"):
        os.makedirs(f"{ZLOCAL}/{d}")
    os.makedirs(ZFAR)
    os.chmod(ZFAR, 0o777)
    with open(f"{ZFAR}/down.bin", "wb") as f:
        f.write(os.urandom(300_000) + bytes(range(256)) * 4)
    os.chmod(f"{ZFAR}/down.bin", 0o644)
    with open(f"{ZLOCAL}/up.bin", "wb") as f:
        f.write(bytes(range(256)) * 1000 + os.urandom(44_444))

    # sz: the question, the directory typed, and the file with its digest.
    t = Terminal(24, 120)
    ready = marker(t, "ZM", 1, 1)
    mark = len(t.buf)
    t.send(f"cd {ZFAR} && {SZ} down.bin\r".encode())
    asked = t.expect(b"Receive into", since=mark)
    t.send(f"{ZLOCAL}/in\r".encode())
    came = t.expect(b"received ", 60, since=mark)
    back = marker(t, "ZMR", 2, 3)
    same = digest(f"{ZLOCAL}/in/down.bin") == digest(f"{ZFAR}/down.bin")
    check("pty.zmodem.receive", "sz on the server: a question, then the file with an equal digest",
          ready and asked and came and back and same, t.buf)
    parts = [n for n in os.listdir(f"{ZLOCAL}/in") if n.endswith(".part")]
    check("pty.zmodem.temp", "no temporary file is left after the rename", came and not parts, t.buf)

    # Ctrl-C at the question cancels sz, and the shell comes back.
    mark = len(t.buf)
    t.send(f"{SZ} down.bin\r".encode())
    asked = t.expect(b"Receive into", since=mark)
    t.send(b"\x03", 2.0)
    t.send(b"\r")
    back = marker(t, "ZMN", 4, 4)
    check("pty.zmodem.refuse", "Ctrl-C at the question cancels sz, and the shell comes back", asked and back, t.buf)

    # rz: the question, the local file typed, and its digest on the server.
    mark = len(t.buf)
    t.send(f"{RZ}\r".encode())
    asked = t.expect(b"Send which file?", since=mark)
    t.send(f"{ZLOCAL}/up.bin\r".encode())
    sent = t.expect(b"sent up.bin", 60, since=mark)
    back = marker(t, "ZMS", 3, 3)
    same = digest(f"{ZFAR}/up.bin") == digest(f"{ZLOCAL}/up.bin")
    check("pty.zmodem.send", "rz on the server: a question, then the file with an equal digest",
          asked and sent and back and same, t.buf)

    # ~Z asks for the file first, then types rz.
    os.remove(f"{ZFAR}/up.bin")
    mark = len(t.buf)
    t.send(b"\r~Z")
    asked = t.expect(b"send which file by ZMODEM", since=mark)
    t.send(f"{ZLOCAL}/up.bin\r".encode())
    sent = t.expect(b"sent up.bin", 60, since=mark)
    back = marker(t, "ZME", 5, 5)
    same = digest(f"{ZFAR}/up.bin") == digest(f"{ZLOCAL}/up.bin")
    check("pty.zmodem.escape", "~Z asks for a file, types rz, and the file arrives",
          asked and sent and back and same, t.buf)
    t.send(b"exit\r")
    t.finish()

    # With no terminal (pipes, -tt forces the pty): sz's bytes reach stdout,
    # and nothing is written here. The pipe of stdin stays open, so that sz
    # waits as it would for an answer.
    cmd = [BIN, "ssh", "--direct", "-p", "2201", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
           "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-i", KEY,
           "-tt", "podtest@127.0.0.1", f"cd {ZFAR} && timeout 20 {SZ} down.bin"]
    p = subprocess.Popen(cmd, cwd=f"{ZLOCAL}/pipe", stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    out = b""
    end = time.time() + 30
    while b"**\x18B00" not in out and time.time() < end:
        ready, _, _ = select.select([p.stdout.fileno()], [], [], 0.5)
        if ready:
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk:
                break
            out += chunk
    # A receiver that answered would have the file, or its temporary name, by now.
    time.sleep(3)
    p.kill()
    p.wait()
    written = os.listdir(f"{ZLOCAL}/pipe")
    check("pty.zmodem.no_terminal", "with no terminal nothing is received, and sz's bytes reach stdout",
          b"**\x18B00" in out and not written, out + f"\nwritten: {written}".encode())


if SZ and RZ:
    zmodem()
else:
    for name in ZMODEM_IDS:
        unmet(name, "no sz and rz of lrzsz on this host")

sys.exit(1 if fails else 0)
