#!/usr/bin/env python3
"""podssh in a real Windows console, the counterpart of interop-pty.py.

Runs `podssh ssh -t` inside a pseudo console (ConPTY, what Windows Terminal
uses) against an SSH server, and checks the window size and a resize,
Ctrl-C, full-screen programs (vi, less, top), the exit status, the ~. escape,
and that podssh leaves the console's input mode as it found it (read with
GetConsoleMode before and after). Prints one `ok` or `FAIL` line per check;
exits 1 if any check failed. Windows only.

Usage: python scripts/interop-conpty.py PODSSH_EXE DESTINATION [SSH ARGS...]
e.g.   python scripts/interop-conpty.py target/debug/podssh.exe root@host --direct
"""

import atexit
import ctypes
import ctypes.wintypes as wt
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

if sys.platform != "win32":
    sys.exit("interop-conpty.py drives a Windows pseudo console; on Linux use interop-pty.py")

BIN, DEST, EXTRA = sys.argv[1], sys.argv[2], sys.argv[3:]
# The report may quote any character the remote side drew.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100
# VT sequences ConPTY writes around the text: CSI, OSC and two-byte escapes.
VT = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")


class COORD(ctypes.Structure):
    _fields_ = [("X", wt.SHORT), ("Y", wt.SHORT)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
                ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
                ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                ("hStdError", wt.HANDLE)]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD),
                ("dwThreadId", wt.DWORD)]


kernel32.CreatePseudoConsole.argtypes = [COORD, wt.HANDLE, wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
kernel32.CreatePseudoConsole.restype = ctypes.c_long
kernel32.ResizePseudoConsole.argtypes = [wt.HANDLE, COORD]
kernel32.ResizePseudoConsole.restype = ctypes.c_long
kernel32.ClosePseudoConsole.argtypes = [wt.HANDLE]
kernel32.CreatePipe.argtypes = [ctypes.POINTER(wt.HANDLE), ctypes.POINTER(wt.HANDLE), ctypes.c_void_p, wt.DWORD]
kernel32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wt.DWORD, wt.DWORD,
                                                       ctypes.POINTER(ctypes.c_size_t)]
kernel32.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                               ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
kernel32.CreateProcessW.argtypes = [wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL, wt.DWORD,
                                    ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(STARTUPINFOEXW),
                                    ctypes.POINTER(PROCESS_INFORMATION)]
kernel32.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
kernel32.CloseHandle.argtypes = [wt.HANDLE]

fails = 0


def check(name, condition, term):
    global fails
    if condition:
        print(f"ok    {name}")
    else:
        fails += 1
        print(f"FAIL  {name}")
        for line in term.text()[-800:].splitlines():
            print(f"      | {line!r}")
    sys.stdout.flush()


class Terminal:
    """A pseudo console running COMMAND, its output collected by a thread."""

    def __init__(self, command, rows, cols):
        in_read, in_write, out_read, out_write = wt.HANDLE(), wt.HANDLE(), wt.HANDLE(), wt.HANDLE()
        if not (kernel32.CreatePipe(ctypes.byref(in_read), ctypes.byref(in_write), None, 0)
                and kernel32.CreatePipe(ctypes.byref(out_read), ctypes.byref(out_write), None, 0)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.hpc = wt.HANDLE()
        hr = kernel32.CreatePseudoConsole(COORD(cols, rows), in_read, out_write, 0, ctypes.byref(self.hpc))
        if hr != 0:
            raise OSError(f"CreatePseudoConsole failed: {hr & 0xFFFFFFFF:#x}")
        # The pseudo console keeps its own references to these ends.
        kernel32.CloseHandle(in_read)
        kernel32.CloseHandle(out_write)
        self.input, self.output = in_write, out_read
        size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        self.attrs = ctypes.create_string_buffer(size.value)
        if not kernel32.InitializeProcThreadAttributeList(self.attrs, 1, 0, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.UpdateProcThreadAttribute(self.attrs, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, self.hpc,
                                                  ctypes.sizeof(wt.HANDLE), None, None):
            raise ctypes.WinError(ctypes.get_last_error())
        info = STARTUPINFOEXW()
        info.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        # Null standard handles, explicitly: otherwise a child of a process
        # whose stdio is redirected (as under a test runner) inherits that
        # stdio instead of using the pseudo console.
        info.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        info.lpAttributeList = ctypes.cast(self.attrs, ctypes.c_void_p)
        process = PROCESS_INFORMATION()
        line = ctypes.create_unicode_buffer(command)
        if not kernel32.CreateProcessW(None, line, None, None, False, EXTENDED_STARTUPINFO_PRESENT, None, None,
                                       ctypes.byref(info), ctypes.byref(process)):
            raise ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(process.hThread)
        self.process = process.hProcess
        self.buf = b""
        self.lock = threading.Lock()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        chunk = ctypes.create_string_buffer(65536)
        got = wt.DWORD()
        while kernel32.ReadFile(self.output, chunk, 65536, ctypes.byref(got), None) and got.value:
            with self.lock:
                self.buf += chunk.raw[:got.value]

    def text(self):
        with self.lock:
            return VT.sub(b"", self.buf).decode("utf-8", "replace")

    def send(self, data, pause=0.0):
        written = wt.DWORD()
        kernel32.WriteFile(self.input, data, len(data), ctypes.byref(written), None)
        if pause:
            time.sleep(pause)

    def resize(self, rows, cols):
        kernel32.ResizePseudoConsole(self.hpc, COORD(cols, rows))

    def expect(self, needle, timeout=15):
        end = time.time() + timeout
        while needle not in self.text() and time.time() < end:
            time.sleep(0.1)
        return needle in self.text()

    def close(self):
        if kernel32.WaitForSingleObject(self.process, 5000) != 0:
            kernel32.TerminateProcess(self.process, 1)
        kernel32.ClosePseudoConsole(self.hpc)
        kernel32.CloseHandle(self.process)


def marker(t, word, a, b):
    """Run `echo WORD-$((a+b))` and wait for the computed value, which the
    echo of the typed line cannot contain."""
    t.send(f"echo {word}-$(({a}+{b}))\r".encode())
    return t.expect(f"{word}-{a + b}")


# The pseudo console's own process: it reads the console's input mode, runs
# podssh, and reads the mode again. Not cmd: cmd restores the console mode
# itself after every program it runs, and so hid a planted podssh that never
# restored it.
SCRATCH = tempfile.mkdtemp(prefix="podssh-conpty-")
atexit.register(shutil.rmtree, SCRATCH, ignore_errors=True)
WRAPPER = os.path.join(SCRATCH, "wrap.py")
with open(WRAPPER, "w", encoding="utf-8") as f:
    f.write("import ctypes, subprocess, sys\n"
            "k = ctypes.windll.kernel32\n"
            "def mode():\n"
            "    m = ctypes.c_uint(0)\n"
            "    return m.value if k.GetConsoleMode(k.GetStdHandle(-10), ctypes.byref(m)) else -1\n"
            "before = mode()\n"
            "rc = subprocess.call(sys.argv[1:])\n"
            "after = mode()\n"
            "print(f'\\r\\nBEFORE={before:#x}\\r\\nRC={rc}\\r\\nAFTER={after:#x}', flush=True)\n")


def session_command(*remote):
    return subprocess.list2cmdline(
        [sys.executable, WRAPPER, BIN, "ssh", "-t", "-o", "BatchMode=yes", *EXTRA, DEST, *remote])


def exit_status(t):
    if not t.expect("RC=", 20):
        return None
    t.expect("AFTER=", 10)
    return int(re.search(r"RC=(-?\d+)", t.text()).group(1))


def restored(t):
    """The input mode after podssh is the one before it."""
    before = re.search(r"BEFORE=(0x[0-9a-f]+)", t.text())
    after = re.search(r"AFTER=(0x[0-9a-f]+)", t.text())
    return bool(before and after and before.group(1) == after.group(1))


t = Terminal(session_command(), 40, 100)
check("a shell in a Windows pseudo console", marker(t, "READY", 1, 2), t)
t.send(b"stty size\r")
check("the window size is sent (40x100)", t.expect("40 100"), t)
t.resize(50, 120)
time.sleep(1.5)
t.send(b"stty size\r")
check("a resize reaches the server (50x120)", t.expect("50 120"), t)
t.send(b"sleep 30\r", 1.5)
start = time.time()
t.send(b"\x03")
check("Ctrl-C interrupts the remote command, not podssh", marker(t, "INT", 3, 4) and time.time() - start < 10, t)
t.send(b"rm -f /tmp/podssh-conpty-vi\r", 0.5)
t.send(b"vi /tmp/podssh-conpty-vi\r", 2.0)
t.send(b"ihello from a windows console", 0.5)
t.send(b"\x1b", 1.0)
t.send(b":wq\r", 1.0)
t.send(b"cat /tmp/podssh-conpty-vi\r")
check("vi edits and saves a file", t.expect("hello from a windows console") and marker(t, "VI", 5, 5), t)
t.send(b"seq 1 500 | less\r", 1.5)
t.send(b"G", 0.5)
t.send(b"q", 0.5)
check("less pages and quits", marker(t, "LESS", 6, 6), t)
t.send(b"top\r", 2.0)
t.send(b"q", 0.5)
check("top draws and quits", marker(t, "TOP", 7, 7), t)
t.send(b"rm -f /tmp/podssh-conpty-vi; exit\r")
check("podssh exits with the shell", exit_status(t) is not None, t)
check("the console's input mode is restored afterwards", restored(t), t)
t.close()

# The exit status of a command: a login shell's is not reported by every
# server (Tailscale SSH reports none, to OpenSSH's own client too; measured
# 2026-10-08).
t = Terminal(session_command("exit 7"), 24, 80)
check("a command's exit status comes back through a pty (7)", exit_status(t) == 7, t)
check("the console's input mode is restored after it", restored(t), t)
t.close()

t = Terminal(session_command(), 24, 80)
check("a second shell", marker(t, "AGAIN", 2, 2), t)
t.send(b"\r~.")
check("~. disconnects (exit 255)", exit_status(t) == 255, t)
check("the console's input mode is restored after ~.", restored(t), t)
t.close()

sys.exit(1 if fails else 0)
