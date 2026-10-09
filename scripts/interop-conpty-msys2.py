#!/usr/bin/env python3
"""interop-conpty.py against the OpenSSH server of MSYS2, on 127.0.0.1.

The console checks need a server with a POSIX shell, stty, vi, less, top and
seq. MSYS2 has each of them, and the Windows runners of CI have MSYS2. For
one run, this script makes a user key with `podssh keygen` and a host key,
starts MSYS2's sshd on a free port of 127.0.0.1 (a key login for the current
user only), runs interop-conpty.py against it with --direct, stops the
server, and deletes the keys.

Usage: python scripts/interop-conpty-msys2.py [--install] PODSSH_EXE
       python scripts/interop-conpty-msys2.py [--install] --plant

  --install  install openssh, vim, less and procps-ng with MSYS2's pacman
             first (CI). Without it, MSYS2 is used as it is.
  --plant    build a podssh that leaves the console raw (the restore of
             crates/podssh-ssh/src/terminal/windows.rs disabled), run the
             checks with it, then put the source back and build again. The
             three restore checks, and only they, must fail.

Exit 0 when the result is the one expected (each of the 14 checks passes;
with --plant, exactly the three restore checks fail), 1 when it is not, and
2 when the checks could not run: a check that did not run is not a pass.
MSYS2_ROOT names the directory of MSYS2 (default C:\\msys64).
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if sys.platform != "win32":
    sys.exit("interop-conpty-msys2.py runs MSYS2's sshd on Windows; on Linux use interop-pty.py")

ROOT = Path(__file__).resolve().parent.parent
MSYS2 = Path(os.environ.get("MSYS2_ROOT", r"C:\msys64"))
BASH = MSYS2 / "usr" / "bin" / "bash.exe"
PACKAGES = "openssh vim less procps-ng"
# Each check of interop-conpty.py: fewer `ok` lines is a failure, so a check
# that someone deletes is seen.
CHECKS = 14
RESTORE_CHECKS = {
    "the console's input mode is restored afterwards",
    "the console's input mode is restored after it",
    "the console's input mode is restored after ~.",
}
# The plant: the restore finds nothing to put back, so podssh leaves the
# console as it set it.
PLANT_FILE = ROOT / "crates" / "podssh-ssh" / "src" / "terminal" / "windows.rs"
PLANT_FROM = b"if let Some(s) = saved {"
PLANT_TO = b"if let Some(s) = saved.filter(|_| false) {"
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def cannot_run(why):
    print(f"interop-conpty-msys2: the checks did not run: {why}", flush=True)
    sys.exit(2)


def msys(command, timeout=120):
    """COMMAND in MSYS2's bash, a login shell that stays in this directory."""
    env = dict(os.environ, MSYSTEM="MSYS", CHERE_INVOKING="1")
    try:
        return subprocess.run([str(BASH), "-lc", command], env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        cannot_run(f"MSYS2's bash did not finish in {timeout} s: {command}")


def posix(path):
    r = msys(f"cygpath -u '{path}'", 60)
    if r.returncode != 0 or not r.stdout.strip():
        cannot_run(f"cygpath could not convert {path}: {r.stderr.strip()}")
    return r.stdout.strip()


def install():
    # A stale package database can name files that the mirrors dropped: then
    # refresh it, and try once more.
    for flags in ("-S", "-Sy"):
        r = msys(f"pacman {flags} --noconfirm --needed {PACKAGES}", 900)
        if r.returncode == 0:
            print(f"interop-conpty-msys2: pacman {flags}: {PACKAGES} installed", flush=True)
            break
        print(f"pacman {flags} exited {r.returncode}:\n{r.stdout[-1500:]}{r.stderr[-1500:]}", flush=True)
    else:
        cannot_run(f"pacman could not install {PACKAGES}")
    # The checks type `vi`; a vim package with no `vi` gets a one-line one.
    r = msys("command -v vi >/dev/null || { command -v vim >/dev/null && mkdir -p /usr/local/bin && "
             "printf '#!/bin/sh\\nexec vim \"$@\"\\n' > /usr/local/bin/vi && chmod 755 /usr/local/bin/vi; }", 60)
    if r.returncode != 0:
        cannot_run(f"no vi, and none could be made: {r.stderr.strip()}")


def require_programs():
    r = msys("for p in /usr/bin/sshd ssh-keygen vi less top seq stty cygpath kill id; do "
             "command -v \"$p\" >/dev/null || echo \"missing: $p\"; done", 60)
    missing = re.findall(r"missing: (\S+)", r.stdout)
    if r.returncode != 0 or missing:
        cannot_run(f"MSYS2 at {MSYS2} lacks {', '.join(missing) or 'a program'} (--install adds them)")


def build():
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    try:
        r = subprocess.run(["cargo", "build", "--locked", "-p", "podssh-cli"], cwd=ROOT, timeout=3600)
    except subprocess.TimeoutExpired:
        return None
    return target / "debug" / "podssh.exe" if r.returncode == 0 else None


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(scratch, public_key):
    host_key = scratch / "host_ed25519"
    r = msys(f"ssh-keygen -q -t ed25519 -N '' -C podssh-conpty-host -f '{posix(host_key)}'", 60)
    if r.returncode != 0:
        cannot_run(f"ssh-keygen could not make the host key: {r.stderr.strip()}")
    (scratch / "authorized_keys").write_bytes(public_key)
    port = free_port()
    config = scratch / "sshd_config"
    # LF only: MSYS2 reads its files as binary, and a CR would end each value.
    config.write_bytes("\n".join([
        f"Port {port}",
        "ListenAddress 127.0.0.1",
        f"HostKey {posix(host_key)}",
        f"PidFile {posix(scratch / 'sshd.pid')}",
        f"AuthorizedKeysFile {posix(scratch / 'authorized_keys')}",
        "PubkeyAuthentication yes",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        # The scratch directory has the modes of Windows, not of a home.
        "StrictModes no",
        "",
    ]).encode())
    r = msys(f"/usr/bin/sshd -t -f '{posix(config)}'", 60)
    if r.returncode != 0:
        cannot_run(f"sshd refused its configuration: {r.stdout.strip()} {r.stderr.strip()}")
    log = open(scratch / "sshd.log", "wb")
    env = dict(os.environ, MSYSTEM="MSYS", CHERE_INVOKING="1")
    # sshd starts again its own binary, by an absolute path: hence /usr/bin.
    proc = subprocess.Popen([str(BASH), "-lc", f"exec /usr/bin/sshd -D -e -f '{posix(config)}'"], env=env,
                            stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            cannot_run(f"sshd exited with {proc.returncode}:\n{server_log(scratch)}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                s.settimeout(5)
                if s.recv(64).startswith(b"SSH-2.0-"):
                    return port, proc
        except OSError:
            time.sleep(0.5)
    stop_server(scratch, proc)
    cannot_run(f"sshd did not answer on 127.0.0.1:{port} in 30 s:\n{server_log(scratch)}")


def server_log(scratch):
    path = scratch / "sshd.log"
    lines = path.read_bytes().decode("utf-8", "replace").splitlines() if path.exists() else []
    return "\n".join(f"      sshd| {line}" for line in lines[-40:])


def stop_server(scratch, proc):
    pid = (scratch / "sshd.pid").read_text().strip() if (scratch / "sshd.pid").exists() else ""
    if pid.isdigit():
        msys(f"kill {pid}", 30)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            print(f"interop-conpty-msys2: sshd (pid {pid or '?'}) did not stop", flush=True)


def run_checks(podssh, port, key, scratch, user):
    command = [sys.executable, str(ROOT / "scripts" / "interop-conpty.py"), str(podssh), f"{user}@127.0.0.1",
               "--direct", "-p", str(port), "-i", str(key), "-o", "StrictHostKeyChecking=accept-new",
               "-o", f"UserKnownHostsFile={scratch / 'known_hosts'}"]
    try:
        r = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=900)
    except subprocess.TimeoutExpired:
        cannot_run("interop-conpty.py did not finish in 900 s")
    print(r.stdout, end="", flush=True)
    if r.stderr.strip():
        print(r.stderr, end="", flush=True)
    passed = re.findall(r"^ok\s+(.+?)\s*$", r.stdout, re.M)
    failed = re.findall(r"^FAIL\s+(.+?)\s*$", r.stdout, re.M)
    return r.returncode, passed, failed


def session(podssh, scratch):
    key = scratch / "id_ed25519"
    try:
        r = subprocess.run([str(podssh), "keygen", "-q", "-t", "ed25519", "-N", "", "-C", "podssh-conpty-user",
                            "-f", str(key)], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        cannot_run("podssh keygen did not finish in 60 s")
    if r.returncode != 0 or not (scratch / "id_ed25519.pub").is_file():
        cannot_run(f"podssh keygen exited {r.returncode}: {r.stderr.strip()}")
    user = msys("id -un", 60).stdout.strip()
    if not user:
        cannot_run("MSYS2 names no user (id -un)")
    port, proc = start_server(scratch, (scratch / "id_ed25519.pub").read_bytes())
    try:
        result = run_checks(podssh, port, key, scratch, user)
    finally:
        stop_server(scratch, proc)
    if result[2]:
        print(server_log(scratch), flush=True)
    return result


def main(argv):
    flags = {a for a in argv if a in ("--install", "--plant")}
    rest = [a for a in argv if a not in flags]
    planted = "--plant" in flags
    if len(rest) != (0 if planted else 1):
        print(__doc__)
        return 2
    if not BASH.is_file():
        cannot_run(f"no MSYS2 at {MSYS2} (MSYS2_ROOT names another)")
    if "--install" in flags:
        install()
    require_programs()
    (ROOT / ".work").mkdir(exist_ok=True)
    # In .work/, which git ignores: a path with no 8.3 name and no space.
    scratch = Path(tempfile.mkdtemp(prefix="conpty-msys2-", dir=ROOT / ".work"))
    try:
        if not planted:
            rc, passed, failed = session(Path(rest[0]), scratch)
        else:
            original = PLANT_FILE.read_bytes()
            if original.count(PLANT_FROM) != 1:
                cannot_run(f"the plant no longer applies: {PLANT_FILE.name} has not one `{PLANT_FROM.decode()}`")
            try:
                PLANT_FILE.write_bytes(original.replace(PLANT_FROM, PLANT_TO))
                podssh = build()
                if podssh is None:
                    cannot_run("the planted podssh did not build")
                rc, passed, failed = session(podssh, scratch)
            finally:
                PLANT_FILE.write_bytes(original)
            if build() is None:
                print("FAIL  podssh did not build again after the plant was removed", flush=True)
                return 1
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        print(f"interop-conpty-msys2: the keys of this run are deleted ({not scratch.exists()})", flush=True)
    if planted:
        if rc == 1 and set(failed) == RESTORE_CHECKS and len(passed) == CHECKS - len(RESTORE_CHECKS):
            print("interop-conpty-msys2: the planted podssh failed the three restore checks and no other, "
                  "as it must", flush=True)
            return 0
        print(f"interop-conpty-msys2: the plant was not caught as it must be (exit {rc}; "
              f"failed: {sorted(failed)})", flush=True)
        return 1
    if rc == 0 and not failed and len(passed) == CHECKS:
        print(f"interop-conpty-msys2: {len(passed)} of {CHECKS} checks passed", flush=True)
        return 0
    print(f"interop-conpty-msys2: {len(passed)} of {CHECKS} checks passed, {len(failed)} failed (exit {rc})",
          flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
