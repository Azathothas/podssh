#!/usr/bin/env python3
"""QUIC's settings on the iroh road, one arm against another (T-665).

The method is T-157's: in each cell, RUNS runs, each a new `podssh ssh` and
a new connection, of MIB down (`head -c N /dev/zero`) and then MIB up (`sh
-c 'echo R; wc -c'`), in separate sessions, 300 s at most each; the clock of
a run starts at the far end's first byte, or its `R`, and stops at the last
byte; then the minimum, p50, p95 and maximum in MiB/s by nearest rank, with
the line of each run. A cell here is an arm of PODSSH_IROH_QUIC, set at both
ends, and the arms take turns in each round, so that a change of the path
falls on each arm alike.

The far end is the operator's server of PODSSH_THROUGHPUT_SSH (Q38; Q91,
short runs). With OpenSSH, this script makes a private directory there,
copies the static podssh of --far-podssh into it (under $TMPDIR, else $HOME
where /tmp does not run programs), and runs one `podssh node --iroh` for
each arm in front of that server's own sshd, its HOME and its keys in that
directory; `podssh ssh -v` here then logs in to each node with --identity,
through n0's relays (or --relay) and a direct path where UDP gives one. -v
says which path carried each run, and the QUIC arm that it took. At the end
the nodes are stopped and the directory removed.

No user, host, address, key or ticket is printed or kept: the result (--out)
holds figures, paths and arms, and a failed run's last line with each user,
host and address taken out. --ci also appends the table to GitHub's step
summary. The buffers that the kernel grants at each end (net.core.rmem_max
and wmem_max) are kept, as iroh asks 7 MiB of each by SO_RCVBUF/SO_SNDBUF.

Usage:
  python3 -I scripts/iroh-ab.py --self-test
  python3 -I scripts/iroh-ab.py --podssh BIN [--far-podssh BIN]
      --destination USER@HOST[:PORT] --identity KEY [--arms 'iroh;tuned']
      [--runs 5] [--mib 4] [--relay URL] --out FILE [--ci]

The defaults, two arms of 5 rounds of 4 MiB each way, move 80 MiB in all:
a short run (Q35, Q91).

Exit 0 when each arm measured at least one run each way; 1 when one did not,
or the self-test failed; 2 for a usage error or a far end that cannot run the
binary. Read the exit code directly, not through a pipe.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

MIB = 1 << 20
RUN_LIMIT = 300  # T-157: each run
NODE_LIMIT = 1800  # a far node's own end, whatever becomes of this script
START_LIMIT = 90  # a node's ticket
CONTROL_LIMIT = 120  # each OpenSSH command of the setup
MAX_ARMS = 4
ELF_MACHINE = {"x86_64": 62, "amd64": 62, "aarch64": 183, "arm64": 183}
DIRECT = "a direct path carried the session"
RELAY_ONLY = "the relay carried each byte of the session"


def rank(ordered: list[float], q: float) -> float:
    """The nearest-rank percentile q: the smallest value with at least the
    share q of the sample at or below it (T-157)."""
    k = min(max(math.ceil(q * len(ordered)), 1), len(ordered))
    return ordered[k - 1]


def summary(samples: list[float]) -> dict | None:
    if not samples:
        return None
    ordered = sorted(samples)
    return {"min": ordered[0], "p50": rank(ordered, 0.50), "p95": rank(ordered, 0.95), "max": ordered[-1]}


def right(summarize) -> bool:
    """Whether summarize gives the figures of T-157's known sample."""
    sample = [float((i * 17) % 40 + 1) for i in range(1, 41)]
    return (summarize(sample) == {"min": 1.0, "p50": 20.0, "p95": 38.0, "max": 40.0}
            and summarize([7.0]) == {"min": 7.0, "p50": 7.0, "p95": 7.0, "max": 7.0}
            and summarize([]) is None)


def destination(text: str) -> tuple[str, str, int]:
    """USER@HOST[:PORT], HOST maybe [IPv6]: its parts, port 22 by default."""
    user, sep, rest = text.strip().rpartition("@")
    port = ""
    if rest.startswith("["):
        host, _, after = rest[1:].partition("]")
        port = after[1:] if after.startswith(":") else after
    elif rest.count(":") == 1:
        host, _, port = rest.partition(":")
    else:
        host = rest
    if not sep or not user or not host or (port and not port.isdigit()):
        raise ValueError("the destination is USER@HOST[:PORT]")
    number = int(port) if port else 22
    if not 0 < number < 65536:
        raise ValueError("the destination's port is from 1 to 65535")
    return user, host, number


def arms(text: str) -> list[str]:
    """The arms, separated by ';': each a value of PODSSH_IROH_QUIC."""
    found = [a.strip().lower() for a in text.split(";") if a.strip()]
    if not 2 <= len(found) <= MAX_ARMS or len(set(found)) != len(found):
        raise ValueError(f"the arms are 2 to {MAX_ARMS} values of PODSSH_IROH_QUIC, each once, separated by ';'")
    for arm in found:
        if not re.fullmatch(r"[a-z]+(,[a-z]+)*", arm):
            raise ValueError("an arm is words of PODSSH_IROH_QUIC separated by ','")
    return found


def ticket_of(line: str) -> str | None:
    at = line.find("ticket iroh:")
    return line[at + len("ticket "):].split()[0] if at >= 0 else None


def fingerprint_of(text: str) -> str | None:
    found = re.search(r"refused this client's key (SHA256:[A-Za-z0-9+/]+)", text)
    return found.group(1) if found else None


def path_of(text: str) -> str:
    return "direct" if DIRECT in text else "relay" if RELAY_ONLY in text else "unknown"


def quic_of(text: str) -> str:
    """The words of the QUIC arm that a line of -v, or of a node, says;
    iroh's own when none says one."""
    found = re.search(r"QUIC: .*\(([a-z,]+)\)\s*$", text, re.MULTILINE)
    return found.group(1) if found else "iroh"


def scrub(text: str, *secrets: str) -> str:
    """text with each secret, each IPv4 address and each IPv6-like run taken out."""
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "X")
    text = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "ADDR", text)
    return re.sub(r"\b[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}\b", "ADDR", text)


def target_of(text: str, port: int) -> str:
    """The address where the far sshd took the login, from its line `sshd
    CLIENT CPORT SERVER SPORT` ($SSH_CONNECTION); the loopback at `port`
    when the line is not there."""
    found = re.search(r"^sshd \S+ \d+ (\S+) (\d+)\s*$", text, re.MULTILINE)
    if not found:
        return f"127.0.0.1:{port}"
    host, number = found.group(1), found.group(2)
    return f"[{host}]:{number}" if ":" in host else f"{host}:{number}"


def elf_machine(head: bytes) -> int | None:
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    return int.from_bytes(head[18:20], "little" if head[5] == 1 else "big")


def self_test() -> int:
    checks = {
        "statistics": right(summary),
        "planted p95 caught": not right(lambda s: summary(s) and {**summary(s), "p95": summary(s)["max"]}),
        "destination": destination("u@h") == ("u", "h", 22) and destination("u@h:2222") == ("u", "h", 2222)
        and destination("u@[::1]:22") == ("u", "::1", 22) and destination("a@b@h") == ("a@b", "h", 22),
        "bad destinations": all(_refused(destination, t) for t in ["h", "@h", "u@", "u@h:0", "u@h:x", "u@h:70000"]),
        "arms": arms(" iroh ; Tuned;rtt,bbr") == ["iroh", "tuned", "rtt,bbr"],
        "bad arms": all(_refused(arms, t) for t in ["iroh", "iroh;iroh", "a;b;c;d;e", "iroh;x y", "iroh;rtt,"]),
        "ticket": ticket_of("podssh node: ab0: ticket iroh:abc123 (home)") == "iroh:abc123",
        "fingerprint": fingerprint_of("x: the node refused this client's key SHA256:ab+/9: it is") == "SHA256:ab+/9",
        "path": path_of(f"x: {DIRECT}") == "direct" and path_of(RELAY_ONLY) == "relay" and path_of("") == "unknown",
        "quic": quic_of("n: the iroh road's QUIC: Cubic, x (rtt,window,streams,cubic)\n") == "rtt,window,streams,cubic"
        and quic_of("nothing") == "iroh",
        "scrub": all(s not in scrub("alice@srv.example 203.0.113.7 [2001:db8::1]:22", "alice", "srv.example")
                     for s in ["alice", "srv.example", "203.0.113.7", "2001:db8::1"]),
        "elf": elf_machine(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00") == 62 and elf_machine(b"MZ") is None,
        "target": target_of("x86_64\nsshd 198.51.100.7 51234 10.0.0.5 22\n", 2222) == "10.0.0.5:22"
        and target_of("sshd 2001:db8::7 5 2001:db8::5 22", 22) == "[2001:db8::5]:22"
        and target_of("x86_64\nsshd \n", 2222) == "127.0.0.1:2222",
    }
    for name, ok in checks.items():
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    return 0 if all(checks.values()) else 1


def _refused(parse, text: str) -> bool:
    try:
        parse(text)
    except ValueError:
        return True
    return False


class Far:
    """The far end over OpenSSH: its directory, its facts, its nodes."""

    def __init__(self, user: str, host: str, port: int, identity: str, scratch: Path):
        self.user, self.host, self.port = user, host, port
        self.base = ["ssh", "-i", identity, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                     "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={scratch / 'known_far'}",
                     "-o", "ConnectTimeout=20", "-p", str(port), f"{user}@{host}"]
        self.dir = ""
        self.nodes: list[subprocess.Popen] = []

    def sh(self, script: str) -> tuple[int, str]:
        """`script` run by the far end's sh, whatever its login shell is."""
        done = subprocess.run(self.base + ["sh -s"], input=script.encode(), capture_output=True,
                              timeout=CONTROL_LIMIT)
        return done.returncode, done.stdout.decode(errors="replace")

    def facts(self) -> dict:
        """The far end's machine, its buffers' bounds, its `timeout`, and
        the address where its sshd took this login, the nodes' TARGET: a
        port forwarded to the server may not be the one that sshd binds."""
        code, out = self.sh("uname -m; cat /proc/sys/net/core/rmem_max /proc/sys/net/core/wmem_max 2>/dev/null; "
                            "command -v timeout >/dev/null && echo timeout; echo \"sshd $SSH_CONNECTION\"\n")
        words = out.split()
        if code != 0 or not words:
            raise RuntimeError(f"the far end did not answer over OpenSSH (exit {code})")
        numbers = [int(x) for x in words[1:3] if x.isdigit()]
        return {"arch": words[0], "rmem_max": numbers[0] if numbers else None,
                "wmem_max": numbers[1] if len(numbers) > 1 else None, "timeout": "timeout" in words,
                "target": target_of(out, self.port)}

    def place(self, binary: bytes) -> str:
        """A private directory that runs the binary: under $TMPDIR or /tmp,
        else under $HOME, as a host may mount /tmp with noexec."""
        for parent in ['"${TMPDIR:-/tmp}"', '"$HOME"']:
            make = (f"umask 077; d=$(mktemp -d {parent}/podssh-ab.XXXXXX 2>/dev/null) || "
                    f"{{ d={parent}/podssh-ab.$$; mkdir \"$d\" || exit 1; }}; printf '%s\\n' \"$d\"\n")
            code, out = self.sh(make)
            if code != 0 or not out.strip():
                continue
            self.dir = out.strip().splitlines()[-1]
            path = shlex.quote(f"{self.dir}/podssh")
            # The binary on stdin: sh -c's own quotes pass each login shell.
            load = f"sh -c 'cat > \"$1\" && chmod 700 \"$1\" && \"$1\" --version >/dev/null' sh {path}"
            done = subprocess.run(self.base + [load], input=binary, capture_output=True, timeout=CONTROL_LIMIT)
            if done.returncode == 0:
                code, _ = self.sh(f"printf '# the client keys of an A/B run\\n' > {shlex.quote(self.dir)}/allow\n")
                if code == 0:
                    return self.dir
            self.cleanup()
        raise RuntimeError("no directory of the far end runs the binary (or it is not built for this host)")

    def start(self, index: int, arm: str, relay: str | None, facts: dict) -> tuple[str, str]:
        """A node of `arm` in front of the far sshd: its ticket, and the arm that it says."""
        d = shlex.quote(self.dir)
        env = f"HOME={d} XDG_CACHE_HOME={d}/cache PODSSH_IROH_QUIC={shlex.quote(arm)}"
        node = (f"{d}/podssh node ab{index} {shlex.quote(facts['target'])} --iroh --iroh-allow {d}/allow "
                f"--iroh-key {d}/node{index}.key") + (f" --iroh-relay {shlex.quote(relay)}" if relay else "")
        limit = f"timeout {NODE_LIMIT} " if facts["timeout"] else ""
        script = f"cd {d} && echo $$ > node{index}.pid && exec env {env} {limit}{node} </dev/null\n"
        proc = subprocess.Popen(self.base + ["sh -s"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, errors="replace")
        self.nodes.append(proc)
        proc.stdin.write(script)
        proc.stdin.close()
        lines: list[str] = []
        reader = threading.Thread(target=lambda: lines.extend(proc.stderr), daemon=True)
        reader.start()
        deadline = time.monotonic() + START_LIMIT
        while time.monotonic() < deadline:
            for line in list(lines):
                if ticket_of(line):
                    return ticket_of(line), quic_of("\n".join(lines))
            if proc.poll() is not None and not reader.is_alive():
                break
            time.sleep(0.2)
        last = scrub(lines[-1].strip(), self.user, self.host) if lines else "nothing"
        raise RuntimeError(f"the node of the arm {arm} gave no ticket within {START_LIMIT} s: {last}")

    def allow(self, fingerprint: str) -> None:
        line = shlex.quote(f"{fingerprint} the A/B run's client")
        code, _ = self.sh(f"printf '%s\\n' {line} >> {shlex.quote(self.dir)}/allow\n")
        if code != 0:
            raise RuntimeError("the far end's allowlist could not take the client's key")

    def cleanup(self) -> None:
        if self.dir:
            d = shlex.quote(self.dir)
            stop = (f"cd {d} 2>/dev/null || exit 0; for f in node*.pid; do [ -f \"$f\" ] && kill \"$(cat \"$f\")\" "
                    f"2>/dev/null; done; sleep 2; cd / && rm -rf {d}\n")
            try:
                self.sh(stop)
            except (subprocess.TimeoutExpired, OSError):
                pass
            self.dir = ""
        for proc in self.nodes:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        self.nodes = []


def client(args, scratch: Path, ticket: str, command: str) -> list[str]:
    cmd = [args.podssh, "ssh", "-v", "-i", args.identity, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={scratch / 'known_iroh'}",
           "--iroh-key", str(scratch / "client.key")]
    if args.relay:
        cmd += ["--iroh-relay", args.relay]
    return cmd + [f"{args.user}@{ticket}", command]


def environment(scratch: Path, arm: str) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PODSSH_")}
    env.update(HOME=str(scratch / "home"), XDG_CACHE_HOME=str(scratch / "cache"), PODSSH_SSH_CONFIG="none",
               PODSSH_IROH_QUIC=arm)
    return env


def one_run(cmd: list[str], env: dict, size: int, up: bool) -> dict:
    """One run: its bytes, its seconds from the far end's first byte (or R)
    to its last, its exit code and its -v text."""
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if up else subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    killer = threading.Timer(RUN_LIMIT, proc.kill)
    killer.start()
    said: list[bytes] = []
    reader = threading.Thread(target=lambda: said.append(proc.stderr.read()), daemon=True)
    reader.start()
    got, first, last, fed = 0, None, None, False
    try:
        if up:
            if proc.stdout.readline().strip() == b"R":
                first, fed = time.monotonic(), True
                threading.Thread(target=_feed, args=(proc.stdin, size), daemon=True).start()
                count = proc.stdout.readline().strip()
                last = time.monotonic()
                got = int(count) if count.isdigit() else 0
            proc.stdout.read()
        else:
            while chunk := proc.stdout.read1(1 << 16):
                last = time.monotonic()
                first = first or last
                got += len(chunk)
    finally:
        # A session that never asked for the bytes gets the end of them.
        if up and not fed:
            proc.stdin.close()
        code = proc.wait()
        killer.cancel()
        reader.join(timeout=10)
    seconds = (last - first) if first and last and last > first else None
    text = b"".join(said).decode(errors="replace")
    return {"bytes": got, "seconds": seconds, "code": code, "said": text}


def _feed(pipe, size: int) -> None:
    block = bytes(1 << 16)
    try:
        left = size
        while left > 0:
            n = min(left, len(block))
            pipe.write(block[:n])
            left -= n
        pipe.close()
    except (BrokenPipeError, OSError):
        pass


def measure(args, far: Far, scratch: Path, tickets: dict) -> list[dict]:
    size = args.mib * MIB
    samples = []
    for run in range(1, args.runs + 1):
        for arm in args.arms:
            for direction in ("down", "up"):
                command = f"head -c {size} /dev/zero" if direction == "down" else "sh -c 'echo R; wc -c'"
                got = one_run(client(args, scratch, tickets[arm], command), environment(scratch, arm), size,
                              direction == "up")
                whole = got["code"] == 0 and got["bytes"] == size and got["seconds"]
                sample = {"arm": arm, "direction": direction, "run": run, "bytes": got["bytes"],
                          "seconds": round(got["seconds"], 4) if got["seconds"] else None,
                          "mib_s": round(size / MIB / got["seconds"], 3) if whole else None,
                          "path": path_of(got["said"]), "quic": quic_of(got["said"]), "code": got["code"]}
                if not whole:
                    tail = [ln for ln in got["said"].splitlines() if ln.strip()][-1:] or ["nothing said"]
                    sample["why"] = scrub(tail[0], args.user, far.host)[:240]
                print(f"{arm:>16} {direction:>4} run {run}: " + (f"{sample['mib_s']:.2f} MiB/s, {sample['path']}"
                      if whole else f"failed (exit {got['code']}): {sample['why']}"), flush=True)
                samples.append(sample)
    return samples


def tally(arms_: list[str], samples: list[dict]) -> dict:
    table = {}
    for arm in arms_:
        table[arm] = {}
        for direction in ("down", "up"):
            mine = [s for s in samples if s["arm"] == arm and s["direction"] == direction]
            rates = [s["mib_s"] for s in mine if s["mib_s"] is not None]
            table[arm][direction] = {"summary": summary(rates), "ok": len(rates), "runs": len(mine),
                                     "direct": sum(1 for s in mine if s["path"] == "direct")}
    return table


def report(table: dict, ci: bool) -> None:
    rows = ["| arm | direction | min | p50 | p95 | max | ok | direct |", "|" + " --- |" * 8]
    for arm, cells in table.items():
        for direction, cell in cells.items():
            s = cell["summary"] or {}
            figures = " | ".join(f"{s[k]:.2f}" if k in s else "-" for k in ("min", "p50", "p95", "max"))
            rows.append(f"| {arm} | {direction} | {figures} | {cell['ok']}/{cell['runs']} | {cell['direct']} |")
    print("\n".join(rows))
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if ci and summary_file:
        with open(summary_file, "a", encoding="utf-8") as out:
            out.write("## iroh A/B (MiB/s)\n\n" + "\n".join(rows) + "\n")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="QUIC's settings on the iroh road, one arm against another (T-665)")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--podssh")
    p.add_argument("--far-podssh")
    p.add_argument("--destination")
    p.add_argument("--identity")
    p.add_argument("--arms", default="iroh;tuned")
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--mib", type=int, default=4)
    p.add_argument("--relay")
    p.add_argument("--out")
    p.add_argument("--ci", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        if not (args.podssh and args.destination and args.identity and args.out):
            raise ValueError("--podssh, --destination, --identity and --out are needed")
        if not (1 <= args.runs <= 20 and 1 <= args.mib <= 256):
            raise ValueError("--runs is from 1 to 20, --mib from 1 to 256")
        args.arms = arms(args.arms)
        args.user, host, port = destination(args.destination)
        far_binary = Path(args.far_podssh or args.podssh).read_bytes()
    except (ValueError, OSError) as e:
        print(f"iroh-ab: {e}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="podssh-ab.") as tmp:
        scratch = Path(tmp)
        (scratch / "home").mkdir(mode=0o700)
        far = Far(args.user, host, port, args.identity, scratch)
        try:
            facts = far.facts()
            want = ELF_MACHINE.get(facts["arch"])
            if want is None or elf_machine(far_binary[:20]) != want:
                print(f"iroh-ab: the far end is {facts['arch']}; give --far-podssh a podssh built for it",
                      file=sys.stderr)
                return 2
            far.place(far_binary)
            tickets, node_quic = {}, {}
            for index, arm in enumerate(args.arms):
                tickets[arm], node_quic[arm] = far.start(index, arm, args.relay, facts)
            # The first run is refused and names this client's key, which the
            # allowlist of each node then holds; it is not measured.
            first = one_run(client(args, scratch, tickets[args.arms[0]], "true"),
                            environment(scratch, args.arms[0]), 0, False)
            fingerprint = fingerprint_of(first["said"])
            if not fingerprint:
                raise RuntimeError("the first run named no key of this client")
            far.allow(fingerprint)
            samples = measure(args, far, scratch, tickets)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            print(f"iroh-ab: {scrub(str(e), args.user, host)}", file=sys.stderr)
            return 1
        finally:
            far.cleanup()
    here = {}
    for name in ("rmem_max", "wmem_max"):
        try:
            here[name] = int(Path(f"/proc/sys/net/core/{name}").read_text().strip())
        except (OSError, ValueError):
            here[name] = None
    table = tally(args.arms, samples)
    result = {"method": "T-157", "entry": "T-665", "arms": args.arms, "runs": args.runs, "mib": args.mib,
              "node_quic": node_quic, "far": {k: facts[k] for k in ("arch", "rmem_max", "wmem_max")},
              "here": here, "samples": samples, "table": table}
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    report(table, args.ci)
    measured = all(cell["ok"] > 0 for cells in table.values() for cell in cells.values())
    return 0 if measured else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
