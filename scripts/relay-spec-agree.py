#!/usr/bin/env python3
"""`podssh relay spec` and `scripts/check-relay-spec.py`: one verdict on one document.

Both read crates/podssh-probe/facts/relay-facts.toml; the binary has it built
in. On the pinned copy of the relay's document both pass; on a copy with the
node path renamed both fail, and both name that fact; on the live relay both
give the same verdict. Two forms of one check that disagree are the drift
that one facts file exists to stop (T-060).

Usage: python scripts/relay-spec-agree.py PODSSH [--offline]
  --offline  the two copies only, not the live relay

Exit 0 when the two agree on each document, 1 when they do not, and 2 when
one of them could not run: a check that did not run is not a pass.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINNED = ROOT / "crates" / "podssh-probe" / "tests" / "spec" / "relay-spec-2026-10-03-r2.txt"
SCRIPT = ROOT / "scripts" / "check-relay-spec.py"
# The plant of crates/podssh-probe/tests/relay_facts.rs, and the fact that it breaks.
PLANT = ("/v1/node/<name>", "/v1/drop/<name>", "reverse-node-path")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def run(argv):
    """The exit code and the output (stdout, then stderr) of ARGV, offline unless asked."""
    env = {k: v for k, v in os.environ.items() if k not in ("PODSSH_OFFLINE", "PODSSH_RELAY", "PODSSH_RELAY_ADDR")}
    try:
        done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=120, env=env)
    except subprocess.TimeoutExpired:
        return None, f"{argv[0]} did not finish in 120 s"
    return done.returncode, done.stdout + done.stderr


def verdict(code, binary):
    """ok, fail or unread, from each one's exit code: the binary's 69 and the
    script's 2 mean that the relay could not be read."""
    if code == 0:
        return "ok"
    if code == 1:
        return "fail"
    return "unread" if code == (69 if binary else 2) else f"exit {code}"


def compare(what, podssh_argv, script_argv, expect=None, fact=None):
    p_code, p_out = run(podssh_argv)
    s_code, s_out = run([sys.executable, str(SCRIPT), *script_argv])
    p, s = verdict(p_code, True), verdict(s_code, False)
    print(f"{what}: podssh relay spec {p}, check-relay-spec.py {s}", flush=True)
    if p != s:
        print(f"  podssh: {p_out.strip()}\n  script: {s_out.strip()}")
        return 1
    if "unread" in (p, s) or p.startswith("exit"):
        print(f"  the check did not run:\n  podssh: {p_out.strip()}\n  script: {s_out.strip()}")
        return 2
    if expect and p != expect:
        print(f"  both said {p}, not {expect}")
        return 1
    if fact and not (f"FAIL {fact}:" in p_out and f"FAIL {fact}:" in s_out):
        print(f"  not both name the fact {fact}:\n  podssh: {p_out.strip()}\n  script: {s_out.strip()}")
        return 1
    return 0


def main(argv):
    if len(argv) not in (1, 2) or (len(argv) == 2 and argv[1] != "--offline"):
        print(__doc__)
        return 2
    if not Path(argv[0]).is_file():
        print(f"relay-spec-agree: no binary at {argv[0]}")
        return 2
    # Absolute: Windows starts no program from a relative path with slashes.
    podssh = str(Path(argv[0]).resolve())
    results = [compare("the pinned copy", [podssh, "relay", "spec", "--document", str(PINNED)],
                       ["--offline", str(PINNED)], expect="ok")]
    text = PINNED.read_text(encoding="utf-8")
    if PLANT[0] not in text:
        print(f"relay-spec-agree: the pinned copy has no {PLANT[0]}: the plant cannot be made")
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        planted = Path(tmp) / "planted.txt"
        planted.write_bytes(text.replace(PLANT[0], PLANT[1], 1).encode("utf-8"))
        results.append(compare("a copy with the node path renamed", [podssh, "relay", "spec", "--document", str(planted)],
                               ["--offline", str(planted)], expect="fail", fact=PLANT[2]))
    if "--offline" not in argv:
        results.append(compare("the live relay", [podssh, "relay", "spec"], []))
    worst = max(results)
    print("relay-spec-agree: " + ("the two forms agree on each document" if worst == 0 else "they do not agree"))
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
