#!/usr/bin/env python3
"""Assert that every shell script in this repository is portable and parses.

Two defects, both measured on 2026-10-01, and both of which shipped here:

1. **CRLF line endings.** A CRLF after `case $link in` makes `dash` fail with
   `Syntax error: word unexpected (expecting "in")` while `bash -n` accepts the
   same file without complaint. It has now happened three times in this
   repository, most recently because a local edit rewrote all three scripts.
   The first CI step that checked this grepped all of `scripts/` rather than
   `scripts/*.sh`, and was RED ON MAIN from the moment it was pushed, because
   `check-todo.py` is Windows-authored and has CRLF on every line. ⛔ A guard
   that fires on correct input is not a strict guard, it is a broken one.

2. **Bashisms.** `arr+=(one two)` parses under `bash -n` and fails under dash.
   A POSIX check written by running `sh -n` does not catch it, because `sh` on
   a Git Bash host is bash in POSIX mode and tolerates what dash rejects.
   MEASURED, both directions:
       dash -n  -> exit 2, "3: Syntax error: "(" unexpected"
       bash -n  -> exit 0
   ⛔ `scripts/gate.sh` and `scripts/plant.sh` run inside the build image as
   `sh`, so a bashism fails there at RUNTIME, after a local `check` has
   reported green.

`check-todo.py` has a CRLF half of this and no parse half. This file has both,
and it is one file so the two halves cannot drift apart.

Exit 0 when every script is clean. Exit 1 with a report naming each file, the
line, and the reason.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

# A directory whose scripts are generated or vendored, not ours to police.
SKIP_DIRS = {"node_modules", "target", ".git", ".tmp", ".work", "__pycache__"}


def scripts() -> list[Path]:
    if not SCRIPTS.is_dir():
        return []
    return sorted(p for p in SCRIPTS.rglob("*.sh")
                  if not any(part in SKIP_DIRS for part in p.parts))


def check_crlf(path: Path) -> list[str]:
    """⛔ **Any carriage return, not only `\\r\\n`.**

    An old-Mac lone `\\r` is a line ending to a reader and not to `dash`, and a
    check written as `b"\\r\\n" in raw` cannot see one. The count is reported so
    a single stray byte reads differently from a whole file written CRLF.
    """
    raw = path.read_bytes()
    if b"\r" not in raw:
        return []
    crlf = raw.count(b"\r\n")
    lone = raw.count(b"\r") - crlf
    detail = f"{crlf} CRLF line(s)" if not lone else f"{crlf} CRLF line(s) and {lone} lone CR"
    line = raw[: raw.index(b"\r")].count(b"\n") + 1
    return [f"{path.relative_to(ROOT)}:{line}: carriage return on {detail} "
            f"; dash rejects this and bash -n does not"]


def check_parses(path: Path) -> list[str]:
    """⛔ `dash -n`, never `sh -n`.

    `sh` on a Git Bash host is bash in POSIX mode: it accepts arrays, which dash
    rejects, so a check written with `sh -n` passes on exactly the files that
    break in the build image. MEASURED on this machine with a planted
    `arr+=(one two)`: `dash -n` exits 2, `bash -n` exits 0.

    ⛔ **Each shell is tried independently, and that is a message fix.** The loop
    used to `return` from its `FileNotFoundError` arm on the FIRST missing shell,
    so a host with `sh` but no `dash` was told *"neither `dash` nor `sh` is on
    PATH"* — a report that sends the reader looking for a problem that is not
    there. ⛔ `sh` alone is still reported as a problem: it is the weaker shell
    and the dash parse did not run, so this stays fail-closed.
    """
    missing: list[str] = []
    for shell in ("dash", "sh"):
        try:
            done = subprocess.run([shell, "-n", str(path)],
                                  capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            missing.append(shell)
            continue
        if done.returncode != 0:
            first = (done.stderr or done.stdout).strip().splitlines()
            detail = first[-1] if first else f"exit {done.returncode}"
            return [f"{path.relative_to(ROOT)}: does not parse under {shell} "
                    f"(exit {done.returncode}): {detail}"]
        if shell == "sh":
            return [f"{path.relative_to(ROOT)}: `dash` is not on PATH, so it "
                    f"parsed under `sh` only — the weaker shell, which accepts "
                    f"the bashisms dash rejects"]
        return []
    # ⛔ A missing shell is NOT a pass. Reporting success for a check that could
    # not run is the defect this repository has shipped three times; it is
    # reported as a failure so nobody reads a green result that verified nothing.
    return [f"{path.relative_to(ROOT)}: {' and '.join(missing)} not on PATH "
            f"(no fallback left), so the POSIX parse was NOT run"]


def main() -> int:
    problems: list[str] = []
    found = scripts()
    if not found:
        print("check-scripts: no shell scripts found", file=sys.stderr)
        return 1

    for path in found:
        problems += check_crlf(path)
        problems += check_parses(path)

    if problems:
        print("check-scripts: a shell script is not portable\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(f"\ncheck-scripts: {len(problems)} problem(s)", file=sys.stderr)
        return 1

    print(f"check-scripts: {len(found)} script(s) are LF and parse under dash")
    return 0


if __name__ == "__main__":
    sys.exit(main())
