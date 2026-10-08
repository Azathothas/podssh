#!/usr/bin/env python3
"""Cheap repository checks that need no build. Exit 0 when all pass.

  1. No Rust source file under crates/ is longer than 500 lines (the
     operator's rule: split the file, never trim its comments to fit).
  2. Every relative link in the live Markdown docs resolves.
  3. No tracked file outside vendor/ carries something shaped like a live
     credential (a relay token or a Tailscale key with a real-looking secret,
     or a private key block with a body).
  4. Shell scripts use LF line endings (dash rejects CRLF; bash -n does not).

Run it from anywhere: `python scripts/check-repo.py`. Read the exit code
directly, not through a pipe.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_SOURCE_LINES = 500

# Markdown whose links are checked.
LIVE_DOCS = ["README.md", "AGENTS.md", "SECURITY.md", "docs", "TODO"]

LINK = re.compile(r"\[[^\]]*\]\((?P<target>[^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^(```|~~~)")

# A relay token is `ephm1.<expiry-ms>.<role>.<mac>`. Test fixtures use MACs
# like `0000...` or `TESTONLYNOTACREDENTIAL`; a real MAC mixes letters and
# digits, so only that shape is flagged. `/` is left out of the class so a
# token embedded in a URL path stops at the path separator.
RELAY_TOKEN = re.compile(r"ephm1\.\d{10,}\.[a-z_]+\.(?P<mac>[A-Za-z0-9+=_-]{16,})")
# A Tailscale key is `tskey-<kind>-<id>-<secret>`. Fixtures are short words.
TS_KEY = re.compile(r"tskey-(?:auth|client|api)-[A-Za-z0-9]{6,}-[A-Za-z0-9]{16,}")
# A private key block: the header, then at least three full lines of base64.
# A header alone (in code that recognises one) or a one-line fragment (in a
# test that feeds a parser a truncated block) is not a key. `podssh keygen`
# writes such blocks, which is why this is checked.
PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\r?\n(?:[A-Za-z0-9+/=:\-]*\r?\n)?(?:[A-Za-z0-9+/=]{60,}\r?\n){3}"
)


def git_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    return [ROOT / p for p in out.decode("utf-8").split("\0") if p]


def check_file_size() -> list[str]:
    problems = []
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        if "target" in path.relative_to(ROOT).parts:
            continue
        lines = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        if lines > MAX_SOURCE_LINES:
            problems.append(
                f"{path.relative_to(ROOT).as_posix()}: {lines} lines, over {MAX_SOURCE_LINES}; split it"
            )
    return problems


def live_markdown() -> list[Path]:
    files = []
    for entry in LIVE_DOCS:
        path = ROOT / entry
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(path.rglob("*.md")))
    return files


def check_links() -> list[str]:
    problems = []
    for path in live_markdown():
        in_fence = False
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if FENCE.match(line.strip()):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for match in LINK.finditer(line):
                target = match.group("target").split("#", 1)[0]
                if not target or re.match(r"^[a-z]+:", target):
                    continue  # anchors, http(s), mailto
                if not (path.parent / target).exists():
                    problems.append(
                        f"{path.relative_to(ROOT).as_posix()}:{line_no}: broken link -> {target}"
                    )
    return problems


def check_secrets() -> list[str]:
    problems = []
    for path in git_files():
        rel = path.relative_to(ROOT)
        if rel.parts[0] == "vendor" or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary
        for match in RELAY_TOKEN.finditer(text):
            mac = match.group("mac")
            if len(set(mac)) >= 6 and re.search(r"\d", mac) and re.search(r"[A-Za-z]", mac):
                line_no = text.count("\n", 0, match.start()) + 1
                problems.append(f"{rel.as_posix()}:{line_no}: looks like a live relay token")
        for match in TS_KEY.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            problems.append(f"{rel.as_posix()}:{line_no}: looks like a Tailscale key")
        for match in PRIVATE_KEY.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            problems.append(f"{rel.as_posix()}:{line_no}: a private key")
    return problems


def check_shell_line_endings() -> list[str]:
    problems = []
    for path in git_files():
        if path.suffix == ".sh" and path.is_file() and b"\r" in path.read_bytes():
            problems.append(f"{path.relative_to(ROOT).as_posix()}: CR in a shell script; use LF")
    return problems


def main() -> int:
    checks = [
        ("source files at most 500 lines", check_file_size),
        ("doc links resolve", check_links),
        ("no credential-shaped strings", check_secrets),
        ("shell scripts are LF", check_shell_line_endings),
    ]
    failed = False
    for name, check in checks:
        problems = check()
        print(f"{'ok  ' if not problems else 'FAIL'} {name}")
        for problem in problems:
            print(f"     {problem}")
        failed = failed or bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
