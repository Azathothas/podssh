#!/usr/bin/env python3
"""Cheap repository checks that need no build. Exit 0 when all pass.

  1. No Rust source file under crates/, and no shell or Python script under
     scripts/, is longer than 500 lines (the operator's rule: split the
     file, never trim its comments to fit).
  2. Every relative link in the live Markdown docs resolves.
  3. No tracked file outside vendor/ carries something shaped like a live
     credential (a relay token or a Tailscale key with a real-looking secret,
     or a private key block with a body).
  4. Shell scripts use LF line endings (dash rejects CRLF; bash -n does not).
  5. Each image that builds or tests podssh is named in one place, a
     Dockerfile of .github/images/, pinned to a digest; no workflow and no
     script names one by its tag.
  6. No Rust source under crates/ makes a listener outside its allowance:
     the rule "no listener unless the user asks for it and a probe at run
     time allows the bind" (AGENTS.md, section 5). Each crate's tests/ may,
     for servers on the loopback. A planted listener must be found first.
  7. No code file (each tracked file but the documents and vendor/) holds a
     stop-sign marker, a line number of a document (NAME.md:N), or a path of
     the documents that moved (under docs/spec/ or docs/TODO/): rule 6 of
     AGENTS.md, section 5. Planted copies of each must be found first.

Each check counts the files that it read, and fails below a floor, so a
scan that read nothing never passes. `--plant-empty` runs each check on an
empty repository, where each must fail: it exits 1 when they all fail, as
they must, and 0 when one passed, which shows a floor gone.

Run it from anywhere: `python scripts/check-repo.py`. Read the exit code
directly, not through a pipe.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
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


# The one place of each image: one FROM line, pinned to an @sha256: digest.
PINNED_FROM = re.compile(r"^FROM\s+\S+@sha256:[0-9a-f]{64}\s*$")
# An image of these, named by a tag, as a workflow or a script would pull it.
IMAGE_BY_TAG = re.compile(r"\b(?:rust|alpine|python):[0-9][\w.-]*")

# Each pattern that makes or names a listening socket, and the files outside
# a crate's tests/ where it may stand. A listener that the user asks for, and
# that a probe allows, joins its row in the commit that adds it, with the
# flag that asks for it and the probe that allows it.
LISTENER_RULE = "no listener unless the user asks for it and a probe at run time allows the bind"
LISTENERS = {
    "TcpListener": [],
    "UnixListener": [],
    "UdpSocket": [],
    # The bind probes of `podssh doctor`, which close at once and never listen.
    "bind(": ["crates/podssh-cli/src/doctor/unix.rs"],
    "listen(": [],
    "socket2": [],
}
# Rule 6 of AGENTS.md in the code: the four markers (written here as escapes,
# so that this file holds none), a line number of a document, and a path of
# the documents that moved.
MARKERS = ("\u26d4", "\u26a0", "\u2b50", "\U0001f6d8")
DOC_LINE = re.compile(r"[\w./-]+\.md`?:\d")
OLD_DOCS = re.compile(r"docs/(?:sp" + r"ec|TO" + r"DO)/")
# Where a document's line, or an old path, is data rather than a citation.
# A marker is refused in each code file.
CODE_TEXT_ALLOWED = {
    "crates/podssh-todo/": "the record's checker: Markdown locations are its data",
    "crates/podssh-probe/tests/relay_facts.rs": "it checks that an old copy of the facts stays gone",
    "scripts/check-repo.py": "the check names what it refuses",
}

# The least files that each scan must read: a scan of fewer read too little
# to pass, so an empty tree passes no check. Each is far below today's count.
MIN_RUST_FILES = 100
MIN_MARKDOWN_FILES = 10
MIN_TRACKED_FILES = 150
MIN_SHELL_SCRIPTS = 5
MIN_SCRIPT_FILES = 15
MIN_CODE_FILES = 100


def too_few(what: str, count: int, floor: int) -> list[str]:
    """The problem of a scan that read fewer files than its floor."""
    return [f"{count} {what} read, fewer than {floor}: the scan read too little to pass"] if count < floor else []


def git_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    return [ROOT / p for p in out.decode("utf-8").split("\0") if p]


def check_file_size() -> list[str]:
    files = [p for p in sorted((ROOT / "crates").rglob("*.rs")) if "target" not in p.relative_to(ROOT).parts]
    scripts = [p for p in sorted((ROOT / "scripts").rglob("*"))
               if p.suffix in (".sh", ".py") and p.is_file() and "__pycache__" not in p.parts]
    problems = too_few("Rust files under crates/", len(files), MIN_RUST_FILES)
    problems += too_few("shell and Python scripts under scripts/", len(scripts), MIN_SCRIPT_FILES)
    check_file_size.note = f"{len(files)} Rust files under crates/ and {len(scripts)} scripts under scripts/ read"
    for path in files + scripts:
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
    files = live_markdown()
    problems = too_few("Markdown files", len(files), MIN_MARKDOWN_FILES)
    check_links.note = f"{len(files)} Markdown files read"
    for path in files:
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
    files = [p for p in git_files() if p.relative_to(ROOT).parts[0] != "vendor" and p.is_file()]
    problems = too_few("tracked files", len(files), MIN_TRACKED_FILES)
    check_secrets.note = f"{len(files)} tracked files read, vendor/ aside"
    for path in files:
        rel = path.relative_to(ROOT)
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
    scripts = [p for p in git_files() if p.suffix == ".sh" and p.is_file()]
    problems = too_few("shell scripts", len(scripts), MIN_SHELL_SCRIPTS)
    check_shell_line_endings.note = f"{len(scripts)} shell scripts read"
    for path in scripts:
        if b"\r" in path.read_bytes():
            problems.append(f"{path.relative_to(ROOT).as_posix()}: CR in a shell script; use LF")
    return problems


def check_images() -> list[str]:
    dockerfiles = sorted((ROOT / ".github" / "images").glob("*/Dockerfile"))
    # A check that finds nothing to check does not pass.
    if not dockerfiles:
        return [".github/images/: no Dockerfile, so no image is pinned"]
    problems = []
    for path in dockerfiles:
        rel = path.relative_to(ROOT).as_posix()
        lines = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(lines) != 1 or not PINNED_FROM.match(lines[0]):
            problems.append(f"{rel}: one FROM line, the image pinned to @sha256: and 64 hex digits")
    for path in git_files():
        rel = path.relative_to(ROOT).as_posix()
        scanned = rel.startswith(".github/workflows/") or (rel.startswith("scripts/") and path.suffix == ".sh")
        if not scanned or not path.is_file():
            continue
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if IMAGE_BY_TAG.search(line):
                problems.append(f"{rel}:{line_no}: names an image by its tag; read it from .github/images/")
    return problems


def listener_hits(root: Path) -> tuple[int, list[tuple[str, int, str]]]:
    """Each use of a listener's pattern in the Rust files under root/crates,
    outside comment lines, as (file, line, pattern); and the files read."""
    files = [p for p in sorted((root / "crates").rglob("*.rs")) if "target" not in p.relative_to(root).parts]
    hits = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if line.lstrip().startswith("//"):
                continue
            hits.extend((rel, line_no, pattern) for pattern in LISTENERS if pattern in line)
    return len(files), hits


def outside_allowance(hits: list[tuple[str, int, str]]) -> list[tuple[str, int, str]]:
    # A crate's tests/ holds servers on the loopback, for tests only.
    return [(rel, n, p) for rel, n, p in hits if "/tests/" not in rel and rel not in LISTENERS[p]]


def check_listeners() -> list[str]:
    count, hits = listener_hits(ROOT)
    # A check that reads too little does not pass.
    if count < MIN_RUST_FILES:
        return too_few("Rust files under crates/", count, MIN_RUST_FILES)
    problems = [f"{rel}:{n}: `{p}`: {LISTENER_RULE}" for rel, n, p in outside_allowance(hits)]
    # The plant: one listener in a library crate's src/ must be found, or
    # the scan proves nothing.
    with tempfile.TemporaryDirectory() as tmp:
        planted = Path(tmp) / "crates" / "podssh-ws" / "src" / "planted.rs"
        planted.parent.mkdir(parents=True)
        planted.write_text('fn planted() { let _l = std::net::TcpListener::bind("127.0.0.1:0"); }\n', encoding="utf-8")
        if not outside_allowance(listener_hits(Path(tmp))[1]):
            problems.append("the listener scan is vacuous: a planted TcpListener in crates/podssh-ws/src was not found")
    allowed = len(hits) - len(outside_allowance(hits))
    check_listeners.note = f"{count} Rust files read; {allowed} uses of a listener's pattern within the allowance"
    return problems


def code_text_hits(items) -> list[str]:
    """Each line of each (path, text) of the code that holds a marker, or,
    outside the allowance, a line number of a document or an old path."""
    problems = []
    for rel, text in items:
        allowed = any(rel == a or (a.endswith("/") and rel.startswith(a)) for a in CODE_TEXT_ALLOWED)
        for n, line in enumerate(text.splitlines(), 1):
            for marker in MARKERS:
                if marker in line:
                    problems.append(f"{rel}:{n}: the marker U+{ord(marker):04X} (AGENTS.md, rule 6)")
            if allowed:
                continue
            if DOC_LINE.search(line):
                problems.append(f"{rel}:{n}: a line number of a document; name its section, or the fact")
            if OLD_DOCS.search(line):
                problems.append(f"{rel}:{n}: a path of the documents that moved; name the one that holds the fact")
    return problems


def check_code_text() -> list[str]:
    items = []
    for path in git_files():
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(("docs/", "TODO/", "vendor/", ".tmp/")) or rel.endswith(".md") or not path.is_file():
            continue
        try:
            items.append((rel, path.read_bytes().decode("utf-8")))
        except UnicodeDecodeError:
            continue
    problems = too_few("code files", len(items), MIN_CODE_FILES)
    problems += code_text_hits(items)
    # The plants: each kind, in a code file outside the allowance, must be found.
    plants = [("crates/podssh-ws/src/frame.rs", "// " + MARKERS[0] + " planted\n"),
              ("crates/podssh-ws/src/frame.rs", "// see docs/cli" + ".md:12\n"),
              ("crates/podssh-ws/src/frame.rs", "// see docs/" + "spec/x.md\n")]
    for plant in plants:
        if not code_text_hits([plant]):
            problems.append(f"the scan of the code's text is vacuous: it did not find {plant[1].strip()!r}")
    check_code_text.note = f"{len(items)} code files read; 3 planted lines found"
    return problems


def main(argv: list[str]) -> int:
    global ROOT
    if argv == ["--plant-empty"]:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            ROOT = Path(tmp)
            return plant_empty()
    if argv:
        print("usage: python scripts/check-repo.py [--plant-empty]", file=sys.stderr)
        return 2
    return run_checks()


CHECKS = [
    ("source files at most 500 lines", check_file_size),
    ("doc links resolve", check_links),
    ("no credential-shaped strings", check_secrets),
    ("shell scripts are LF", check_shell_line_endings),
    ("each image is pinned, in one place", check_images),
    ("no listener outside its allowance", check_listeners),
    ("no marker, document line or old path in the code", check_code_text),
]


def plant_empty() -> int:
    """Each check on an empty repository: 1 when each failed, as it must."""
    passed = [name for name, check in CHECKS if not check()]
    for name in passed:
        print(f"FAIL {name}: it passed on an empty tree, so its floor is gone")
    if passed:
        return 0
    print(f"ok   each of the {len(CHECKS)} checks failed on an empty tree")
    return 1


def run_checks() -> int:
    failed = False
    for name, check in CHECKS:
        problems = check()
        print(f"{'ok  ' if not problems else 'FAIL'} {name}")
        note = getattr(check, "note", None)
        if note:
            print(f"     {note}")
        for problem in problems:
            print(f"     {problem}")
        failed = failed or bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
