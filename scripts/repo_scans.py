"""Scans of scripts/check-repo.py, each on a tree's root, so that a check can
run it on the repository and on a tree with a planted defect. Apart from
check-repo.py so that each file stays within 500 lines.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

# A step's action, and the forms that pin it: a commit of 40 hexadecimal
# digits, an action of this repository, or an image by its digest.
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?(?P<ref>[^\s'\"#]+)")
PINNED_USES = re.compile(r"^(?:[\w.-]+/[\w./-]+@[0-9a-f]{40}|\./\S+|docker://\S+@sha256:[0-9a-f]{64})$")

# The macros of std that panic when their write fails: the release build
# aborts on a panic, so a node whose log's disk filled would end at its next
# line (T-389). The sources use podssh_ssh's `err_line!` and `out_line!`.
PRINT = re.compile(r"\b(?P<macro>eprintln|println|eprint|print|dbg)!\s*[(\[{]")
PRINT_RULE = "a write that fails must not end podssh: use podssh_ssh's err_line! or out_line! (T-389)"
# A module of tests in a source file, which runs under the test harness.
TEST_MODULE = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")
MOD_OPEN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{")


def unpinned_uses(root: Path) -> tuple[int, list[tuple[str, int, str]]]:
    """Each `uses:` of the workflows under root that names no commit, as
    (file, line, reference); and the count of `uses:` read."""
    count, hits = 0, []
    workflows = root / ".github" / "workflows"
    for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        rel = path.relative_to(root).as_posix()
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            found = USES.match(line)
            if not found:
                continue
            count += 1
            if not PINNED_USES.match(found.group("ref")):
                hits.append((rel, line_no, found.group("ref")))
    return count, hits


def _is_test_file(rel: Path) -> bool:
    """A file of tests inside src/: `tests.rs`, `*_tests.rs`, or one under a
    directory `tests`."""
    name = rel.name
    return name == "tests.rs" or name.endswith("_tests.rs") or any(p == "tests" for p in rel.parts[:-1])


def code_lines(text: str):
    """Each (line number, line) of the code outside comments and outside a
    module of tests (`#[cfg(test)]` on a `mod NAME {`, to its closing brace,
    counted by braces; to the file's end when the count does not close)."""
    lines = text.splitlines()
    n = 0
    while n < len(lines):
        line = lines[n]
        if TEST_MODULE.match(line) and n + 1 < len(lines) and MOD_OPEN.match(lines[n + 1]):
            depth, k = 0, n + 1
            while k < len(lines):
                depth += lines[k].count("{") - lines[k].count("}")
                if depth <= 0:
                    break
                k += 1
            n = k + 1
            continue
        stripped = line.lstrip()
        if not stripped.startswith("//"):
            yield n + 1, line
        n += 1


def print_hits(root: Path) -> tuple[int, list[tuple[str, int, str]]]:
    """Each use of a macro of PRINT in the sources under root/crates/*/src,
    outside comments and tests, as (file, line, macro); and the files read."""
    files = [p for p in sorted((root / "crates").glob("*/src/**/*.rs")) if "target" not in p.parts]
    hits = []
    for path in files:
        rel = path.relative_to(root)
        if _is_test_file(rel.relative_to(*rel.parts[:3])):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, line in code_lines(text):
            # A macro named inside a string, such as a message about it, is
            # text: only the code before the first quote is read.
            code = line.split('"', 1)[0]
            hits.extend((rel.as_posix(), line_no, m.group("macro")) for m in PRINT.finditer(code))
    return len(files), hits


def planted_prints_found(root: Path) -> set[str]:
    """A print planted in a source under root, and one in a module of tests:
    the files that the scan finds, which must be the first alone."""
    src = root / "crates" / "podssh-ws" / "src"
    src.mkdir(parents=True)
    (src / "planted.rs").write_text('fn planted() { eprintln!("x"); }\n', encoding="utf-8")
    (src / "tested.rs").write_text('#[cfg(test)]\nmod tests {\n    fn t() { println!("x"); }\n}\n', encoding="utf-8")
    return {rel for rel, _, _ in print_hits(root)[1]}


# The manifests whose `[patch.crates-io]` puts a copy of vendor/ in the place
# of a release (T-460), each with its lock file.
PATCHED = [("Cargo.toml", "Cargo.lock"), ("fuzz/Cargo.toml", "fuzz/Cargo.lock")]
PATCH_RULE = "the lock builds the release in place of the copy of vendor/: move the patch first (vendor/README.md)"


def patch_misses(manifest: str, lock: str) -> tuple[int, list[str]]:
    """Each package of the manifest's `[patch.crates-io]` that the lock does
    not take from its path, and each `[[patch.unused]]` of the lock: an
    update of the crate that did not move the copy builds the release, with
    none of the patch, and cargo only warns. The count is of the patches read."""
    patched = ((tomllib.loads(manifest).get("patch") or {}).get("crates-io") or {})
    locked = tomllib.loads(lock)
    misses = [f"[[patch.unused]] names {u.get('name')} {u.get('version')}"
              for u in (locked.get("patch") or {}).get("unused", [])]
    for name in sorted(patched):
        found = [p for p in locked.get("package", []) if p.get("name") == name]
        if not found:
            misses.append(f"{name} is patched, and no package of the lock has that name")
        misses.extend(f"{name} {p.get('version')} comes from {p['source']}" for p in found if "source" in p)
    return len(patched), misses
