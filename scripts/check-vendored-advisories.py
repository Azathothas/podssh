#!/usr/bin/env python3
"""The advisories of the crates that podssh builds from a path (T-341).

cargo-deny matches an advisory to a package of crates.io's source and passes
over a path package: an advisory planted for russh 0.64.1, which vendor/russh
held, passed `cargo deny check advisories`, while the same advisory for base64
failed it (measured 2026-10-31). So this reads cargo-deny's copy of
advisory-db for each package of the lock files that has no source and is not
podssh's own (vendor/, the Tailscale fork), and fails on an advisory whose
patched and unaffected versions leave out the version built. The ignores of
deny.toml hold here too. .github/workflows/deny.yml runs it after cargo-deny
has fetched the database.

Exit codes, and they are not interchangeable:

    0   no advisory names a version that podssh builds from a path
    1   an advisory names one: each is printed with its id and its crate
    2   a lock file, deny.toml or the database could not be read. Never a pass.

Usage:
    check-vendored-advisories.py [--db DIR]  DIR is advisory-db; default: the
                                             newest ~/.cargo/advisory-dbs/advisory-db-*
    check-vendored-advisories.py --self-test planted databases and lock files,
                                             each of which must fail or pass
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCKS = [ROOT / "Cargo.lock", ROOT / "fuzz" / "Cargo.lock"]
DENY = ROOT / "deny.toml"
FENCE = re.compile(r"```toml\n(.*?)\n```", re.S)
COMPARATOR = re.compile(r"^(=|>=|<=|>|<|~|\^)?\s*(\*|\d+(?:\.(?:\d+|\*))?(?:\.(?:\d+|\*))?)(?:-([0-9A-Za-z.-]+))?$")
VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def key(major: int, minor: int, patch: int, pre: str | None = None) -> tuple:
    """A version's order (semver 2.0.0, 11): a pre-release comes before its
    release; its identifiers compare as numbers when they are digits."""
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")) if pre else ()
    return (major, minor, patch, 0 if pre else 1, parts)


def version(text: str) -> tuple:
    match = VERSION.match(text.strip())
    if not match:
        raise ValueError(f"not a version: {text!r}")
    return key(int(match[1]), int(match[2]), int(match[3]), match[4])


def bounds(op: str, partial: str, pre: str | None) -> tuple:
    """The range of one comparator as (lower, upper), each None or (key,
    inclusive), as Cargo reads a requirement."""
    if partial == "*":
        return None, None
    nums = [None if n == "*" else int(n) for n in partial.split(".")] + [None, None]
    major, minor, patch = nums[0], nums[1], nums[2]
    low = key(major, minor or 0, patch or 0, pre)
    if minor is None:
        next_up = key(major + 1, 0, 0)
    elif patch is None:
        next_up = key(major, minor + 1, 0)
    else:
        next_up = None
    if op == "=":
        return (low, True), ((next_up, False) if next_up else (low, True))
    if op == ">=":
        return (low, True), None
    if op == ">":
        return ((next_up, True) if next_up else (low, False)), None
    if op == "<":
        return None, (low, False)
    if op == "<=":
        return None, ((next_up, False) if next_up else (low, True))
    if op == "~":
        up = key(major + 1, 0, 0) if minor is None else key(major, minor + 1, 0)
        return (low, True), (up, False)
    # A caret, written or not: the leftmost number that is not zero stays.
    if major > 0 or minor is None:
        up = key(major + 1, 0, 0)
    elif minor > 0 or patch is None:
        up = key(0, minor + 1, 0)
    else:
        up = key(0, 0, patch + 1)
    return (low, True), (up, False)


def matches(requirement: str, built: tuple) -> bool:
    """Whether `built` meets each comparator of `requirement` ("A, B")."""
    for part in requirement.split(","):
        found = COMPARATOR.match(part.strip())
        if not found:
            raise ValueError(f"not a requirement: {requirement!r}")
        low, up = bounds(found[1] or "^", found[2], found[3])
        if low and (built < low[0] or (built == low[0] and not low[1])):
            return False
        if up and (built > up[0] or (built == up[0] and not up[1])):
            return False
    return True


def path_packages(locks: list[Path]) -> dict[str, set[str]]:
    """Each package of the locks with no source, but podssh's own."""
    found: dict[str, set[str]] = {}
    for lock in locks:
        if not lock.exists():
            continue
        for package in tomllib.loads(lock.read_text(encoding="utf-8")).get("package", []):
            if "source" not in package and not package["name"].startswith("podssh"):
                found.setdefault(package["name"], set()).add(package["version"])
    if not found:
        raise ValueError("the lock files name no path package: nothing would be checked")
    return found


def ignored(deny: Path) -> set[str]:
    entries = tomllib.loads(deny.read_text(encoding="utf-8")).get("advisories", {}).get("ignore", [])
    return {entry if isinstance(entry, str) else entry["id"] for entry in entries}


def check(db: Path, packages: dict[str, set[str]], ignore: set[str]) -> tuple[list[str], list[str]]:
    """The advisories that name a version built, and the notices."""
    if not (db / "crates").is_dir():
        raise ValueError(f"{db} holds no crates/: not advisory-db")
    failed, notes = [], []
    for name, versions in sorted(packages.items()):
        for path in sorted((db / "crates" / name).glob("*.md")):
            fence = FENCE.search(path.read_text(encoding="utf-8"))
            if not fence:
                raise ValueError(f"{path}: no TOML block")
            data = tomllib.loads(fence[1])
            advisory, ranges = data.get("advisory", {}), data.get("versions", {})
            if advisory.get("withdrawn") or advisory.get("id") in ignore:
                continue
            safe = ranges.get("patched", []) + ranges.get("unaffected", [])
            for built in sorted(versions):
                if any(matches(requirement, version(built)) for requirement in safe):
                    continue
                line = f"{advisory.get('id')} names {name} {built}, which podssh builds from a path: " \
                       f"patched {ranges.get('patched', [])}"
                (notes if advisory.get("informational") == "notice" else failed).append(line)
    return failed, notes


def newest_db() -> Path:
    found = sorted((Path.home() / ".cargo" / "advisory-dbs").glob("advisory-db-*"), key=lambda p: p.stat().st_mtime)
    if not found:
        raise ValueError("no ~/.cargo/advisory-dbs/advisory-db-*: run cargo deny check advisories first")
    return found[-1]


def run(db: Path, locks: list[Path], deny: Path) -> int:
    try:
        packages = path_packages(locks)
        failed, notes = check(db, packages, ignored(deny))
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f"check-vendored-advisories: {exc}", file=sys.stderr)
        print("check-vendored-advisories: exiting 2. A check that could not run is not a pass.", file=sys.stderr)
        return 2
    built = ", ".join(f"{name} {' '.join(sorted(v))}" for name, v in sorted(packages.items()))
    print(f"the advisories of {db.name} for the path packages: {built}")
    for line in notes:
        print(f"note {line}")
    for line in failed:
        print(f"FAIL {line}")
    if failed:
        print("check-vendored-advisories: move the vendored copy to a patched release, or judge the advisory "
              "and ignore it in deny.toml with the reason", file=sys.stderr)
        return 1
    print(f"ok   no advisory names a version of the {len(packages)} path packages")
    return 0


ADVISORY = """```toml
[advisory]
id = "{id}"
package = "{name}"
date = "2026-10-31"
{extra}
[versions]
{versions}
```

# A planted advisory
"""


def self_test() -> int:
    """Each planted case of a database and a lock: the exit that it must give."""
    cases = [  # (requirement, version, whether it matches)
        (">= 0.64.2", "0.64.1", False), (">= 0.64.1", "0.64.1", True), ("^0.63.1", "0.63.9", True),
        ("^0.63.1", "0.64.0", False), ("^1.2", "1.9.0", True), ("^1.2", "2.0.0", False), ("~1.2.3", "1.2.9", True),
        ("~1.2.3", "1.3.0", False), ("< 0.2.0", "0.1.9", True), (">= 1.0.0, < 1.2.0", "1.2.0", False),
        ("^0.0.3", "0.0.4", False), ("=1.4.1", "1.4.1", True), ("*", "9.9.9", True), (">= 1.0.0-rc.1", "1.0.0", True),
        ("1.2", "1.2.7", True), ("> 1.2", "1.2.9", False), ("<= 1.2", "1.2.9", True),
    ]
    wrong = [case for case in cases if matches(case[0], version(case[1])) != case[2]]
    for requirement, built, expected in wrong:
        print(f"FAIL {requirement!r} against {built}: matched is {not expected}, not {expected}")
    with tempfile.TemporaryDirectory() as scratch:
        base = Path(scratch)
        lock = base / "Cargo.lock"
        lock.write_text('version = 4\n\n[[package]]\nname = "planted-crate"\nversion = "1.2.3"\n\n'
                        '[[package]]\nname = "podssh-own"\nversion = "1.0.0"\n', encoding="utf-8")
        deny = base / "deny.toml"
        deny.write_text('[advisories]\nignore = [{ id = "RUSTSEC-2099-0006", reason = "planted" }]\n', encoding="utf-8")
        plants = [  # (what, versions, the advisory's other lines, the exit)
            ("patched past the version built", 'patched = [">= 1.2.4"]', "", 1),
            ("the control: patched at the version built", 'patched = [">= 1.2.3"]', "", 0),
            ("unaffected", 'patched = [">= 2.0.0"]\nunaffected = ["< 1.3.0"]', "", 0),
            ("withdrawn", 'patched = [">= 9.0.0"]', 'withdrawn = "2026-10-31"', 0),
            ("no patched release", "", 'informational = "unmaintained"', 1),
            ("ignored in deny.toml", 'patched = [">= 9.0.0"]', "", 0),
        ]
        for number, (what, versions, extra, want) in enumerate(plants, 1):
            db = base / f"db{number}"
            (db / "crates" / "planted-crate").mkdir(parents=True)
            advisory_id = f"RUSTSEC-2099-000{number}"
            (db / "crates" / "planted-crate" / f"{advisory_id}.md").write_text(
                ADVISORY.format(id=advisory_id, name="planted-crate", extra=extra, versions=versions), encoding="utf-8")
            got = run(db, [lock], deny)
            if got != want:
                wrong.append(what)
                print(f"FAIL the plant {what!r} exited {got}, not {want}")
        if run(base / "nowhere", [lock], deny) != 2:
            wrong.append("no database")
            print("FAIL a database that is not there did not exit 2")
    if wrong:
        return 1
    print(f"ok   the self-test: {len(cases)} requirements and {len(plants) + 1} planted databases")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--db", default=None, metavar="DIR")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        db = Path(args.db) if args.db else newest_db()
    except ValueError as exc:
        print(f"check-vendored-advisories: {exc}; exiting 2", file=sys.stderr)
        return 2
    return run(db, LOCKS, DENY)


if __name__ == "__main__":
    sys.exit(main())
