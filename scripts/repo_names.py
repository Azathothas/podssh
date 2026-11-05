"""The scan of the repository's old name (check 12 of check-repo.py, T-683).

The repository moved to PodUtils/podssh on 2026-11-05. GitHub's redirect
hides the old name for a time only: a name left behind breaks once another
repository takes the old place, and `podssh update` refuses each release
whose signer names another repository. Dated records keep the old name.
"""

from __future__ import annotations

import re
from pathlib import Path

# Written in two parts, so that this file holds no copy of the name.
OLD_NAME = re.compile("Azathothas" + r"/podssh\b", re.IGNORECASE)

# Where the old name is a dated record or a test of its refusal.
NAMES_ALLOWED = {
    "docs/releases/": "the notes of each release, as published",
    "docs/STATUS.md": "dated measurements, with the runs and issues of their day",
    "docs/decisions.md": "dated rulings, in the words of their day",
    "docs/research/": "dated studies",
    "TODO/": "dated entries and their proofs (the live headers are scanned: see SCANNED_RECORDS)",
    "vendor/": "the record of the vendored patches, by the issue of their day",
    "crates/podssh-cli/src/update/sigstore_tests.rs": "a bundle that a release signed under the old name",
    "crates/podssh-cli/tests/update.rs": "a leaf of the old name, which must be refused",
}
# Files under an allowed place that still describe the repository as it is.
SCANNED_RECORDS = {"TODO/github.txt", "TODO/issues.md", "TODO/RULES.md"}

PLANTED = 'repository = "https://github.com/' + "Azathothas" + '/podssh"\n'


def allowed(rel: str) -> bool:
    if rel in SCANNED_RECORDS:
        return False
    return any(rel == p or (p.endswith("/") and rel.startswith(p)) for p in NAMES_ALLOWED)


def name_hits(root: Path, files: list[Path]) -> tuple[int, list[str]]:
    """The files read, and each `FILE:LINE` that names the old repository."""
    read, hits = 0, []
    for path in files:
        rel = path.relative_to(root).as_posix()
        if allowed(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        read += 1
        for number, line in enumerate(text.splitlines(), 1):
            if OLD_NAME.search(line):
                hits.append(f"{rel}:{number}")
    return read, hits


def planted_name_found() -> bool:
    return bool(OLD_NAME.search(PLANTED))
