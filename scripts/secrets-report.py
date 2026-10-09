#!/usr/bin/env python3
"""The findings of TruffleHog, read from its JSON lines, printed with no
secret in them.

  python scripts/secrets-report.py FOUND.jsonl
  python scripts/secrets-report.py --expect DETECTOR FOUND.jsonl

Each finding prints as its state (verified, unknown or unverified), the
detector, the file and line, and the commit; never its raw value, its
redacted form or its extra data, as the logs of a public repository are
public. Exit 1 when a finding is verified, or could not be verified
(unknown); an unverified finding is a note. With --expect, exit 0 only when
a finding of DETECTOR is there: the check of a plant. Exit 2 when FOUND
cannot be read: a check that cannot run is not a pass.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def state(finding: dict) -> str:
    if finding.get("Verified") is True:
        return "verified"
    if finding.get("VerificationError"):
        return "unknown"
    return "unverified"


def place(finding: dict) -> str:
    git = (((finding.get("SourceMetadata") or {}).get("Data") or {}).get("Git")) or {}
    file = str(git.get("file") or "?")
    line = git.get("line")
    commit = str(git.get("commit") or "?")[:12]
    return f"{file}:{line if isinstance(line, int) else '?'} at {commit}"


def findings(path: Path) -> list[dict]:
    found = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            item = json.loads(raw)
        except ValueError:
            continue
        # A log line of the scanner is JSON too; a finding names a detector.
        if isinstance(item, dict) and item.get("DetectorName"):
            found.append(item)
    return found


def main(argv: list[str]) -> int:
    expect = None
    if len(argv) == 3 and argv[0] == "--expect":
        expect, argv = argv[1], argv[2:]
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        return 2
    path = Path(argv[0])
    try:
        found = findings(path)
    except OSError as e:
        print(f"secrets-report: {path}: {e.strerror}", file=sys.stderr)
        return 2
    for finding in found:
        print(f"{state(finding):<10} {str(finding.get('DetectorName'))[:40]:<20} {place(finding)}")
    if expect is not None:
        hit = any(str(f.get("DetectorName")) == expect for f in found)
        print(f"secrets-report: {'a' if hit else 'no'} finding of {expect}")
        return 0 if hit else 1
    bad = [f for f in found if state(f) != "unverified"]
    print(f"secrets-report: {len(found)} findings, {len(bad)} verified or unknown")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
