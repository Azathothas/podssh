#!/usr/bin/env python3
"""cloudflared's newest release against the pin of podssh's quick tunnel (T-339).

podssh speaks cloudflared's protocol, which publishes no contract, as the
release of crates/podssh-relay/src/quick/cloudflared-pin.txt speaks it. This
reads cloudflared's newest release, then each file of the table at its tag,
and compares the file's SHA-256 with the sums that the table holds for it.
It makes no tunnel. .github/workflows/upstream.yml runs it each week.

Exit codes, and they are not interchangeable:

    0   each file of the newest release holds bytes that the table knows, and
        the pin is younger than 9 months.
    1   a file moved, each one named, or the pin is 9 months old: read the
        change, then move the pin, or add the release's sum to its file's
        line with the reason.
    2   the release or a file could not be read. Never a pass.

Usage:
    check-upstream.py                   live; GH_TOKEN, when set, for the API
    check-upstream.py --offline DIR     DIR/release.json and DIR/files/PATH
    check-upstream.py --plant-sum PATH  the table's sums of PATH replaced, so
                                        the check must fail, and name PATH
    check-upstream.py --today DATE      the pin's age as at DATE (YYYY-MM-DD)
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = ROOT / "crates" / "podssh-relay" / "src" / "quick" / "cloudflared-pin.txt"
REPO = "cloudflare/cloudflared"
RELEASE = f"https://api.github.com/repos/{REPO}/releases/latest"
RAW = f"https://raw.githubusercontent.com/{REPO}/{{tag}}/{{path}}"
# Nine months: Cloudflare supports a cloudflared for a year after its newest
# release, and the move of the pin takes the months that are left.
OLDEST = datetime.timedelta(days=274)
TIMEOUT_SECONDS = 30
USER_AGENT = "podssh-check-upstream/1"


def read_pin(path: Path) -> dict:
    """The table: its tag, commit and day, and each file's accepted sums."""
    pin: dict = {"files": {}}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, rest = line.partition(" ")
        if key in ("tag", "commit", "released") and rest:
            pin[key] = rest.strip()
        elif key == "file" and len(rest.split()) == 2 and len(rest.split()[1]) == 64:
            name, digest = rest.split()
            pin["files"].setdefault(name, set()).add(digest)
        else:
            raise ValueError(f"{path.name}:{number}: not a line of the table: {raw!r}")
    for key in ("tag", "commit", "released"):
        if key not in pin:
            raise ValueError(f"{path.name} names no {key}")
    if not pin["files"]:
        raise ValueError(f"{path.name} names no file, so nothing would be checked")
    pin["released"] = datetime.date.fromisoformat(pin["released"])
    return pin


def get(url: str) -> bytes:
    headers = {"user-agent": USER_AGENT}
    token = os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.read()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--offline", default=None, metavar="DIR")
    parser.add_argument("--plant-sum", default=None, metavar="PATH")
    parser.add_argument("--today", default=None, metavar="DATE")
    args = parser.parse_args()
    try:
        pin = read_pin(PIN)
        today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
        if args.plant_sum:
            if args.plant_sum not in pin["files"]:
                raise ValueError(f"--plant-sum {args.plant_sum}: the table names no such file")
            pin["files"][args.plant_sum] = {"0" * 64}
        if args.offline:
            base = Path(args.offline)
            release = json.loads((base / "release.json").read_text(encoding="utf-8"))
            fetch = lambda name: (base / "files" / name).read_bytes()  # noqa: E731
        else:
            release = json.loads(get(RELEASE).decode("utf-8"))
            fetch = lambda name: get(RAW.format(tag=release["tag_name"], path=name))  # noqa: E731
        tag = release["tag_name"]
        digests = {name: hashlib.sha256(fetch(name)).hexdigest() for name in sorted(pin["files"])}
    except (OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        print(f"check-upstream: {exc}", file=sys.stderr)
        print("check-upstream: exiting 2. A check that could not run is not a pass.", file=sys.stderr)
        return 2

    problems = []
    for name, digest in digests.items():
        if digest not in pin["files"][name]:
            problems.append(f"{name} holds other bytes at {tag} (sha256 {digest[:16]}) than at the pin "
                            f"{pin['tag']} or at a release read since")
    age = today - pin["released"]
    if age >= OLDEST:
        problems.append(f"the pin {pin['tag']} of {pin['released']} is {age.days} days old: move it to a newer "
                        f"release before Cloudflare's year of support ends")
    print(f"cloudflared: the newest release is {tag}; the pin is {pin['tag']} ({pin['commit'][:7]}, "
          f"{pin['released']}, {age.days} days old)")
    for problem in problems:
        print(f"FAIL {problem}")
    if problems:
        print("check-upstream: read the change of each file named, then move the pin, or add the release's sum "
              "to that file's line of the table with the reason", file=sys.stderr)
        return 1
    print(f"ok   each of the {len(digests)} files at {tag} holds bytes that the table knows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
