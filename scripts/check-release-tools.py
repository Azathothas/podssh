#!/usr/bin/env python3
"""The tools of the release and of CI that no lock pins (T-343), against
their sources, each week: Zig's community mirrors against the copy that
scripts/fetch-zig.sh reads (scripts/zig-mirrors.txt), and PyPI's newest
check-jsonschema against the version that .github/workflows/build.yml runs.

Exit 1 names what moved, and what to do; 0 when each agrees. A plant changes
the copy as read, and must exit 1: --plant-mirror adds a mirror that
ziglang.org does not list, --plant-pin pins a version that PyPI's newest is
not.
"""

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIRRORS = "https://ziglang.org/download/community-mirrors.txt"
PYPI = "https://pypi.org/pypi/check-jsonschema/json"


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as answer:
        return answer.read().decode("utf-8")


def mirrors_of(text: str) -> set:
    return {line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plant-mirror", action="store_true")
    parser.add_argument("--plant-pin", action="store_true")
    args = parser.parse_args()
    problems = []

    copy = mirrors_of((ROOT / "scripts" / "zig-mirrors.txt").read_text(encoding="utf-8"))
    if args.plant_mirror:
        copy.add("https://planted.invalid/zig")
    listed = mirrors_of(fetch(MIRRORS))
    if copy != listed:
        problems.append(
            f"scripts/zig-mirrors.txt is not {MIRRORS}: new {sorted(listed - copy)}, gone {sorted(copy - listed)}; "
            "copy the list again"
        )
    else:
        print(f"ok   scripts/zig-mirrors.txt: the {len(copy)} mirrors of {MIRRORS}")

    workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
    pins = sorted(set(re.findall(r"check-jsonschema==([0-9][0-9A-Za-z.]*)", workflow)))
    if len(pins) != 1:
        problems.append(f"build.yml pins check-jsonschema as {pins or 'nothing'}, not one version")
    else:
        pin = "0.0.0" if args.plant_pin else pins[0]
        newest = json.loads(fetch(PYPI))["info"]["version"]
        if pin != newest:
            problems.append(
                f"build.yml runs check-jsonschema=={pin}, and PyPI's newest is {newest}: read its changes, "
                "then move the pin"
            )
        else:
            print(f"ok   check-jsonschema=={pin}, PyPI's newest")

    for problem in problems:
        print(f"FAIL {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
