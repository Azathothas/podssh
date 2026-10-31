#!/usr/bin/env python3
"""The upstreams of the vendored crates against what vendor/README.md names (T-341).

Dependabot moves no path package, so nothing else says that iroh-relay or
the Tailscale fork released again (russh was one until T-356 took crates.io's
0.65.0, which Dependabot and cargo-deny see). For each section of vendor/README.md
that a copy under vendor/ still has, this reads the upstream's newest release
(crates.io's max_stable_version, or the repository's latest release on
GitHub) and compares it with the version of the copy and with the section's
line "- **Upstream read**: VERSION on DATE", the newest release that a session
read and judged. .github/workflows/upstream.yml runs it each week.

Exit codes, and they are not interchangeable:

    0   each upstream's newest release is the copy's or the one judged
    1   an upstream released again: each crate is named; read the release,
        judge it, then move the copy or the line "Upstream read"
    2   an upstream, a manifest or vendor/README.md could not be read. Never
        a pass.

Usage:
    check-vendored.py                     live; GH_TOKEN, when set, for GitHub
    check-vendored.py --offline DIR       DIR/NAME.json, the APIs' answers
    check-vendored.py --plant-read NAME   the copy of NAME, or of the first crate
                                          with `first`, and its line "Upstream
                                          read" taken as 0.0.0, so that its newest
                                          release is new to both: the check must fail
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "vendor" / "README.md"
# The section of vendor/README.md, where its upstream releases, and the
# manifest of the copy with the keys of its version.
WATCHES = [
    ("iroh-relay", "crates.io", "iroh-relay", "vendor/iroh-relay/Cargo.toml", ("package", "version")),
    ("tailscale-rs", "github", "tailscale/tailscale-rs", "vendor/tailscale-rs/Cargo.toml",
     ("workspace", "package", "version")),
]
URLS = {
    "crates.io": "https://crates.io/api/v1/crates/{0}",
    "github": "https://api.github.com/repos/{0}/releases/latest",
}
READ = re.compile(r"^- \*\*Upstream read\*\*: `?v?(\S+?)`? on (\d{4}-\d{2}-\d{2})\b", re.M)
TIMEOUT_SECONDS = 30
# crates.io asks each client to name itself (its data access policy).
USER_AGENT = "podssh-check-vendored/1 (https://github.com/Azathothas/podssh)"


def sections(text: str) -> dict[str, str]:
    """The level-2 sections of vendor/README.md, by their heading."""
    found: dict[str, str] = {}
    for part in re.split(r"^## ", text, flags=re.M)[1:]:
        heading, _, body = part.partition("\n")
        found[heading.strip()] = body
    return found


def get(url: str) -> dict:
    headers = {"user-agent": USER_AGENT, "accept": "application/json"}
    token = os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=TIMEOUT_SECONDS) as answer:
        return json.loads(answer.read().decode("utf-8"))


def newest(kind: str, answer: dict) -> str:
    """The newest release in an API's answer, with no `v` before it."""
    found = answer["crate"]["max_stable_version"] if kind == "crates.io" else answer["tag_name"]
    if not found:
        raise ValueError("the answer names no release")
    return found.removeprefix("v")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--offline", default=None, metavar="DIR")
    parser.add_argument("--plant-read", default=None, metavar="NAME")
    args = parser.parse_args()
    rows, problems = [], []
    try:
        by_heading = sections(README.read_text(encoding="utf-8"))
        watched = [w for w in WATCHES if w[0] in by_heading or (ROOT / w[3]).exists()]
        if not watched:
            raise ValueError("vendor/README.md and vendor/ name no vendored crate: nothing would be checked")
        plant = watched[0][0] if args.plant_read == "first" else args.plant_read
        if plant and plant not in [w[0] for w in watched]:
            raise ValueError(f"--plant-read {plant}: no such section")
        for name, kind, upstream, manifest, keys in watched:
            if name not in by_heading or not (ROOT / manifest).exists():
                raise ValueError(f"{name}: vendor/README.md and {manifest} must both be there, or neither")
            value = tomllib.loads((ROOT / manifest).read_text(encoding="utf-8"))
            for key in keys:
                value = value[key]
            read = READ.search(by_heading[name])
            if not read:
                raise ValueError(f"vendor/README.md, section {name}: no line \"- **Upstream read**: VERSION on DATE\"")
            judged, day = ("0.0.0", "a plant") if name == plant else (read[1], read[2])
            if name == plant:
                value = "0.0.0"
            if args.offline:
                answer = json.loads((Path(args.offline) / f"{name}.json").read_text(encoding="utf-8"))
            else:
                answer = get(URLS[kind].format(upstream))
            rows.append((name, value, judged, day, newest(kind, answer)))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, tomllib.TOMLDecodeError,
            urllib.error.URLError) as exc:
        print(f"check-vendored: {exc}", file=sys.stderr)
        print("check-vendored: exiting 2. A check that could not run is not a pass.", file=sys.stderr)
        return 2
    for name, value, judged, day, release in rows:
        print(f"{name}: the copy is {value}; read and judged {judged} on {day}; the newest release is {release}")
        if release not in (value, judged):
            problems.append(f"{name} released {release}, which is neither the copy ({value}) nor the one judged "
                            f"({judged})")
    for problem in problems:
        print(f"FAIL {problem}")
    if problems:
        print("check-vendored: read each release named, judge it, then move the copy, or the line \"Upstream "
              "read\" of its section of vendor/README.md with what was judged", file=sys.stderr)
        return 1
    print(f"ok   the {len(rows)} upstreams have released nothing that was not read")
    return 0


if __name__ == "__main__":
    sys.exit(main())
