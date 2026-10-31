#!/usr/bin/env python3
"""The relay's limits in /relays.json against the facts of podssh (T-342).

podssh compiles in the relay's idle cut, its caps of a session and its cap of a
frame, and narrows or widens them at run time from a cached /relays.json. This
reads the live document's "limits" for a target and compares each with
crates/podssh-probe/facts/relay-limits.toml, which a test of podssh-relay ties
to the compiled constants. It makes no session.

Exit codes, and they are not interchangeable:

    0   each limit of the facts file is the live one
    1   a limit changed or is missing, each named: read the relay's change,
        then move the facts file and the constants in the same commit
    2   the document or the facts file could not be read. Never a pass.

Usage:
    check-relay-limits.py                   live, from the facts' origin
    check-relay-limits.py --offline FILE    a /relays.json body saved before
    check-relay-limits.py --plant NAME=N    the facts' NAME taken as N, so the
                                            check must fail and name it
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIMITS = ROOT / "crates" / "podssh-probe" / "facts" / "relay-limits.toml"
ORIGIN = "https://tcp.ssh.relay.ajam.dev"
# The target of the measurement in the facts file's comment; any public one
# gives the same limits.
QUERY = "/relays.json?host=github.com&port=22"
TIMEOUT_SECONDS = 30
USER_AGENT = "podssh-check-relay-limits/1"


def live(origin: str) -> bytes:
    request = urllib.request.Request(origin + QUERY, headers={"user-agent": USER_AGENT, "accept": "application/json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as answer:
        return answer.read()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--offline", default=None, metavar="FILE")
    parser.add_argument("--plant", default=None, metavar="NAME=N")
    parser.add_argument("--origin", default=ORIGIN)
    args = parser.parse_args()
    try:
        facts = tomllib.loads(LIMITS.read_text(encoding="utf-8"))
        if not facts or not all(isinstance(v, int) and v > 0 for v in facts.values()):
            raise ValueError(f"{LIMITS.name} must hold whole numbers above zero, and holds {facts}")
        if args.plant:
            name, _, value = args.plant.partition("=")
            if name not in facts or not value.isdigit():
                raise ValueError(f"--plant {args.plant}: no such limit, or not a number")
            facts[name] = int(value)
        body = Path(args.offline).read_bytes() if args.offline else live(args.origin)
        limits = json.loads(body.decode("utf-8")).get("limits")
        if not isinstance(limits, dict):
            raise ValueError("the document has no object \"limits\"")
    except (OSError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError, urllib.error.URLError) as exc:
        print(f"check-relay-limits: {exc}", file=sys.stderr)
        print("check-relay-limits: exiting 2. A check that could not run is not a pass.", file=sys.stderr)
        return 2
    source = args.offline or args.origin + QUERY
    problems = []
    for name, want in sorted(facts.items()):
        got = limits.get(name)
        if got != want:
            problems.append(f"{name} is {got!r} at {source}, where the facts hold {want}")
        else:
            print(f"ok   {name} = {got}")
    for problem in problems:
        print(f"FAIL {problem}")
    if problems:
        print("check-relay-limits: read the relay's change, then move relay-limits.toml and podssh's constants "
              "in the same commit", file=sys.stderr)
        return 1
    print(f"ok   the {len(facts)} limits of the facts are the relay's")
    return 0


if __name__ == "__main__":
    sys.exit(main())
