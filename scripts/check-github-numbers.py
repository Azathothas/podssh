#!/usr/bin/env python3
"""TODO/github.txt against GitHub itself (T-360): each number of the
repository, an issue or a pull request, with its state, as `gh issue list`
and `gh pr list` give them. A difference names each number and exits 1; the
session that reads the run maps the issue (TODO/RULES.md) and moves the
list. `cargo todo check` holds TODO/issues.md to the list, with no network.

  --plant-drop N     drop N from the list first: the run must then exit 1
  --issues FILE      `gh issue list --json number,state` read from FILE
  --pulls FILE       `gh pr list --json number,state` read from FILE

Exit 0 when they agree, 1 at a difference, 2 when GitHub cannot be read.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIST = ROOT / "TODO" / "github.txt"


def listed(drop):
    out = {}
    for raw in LIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        number, kind, state = line.split()
        if int(number) != drop:
            out[int(number)] = (kind, state)
    return out


def read_gh(kind, path):
    """`gh KIND list` as JSON, from `path` when one is given."""
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    command = ["gh", kind, "list", "--state", "all", "--limit", "5000", "--json", "number,state"]
    if os.environ.get("GITHUB_REPOSITORY"):
        command += ["--repo", os.environ["GITHUB_REPOSITORY"]]
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"check-github-numbers: gh {kind} list: {e}", file=sys.stderr)
        sys.exit(2)
    if done.returncode != 0:
        print(f"check-github-numbers: gh {kind} list: {done.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return json.loads(done.stdout)


def on_github(issues_file, pulls_file):
    out = {}
    for item in read_gh("issue", issues_file):
        out[item["number"]] = ("issue", "open" if item["state"] == "OPEN" else "closed")
    # A pull request is OPEN, CLOSED or MERGED: each but the first is closed.
    for item in read_gh("pr", pulls_file):
        out[item["number"]] = ("pull", "open" if item["state"] == "OPEN" else "closed")
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plant-drop", type=int)
    parser.add_argument("--issues")
    parser.add_argument("--pulls")
    args = parser.parse_args()
    mine = listed(args.plant_drop)
    theirs = on_github(args.issues, args.pulls)
    differences = []
    for number in sorted(set(mine) | set(theirs)):
        here, there = mine.get(number), theirs.get(number)
        if here == there:
            continue
        if here is None:
            differences.append(f"#{number} on GitHub, {there[0]} {there[1]}, has no line in TODO/github.txt")
        elif there is None:
            differences.append(f"#{number} is in TODO/github.txt ({here[0]} {here[1]}), and GitHub has no such number")
        else:
            differences.append(f"#{number}: TODO/github.txt says {here[0]} {here[1]}, GitHub {there[0]} {there[1]}")
    for line in differences:
        print(f"FAIL  {line}")
    if differences:
        print(f"check-github-numbers: {len(differences)} difference(s): map each issue (TODO/RULES.md), then move "
              "TODO/github.txt")
        return 1
    print(f"ok    TODO/github.txt holds GitHub's {len(theirs)} numbers, each with its state")
    return 0


if __name__ == "__main__":
    sys.exit(main())
