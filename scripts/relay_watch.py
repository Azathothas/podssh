#!/usr/bin/env python3
"""The issues of .github/workflows/relay-watch.yml (T-338).

From the day's checks and the results of the runs before it, the issues to
open: one when a fact of the relay's document changed, titled with the pinned
version and the facts that failed; one when the document could not be read
three runs in a row; one when the relay's domain expires within 90 days, and
one when its expiry could not be read three runs in a row. An issue whose
title an open issue has already is not opened again.

    relay_watch.py DIR             decide, and open each issue with gh
    relay_watch.py DIR --dry-run   decide, and print each issue only
    relay_watch.py --self-test     the decision on made-up days

DIR holds the day's facts.json (check-relay-spec.py --json), domain.txt
(check-domain.py's output), result.json ({"facts": RC, "domain": RC}), and
previous/RUN/result.json for each earlier run, the newest RUN first by its
number. Exit 0 when each issue was opened or found open, 1 when one could not
be, 2 on a usage error.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PREFIX = "relay-watch: "
# The runs in a row that a check could not run before an issue says so.
UNREAD_RUNS = 3


def unread_in_a_row(check: str, today: dict, previous: list[dict]) -> bool:
    runs = [today] + previous[:UNREAD_RUNS - 1]
    return len(runs) == UNREAD_RUNS and all(run.get(check) == 2 for run in runs)


def decide(today: dict, previous: list[dict], facts: dict, domain_text: str) -> list[tuple[str, str]]:
    """The issues, as (title, body), for the day `today` after `previous`, the
    newest first."""
    issues = []
    pinned = facts.get("pinned_version", "?")
    if today.get("facts") == 1:
        failed = sorted({problem.split(":", 1)[0] for problem in facts.get("problems", [])})
        title = f"{PREFIX}the relay's document disagrees with the pin {pinned}: {', '.join(failed)}"
        body = ("scripts/check-relay-spec.py found the relay's document changed against the facts of "
                "crates/podssh-probe/facts/relay-facts.toml:\n\n"
                + "\n".join(f"- {problem}" for problem in facts.get("problems", []))
                + "\n\nRead the diff, then either measure again and update the facts file and docs/relay.md, "
                  "or record why the new form is equivalent. Never pin again silently.")
        issues.append((title, body))
    if unread_in_a_row("facts", today, previous):
        issues.append((f"{PREFIX}the relay's document could not be read in {UNREAD_RUNS} runs in a row",
                       f"scripts/check-relay-spec.py exited 2 in each of the last {UNREAD_RUNS} runs of "
                       f"relay-watch.yml: the relay, or the way to it, is down. The pin is {pinned}."))
    if today.get("domain") == 1:
        issues.append((f"{PREFIX}the relay's domain expires within 90 days",
                       f"scripts/check-domain.py: {domain_text.strip()}\n\nEach road but --direct stops when it "
                       "lapses."))
    if unread_in_a_row("domain", today, previous):
        issues.append((f"{PREFIX}the expiry of the relay's domain could not be read in {UNREAD_RUNS} runs in a row",
                       f"scripts/check-domain.py exited 2 in each of the last {UNREAD_RUNS} runs: "
                       f"{domain_text.strip()}"))
    return issues


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8") or "{}")
    except (OSError, ValueError):
        return {}


def previous_results(directory: Path) -> list[dict]:
    runs = [p for p in directory.glob("*/result.json")] if directory.is_dir() else []
    runs.sort(key=lambda p: int(p.parent.name) if p.parent.name.isdigit() else 0, reverse=True)
    return [read_json(p) for p in runs]


def gh(*args: str) -> str:
    done = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=120)
    if done.returncode != 0:
        raise RuntimeError(f"gh {args[0]} {args[1]}: {done.stderr.strip()}")
    return done.stdout


def open_issues(issues: list[tuple[str, str]], dry_run: bool) -> int:
    if not issues:
        print("relay-watch: nothing to open")
        return 0
    failed = 0
    for title, body in issues:
        if dry_run:
            print(f"relay-watch: would open: {title}\n{body}\n")
            continue
        try:
            open_titles = json.loads(gh("issue", "list", "--state", "open", "--limit", "200",
                                        "--search", "relay-watch in:title", "--json", "title"))
            if any(issue.get("title") == title for issue in open_titles):
                print(f"relay-watch: open already: {title}")
                continue
            print(gh("issue", "create", "--title", title, "--body", body).strip())
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            print(f"relay-watch: {title}: {exc}", file=sys.stderr)
            failed = 1
    return failed


def self_test() -> int:
    facts = {"pinned_version": "2026-10-03-r2", "problems": ["reverse-node-path: no line of its section ..."]}
    ok, unread, changed, soon = {"facts": 0, "domain": 0}, {"facts": 2, "domain": 0}, {"facts": 1, "domain": 0}, \
        {"facts": 0, "domain": 1}
    cases = [
        ("all well", ok, [ok, ok], 0),
        ("a fact changed", changed, [ok, ok], 1),
        ("unread once", unread, [ok, ok], 0),
        ("unread twice", unread, [unread, ok], 0),
        ("unread three times", unread, [unread, unread], 1),
        ("unread three times, the first run of all", unread, [unread], 0),
        ("the domain soon", soon, [ok], 1),
        ("the domain unread three times", {"facts": 0, "domain": 2}, [{"facts": 0, "domain": 2}] * 2, 1),
    ]
    failed = 0
    for name, today, previous, count in cases:
        issues = decide(today, previous, facts, "ajam.dev expires on 2027-01-28")
        mark = "ok  " if len(issues) == count else "FAIL"
        failed |= len(issues) != count
        print(f"{mark} {name}: {len(issues)} issue(s), {count} wanted")
    title = decide(changed, [], facts, "")[0][0]
    if "2026-10-03-r2" not in title or "reverse-node-path" not in title:
        print(f"FAIL the title names neither the pin nor the fact: {title}")
        failed = 1
    return failed


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if not argv or len(argv) > 2 or (len(argv) == 2 and argv[1] != "--dry-run"):
        print(__doc__, file=sys.stderr)
        return 2
    directory = Path(argv[0])
    today = read_json(directory / "result.json")
    if "facts" not in today or "domain" not in today:
        print(f"relay-watch: {directory}/result.json holds no day's result", file=sys.stderr)
        return 2
    facts = read_json(directory / "facts.json")
    domain = (directory / "domain.txt").read_text(encoding="utf-8") if (directory / "domain.txt").is_file() else ""
    issues = decide(today, previous_results(directory / "previous"), facts, domain)
    return open_issues(issues, dry_run=len(argv) == 2)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
