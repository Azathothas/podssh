"""The marks of releases in docs/STATUS.md, a scan of scripts/check-repo.py
(T-594). The page reads `main`, and a user plans by it: so each row of work
after `v1.0.0` names the first release that holds it, or says `unreleased`.
It reads no git, so a checkout of depth 1 checks the same. Apart from
check-repo.py so that each file stays within 500 lines.
"""

from __future__ import annotations

import re

STATUS = "docs/STATUS.md"
# The first day of work after `v1.0.0`, whose commit (`35a0d19`) is of
# 2026-11-01: each row of the page dated before it is in that release.
FLOOR = "2026-11-02"
# The head's line of the newest release: its name, its date and its commit.
NEWEST = re.compile(
    r"The newest release is `(?P<name>v[^`]+)` \((?P<date>\d{4}-\d\d-\d\d), at `(?P<commit>[0-9a-f]{7,40})`\)"
)
DATE = re.compile(r"\b20\d\d-\d\d-\d\d\b")
RELEASE = re.compile(r"`(v\d+\.\d+\.\d+(?:-[a-z]+\.\d+)?)`")
# A release's mark as a label at the head of a first cell, as `v1.0.1`: ;
# a first cell may also begin with a command so (`-J cf://HOST`: ...).
LABEL = re.compile(r"^`(?P<name>v\d+\.\d+\.\d+[^`]*)`: ")
UNRELEASED = "unreleased"
SEPARATOR = re.compile(r"^\|(?:\s*:?-+:?\s*\|)+\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")
# A page with fewer rows was not read, so the scan of it does not pass (T-223).
MIN_ROWS = 100
MARK_RULE = "the page reads main: a row of work after v1.0.0 names the first release that holds it, or says `unreleased`"


def first_cells(text: str):
    """Each (line number, first cell) of the rows of the page's tables, outside
    fenced blocks, with no header row and no separator."""
    lines = text.splitlines()
    fence = False
    for i, line in enumerate(lines):
        if FENCE.match(line):
            fence = not fence
            continue
        if fence or not line.startswith("|") or SEPARATOR.match(line):
            continue
        if i + 1 < len(lines) and SEPARATOR.match(lines[i + 1]):
            continue
        yield i + 1, line[1:].split(" | ", 1)[0].strip()


def mark_problems(text: str, releases: set[str]) -> tuple[int, int, list[str]]:
    """Each row whose mark is missing, stale or of no release, as a problem;
    the rows read, and the rows marked. `releases` are the names of the notes
    of docs/releases/, one file for each tag."""
    head = NEWEST.search(text)
    if not head:
        return 0, 0, [f"{STATUS}: its head names no newest release, as \"The newest release is `vX.Y.Z` (DATE, at `COMMIT`)\""]
    newest, since = head.group("name"), head.group("date")
    problems = [] if newest in releases else [f"{STATUS}: the newest release `{newest}` has no notes in docs/releases/"]
    read = marked = 0
    for n, cell in first_cells(text):
        read += 1
        dates = DATE.findall(cell)
        latest = max(dates) if dates else None
        label = LABEL.match(cell)
        if label and label.group("name") not in releases:
            problems.append(f"{STATUS}:{n}: `{label.group('name')}` is the mark of no release with notes in docs/releases/")
        named = [r for r in RELEASE.findall(cell) if r in releases]
        if f"`{UNRELEASED}`" in cell:
            marked += 1
            if latest is None:
                problems.append(f"{STATUS}:{n}: says `unreleased` with no date in its first cell")
            elif latest < since:
                problems.append(f"{STATUS}:{n}: says `unreleased`, dated {latest}, before `{newest}` of {since}: "
                                "name the release that holds it")
        elif named:
            marked += 1
        elif latest is not None and latest >= FLOOR:
            problems.append(f"{STATUS}:{n}: a row dated {latest} names no release and does not say `unreleased`: {MARK_RULE}")
    return read, marked, problems


# A page of the plants: the newest release, a row marked by it, a row that
# says `unreleased` on its day, a row before the floor with no mark, a row
# that begins with a command; and the three defects, a row after the release
# with no mark (line 9), one that says `unreleased` before it (line 10), and
# one marked by a release that has no notes (line 11).
PLANTED_PAGE = """# Status

The newest release is `v1.1.0-beta.1` (2026-11-03, at `5d95e5f`).

| Row | State |
| --- | --- |
| `v1.1.0-beta.1`: a row of the release (T-1, 2026-11-03) | Works |
| `unreleased`: a row after it (T-2, 2026-11-03) | Works |
| a row after the release (T-3, 2026-11-04) | Works |
| `unreleased`: a row that the release holds (T-4, 2026-11-02) | Works |
| `v1.0.2`: a row of a release with no notes (T-5, 2026-11-03) | Works |
| a row of `v1.0.0` with no mark (T-6, 2026-10-30) | Works |
| `-J cf://HOST`: a row that begins with a command (T-7, 2026-10-31) | Works |
"""
PLANTED_LINES = {9, 10, 11}


def planted_marks_found() -> set[int]:
    """The lines of the planted page that the scan finds, which must be the
    three defects alone."""
    _, _, problems = mark_problems(PLANTED_PAGE, {"v1.0.0", "v1.1.0-beta.1"})
    found = set()
    for problem in problems:
        place = problem.split(": ", 1)[0]
        if place.startswith(f"{STATUS}:"):
            found.add(int(place.rsplit(":", 1)[1]))
    return found
