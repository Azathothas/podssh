"""Where a fact of the relay's document stands, for scripts/check-relay-spec.py
(T-338): at its line, the facts file's hint, else on a line of its section, a
heading of the document named by its first words. The same reading as
crates/podssh-probe/src/relay_facts.rs, which `podssh relay spec` runs;
scripts/relay-spec-agree.py asks both for one verdict.
"""

from __future__ import annotations

import re
from typing import Callable

HEADING = re.compile(r"^(#+) (.*)$")
FENCE = re.compile(r"^(```|~~~)")


def section_bounds(lines: list[str], name: str) -> tuple[int, int] | None:
    """The lines, 1-based and inclusive, of the section whose heading starts
    with `name`: its heading, and each line before the next heading of its
    level or above. A line in a fence of code is no heading."""
    fenced, start, level = False, None, 0
    for number, line in enumerate(lines, 1):
        text = line.rstrip()
        if FENCE.match(text):
            fenced = not fenced
            continue
        found = None if fenced else HEADING.match(text)
        if not found:
            continue
        depth = len(found.group(1))
        if start is None:
            if found.group(2).strip().startswith(name):
                start, level = number, depth
        elif depth <= level:
            return start, number - 1
    return (start, len(lines)) if start is not None else None


def locate(lines: list[str], hint: int, section: str, holds: Callable[[str], bool], what: str) -> int:
    """The number of the line that `holds` a fact: the hint first, then each
    line of its section. Raise ValueError with why when none does."""
    if 1 <= hint <= len(lines) and holds(lines[hint - 1]):
        return hint
    if 1 <= hint <= len(lines):
        reads = f"spec line {hint} reads: {lines[hint - 1].strip()}"
    else:
        reads = f"spec line {hint} does not exist; the document has {len(lines)} lines"
    bounds = section_bounds(lines, section)
    if bounds is None:
        raise ValueError(f"{reads}; and the document has no section {section!r}")
    first, last = bounds
    for number in range(first, last + 1):
        if holds(lines[number - 1]):
            return number
    raise ValueError(f"no line of its section {section!r} (lines {first}-{last}) carries {what}; {reads}")


def plant_moved_line(lines: list[str]) -> list[str]:
    """A line inserted at the top: each fact moves by one line, within its
    section, and each must hold with a note."""
    return ["A line that the relay inserted."] + lines


def plant_moved_section(lines: list[str], facts: dict) -> list[str]:
    """The node path's line moved to the end of the document, out of its
    section: the fact must fail, though the document holds its text. The
    line is found as the check finds it, so a moved document can be planted."""
    fact = next(f for f in facts["facts"] if f["id"] == "reverse-node-path")
    needle = fact["contains"]
    index = locate(lines, fact["line"], fact["section"], lambda text: needle in text, repr(needle)) - 1
    return lines[:index] + lines[index + 1:] + [lines[index]]
