#!/usr/bin/env python3
"""Assert the relay's structural facts, and report version drift.

Background: docs/relay.md (the relay contract and how drift is handled).

THE FACTS LIVE IN `crates/podssh-probe/facts/relay-facts.toml` AND NOWHERE
ELSE. This script reads that file and asserts against the relay's live
document. A second hand-written copy of these numbers is the exact drift this
entry exists to catch, and a copy the Rust startup path cannot see would be
worse than no copy at all.

THIS SCRIPT IS NOT THE ACCEPTANCE, AND IT DOES NOT PRETEND TO BE.
`cargo test -p podssh-probe` is the acceptance, because MEASURED 2026-10-02,
`rust:1-alpine` ships no Python at all - `command -v python` and
`command -v python3` both return nothing - so a check written in Python cannot
run in the one image that proves this repository's central constraint. A check
that only runs where its interpreter happens to exist is a check nobody runs.
This script exists because CI can run it directly and report a diff on one
line, and because a human wants one command against the live relay.

Exit codes, and they are not interchangeable:

    0   every structural fact holds. The version is unchanged, or it moved and
        every fact still holds - a version move with facts intact is a warning,
        never a failure.
    1   a structural fact is wrong, or a plant did not redden. THIS IS A RELAY
        CHANGE, NOT A SCRIPT FAILURE. Read the diff, then either re-measure and
        update the facts file and docs/relay.md, or record why
        the new form is equivalent. Never re-pin silently.
    2   the relay could not be read, or the facts file is unusable. Never
        reported as 0: a check that could not run is not a pass, and that is the
        defect this repository has shipped three times.

Usage:
    check-relay-spec.py                     fetch live, assert the facts
    check-relay-spec.py --offline PATH      assert against a local document
    check-relay-spec.py --plant-bad-path    corrupt the node path in the
                                            document, to prove the gate fires
    check-relay-spec.py --plant-bad-timeout corrupt the open timeout
    check-relay-spec.py --plant-bad-cap     corrupt the node frame cap
    check-relay-spec.py --plant-moved-line  a line inserted at the top: each
                                            fact holds, with a note (T-338)
    check-relay-spec.py --plant-moved-section the node path out of its
                                            section: it must fail
    check-relay-spec.py --url URL           a different origin, for a fork
    check-relay-spec.py --json              machine-readable
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FACTS_FILE = ROOT / "crates" / "podssh-probe" / "facts" / "relay-facts.toml"
# The module beside this script, also under `python -I`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from relay_sections import locate, plant_moved_line, plant_moved_section  # noqa: E402

# Bounded. An unbounded read on a host whose egress hangs is a gate that hangs,
# and a gate that hangs is a gate whose verdict nobody reads.
TIMEOUT_SECONDS = 30
USER_AGENT = "podssh-check-relay-spec/1"


def strip_comment(line: str) -> str:
    """A `#` comment, honouring quotes so a `#` inside a string survives."""
    out, in_quote = [], False
    for char in line:
        if char == '"' and (not out or out[-1] != "\\"):
            in_quote = not in_quote
        if char == "#" and not in_quote:
            break
        out.append(char)
    return "".join(out)


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        # TOML's basic strings honour backslash escapes; the facts file uses
        # them for regex metacharacters.
        return json.loads(value)
    return value


class FactsFileError(Exception):
    pass


def load_facts(path: Path) -> dict:
    """Parse the one facts file into plain dicts.

    A hand-rolled reader, because `tomllib` is Python 3.11+ and this repository
    has already had a check fail on a host whose interpreter is a Microsoft
    Store alias. That alias exits 0, and exit 0 from a check that did not run is
    the defect this repository has shipped three times - so the reader is
    explicit about what it understands and refuses the rest.

    Refusing is the point. The first version of this function scanned for
    `=` and so could not tell `[relations.src]` from a bare key: it read the
    src operand as `None`, crashed on `int(None)`, and every plant exited 1
    THROUGH THE TRACEBACK. A check that reds for the wrong reason is a check
    that has proven nothing.
    """
    facts: dict = {"pin": {}, "facts": [], "relations": [], "top": {}}
    # Top-level keys come BEFORE any table header. `section = "pin"` would be
    # a lie for them, and a reader that trusts `section` would file `origin`
    # under the pin and then report "no origin" - which is exactly what the
    # first version of this function did.
    table: dict | None = None
    section: str | None = None
    relation: dict | None = None
    operand_side: str | None = None

    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = strip_comment(raw).strip()
        if not line:
            continue
        where = f"{path.name}:{number}"

        if line.startswith("[["):
            if not line.endswith("]]"):
                raise FactsFileError(f"{where}: malformed array-of-tables header")
            section = line[2:-2].strip()
            if section == "facts":
                relation = {"id": None, "line": None, "section": None, "contains": None,
                            "pattern": None, "value": None}
                facts["facts"].append(relation)
                table = relation
                operand_side = None
            elif section == "relations":
                relation = {"id": None, "expression": None, "why": None,
                            "src": None, "dst": None}
                facts["relations"].append(relation)
                table = relation
                operand_side = None
            else:
                raise FactsFileError(f"{where}: unknown section [[{section}]]")
            continue

        if line.startswith("["):
            if not line.endswith("]"):
                raise FactsFileError(f"{where}: malformed table header")
            header = line[1:-1].strip()
            if header == "pin":
                table, section, operand_side = facts["pin"], "pin", None
            elif header.startswith("relations."):
                side = header.split(".", 1)[1].strip()
                if side not in ("src", "dst"):
                    raise FactsFileError(f"{where}: unknown sub-table [{header}]")
                if relation is None:
                    raise FactsFileError(f"{where}: [{header}] outside a [[relations]]")
                operand_side = side
                table = relation[side] = {"line": None, "section": None, "pattern": None, "names": []}
            else:
                raise FactsFileError(f"{where}: unknown section [{header}]")
            continue

        if "=" not in line:
            raise FactsFileError(f"{where}: not a key = value line: {line!r}")

        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()

        if operand_side is not None:
            match key:
                case "line":
                    table["line"] = int(unquote(value))
                case "section":
                    table["section"] = unquote(value)
                case "pattern":
                    table["pattern"] = unquote(value)
                case "names":
                    if not (value.startswith("[") and value.endswith("]")):
                        raise FactsFileError(f"{where}: names must be an array")
                    table["names"] = [unquote(part) for part in
                                      value[1:-1].split(",") if part.strip()]
                case other:
                    raise FactsFileError(f"{where}: unknown key {other!r} in "
                                         f"[relations.{operand_side}]")
            continue

        match section:
            case None:
                table = facts["top"]
                match key:
                    case "origin":
                        table[key] = unquote(value)
                    case "forward-max-frame-bytes":
                        table[key] = int(unquote(value))
                    case other:
                        raise FactsFileError(f"{where}: unknown top-level key "
                                             f"{other!r}")
            case "pin":
                table = facts["pin"]
                table[key] = unquote(value)
            case "facts":
                match key:
                    case "id":
                        table["id"] = unquote(value)
                    case "line":
                        table["line"] = int(unquote(value))
                    case "section":
                        table["section"] = unquote(value)
                    case "contains":
                        table["contains"] = unquote(value)
                    case "pattern":
                        table["pattern"] = unquote(value)
                    case "value":
                        table["value"] = int(unquote(value))
                    case "why":
                        pass
                    case other:
                        raise FactsFileError(f"{where}: unknown key {other!r} in [[facts]]")
            case "relations":
                match key:
                    case "id" | "why":
                        table[key] = unquote(value)
                    case "expression":
                        table["expression"] = unquote(value)
                    case other:
                        raise FactsFileError(f"{where}: unknown key {other!r} in [[relations]]")
    return facts


def validate(facts: dict) -> None:
    """Every fact must be complete, or nothing is asserted and that is a pass."""
    if not facts["top"].get("origin"):
        raise FactsFileError("no origin")
    for field in ("version", "spec-sha256"):
        if not facts["pin"].get(field):
            raise FactsFileError(f"the pin has no {field}")
    if not facts["facts"]:
        raise FactsFileError("there are no structural facts at all; a gate "
                             "with no facts asserts nothing")
    for fact in facts["facts"]:
        if not fact.get("id") or not fact.get("line") or not fact.get("section"):
            raise FactsFileError(f"fact {fact.get('id')!r} has no id, line or section")
        if fact.get("contains") is None and fact.get("pattern") is None:
            raise FactsFileError(f"fact {fact['id']} has neither `contains` nor "
                                 f"`pattern`")
        if fact.get("pattern") and fact.get("value") is None:
            raise FactsFileError(f"fact {fact['id']} has a pattern but no value")
    for relation in facts["relations"]:
        if not relation.get("expression"):
            raise FactsFileError(f"relation {relation.get('id')!r} has no expression")
        for side in ("src", "dst"):
            operand = relation.get(side)
            if not operand or not operand.get("line") or not operand.get("pattern") or not operand.get("section"):
                raise FactsFileError(f"relation {relation.get('id')} has no "
                                     f"readable {side} operand")
            if not operand.get("names"):
                raise FactsFileError(f"relation {relation.get('id')} {side} names "
                                     f"no groups")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"user-agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        if response.status != 200:
            raise urllib.error.HTTPError(url, response.status, "not 200", None, None)
        return response.read()


def read_version(health: bytes) -> str:
    """`/health`'s version, or raise. Never a default.

    "The relay did not say what version it is" and "the relay is on the version
    we expect" are different facts, and only one of them is a pass.
    """
    try:
        version = json.loads(health.decode("utf-8"))["version"]
    except (ValueError, KeyError, UnicodeDecodeError) as exc:
        raise ValueError(f"/health carried no usable version: {exc}") from exc
    if not isinstance(version, str) or not version:
        raise ValueError("/health carried an empty version")
    return version


def read_operands(relation: dict, spec_lines: list[str], moved: list[dict]) -> dict[str, int]:
    values: dict[str, int] = {}
    for side in ("src", "dst"):
        operand = relation[side]
        pattern = re.compile(operand["pattern"])
        line = locate(spec_lines, int(operand["line"]), operand["section"],
                      lambda text: pattern.search(text) is not None, f"a number for {side}")
        note(moved, relation["id"], operand["section"], int(operand["line"]), line)
        found = pattern.search(spec_lines[line - 1])
        for name, group in zip(operand["names"], range(1, found.lastindex + 1)):
            values[name] = int(found.group(group))
    return values


def note(moved: list[dict], fact_id: str, section: str, hint: int, line: int) -> None:
    """A fact that holds away from its line, once: the hint is old."""
    entry = {"fact": fact_id, "section": section, "from": hint, "to": line}
    if hint != line and entry not in moved:
        moved.append(entry)


def check(facts: dict, spec_lines: list[str]) -> tuple[list[str], list[dict]]:
    problems: list[str] = []
    moved: list[dict] = []

    for fact in facts["facts"]:
        hint, section = int(fact["line"]), fact["section"]
        try:
            if fact.get("contains") is not None:
                needle = fact["contains"]
                note(moved, fact["id"], section, hint,
                     locate(spec_lines, hint, section, lambda text: needle in text, repr(needle)))
            elif fact.get("pattern") is not None:
                pattern = re.compile(fact["pattern"])
                line = locate(spec_lines, hint, section, lambda text: pattern.search(text) is not None,
                              "a value for this fact")
                got = pattern.search(spec_lines[line - 1]).group(1)
                if int(got) != fact["value"]:
                    problems.append(f"{fact['id']}: spec line {line} says {got}; this repository says "
                                    f"{fact['value']}")
                else:
                    note(moved, fact["id"], section, hint, line)
        except ValueError as exc:
            problems.append(f"{fact['id']}: {exc}")

    for relation in facts["relations"]:
        try:
            values = read_operands(relation, spec_lines, moved)
        except ValueError as exc:
            problems.append(f"{relation['id']}: {exc}")
            continue
        expression = relation["expression"]
        if expression == "id + payload == cap":
            # The 32-byte id is an internal constant on BOTH sides. It is not
            # read out of the peer's sentence: line 147 states one parenthetical
            # bound, and the total comes BEFORE the "(".
            total = 32 + values["payload"]
            if total != values["cap"]:
                problems.append(f"{relation['id']}: 32 + {values['payload']} = "
                                f"{total}, but the published cap is {values['cap']}")
        else:
            problems.append(f"{relation['id']}: no evaluator for {expression!r}; a "
                            f"relation this gate does not understand must fail "
                            f"loudly rather than pass")
    return problems, moved


def note_line(entry: dict) -> str:
    """A note as `podssh relay spec` prints it."""
    section = json.dumps(entry["section"], ensure_ascii=False)
    return (f"note {entry['fact']}: at line {entry['to']} of its section {section}, not at line "
            f"{entry['from']}: move the line in the facts file")


PLANTS = {
    "plant_bad_path": ("/v1/node/<name>", "/v1/drop/<name>", "reverse-node-path"),
    "plant_bad_timeout": ("within 15 s of `open`", "within 45 s of `open`",
                          "node-open-timeout"),
    "plant_bad_cap": ("over 65568 (32-byte id plus 65536 payload)",
                      "over 32768 (32-byte id plus 65536 payload)",
                      "reverse-node-frame-cap"),
}


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--url", default=None)
    parser.add_argument("--offline", default=None, metavar="PATH")
    parser.add_argument("--json", action="store_true", dest="as_json")
    for flag in PLANTS:
        parser.add_argument("--" + flag.replace("_", "-"), action="store_true")
    parser.add_argument("--plant-moved-line", action="store_true")
    parser.add_argument("--plant-moved-section", action="store_true")
    args = parser.parse_args()

    try:
        facts = load_facts(FACTS_FILE)
        validate(facts)
    except FactsFileError as exc:
        print(f"check-relay-spec: {FACTS_FILE.name}: {exc}", file=sys.stderr)
        print("check-relay-spec: exiting 2. A gate whose facts cannot be read "
              "asserts nothing, and that is not a pass.", file=sys.stderr)
        return 2

    origin = args.url or facts["top"]["origin"]

    try:
        if args.offline:
            spec_bytes = Path(args.offline).read_bytes()
            version = facts["pin"]["version"]
            source = args.offline
        else:
            spec_bytes = fetch(f"{origin}/llms-full.txt")
            version = read_version(fetch(f"{origin}/health"))
            source = origin
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"check-relay-spec: could not read the relay: {exc}", file=sys.stderr)
        print("check-relay-spec: exiting 2. A check that could not run is not a "
              "pass.", file=sys.stderr)
        return 2

    lines = spec_bytes.decode("utf-8", errors="replace").splitlines()
    sha = hashlib.sha256(spec_bytes).hexdigest()

    planted = None
    for flag, (needle, replacement, fact_id) in PLANTS.items():
        if not getattr(args, flag):
            continue
        planted = fact_id
        for index, text in enumerate(lines):
            if needle in text:
                lines[index] = text.replace(needle, replacement)
                break
        else:
            print(f"check-relay-spec: --{flag.replace('_', '-')} found nothing to "
                  f"corrupt in the document; the gate cannot be proven to fire",
                  file=sys.stderr)
            return 2

    try:
        if args.plant_moved_line:
            lines = plant_moved_line(lines)
        if args.plant_moved_section:
            planted = "reverse-node-path"
            lines = plant_moved_section(lines, facts)
    except ValueError as exc:
        print(f"check-relay-spec: {exc}", file=sys.stderr)
        return 2

    problems, moved = check(facts, lines)

    pin_version = facts["pin"]["version"]
    version_moved = version != pin_version

    if planted and not problems:
        print("check-relay-spec: THE GATE IS VACUOUS. A planted defect did not "
              "fail it.", file=sys.stderr)
        return 1
    # Each fact moved by one line within its section: each must hold, with a
    # note; a fact read at its line alone fails here (T-338).
    if args.plant_moved_line:
        unmoved = {f["id"] for f in facts["facts"]} | {r["id"] for r in facts["relations"]}
        unmoved -= {entry["fact"] for entry in moved if entry["to"] == entry["from"] + 1}
        if problems or unmoved:
            print("check-relay-spec: a line inserted at the top did not move each fact within its section: "
                  f"{sorted(unmoved)}", file=sys.stderr)
            problems = problems or [f"{fact}: not found one line down" for fact in sorted(unmoved)]

    verdict = {
        "source": source,
        "version": version,
        "pinned_version": pin_version,
        "version_moved": version_moved,
        "spec_sha256": sha,
        "spec_lines": len(lines),
        "facts_checked": len(facts["facts"]) + len(facts["relations"]),
        "planted": planted,
        "problems": problems,
        "moved": moved,
    }

    if args.as_json:
        print(json.dumps(verdict, indent=2))
    else:
        print(f"relay:   {source}")
        print(f"version: {version}"
              + (f"   MOVED from {pin_version}" if version_moved else ""))
        print(f"spec:    {len(lines)} lines, sha256 {sha[:16]}")
        print(f"facts:   {verdict['facts_checked']} structural facts asserted")
        for problem in problems:
            print(f"  FAIL {problem}")
        for entry in moved:
            print(f"  {note_line(entry)}")

    if problems:
        print(f"\ncheck-relay-spec: {len(problems)} structural fact(s) disagree with "
              f"the live relay.", file=sys.stderr)
        print("Read the diff, then either re-measure and update "
              "crates/podssh-probe/facts/relay-facts.toml and "
              "docs/relay.md, or record why the new form is "
              "equivalent. Never re-pin silently.", file=sys.stderr)
        return 1

    if version_moved and not args.as_json:
        print(f"\ncheck-relay-spec: version moved {pin_version} -> {version} and "
              f"every structural fact still holds.", file=sys.stderr)
        print("The protocol did not move. Update the pin and "
              "docs/relay.md in the same change.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())