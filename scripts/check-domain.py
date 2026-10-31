#!/usr/bin/env python3
"""The expiry of the relay's domain, read from its RDAP record (T-338).

Each road but --direct reaches the relay at the origin of
crates/podssh-probe/facts/relay-facts.toml, so a domain that lapses stops
them all for each user. This reads the domain's record from the registry's
RDAP server that IANA's bootstrap names for its top-level domain, else from
rdap.org, and judges its `expiration` event. The registrable name is not
guessed from a list of suffixes: the shortest name under the host that the
registry knows is the one registered.

Exit codes, and they are not interchangeable:

    0   the domain expires 90 days or more ahead.
    1   it expires in less than 90 days, or it has expired: renew it.
    2   no record was read, or the record holds no expiration. Never a pass.

Usage:
    check-domain.py                  the domain of the facts file's origin, live
    check-domain.py --name NAME      another host
    check-domain.py --offline FILE   a record read from FILE, not the network
    check-domain.py --plant-days N   the record's expiry moved N days ahead of
                                     now, to prove the judgement (89 fails, 91
                                     passes)
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FACTS_FILE = ROOT / "crates" / "podssh-probe" / "facts" / "relay-facts.toml"
BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
FALLBACK = "https://rdap.org/"
# How far ahead the expiry must be: time for a renewal that waits on a person.
AHEAD = datetime.timedelta(days=90)
TIMEOUT_SECONDS = 30
USER_AGENT = "podssh-check-domain/1"


def origin_host() -> str:
    found = re.search(r'^origin\s*=\s*"([^"]+)"', FACTS_FILE.read_text(encoding="utf-8"), re.MULTILINE)
    if not found:
        raise ValueError(f"{FACTS_FILE.name} names no origin")
    host = urllib.parse.urlsplit(found.group(1)).hostname
    if not host:
        raise ValueError(f"the origin {found.group(1)!r} names no host")
    return host


def get_json(url: str):
    """The JSON at `url`, or None for a 404; raise for any other failure."""
    request = urllib.request.Request(url, headers={"user-agent": USER_AGENT, "accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def servers_for(name: str) -> list[str]:
    """The registry's RDAP servers for `name`'s top-level domain, by IANA's
    bootstrap, then rdap.org; rdap.org alone when the bootstrap is not read."""
    tld = name.rsplit(".", 1)[-1].lower()
    try:
        bootstrap = get_json(BOOTSTRAP) or {}
        servers = [url for tlds, urls in bootstrap.get("services", []) if tld in tlds for url in urls]
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"check-domain: IANA's bootstrap: {exc}; rdap.org alone", file=sys.stderr)
        servers = []
    return [url if url.endswith("/") else url + "/" for url in servers] + [FALLBACK]


def read_record(host: str) -> tuple[dict, str, str]:
    """The record of the shortest name under `host` that a server knows, the
    name, and the server that answered."""
    labels = host.lower().rstrip(".").split(".")
    failures = []
    for count in range(2, len(labels) + 1):
        name = ".".join(labels[-count:])
        for server in servers_for(name):
            url = f"{server}domain/{name}"
            try:
                record = get_json(url)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                failures.append(f"{url}: {exc}")
                continue
            if record is None:
                # Not registered at this level: a longer name may be.
                break
            return record, name, server
    raise ValueError("no RDAP record was read: " + ("; ".join(failures) or f"no server knows a name under {host}"))


def expiration(record: dict) -> datetime.datetime:
    for event in record.get("events", []):
        if event.get("eventAction") == "expiration":
            date = event.get("eventDate", "")
            try:
                return datetime.datetime.fromisoformat(date.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"the expiration {date!r} is no date: {exc}") from exc
    raise ValueError("the record holds no expiration event")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--name", default=None)
    parser.add_argument("--offline", default=None, metavar="FILE")
    parser.add_argument("--plant-days", type=int, default=None, metavar="N")
    args = parser.parse_args()
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        if args.offline:
            record = json.loads(Path(args.offline).read_text(encoding="utf-8"))
            name, server = record.get("ldhName", "?").lower(), args.offline
        else:
            record, name, server = read_record(args.name or origin_host())
        expires = expiration(record)
    except (OSError, ValueError) as exc:
        print(f"check-domain: {exc}", file=sys.stderr)
        print("check-domain: exiting 2. A check that could not run is not a pass.", file=sys.stderr)
        return 2
    if args.plant_days is not None:
        expires = now + datetime.timedelta(days=args.plant_days)
        print(f"check-domain: planted: the expiry {args.plant_days} days ahead", file=sys.stderr)
    left = expires - now
    when = f"{name} expires on {expires.date().isoformat()}, {left.days} days ahead (by {server})"
    if left < AHEAD:
        print(f"FAIL {when}: less than {AHEAD.days} days; renew the domain, or each road but --direct stops")
        return 1
    print(f"ok   {when}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
