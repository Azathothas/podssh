#!/usr/bin/env python3
"""The public facts of GitHub that scripts/release-check.sh reads (T-251): a
release, the commit of a tag, and a run of GitHub Actions with its jobs. One
line for each fact, its fields split by tabs, the first field naming it:

    release-check-api.py release OWNER/NAME TAG
        release   PRERELEASE  DRAFT  PUBLISHED_AT
        asset     NAME  SIZE
    release-check-api.py commit OWNER/NAME REF
        commit    SHA
    release-check-api.py run OWNER/NAME RUN_ID
        run       PATH  HEAD_SHA  STATUS  CONCLUSION  CREATED_AT  EVENT  HEAD_BRANCH
        job       NAME  STATUS  CONCLUSION

A public repository's API needs no token. Each request has a time limit and
three tries. When the API refuses an address with no token (its hourly
limit, 403 or 429), `gh api` reads the same path with gh's own login, whose
token gh keeps and never prints. Exit 0 when each fact was read, 2 when it
could not be, 64 for a usage error. What the API returns is data: each field
is printed with no tab and no line end in it, and nothing of it runs.

Run it isolated, as the release check does: python3 -I scripts/release-check-api.py ...
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com/"
SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
TRIES = 3
LIMIT = 30
# The pages of a run's jobs: a run of the release has about a dozen.
MAX_PAGES = 10


class Unread(Exception):
    """A fact that could not be read, with the reason."""


def field(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return re.sub(r"[\t\r\n]", " ", "" if value is None else str(value))


def emit(*fields) -> None:
    print("\t".join(field(f) for f in fields))


def by_gh(path: str, why: str):
    """The same path through `gh api`, when gh is here."""
    if not shutil.which("gh"):
        raise Unread(f"{API}{path}: {why}; no gh to read it with its login")
    try:
        done = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        raise Unread(f"{API}{path}: {why}; gh api: no answer in 90 s") from None
    if done.returncode != 0:
        raise Unread(f"{API}{path}: {why}; gh api: {done.stderr.strip()[-300:]}")
    return json.loads(done.stdout)


def get(path: str):
    why = "no answer"
    for attempt in range(TRIES):
        request = urllib.request.Request(
            API + path,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "podssh-release-check",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=LIMIT) as answer:
                return json.loads(answer.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            why = f"HTTP {e.code}"
            # A refusal of this address, or no such thing: no try again.
            if e.code in (403, 404, 429):
                break
        except (urllib.error.URLError, OSError, ValueError) as e:
            why = str(e)
        if attempt + 1 < TRIES:
            time.sleep(5)
    return by_gh(path, why)


def release(slug: str, tag: str) -> None:
    rel = get(f"repos/{slug}/releases/tags/{tag}")
    emit("release", bool(rel.get("prerelease")), bool(rel.get("draft")), rel.get("published_at"))
    for asset in rel.get("assets") or []:
        emit("asset", asset.get("name"), asset.get("size"))


def commit(slug: str, ref: str) -> None:
    sha = get(f"repos/{slug}/commits/{ref}").get("sha") or ""
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise Unread(f"the commit of {ref} is not a commit: {sha!r}")
    emit("commit", sha)


def run(slug: str, run_id: str) -> None:
    info = get(f"repos/{slug}/actions/runs/{run_id}")
    emit("run", info.get("path"), info.get("head_sha"), info.get("status"), info.get("conclusion"),
         info.get("created_at"), info.get("event"), info.get("head_branch"))
    seen = 0
    for page in range(1, MAX_PAGES + 1):
        jobs = get(f"repos/{slug}/actions/runs/{run_id}/jobs?filter=latest&per_page=100&page={page}")
        listed = jobs.get("jobs") or []
        for job in listed:
            emit("job", job.get("name"), job.get("status"), job.get("conclusion"))
        seen += len(listed)
        if not listed or seen >= int(jobs.get("total_count") or 0):
            return
    raise Unread(f"run {run_id}: more than {MAX_PAGES} pages of jobs")


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] not in ("release", "commit", "run") or not SLUG.match(argv[1]):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 64
    what, slug, arg = argv
    if (what == "run" and not arg.isdigit()) or (what != "run" and not REF.match(arg)):
        print(f"release-check-api: not a {'run id' if what == 'run' else 'tag or ref'}: {arg!r}", file=sys.stderr)
        return 64
    try:
        {"release": release, "commit": commit, "run": run}[what](slug, arg)
    except (Unread, KeyError, TypeError, ValueError, AttributeError) as e:
        print(f"release-check-api: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
