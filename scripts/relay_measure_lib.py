"""The numbers of scripts/relay-measure.py (T-605, DRAFT): the summary of
each host's probes, the rank of the hosts, the conditions of a run, and the
Markdown table of a GitHub Actions step. No network, no podssh: each function
here takes what the runs gave, so the self-test can check it on canned runs.

The percentiles are by the nearest rank, as `podssh ping` gives them, so a
p50 here and a p50 of podssh's own JSON mean the same. The rank's order is
the one that `podssh relay rank` is to keep (T-606): the share of probes
that failed first, then the median time to open, then the p95; two medians
closer than TIE_MS or TIE_SHARE of the larger are a tie, which keeps the
order that the hosts came in, so that noise between two runs reorders
nothing.
"""

from __future__ import annotations

import math
import platform
import sys
from urllib.parse import urlsplit

# Two medians closer than this, in ms, or than this share of the larger,
# are the same: one run's noise is no reason to move a host.
TIE_MS = 50.0
TIE_SHARE = 0.10


def rank_of(sorted_values: list[float], percent: float) -> float | None:
    """The nearest-rank percentile of values in order; None for none."""
    if not sorted_values:
        return None
    at = max(1, math.ceil(percent / 100.0 * len(sorted_values)))
    return sorted_values[min(at, len(sorted_values)) - 1]


def spread(values: list[float]) -> dict:
    """min, p50, p95, max and n of a list of numbers, nearest rank."""
    s = sorted(v for v in values if v is not None)
    if not s:
        return {"n": 0, "min": None, "p50": None, "p95": None, "max": None}
    return {"n": len(s), "min": s[0], "p50": rank_of(s, 50), "p95": rank_of(s, 95), "max": s[-1]}


def open_ms(leg: dict) -> float | None:
    """The time to open a session through one host: the dial (TCP or the
    proxy's CONNECT), TLS and the upgrade, which the relay answers once it
    dialed the target. The token's time is left out: a session pays it once
    for days, as the token is cached."""
    parts = [leg.get("connect_ms"), leg.get("tls_ms"), leg.get("upgrade_ms")]
    if any(p is None for p in parts):
        return None
    return float(sum(parts))


def summarize(host: str, pool_runs: list[dict], trace_runs: list[dict], forward_runs: list[dict]) -> dict:
    """What the probes of one host say: how many opened, the time to open,
    the round trip of the WebSocket pings, the relay's own dial of the
    target from /trace, and whether GitHub's host key came through it."""
    opens, rtts, ups, errors = [], [], [], []
    for r in pool_runs:
        leg = r.get("leg") or {}
        took = open_ms(leg) if not leg.get("error") else None
        if took is None:
            errors.append(r.get("why") or leg.get("error") or "no leg")
            continue
        opens.append(took)
        ups.append(float(leg["upgrade_ms"]))
        pings = leg.get("pings") or {}
        if pings.get("p50_ms") is not None:
            rtts.append(float(pings["p50_ms"]))
    relay_dial = [float(t["connect_ms"]) for t in trace_runs if t.get("connect_ms") is not None]
    forward = None
    if forward_runs:
        forward = "ok" if all(f.get("status") == "ok" for f in forward_runs) else "fail"
    tries = len(pool_runs)
    return {
        "host": host,
        "tries": tries,
        "opened": len(opens),
        "failed_share": (tries - len(opens)) / tries if tries else 1.0,
        "open_ms": spread(opens),
        "upgrade_ms": spread(ups),
        "rtt_ms": spread(rtts),
        "relay_dial_ms": spread(relay_dial),
        "forward": forward,
        "errors": sorted(set(errors))[:3],
    }


def _same(a: float | None, b: float | None) -> bool:
    if a is None or b is None:
        return a is b
    return abs(a - b) < max(TIE_MS, TIE_SHARE * max(a, b))


def rank(summaries: list[dict]) -> list[dict]:
    """The hosts in the order to try them: fewer failed probes first, then
    the lower median time to open, then the lower p95; a tie keeps the order
    of the list given. A host that never opened goes last, in that order."""
    out: list[dict] = []
    for s in summaries:
        at = len(out)
        while at > 0 and _before(s, out[at - 1]):
            at -= 1
        out.insert(at, s)
    return out


def _before(a: dict, b: dict) -> bool:
    """Whether `a` goes strictly before `b`; a tie never moves `a` up."""
    if a["failed_share"] != b["failed_share"]:
        return a["failed_share"] < b["failed_share"]
    a50, b50 = a["open_ms"]["p50"], b["open_ms"]["p50"]
    if a50 is None or b50 is None:
        return False
    if not _same(a50, b50):
        return a50 < b50
    a95, b95 = a["open_ms"]["p95"], b["open_ms"]["p95"]
    return a95 is not None and b95 is not None and not _same(a95, b95) and a95 < b95


def proxy_kind(env: dict) -> str:
    """The kind of the proxy that podssh reads, never its address or its
    credentials: `none`, or the URL's scheme (`http` when it names none)."""
    value = env.get("HTTPS_PROXY") or env.get("https_proxy") or env.get("ALL_PROXY") or env.get("all_proxy")
    if not value:
        return "none"
    scheme = urlsplit(value if "://" in value else "http://" + value).scheme
    return scheme or "http"


def conditions(env: dict, podssh_version: str) -> dict:
    """The conditions of a run, as the archive's harness kept them, with no
    proxy URL: a URL may hold a user and a password."""
    ci = None
    if env.get("GITHUB_ACTIONS") == "true":
        ci = {k: env.get(k) for k in ("GITHUB_RUN_ID", "GITHUB_SHA", "RUNNER_OS", "RUNNER_ARCH")}
    return {
        "podssh": podssh_version,
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "proxy": proxy_kind(env),
        "ci": ci,
    }


def cell(v) -> str:
    if v is None:
        return "-"
    return f"{v:.0f}" if isinstance(v, float) else str(v)


def markdown(result: dict) -> str:
    """The rank as a Markdown table, for `$GITHUB_STEP_SUMMARY`."""
    cond = result["conditions"]
    lines = [
        f"### Relay hosts, {result['started']} ({cond['podssh']}, proxy {cond['proxy']})",
        "",
        "DRAFT harness (T-605): each figure is UNVERIFIED until the harness itself is verified.",
        "",
        "| # | host | opened | open p50 ms | open p95 ms | ping p50 ms | relay dial p50 ms | GitHub's key |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for i, s in enumerate(result.get("rank", []), 1):
        lines.append(
            f"| {i} | {s['host']} | {s['opened']} of {s['tries']} | {cell(s['open_ms']['p50'])} | "
            f"{cell(s['open_ms']['p95'])} | {cell(s['rtt_ms']['p50'])} | {cell(s['relay_dial_ms']['p50'])} | "
            f"{s['forward'] or '-'} |"
        )
    for d in result.get("dest", []):
        lines.append("")
        lines.append(f"- dest {d['road']}: exit {d['code']}, {d.get('line', '')}")
    return "\n".join(lines) + "\n"


def write_summary(result: dict, env: dict) -> None:
    """Append the table to the step summary of GitHub Actions, if any."""
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown(result))
    except OSError as exc:
        print(f"relay-measure: the step summary could not be written: {exc}", file=sys.stderr)


def dest_line(doc: dict) -> str:
    """One line of a `podssh ping --json DEST` document: the login, the
    echo and the throughput, as podssh measured them."""
    d = (doc or {}).get("destination") or {}
    if not d:
        return "no destination in the answer"
    parts = [f"login {cell(d.get('login_ms'))} ms"]
    echo = d.get("echo") or {}
    if echo:
        parts.append(f"echo p50 {cell(echo.get('p50_ms'))} ms")
    for way in ("down", "up"):
        m = d.get(way) or {}
        if m.get("seconds"):
            parts.append(f"{way} {m['bytes'] / 1048576.0 / max(m['seconds'], 1e-6):.2f} MiB/s")
        elif m.get("error"):
            parts.append(f"{way}: {m['error'][:80]}")
    if d.get("error"):
        parts.append(str(d["error"])[:120])
    return ", ".join(parts)


def env_for_runs(base: dict, cache_dir: str) -> dict:
    """The environment of each podssh run: the caller's, with a cache of
    the run's own (its token and records go there, never into the user's,
    and no record of an earlier run reorders a host), and no ssh_config of
    the machine. HTTPS_PROXY and PODSSH_OFFLINE stay as the caller set
    them: podssh reads the proxy itself, as a user's run does."""
    env = dict(base)
    env["PODSSH_CACHE_DIR"] = cache_dir
    env["PODSSH_SSH_CONFIG"] = "none"
    return env
