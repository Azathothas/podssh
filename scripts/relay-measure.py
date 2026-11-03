#!/usr/bin/env python3
"""Measure the relay hosts and the roads through podssh's own binary (T-605).

DRAFT, UNVERIFIED: nothing has run this file against a real podssh. Each
claim below of what a stage measures is what the stage is written to do,
not a measured fact, until the entry's Prove runs.

Adapted from the measurement harness of an archive of relay research that
the operator attached on 2026-11-03, under 0BSD as podssh is
(docs/research/relay-measurement.md): its stages, a JSON result that keeps
the conditions of the run, and a write leg proved by bytes that only the far
end can answer. Unlike that harness, each measure here is a run of podssh
itself, so it measures what a user of podssh gets: podssh's dial through
HTTPS_PROXY, its TLS, its token, its upgrade and its SSH. No relay protocol
is written here, and no socket is opened by this file.

Stages, each one podssh process at a time, never two at once:

  pool     each host's leg: `podssh ping --json --relay-host HOST --target T
           --count C`, the dial, TLS and the upgrade (which the relay answers
           once it dialed T), then C WebSocket pings; --rounds times, the
           hosts in a new random order each round.
  trace    the relay's own side of the same path: `podssh relay trace --json
           --relay-host HOST T`, the time that the relay took to dial T, so a
           slow client leg is told from a slow relay leg.
  forward  `podssh doctor --quick --json --jobs 1 --relay-host HOST`: GitHub's
           published host key through the host, which needs the key exchange
           in both directions (the write leg), once for each host.
  roads    `podssh doctor --quick --json --jobs 1 FLAGS` for each
           --doctor-road FLAGS (`--forwarder mudlet`, `--vless FILE`, ...):
           each check of the run, GitHub's key through that road among them.
  dest     with --destination: `podssh ping --json [FLAGS] DEST`, the login,
           the echo through cat and the throughput down and up, the SSH
           window included, for each --ping-road FLAGS (`--relay-host HOST`,
           `--direct`, `-J HOP`); with none, the first host of the rank.

Each run of podssh has a time limit, and so has the whole run (--budget).
The runs share a cache directory of their own, which holds the token and is
removed at the end; no token, no proxy address and no proxy credential is
written. The result is one JSON document (--out); --ci also appends a table
to GitHub's step summary.

Usage:
  python3 scripts/relay-measure.py --podssh BIN [--stages pool,trace,forward]
      [--hosts all|N|HOST,HOST] [--rounds 5] [--count 5] [--target github.com:22]
      [--doctor-road FLAGS]... [--destination USER@HOST [--identity FILE]
       [--known-hosts FILE] [--size 8M] [--ping-road FLAGS]...]
      [--budget 1800] [--seed N] [--out FILE] [--ci]
  python3 scripts/relay-measure.py --self-test

Exit 0 when the stages ran and a host opened (or no stage needed one); 1
when the pool stage ran and no host opened; 2 for a usage error or a podssh
that does not run. Read the exit code directly, not through a pipe.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shlex
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import relay_measure_lib as lib  # noqa: E402

# A run of podssh past this is killed: podssh's own steps have limits (20 s
# each, 600 s for a whole `ping`), and this one holds when a run hangs past
# them. A destination's run moves --size twice, so it has more.
PROBE_LIMIT = 90.0
DEST_LIMIT = 330.0
# Between two runs, so that the end of one (its Close) is not inside the next.
PAUSE = 0.25
STAGES = ("pool", "trace", "forward", "roads", "dest")
# The stages that measure each relay host, and so need the list of hosts.
HOST_STAGES = ("pool", "trace", "forward")
# The relay leg's target with no other: GitHub's SSH port, which podssh's
# own ping and doctor use; never a session's destination.
TARGET = "github.com:22"
# The planted defect of the self-test: two probes at once.
PLANT_ENV = "RELAY_MEASURE_PLANT"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def one_line(raw: bytes, limit: int = 300) -> str:
    """The last line of podssh's stderr, made safe: podssh hides tokens and
    proxy credentials in its own lines."""
    text = raw.decode("utf-8", "replace").strip().splitlines()
    last = text[-1] if text else ""
    return "".join(c if c.isprintable() else "?" for c in last)[:limit]


class Runner:
    """Runs podssh, one process at a time, each within its limit and within
    what is left of the run's budget."""

    def __init__(self, cmd: list[str], env: dict, budget: float):
        self.cmd = cmd
        self.env = env
        self.deadline = time.monotonic() + budget
        self.count = 0
        self.skipped = 0

    def run(self, args: list[str], limit: float) -> dict:
        left = self.deadline - time.monotonic()
        if left <= 1.0:
            self.skipped += 1
            return {"code": None, "timed_out": False, "secs": 0.0, "out": "", "err": "", "skipped": True}
        limit = min(limit, left)
        started = time.monotonic()
        try:
            done = subprocess.run(self.cmd + args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=limit, env=self.env)
            code, out, err, timed_out = done.returncode, done.stdout, done.stderr, False
        except subprocess.TimeoutExpired as exc:
            # subprocess.run kills the child and waits for it.
            code, out, err, timed_out = None, exc.stdout or b"", exc.stderr or b"", True
        except OSError as exc:
            code, out, err, timed_out = None, b"", str(exc).encode(), False
        self.count += 1
        took = round(time.monotonic() - started, 3)
        time.sleep(PAUSE)
        return {"code": code, "timed_out": timed_out, "secs": took,
                "out": out.decode("utf-8", "replace"), "err": one_line(err), "skipped": False}


def parse(out: str) -> dict | None:
    """podssh's one JSON object on stdout, or None."""
    try:
        doc = json.loads(out)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def why(r: dict) -> str | None:
    """Why a run gave no answer, in a few words."""
    if r["skipped"]:
        return "not run: the run's budget was spent"
    if r["timed_out"]:
        return "podssh did not end within its limit"
    if r["code"] not in (0, None) and r["err"]:
        return f"exit {r['code']}: {r['err']}"
    return None


def hosts_of(runner: Runner, spec: str) -> tuple[list[str], str | None]:
    """The hosts to measure: a list that the caller named, or the default
    host and its pool from `podssh relay info --json`, all or the first N."""
    if spec not in ("all",) and not spec.isdigit():
        return [h.strip() for h in spec.split(",") if h.strip()], None
    r = runner.run(["relay", "info", "--json"], PROBE_LIMIT)
    doc = parse(r["out"])
    if not doc or not isinstance(doc.get("info"), dict):
        return [], why(r) or "podssh relay info gave no JSON"
    primary = str(doc.get("relay") or "")
    pool = [str(p.get("host")) for p in doc["info"].get("pool") or [] if isinstance(p, dict) and p.get("host")]
    hosts = [primary] + [h for h in pool if h != primary] if primary else pool
    if spec.isdigit():
        hosts = hosts[: int(spec)]
    return hosts, None


def rounds_of(hosts: list[str], rounds: int, rng: random.Random):
    """Each round's hosts in a new random order, so that the time of day, a
    cold start or the proxy's state falls on no one host each time."""
    for n in range(rounds):
        order = hosts[:]
        rng.shuffle(order)
        yield n, order


def stage_pool(runner: Runner, hosts: list[str], a, rng: random.Random, runs: list) -> None:
    def probe(n: int, host: str) -> dict:
        r = runner.run(["ping", "--json", "--relay-host", host, "--target", a.target, "--count", str(a.count)],
                       PROBE_LIMIT)
        doc = parse(r["out"]) or {}
        legs = doc.get("relays") or []
        leg = legs[0] if legs and isinstance(legs[0], dict) else None
        return {"stage": "pool", "host": host, "round": n, "code": r["code"], "secs": r["secs"],
                "leg": leg, "why": why(r) or (None if leg else "no leg in podssh's answer")}

    for n, order in rounds_of(hosts, a.rounds, rng):
        if os.environ.get(PLANT_ENV) == "parallel":
            with ThreadPoolExecutor(2) as pool:
                runs.extend(pool.map(lambda h: probe(n, h), order))
            continue
        for host in order:
            runs.append(probe(n, host))
            print(f"pool {n + 1}/{a.rounds} {host}: {runs[-1]['why'] or 'ok'}", file=sys.stderr, flush=True)


def stage_trace(runner: Runner, hosts: list[str], a, rng: random.Random, runs: list) -> None:
    host_t, _, port_t = a.target.rpartition(":")
    for n, order in rounds_of(hosts, a.rounds, rng):
        for host in order:
            r = runner.run(["relay", "trace", "--json", "--relay-host", host, host_t, port_t], PROBE_LIMIT)
            doc = parse(r["out"]) or {}
            target = doc.get("target") if isinstance(doc.get("target"), dict) else {}
            keep = {k: target.get(k) for k in ("ok", "connect_ms", "first_byte_ms", "bytes_seen", "verdict")}
            runs.append({"stage": "trace", "host": host, "round": n, "code": r["code"], "secs": r["secs"],
                         "edge": doc.get("edge"), **keep, "why": why(r)})


def doctor(runner: Runner, flags: list[str]) -> tuple[dict, list[dict]]:
    """`podssh doctor --quick --json --jobs 1 FLAGS`: one section at a time,
    and each check with its status, its detail cut short."""
    r = runner.run(["doctor", "--quick", "--json", "--jobs", "1"] + flags, PROBE_LIMIT)
    doc = parse(r["out"]) or {}
    checks = [{"section": c.get("section"), "check": c.get("check"), "status": c.get("status"),
               "detail": str(c.get("detail") or "")[:200]}
              for c in doc.get("checks") or [] if isinstance(c, dict)]
    return r, checks


def stage_forward(runner: Runner, hosts: list[str], runs: list) -> None:
    for host in hosts:
        r, checks = doctor(runner, ["--relay-host", host])
        line = next((c for c in checks if c["check"] == "forward"), {})
        runs.append({"stage": "forward", "host": host, "code": r["code"], "secs": r["secs"],
                     "status": line.get("status"), "detail": line.get("detail", ""), "why": why(r)})


def stage_roads(runner: Runner, roads: list[str], runs: list) -> None:
    for road in roads:
        r, checks = doctor(runner, shlex.split(road))
        runs.append({"stage": "roads", "road": road, "code": r["code"], "secs": r["secs"], "checks": checks,
                     "why": why(r)})


def stage_dest(runner: Runner, a, best: str | None, scratch: Path, runs: list) -> None:
    roads = a.ping_road or ([f"--relay-host {best}"] if best else [""])
    for road in roads:
        args = ["ping", "--json"] + shlex.split(road)
        if a.identity:
            args += ["-i", a.identity]
        # A host key that the caller gave, or the first one seen, kept in a
        # file of the run's own: a measurement, not a trust decision.
        if a.known_hosts:
            args += ["-o", f"UserKnownHostsFile={a.known_hosts}", "-o", "StrictHostKeyChecking=yes"]
        else:
            args += ["-o", f"UserKnownHostsFile={scratch / 'known_hosts'}", "-o", "StrictHostKeyChecking=accept-new"]
        args += ["--size", a.size, "--count", str(a.count), a.destination]
        r = runner.run(args, DEST_LIMIT)
        doc = parse(r["out"]) or {}
        runs.append({"stage": "dest", "road": road or "podssh's own choice", "code": r["code"], "secs": r["secs"],
                     "host_key": "given" if a.known_hosts else "accepted on first use",
                     "destination": doc.get("destination"), "relays": doc.get("relays"),
                     "line": lib.dest_line(doc), "why": why(r)})


def arguments(argv: list[str]):
    p = argparse.ArgumentParser(prog="relay-measure.py", description="DRAFT (T-605): see the file's docstring.")
    p.add_argument("--podssh", help="the podssh binary to run")
    p.add_argument("--stages", default="pool,trace,forward")
    p.add_argument("--hosts", default="all")
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--count", type=int, default=5)
    p.add_argument("--target", default=TARGET)
    p.add_argument("--doctor-road", action="append", default=[])
    p.add_argument("--destination")
    p.add_argument("--identity")
    p.add_argument("--known-hosts")
    p.add_argument("--size", default="8M")
    p.add_argument("--ping-road", action="append", default=[])
    p.add_argument("--budget", type=float, default=1800.0)
    p.add_argument("--seed", type=int)
    p.add_argument("--out", default="relay-measure.json")
    p.add_argument("--ci", action="store_true")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args(argv)
    if a.self_test:
        return a, None
    stages = [s.strip() for s in a.stages.split(",") if s.strip()]
    wrong = [s for s in stages if s not in STAGES]
    if not a.podssh:
        return a, "--podssh BIN is needed"
    if wrong:
        return a, f"--stages: {', '.join(wrong)} is no stage of {', '.join(STAGES)}"
    if "dest" in stages and not a.destination:
        return a, "the stage dest needs --destination"
    if "roads" in stages and not a.doctor_road:
        return a, "the stage roads needs --doctor-road FLAGS, once for each road"
    if not (1 <= a.rounds <= 20) or not (1 <= a.count <= 100) or not (60 <= a.budget <= 7200):
        return a, "--rounds 1 to 20, --count 1 to 100, --budget 60 to 7200"
    if ":" not in a.target or not a.target.rpartition(":")[2].isdigit():
        return a, "--target HOST:PORT"
    a.stage_list = stages
    return a, None


def of_stage(runs: list[dict], stage: str, host: str) -> list[dict]:
    return [r for r in runs if r["stage"] == stage and r.get("host") == host]


def measure(a, cmd: list[str], env: dict) -> tuple[dict, int]:
    """Run the stages of `a` with podssh as `cmd`; the result and the exit."""
    seed = a.seed if a.seed is not None else int(time.time())
    rng = random.Random(seed)
    with tempfile.TemporaryDirectory(prefix="relay-measure-", ignore_cleanup_errors=True) as scratch:
        runner = Runner(cmd, lib.env_for_runs(env, str(Path(scratch) / "cache")), a.budget)
        version = runner.run(["--version"], 30.0)
        if version["code"] != 0:
            return {"error": f"podssh does not run: {why(version) or version['err'] or 'no version'}"}, 2
        params = ("hosts", "rounds", "count", "target", "size", "doctor_road", "ping_road")
        result = {"schema": 1, "tool": "relay-measure", "draft": True, "started": now_iso(), "seed": seed,
                  "conditions": lib.conditions(env, version["out"].strip()),
                  "params": {k: getattr(a, k) for k in params},
                  "stages": a.stage_list, "runs": [], "note": "DRAFT harness: each figure is UNVERIFIED"}
        runs = result["runs"]
        hosts: list[str] = []
        if any(s in a.stage_list for s in HOST_STAGES):
            hosts, failed = hosts_of(runner, a.hosts)
            if failed:
                result["hosts_error"] = failed
        result["hosts"] = hosts
        if "pool" in a.stage_list:
            stage_pool(runner, hosts, a, rng, runs)
        if "trace" in a.stage_list:
            stage_trace(runner, hosts, a, rng, runs)
        if "forward" in a.stage_list:
            stage_forward(runner, hosts, runs)
        summaries = [lib.summarize(h, of_stage(runs, "pool", h), of_stage(runs, "trace", h),
                                   of_stage(runs, "forward", h)) for h in hosts]
        result["rank"] = lib.rank(summaries) if "pool" in a.stage_list else summaries
        if "roads" in a.stage_list:
            stage_roads(runner, a.doctor_road, runs)
        if "dest" in a.stage_list:
            first = result["rank"][0] if result["rank"] else None
            stage_dest(runner, a, first["host"] if first and first["opened"] else None, Path(scratch), runs)
            result["dest"] = [r for r in runs if r["stage"] == "dest"]
        result["ended"] = now_iso()
        result["podssh_runs"] = runner.count
        result["not_run"] = runner.skipped
    needs_hosts = any(s in a.stage_list for s in HOST_STAGES)
    if needs_hosts and not hosts:
        return result, 1
    if "pool" in a.stage_list and not any(s["opened"] for s in result["rank"]):
        return result, 1
    return result, 0


def write(path: str, doc: dict) -> None:
    part = path + ".part"
    with open(part, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    os.replace(part, path)


def main(argv: list[str]) -> int:
    a, refused = arguments(argv)
    if a.self_test:
        import relay_measure_selftest
        return relay_measure_selftest.main()
    if refused:
        print(f"relay-measure: {refused}", file=sys.stderr)
        return 2
    result, code = measure(a, [a.podssh], dict(os.environ))
    if "error" in result:
        print(f"relay-measure: {result['error']}", file=sys.stderr)
        return code
    write(a.out, result)
    for i, s in enumerate(result["rank"], 1):
        print(f"{i:2} {s['host']}: opened {s['opened']} of {s['tries']}, open p50 {lib.cell(s['open_ms']['p50'])} ms, "
              f"p95 {lib.cell(s['open_ms']['p95'])} ms, ping p50 {lib.cell(s['rtt_ms']['p50'])} ms, "
              f"GitHub's key {s['forward'] or '-'}")
    for d in result.get("dest", []):
        print(f"dest {d['road']}: {d['line']}")
    for r in (r for r in result["runs"] if r["stage"] == "roads"):
        bad = ", ".join(f"{c['check']} {c['status']}" for c in r["checks"] if c["status"] != "ok") or "each ok"
        tail = f"; {r['why']}" if r["why"] else ""
        print(f"road {r['road']}: {len(r['checks'])} checks, {bad}{tail}")
    if a.ci:
        lib.write_summary(result, dict(os.environ))
    print(f"relay-measure: wrote {a.out} ({result['podssh_runs']} runs of podssh, {result['not_run']} not run)",
          file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
