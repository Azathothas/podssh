"""The offline self-test of scripts/relay-measure.py (T-605, DRAFT).

A stand-in podssh, written here into a temporary directory, answers each
command that the harness runs with canned JSON, under names of `.test`, and
logs when each of its runs started and ended. No network is used. The
checks:

1. No two runs of podssh overlap: the archive's harness ran its cells at
   once, and each cell's number was a share of one link. The plant
   RELAY_MEASURE_PLANT=parallel runs two probes at once, and must fail here.
2. A run that hangs is killed at its limit, named, and the stages go on.
3. The summary and the rank of the canned legs are the ones written here by
   hand: a tie keeps the order of the list, a host that never opened is last.
4. No proxy address and no proxy credential reaches the result.
5. The runs' cache directory, which would hold a token, is gone at the end.
6. The percentiles are by the nearest rank, as `podssh ping` gives them.

Run: python3 scripts/relay-measure.py --self-test. Exit 0 when each check
passed, 1 when one failed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import relay_measure_lib as lib  # noqa: E402

# The stand-in: each host's canned times, and two hosts that fail.
STAND_IN = r'''
import json, os, sys, time
log = os.environ["STAND_IN_LOG"]
def mark(word):
    with open(log, "a") as fh:
        fh.write(f"{word} {time.time():.6f} {os.getpid()} {os.environ.get('PODSSH_CACHE_DIR', '')}\n")
mark("start")
argv = sys.argv[1:]
cache = os.environ.get("PODSSH_CACHE_DIR")
if cache:
    os.makedirs(cache, exist_ok=True)
    with open(os.path.join(cache, "token-of-the-run"), "w") as fh:
        fh.write("not a token")
host = argv[argv.index("--relay-host") + 1] if "--relay-host" in argv else ""
UP = {"fast.example.test": 300, "slow.example.test": 900, "tie.example.test": 320}
out, code = {}, 0
if argv[:1] == ["--version"]:
    print("podssh 0.0.0-stand-in"); mark("end"); sys.exit(0)
if argv[:3] == ["relay", "info", "--json"]:
    pool = [{"host": h} for h in ("slow.example.test", "tie.example.test", "hang.example.test", "down.example.test")]
    out = {"schema": 1, "relay": "fast.example.test", "info": {"pool": pool}}
elif argv[:1] == ["ping"]:
    time.sleep(0.2)
    if host == "hang.example.test":
        time.sleep(30)
    if host in UP:
        leg = {"host": host + ":443", "connect_ms": 100.0, "tls_ms": 50.0, "upgrade_ms": float(UP[host]),
               "pings": {"min_ms": 70.0, "p50_ms": 80.0, "p95_ms": 90.0, "max_ms": 95.0}, "pings_lost": 0,
               "error": None}
    else:
        leg, code = {"host": host + ":443", "error": "no answer"}, 69
        print("podssh ping: no relay host answered", file=sys.stderr)
    out = {"schema": 1, "relays": [leg], "destination": None, "exit": code}
elif argv[:2] == ["relay", "trace"]:
    out = {"schema": 1, "relay": host, "edge": "TST", "exit": 0,
           "target": {"ok": True, "connect_ms": 40, "first_byte_ms": 90, "bytes_seen": 22, "verdict": "banner"}}
elif argv[:1] == ["doctor"]:
    status = "FAIL" if host == "down.example.test" else "ok"
    out = {"schema": 1, "checks": [{"section": "relay", "check": "forward", "status": status, "detail": host}]}
print(json.dumps(out))
mark("end")
sys.exit(code)
'''


def load_harness():
    spec = importlib.util.spec_from_file_location("relay_measure", HERE / "relay-measure.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def intervals(log: Path) -> tuple[list[tuple[float, float]], list[float], set[str]]:
    """The runs that ended, as (start, end); the starts of runs that never
    ended; and the cache directories that the runs were given."""
    starts: dict[str, float] = {}
    done: list[tuple[float, float]] = []
    caches: set[str] = set()
    for line in log.read_text().splitlines():
        word, at, pid, *cache = line.split(" ", 3)
        caches.update(c for c in cache if c)
        if word == "start":
            starts[pid] = float(at)
        elif pid in starts:
            done.append((starts.pop(pid), float(at)))
    return sorted(done), sorted(starts.values()), caches


def main() -> int:
    harness = load_harness()
    harness.PROBE_LIMIT = 2.0
    harness.PAUSE = 0.0
    failures: list[str] = []

    def check(ok: bool, what: str) -> None:
        print(f"{'ok  ' if ok else 'FAIL'} {what}")
        if not ok:
            failures.append(what)

    with tempfile.TemporaryDirectory(prefix="relay-measure-selftest-") as tmp:
        tmp_path = Path(tmp)
        stand_in = tmp_path / "podssh_stand_in.py"
        stand_in.write_text(STAND_IN)
        log = tmp_path / "runs.log"
        env = dict(os.environ)
        env.update({"STAND_IN_LOG": str(log), "HTTPS_PROXY": "http://user:s3cret-word@proxy.invalid:3128"})
        a = SimpleNamespace(hosts="all", rounds=2, count=3, target="github.com:22", size="1M", doctor_road=[],
                            ping_road=[], destination=None, identity=None, known_hosts=None, budget=600.0, seed=7,
                            stage_list=["pool", "trace", "forward"])
        result, code = harness.measure(a, [sys.executable, "-I", str(stand_in)], env)
        done, unended, caches = intervals(log)

        # A run that never ended was killed at its limit: it ran until then.
        killed = [(at, at + harness.PROBE_LIMIT - 0.1) for at in unended]
        overlaps, last_end = 0, 0.0
        for start, end in sorted(done + killed):
            overlaps += start < last_end
            last_end = max(last_end, end)
        check(not overlaps, f"no two runs of podssh overlap ({len(done)} runs that ended, {overlaps} overlaps)")
        hung = [r for r in result["runs"] if r.get("host") == "hang.example.test" and r["stage"] == "pool"]
        check(len(hung) == 2 and all(r["why"] == "podssh did not end within its limit" for r in hung),
              "each hung run is killed at its limit and named")
        check(len(unended) == 2, f"the hung runs are the only ones that never ended ({len(unended)})")
        order = [s["host"].split(".")[0] for s in result["rank"]]
        check(order == ["fast", "tie", "slow", "hang", "down"], f"the rank keeps a tie in the list's order: {order}")
        fast = result["rank"][0]
        check((fast["opened"], fast["tries"], fast["open_ms"]["p50"]) == (2, 2, 450.0),
              f"the open time is connect, TLS and the upgrade: {fast['open_ms']}")
        check(fast["forward"] == "ok" and result["rank"][-1]["forward"] == "fail", "GitHub's key is kept per host")
        check(fast["relay_dial_ms"]["p50"] == 40.0, "the relay's own dial comes from /trace")
        text = json.dumps(result)
        check("s3cret-word" not in text and "proxy.invalid" not in text and result["conditions"]["proxy"] == "http",
              "no proxy address or credential in the result, only its kind")
        check(code == 0, f"the exit is 0 when a host opened ({code})")
        check(lib.markdown(result).count(".example.test |") == 5, "the step summary has a row for each host")
        check(bool(caches) and not any(Path(c).exists() for c in caches),
              f"the runs' cache directory is gone at the end ({len(caches)} given)")

    s = lib.spread([5, 1, 3, 2, 4, 10, 9, 8, 7, 6])
    check((s["min"], s["p50"], s["p95"], s["max"]) == (1, 5, 10, 10), f"nearest-rank percentiles: {s}")
    check(lib.proxy_kind({"HTTPS_PROXY": "socks5h://u:p@h:1"}) == "socks5h" and lib.proxy_kind({}) == "none",
          "the proxy's kind alone")
    print(f"relay-measure self-test: {'FAIL, ' + str(len(failures)) + ' failed' if failures else 'each check passed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
