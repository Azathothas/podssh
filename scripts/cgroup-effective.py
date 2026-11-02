"""The effective CPUs and memory of a cgroup, read here, against `podssh health --json` (T-480).

    python3 scripts/cgroup-effective.py FACTS.json SELF_CGROUP

FACTS.json is the object of `podssh health --json` for a server on this host,
and SELF_CGROUP what `cat /proc/self/cgroup` printed in a session of that
server: the cgroup that podssh's script ran in. This reader takes that path
under /sys/fs/cgroup here, as the server shares this host's view of it (the
gate's servers run in its own container), and computes, apart from podssh's
code, the least of the host's CPUs, the quotas of the cgroup and its parents
(cpu.max of v2, cpu.cfs_quota_us of v1) and its cpuset, and the least of the
host's memory and the limits (memory.max of v2, memory.limit_in_bytes and
hierarchical_memory_limit of v1): the forms of the kernel's cgroup-v2.rst,
cgroup-v1/memory.rst and sched-bwc.rst. It also checks that podssh read the
version and the directory that it reads. Exit 0 when they agree, else 1 with
the difference on stderr.
"""

import json
import os
import sys

ROOT = "/sys/fs/cgroup"


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def count(cpus):
    total = 0
    for part in cpus.split(","):
        first, _, last = part.partition("-")
        total += int(last or first) - int(first) + 1
    return total


def v2(own, cpus, memory):
    path = next(line[3:] for line in own if line.startswith("0::"))
    leaf = ROOT + path
    if not os.path.exists(leaf + "/cgroup.controllers"):
        leaf = ROOT
    at = leaf.rstrip("/")
    levels = [leaf]
    while True:
        at = at.rsplit("/", 1)[0]
        if not at.startswith(ROOT + "/"):
            break
        levels.append(at)
    for level in levels:
        quota = (read(level + "/cpu.max") or "max").split()
        if quota[0] != "max":
            cpus.append(int(quota[0]) / int(quota[1]))
        limit = read(level + "/memory.max") or "max"
        if limit != "max":
            memory.append(int(limit) // 1024)
    cpuset = read(leaf + "/cpuset.cpus.effective")
    if cpuset:
        cpus.append(float(count(cpuset)))
    return leaf


def v1(own, cpus, memory):
    paths = {}
    for line in own:
        _, controllers, path = line.split(":", 2)
        for controller in controllers.split(","):
            paths[controller] = path

    def dir_of(controller):
        d = ROOT + "/" + controller + paths.get(controller, "")
        return d if os.path.isdir(d) else ROOT + "/" + controller

    quota, period = read(dir_of("cpu") + "/cpu.cfs_quota_us"), read(dir_of("cpu") + "/cpu.cfs_period_us")
    if quota and period and int(quota) > 0:
        cpus.append(int(quota) / int(period))
    limit = read(dir_of("memory") + "/memory.limit_in_bytes")
    if limit:
        memory.append(int(limit) // 1024)
    for line in (read(dir_of("memory") + "/memory.stat") or "").splitlines():
        key, _, value = line.partition(" ")
        if key == "hierarchical_memory_limit":
            memory.append(int(value) // 1024)
    cpuset = read(dir_of("cpuset") + "/cpuset.effective_cpus") or read(dir_of("cpuset") + "/cpuset.cpus")
    if cpuset:
        cpus.append(float(count(cpuset)))
    return dir_of("memory")


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: python3 scripts/cgroup-effective.py FACTS.json SELF_CGROUP")
    with open(sys.argv[1], encoding="utf-8") as f:
        facts = json.load(f)
    with open(sys.argv[2], encoding="utf-8") as f:
        own = [line.strip() for line in f if line.strip()]
    host_cpus, host_kib = float(facts["cpus"]), facts["memory"]["total_kib"]
    cpus, memory = [host_cpus], [host_kib]
    if os.path.exists(ROOT + "/cgroup.controllers"):
        version, path = 2, v2(own, cpus, memory)
    elif os.path.isdir(ROOT + "/memory") or os.path.isdir(ROOT + "/cpu"):
        version, path = 1, v1(own, cpus, memory)
    else:
        version, path = None, None
    effective, cgroup = facts["effective"], facts.get("cgroup") or {}
    want_cpus, want_kib = min(cpus), min(memory)
    problems = []
    if cgroup.get("version") != version or cgroup.get("path") != path:
        problems.append(f"podssh read cgroup v{cgroup.get('version')} at {cgroup.get('path')}, here v{version} at {path}")
    if abs(effective["cpus"] - want_cpus) > 0.01:
        problems.append(f"effective.cpus {effective['cpus']}, here {want_cpus} ({cpus})")
    if (effective["cpus_from"] == "host") != (want_cpus >= host_cpus):
        problems.append(f"cpus_from {effective['cpus_from']}, with {want_cpus} of the host's {host_cpus}")
    if effective["memory_total_kib"] != want_kib:
        problems.append(f"effective.memory_total_kib {effective['memory_total_kib']}, here {want_kib} ({memory})")
    if (effective["memory_from"] == "host") != (want_kib >= host_kib):
        problems.append(f"memory_from {effective['memory_from']}, with {want_kib} KiB of the host's {host_kib}")
    available = effective.get("memory_available_kib")
    if available is not None and available > want_kib:
        problems.append(f"memory_available_kib {available} above the limit {want_kib}")
    for problem in problems:
        print(problem, file=sys.stderr)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
