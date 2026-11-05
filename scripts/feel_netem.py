#!/usr/bin/env python3
"""The links of scripts/fake_shape.py's four profiles as `tc netem` on the
loopback, for scripts/feel-matrix.py --links netem (T-660): the kernel's own
queue, delay and loss, as the reference for the fake links that shape in
user space, on a host where root may shape (a GitHub Actions runner).

Each link is read from fake_shape.PROFILES, so the two never drift: the
same delay each way, the same rate, the same loss in a thousand, and the
same queue in full packets. Only the packets to and from the far ends'
ports are shaped (a u32 filter on each port, TCP and UDP alike), each way
on a netem of its own, as the stand-in proxy shapes each way of a client's
first hop alone; the loopback's other packets (a resolver's stub, the
runner's own) pass as before.

The loopback's MTU becomes a link's 1500 bytes, and its segmentation
offloads are turned off where ethtool can: netem queues, delays and loses a
packet whole, and at the loopback's own 65536 bytes one packet would be 44
of a real link's. Each change is put back at the end.

tc, ip and ethtool change the host as root: directly when this process is
root, else through `sudo -n`, which fails rather than asks. Each has a limit.
"""

import json
import math
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_shape  # noqa: E402

DEV = "lo"
# A link's packet, as Ethernet's; fake_shape's queues are counted in these.
MTU = 1500
LIMIT = 30
# The prio qdisc's bands: 1:2 takes each packet that no filter names, 1:3
# those toward a far end, 1:4 those from one.
PRIOMAP = ["1"] * 16
TOWARD, FROM = "1:3", "1:4"
# A queue of fake_shape with no bound (0), as netem counts one.
NO_BOUND = 1_000_000
# ethtool's names of the offloads that make a packet larger than the MTU.
OFFLOADS = {"tso": "tcp-segmentation-offload", "gso": "generic-segmentation-offload",
            "gro": "generic-receive-offload"}


class Unavailable(Exception):
    """The host cannot shape its loopback, and why."""


def link(name):
    """A profile's link as (delay in ms each way, rate in bytes a second,
    queue in bytes, loss in a thousand); ValueError for no such profile."""
    kind, _, rest = fake_shape.link_of(f"profile:{name}").partition(":")
    if kind != "link":
        raise ValueError(f"profile:{name} is no link")
    delay, rate, queue, loss, _seed = (int(v) for v in rest.split(":"))
    return delay, rate, queue, loss


def netem_args(name):
    """netem's arguments for a profile: its delay, its rate in bits, its
    queue in full packets (netem counts those in flight too, as fake_shape
    counts its bytes in flight), and its loss."""
    delay, rate, queue, loss = link(name)
    packets = math.ceil(queue / MTU) if queue else NO_BOUND
    args = ["delay", f"{delay}ms", "rate", f"{rate * 8}bit", "limit", str(packets)]
    if loss:
        args += ["loss", f"{loss / 10:g}%"]
    return args


class Links:
    """The loopback, shaped one profile at a time, and put back at the end."""

    def __init__(self, out):
        self.out = Path(out)
        self.mtu = None
        self.offloads = []
        self.record = {"device": DEV, "mtu": MTU, "kernel": platform.release(), "shapes": {}}

    def root(self, argv, check=True):
        """`argv` as root, its exit read from its own process; Unavailable
        when it fails and `check` asks."""
        program = shutil.which(argv[0]) or argv[0]
        command = [program] + argv[1:] if os.geteuid() == 0 else ["sudo", "-n", program] + argv[1:]
        try:
            done = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=LIMIT, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise Unavailable(f"{' '.join(argv)}: {e}") from e
        if check and done.returncode != 0:
            why = (done.stderr.strip().splitlines() or [""])[-1]
            raise Unavailable(f"{' '.join(argv)}: exit {done.returncode}: {why}")
        return done

    def setup(self):
        """The tools, netem itself (a qdisc added and removed), the MTU and
        the offloads; each step that fails says why."""
        for tool in ("tc", "ip"):
            if shutil.which(tool) is None:
                raise Unavailable(f"no {tool} here (iproute2)")
        if os.geteuid() != 0 and shutil.which("sudo") is None:
            raise Unavailable("not root, and no sudo")
        try:
            self.mtu = int(Path(f"/sys/class/net/{DEV}/mtu").read_text().strip())
        except (OSError, ValueError) as e:
            raise Unavailable(f"the MTU of {DEV}: {e}") from e
        self.clear()
        self.root(["tc", "qdisc", "add", "dev", DEV, "root", "netem", "delay", "0ms"])
        self.clear()
        self.record["tc"] = self.root(["tc", "-V"], check=False).stdout.strip()
        self.record["mtu_before"] = self.mtu
        if self.mtu != MTU:
            self.root(["ip", "link", "set", "dev", DEV, "mtu", str(MTU)])
        self.offload(False)
        self.save()

    def offload(self, on):
        """The offloads off, those that were on and could change; or back
        on. Without ethtool the record says so, and the run goes on: TCP
        then sends a GSO packet of several segments, which netem queues and
        loses whole."""
        if shutil.which("ethtool") is None:
            self.record["ethtool"] = "no ethtool here: the offloads stay as they are"
            return
        if not on:
            shown = subprocess.run(["ethtool", "-k", DEV], stdin=subprocess.DEVNULL, capture_output=True,
                                   text=True, timeout=LIMIT, check=False).stdout
            for short, name in OFFLOADS.items():
                for line in shown.splitlines():
                    if line.strip().startswith(f"{name}:") and ": on" in line and "[fixed]" not in line:
                        self.offloads.append(short)
        changed = [w for short in self.offloads for w in (short, "on" if on else "off")]
        if changed:
            self.root(["ethtool", "-K", DEV] + changed, check=False)
        after = subprocess.run(["ethtool", "-k", DEV], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               timeout=LIMIT, check=False).stdout
        self.record["ethtool"] = [line.strip() for line in after.splitlines()
                                  if line.strip().split(":")[0] in OFFLOADS.values()]

    def shape(self, name, ports):
        """The loopback as profile `name` for the packets of `ports`, each
        way on a netem of its own; `none` leaves the MTU and the offloads
        alone in place."""
        self.clear()
        self.record["shapes"][name] = {"ports": list(ports)}
        if name == "none":
            self.save()
            return
        args = netem_args(name)
        self.record["shapes"][name]["netem"] = " ".join(args)
        self.root(["tc", "qdisc", "add", "dev", DEV, "root", "handle", "1:", "prio", "bands", "4",
                   "priomap"] + PRIOMAP)
        self.root(["tc", "qdisc", "add", "dev", DEV, "parent", TOWARD, "handle", "30:", "netem"] + args)
        self.root(["tc", "qdisc", "add", "dev", DEV, "parent", FROM, "handle", "40:", "netem"] + args)
        for port in ports:
            for field, band in (("dport", TOWARD), ("sport", FROM)):
                self.root(["tc", "filter", "add", "dev", DEV, "parent", "1:", "protocol", "ip", "prio", "1",
                           "u32", "match", "ip", field, str(port), "0xffff", "flowid", band])
        self.save()

    def tally(self, name):
        """What the qdiscs counted under profile `name` (packets sent,
        dropped, over the limit), into netem.NAME.txt beside the cells."""
        shown = [self.root(argv, check=False).stdout for argv in
                 (["tc", "-s", "qdisc", "show", "dev", DEV], ["tc", "filter", "show", "dev", DEV])]
        (self.out / f"netem.{name}.txt").write_text("\n".join(shown), encoding="utf-8")

    def clear(self):
        """No qdisc of ours on the loopback; none there is no failure."""
        self.root(["tc", "qdisc", "del", "dev", DEV, "root"], check=False)

    def restore(self):
        """The loopback as it was: no qdisc, its MTU, its offloads."""
        self.clear()
        if self.mtu is not None and self.mtu != MTU:
            self.root(["ip", "link", "set", "dev", DEV, "mtu", str(self.mtu)], check=False)
        if self.offloads:
            self.offload(True)

    def save(self):
        with open(self.out / "netem.json", "w", encoding="utf-8") as f:
            json.dump(self.record, f, indent=1)
            f.write("\n")
