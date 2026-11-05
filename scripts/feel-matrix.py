#!/usr/bin/env python3
"""What a user feels, on each road through each of osewa's four lab shapes
(T-660): a key's echo idle and while a download runs on the same connection,
cold connects with their first command, and the download's rate while one
types. A cell of podssh is one run of `podssh ping --json --under-load
--connect-runs N`, and N runs of `podssh ssh DEST true`, each timed from its
process's spawn; OpenSSH's client is the reference (scripts/feel_openssh.py).
Each end is on this host's loopback: OpenSSH's sshd for this user, `podssh
relay serve` with a CA of the run, a pair of it with its node in front of the
sshd, and scripts/fake-proxy.py --shape between each client and its first
hop, as the client's HTTPS_PROXY. No root and no netem.

With --links netem the kernel shapes instead (scripts/feel_netem.py): `tc
netem` on the loopback, as root, for the packets of the far ends' ports,
with the same links; each client dials its far end with no proxy. It is
the reference for the links of user space, and runs on a GitHub Actions
runner (.github/workflows/feel-netem.yml). Only the roads of one host run
so: openssh, direct, and osewa's release binary beside them, over QUIC and
over its WebSocket (scripts/feel_osewa.py; a reference, never a road).

Usage: feel-matrix.py PODSSH [--links proxy|netem] [--osewa OSEWA]
                             [--roads LIST] [--shapes LIST] [--runs N]
                             [--out DIR]

  --links   proxy: the stand-in proxy shapes in user space (the default);
            netem: tc netem on the loopback, as root or through sudo -n
  --osewa   osewa's release binary, for the rows osewa-quic and osewa-ws
  --roads   openssh, direct, role, node, iroh, derp, osewa-quic, osewa-ws
            (default: the first six with proxy; openssh, direct and the two
            of osewa with netem)
  --shapes  none, far, cellular, wifi, slow (default: each)
  --runs    the cold connects of each cell (default 5, at most 20)
  --out     the raw files (default .work/feel/STAMP): ROAD.SHAPE.json, its
            .err, ROAD.SHAPE.process.json, and summary.tsv; with netem also
            netem.json and netem.SHAPE.txt (the qdiscs' counts), and
            osewa-server.log

The rows iroh and derp say why they did not run: `podssh ping` reaches no
iroh: and no derp: ticket, and a relay of either on this host is a Rust
test's alone. So does each row that its way of shaping cannot shape. Each
wait has a limit. The exit is 0 when each cell that ran passed, 1 when one
failed, 2 when the setup could not run. No key or token is printed; the
keys and the pair are throwaways of a scratch directory, removed at the
end, and the loopback is put back as it was, also after a TERM.
"""

import argparse
import datetime
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import feel_netem  # noqa: E402
import feel_openssh  # noqa: E402
import feel_osewa  # noqa: E402

ROADS = ("openssh", "direct", "role", "node", "iroh", "derp", "osewa-quic", "osewa-ws")
LINKS = ("proxy", "netem")
# What each way of shaping runs when no --roads is given.
DEFAULT_ROADS = {"proxy": ("openssh", "direct", "role", "node", "iroh", "derp"),
                 "netem": ("openssh", "direct", "osewa-quic", "osewa-ws")}
SHAPES = ("none", "far", "cellular", "wifi", "slow")
CELL_LIMIT = 300
SETUP_LIMIT = 60
NOT_HERE = {
    "iroh": "podssh ping reaches no iroh: ticket (its session runs in podssh ssh's own code), and an iroh "
            "relay on this host is a Rust test's alone",
    "derp": "podssh ping reaches no derp: ticket, and a DERP server on this host is a Rust test's alone",
}
# The roads that a way of shaping cannot shape as the others, and why.
NOT_WITH = {
    "proxy": {road: "osewa has no proxy client (docs/research/osewa-code.md), so the stand-in proxy cannot "
                    "shape it: its rows run with --links netem" for road in feel_osewa.CARRIERS},
    "netem": {road: "each of its legs is on the loopback, and a filter by port would shape the role's own leg "
                    "to the sshd beside the client's: it runs with --links proxy" for road in ("role", "node")},
}
# The variables of the machine that would carry a client elsewhere.
DROPPED = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY",
           "no_proxy", "SSH_AUTH_SOCK", "PODSSH_RELAY", "PODSSH_RELAY_ADDR", "PODSSH_RELAY_TOKEN")


class Setup(Exception):
    """A part of the bench that could not start, and why."""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(test, limit, what):
    deadline = time.monotonic() + limit
    while not test():
        if time.monotonic() > deadline:
            raise Setup(f"{what} within {limit} s")
        time.sleep(0.1)


class Bench:
    """The far ends of the run, stopped and removed when it ends."""

    def __init__(self, podssh, out, runs, links="proxy"):
        self.podssh, self.out, self.runs, self.links = podssh, out, runs, links
        self.osewa = None
        # A short path: a ControlMaster's socket must fit in 108 bytes.
        self.work = Path(tempfile.mkdtemp(prefix="feel-"))
        self.home = self.work / "home"
        (self.home / "cache").mkdir(parents=True)
        self.children = []
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.sshd_port = self.role_port = None
        self.pair = f"feel{os.getpid()}"

    def env(self, **more):
        env = {k: v for k, v in os.environ.items() if k not in DROPPED}
        # Each road ends on this host: no record of a node at n0's, and no
        # transit road through Least Authority's relay.
        env.update(HOME=str(self.home), XDG_CACHE_HOME=str(self.home / "cache"), PODSSH_SSH_CONFIG="none",
                   PODSSH_IROH_PKARR="off", PODSSH_TRANSIT="no")
        # The run's CA, once made: with netem no road has TLS, and none is made.
        ca = self.work / "certs" / "ca.pem"
        if ca.exists():
            env["SSL_CERT_FILE"] = str(ca)
        env.update(more)
        return env

    def spawn(self, argv, log, env=None):
        with open(log, "ab") as sink:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=sink, stderr=sink, env=env)
        self.children.append(child)
        return child

    def stop(self):
        for child in reversed(self.children):
            child.terminate()
            try:
                child.wait(10)
            except subprocess.TimeoutExpired:
                child.kill()
        shutil.rmtree(self.work, ignore_errors=True)

    def keys(self):
        """The host key and the user's key, throwaways of this run."""
        for name in ("host_key", "id"):
            argv = ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"feel-{name}", "-f", str(self.work / name)]
            if shutil.which("ssh-keygen") is None:
                argv = [self.podssh, "keygen"] + argv[1:]
            if subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=SETUP_LIMIT,
                              check=False).returncode != 0:
                raise Setup(f"no {name} was made")
        shutil.copy(self.work / "id.pub", self.work / "authorized_keys")

    def sshd(self):
        """OpenSSH's server on the loopback, for this user and the run's key."""
        program = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
        if program is None:
            raise Setup("no sshd here (sh scripts/cloud-setup.sh installs openssh-server)")
        self.sshd_port = free_port()
        config = self.work / "sshd_config"
        config.write_text(
            f"ListenAddress 127.0.0.1\nPort {self.sshd_port}\nHostKey {self.work / 'host_key'}\n"
            f"AuthorizedKeysFile {self.work / 'authorized_keys'}\nStrictModes no\nUsePAM no\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n"
            "PidFile none\n")
        if os.getuid() == 0:
            os.makedirs("/run/sshd", exist_ok=True)
        # OpenSSH 9.8 and later penalise a source of many sessions; older ones
        # do not know the keyword.
        knows = [program, "-t", "-f", str(config), "-o", "PerSourcePenalties=no"]
        if subprocess.run(knows, capture_output=True, timeout=SETUP_LIMIT, check=False).returncode == 0:
            with open(config, "a", encoding="utf-8") as f:
                f.write("PerSourcePenalties no\n")
        log = self.work / "sshd.log"
        self.spawn([program, "-D", "-e", "-f", str(config)], log)
        wait_until(lambda: "listening on" in log.read_text(errors="replace"), 15, "sshd did not listen")

    def certs(self):
        """A CA of the run and the role's leaf for relay-a.test, as the fault
        harness makes them (scripts/interop-faults-certs.sh)."""
        certs = self.work / "certs"
        certs.mkdir()
        made = subprocess.run(["sh", "-c", '. "$0"; echo "$FAULT_CERTS"', str(HERE / "interop-faults-certs.sh")],
                              env={**os.environ, "FK": str(certs), "SAN": "DNS:relay-a.test"},
                              capture_output=True, text=True, timeout=SETUP_LIMIT, check=False)
        if made.stdout.strip() != "made":
            raise Setup("the test certificates were not made (openssl)")

    def role(self):
        """podssh relay serve on the loopback, which dials the loopback's sshd."""
        port_file = self.work / "role-port"
        certs = self.work / "certs"
        argv = [self.podssh, "relay", "serve", "--listen", "127.0.0.1:0", "--cert", str(certs / "relay.pem"),
                "--key", str(certs / "relay.key"), "--port-file", str(port_file), "--mint", "anyone",
                "--allow-private"]
        self.spawn(argv, self.work / "role.log", self.env())
        wait_until(lambda: port_file.exists() and port_file.read_text().strip(), 10, "the role did not start")
        self.role_port = int(port_file.read_text().strip())

    def node(self):
        """A pair of the role, kept in the run's home, and its node in front of
        the sshd; the node's own leg is not shaped."""
        env = self.env(PODSSH_RELAY=f"relay-a.test:{self.role_port}", PODSSH_RELAY_ADDR="relay-a.test=127.0.0.1")
        paired = subprocess.run([self.podssh, "relay", "pair", self.pair], stdin=subprocess.DEVNULL, env=env,
                                capture_output=True, text=True, timeout=SETUP_LIMIT, check=False)
        if paired.returncode != 0:
            raise Setup(f"relay pair: exit {paired.returncode}")
        log = self.work / "node.log"
        self.spawn([self.podssh, "node", self.pair, f"127.0.0.1:{self.sshd_port}"], log, env)
        wait_until(lambda: "serving" in log.read_text(errors="replace"), SETUP_LIMIT, "the node said no 'serving'")

    def proxy(self, shape):
        """The stand-in proxy, shaped, in front of each first hop."""
        port_file = self.work / f"proxy-{shape}-port"
        argv = [sys.executable, str(HERE / "fake-proxy.py"), "--port-file", str(port_file),
                "--log", str(self.work / f"proxy-{shape}.log"), "--map", f"sshd.test=127.0.0.1:{self.sshd_port}"]
        if self.role_port is not None:
            argv += ["--map", f"relay-a.test=127.0.0.1:{self.role_port}"]
        if shape != "none":
            argv += ["--shape", f"profile:{shape}"]
        child = self.spawn(argv, self.work / f"proxy-{shape}.err")
        wait_until(lambda: port_file.exists() and port_file.read_text().strip(), 10, "the proxy did not start")
        return child, int(port_file.read_text().strip())

    def common(self, known):
        """The options of each login: the run's key alone, no prompt, and the
        far end's key recorded in the scratch directory."""
        return ["-i", str(self.work / "id"), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known}"]

    def road(self, road):
        """A road's flags and destination for ping and ssh, and ping's own: the
        relay leg goes to the sshd, never to github.com from this bench. With
        netem there is no proxy to name sshd.test, so the address itself."""
        if road == "direct":
            return ["--direct", "-p", str(self.sshd_port)], f"{self.user}@{self.far_name()}", []
        if road == "role":
            flags = ["--relay-host", f"relay-a.test:{self.role_port}", "-p", str(self.sshd_port)]
            return flags, f"{self.user}@127.0.0.1", ["--target", f"127.0.0.1:{self.sshd_port}"]
        return [], f"node://{self.user}@{self.pair}", []

    def cell(self, road, shape, proxy_port):
        """One cell of podssh: ping's measures, then `ssh DEST true` as a
        process, each run from its spawn to its exit."""
        name = f"{road}.{shape}"
        # With netem the kernel shapes the far end's port, and podssh dials it
        # itself, as a client with no proxy does.
        env = self.env(HTTPS_PROXY=f"http://127.0.0.1:{proxy_port}") if proxy_port else self.env()
        flags, dest, ping_only = self.road(road)
        common = self.common(self.work / f"known_hosts.{road}")
        argv = [self.podssh, "ping", "--json", "--under-load", "--connect-runs", str(self.runs)]
        code = run_to(argv + ping_only + flags + common + [dest], env, self.out / f"{name}.json",
                      self.out / f"{name}.err")
        samples, ssh_code = [], 0
        for _ in range(self.runs):
            started = time.monotonic()
            ssh_code = run_to([self.podssh, "ssh"] + flags + common + [dest, "true"], env, None,
                              self.out / f"{name}.process.err")
            if ssh_code != 0:
                break
            samples.append(feel_openssh.ms(time.monotonic() - started))
        doc = {"command": "podssh ssh DEST true", **feel_openssh.summary(samples), "samples_ms": samples,
               "exit": ssh_code}
        write_json(self.out / f"{name}.process.json", doc)
        return code or ssh_code

    def openssh(self, shape, proxy_port):
        """The reference: OpenSSH's ssh through the same proxy, or with
        netem straight to the sshd's shaped port."""
        base = ["ssh", "-F", "/dev/null", "-o", "LogLevel=ERROR", "-o", "IdentityAgent=none"]
        if proxy_port:
            via = f"{sys.executable} -I {HERE / 'feel_openssh.py'} --connect-via 127.0.0.1:{proxy_port} %h %p"
            base += ["-o", f"ProxyCommand={via}"]
        base += ["-p", str(self.sshd_port)] + self.common(self.work / "known_hosts.openssh")
        doc = feel_openssh.measure(base, f"{self.user}@{self.far_name()}", self.runs,
                                   str(self.work / f"ctl-{shape}"))
        write_json(self.out / f"openssh.{shape}.json", doc)
        return doc["exit"]

    def far_name(self):
        return "sshd.test" if self.links == "proxy" else "127.0.0.1"

    def start_osewa(self, program):
        """osewa's server on the loopback and the run's device in it; its log
        and login's go with the raw files."""
        self.osewa = feel_osewa.Osewa(program, self.work, self.spawn)
        self.osewa.start(self.env(), self.out / "osewa-server.log")

    def ports(self):
        """The far ends' ports, which netem shapes: the sshd's, and osewa's."""
        return [self.sshd_port] + ([self.osewa.port] if self.osewa else [])

    def osewa_cell(self, road, shape):
        """One cell of osewa, in the JSON of OpenSSH's reference."""
        doc = self.osewa.measure(road, self.env(), self.runs)
        write_json(self.out / f"{road}.{shape}.json", doc)
        return doc["exit"]


def run_to(argv, env, out, err):
    """The exit code of `argv` within CELL_LIMIT, read from its own process;
    124 past it."""
    with (open(out, "wb") if out else open(os.devnull, "wb")) as sink, open(err, "ab") as errors:
        try:
            return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=sink, stderr=errors, env=env,
                                  timeout=CELL_LIMIT, check=False).returncode
        except subprocess.TimeoutExpired:
            errors.write(f"feel-matrix: no end within {CELL_LIMIT} s\n".encode())
            return 124


def write_json(path, doc):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


HEADER = ["road", "shape", "exit", "idle_p50_ms", "idle_p95_ms", "loaded_p50_ms", "loaded_p95_ms", "keys_beside",
          "connect_p50_ms", "process_p50_ms", "typing_mib_s", "note"]


def row(road, shape, doc, process, note=""):
    """A line of summary.tsv: the figures of a cell's raw files."""
    far = (doc or {}).get("destination") or {}
    under = far.get("under_load") or {}
    idle, loaded, load = under.get("idle") or {}, under.get("loaded") or {}, under.get("load") or {}
    seconds = load.get("typing_seconds")
    rate = load["typing_bytes"] / 1048576 / seconds if seconds else None
    beside = sum(1 for k in loaded.get("samples", []) if k.get("beside")) if under else None

    def shown(value):
        return "-" if value is None else f"{value:.1f}" if isinstance(value, float) else str(value)

    figures = [(doc or {}).get("exit"), idle.get("p50_ms"), idle.get("p95_ms"), loaded.get("p50_ms"),
               loaded.get("p95_ms"), beside, (far.get("connect") or {}).get("p50_ms"),
               (process or {}).get("p50_ms"), rate]
    return [road, shape] + [shown(v) for v in figures] + [note or far.get("error") or ""]


def why_not(road, links, osewa):
    """Why a road does not run here with this way of shaping, or ''."""
    if road in NOT_HERE:
        return NOT_HERE[road]
    if road in NOT_WITH[links]:
        return NOT_WITH[links][road]
    if road == "openssh" and not shutil.which("ssh"):
        return "no ssh here"
    if road in feel_osewa.CARRIERS and osewa is None:
        return "no --osewa (osewa's release binary)"
    return ""


def main():
    parser = argparse.ArgumentParser(description="What a user feels, on each road through each shape (T-660).")
    parser.add_argument("podssh")
    parser.add_argument("--links", choices=LINKS, default="proxy")
    parser.add_argument("--osewa", default=None)
    parser.add_argument("--roads", default=None)
    parser.add_argument("--shapes", default=",".join(SHAPES))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    roads = [r for r in (args.roads or ",".join(DEFAULT_ROADS[args.links])).split(",") if r]
    shapes = [s for s in args.shapes.split(",") if s]
    for what, given, known in (("road", roads, ROADS), ("shape", shapes, SHAPES)):
        for value in given:
            if value not in known:
                parser.error(f"no {what} {value}: one of {', '.join(known)}")
    if not 1 <= args.runs <= 20:
        parser.error("--runs: from 1 to 20")
    podssh = shutil.which(args.podssh) or args.podssh
    if not os.access(podssh, os.X_OK):
        parser.error(f"{args.podssh}: not a program")
    osewa = None
    if args.osewa:
        osewa = os.path.abspath(shutil.which(args.osewa) or args.osewa)
        if not os.access(osewa, os.X_OK):
            parser.error(f"--osewa {args.osewa}: not a program")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.out) if args.out else HERE.parent / ".work" / "feel" / stamp
    out.mkdir(parents=True, exist_ok=True)
    # The reference offers the run's key alone, as podssh does.
    os.environ.pop("SSH_AUTH_SOCK", None)
    # A time limit's TERM ends the run through `finally`, which puts the
    # loopback back.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    bench = Bench(os.path.abspath(podssh), out, args.runs, args.links)
    links = feel_netem.Links(out) if args.links == "netem" else None
    rows, failed, code = [], False, 0
    print("\t".join(HEADER), flush=True)
    try:
        bench.keys()
        bench.sshd()
        ran_here = [r for r in roads if not why_not(r, args.links, osewa)]
        if {"role", "node"} & set(ran_here):
            bench.certs()
            bench.role()
        if "node" in ran_here:
            bench.node()
        if set(feel_osewa.CARRIERS) & set(ran_here):
            bench.start_osewa(osewa)
        if links:
            links.setup()
        for shape in shapes:
            proxy, port = (None, None) if links else bench.proxy(shape)
            if links:
                links.shape(shape, bench.ports())
            for road in roads:
                note = why_not(road, args.links, osewa)
                if note:
                    rows.append(row(road, shape, None, None, f"not run: {note}"))
                else:
                    if road == "openssh":
                        ran = bench.openssh(shape, port)
                    elif road in feel_osewa.CARRIERS:
                        ran = bench.osewa_cell(road, shape)
                    else:
                        ran = bench.cell(road, shape, port)
                    failed = failed or ran != 0
                    doc = read_json(out / f"{road}.{shape}.json")
                    rows.append(row(road, shape, doc, read_json(out / f"{road}.{shape}.process.json")))
                print("\t".join(rows[-1]), flush=True)
            if links:
                links.tally(shape)
            else:
                proxy.terminate()
                proxy.wait(10)
        code = 1 if failed else 0
    except (Setup, feel_osewa.Setup, feel_netem.Unavailable) as e:
        print(f"feel-matrix: {e}", file=sys.stderr)
        code = 2
    finally:
        if links:
            try:
                links.restore()
            except feel_netem.Unavailable as e:
                print(f"feel-matrix: the loopback was not put back: {e}", file=sys.stderr)
        bench.stop()
        with open(out / "summary.tsv", "w", encoding="utf-8") as f:
            f.write("\n".join("\t".join(r) for r in [HEADER] + rows) + "\n")
    print(f"feel-matrix: the raw files are in {out}")
    return code


if __name__ == "__main__":
    sys.exit(main())
