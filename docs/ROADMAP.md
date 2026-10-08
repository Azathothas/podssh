# Roadmap

This page gives the milestones of podssh, in order. Each milestone ends with
something that a user can run. Its exit criteria are commands and results.
[STATUS.md](STATUS.md) gives the measured state.

- Do one milestone at a time, in order.
- Do not start the next milestone until the exit criteria of the current
  one pass on a real host.
- The open work of a milestone is entries in [TODO/](../TODO/INDEX.md),
  named here by id. [TODO/PROGRESS.md](../TODO/PROGRESS.md) gives the order.
  This page has no open checkbox; `cargo todo check` refuses one.
- When an entry is done, close it in `TODO/`, and record the measurement in
  [STATUS.md](STATUS.md) in the same commit. The `- [x]` items below are
  the record of what each milestone delivered.

## M0: Repository rescue (done 2026-10-08)

- [x] The real state is measured: build, tests, binary behaviour, CI.
- [x] CI passes: the IRC grammar fixture keeps its CRLFs.
- [x] Each script limits the build jobs.
- [x] The Tailscale adapter is the cargo feature `ts`; the default build has
      no Tailscale code.
- [x] The documents are README, STATUS, ROADMAP, decisions, defects, a short
      AGENTS.md, and topic pages.

## M1: `podssh proxy`, a byte pipe through the relay (done 2026-10-08)

A host that has `ssh` reaches SSH servers through the relay:
`ssh -o ProxyCommand='podssh proxy %h %p' user@host`. The pipe also works for
each TCP protocol that a tool can speak over stdin and stdout.

- [x] The relay client (`podssh-ws`): full duplex; limits on TCP, the proxy
      exchange, TLS and the upgrade; an idle read limit above the relay's
      keepalive (25 s); WebSocket Close sent, echoed and parsed; fragmented
      messages joined; typed errors that keep the relay's status and reason.
- [x] `HTTPS_PROXY`: `CONNECT relay:443` with the host name (no DNS on the
      client); `https_proxy`, `ALL_PROXY`, `NO_PROXY`; Basic proxy
      credentials.
- [x] Trust roots with fallbacks: `--ca-file` or `SSL_CERT_FILE` alone;
      else a `podssh-ca.pem` next to the binary, the first system bundle, and
      the compiled-in Mozilla roots.
- [x] Tokens: minted with `POST /v1/mint`, cached for each relay, minted
      again once when the relay refuses a cached token; `PODSSH_RELAY_TOKEN`.
      Never printed.
- [x] The command `podssh proxy HOST PORT`.
- [x] A default relay, `tcp.ssh.relay.ajam.dev`, that `--relay-host` and
      `PODSSH_RELAY` override.

**Exit criteria**

- [x] `ssh -o ProxyCommand='podssh proxy %h %p' git@github.com` reaches the
      authentication step of GitHub: on Windows, with the static Linux
      binary, and through a CONNECT proxy that allows only port 443.
- [x] The same from a constrained sandbox (M3, T-001). There, the client
      of OpenSSH cannot start with no user database entry (`No user exists
      for uid 0`). With a `getpwuid` shim that the tester put into OpenSSH,
      not into podssh, OpenSSH reached the authentication step of GitHub.
- [x] An idle session with `ServerAliveInterval=60` stays up for 10
      minutes.

## M2: `podssh ssh`, a client for hosts with no `ssh` (done 2026-10-08)

The client is `russh` with the `aws-lc-rs` backend
([decisions.md](decisions.md)). podssh keeps its own code for the transport
(relay, proxy, TLS), host keys, the terminal and the command line.

- [x] An interop harness that the gate runs on each change
      (`scripts/interop.sh`, `scripts/interop-pty.py`; 62 checks).
- [x] Host keys: `known_hosts` lookup (hashed entries, wildcards, negation,
      `@revoked`), the prompt on first use, accept-new, and refusal of a
      changed key with both fingerprints.
- [x] Authentication: agent, key files (Ed25519, ECDSA, RSA with SHA-2),
      encrypted keys, keyboard-interactive and password, from the terminal or
      `SSH_ASKPASS`.
- [x] Sessions: exec with stdout and stderr apart and the remote exit status;
      a shell with a pty and a raw local terminal; window size and resize;
      `~.`; keepalives every 60 s.
- [x] The hand-written client and the unused `security` module are removed.
- The line discipline in the process (`podssh-terminal`) moved to M5.

**Exit criteria**

- [x] `podssh ssh user@host 'exit 3'` exits 3 against OpenSSH and Dropbear,
      and through the relay.
- [x] An interactive session (`vi`, `less`, `top`, Ctrl-C) works from a
      terminal, from a host with no `/dev/ptmx` (`-tt` over pipes), and on
      Windows.
- [x] The same from a box like the operator's sandbox (T-004, 2026-10-09);
      a run in a real sandbox follows the release (the operator's ruling of
      2026-10-08).

## M3: Nothing single-point and nothing assumed

After M3, no single relay host, missing DNS or silent stop can stop
podssh. M3 has no release: the one release is `v1.0.0`, in M9
([decisions.md](decisions.md)).

- [x] **Relay hosts with failover** (`podssh-relay`). `--relay-host` and
      `PODSSH_RELAY` take an ordered list. By default, the main host comes
      first, then up to three hosts of the pool. One attempt for each host,
      limited to 45 s. An error that another host can repair goes to the next
      host; an error that each host gives stops at once. `ConnectionAttempts`
      repeats the rounds, with a jittered backoff.
- [x] **Liveness.** The session pings the relay every 10 s. After three
      checks in a row with no frame at all, the link is dead: 30 to 40 s.
      The rule applies only after the relay answers a ping.
- [x] **No proxy and no DNS.** The dialer uses, in order: an IP literal; a
      pinned address (`--relay-addr HOST=IP`, `PODSSH_RELAY_ADDR`); the
      system resolver; DNS over HTTPS to Cloudflare and Google by IP literal.
      TLS always checks the relay's name.
- [x] **`podssh doctor`.** One `ok`, `FAIL` or `????` line for each check
      of the host, the egress and the relay. Unknowns never fail the run.
      Servers are identified by equality (the expected host key), never by
      the form of a banner.
- [x] **`podssh keygen`** for hosts with no working `ssh-keygen`. OpenSSH
      reads its keys and accepts them.
- [x] **A fault-injection harness** in the gate (`scripts/interop-faults.sh`,
      11 faults).
- [x] **Interactive use on Windows** (`scripts/interop-conpty.py`, 14
      checks in a real pseudo console).
- [x] **`podssh man`, the whole manual from the binary.** Text that the
      binary generates from its own tables, paged on a terminal, with
      `--no-pager`, `--roff` and one section at a time. Tests check it
      against the code; the gate renders it with groff and mandoc.
- [x] **A box like the target sandbox** (`scripts/test_in_box.sh`): a Podman
      box that matches the sandprobe report of the target sandbox. podssh
      passes all its checks in the box.
- [x] **Measured in the operator's real sandbox** (T-001): two sandboxes
      on 2026-10-08, with `sh scripts/sandbox-check.sh`, failover and
      throughput. See STATUS.
- [x] The entries that the sandbox runs found: T-005, T-006,
      T-007, T-008, T-009, T-010, T-011, T-023, T-024 and T-057; and T-004
      (interactive use from a box like the sandbox).
- [x] The git history was replaced by one commit before the repository went
      public. The old history is in a local bundle.
- [x] The repository is public. CI runs the gate on each push.

- [x] The compiled-in roots (T-003): a release follows each update of
      `webpki-roots`, and `podssh doctor` gives their version and age.

**Exit criteria** (met on 2026-10-09)

- [x] The interop and fault-injection harnesses pass in the gate.
- [x] `podssh ssh` and `podssh proxy` work from the operator's real sandbox,
      also when one relay host cannot be reached (T-001).

## M4: `podssh-relay`, the reverse road, and podbox

- Add to the C-free crate `podssh-relay` ([design.md](design.md), section
  1): pairing (`pair`, `stop`, `status`), the reverse node and operator
  runners, and a blocking facade for podbox: T-078, T-079, T-080, T-081.
  Port the runners from podbox, which works live, and move the codecs of
  `podssh-transport` into them (T-082): one writer, `ready` before data,
  late bytes dropped, a limited queue before `ready`, actions for each close
  code, liveness, jittered backoff. First repair the defects of
  `podssh-transport` that these runners use: T-071, T-072, T-073, T-075,
  T-076 (and T-074, T-077). The rules so far: [reverse.md](reverse.md).
- `podssh-ws`: a `rustls::ClientConfig` that the caller supplies (podbox
  keeps `ring` and TLS 1.2 for intercepting proxies), plain `ws://` on
  loopback for tests, typed session errors, and `probe::PrintChain` behind a
  feature: T-066, T-068, T-069, T-065. Also T-063 and T-064.
- `podssh node NAME TARGET` (a local TCP service through the reverse road),
  and `podssh ssh NODE` and `podssh operator NAME`: T-083, T-084.
- The idle cut on reverse sockets: T-061.

**Exit criteria** (T-085)

- Two sessions at the same time through the live relay, from a sandbox whose
  only egress is a CONNECT proxy, to a node in another such sandbox.
- The blocking facade for podbox passes a test with two clients here. podbox
  pins it later, as an operator action ([decisions.md](decisions.md)).

## M5: `podssh serve`, into the cage

- The server of russh in the node: T-107, T-108, T-109, T-117, T-118. It
  runs as the user that the sandbox gives, with no passwd entry, setgroups,
  chroot, `/etc/shells` or `/var`, and finds a shell to start without them
  (T-222). The host key is in a state file.
  Authorized keys come from a flag or a file. It supplies exec, and
  direct-tcpip into the cage.
- The terminal: a real pty when `/dev/ptmx` exists (T-110). Else the line
  discipline in the process (`podssh-terminal`, with its defects T-125 to
  T-129 repaired), which signals the process group of the child on Ctrl-C
  (T-111, [terminal.md](terminal.md)). Where `/dev/ptmx` is missing, podssh
  makes a tty when a probe allows it: a new devpts instance, or a tty in user
  space (T-248).
- SFTP in the process (`russh-sftp`, client and server): T-112, T-133.
- `podssh cp` and `podssh mv`: T-134 to T-139. SFTP, with an exec transfer
  as the fallback for minimal servers. Write to a temporary name, and rename
  only after the digest is correct. Continue from an offset after a drop.
  Open a new relay session before the limits of the relay (64 MiB, 12 h).
  Across hosts, `mv` is copy, verify, delete; podssh says first that it is
  not atomic. Do not assume POSIX tools or an interactive shell on the
  remote host.

**Exit criteria** (T-113)

- From a sealed sandbox (no ptmx, no passwd, no bind), an operator gets a
  shell where `vi`, `less` and Ctrl-C work, and copies 200 MiB in and out
  with matching digests.

## M6: Sessions that survive

- podssh's own resumable stream layer over the reverse road: T-151 to
  T-155. Byte offsets and acknowledgements for each direction, a limited
  replay buffer with backpressure, a session id and a resume secret,
  heartbeats that also prevent the relay's idle cut, a new session before
  the relay's limits, and reconnection through each relay host.
- The iroh road, cargo feature `iroh`: T-162 to T-165. Version 1.1 or later,
  aws-lc-rs, the `Minimal` preset, podssh's proxy resolution, no UDP unless
  probed, dialled by ticket, raced with the reverse road. The iroh relays are
  configurable. The default is n0's public relays until the operator runs an
  iroh relay on the operator's Cloudflare account; then that relay is first
  and n0's relays are the fallback.
- Throughput measured on each road and relay, in and out of a sandbox,
  before a default depends on it: T-157.
- The fault-injection harness with latency, jitter, limited bandwidth and a
  changed address: T-203.

**Exit criteria** (T-156)

- A session survives a stopped relay host, a change of the client's address
  and a stall of 3 minutes, on the resumable layer and on the iroh road.

## M7: `podssh pipe`, and `--persist`

- `podssh pipe A B`, with no listener: `stdio`, `fd:N`, `exec:CMD` (a
  socketpair, with pipes as the fallback), `unix-connect:PATH`,
  `relay:HOST:PORT`, `ssh:BASTION,HOST:PORT`, `node:NAME`, `iroh:TICKET`:
  T-174, T-175, T-176. A local listener only after a probe shows that it is
  allowed ([design.md](design.md), section 6): T-177.
- `--persist` for interactive sessions against a standard sshd: connect
  again and attach `tmux` again when the server has it (probed, never
  assumed): T-178.

## M8: The rest

- Chat on the roads between two podssh binaries, end-to-end encrypted
  (T-099), and IRC as a second transport ([irc.md](irc.md), T-252), after
  M6. The defects of the IRC client: T-091 to T-098.
- Tailscale (`podssh ts`, feature `ts`): first repair its DERP dial, which
  does not use the proxy, and its missing reconnection; then the tests with
  two nodes ([tailscale.md](tailscale.md)): T-103, T-104, T-106, and the
  defects T-100, T-101, T-102, T-105.
- Compatibility with `ssh_config` ([cli.md](cli.md)): T-043, T-044, T-046.
  `-R`: T-035.
- Resumption in the relay for a standard sshd (a Durable Object that keeps
  the target socket across reconnections): not now; look at it again after
  M6 (T-173).

## After M8

The entries with the milestone `backlog` in [TODO/INDEX.md](../TODO/INDEX.md)
come after M8, in the order of the index: the operator scheduled each of
them on 2026-10-08. The entries that wait for the relay's operator are
skipped.

## M9: `v1.0.0`, the first stable release

- More release targets: macOS x86_64 and aarch64, Linux armv7 and riscv64
  (static), and Windows aarch64, each built and run in CI: T-218.
- Provenance and signed checksums for each binary: T-210, T-211.
- The check from end to end before the tag (T-251), then `v1.0.0`, tagged
  once: T-250.

**Exit criteria** (T-251)

- Each entry of `TODO/` is done, except the entries that wait for the
  relay's operator. Each test passes, and the gate is green.
- The published assets of `v1.0.0`, on clean hosts (Windows, a fresh Linux
  container, and the box like the target sandbox), pass the check from end
  to end with no human: checksums and signatures; the commands of the
  README; `doctor`; `proxy` and `ssh` through the live relay; the reverse
  road; `serve` with `vi`, `less` and Ctrl-C in the box; `cp` of 200 MiB
  each way; a session that survives a killed relay connection; `pipe`.
