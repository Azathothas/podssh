# Design: the finished podssh

This page gives the design of the finished podssh, and why. It answers five
questions of the operator: can the core be a library for podbox; can podssh
replace podbox, sandssh and dropssh on the most constrained hosts; how
reliable must it be; can it replace socat or tailcat; and is iroh useful.
[ROADMAP.md](ROADMAP.md) gives the order of the work.
[decisions.md](decisions.md) gives what the operator decided.

Each fact has a label:

- **MEASURED**: a test was run.
- **READ**: read in code or in a document.
- **INFERRED**: a conclusion that no test or document confirms yet.

## 1. The summary

- podssh gets out of a cage better than each sibling project.
- podssh does not yet get into a cage: that is milestones M4 and M5.
- One architecture serves all three needs: a shared C-free relay library
  with several transport roads, a resumable session layer when both ends run
  podssh, and an SSH server in the process for the cage side.

## 2. The architecture

```
                        podssh (one static binary)
  ssh  proxy  pipe  cp  serve  node  operator  doctor  keygen  chat  ts  iroh
   |                       |
   |        podssh-ssh: russh client and server, terminal, SFTP     [C: aws-lc]
   |                       |
   `---- podssh-relay: roads, failover, liveness, resumable sessions,
                       tokens, pairing, node/operator, blocking facade   [no C]
                                    |
   .--------------.-----------------+--------------.-------------.-----------.
 forward road   reverse road      iroh road      direct road   tailscale road
 any public     podssh at both    podssh at both TCP, through  feature ts
 TCP service    ends; resumable   ends; QUIC     HTTPS_PROXY
 (one-sided)    layer on top      [feature, C]
   `--------------`-- podssh-ws: CONNECT proxy, TLS, WebSocket, DNS fallbacks [no C]
```

### Select a road

podssh tries the roads in this order. When two roads are possible, podssh
races them.

| Far end | First | Then | Last |
| --- | --- | --- | --- |
| A podssh node or peer (a name or a ticket) | The iroh road (direct when UDP works, else through a relay) | The reverse road with the resumable layer | None |
| A standard sshd, public | The forward road, with failover across relay hosts | The direct road (`--direct`, or when a probe shows it works) | None |
| A standard sshd behind a podssh `roost` | The iroh or reverse road to the roost | The forward road | None |
| A tailnet node | The tailscale road (feature `ts`) | None | None |

Each road has the same rules:

- one attempt for each host, with a time limit, and a jittered backoff
  across hosts;
- liveness checks at each layer;
- the relay's close reason goes to the user;
- credentials never go on argv, in URLs, or in output;
- each capability is probed before podssh uses it.

## 3. The core as a library for podbox

podbox is the container runtime that podssh grew out of (HEAD `452d792`). It
needs the reverse legs of the relay: a node in the sandbox registers at
`/v1/node/NAME`, and an operator outside connects to it.

Facts about podbox (READ):

- Its own implementation of the reverse legs works live: two sessions at
  the same time over the live relay (2026-09-28).
- It has no support for an HTTPS proxy. It connects to the relay directly,
  so its node cannot reach the relay from a sandbox whose only egress is an
  HTTP proxy (`podbox-ssh/src/mux.rs`).
- It is synchronous (no async runtime). It allows a C compiler (it builds
  `ring`). Its MSRV is 1.85. It measures the size cost of each dependency.
- It is made for TLS-intercepting proxies, which often present RSA
  certificates or TLS 1.2.

**What exists (2026-10-09).** The C-free crate `podssh-relay` gives relay
selection, the pool, failover, tokens (mint, cache, mint again) and the
forward opener. `podssh-ws` gives CONNECT dialing with `NO_PROXY`, verified
TLS with RSA, the DNS fallbacks, the WebSocket upgrade with typed errors that
keep the relay's status and reason, and `RelaySession`, which keeps text and
binary frames apart as the reverse protocol needs.

The facade for podbox (`podssh_relay::blocking`, feature `blocking`, T-081)
is a `Client` that owns a tokio runtime on the current thread and blocks on
it; no tokio type is in its API. It makes, asks about and stops pairs; runs
a node whose handler opens each session as a `std::io` reader and writer;
runs an operator session over a reader and a writer, such as standard input
and output; and opens a forward session as a `Read + Write` stream. Two
threads carry each session, so a blocking read stalls no other session. A
call from a thread that runs a tokio runtime is refused, and nothing panics.
Its offline tests run against a stand-in relay over plain `ws://` (feature
`plain-ws`), as podbox's can. The library crates declare Rust 1.85,
podbox's minimum: they pass `cargo check --locked --all-targets` on 1.85.0
(measured 2026-10-09), and the gate checks them on it, so podbox needs no
newer Rust.

**What podbox needs (milestone M4), and what of it exists:**

```
podssh-relay
  pair       pair / stop / status                    [feature pair: T-078]
  reverse    node::run(handler) and operator::run(io): one writer, ready
             before data, late bytes dropped, a limited queue before ready,
             liveness pings, actions for close codes (409 exit, 1001 stopped,
             expiry -> a re-pair hook), jittered backoff  [T-079, T-080]
  session    the resumable stream layer (section 5)
  blocking   a synchronous facade that owns a current-thread runtime
                                                   [feature blocking: T-081]
```

- `podssh-ws`: a `rustls::ClientConfig` that the caller supplies (so podbox
  can keep `ring` and TLS 1.2; `Trust::caller`, T-066), plain `ws://` on
  loopback for tests (feature `plain-ws`, T-068), typed session errors
  (`SessionError`, T-069), and no verifier that accepts each certificate
  (T-065 moved `PrintChain` to an example).
- `podssh-transport` moves into `podssh-relay`. Its unused backpressure
  module goes.
- podbox then pins `podssh-relay` by git revision and removes its own
  `ws.rs`, `tls.rs`, its direct dial and its pairing through curl.

## 4. Constrained hosts, and the sibling projects

To get out of a cage, podssh is ready now. To get into one, podssh needs M4
and M5. Getting into the cage was the main job of sandssh and dropssh.

The sibling projects (READ in their code):

| | sandssh (Python) | dropssh (C) | sandhome (POSIX sh) |
| --- | --- | --- | --- |
| Job | SSH into the cage, one session for each dial, its own relay | Multiplexed SSH into the cage over the reverse path of the ajam relay | A development environment in the cage |
| Needs in the cage | python3, a patched dynamic dropbear, cc for `fakepwd.so` | A static binary, a patched dropbear, `/bin/sh` | sh, curl or wget, cc for its shims |
| Shims | `fakepwd`, `fakepty` (LD_PRELOAD), dropbear patches | dropbear patches (`-Y` passwd file, setgroups, pipe and AF_UNIX peers, `/etc/shells`) | Seven LD_PRELOAD shims (pty, passwd, ptrace, GPU, input, X11, Wayland), the `errandsh` line discipline, memfd exec |
| Known defects | Exits 1 on each clean close (MEASURED). An idle node dials again every 15 s, and the relay pairs operators with dead registrations (MEASURED). | Exits 0 after 1003 or 1009. Retries 409 forever. Tokens on argv. | Ctrl-C cannot stop a running command under `errandsh`. |

podssh now replaces `sandssh connect` and `dropssh connect`: one static
binary, no OpenSSH, no Python, no shims, correct exit codes, tokens never on
argv, and tests against real servers. podssh also has, since 2026-10-08:
`podssh doctor`, `podssh keygen`, pinned addresses and DNS over HTTPS, and a
box like the target sandbox for tests.

podssh does not yet have, in order of importance:

1. **A reverse node and operator** with the measured rules of dropssh
   (section 3).
2. **An SSH server in the process for the node** (`podssh serve`): the
   server side of russh. It runs as the user that the sandbox gives, with no
   passwd entry, setgroups, chroot, `/etc/shells` or `/var`. The host key is
   in a state file. Authorized keys come from a flag or a file. This
   replaces dropbear and each patch of the siblings.
3. **A terminal on the server side for cages with no `/dev/ptmx`**: a real
   pty when one exists; else a tty that podssh makes when a probe allows it
   (T-248); else a line discipline in the process that also *signals the
   process group of the child* on Ctrl-C. Only the server side
   can do this, and `errandsh` cannot.
4. **File copy with no scp, sftp-server or rsync**: an SFTP server in
   `podssh serve`, and `podssh cp` with an exec transfer (cat and base64) as
   the fallback for minimal servers. In chunks, verified by digest,
   resumable from an offset, and aware of the relay's limits (64 MiB and
   12 h for each session).
5. **A run in a real sealed sandbox.** Each sibling records one. podssh
   passes in a box like the sandbox; the real sandbox is not run yet.

The job of sandhome (to make third-party programs work in the cage with
LD_PRELOAD shims and toolchains) is not in the scope of podssh, because of
the decision "no LD_PRELOAD". podssh goes the other way: use the cage as a
thin client and work on a real host over `podssh ssh -tt`, or give the cage a
usable shell through `podssh serve`.

## 5. Reliability: jitter, latency, drops, reconnections, changed addresses

### What podssh does now (2026-10-08)

| Failure | What podssh does |
| --- | --- |
| A relay host is down, refuses, or is behind a proxy 5xx | Fails over to the next host: the default host and up to three hosts of the pool, or the user's list. Each attempt has a limit of 45 s. |
| No proxy and no DNS | Uses an IP literal, a pinned address, the system resolver, then DNS over HTTPS by IP literal |
| Latency | 60 s for the SSH handshake; 30 s for a pty or exec reply |
| A silent link | A ping every 10 s; dead after three checks with no frame (30 to 40 s) |
| A stuck write | Fails after 60 s |
| The relay's idle cut | Keepalives every 60 s keep the session (MEASURED: 602 s with keepalives; cut at 184 s without) |
| The relay's limits (12 h, 64 MiB) | The session ends, with the reason |
| A dropped connection | The session ends; `ssh` prints the relay's reason and exits 255 |
| A changed client address | The session is lost |

The relay has no resumption on either path (READ, in the relay's source and
contract). When the WebSocket closes, the relay closes the TCP connection to
the target within 15 s. When a reverse node connects again, each operator
session on it ends.

### The design: three layers

1. **Each connection attempt is redundant** (done in M3): an ordered list of
   relay hosts, a jittered backoff, a limit for each attempt, failover on
   dial errors, proxy 5xx and refused upgrades, `ConnectionAttempts`, and
   pings that find a dead link in seconds. To add: a race between roads when
   two are possible.
2. **When both ends run podssh, a session survives a drop** (M6). A
   resumable stream layer under SSH, as in Eternal Terminal:
   - each direction carries byte offsets, and the receiver acknowledges;
   - the sender keeps the bytes that are not acknowledged in a limited
     replay buffer (4 to 16 MiB, with backpressure when it is full);
   - the first connection sets a session id and a 256-bit resume secret;
   - after a loss, the client connects again through any road and any relay
     host, proves the secret, and each side sends again from the other's
     offset;
   - a heartbeat every 10 to 15 s counts as payload, so it also prevents the
     relay's idle cut;
   - before the limit of 64 MiB or 12 h, the session moves to a new relay
     connection.

   The far end is `podssh serve` or `podssh node` in a cage, or a podssh next
   to a standard sshd. That podssh owns the TCP connection to sshd, so a
   standard server also gets a session that survives a change of the
   client's network. The cost is about 1000 to 2000 lines.
3. **When only one end runs podssh** (a standard sshd behind the forward
   road), nothing can keep the TCP connection to sshd without help from the
   relay. The options, the least costly first:
   - automatic reconnection with a new authentication, and `tmux new -A` to
     attach again for interactive sessions (only on request; tmux is probed,
     never assumed; M7);
   - a relay feature: a Durable Object that owns the target socket across
     client reconnections, a resume token in the `101` response, and offset
     framing as a protocol version that the client selects. This is a
     project of the relay's operator, and it costs Durable Object time for
     the whole session.

An interactive echo for high latency (as mosh does) is a later option on top
of layer 2. It needs podssh at both ends, and it cannot use UDP here.

The fault-injection harness in the gate (`scripts/interop-faults.sh`) tests
layer 1. Layers 2 and 3 need it extended: latency, jitter, limited
bandwidth, a changed address.

## 6. socat and tailcat

**tailcat** ([tailscale/tailcat](https://github.com/tailscale/tailcat), Go,
BSD-3) is netcat over the data plane of Tailscale, with no control plane: no
account, user space, DERP then hole punching, a `tc...` address that is a
bearer credential, with `serve`, `forward`, `socks`, `serve exec`, an SSH
server and file transfer. Its released builds have no support for a system
proxy (`ts_omit_useproxy`, READ). On a host whose only egress is an HTTP
proxy, it cannot reach DERP. podssh cannot repair that by forwarding
sockets: tailcat connects to DERP itself, and the only hooks are a listener
or LD_PRELOAD, which podssh does not use.

**socat** has address types that need no listener: stdio and file
descriptors, EXEC and SYSTEM, outbound TCP (only through CONNECT on the
measured host), UNIX-CONNECT, socketpairs and pipes. Each `*-LISTEN` address
needs `bind`, which the measured sandbox refuses for TCP.

**The design: `podssh pipe A B`**, with no listener by default (M7):

| Address | Meaning |
| --- | --- |
| `-`, `stdio`, `fd:N` | Local descriptors |
| `exec:CMD` | A child with a socketpair (pipes as the fallback, and on Windows); its exit status passes through |
| `unix-connect:PATH` | An existing local socket |
| `relay:HOST:PORT` | TCP through the relay (what `podssh proxy` is now) |
| `ssh:[USER@]BASTION,HOST:PORT` | TCP that an SSH server opens (`-W`) |
| `node:NAME[,PORT]` | A podssh node through the reverse road |
| `iroh:TICKET` | A podssh peer over iroh (section 7) |

A listener exists only where it is allowed: on the far side (a node, or SSH
`-R`, where the server listens), or locally after a probe shows that an
AF_UNIX or loopback bind works. Tools that start an ssh-like program
already work through podssh (`GIT_SSH_COMMAND`, `rsync -e`, the
`core.gitProxy` of git with `podssh proxy`). Tools that call `connect()`
themselves (curl, browsers) need a listener or the sandbox's own proxy;
podssh cannot help them without one.

## 7. iroh

**Use iroh as the road between two podssh ends, for reliability and
multiplexing more than for speed. Do not use it in place of the WebSocket
relay when the far end is a standard sshd.** (Research of 2026-10-08 in the
crates, the iroh source at v1.3.0 and the documents of n0; no build.)

Facts (READ):

- iroh is QUIC between endpoints identified by Ed25519 keys, with NAT
  traversal when UDP works, and a relay (HTTPS on port 443, upgraded to a
  WebSocket) when it does not.
- Version 1.0 came on 2026-06-15, with a promise of stable wire and API. The
  current release is 1.3.0 (2026-09-28).
- Three advisories of 2026-10-05 affect each release up to 1.0.3. The worst
  is a relay frame that blocks the inbound traffic of a client for good.
  podssh must require version 1.1 or later.
- MIT or Apache-2.0. MSRV 1.91. It can use the aws-lc-rs backend, as russh
  does. It adds about 190 to 245 crates, and several megabytes.

**In the target sandbox** (no UDP, egress only through CONNECT, no DNS),
iroh can run only with this configuration (READ; not MEASURED yet):

| Need | How |
| --- | --- |
| No UDP | `clear_ip_transports()` (relay only), or a UDP bind marked as not required and tried only after podssh's own probe. The default endpoint requires a UDP bind and does not start without one. |
| Egress only through CONNECT | `proxy_url(...)`: the relay dial sends `CONNECT relay:443` with the name. podssh gives its own proxy resolution (the `proxy_from_env` of iroh ignores `ALL_PROXY` and `NO_PROXY`). |
| No DNS | The `Minimal` preset (no pkarr or DNS lookups), podssh's own relay URL, peers dialled by ticket (a key and a relay URL), a resolver that fails fast |
| A home relay | The HTTPS `/ping` probe must pass through the proxy. Without it, the endpoint can connect out but nothing can connect to it. |

What iroh then gives, when both ends run podssh:

- **Sessions that survive relay drops and address changes**: QUIC
  keepalives every 5 s, a relay client that connects again after network
  changes and relay restarts, and retransmission of lost packets.
- **Multiplexing**: SSH sessions, forwards, file transfers and chat as
  streams of one connection.
- **No accounts**: the key is the identity. Access by an allowlist of keys or
  a relay token. A node is reachable through its relay with no `listen()`.
- **Full speed outside the sandbox**: on normal networks, the connection
  moves from the relay to direct UDP during the session.

**The speed in the sandbox is not measured.** There, each byte goes through
the relay, as QUIC in a WebSocket in TLS in a CONNECT tunnel (two congestion
controllers, TCP head-of-line blocking), so the relay sets the limit. The
known figures (2026-10-08):

- The operator measured **30 to 50 MiB/s with `sendme`** (iroh's file
  transfer) on normal networks. This was most likely a direct path, which a
  sandbox with no UDP cannot use.
- A third party measured a **browser** client (wasm), relay only, at 1.0 to
  1.3 MiB/s through the relays of n0 with round trips of 290 to 378 ms, and
  12.5 MiB/s through a local relay. This is a worst case, not the native
  relay throughput.
- n0 publishes no relay throughput figures. Its free relays are for
  development and hobby use, with a rate limit that is not published. Its
  paid tier states 5 MB/s.

The number that matters (native, relay only, through a CONNECT proxy, on
each candidate relay) is measured in M6, before a default depends on it. The
operator's own Cloudflare relay could host the iroh relay protocol: at least
three independent projects implement it on Workers and Durable Objects
(READ, not verified), billed for each incoming message.

dumbpipe ("netcat over iroh"), pigeons (`pigeons roost` next to sshd,
`pigeons fly --stdio` as a ProxyCommand), iroh-ssh and sendme all use the
default preset of n0 with no proxy support. None works in the target sandbox
as released. They are design references, not dependencies.

Costs against the rules of podssh, which the operator accepted for this road
([decisions.md](decisions.md)): iroh binds netlink sockets on Linux (not
fatal if refused, but it tries), and it opens more than one outbound
connection (latency probes, the home relay of a peer).

**The consequence: the road between two podssh ends has two
implementations.** The iroh road where it can run (measured on each host,
by `doctor` and at connect time), and podssh's own resumable layer over the
WebSocket reverse road where it cannot. The fallback is necessary: the first
real sandbox can block what iroh needs (the `/ping` probe, netlink, or the
relay name in the proxy's allowlist). Both roads carry the same SSH, `cp`,
`pipe` and chat, so a session does not depend on its road.

## 8. Questions for the operator

The operator decided the questions about the beta, the order of M4 to M6,
iroh, the resumable layers, `podssh pipe exec:` and chat
([decisions.md](decisions.md)). One question stays open, for the relay's
operator.

1. **Resumption in the relay for a standard sshd** (a Durable Object that
   keeps the target socket across client reconnections; a protocol change;
   billing for its time). Recommendation: not now; look at it again after
   M6 (T-173).
2. **`podssh pipe exec:`** runs the user's own program. Decided on
   2026-10-08: accepted; the rule "no helper processes" is about podssh's
   own shims (T-174).
3. **Chat**: decided on 2026-10-08: on the roads between two podssh ends,
   end-to-end encrypted, after M6 (T-099), and IRC through public servers
   as a second transport (T-252).
