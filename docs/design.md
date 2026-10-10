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

**The race (T-164, built 2026-10-10).** `podssh ssh node://NAME
--iroh-ticket TICKET` races the iroh road to the node's ticket and the
reverse road of its pair. The iroh road starts first; the pair's road after
250 ms (`session::race::HEAD_START`, as RFC 8305 gives IPv6 one), or at
once when the iroh road fails before. The first far end that speaks wins,
and the layer's handshake goes on that link alone: the far end dials its
target only when a handshake completes, so the losing link, which never
sends `OPEN`, costs no connection to sshd. Each resume runs the same race.
`podssh node NAME TARGET --iroh` serves both roads when it has the pair,
with one keeper of sessions for both, so a session resumes on either.
MEASURED: the rules on a paused clock with stand-in roads
(`cargo test -p podssh-relay --test session_race`); live, with a pair on the
live relay and iroh's relay server on the loopback, the iroh road won when
both answered, and TARGET saw one connection; with the iroh road pointed at
a silent relay, the pair's road won (`cargo test -p podssh-cli --features
iroh-test --test road_race -- --ignored`).

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
- `podssh-transport` moved into `podssh-relay`, and its unused backpressure
  module went (T-082, 2026-10-09).
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
| Latency | 60 s for the SSH handshake; 30 s for a pty or exec reply; 30 s for each SFTP reply with no file data, and 60 s for an SFTP read or write (T-133) |
| A silent link | A ping every 10 s; dead after three checks with no frame (30 to 40 s). To a node, the resumable layer's heartbeat too: a link with nothing from the far end for 30 s is dead, and a new one replaces it (T-154) |
| A stuck write | Fails after 60 s |
| The relay's idle cut | Keepalives every 60 s keep the session (MEASURED: 602 s with keepalives; cut at 184 s without). To a node, the layer's records each 10 s keep it, and SSH sends no keepalive unless asked (T-154) |
| The relay's limits (12 h, 64 MiB) | The session ends, with the reason. To a node, the session moves to a new link before them, at 48 MiB or 11 h (T-155) |
| A dropped connection | On the forward road, the session ends; `ssh` prints the relay's reason and exits 255; with `--persist`, it connects again and attaches the same tmux session on the server (T-178). `cp` and `mv` go on over a new connection, at the offset of the copy, 5 times in a row at most with no new byte (T-136). To a node (`ssh node://`, `operator`), the resumable layer carries the session onto a new link, for 10 minutes (T-153) |
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
     never assumed): `podssh ssh --persist` since T-178;
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

### The end-to-end channel above layer 2 (T-088)

When both ends run podssh, each session runs a Noise XX channel above layer 2
(`crates/podssh-relay/src/e2e/`), on both roads: one handshake for a session,
which a resume carries on, as the layer gives each byte once and in order.
The relay sees the layer's records (offsets, acknowledgements, heartbeats) and
ciphertext. A channel for each link, under the layer, lost: a handshake at each
resume, with the resume's proof inside it, for nothing that the relay learns
less. Each end proves its Ed25519 key of T-087 in the handshake: the Noise
static key is derived from the key's seed and signed by it. The layer's own
exchange (the resume secret, from X25519) stays unauthenticated: an active
relay could take part in a resume, but it reads and writes ciphertext only,
and each change that it makes ends the session.

### The records and the handshake of layer 2 (T-151)

The layer is the `session` module of `podssh-relay`: sans-IO, but for its
two ends over tokio streams. A record is a type byte, a 32-bit length and a
body of at most 64 KiB. Numbers are big-endian, and offsets and values have
64 bits.

| Type | Record | Sent by | Body |
| --- | --- | --- | --- |
| 0x01 | `GREETING` | far end | magic, version, role, nonce, features |
| 0x02 | `OPEN` | client | magic, version, role, nonce; then 0x00 and a public key (new), or 0x01 and a session id (resume); then features |
| 0x03 | `ACCEPT` | far end | 0x00, a session id and a public key (new); or 0x01, an offset and a proof (resume) |
| 0x04 | `PROOF` | client | an offset and a proof |
| 0x05 | `REFUSE` | either | a code byte and a reason |
| 0x06 | `DATA` | either | the offset of its first byte, then the bytes |
| 0x07 | `ACK` | either | an offset |
| 0x08 | `PING` | either | a value |
| 0x09 | `PONG` | either | the value of the `PING`, then an offset |
| 0x0a | `CLOSE` | either | a reason: the session ends, not only the link; the peer answers with its own `CLOSE` (T-262) |
| 0x0b | `RETIRE` | client | nothing: this link ends, and the session goes on over another (T-155) |

The magic is the 14 bytes `podssh-session`, and the version is 1; each side
names the highest version that it speaks, and the session speaks the lower.
The roles are 1 (a client), 2 (`podssh node`) and 3 (`podssh serve`). A
nonce, a public key and a proof have 32 bytes, and a session id 16. Features
are a count byte (16 at most), then each name as a length byte and 1 to 32
bytes of `a-z`, `0-9`, `.`, `-` and `_`; a side ignores a name that it does
not know (`replay.v1`, `heartbeat.v1` and `move.v1` come with T-152 to
T-155). A reason is UTF-8, 1024 bytes at most. The codes of `REFUSE`: 1 an
unknown session, 2 a wrong proof, 3 an offset no longer kept, 4 the
version, 5 the role, 6 busy, 7 a record out of its place, 0 another reason.

- **Offsets.** Each side numbers the bytes that it sends from 0, across
  each link of the session. A `DATA` record below the next offset expected
  loses its overlap. One above it is a gap: the link ends, and nothing after
  a gap is ever delivered.
- **A new session.** The far end sends `GREETING` and the client `OPEN`
  with its X25519 public key; neither record waits for the other. `ACCEPT`
  gives the session's id and the far end's public key. The secret is
  HKDF-SHA256 with both nonces as the salt (the far end's first), the X25519
  value as the input, and as the info `podssh-session v1 secret`, a 0 byte,
  the id and both public keys (the client's first): 32 bytes.
- **A resume.** `OPEN` names the session. Once the client has the far end's
  nonce, its `PROOF` carries its received offset and the HMAC-SHA256 under
  the secret of `podssh-session v1 client proof`, a 0 byte, the id, both
  nonces of this link and that offset. The far end checks it, and answers
  `ACCEPT` with its own received offset and the same HMAC of
  `podssh-session v1 far proof`, which the client checks. Each side then
  sends from the other's offset.
- **The replay buffer** (T-152), when both sides name `replay.v1`. Each
  side keeps the bytes that it sent from the peer's acknowledged offset on:
  4 MiB in each direction, up to 16 MiB with `PODSSH_REPLAY_BUFFER`. When it
  is full, the writer waits for an `ACK`, so SSH waits and its window stops
  the far side; no byte that is not acknowledged is ever dropped. A receiver
  acknowledges each 64 KiB at once, fewer bytes after 200 ms, and in each
  `PONG`. A resume sends again from the peer's received offset; one that the
  buffer no longer keeps (below the acknowledged offset, or past the bytes
  sent) gets `REFUSE` (3) with both offsets in its reason, and the session
  ends: never a silent gap. A peer that does not name `replay.v1` gets no
  buffer and no `ACK`, since it would never acknowledge.
- **What the layer defends against.** The relay terminates TLS, so it can
  read and log each byte. The secret never crosses it, and a proof names the
  nonces of its own link: a reader of the relay's logs cannot take a
  session, and a replayed `PROOF` fails. An active relay can still put itself
  in the middle of a new session's exchange and break the session, as it can
  break any session today; SSH, above the layer, keeps the bytes secret and
  whole either way. A public key of low order is refused at both ends.
- **A far end with no layer.** No type byte is printable, and an SSH server
  sends a line of text first (RFC 4253, section 4.2). On the reverse road the
  client sends nothing until the far end's first byte, 30 s at most (longer
  than the operator leg's wait for `ready`): a `GREETING` starts the layer,
  and any other byte, or none, means no layer. The bytes then pass as they
  are, and `-v` says so.

- **The heartbeat** (T-154), when both sides name `heartbeat.v1`. A side
  that sent nothing for 10 s sends `PING`, and the far side answers `PONG`
  with its received offset, an acknowledgement. Any bytes from the far end
  count as life; a link with none for 30 s is dead, and the session goes
  on over a new one. Each record is payload to the relay, so the idle cut
  never comes; the cost is about 34 bytes each way each 10 s. To a node,
  SSH sends no keepalive of its own unless `ServerAliveInterval` is set,
  since a keepalive with no answer would end a session that the layer
  carries over.
- **Across links** (T-153). The client resumes after each loss but a
  `CLOSE`, a `REFUSE`, and a relay close that a new link would only get
  again (a stopped or expired pair, a fault of podssh's own bytes:
  `podssh_relay::reverse::closes::resumes`). It tries a new link with the
  backoff of the forward opener, until 10 minutes after the loss; the far end
  keeps the session and its target as long, then forgets it, and a late
  resume gets `REFUSE` (1, an unknown session). A resume can come while the
  far end still runs the old link: the old link stops, and the new one goes
  on from the client's offset. Bytes received but not yet written to the
  application stay with the session, so a link that ends in a write loses
  none.
- **One writer for each link** (T-262). The side that reads a link never
  waits to write to it: an `ACK`, a `PONG` or a `PING` waits for the link's
  one writer, which sends it before its next `DATA`. When each end's reader
  waited for its own writer, stalled on a full link, and both ends sent at
  once, neither link moved again. The bytes of a resume go out the same
  way, while the new link is read. A link whose writes fail is still read
  for 5 s at most: a relay delivers the far end's last bytes and its `CLOSE`
  before it closes the link.
- **The end of a session** (T-262). The side whose application ended its
  bytes sends `CLOSE` after the last of them, and the peer answers with its
  own `CLOSE`; then both forget the session. A link that ends before the
  answer leaves the session to a resume, which sends the `CLOSE` again. A
  far end that no longer knows the session, after this side's application
  ended, had the `CLOSE`, and the session ended there. A resume that the far
  end accepted while the session ended on the old link gets a `CLOSE`.
- **A move** (T-155), when both sides name `move.v1` and
  `replay.v1`. At 48 MiB of a link both ways, or at 11 h, the client opens a
  new link and waits for its `GREETING` while the old link carries the
  session; then the old link stops at a record boundary and says `RETIRE`,
  and only then does the new link's handshake take the offsets. An offset
  taken while the old link still carried acknowledgements could fall below
  them, and ask for bytes that the other side no longer keeps. A session
  whose application ended does not move. The far end lets the newest resume
  take a session: the client runs one handshake at a time, so an older one
  that still waits is a link that the client left. The client warns an hour
  before its pair expires (72 h at most); at the expiry the relay ends each
  session of the pair with `1001`, which no resume carries on.

Measured 2026-10-09: `podssh node` runs the far end for each session, and
`podssh ssh node://` and `podssh operator` run the client. A node keeps 64
MiB of replay buffers at most, a whole buffer for each session that it
keeps, and dials its target only after a session's handshake. Through the
live relay, a node in front of `github.com:22` carried GitHub's banner
through the layer to `podssh operator`, and `podssh ssh node://` logged in
through it.

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

Since T-174 and T-175, `podssh pipe` has the local addresses (`-`,
`stdio`, `fd:N`, `exec:CMD`), the roads (`relay:`, `ssh:`, `node:`,
`iroh:`) and `tcp:HOST:PORT`, the direct road through `HTTPS_PROXY`;
since T-176, `unix-connect:PATH`, with a named pipe or AF_UNIX on Windows;
since T-177, the listeners `unix-listen:PATH` and `tcp-listen:[ADDR:]PORT`,
after a probe, for one client or, with `--keep-listening`, each in turn.

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

**Built (T-162, 2026-10-09):** the crate `podssh-iroh`, in the binary with
the feature `iroh` only. iroh 1.3.0 with no default features and
`tls-aws-lc-rs`: no ring, no port mapping, no metrics. The endpoint has the
`Minimal` preset and no address lookup; the relays given, n0's four public
relays by default; podssh's proxy for the relay (iroh's `proxy_url`), at an
address that podssh resolved; podssh's name resolution in place of iroh's
resolver; podssh's trust store for the relay's certificate; and no IP
transport unless a UDP probe binds, then UDP sockets that are not required.
The HTTPS probe of the relays, through the proxy, picks the home relay; the
captive portal check is off. A session is a bidirectional QUIC stream with
the ALPN `podssh/1`; the client's first byte announces it, as a QUIC peer
learns of a stream only from its first byte, and the stream then carries the
resumable layer's records. Found on the way (READ in iroh 1.3.0, and
MEASURED in the crate's tests):

- iroh's own proxy selection reads `HTTP_PROXY` first, then `HTTPS_PROXY`,
  and knows no `ALL_PROXY` or `NO_PROXY`; the HTTP client of its relay probe
  reads `ALL_PROXY` itself. With `ALL_PROXY` alone, an endpoint with iroh's
  own selection probed its relay through the proxy, dialled it without, and
  got no home relay.
- iroh puts a proxy's user name and password in `Proxy-Authorization` as the
  URL writes them, escapes and all, and in base64url, where RFC 7617 asks for
  base64. podssh refuses such credentials with the reason, where the proxy
  would refuse them with none.
- The relay's name goes to the proxy in `CONNECT`; the proxy's own name is
  resolved by the resolver that podssh gives iroh.

MEASURED offline: 20 MiB each way through a stand-in CONNECT proxy and a
relay on the loopback, under a name that only the proxy resolves, with equal
digests; podssh's trust store refuses the test relay's self-signed
certificate. `podssh doctor`, with the feature, reached n0's first relay
with `/ping` in 576 ms. Not measured yet: a real sandbox, and the
throughput (T-157).

**Built (T-163, 2026-10-10):** keys, tickets and the allowlist.
`podssh node NAME TARGET --iroh` serves TARGET over the iroh road with no
pair, and prints its key and its ticket; `podssh ssh iroh:TICKET` dials it.

- Each end's key is an Ed25519 secret in a private file, in hex as iroh
  parses it: the node's under its NAME, the client's one for each user, in
  the cache's directories or the file of `--iroh-key`. A file is made whole
  or not at all (a temporary file and a hard link), so two first runs get
  one key; a file that is not private, or a symbolic link, is refused and
  kept, as a new key would change the ticket. A key is shown by its public
  half, which the allowlist takes as it is.
- The ticket is `iroh:` and iroh's own ticket of an endpoint (iroh-tickets
  1.0), with the node's key and its home relay, and no address of its host:
  with UDP, the relay tells each side the other's addresses. It is an
  address, not a credential (the entry's decision), so it may go on a
  command line.
- Access is by the allowlist of `--iroh-allow`, read again for each
  connection: the handshake proves the client's key, and a refused one is
  closed with the code 403 before any stream, so it never reaches TARGET.
  The client then prints its own key, the line to add.
- The client carries the session over a stream of one QUIC connection, and
  after a lost link over a new stream, or a new connection. The layer's
  features over iroh are `replay.v1` and `heartbeat.v1`: a move keeps a
  session within the limits of the WebSocket relay's sessions, which a QUIC
  connection does not have.

MEASURED offline (`cargo test -p podssh-iroh --test keys --test tickets`):
iroh's own ticket (the vector of iroh-tickets, written by another encoder)
parses to its key, relay and address, and podssh writes it back the same; a
node refuses a client whose key is not in its allowlist, opens no target
for it, and lets the client in once its key is added; a planted node that
admits each key fails that check. The command line end to end came with
T-165.

**Built (T-165, 2026-10-10):** the relays as a setting, the first that
answers first. The table is n0's four public relays, read in iroh 1.3.0;
`--iroh-relay` (on `node` and `ssh`) and `PODSSH_IROH_RELAY` replace it, the
flag first. A relay is `https://HOST[:PORT]` and nothing more. iroh itself
picks the relay with the least latency, in no order, and can change it
during a run (READ: `net_report.rs`); so podssh asks `/ping` of each relay in
the list's order, through the proxy and with its own trust store, 5 s at
most each, and gives iroh the first that answers alone: the home relay, and
the one that a node's ticket names for the run. With none that answers,
iroh gets them all, and its own probes are the fallback. A client asks the
ticket's relays first; iroh dials a peer's relay when it is in no list
(READ: the relay actor reads its map only for a token). `podssh doctor`
says the `/ping` of each relay, and the home relay.

MEASURED offline (`cargo test -p podssh-iroh --test relays`, and
`cargo test -p podssh-cli --features iroh-test --test iroh_road`): with a
silent relay first and iroh's relay server on the loopback second, the
second is the home relay, its certificate checked by podssh's trust store;
`podssh node --iroh` and `podssh ssh iroh:TICKET` from end to end: the
client is refused and prints its key, and once that key is in the
allowlist, with no new start of the node, the command runs, and the host
key is kept under `iroh:` and the node's key.

MEASURED on the loopback (T-157, the debug build, 2026-10-10): SSH through
iroh's relay server, p50 34.6 MiB/s up and 25.6 MiB/s down, where `--direct`
to the same server gives 165.9 and 106.3: the iroh road's own limit on this
machine, before any network. Through n0's relays: not measured yet (T-251).

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
