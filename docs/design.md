# Design: what a finished podssh is

Written 2026-10-08, after `podssh ssh` (milestone 2) passed its interop
checks, to answer the operator's five questions before the first beta is cut:
can the core be a library for podbox; can podssh replace podbox, sandssh and
dropssh in the most constrained hosts; how reliable is it and should it be;
can it replace socat or tailcat; and is iroh useful. Each answer below is
built on research done the same day from code and primary sources, with
evidence labels: MEASURED (run), READ (code or documents), INFERRED.

The short version: **podssh already gets out of a cage better than any of the
sibling projects; it does nothing yet to get into one; it has no reconnect or
failover at all; and the fix for all three is the same architecture** — a
shared, C-free relay library with several transport "roads", a resumable
session layer when both ends run podssh, and an in-process SSH server for the
cage side.

## 1. Can the core be used as a library? (podbox)

**Partly, today; fully after one restructuring.**

podbox (the container runtime podssh grew out of, HEAD `452d792`) needs the
relay's reverse legs: a node inside the sandbox registers at
`/v1/node/NAME`, an operator outside connects to it. It has its own,
live-proven implementation of those legs (two concurrent sessions over the
live relay, 2026-09-28) but **no HTTPS-proxy support at all** — it only dials
the relay directly, so in a sandbox whose only egress is an HTTP proxy its
node cannot reach the relay (READ, `podbox-ssh/src/mux.rs:438-445`). podbox is
synchronous (no async runtime), allows a C compiler (it builds `ring`), pins
MSRV 1.85 and measures every dependency's size cost.

What podbox could take from podssh now: `podssh-ws` — CONNECT proxy dialing
with `NO_PROXY`, verified TLS, the WebSocket upgrade with typed errors that
keep the relay's status and reason, and `RelaySession`, which keeps text and
binary frames apart as the reverse protocol needs. What it cannot take:
podssh's reverse legs (`podssh-transport`'s node leg sends control frames as
binary and cannot work live), any pairing client (none exists), and the relay
and token code, which lives in the `podssh-cli` binary crate and drags in
aws-lc and clap. `podssh-ws` also fixes its TLS provider (TLS 1.3, no RSA),
while podbox is designed for TLS-intercepting proxies, which often present
RSA certificates or TLS 1.2.

**Design:** a new C-free crate, `podssh-relay`, built from podbox's proven
node/operator loops and podssh's relay, token and proxy code, used by both
projects:

```
podssh-relay
  relay      relay selection, the 37-host pool, ordered failover
  token      mint, cache, re-mint once on 403        [features mint, cache]
  pair       pair / stop / status                     [feature pair]
  forward    open a forward session; stream adapter
  reverse    node::run(handler) and operator::run(io): one writer, ready
             before data, late bytes dropped, pre-ready queue capped,
             liveness pings, close-code actions (409 exit, 1001 stopped,
             expiry -> re-pair hook), jittered backoff
  session    the resumable stream layer (section 3)
  blocking   a synchronous facade owning a current-thread runtime, for podbox
```

`podssh-ws` gains: a caller-supplied `rustls::ClientConfig` (so podbox can
keep `ring` and TLS 1.2), plain `ws://` on loopback for fake-relay tests, and
typed session errors; `probe::PrintChain` moves behind a feature.
`podssh-transport` folds into `podssh-relay` and its unused DNS and
backpressure modules go. podbox then pins `podssh-relay` by git revision and
drops its own `ws.rs`, `tls.rs`, direct dial and curl-based pairing.

## 2. Can podssh work in the most constrained environments and replace the siblings?

**Getting out of a cage: yes, and better than any sibling already. Getting
into one: not yet — that was sandssh's and dropssh's main job.**

What each sibling is (READ from code; sandhome upstream checked, 18 commits
newer than the clone, nothing transport-related):

| | sandssh (Python) | dropssh (C) | sandhome (POSIX sh) |
| --- | --- | --- | --- |
| job | SSH into the cage, one session per dial, own relay | multiplexed SSH into the cage over the ajam relay's reverse path | a dev environment inside the cage |
| needs in the cage | python3, a patched dynamic dropbear, cc for `fakepwd.so` | a static binary and patched dropbear, `/bin/sh` | sh, curl/wget, cc for its shims |
| shims | `fakepwd`, `fakepty` (LD_PRELOAD), dropbear patches | dropbear patches (`-Y` passwd file, setgroups, pipe and AF_UNIX peers, `/etc/shells`) | seven LD_PRELOAD shims (pty, passwd, ptrace, GPU/input/X11/Wayland probes), `errandsh` line discipline, memfd exec |
| known defects | exits 1 on every clean close (MEASURED); idle node redials every 15 s and the relay pairs operators with dead registrations (MEASURED) | exits 0 after 1003/1009; retries 409 forever; tokens on argv | Ctrl-C cannot interrupt a running command under `errandsh` |

podssh today replaces `sandssh connect` and `dropssh connect` outright: one
static binary, no OpenSSH, no Python, no shims, correct exit codes, tokens
never on argv, and 62 of 62 interop checks against real servers. What it does
not yet do, in the order it matters:

1. **A reverse node and operator** with dropssh's measured rules (section 1's
   `podssh-relay`).
2. **An in-process SSH server for the node** (`podssh serve`): russh's server
   side, running as whatever user the sandbox gives, with no passwd entry,
   setgroups, chroot, `/etc/shells` or `/var`; host key in a state file;
   authorized keys from a flag or file. This replaces dropbear and every
   patch the siblings carry.
3. **A server-side terminal for cages without `/dev/ptmx`**: when a pty
   exists, a real one; when not, an in-process line discipline that also
   *signals the child's process group* on Ctrl-C — possible only on the server
   side, and exactly what `errandsh` cannot do.
4. **File copy that needs no scp, sftp-server or rsync**: an in-process SFTP
   server in `podssh serve`, and `podssh cp` that falls back to exec-based
   transfer (cat/base64) against minimal servers; chunked, verified by
   digest, resumable by offset, and aware of the relay's 64 MiB and 12 h
   per-session caps.
5. **No proxy and no DNS**: DNS over HTTPS to an IP literal, or a configured
   (hostname, address) pair. The 2.3k-line DoH stack in `podssh-transport` is
   unused and cannot resolve anything today.
6. **`podssh doctor`**: proxy allowlist, AF_INET vs AF_UNIX bind (a measured
   cage refuses the first and allows the second), ptmx, passwd, which
   directories can execute, `/proc`, CA bundle, relay reachability — `ok`,
   `FAIL` or `????` each.
7. **`podssh keygen`**, for hosts with no `ssh-keygen`.
8. **A run in a real sealed sandbox.** Every sibling has one in its own
   record; podssh does not yet.

sandhome's job — making third-party programs work inside the cage with
LD_PRELOAD shims and toolchains — stays out of scope under the no-LD_PRELOAD
decision. podssh's answer to "a dev environment in the cage" is the other
direction: treat the cage as a thin client and work on a real host over
`podssh ssh -tt`, or give the cage a usable shell through `podssh serve`.

## 3. Reliability: jitter, latency, drops, reconnects, changing addresses

**Today podssh bounds every wait and fails clearly, but it has no reconnect,
retry or failover anywhere.** (READ; the only backoff code,
`podssh-transport/src/backoff.rs`, is unused.) What it does now:

| failure | today |
| --- | --- |
| reaching the relay | TCP/proxy, TLS and upgrade each bounded at 20 s; one attempt |
| latency | 60 s for the SSH handshake; 30 s for a pty or exec reply |
| stalls | a link with no frame for 90 s is dead (the relay sends one every 25 s); a write stuck for 60 s fails; SSH keepalives every 60 s, 3 missed |
| a dropped connection | the session ends; `ssh` prints the relay's reason and exits 255 |
| the relay's limits | idle cut avoided by keepalives (MEASURED: 602 s survived, 184 s without); 12 h and 64 MiB end the session with the reason |
| a bad relay host or a proxy 5xx | fatal; the 37-host pool is never used |
| a changed client address | the session is lost |
| no proxy and no DNS | fails |

The relay offers no resumption on either path (READ, from the relay's source
and its contract): when the WebSocket closes, the relay closes the target's
TCP connection within 15 s; a reverse node's reconnect ends every operator
session on it.

**Design — reliability in three layers, from day one of each road:**

1. **Every connection attempt is redundant.** An ordered list of relay hosts
   (the pool from `/relays.json`, cached, with the compiled-in default first);
   jittered exponential backoff; one overall deadline per attempt; a proxy 5xx
   or a dead host moves to the next host; `ConnectionAttempts` honoured;
   WebSocket pings with a miss count so a dead link is found in seconds, not
   at the 90 s idle limit. Happy-eyeballs racing between roads when more than
   one is possible.
2. **When both ends run podssh, sessions survive drops.** A resumable stream
   layer under SSH, in the style of Eternal Terminal: each direction carries
   byte offsets; the receiver acknowledges; the sender keeps unacknowledged
   bytes in a bounded replay buffer (4–16 MiB, backpressure when full). The
   first connection establishes a session id and a 256-bit resume secret; on
   any loss the client reconnects through any road and any relay host,
   proves the secret, and both sides resend from the other's offset. A
   heartbeat every 10–15 s counts as payload, so it also defeats the relay's
   idle cut. Before the 64 MiB or 12 h cap, the session rolls over to a new
   relay connection. The far end is `podssh serve`/`node` in a cage, or a
   podssh next to a vanilla sshd: it owns the TCP connection to sshd, so even
   a stock server gets a session that survives the client's network changing.
   Cost: about 1–2k lines plus a fault-injection harness.
3. **When only one end runs podssh (a vanilla sshd behind the forward road),
   nothing can save the TCP connection to sshd without the relay's help.**
   Options, cheapest first: automatic reconnect with re-authentication and
   `tmux new -A` reattach for interactive sessions (opt-in; tmux is probed,
   never assumed); or a relay feature — a Durable Object that owns the target
   socket across client reconnects, a resume token in the `101` response, and
   offset framing as an opt-in protocol version. The second is the relay
   operator's project and costs Durable Object duration billing for the whole
   session.

Interactive comfort under high latency (mosh-style local echo and screen
sync) is a later option on top of layer 2; it needs podssh on both ends and
cannot use UDP here.

**Testing**: a fault-injection harness in the gate — latency, jitter,
bandwidth caps, stalls past each timeout, killed WebSockets mid-transfer,
host failover, proxy 5xx — run against real OpenSSH like the interop
harness.

Fixed on the spot (2026-10-08): `-4`/`-6` always failed (the path check
refused the `?family=` they add); `podssh proxy` treated the relay's 1001
(idle cut, 12 h cap) as success; `ssh -W` exited 0 when the connection died;
the keepalive warning needed `-v`; a proxy 5xx was blamed on the allowlist.

## 4. Can podssh replace socat or tailcat?

**tailcat** ([tailscale/tailcat](https://github.com/tailscale/tailcat), Go,
BSD-3) is netcat over Tailscale's data plane without its control plane: no
account, userspace, DERP then hole punching, a `tc…` address that is a bearer
credential, with `serve`/`forward`/`socks`/`serve exec`, an SSH server and file
transfer. Its shipped builds are compiled without system-proxy support
(`ts_omit_useproxy`, READ), so on a host whose only egress is an HTTP proxy it
cannot reach DERP at all, and podssh cannot fix that by forwarding sockets
(it dials DERP itself; the only hooks would be a listener or LD_PRELOAD, both
ruled out).

**socat**'s address types that matter here are the listener-free ones:
stdio and file descriptors, EXEC/SYSTEM, outbound TCP (only through CONNECT on
the measured host), UNIX-CONNECT, socketpairs and pipes. Every `*-LISTEN`
needs `bind`, which the measured sandbox forbids for TCP (AF_UNIX not
measured; a sibling's cage allowed it).

**Design: `podssh pipe A B`**, listener-free by default:

| address | meaning |
| --- | --- |
| `-`, `stdio`, `fd:N` | local descriptors |
| `exec:CMD` | a child with a socketpair (pipes as the fallback, and on Windows); its exit status passes through |
| `unix-connect:PATH` | an existing local socket |
| `relay:HOST:PORT` | TCP through the relay (what `podssh proxy` is today) |
| `ssh:[USER@]BASTION,HOST:PORT` | TCP opened by an SSH server (`-W`) |
| `node:NAME[,PORT]` | a podssh node through the reverse road |
| `iroh:TICKET` | a podssh peer over iroh (section 5) |

"Listening" happens only where it is allowed: on the far side (a node, SSH
`-R` where the server listens) or locally after a probe shows AF_UNIX or
loopback bind works. Tools that spawn an ssh-like program already work
through podssh (`GIT_SSH_COMMAND`, `rsync -e`, git's `core.gitProxy` with
`podssh proxy`); tools that call `connect()` themselves (curl, browsers) need
a listener or the sandbox's own proxy and cannot be helped without one.
`exec:` runs the user's own program, which the operator should confirm does
not conflict with "no helper processes" (that rule was about podssh's own
shims).

## 5. Is iroh useful?

**Yes — as the road between two podssh ends, chosen for reliability and
multiplexing rather than speed; never as a replacement for the WebSocket relay
when the far end is a stock sshd.** (Research 2026-10-08 from the crates, the
iroh source at v1.3.0 and n0's documents; no build was run.)

iroh is QUIC between endpoints identified by Ed25519 keys, with NAT traversal
when UDP works and a relay (HTTPS on 443, upgraded to a WebSocket) when it
does not. It reached 1.0 on 2026-06-15 with a promise of wire and API
stability; the current release is 1.3.0 (2026-09-28). Three advisories
published 2026-10-05 affect every release up to 1.0.3, the worst a relay frame
that blocks a client's inbound traffic for good, so podssh would require
`>= 1.1`. License MIT/Apache-2.0; MSRV 1.91; it can use the same aws-lc-rs
backend as russh. Its dependency closure adds roughly 190–245 crates podssh
does not have, and several megabytes.

**In the target sandbox** (no UDP, CONNECT-only egress, no DNS) iroh can run,
but only configured for it (READ from source; not yet MEASURED):

| need | how |
| --- | --- |
| no UDP | `clear_ip_transports()` (relay only), or a UDP bind marked not-required, attempted only after podssh's own probe — the default endpoint binds UDP as *required* and fails to start without it |
| CONNECT-only egress | `proxy_url(...)`: the relay dial sends `CONNECT relay:443` by name, unresolved; podssh passes its own proxy resolution (iroh's `proxy_from_env` ignores `ALL_PROXY` and `NO_PROXY`) |
| no DNS | the `Minimal` preset (no pkarr or DNS lookups), our own relay URL, peers dialled by ticket (key + relay URL), a resolver that fails fast |
| a home relay | the HTTPS `/ping` probe must pass through the proxy; without it the endpoint can dial out but cannot be dialled |

What it then gives, when both ends run podssh:

- **sessions that survive relay drops and address changes**: QUIC keepalives
  every 5 s, the relay client reconnects transparently after network changes
  and relay restarts, and lost packets are retransmitted — the property
  section 3 otherwise builds by hand;
- **multiplexing**: SSH sessions, forwards, file transfers and chat as streams
  of one connection;
- **no accounts**: identity is the key; access by an allowlist of keys or a
  relay token; a node is reachable through its relay without `listen()`;
- **full speed off the sandbox**: on ordinary networks the connection moves
  from relay to direct UDP mid-flight.

What it does **not** give in the sandbox: speed. Every byte is relayed, as
QUIC inside a WebSocket inside TLS inside a CONNECT tunnel (two congestion
controllers, TCP head-of-line blocking). n0's free relays are for
development, rate-limited, and measured by a third party at about 1 MiB/s;
volume needs a relay podssh's operator runs (a VPS `iroh-relay`, or n0's paid
tier at 5 MB/s). The operator's own Cloudflare relay could also host the iroh
relay protocol: at least three independent projects implement it on Workers
and Durable Objects (READ, unverified), with billing per incoming message.

dumbpipe ("netcat over iroh"), pigeons (`pigeons roost` next to sshd, `pigeons
fly --stdio` as a ProxyCommand — the closest existing match to "iroh when
both ends run the binary"), iroh-ssh and sendme all use n0's default preset
without proxy support, so none of them works in the target sandbox as
shipped. They are design references, not dependencies.

Costs against podssh's own rules, which the operator decides: iroh binds
netlink sockets on Linux (non-fatal if denied, but it tries), and it opens
more than one outbound connection (latency probes, a peer's home relay). Its
pre-1.0 history churned every release; 1.x has been stable for four months.

**Design consequence: a two-podssh road with two implementations.** The iroh
road where it can run (measured per host, by `doctor` and at connect time),
and podssh's own resumable layer over the WebSocket reverse road (section 3,
layer 2) where it cannot — the fallback is not optional, because the first
real sandbox may block exactly what iroh needs (the `/ping` probe, netlink,
or the relay name in the proxy's allowlist). Both carry the same SSH, `cp`,
`pipe` and chat on top, so a session does not care which road it rides.

## 6. The architecture these answers lead to

```
                        podssh (one static binary)
  ssh  proxy  pipe  cp  serve  node  operator  doctor  keygen  chat  ts  iroh
   │                       │
   │        podssh-ssh: russh client and server, terminal, SFTP     [C: aws-lc]
   │                       │
   └──── podssh-relay: roads, failover, liveness, resumable sessions,
                       tokens, pairing, node/operator, blocking facade   [no C]
                                    │
   ┌──────────────┬─────────────────┼──────────────┬─────────────┬───────────┐
 forward road   reverse road      iroh road      direct road   tailscale road
 any public     podssh at both    podssh at both TCP, through  feature ts
 TCP service    ends; resumable   ends; QUIC     HTTPS_PROXY
 (one-sided)    layer on top      [feature, C]
   └──────────────┴── podssh-ws: CONNECT proxy, TLS, WebSocket, DoH [no C]
```

**Choosing a road** (in this order, raced where two are possible):

| far end | first | then | last |
| --- | --- | --- | --- |
| a podssh node or peer (name or ticket) | iroh road (direct if UDP works, else through a relay) | reverse road with the resumable layer | — |
| a stock sshd, public | forward road, failing over across relay hosts | direct road (`--direct`, or when probed) | — |
| a stock sshd behind a podssh `roost` | iroh or reverse road to the roost | forward road | — |
| a tailnet node | tailscale road (feature) | — | — |

Every road shares the same rules: one bounded attempt per host with
jittered backoff across hosts; liveness checks at every layer; the relay's
close reason carried up to the user; credentials never on argv, in URLs or
in output; every capability probed before it is used.

Rule changes this design asks for (section 8): the iroh road binds netlink
sockets and opens more than one outbound connection; `pipe exec:` runs a
user's program.

## 7. Milestones

M0–M2 are done. Proposed from here, each with commands as exit criteria:

**M3 — Beta: nothing single-point, nothing assumed.**
- An ordered relay host list: `--relay-host` and `PODSSH_RELAY` take a list;
  the pool from `/relays.json`, cached; failover on dial errors, proxy 5xx and
  refused upgrades; jittered backoff; one overall deadline per attempt;
  `ConnectionAttempts` honoured.
- WebSocket pings with a miss count (seconds, not the 90 s idle limit).
- No proxy and no DNS: DNS over HTTPS to an IP literal (the existing DoH code,
  repaired and wired), and a `--relay-addr HOST=IP` pin.
- `podssh doctor` (each probe `ok`, `FAIL` or `????`) and `podssh keygen`.
- Run in the operator's real sandbox; interactive use on Windows.
- Exit: the interop harness plus a fault-injection harness (killed relay
  host, proxy 5xx, stalled link) pass in the gate; the same commands pass in a
  real sandbox. Then tag `v0.1.0-beta.1`.

**M4 — `podssh-relay`, the reverse road, and podbox.**
- The C-free library crate (section 1), with podbox's node/operator loops
  ported and podssh-transport folded in; pairing; close-code actions;
  liveness; a blocking facade; a caller-supplied rustls config in
  `podssh-ws`; plain `ws://` on loopback for tests.
- `podssh node NAME TARGET` (expose a local TCP service) and `podssh ssh
  NODE` / `podssh operator NAME` through the reverse road.
- Exit: two concurrent sessions through the live relay from a sandbox with
  only a CONNECT proxy; podbox builds against `podssh-relay` with its
  blocking facade and passes its own two-client test.

**M5 — `podssh serve`: into the cage.**
- russh's server inside the node: no passwd, setgroups, chroot or `/var`;
  host key in a state file; authorized keys from a flag or file; exec; a
  real pty when `/dev/ptmx` exists, else a server-side line discipline that
  signals the child's process group on Ctrl-C (podssh-terminal, its mode
  selection fixed); direct-tcpip into the cage; SFTP (`russh-sftp`).
- `podssh cp`: SFTP, falling back to exec transfer; chunked, verified by
  digest, resumable by offset, rolling over before the relay's caps.
- Exit: from a sealed sandbox (no ptmx, no passwd, no bind), an operator
  gets a shell where `vi`, `less` and Ctrl-C work, and copies 200 MiB in and
  out with matching digests.

**M6 — Sessions that survive.**
- The resumable stream layer over the reverse road (offsets, acknowledgements,
  a bounded replay buffer, resume secret, heartbeats, rollover before caps).
- The iroh road as the cargo feature `iroh` (`>= 1.1`, aws-lc-rs, `Minimal`
  preset, own relay, proxy, no UDP unless probed), dialled by ticket, raced
  with the reverse road.
- An iroh relay the operator runs (on the Cloudflare relay or a VPS), with
  n0's public relays as the last fallback.
- Exit: a session survives the relay host being killed, the client's
  address changing, and a 3-minute stall, on both roads; measured
  throughput on each road, in and out of a sandbox.

**M7 — `podssh pipe`** (section 4), and `--persist` for one-sided
interactive sessions (reconnect and reattach `tmux` when the server has it).

**M8 — the rest**: chat (redesigned on top of the two-podssh roads, or IRC as
before — the operator decides), Tailscale (fix its proxy-less DERP dial and
missing reconnect first), `ssh_config`, `-R`, and relay-side resumption for
stock sshd if the operator builds it.

## 8. Decisions for the operator

1. **Cut the beta now, or after M3?** The client works today; what makes it
   "hardcoded" is one relay host, no failover and no liveness. Recommended:
   after M3.
2. **Order of M4/M5 versus M6.** Getting into a cage (M4, M5) is what the
   siblings did and podbox needs; surviving drops (M6) is what makes every
   road reliable. Recommended: M4, M5, M6 in that order, with M3's failover
   and liveness carrying reliability until then.
3. **iroh**: adopt it as an opt-in road for two-podssh connections, accepting
   its netlink binds and extra outbound connections on that road, MSRV 1.91
   for the feature, and about 200 more crates. Recommended: yes, behind a
   feature until measured in a real sandbox.
4. **Who runs the iroh relay**: an iroh-relay endpoint on your Cloudflare
   relay (prior art exists; billed per message), a VPS `iroh-relay` (needed for
   volume), or only n0's public relays (development use, rate-limited).
5. **Our own resumable layer as well as iroh** (redundancy) or iroh alone.
   Recommended: both; the resumable layer is the fallback when a sandbox
   blocks what iroh needs.
6. **Relay-side resumption for stock sshd** (a Durable Object that keeps the
   target socket across client reconnects; protocol change; duration
   billing). Recommended: not now; revisit after M6.
7. **`podssh pipe exec:`** runs the user's own program; confirm it is outside
   "no helper processes".
8. **Chat**: keep IRC through public servers (plaintext through the relay,
   most networks refuse the relay's addresses), or move chat onto the
   two-podssh roads (end-to-end encrypted, iroh-gossip or a stream).
