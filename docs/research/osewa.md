# osewa against podssh: the reality check, and the entries it filed

Read on 2026-11-04, for the operator's ruling Q99 ("everything they have network/connectivity wise
+ beat/exceed them", after an honest study first). Two agents studied osewa apart from each other:
its code at `rjyo/osewa` (HEAD `3190718`), in [osewa-code.md](osewa-code.md), and its paper
(<https://osewa.dev/paper>) with the documents around it, in [osewa-paper.md](osewa-paper.md).
Nothing of osewa was built or run. Each figure of osewa below is osewa's own.

## 1. What osewa is

A terminal transport in Rust, in place of ssh and mosh, for hosts that the client reaches directly:
a server on each host listens on TCP and UDP 7322, a process of its own holds each session's screen
(libghostty-vt, in C and Zig), and the client attaches over QUIC raced with a TLS WebSocket. It was
6 days old at the reading, with one author, one release (`v0.1.0`), 739 tests, no CI, and no
Windows.

## 2. The verdict

The two studies agree.

- **Reachability: podssh is far ahead.** osewa has no proxy client (no CONNECT, no SOCKS, no
  `HTTPS_PROXY`: its dial is a plain TCP connect), no relay, no NAT traversal, no port 443, no DNS
  fallback, no reverse road and no bastion (its own issue #2 asks for ProxyJump). It needs an
  inbound port on the host. It cannot connect at all from podssh's target sandbox. Its README's
  claim that the WebSocket "gets through proxies" is not in its code.
- **Feel between two reachable ends: osewa is ahead, and podssh has measured none of it.** A key's
  echo while a download runs (a priority writer, end-to-end credit, bulk held to about a round trip
  plus 40 ms while the user types, `TCP_NOTSENT_LOWAT` of 16 KiB on both ends); a cold connect of
  about three round trips; liveness after the larger of three round trips and 1 s while a key waits;
  sessions held on the host across a restart of its server; a snapshot of the screen on attach; and
  predictive local echo.
- **The cause of osewa's gain is its flow control, not QUIC.** In osewa's own lab its TCP
  WebSocket echoed faster under load than its QUIC (73 against 138 ms, and 125 against 154 ms). So
  podssh can take the gain without QUIC and without a server of its own: from its SSH client's
  windows, against any sshd, on every road. That is where podssh can exceed osewa.
- **osewa's evidence is weaker than it reads.** The lab rig behind its headline multiples is not
  in its repository, and the `make` targets that its paper names to reproduce them do not exist; its
  "100 times" is ssh's 15 s timeout; on real paths the echo gain is about 1.4 times, mosh's echo was
  within 11 ms of osewa's, and on the Tailscale path ssh downloaded faster while the user typed.
  "A dead path in about a second" holds only while a key waits (idle, up to about 6 s); "never
  drops" has a 24 h idle bound and drops parked input past 1 MiB; "no trust on first use" moves
  ssh's first use earlier.
- **podssh's own record claims less than it might seem to, in one area.** It measures capability
  and failover, not what a user feels: no echo under load, no cold connect, no throughput on a
  direct wide-area road, no roam of a real client (T-305's 3.0 to 3.2 s is a stand-in's move).
  "Parity with Tailscale" in [mesh.md](../mesh.md) is parity of features.

## 3. The entries, in their order (Q99: ahead of the rest of M10)

- T-660 (P2, M): What a user feels, measured on each road: a key's echo while a download runs, a cold connect and its first command, a bulk copy while one types.
- T-661 (P2, M): Typing-aware flow control in podssh's SSH client: a bulk channel's window held to a round trip and 40 ms while a key waits.
- T-662 (P2, S): SSH windows that grow to the path where nobody types, to a cap of each road.
- T-663 (P2, S): Liveness in round trips: a spare link after the larger of three round trips and 1 s, and a check when the host wakes.
- T-664 (P3, M): A faster cold connect: TLS tickets kept across runs, a key's signature sent with no query first, and fewer waits before the first command.
- T-665 (P3, S): QUIC on the iroh road, tuned and measured on a wide-area path.
- T-666 (P3, M): Bulk off the interactive stream: a copy beside a terminal on its own QUIC stream of the same iroh connection.
- T-667 (P3, L): QUIC on UDP 443 to podssh's relay role, raced with its TCP roads where a probe found that UDP passes.
- T-668 (P3, L): A node that keeps its sessions across its own upgrade: the new binary takes the sockets and the layer's state.
- T-669 (P3, S): Compression of a terminal's output on the relay roads, measured against the session's 64 MiB.

The host-held sessions, the screen's snapshot and predictive echo are entries of `podssh serve`
already: T-159, T-161, T-303 and T-160, in the work order since Q92. The two studies add to them:
mosh's epoch rule keeps a secret that is never echoed off the screen with no help from the far end,
so a mode of T-160 for a standard sshd is possible, which changes that entry's invariant and needs
its own Decision; and a model of the screen stays pure Rust (rule 4), never libghostty.

## 4. What podssh does not take from osewa

An inbound port that is not 443 on each host; self-signed TLS as the outer layer on a public port
(a proxy that inspects TLS cannot pass it, and it is a fingerprint); compression with a context
across messages by default (a side channel, and CPU spent on data that does not compress); parallel
dials of one host every 500 ms; a server that installs itself over ssh and updates itself each hour
from a `SHA256SUMS` with no signature; a protocol of its own at the far end in place of SSH; a C or
Zig terminal engine in the path of a session; and benchmark figures from a rig that is not in the
repository. [osewa-code.md](osewa-code.md) (section 6) and [osewa-paper.md](osewa-paper.md)
(section 7) give the reasons.

## 5. A comparison that runs osewa

osewa runs no public server, so Q99's live test has no target. The measurement's last step runs
osewa's release binary on a GitHub Actions runner, beside podssh and OpenSSH on the loopback with
`tc netem`, as a reference and never as a road.
