# Relay measurement: an archive of research, read, and what podssh takes from it

On 2026-11-03 the operator attached an archive that the operator's own agent
produced from research on public relays (`ff-relay`, its `master` branch).
The operator's words: "we should copy/adapt some of the scripts/measurement
harness, after improving them to fit our needs better, maybe even include it
in podssh itself so it can rank relays on demand and then use".

A drafting agent read the whole archive on 2026-11-03. It ran none of the
archive's scripts and contacted no host that the archive names: each number
below is the archive's, read in its files, or arithmetic on them. Each claim
is tagged as the archive tags its own:

- **Read**: the archive's file says so, or podssh's file at the cited line.
- **Inferred**: reasoning from what was read; the measurement that would
  settle it is named.

By the operator's ruling Q79 ([decisions.md](../decisions.md)), this page
names only the hosts that podssh uses or tries, and keeps the others of the
archive as classes and counts. It names no address of a host, no place of
the measuring host, and no credential that the archive holds.

## 1. What the archive holds

| Part | What it is |
| --- | --- |
| README.md | The scoreboard: dial, write leg, 1 and 8 streams, the 8-to-1 ratio, for nine relays. |
| docs/agent-relay-REPORT.md | A survey of public relays with no account (905 lines): forward relays, telnet forwarders, probe APIs, reverse tunnels, mesh overlays, game relays, HTTP forwarders, an Ethernet relay, and a registry of dead endpoints. |
| docs/RE-MEASURED.md | A second pass of the survey from a second host (348 lines), and the roads of GitHub #59 measured. |
| tools/probes.py | One driver for each relay family: it opens a WebSocket and turns each relay's frames into the target's bytes. |
| tools/measure.py | Five stages: `probe`, `throughput`, `concurrency`, `wisp`, `blindspot`. |
| tools/measure_podssh.py | The roads of GitHub #59: the 37 hosts of podssh's default relay, SSH on port 443, Shadowsocks nodes with a published key, wstunnel's demo. |
| tools/measure_warp.py | Two relays on ports that the measuring host could not reach, through cfrs's WARP proxy. |
| tools/proxy_forward.py | A local TCP listener that forwards each connection through the CONNECT proxy, for a client that cannot use a proxy. |
| tools/wisp_idle_check.py | A cold window on port 80 through four Wisp servers, 15 minutes idle, a second window. |
| tools/make_svgs.py | The figures, from the JSON. |
| results/*.json | Eight stage outputs. |
| assets/* | Three figures, SVG and PNG. |
| LICENSE | 0BSD. |

## 2. What each tool measures, and how

Read in the tools. Each stage is one pass: each cell is measured once.

| Stage | What it sends and reads | What it reports |
| --- | --- | --- |
| `measure.py probe` | A WebSocket to each relay with `git.sr.ht:22` as the target; the first data frame as the banner; then `SSH-2.0-probe-frelay` and a structural check for an `SSH_MSG_KEXINIT` packet in the next frame; when that stalls, a second connection to an IRC server, `NICK`/`USER`, and the bytes `NOTICE` or `001` in the answer. | `upgrade_ms` (the time of `websockets.connect`), `banner_ms`, `bidi` and how it was proved. |
| `measure.py throughput` | An HTTP GET of a Debian kernel package (77 MB) on port 80 of a US mirror, through each relay, one relay after another; a window of 10 s or 16 MiB. | Bytes, and MiB/s over the time from before the dial to the last byte. |
| `measure.py concurrency` | The same download, 1, 2, 4 and 8 streams, for four relays. | Aggregate MiB/s for each relay and stream count. |
| `measure.py wisp` | A Wisp CONNECT to port 22 (the banner), then a GET on port 80. | Banner time; bytes of the GET. |
| `measure.py blindspot` | Three targets behind Cloudflare, through two Workers: open, then read for 4 s. | Whether a byte came. |
| `measure_podssh.py pool` | A token minted once; for each of 37 pool hosts, 8 hosts at a time: the probe's banner and KEXINIT check, then the 10 s download. | 37 rows of each. |
| `measure_podssh.py ssh443` | TCP through the proxy to port 443 of six SSH services: a banner read, else TLS and a banner read; then the version line and the KEXINIT check. | Mode, banner, `bidi_kexinit`, bytes after the line. |
| `measure_podssh.py shadowsocks` | `sslocal` of shadowsocks-rust, reached through proxy_forward.py, to three nodes with a key that their provider publishes; SOCKS5 to `git.sr.ht:22`, then the download. | Banner; bytes in 10 s. |
| `measure_warp.py` | The probe and the text download through cfrs's WARP proxy (SOCKS5 on the loopback), three tries at most. | As the probe. |
| `wisp_idle_check.py` | The Wisp download and banner, 15 minutes idle, again. | A verdict: "port-80 filtered at endpoints". |

## 3. The quality of the method

### Sample size and timing

- Each cell is one sample. The archive says so ("One run, 2026-11-03";
  "numbers are lower bounds, not capacity claims"), and then ranks relays by
  those single samples (Read: README.md, the scoreboard's green and red).
- Two runs of the same 1-stream download give a different order of the
  same four relays. In MiB/s, the sequential run (results/throughput.json)
  against the run inside the concurrency stage (results/concurrency.json):
  Mudlet's Worker 1.03 against 3.73, its older copy 3.32 against 1.09,
  ssheasy 2.62 against 1.34, podssh's default relay 1.56 against 2.36 (Read).
  The best relay of one run is the worst of the other.
- The table of RE-MEASURED.md, "What was dialed, in one pass", is not the
  JSON that it cites. The table says that the runs were from 09:37 to 10:05
  UTC; results/probe.json is of 12:54:42 UTC, and its numbers differ (Mudlet's
  Worker: 593 ms in the table, 341 ms in the JSON; ssheasy: 5,848 against 850;
  one Pages Function: 907 against 7,708) (Read). A later run wrote over the
  data, and the document kept the older numbers.

### Defects of the harness that change a result

1. **The concurrency stage runs each cell at once.** It gathers
   `download_window` for each relay and each stream count in one
   `asyncio.gather` (Read: measure.py, stage `concurrency`): 16 cells, 60
   streams at the same time, 952,937,952 bytes within 16.5 s, so at least
   55 MiB/s through the measuring host's one egress (arithmetic on
   results/concurrency.json). The "1 stream" cell of a relay shared the link
   with 59 other streams. The scoreboard's "1 stream" and "8/1" columns are
   shares of one link, not properties of the relays.
2. **The rate counts the dial.** `t0` is taken before the WebSocket opens,
   and the window of 10 s starts after the open and a sleep of 0.15 s;
   `mib_s` divides by the time from `t0` to the last byte (Read). A host
   whose 16 MiB came within its window of 10 s, 15.69 s after `t0`, so after
   an open of more than 5 s, reads as 1.02 MiB/s (the pool host
   `tcp-eu-central-1`; arithmetic).
3. **The cap ends most windows.** Each stream stops at 16 MiB. 30 of the 37
   pool rows and 7 of the 16 concurrency cells reached the cap (arithmetic),
   so their figure is 16 MiB over the time to reach it, dial included.
4. **The pool stage measures 8 hosts at a time**, for the probe and for the
   download (`asyncio.Semaphore(8)`; Read): each figure shares the link with
   seven others, and which seven depends on the order of a file.
5. **The Wisp GET was never sent as Wisp.** `WispStream` inherits
   `Stream.send`, which sends the bytes as one WebSocket frame;
   `wisp_data_frame` is defined and never called (Read: probes.py). The
   server reads the frame's first byte, `G` (0x47), as a packet type; Wisp
   has the types 0x01 to 0x05 (Read: `crates/podssh-ws/src/wisp/packet.rs`
   and the protocol's document). The target never got the request, and an
   HTTP server says nothing before one: zero bytes on port 80, while an SSH
   server, which speaks first, gave its banner. The verdict "port 80 is
   filtered at the endpoints", and the 15-minute check made to tell its two
   causes apart, measured the harness. The survey itself had read 891 bytes
   of `HTTP/1.1 200 OK` for `example.com:80` through a Wisp server, with a
   tool that is not in the archive (Read: agent-relay-REPORT.md, section
   1.10).
6. **The blind-spot check sends nothing.** It opens the relay to port 80 and
   reads for 4 s (Read: measure.py, `blindspot`). Through any relay that
   works, an HTTP server sends nothing then. So "upgrade OK, then zero
   bytes" through the older copy of Mudlet's Worker says nothing of a blind
   spot; the template relay's `502` at the handshake does, for that relay,
   as it dials before its 101.
7. **ssheasy's "banner" is its acknowledgement.** The first data frame of
   ssheasy's proxy is `{"status":"ok"}` (Read: results/probe.json), which the
   probe took for the target's banner: its `banner_ms` is the time of the
   acknowledgement.
8. **The text-frame drivers break binary bytes from the client.**
   `Stream.send` for a text relay, and the base64 relay's `send`, decode the
   bytes as UTF-8 with replacement (Read: probes.py). An ASCII version line
   survives that, so the write leg passes; an SSH packet does not. Nothing in
   the archive shows that those relays carry binary bytes from the client.
9. **The conditions write the proxy URL.** `env_conditions` writes
   `HTTPS_PROXY` as it is, unless it is the measuring host's own proxy, and
   measure_warp.py writes `WSS_PROXY` as it is (Read). A URL that holds a user
   and a password would go into each result file. podssh never writes a
   proxy's credentials ([AGENTS.md](../../AGENTS.md), section 4).
10. **measure_podssh.py holds what podssh may not.** Paths of the measuring
    host, a Shadowsocks password that a provider publishes, a local listener
    (proxy_forward.py) and another program (`sslocal`) (Read).

### What a result proves, and what it does not

- **The KEXINIT proof holds for one kind of server only.** An OpenSSH
  server sends its KEXINIT after it read the client's version line, so a
  KEXINIT after the probe's line proves that the line reached it (Inferred
  from OpenSSH's exchange of version lines; the probe's own target,
  `git.sr.ht`, is OpenSSH 10.3). A server that sends its KEXINIT at once
  proves nothing so. The archive's Dropbear 2017.75 server on port 443 did:
  the two reads of 64 bytes before the probe wrote held the version line (26
  bytes) and the start of a packet of length 0x27c (636) whose message code
  is 20, KEXINIT; 26 + 4 + 636 = 666, and 666 - 128 = 538, the "538 bytes
  after the version line" that RE-MEASURED.md reads as two-way (arithmetic on
  results/podssh-roads.json). Each byte counted was the rest of the packet
  that the server sent unasked. The two documents also disagree about that
  packet: the survey reads `curve25519-sha256@libssh.org` in it, the second
  pass reads `diffie-hellman-group14-sha1` alone; the JSON does not hold the
  list.
- **The IRC proof does not prove the write leg.** It matches `NOTICE` or
  `001` in the answer (Read: measure.py). An IRC server sends NOTICE lines
  of its own as a client connects, before it reads anything (Inferred from
  the usual behaviour of IRC servers; a registration's `001`, or the answer
  to a `PING`, would settle it). The archive's own data say the same: the
  template relay closes with `1008 first packet is not handshake` when the
  first frame of the client is not a Minecraft handshake (Read:
  RE-MEASURED.md, "What it cannot carry", and the closes of its download in
  results/throughput.json), and the probe still reports "bidi via irc" for
  each of its three deployments, where the client's first frame was
  `NICK`/`USER`.
- **A banner proves the read leg only**, as the survey says itself.
- **A refusal at the proxy is the measuring host's.** The two relays on
  ports 5999 and 6200 got `403` from the measuring host's proxy; the archive
  marks them as host nulls, correctly (Read).

### What it confuses

- **The proxy with the relay.** Of the 37 pool hosts, 29 upgraded in 575 to
  1,778 ms and 8 in 5,435 to 6,531 ms, with none between (arithmetic on
  results/podssh-roads.json). A gap of more than 3.6 s with no host in it is
  a fixed delay added to some runs, as a resolver's retry after 5 s adds
  (Inferred; the proxy resolves each name). Three of the eight then reached
  16 MiB in 4.4 to 6.3 s, dial included, in the next stage, so the delay did
  not come again with the host. `podssh ping` times the CONNECT apart from
  the TLS and the upgrade, so its numbers keep a slow proxy out of the
  relay's line (`crates/podssh-cli/src/ping/relay.rs:161-191`).
- **The relay's dial of the target with the client's leg.** podssh's relay
  dials the target before its `101` ([relay.md](../relay.md), "The forward
  path"), so its `upgrade_ms` holds the dial of `git.sr.ht`; through
  Mudlet's Worker the upgrade came at 341 ms and the banner at 792 ms (Read:
  results/probe.json), so that Worker dials after its 101 (Inferred). The
  upgrade times of the two kinds are not the same measure. `podssh relay
  trace` gives the relay's own dial time, which tells the two legs apart
  (`crates/podssh-cli/src/relay_diag.rs:182-255`).
- **The target's path with the relay.** The download goes to one mirror in
  the US on port 80. A pool host is the same Worker placed near a cloud's
  region ([carriers.md](../carriers.md), the pool), so its MiB/s is mostly
  the path from that region to that mirror, not what a session to another
  target gets. The archive ranks the pool hosts by it (Read: README.md, "pick
  by colo").
- **Raw TCP with SSH.** A podssh session is SSH, with a window of 512 KiB
  ([relay.md](../relay.md), "Errors and close codes"), so one channel moves
  at most 512 KiB for each round trip: 2.5 MiB/s at 200 ms (Inferred). A
  raw download above that through the same relay is not a figure that a
  podssh session reaches.
- **The measuring host's link with the relay's capacity**, which the archive
  says itself ("lower bounds").
- **WARP's path with the relay.** The two relays measured through WARP carry
  the path of cfrs's MASQUE tunnel in each figure, as the archive says; they
  are not podssh's WARP road either.
- **One edge with the relay.** Five edges of Cloudflare answered seven
  relays in one run (Read: the `cf-ray` of results/probe.json), and an edge
  can change between two calls ([relay.md](../relay.md), "Relay facts for a
  client that selects a relay"). A figure is of an edge at a time.

## 4. What the results say of each road

### podssh's default relay and its pool

- 37 of 37 hosts opened, and each answered the probe's version line with a
  KEXINIT from an OpenSSH server: the write leg holds through each (Read:
  results/podssh-roads.json; the proof is valid for that target, section 3).
- One token minted at the default host was taken by each pool host (Read),
  as [relay.md](../relay.md) says of the deployment's hosts.
- Times to open: median 1,056 ms, 575 to 6,531 ms, with the cluster of
  section 3 (arithmetic). 1-stream download, eight hosts at a time: 0.68 to
  5.58 MiB/s, median 2.95 (arithmetic). The default host itself was among
  the slow eight at the probe (5,807 ms) and read 0.90 MiB/s, one sample of
  each.
- `/relays.json` gave the version `2026-10-03-r2` and the limits that
  podssh has as facts (Read), so the archive found no change of the
  contract.
- What it does not say: which hosts are best for a podssh user. One sample,
  eight at a time, to one target in one region, through one proxy whose
  delay fell on 8 of 37 runs, cannot rank 37 hosts. It does say that every
  host works, so the choice of three alternates out of 37
  (`crates/podssh-relay/src/relay.rs:75-78`) is a choice among working hosts,
  and worth making by measurement (sections 7 and 8).

### The three forwarders of Q56

Mudlet's Worker, its older copy and ssheasy's proxy, which podssh names by
the words `mudlet`, `mudix` and `ssheasy`
(`crates/podssh-ws/src/forwarder/builtin.rs:24-37`): each opened and each
answered the version line with a KEXINIT of `git.sr.ht` (Read), so each
carries both legs for an SSH client. Their 1-stream downloads are those of
section 3, whose order turns over between two runs. ssheasy's own code
slows a connection to 100 KiB/s after 1 GiB ([carriers.md](../carriers.md),
item 7), which a window of 16 MiB cannot see.

### The Wisp demo server

`wss://wisp.mercurywork.shop/`, podssh's word `wisp`: the SSH banner came in
1,487 ms (Read: results/wisp.json). The port-80 result is the harness's
defect (section 3, item 5), so nothing is known of its bytes from the
client. Its operator states 500 kB/s for each address
([carriers.md](../carriers.md), item 7). For T-535's choice of more Wisp
servers, the archive's verdict that public Wisp servers filter port 80 is
not evidence.

### WARP

The archive measured two relays of other parties through cfrs's WARP proxy,
one stream each (0.51 and 0.22 MiB/s of text; Read), with the WARP egress
named in its trace. That is a relay behind WARP behind cfrs, not podssh's
`warp://` road (T-352), and one sample.

### SSH on port 443 (GitHub #61)

Six services, which this page does not name (Q79; T-371 names those of
#61): two answered plain SSH on port 443 through the measuring host's
proxy, an OpenSSH 10.0 server whose KEXINIT after the line proves both legs,
and the Dropbear 2017.75 server whose "two-way" is not proved (section 3).
Three finished TLS and then sent no banner in 6 s: a service of "SSH over
TLS" that waits for an HTTP request first would do that too (Inferred), so
the result does not tell T-372's `ssh+tls://` that they refuse SSH. One was
not reached. The measuring host's proxy carried plain SSH on port 443, as
this repository's cloud sessions' proxy does not (T-371's Done).

### Shadowsocks nodes with a published key (GitHub #62)

Two of three nodes dialed `git.sr.ht:22` and the mirror on port 80 through
the published key, with no account (Read: results/podssh-roads.json): this
answers the point that T-373's Premise left open, that such a server dials
any target, for those two nodes on that day, through `sslocal` and not
through podssh's `--shadowsocks`. Their rates, 0.03 and 0.40 MiB/s, divide
the bytes by the whole window although the second reached its cap of 4 MiB
(Read). podssh names no such server and no key (T-373's Decision), and this
page keeps it so.

### wstunnel's demo

A self-signed certificate (Read): nothing past it was measured. podssh's
`--wstunnel` is for a server that the user runs (T-441).

### The relays that podssh does not use

The archive's class 1 holds eleven relay families that take the target from
the client (Read): three deployments of one template of a Minecraft relay
(two Workers, one on Vercel), a MUD host's own proxy, a Pages Function, two
MUD clients' proxies on ports other than 443, the three forwarders of Q56,
and podssh's relay. Of the seven that podssh does not use:

- none is shown to carry a client's binary bytes to the target: two of the
  template's three deployments closed a first frame that is not a Minecraft
  handshake with `1008`, and the third moved no byte of the download; the
  MUD host's proxy and the two MUD clients' proxies
  are text or base64 relays, whose bytes from the client the harness itself
  broke (section 3, item 8); and the Pages Function's write leg rests on the
  IRC proof, while its download moved no byte in 16 s (Read:
  results/throughput.json);
- two answer only on ports 5999 and 6200, which a host whose egress is port
  443 alone cannot reach;
- one re-encodes the stream with raw deflate above a size, so it is not
  byte-transparent (Read: RE-MEASURED.md).

So the archive adds no road for podssh. By Q78 a service that carries bytes
may be a last fallback; none of these is shown to carry an SSH session, and
a research entry would need the measurements of section 7 first.

The survey's other classes (telnet forwarders, probe APIs, reverse tunnels,
mesh overlays, the Ethernet relay, proxy lists) are read and not measured
again here: [carriers.md](../carriers.md) and the entries of Q74 to Q78
hold podssh's own reading of each class.

## 5. What podssh already does that overlaps

| The archive's stage | podssh | Where |
| --- | --- | --- |
| The probe's upgrade and banner | `podssh ping`, the relay leg of each host: the token, TCP or CONNECT, TLS and the upgrade, each timed, then WebSocket pings with min, p50, p95 and max, one host after another; `--json` | `crates/podssh-cli/src/ping/relay.rs:102-150`, `crates/podssh-cli/src/ping/relay.rs:195-226`, `crates/podssh-cli/src/ping/mod.rs:167-172` |
| The write leg (KEXINIT, IRC) | `doctor`'s `forward`: a forward session to `github.com:22` must show one of GitHub's published host keys, which needs the key exchange both ways and that nothing between answered in GitHub's place | `crates/podssh-cli/src/doctor/relay_checks.rs:199-230` |
| One sample | `doctor`'s samples: nine tries over at least a second, best, median, p95, jitter and loss, a refusal counted apart | `crates/podssh-cli/src/doctor/samples.rs:1-25` |
| The relay's side | `podssh relay trace` (the relay's dial and first byte), `relay status` (each host's `/health` and edge), `relay info` (the pool and the limits) | `crates/podssh-cli/src/relay_diag.rs:1-7` |
| Throughput | `podssh ping DEST`: the login, the echo through `cat`, `--size` down and up; T-157's method: 5 runs a cell, the setup not counted | `crates/podssh-cli/src/ping/mod.rs:222-302`; `docs/STATUS.md`, "Throughput, measured" |
| Concurrency | `cp --parallel K`, several relay sessions for one copy when the user asks (Q23, T-141) | |
| The pool | `/relays.json`'s hosts, cached 7 days, six seeds before a cache; the default host and the first three of the pool | `crates/podssh-relay/src/pool.rs:25-37`, `crates/podssh-relay/src/pool.rs:111-126`, `crates/podssh-relay/src/relay.rs:104-125` |
| The choice of a host | the race of the hosts (`staggered`, `parallel`, `serial`), and the record of failures and opens, which puts a host that failed last and one that opened first | `crates/podssh-relay/src/failover.rs:133-256`, `crates/podssh-relay/src/failures.rs:231-255` |
| Forwarders, Wisp, WARP | `--forwarder` and its words, `doctor --forwarder`; the Wisp client; `warp://` | `crates/podssh-ws/src/forwarder/builtin.rs`, `crates/podssh-ws/src/wisp/handshake.rs:1-5`, `crates/podssh-warp/src/lib.rs` |

What podssh does not do: it never measures more than the default host and
its three alternates, unless a list is named; it keeps no measured time of a
host; and the three alternates are the first three of `/relays.json`, whose
order is the edge's of the moment and whose `score_ms` did not agree with
measured latency ([relay.md](../relay.md), "Relay facts for a client that
selects a relay").

## 6. The license

The archive is under 0BSD (its LICENSE, and "License: 0BSD" in its README);
six of its seven tools carry `SPDX-License-Identifier: 0BSD`, and the README
puts the whole repository, proxy_forward.py with it, under the LICENSE.
podssh is under 0BSD too (its `LICENSE`, and `license = "0BSD"` in
`Cargo.toml`). 0BSD asks for no notice, so any file may be copied or changed
into podssh. What may not be copied is decided by podssh's own rules, not by
the license:

| File | May be | Why |
| --- | --- | --- |
| tools/probes.py, `ssh_kexinit` | adapted | The structural check is right; it must read the whole buffer across frames, and must say when a KEXINIT came before the client's line. The harness of section 7 uses `doctor`'s host key instead, which proves more. |
| tools/probes.py, the drivers | read only | Their relays are not podssh's (Q79); podssh speaks the forwarders that it uses itself, in `podssh-ws`. |
| tools/measure.py | its ideas adapted | Stages, the conditions in each result, a JSON per run. Not its code: items 1 to 6 and 9 of section 3, and a target that is no test target of `AGENTS.md`. |
| tools/measure_podssh.py | its ideas adapted | The pool stage is the model of section 7's, through podssh. Not its code: item 10 of section 3. |
| tools/measure_warp.py, tools/wisp_idle_check.py | read only | cfrs's WARP, not podssh's road; and the check measured item 5. |
| tools/proxy_forward.py | not taken | A listener on the loopback, which rules 2 and 3 of `AGENTS.md` (section 5) keep out of podssh; podssh dials through `HTTPS_PROXY` itself. |
| tools/make_svgs.py | may be copied, not needed | A step summary in Markdown says the same in GitHub Actions. |
| docs, results, assets | may be quoted | Kept out of the repository: they name hosts that podssh does not use (Q79), and their figures carry section 3's defects. |

## 7. Design: the harness of podssh

`scripts/relay-measure.py`, with `scripts/relay_measure_lib.py` (the
numbers) and `scripts/relay_measure_selftest.py` (an offline test), drafted
with T-605. It is the archive's idea of stages and of a JSON result, with
each measure made by podssh's own binary, so it measures what a user gets.

- **Through podssh.** Each stage runs podssh: `relay info --json` for the
  pool, `ping --json --relay-host HOST --target T` for each host's leg,
  `relay trace --json` for the relay's own dial, `doctor --quick --json
  --jobs 1 --relay-host HOST` for GitHub's host key through the host (the
  write leg), `doctor --quick --json` with a road's flags for the
  forwarders, Wisp, `--via` or `--vless`, and `ping --json DEST` for the
  login, the echo and the throughput with SSH's window. No relay protocol is
  written in the script.
- **Through `HTTPS_PROXY`, as podssh is.** The script passes the
  environment to podssh and opens no socket of its own.
- **One podssh at a time**, with a pause between two, never two at once
  (section 3, items 1 and 4); a plant that runs two at once fails the
  self-test.
- **Rounds.** Each host `--rounds` times (5 by default), in a new random
  order each round from a seed that the result keeps, so that a cold start,
  the time or the proxy's state does not fall on one host each time.
- **Time limits.** Each run of podssh is killed at its limit (90 s; 330 s
  with a destination), and the whole run has `--budget` (1,800 s); a run not
  made is counted and named.
- **Numbers.** Nearest-rank percentiles, as `podssh ping` gives them; the
  time to open is the dial, TLS and the upgrade, the token left out; the
  relay's own dial from `/trace` beside it.
- **A rank.** The share of probes that failed, then the median time to open,
  then the p95; two medians closer than 50 ms or 10 % are a tie, which keeps
  the order of the list. The same rule as the rank of section 8, so that the
  harness can check podssh's own.
- **Targets.** `github.com:22` for the relay legs, which is GitHub's SSH
  endpoint, a test target; a destination only when one is given, which in
  GitHub Actions is the operator's server of `PODSSH_THROUGHPUT_SSH` (Q38).
  Third parties' forwarders and Wisp servers only through `--doctor-road`,
  short, from GitHub Actions (Q56, Q65).
- **Nothing secret in the result.** The runs share a cache directory of
  their own, removed at the end, so the token stays in it and no record of
  an earlier run reorders a host; the result names the proxy's kind alone.
- **A JSON result**, with the conditions (podssh's version, the system,
  Python, the proxy's kind, the run of Actions), the parameters, each run of
  podssh, each host's summary and the rank; `--ci` appends a Markdown table
  to `$GITHUB_STEP_SUMMARY`.

A workflow by hand, `.github/workflows/relay-measure.yml`, which T-605's
merge adds (a drafting agent writes only under `docs/research/`, `TODO/`
and `scripts/`). Its draft, UNVERIFIED, with the pins of
`.github/workflows/forwarder-live.yml`:

```yaml
name: relay measure

# The relay hosts and the roads, measured through podssh's own binary
# (T-605): scripts/relay-measure.py, one podssh at a time. By hand only.
# The live relay is the operator's own (2026-10-31); the forwarders of a
# --doctor-road are short and from Actions alone (Q56, Q65). No token or
# credential is printed; the result is an artifact.

on:
  workflow_dispatch:
    inputs:
      stages:
        description: "Stages: pool, trace, forward, roads, dest"
        default: "pool,trace,forward"
      hosts:
        description: "all, a number, or HOST,HOST"
        default: "all"
      rounds:
        description: "Rounds of each host, 1 to 20"
        default: "5"

permissions:
  contents: read

jobs:
  measure:
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    env:
      CARGO_BUILD_JOBS: "4"
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: build podssh
        run: cargo build --locked -p podssh-cli --bin podssh
      - name: the harness offline
        run: python3 -I scripts/relay-measure.py --self-test
      - name: measure
        env:
          STAGES: ${{ inputs.stages }}
          HOSTS: ${{ inputs.hosts }}
          ROUNDS: ${{ inputs.rounds }}
        run: |
          rc=0
          timeout 2400 python3 -I scripts/relay-measure.py --podssh target/debug/podssh \
            --stages "$STAGES" --hosts "$HOSTS" --rounds "$ROUNDS" \
            --out "$RUNNER_TEMP/relay-measure.json" --ci || rc=$?
          echo "relay-measure exit $rc"
          exit "$rc"
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: always()
        with:
          name: relay-measure
          path: ${{ runner.temp }}/relay-measure.json
```

The stage `dest` in Actions needs the operator's server and a key as
secrets, as the throughput run has them; the draft leaves it out, and
T-605's Approach names it.

What the harness does not do: concurrency (`cp --parallel K` is the
user's form of it, and the throughput test of T-157 measures it), soaks
longer than a few minutes (Q88), and targets that are not test targets.

## 8. Design: a rank of relay hosts inside podssh

podssh measures the hosts that a user names with `ping`, and remembers each
host's failures and opens; it keeps no measured time of a host, and it never
looks past the first three hosts of the pool. The design:

1. **`podssh relay rank`**, on demand (T-606). The default host and each
   host of the cached pool (all of them), or the list of `--relay-host`; each host
   probed `--rounds` times in a new random order each round, one host at a
   time, by the code of `podssh ping`'s relay leg
   (`crates/podssh-cli/src/ping/relay.rs:102`), to `--target` (GitHub's SSH
   port by default, never a session's destination). The order of the
   harness's rank (section 7). The rank goes into the cache as
   `relay-rank.json`, mode 0600, beside `relay-failures.json`: when it was
   measured, the egress it was measured through (a digest of the proxy's
   host and port, or `direct`; no credential, no name), the target, and each
   host with its numbers. `--cached` shows the rank kept, with no
   connection; `--json` gives one object.
2. **The list uses the rank** (T-607). With no list named, the default list
   is the default host and the three best other hosts of a rank that holds (less
   than 24 h old, of the same egress), in the rank's order; with none, the
   first three of the pool, as now. The record of failures still moves a
   host that failed last and one that opened first: the rank orders the
   list, the record moves hosts within it. A list that the user named keeps
   its order. `PODSSH_RELAY_RANK=no`, or `RelayRank no` in the settings
   file, leaves the rank out.
3. **Samples with no connection** (T-607). Each attempt that opens in a
   session's own race, kept or dismissed, gives its time to open; the last few of each
   host go into the same file, and order the hosts of the list when no rank
   holds. They cost no connection: they time the race's own.
4. **A rank that podssh makes unasked** (T-608) would open connections that
   the user did not ask for, beyond the session: rule 2 of `AGENTS.md` has no
   exception for it, so it is a question for the operator, Q89 of
   [PROGRESS.md](../../TODO/PROGRESS.md). Its recommendation: not by default,
   as the samples of item 3 order the hosts that a user's runs try with no
   connection; yes when the user sets `RelayRank auto`, bounded (once in 24 h
   for an egress, after a session ran 60 s, one probe each 10 s at most, 8
   hosts at most, each with `?dial=lazy` so that no target is dialed).

Rule by rule (`AGENTS.md`, section 5):

- **Rule 1**: each number is measured at run time, on this host, through
  its egress; a rank of another egress, or older than a day, is not used.
- **Rule 2**: `relay rank` makes one connection at a time, as `podssh ping`
  does over its hosts and `doctor` over each host's `/health`, so it stays
  within the rule's one connection; it offers no parallel probes, which
  would need an exception and would skew the rank as section 3, item 1
  shows. The samples of item 3 use the race's connections, which the
  exception of the race between relay hosts covers. Item 4 needs a ruling.
- **Rule 4**: the rank's order, its file and its use are pure Rust in
  `podssh-relay`, with serde as now; the probes are in `podssh-cli`.
- **Rule 5**: new files, `crates/podssh-relay/src/rank.rs` with its tests
  apart, and `crates/podssh-cli/src/relay_rank.rs`;
  `crates/podssh-relay/src/open.rs` has 473 lines and
  `crates/podssh-cli/src/flags.rs` 492, so each gets a few lines at most.

The ranking is also a part of M10's parity with Tailscale: `tailscale
netcheck` measures the latency to each DERP region and prefers the best,
and `podssh status`, `ping` and `doctor` for the net are T-435's. The rank
takes any list of relay hosts, so a net's own relays, once a net names
them, rank the same way.

## 9. The entries, and the question

| Entry | What |
| --- | --- |
| T-605 | The harness of section 7, drafted in `scripts/`, and its workflow by hand (`none`, P2). |
| T-606 | `podssh relay rank` on demand, and `relay-rank.json` in the cache (M10, P2). |
| T-607 | The default list takes the rank, and samples of each session's own race (M10, P2). |
| T-608 | A rank that podssh makes unasked, in a session's background (M10, P3); Q89 ruled it on 2026-11-03: with `RelayRank auto` alone. |

Q89, in [PROGRESS.md](../../TODO/PROGRESS.md): may podssh measure relay
hosts that the user did not ask it to measure, by default or with the
user's setting? The recommendation is section 8, item 4.

## 10. What a main session verifies

Each of these is UNVERIFIED in the draft:

- The flags and the JSON that the harness reads: `relay info --json`'s
  `relay` and `info.pool[].host`; `ping --json`'s `relays[0]` with
  `connect_ms`, `tls_ms`, `upgrade_ms` and `pings.p50_ms`; `relay trace
  --json --relay-host HOST HOST PORT`'s `target.connect_ms`; `doctor --quick
  --json --jobs 1`'s check `forward`; and `ping`'s `-o UserKnownHostsFile`
  and `-o StrictHostKeyChecking=accept-new`.
- That `PODSSH_CACHE_DIR` and `PODSSH_SSH_CONFIG=none` keep each run off the
  user's cache and `ssh_config`.
- The harness against a real podssh, from a session's host: a short run of
  the stages `pool,trace,forward` with `--hosts 4 --rounds 2`.
- The workflow, once added: one run by hand.
- The inferences of sections 3 and 4: the 5 s of the resolver (a run of the
  harness shows the CONNECT's time apart), and the IRC NOTICE before the
  client's bytes (a capture of an IRC server's first lines).

## 11. The second version: forward carriers (2026-11-04)

On 2026-11-04 the operator uploaded a new version of the same archive, one
commit: "Public forward carriers: harness, measurements and two podssh
forwarders". It measures HTTP forwarding and buffering on the loopback,
Piping Servers and other pairing services, 71 Wisp servers (both legs, port
80, concurrency), hosted reverse tunnels, TURN with RFC 6062 and a sweep of
541 names; and proposes a patch of two forwarders for podssh-ws. Its
reading, each claim tagged as the archive's, the findings against podssh's
record, the patch read as a proposal, and the entries T-621 to T-626, are
on their own page: [forward-carriers.md](forward-carriers.md). The new
Wisp harness sends its requests as DATA packets, so its port-80 bytes
settle item 5 of section 3: 29 of 32 servers carried port 80, the demo
server among them at about its operator's 500 kB/s.
