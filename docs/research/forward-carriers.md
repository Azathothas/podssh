# Forward carriers: the second archive of relay research, read, and what podssh takes from it

On 2026-11-04 the operator uploaded a new version of the research project
that [relay-measurement.md](relay-measurement.md) read on 2026-11-03
(`ff-relay`). The new version is one commit, "Public forward carriers:
harness, measurements and two podssh forwarders". Its subject is a carrier
of one TCP or HTTP byte stream that a host with HTTPS alone can use: a
service that dials a target that the client names ("forward"), or one that
joins two clients on one path ("pairing").

A drafting agent read the whole commit on 2026-11-04. It ran none of the
archive's tools, applied no part of its patch, and contacted no host that
the archive names: each number below is the archive's, read in its files,
or arithmetic on them. The tags are those of
[relay-measurement.md](relay-measurement.md):

- **Read**: the archive's file says so, or podssh's file at the cited line.
- **Inferred**: reasoning from what was read; the measurement that would
  settle it is named.
- **Arithmetic**: a figure computed here from the archive's numbers.

By the operator's ruling Q79 ([decisions.md](../decisions.md)), this page
names only the hosts that podssh uses or tries, and those that an entry of
`TODO/` proposes to try; it keeps the others of the archive as classes and
counts. It names no address, no place of the measuring host, no person,
and no credential: one tool of the archive holds a proxy's credential in a
URL (section 4, item 10), and this page does not copy it. The archive's
own paths are written as plain text (results/reverse.json), and podssh's in
code spans.

## 1. What the commit holds

| Part | What it is |
| --- | --- |
| README.md | The two shapes (forward, pairing), a table of six carriers with a verdict each, and "the one property that decides usability": whether a response streams before the request body ends. |
| docs/carriers.md | Each carrier measured, in three tables: forward carriers, pairing carriers, and "dead or absent". |
| docs/hostname-sweep.md | 541 names on the domains of hosting platforms, each with an HTTP status or a DNS answer. |
| docs/poc.md | The two forwarders of the patch, each with its tests and numbers, and the limits of the proof of concept. |
| podssh-poc.patch | Two commits for podssh-ws: a TURN forwarder (RFC 6062, `turn://HOST:PORT`) and a streaming HTTP forwarder (`http://` and `https://` templates). Section 6. |
| results/*.json | Nine files: http-buffering, http-forward-direct, http-forward-proxy, http-piping, http-relay-hunt, reverse, wisp-concurrency, wisp-probe, wisp-throughput. |
| tools/*.py | Eighteen scripts: the HTTP relays and their probes, the pairing tools, the Wisp client and its stages, the hosted tunnels, TURN, Nostr, an echo server and a CONNECT proxy for the loopback, and a driver of `podssh ssh --forwarder`. |
| assets/* | Three figures, SVG and PNG. Each is of the run of 2026-11-03 ("One run, 2026-11-03" in each), which [relay-measurement.md](relay-measurement.md) read: none shows this commit's data. |
| LICENSE | 0BSD, as the first version's. |

What the commit does not hold (Read): the README's command
`tools/pair_stream.py` names a tool that is not in it; the Wisp probe reads
its server lists from a directory `enum/wisp/` that is not in it; and the
TURN numbers, smee.io's numbers and the Nostr harness's output have no
result file (TURN's are in docs/poc.md and the patch's comments, smee.io's
in results/http-relay-hunt.json without its tool, Nostr's nowhere).

## 2. How it measured, and from where

As its documents say (Read): one host, one egress, on 2026-11-04
(README.md, "Scope"). The egress is an HTTP CONNECT proxy that allows
listed names ("The HTTP CONNECT proxy is an allowlist", tools/probe_wisp.py);
a host that the proxy refused was tried again through cfrs's WARP proxy, a
SOCKS5 proxy on the loopback (tools/wisp.py, tools/measure_reverse.py).
The clients are Python's `websockets` and `asyncio`, and curl 8.14.1 for
the pairing services (results/http-piping.json).

| Tool | What it sends and reads | What it reports |
| --- | --- | --- |
| tools/http_probe.py | Forward: one POST, chunked, to the relay's URL with the target in it; a chunk, then a response byte waited for; a second chunk; 1 KiB of each byte value; the body's end. Pairing: a GET and a POST on one random path. | `streams`, `duplex`, `binary`, `closes`, a verdict. |
| tools/http_measure.py | On one open POST: 20 round trips of a numbered line; then 64 KiB blocks echoed for 10 s or 16 MiB; then 1, 2, 4 and 8 such sessions at once. | `rtt_ms` (min, median, p95), MiB/s, MiB/s at each count. |
| tools/http_relay.py, tools/buffering_relay.py | Two relays of 132 and 101 lines for the loopback: `POST /connect?host=H&port=P` dials H:P and streams both bodies, or reads the whole body first. | The shapes measured, not services. |
| tools/pair_curl.py | Two legs of curl on one path, lines written one second apart on the POST, each arrival timed on the GET. | STREAMS or BUFFERS. |
| tools/piping_measure.py | `curl -T` of a file of zeros up a path, a pause of 0.6 s, `curl` down the same path; 1, 2 and 4 pairs at once. | Bytes over the wall clock. |
| tools/probe_wisp.py | A Wisp CONNECT to `git.sr.ht:22`, the banner, then the client's version line and a check for SSH's KEXINIT; 8 servers at a time. | `two-way`, `no-ssh-banner` with the CLOSE's reason, or `fail`. |
| tools/throughput_wisp.py | A GET of a file of 13,332,982 bytes from a Debian mirror on port 80, through each server that passed the probe, 4 at a time; then 1, 2, 4 and 8 streams of the five fastest, each stream its own WebSocket, one server after another. | MiB/s from before the dial, the CLOSE's reason. |
| tools/measure_reverse.py | A local HTTP server with 16 MiB of random bytes, published by each hosted tunnel's own client inside cfrs's WARP namespace; the public URL fetched by curl through the proxy, then through WARP. | Bytes, seconds, the HTTP code. |
| tools/turn6062.py | Allocate, Connect and ConnectionBind to a TURN server; the first 60 bytes of the target. | "RFC 6062 TCP relay WORKS" when they are an SSH banner. |
| tools/measure_podssh_carrier.py | `podssh ssh --forwarder FORWARDER` to an sshd on the loopback: 20 round trips of a line, then 16 MiB of zeros down. | RTT and MiB/s. |
| tools/nostr_measure2.py | Eight public Nostr relays: a publish, its delivery to a second connection, a burst, an idle check, a ladder of message sizes. | No result in the commit. |

## 3. The results, file by file

### 3.1 HTTP forwarding on the loopback

The relay (tools/http_relay.py), the target (tools/echo_server.py) and the
CONNECT proxy (tools/connect_proxy.py) all ran on 127.0.0.1 (Read: the URLs
in results/http-forward-direct.json and the tools' addresses).

| File | Round trip, ms (min, median, p95) | 16 MiB | 1, 2, 4, 8 at once, MiB/s |
| --- | --- | --- | --- |
| results/http-forward-direct.json | 0.1, 0.2, 0.4 | 0.471 s, 33.97 MiB/s | 33.75, 67.19, 122.73, 201.94 |
| results/http-forward-proxy.json | 0.2, 0.2, 0.5 | 0.571 s, 28.02 MiB/s | 27.71, 54.06, 100.62, 167.07 |

docs/poc.md, through the patch's HTTP form under podssh's SSH: 33.75 MiB/s
and a median round trip of 0.7 ms direct, 36.41 MiB/s through the CONNECT
proxy, and "SSH hangs at banner exchange" through the buffering relay. The
patch's own comment says 0.3 ms and 80 MiB/s, of its run against a local
relay and an OpenSSH server (Read: three figures for one claim). These numbers are the loopback's: they measure a
Python relay and the host's CPU, not a network or a service (section 4,
item 1).

### 3.2 Buffering

results/http-buffering.json: the probe of the buffering relay ends as
`"verdict": "error"`, `TimeoutError` (Read). The probe waits for the
answer's head first, and that relay sends its head only after the body
ends, so the probe's own verdict `buffers` is never reached: the error is
the buffering (Inferred from tools/http_probe.py and
tools/buffering_relay.py). The timing test of tools/pair_curl.py tells the
two apart on public services: "streaming: SEND TICK-00, RECV +0.5s" against
"buffering: SEND TICK-00..03, then all four RECV at +6.41s after the body
ends" (Read: docs/carriers.md, "Streaming discriminator").

### 3.3 Piping Servers and other pairing services

| Service | Shape | Numbers (Read) | Verdict (the archive's) |
| --- | --- | --- | --- |
| `ppng.io` | Piping Server 1.12.9 | Streams, both ways, binary; the pair met in 808 ms. 1 MiB in 5.08 s (0.20 MiB/s); 2 pairs 0.35, 4 pairs 0.59 MiB/s in all. Bulk: 1 MiB 0.18, 8 MiB 0.12 MiB/s, and one transfer of 4 MiB moved 0 bytes. | usable |
| A Piping Server 0.18.0 (Rust) on a company's own cluster | Piping Server | Streams both ways; 1 MiB 0.52, 2 pairs 0.80, 4 pairs 1.07; 4 MiB 1.84, 8 MiB 3.10 MiB/s. | usable |
| smee.io | A POST in, server-sent events out | A round trip of 441 ms, 143.9 KiB/s. | usable |
| `piping.onrender.com`, and a second Piping Server on the same platform | Piping Server | Transfers complete; the bytes come "after body end only". | buffers |
| serv00's Piping Server (the name with `www.` before `p.kokoro.serv00.net`), and one more server | Piping Server | The same. | buffers |
| One service | HTTP | "streams at volume", "one direction only". | half-duplex |
| One HTTP relay on a public name, of the forward shape | HTTP | Wants a key. | key-gated |
| A demo hub of a publish-subscribe protocol | Server-sent events | Reads; publishes need its key. | read only |

Arithmetic on the rates: through `ppng.io`, 1 MiB took 5.56 s and 8 MiB
66.7 s in the bulk stage, so the seven MiB between them came at about
0.115 MiB/s (118 KiB/s); 4 pairs gave 0.59 MiB/s in all, about 0.15 each,
so the bound is of each transfer, not of the measuring host's link
(Inferred). Through the Rust server, 1 MiB took 1.92 s and 8 MiB 2.58 s:
the seven MiB between them came at about 10.6 MiB/s, and its "0.52 MiB/s"
is the fixed cost of the method (the pause of 0.6 s, two TLS handshakes
through the proxy, curl's start), not a rate (section 4, item 5).

The archive also says (Read: docs/carriers.md, "Pairing carriers") that
Piping Server 1.12.9 refuses a GET that declares a body, and that "a POST
that arrives before the GET is registered makes the server close both, so
the GET must be issued first with a delay". Its own tools/http_probe.py
sends `Transfer-Encoding: chunked` on each request, its GET too, which
explains the first; its own tools/piping_measure.py sends the POST first
and the GET 0.6 s later, and those transfers completed, which contradicts
the second (Read in both tools). podssh's reading of the source, a sender
and a receiver in either order (`docs/carriers.md:622-625`), and T-437's
measured road against nwtgck's servers stand.

### 3.4 Wisp servers: the probe

results/wisp-probe.json: 71 servers from the server lists of web proxies
(the archive's `enum/wisp/`), each asked for `git.sr.ht:22`; 57 through the
CONNECT proxy, 14 through WARP after the proxy refused them (Read).

| Verdict | Servers | What (Read; Arithmetic for the medians) |
| --- | --- | --- |
| two-way | 21 | The banner `SSH-2.0-OpenSSH_10.3`, then a KEXINIT after the client's line: both legs. Upgrade median 884 ms (246 to 1,820), banner 1,373 ms (699 to 2,567), KEXINIT 1,724 ms (846 to 2,948). |
| no-ssh-banner | 11 | Each a CLOSE with reason 72, 0x48, "the server blocks this destination" in podssh's words (`crates/podssh-ws/src/wisp/packet.rs:120`), after an upgrade of 848 to 1,206 ms. |
| fail | 39 | 14 through WARP, unmeasured (11 could not reach the SOCKS5 proxy, 2 timed out, 1 gave no HTTP answer); 25 through the proxy: 9 parked or expired domains whose redirect is a parking page, 5 `502`, 4 `503` on one platform (asleep, Inferred), 4 `404`, 1 `403`, 1 `200` with no upgrade, 1 timeout. |

The demo server `wss://wisp.mercurywork.shop/`: two-way, upgrade 986 ms,
banner 1,589 ms, KEXINIT 2,012 ms (Read). Mercury Workshop's second host
`anura.pro` ([carriers.md](../carriers.md), the other public Wisp servers):
two-way too. Of the other 19, 7 sit on subdomains of four other parties'
domains (one of them a school's name), and the archive gives no operator
for any of the 19 (Read in the URLs; counted here). By Q79 none is named,
and by T-535's Decision none is a candidate: no operator offers them.

### 3.5 Wisp servers: the bytes

results/wisp-throughput.json: the 32 servers that did not fail, the GET of
13,332,982 bytes on port 80, 4 servers at a time (Read).

| Outcome | Servers | MiB/s, from before the dial (Read; Arithmetic for the medians) |
| --- | --- | --- |
| The whole object, then CLOSE 0x02 | 23 | 0.683 to 3.99, median 2.249; after the upgrade, 0.97 to 4.96, median 3.58 |
| The 10 s window ended first | 6 | 0.085, 0.334, 0.420, 0.427, 0.440, 0.498 |
| No byte | 2 | Both two-way at the probe |
| No session | 1 | A timeout of the upgrade |

- 10 of the 11 servers that refused port 22 with 0x48 moved the whole object
  on port 80 (0.683 to 2.895 MiB/s); the eleventh did not open at this
  stage (Read). So those deployments refuse port 22 or that target by a
  rule of their own, and carry the web (Inferred: a port filter of the
  server; which rule was not read).
- The demo server: 5,054,472 bytes in 11.299 s from before the dial, its
  upgrade 903 ms, the window ended first: 0.427 MiB/s; 486,194 bytes a second
  after the upgrade (Arithmetic), which is its operator's "500kB/s bandwidth
  limit per IP" ([carriers.md](../carriers.md), the Wisp demo server).
  Three servers more ended near that rate (0.420 to 0.498 MiB/s); whether by
  the same limit was not read.
- `anura.pro`: the whole object in 13.92 s, 0.913 MiB/s (Read).
- The archive's Wisp client sends each request as a DATA packet (`0x02`,
  tools/wisp.py), so these port-80 bytes are real, where the first
  version's harness sent none ([relay-measurement.md](relay-measurement.md),
  section 3, item 5): 29 of the 32 servers carried port 80.

results/wisp-concurrency.json, the five fastest, each count after the other
on one server, each stream a WebSocket of its own, no error (Read):

| Server (by rank of the one-stream stage) | 1 | 2 | 4 | 8 MiB/s |
| --- | --- | --- | --- | --- |
| first | 1.199 | 2.251 | 4.283 | 8.442 |
| second | 3.176 | 6.101 | 6.457 | 4.495 |
| third | 2.328 | 6.971 | 5.818 | 3.800 |
| fourth | 3.808 | 3.579 | 13.464 | 14.059 |
| fifth | 1.237 | 3.564 | 12.429 | 9.335 |

The "1" cell of the first server is 1.199 MiB/s where the one-stream stage
gave 3.99 (Arithmetic: 3.3 times), as the first version's two runs differed
([relay-measurement.md](relay-measurement.md), section 3).

### 3.6 Hosted reverse tunnels

results/reverse.json: a 16 MiB file of random bytes published by each
tunnel's own client, run inside cfrs's WARP namespace, and fetched by curl
through the proxy, else through WARP (Read; tools/measure_reverse.py).

| Tunnel | Runs | Result (Read) |
| --- | --- | --- |
| bore.pub | 4 | `403` through the proxy at its public port; through WARP an empty reply, then 234 bytes, then the 16 MiB in 14.99 s, 1.067 MiB/s |
| Cloudflare's quick tunnel, by `cloudflared` | 1 | `530`, 7,735 bytes of a page, through WARP, 3 s after its URL came |
| localtunnel (`loca.lt`) | 2 | No URL; then the 16 MiB in 8.91 s, 1.796 MiB/s, through the proxy, `200` |
| Tunnelmole | 1 | No URL |
| tunnl.gg | 2 | No URL; then 520,192 bytes in 3.13 s, `200`, and curl's "HTTP/2 stream 1 was not closed cleanly: INTERNAL_ERROR (err 2)" |
| Sandhole's public server | 1 | No URL |
| hostc (`hostc.app`) | 1 | The 16 MiB in 3.95 s, 4.052 MiB/s, through the proxy |

The tool names one more client, tunelo, with no row. The localtunnel fetch
sent no `Bypass-Tunnel-Reminder` and got exactly 16,777,216 bytes, so no
reminder page came before the file (Arithmetic on the payload's size).

### 3.7 TURN

No result file (Read). The figures, each from another place: 3.43 MiB/s
(README.md and docs/carriers.md); "16 MiB down 3.10 MiB/s", "SSH session
runs" directly and "through an HTTP CONNECT proxy ... proxy logs 2
CONNECTs", and "a server without RFC 6062: `508`" (docs/poc.md); "64 MiB
echoed through TLS on 443 at 9.74 MiB/s" against coturn 4.6.1, and
"Cloudflare's Realtime TURN and LiveKit's public TURN both refuse the TCP
allocation with `508 Insufficient Capacity`" (the patch's comment, part 1).
Where the coturn ran is not said; tools/turn6062.py's defaults point at the
loopback, and its credentials are fixed test words (Inferred: the author's
own server).

### 3.8 The hostname sweep

docs/hostname-sweep.md: 541 names, about forty labels (bridge, pipe, relay,
tunnel, ssh, ws and the like) under 19 domains of hosting platforms, and a
made-up control name on each (Read). Counted here: 212 NXDOMAIN, 194 `404`,
62 `200`, 39 `410`, 14 refused, 5 TLS ended, 4 timeouts, 11 other codes.
Each name of one platform answered `200`, the made-up one too, so a `200`
there says nothing (a wildcard; Inferred); each of one platform's 39 names
answered `410` (that platform ended its hosting, Inferred); each name of the
Workers' domain was NXDOMAIN, as a Worker's name holds its account's
subdomain (Inferred). The sweep records a status alone: no upgrade, no
request of a carrier's shape. The archive's own carriers.md takes no
carrier from it.

### 3.9 The archive's "dead or absent"

Read in its docs/carriers.md: five Piping Server URLs of the project's
ecosystem with no service; `ppng.io:8443` not reachable from that egress;
bore.pub's control port 7835; croc's 9009; a NATS server and two MQTT
brokers on 4222, 8883 and 8084; one deployment of the template relay that
the first version read, its write leg gated; a DNS project's proxy, `502`; a
Media-over-QUIC relay, "transport only; no byte path"; "libp2p public
bootstrap nodes | refuse reservations"; "Nym, cjdns, I2P | peer addressing
only, no destination dial"; and a gRPC echo service that dials nothing.

## 4. The quality of the method

1. **The forward numbers are of the loopback.** The relay, the target and
   the CONNECT proxy are processes on 127.0.0.1 (section 3.1). The README
   calls throughput figures "lower bounds for a real network path"; on the
   loopback they are an upper bound of a Python relay. They prove the
   shape: one POST with both bodies open carries SSH where nothing on the
   way holds a body; and its twin shows that a hop that holds the body
   stops it at the banner.
2. **The forward shape was never measured through a hop that refuses the
   upgrade.** Through an opaque CONNECT proxy a WebSocket passes as well
   (Inferred), so the measured case is one where podssh's relay road works
   already. The case that matters, a proxy or a front that ends TLS, refuses
   the upgrade and still streams a request's body, has no measurement.
3. **The rate counts the dial**, as in the first version
   ([relay-measurement.md](relay-measurement.md), section 3, item 2): the
   Wisp stages take `t0` before the WebSocket opens; one server's upgrade of
   10.9 s turns its rate into 0.683 MiB/s.
4. **Four Wisp servers at a time** in the one-stream stage, 8 in the probe,
   so each figure shares the link with others (the first version's item 4).
   The concurrency stage runs one server at a time, which repairs the first
   version's item 1.
5. **The pairing rates hold fixed costs.** tools/piping_measure.py waits
   0.6 s between its two legs and counts two TLS handshakes through the
   proxy and curl's start in each transfer; at 1 MiB that is most of the
   time (section 3.3).
6. **A probe's verdict that cannot be reached.** The forward probe waits for
   the answer's head before its streaming test, so a relay that holds its
   head reads as an error (section 3.2).
7. **One run each**, as the first version; the reverse tunnels' "no public
   URL" rows say nothing of the service beyond that run.
8. **Three figures for one claim, and no file for it**: TURN's 3.43, 3.10
   and 9.74 MiB/s, the HTTP form's 0.7 ms and 33.75 MiB/s against 0.3 ms and
   80 MiB/s (sections 3.1 and 3.7).
9. **TLS with no check.** tools/turn6062.py turns off the check of the
   server's certificate (`CERT_NONE`, Read), so its TLS proves the path and
   nothing of the server.
10. **A credential in a tool.** tools/nostr_measure2.py holds a proxy's URL
    with a user and a password (Read). podssh never writes a proxy's
    credentials ([AGENTS.md](../../AGENTS.md), section 4); this page does
    not copy it, and no file of the archive goes into the repository.
11. **Its forward carriers are its own.** The two "usable" forward carriers
    of its README are its test relay on the loopback and a coturn of its
    author's; of the public services, the Wisp servers on other parties'
    domains and the pairing services remain.

## 5. Each finding against podssh's record

"Known" means that the record holds it; "confirms" that the archive's data
agrees with the record; "contradicts" that it disagrees (a `## Correction`
in the entry); "new" that the record does not hold it.

| # | Finding (the archive's) | podssh's record | Verdict |
| --- | --- | --- | --- |
| 1 | No public service of the forward shape over HTTP: the hunt found one relay, which wants a key; the sweep of 541 names found none. | `docs/carriers.md:22-24`: no provider with no account carries any TCP target over a WebSocket. | confirms, for plain HTTP too |
| 2 | One POST whose body is the way up and whose answer is the way down carries SSH where no hop holds a body; the same hangs where one does. | XHTTP's stream-one inside VLESS (`crates/podssh-ws/src/vless/xhttp.rs:10-11`); the HTTP road's split and serial forms for hops that hold bodies (T-319); no raw form. | new; T-622 |
| 3 | The discriminator: a response byte before the request's body ends. | `doctor`'s stream probe measures whether a request's body passes as it comes (`crates/podssh-cli/src/doctor/stream/mod.rs:1-3`, T-325). | known |
| 4 | A carrier that buffers passes a bulk test and hangs a session. | The Piping road's numbered pieces after 15 s (`crates/podssh-relay/src/piping/flow.rs:21-24`); T-319's forms. | known |
| 5 | TURN with RFC 6062 to a coturn carries SSH, directly and through a CONNECT proxy, on two connections. | No TURN client in podssh; `docs/carriers.md:364`, `docs/carriers.md:736-740`, `docs/carriers.md:911-912`. | new; T-621 |
| 6 | Cloudflare's Realtime TURN and LiveKit's public TURN refuse a TCP allocation (`508`). | `docs/carriers.md:364` and `docs/carriers.md:739`: no RFC 6062 at Cloudflare. | confirms (LiveKit's is new; both need an account) |
| 7 | `ppng.io`: streams, both ways, binary; about 0.12 to 0.20 MiB/s for one transfer, 0.59 for four; one of 4 MiB moved nothing. | `docs/carriers.md:619`: "Limits: not published, and not determined"; T-437's live runs carried 64 KiB each way. | new (a rate); T-625 |
| 8 | `ppng.io:8443` not reached from that egress. | `docs/carriers.md:600-601` names the Rust server on 8443; the road uses 443 (`crates/podssh-relay/src/piping/server.rs:12`). | confirms |
| 9 | `piping.onrender.com` and a second server on its platform hold a streamed body until its end. | T-497 takes it as the second server, with nothing on buffering (`docs/carriers.md:579-590`). | new; Correction in T-497 |
| 10 | serv00's Piping Server holds a streamed body. | T-575, step 1: "whether it streams". | answers step 1; Correction in T-575 |
| 11 | A Piping Server 0.18.0 on a company's cluster streams, 3.10 MiB/s at 8 MiB. | None; no operator offers it to others. | new, not used (Q79; T-497's rule of a public server) |
| 12 | "A POST that arrives before the GET ... close both". | `docs/carriers.md:622-625`, either order; T-437's Done. | the archive's own tool contradicts it; podssh's record stands |
| 13 | smee.io: a POST in, server-sent events out, 441 ms, 143.9 KiB/s, both ways. | None. | new; T-623 |
| 14 | One half-duplex service, one HTTP relay with a key, one read-only hub. | The class of HTTP Relay's demo (`docs/carriers.md:857-862`). | new, out for the reason of each; no entry |
| 15 | 21 of 71 Wisp servers of web proxies' lists carry both legs to port 22. | `docs/carriers.md:238-253`; T-535's Decision. | confirms the class; no candidate for T-535 |
| 16 | 11 Wisp servers refuse port 22 with 0x48 and carry port 80. | podssh says 0x48 in words (`crates/podssh-ws/src/wisp/packet.rs:120`); `docs/carriers.md:228-231`: "whether it does was not read". | new (some deployments add the rule); confirms that the first version's port-80 verdict was its harness's |
| 17 | The demo server: both legs; 486 kB/s after its upgrade. | `docs/carriers.md:226-227`; the word's note (`crates/podssh-ws/src/forwarder/builtin.rs:43`). | confirms; T-625 measures it through podssh |
| 18 | `anura.pro`: both legs, 0.913 MiB/s. | `docs/carriers.md:254-257`: Mercury Workshop's second host; its operator offers the demo alone. | known; out by T-535's Decision |
| 19 | Wisp's aggregate with several WebSockets, 3.8 to 14.1 MiB/s at 8. | podssh's Wisp puts streams on one WebSocket (`crates/podssh-ws/src/wisp/mux.rs`), and a session is one stream. | not podssh's measure; no entry |
| 20 | bore.pub up on 2026-11-04; 16 MiB at 1.07 MiB/s through WARP; the proxy refused its public port. | `docs/carriers.md:899-908`; T-569, Approach item 2. | confirms |
| 21 | localtunnel: 16 MiB at 1.80 MiB/s; curl's fetch with no `Bypass-Tunnel-Reminder` got the file. | `docs/carriers.md:957`, T-568's Premise and its plant. | contradicts; Correction in T-568 |
| 22 | tunnl.gg: a fetch cut at 520,192 bytes. | `docs/carriers.md:946-950`; T-567. | new (one sample); Correction in T-567 |
| 23 | `cloudflared`'s quick tunnel: `530` 3 s after its URL. | podssh's own quick tunnel (T-300), `docs/carriers.md:572-598`. | one sample of another program; no entry |
| 24 | hostc: 4.05 MiB/s; Tunnelmole, Sandhole's public server: no URL in one run. | None (Sandhole as a project of GitHub #18, the source of T-123: `TODO/serve.md:1185`). | new; T-624 |
| 25 | libp2p's public bootstrap nodes refuse reservations. | T-579; `docs/carriers.md:868-869`. | new for T-579's step 1; Correction in T-579 |
| 26 | Nym, cjdns, I2P: peer addressing only. | None; Q77 gives each overlay network a research entry. | new; T-626 (the reverse road needs no dial) |
| 27 | Non-443 services: croc, NATS and MQTT, bore's control port. | `docs/carriers.md:870-873`, `docs/carriers.md:899-908`, `docs/carriers.md:919`; T-541. | confirms |
| 28 | The hostname sweep: no carrier. | The sweep of 2026-11-02 and its rule (Q79). | nothing for podssh |
| 29 | A Nostr harness of eight relays, with no result. | T-545, step 1 (a start condition: T-086). | no data |

## 6. The patch, read as a proposal

podssh-poc.patch holds two commits for `crates/podssh-ws` (Read; not
applied, not built).

**Part 1, `turn://HOST:PORT`.** It changes
`crates/podssh-ws/src/forwarder/mod.rs` (the dispatch of a new form),
`crates/podssh-ws/src/forwarder/template.rs` (the form `Turn`, its parse,
`turn_server()`, a test), `crates/podssh-ws/src/lib.rs` (`pub mod turn`)
and `crates/podssh-ws/tests/forwarder.rs` (the stand-in skips the form),
and adds two files, turn/mod.rs (339 lines: the STUN codec, the long-term
credential with the MD5 key and HMAC-SHA1, Allocate with
REQUESTED-TRANSPORT 6 and a lifetime of 600 s, Connect with the target's
XOR-PEER-ADDRESS, ConnectionBind on a second TLS connection that takes the
first's realm, nonce and key, the words of `508` and `403`) and
turn/forward.rs (73 lines: a forwarder's session, the credentials from
`PODSSH_TURN_USER` and `PODSSH_TURN_PASS`, the target resolved by the
host's resolver).

- podssh has: none of TURN (no code names it); the parts that it takes,
  each pure Rust: `hmac`, `md5` and `sha1` in podssh-ws
  (`crates/podssh-ws/Cargo.toml:17`, `crates/podssh-ws/Cargo.toml:45-46`),
  the dial through `HTTPS_PROXY` (`crates/podssh-ws/src/dial.rs:201`) and TLS
  over it (`crates/podssh-ws/src/tls.rs:135`), and its own resolver order
  (`crates/podssh-ws/src/resolve.rs:2`).
- What the reading finds in it: no Refresh, so a session ends with its
  allocation of 600 s (its own "Limits"); credentials in the environment,
  where podssh reads a user's file (`--via-auth-file`); a scheme `turn://`
  that always means TLS, where RFC 7065's `turn:` has none and `turns:` has
  TLS; the host's resolver, which a host may lack; `508` alone taken as "no
  RFC 6062", where RFC 8656 names `442`, Unsupported Transport Protocol, for
  a transport that a server does not take (Inferred from RFC 8656's codes;
  T-621 reads them); a CONNECTION-ID read with no check of its length, an
  index past the end on a short attribute from a hostile server; and a
  second connection, which rule 2 of [AGENTS.md](../../AGENTS.md) (section
  5) has no exception for.
- Where it went: T-621, a road of its own (`--turn turns:HOST`) with a
  file of credentials, not a form of `--forwarder`; its second connection
  is a question for the operator (section 8).

**Part 2, `http://` and `https://` templates.** It changes
`crates/podssh-ws/src/forwarder/mod.rs` and
`crates/podssh-ws/src/forwarder/template.rs` (the form `Http`, the scheme
rewritten to `ws://` or `wss://` so that each check of a template applies;
the test case of an `https://` template taken out of the refusals; a new
test) and `crates/podssh-ws/src/lib.rs` (`pub mod httpstream`), and adds
httpstream/mod.rs (210 lines: a plain or TLS link, a POST with a chunked
body, the answer's head read a byte at a time, a reader of a chunked body)
and httpstream/forward.rs (78 lines: the session, the bytes up in chunks of
`FORWARD_SEND_PAYLOAD`, `crates/podssh-ws/src/frame.rs:52`).

- podssh has: no raw HTTP form of `--forwarder`, whose templates are
  `ws://`, `wss://` and `wisp+` alone
  (`crates/podssh-ws/src/forwarder/template.rs:64-66`, and the refusal of an
  `https://` template that `crates/podssh-ws/src/forwarder/template.rs:198`
  tests); the same shape inside XHTTP's stream-one, over HTTP/2 alone, as
  Go's server reads a whole body before it answers on HTTP/1.1
  (`crates/podssh-ws/src/vless/xhttp.rs:19-21`); the HTTP road of podssh's
  relay role for hops that refuse the upgrade and hold bodies (T-319); and
  chunked HTTP/1.1 in the Piping Server road
  (`crates/podssh-relay/src/piping/http1.rs`).
- What the reading finds in it: HTTP/1.1 alone; no form for a hop that
  holds the body (its own "Limits"); an answer read as chunked whatever its
  head says, so an answer with a `Content-Length`, or one that ends at the
  close, is read wrong; a size line with no bound on its length; and an
  `https://` template, refused today as a mistyped `wss://`, that becomes
  another road with no word.
- Where it went: T-622, the shape as a form of the HTTP road of podssh's
  relay role, tried first where the way streams a body, with T-319's forms
  behind it; no server of the shape exists apart from the role, so no
  `--forwarder` form (T-622's Decision).

The archive's "Tests: 171 in podssh-ws, including the new template
parsing" (docs/poc.md) is the archive's claim; nothing here ran.

## 7. The entries and the Corrections

| Entry | What |
| --- | --- |
| T-621 | TURN with RFC 6062: a TURN server that the user runs, as a road (`--turn`), M10, P3, M. |
| T-622 | The HTTP road's one-POST form, where the way streams a body, M10, P3, M; after T-319. |
| T-623 | smee.io as a carrier where a proxy refuses the upgrade: the research, M10, P3, S. |
| T-624 | hostc, Tunnelmole and Sandhole's public server: the research, M10, P3, S. |
| T-625 | The rates of `ppng.io`'s road and of the Wisp demo server, through podssh, M10, P3, S. |
| T-626 | I2P, Nym and cjdns for the reverse road: the research (Q77), M10, P3, S. |

Corrections, each with the archive's file: T-497 (its second server holds a
streamed body), T-575 (serv00's server holds one too), T-568 (curl met no
reminder page), T-567 (a fetch cut at 520,192 bytes) and T-579 (the
bootstrap nodes refuse reservations).

## 8. Questions for the operator

They are in [PROGRESS.md](../../TODO/PROGRESS.md), "Questions for the
operator", as calls for the operator to confirm (Q86), numbered Q93 to Q95
in the order below at the merge; each entry's `## Decision` holds the call
that it makes until the operator rules.

1. **May the TURN road open a second connection?** RFC 6062 carries the
   bytes on a data connection of its own, beside the control connection
   that holds the allocation. Recommendation: yes, a sixth exception of rule
   2 of [AGENTS.md](../../AGENTS.md) (section 5), as Q44 and Q67 are: to the
   same server, only when the user names one with `--turn`, never unasked
   (T-621).
2. **May a session run short live tests against smee.io and the three
   hosted tunnels of T-624?** Q91 allows them for the services that T-548
   named, and these were not among them. Recommendation: yes, as Q91 rules
   for those: short runs, throwaway channels and tunnels given up at the
   end, from GitHub Actions and the session's own host, once each research
   entry has read the service's terms (T-623, T-624).
3. **The archive's two forwarders as podssh's?** The patch proposes
   `turn://` and `https://` forms of `--forwarder`. Recommendation: no, as
   T-621 and T-622 decide: TURN as a road of the user's own server with a
   file of credentials, and the HTTP form inside podssh's relay role, where
   a fallback for a hop that holds bodies exists.

## 9. What a main session verifies

- The counts of `TODO/INDEX.md` and `TODO/PROGRESS.md`, which this draft
  wrote by hand: `cargo todo counts`, then `cargo todo check`.
- `cargo todo remap TODO/mesh.md`: the Corrections went into the middle of
  that file.
- The readings of the patch in section 6, against the patch itself
  (UNVERIFIED: nothing built).
- The inferences of sections 3 and 4, each by the entry that names it: the
  front that holds bodies at `piping.onrender.com` (T-497), the reminder page
  of `loca.lt` and a browser's `User-Agent` (T-568), the cut of tunnl.gg
  (T-567), the rate of `ppng.io` through podssh (T-625), and the codes of
  RFC 8656 (T-621).
