# A note to the relay's operator

podssh is one static Rust binary that carries SSH, or another TCP stream,
through a WebSocket relay on port 443, for hosts whose only way out is
HTTPS. Its relay is `tcp-ssh-relay` at `https://tcp.ssh.relay.ajam.dev`, a
Cloudflare Worker that podssh's operator runs from another repository: the
forward road (`podssh ssh`, `proxy`, `cp` and the others) and the reverse
road (`podssh node`, `operator` and `ssh node://`) go through it. The
relay's live document, `https://tcp.ssh.relay.ajam.dev/llms-full.txt`, is
the contract and the boundary of podssh ([decisions.md](decisions.md), Q4
and Q9). podssh uses version `2026-10-03-r2`, and [relay.md](relay.md)
gives the parts that it uses. When an item is done, change the contract and
tell podssh's operator, as the last section says
([When an item is ready](#when-an-item-is-ready)).

Each item below waits for the relay, unless it says that it is optional or
a question. It names the entry of [TODO/](../TODO/INDEX.md) that holds the
detail, and the GitHub issue where there is one; "no entry" marks a
question or an option that podssh's record does not hold. podssh's sessions
skip the entries that wait for the relay. The most urgent come first: the defects of the relay's side,
then the roads that the testers asked for. Read on 2026-10-31: the relay
served version `2026-10-03-r2`, byte for byte the pinned copy
[`relay-spec-2026-10-03-r2.txt`](../crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt)
(SHA-256 `88eb1b0b...a5a8`), and `python3 scripts/check-relay-spec.py`
found each of podssh's 7 facts in it.

## Defects on the relay's side

1. **A slow client's bytes are held with no bound** (T-336, [TODO/relay.md](../TODO/relay.md); [#17](https://github.com/Azathothas/podssh/issues/17)).
   Measured on 2026-10-31, twice from a cloud container and once from
   GitHub Actions (`.github/workflows/relay-live.yml`, run 41157016178),
   through the relay's own loop: a forward session to
   `tcp.ssh.relay.ajam.dev:443` (the relay dials itself, on the VPC road)
   carried, inside its TLS, the operator's leg of a pair of the reverse
   road. The pair's node had 48 MiB to send, and the forward client read
   16 KiB/s. No Close came in 90 s: neither the forward road's
   `1013 client receive backlog` (at 2 MiB queued, by the relay's source)
   nor the reverse road's `1011 relay backpressure` (over 1 MiB queued, by
   the contract). The node gave the relay all 48 MiB within 15 s, so
   48872032 bytes (46.6 MiB) more than the client had read waited in the
   relay or its edge. The control, at full speed, carried 8 MiB and ended
   `1000` at both levels. By the relay's source, the forward check reads
   `bufferedAmount`, which Workers may not supply. Not measured: the other
   direction, `1013 target write backlog`.
   - Find where the bytes wait: in the forward road's Worker, in the
     reverse road's object, or at the edge between the relay's egress and
     its own front. Count what each socket queued.
   - Bound them: stop reading the target, or the node's socket, while the
     limit waits for the client, or close with the documented code once the
     limit is passed. Say which in the contract.
   - Inferred, not measured: a Worker's memory has a limit, so a few such
     sessions in one isolate could end it, and each session that it
     carries. Check whether this causes the drops of item 2.
   - podssh's check: `crates/podssh-relay/tests/live_backpressure.rs`
     (108 s, from podssh's host or in `relay-live.yml`). When the relay
     bounds the queue, its verdict names a `1013`, or less than 16 MiB past
     the node. podssh keeps the SSH window at 512 KiB, so the relay holds no
     more than that for an SSH session; a raw stream (`podssh proxy`, `-W`)
     has no such bound.
2. **Reverse sockets end with no Close** (T-255, [TODO/relay.md](../TODO/relay.md)).
   Measured on 2026-10-09: the TCP connection of a socket of the reverse
   road (`/v1/node/<name>` or `/v1/connect/<name>`) ended at random, with
   no WebSocket Close. In 6 of 12 runs of 240 s, a drop came at 24 s to
   212 s, with payload, with Pings and with no frame at all, so the traffic
   does not cause it. The drops come in bursts:
   - 00:27 to 01:28 UTC, from podssh's machine: about 9 drops an hour of a
     session.
   - 01:31 to 02:05:38 UTC, from podssh's machine and a GitHub Actions
     runner at once (`.github/workflows/reverse-drops.yml`, run
     37870123203): no drop from the machine in 2.3 hours of sessions; one
     from the runner, at 02:01:01.872Z, when both sockets of one pair ended
     at once. The machine saw nothing at that moment, so the whole relay
     did not restart.
   - Two kinds: one socket ends while the relay lives on, and the relay
     tells the other end (`1011 node disconnected` to the operator, or a
     `close` of the session to the node), 6 times; or both sockets of one
     pair end at once, as when the pair's object ends, 2 times.
   - Forward sessions beside them, from both networks: no drop in 1.2
     hours.

   Read the relay's logs for the ends of reverse sockets in those windows.
   podssh's runs kept the UTC time of each drop, not the relay's session
   ids. Send a Close (`1001` or `1012`) before a restart that the relay
   plans, so that a client can tell it from a broken link. Keep the reverse
   sockets across a restart of the pair's object, where the platform allows
   it. Item 1 may be a cause. If the logs of that day are gone, ask podssh's
   operator for a new run in a window that you name:
   `crates/podssh-relay/tests/reverse_drops_live.rs` holds four pairs for
   about 16 minutes from podssh's host, and `reverse-drops.yml`, run by
   hand, holds them from GitHub Actions at the same time. podssh's side is
   done: `podssh operator` and `podssh ssh node://NAME` say that the link
   ended with no Close, a node connects again, and the resumable layer
   carries a session over a drop.
3. **No IPv6 egress** (T-253, [TODO/relay.md](../TODO/relay.md); [#2](https://github.com/Azathothas/podssh/issues/2)).
   Measured on 2026-10-08, at the version that the relay still serves: no
   IPv6 host can be reached. `/connect/2001:4860:4860::8888/853` (the bare
   address; also with `%5B` and `%5D`, raw brackets, or `%3A` for each
   colon) upgrades, and the session closes with
   `1011 target closed before sending anything` at the client's first
   bytes. `/trace?target=[2001:4860:4860::8888]:853` says
   `dialed_literal: true`, `address_family: 6` and `road: vpc`.
   `www.google.com:80` with `?family=6` gets the same `1011`, and with
   `?family=6&path=direct` a `502`; `ipv6.google.com:80`, which has only an
   IPv6 address, the same `1011`. IPv4 to the same hosts works. So the VPC
   road takes an IPv6 dial and fails it at once, and the direct road
   refuses it. Give the egress an IPv6 route. Else refuse an IPv6 target
   before the upgrade, with a `502` and the reason, so that a client learns
   it at once, and say so in the contract. podssh's check:
   `cargo test -p podssh-relay --test live -- --ignored ipv6 --nocapture`
   prints "bytes came back from the IPv6 host".
4. **A question: one write of a frame above 64 KiB** (T-323, [TODO/relay.md](../TODO/relay.md)).
   workerd issue 7074 (`cloudflare/workerd`, opened on 2026-08-20)
   reports that one `write()` of more than 65,536 bytes to a socket of
   `connect()` resolves, and that the next read then fails with
   `Error: Network connection lost.` ("Exactly 65,536 bytes succeeds;
   65,537 fails, every time"; in the production runtime only; writes of
   32 KiB or less avoid it). The relay takes frames of up to 262144 bytes
   (`/relays.json`, `limits.max_frame_bytes`). Does the relay write each
   frame to the target in one `write()`, and does its runtime have that
   limit? If so, write in pieces of 32 KiB or less. podssh sends at most
   32 KiB in a frame since T-323, and no test of podssh has sent a frame
   above 65,536 bytes to the relay; other clients can.

## Roads for networks that block the WebSocket

The testers asked for these (#51, #54, #55 and #56). podssh's operator
allowed the two roads that needed a ruling (Q44 and Q45 in
[decisions.md](decisions.md)). podssh builds its side of each when the
relay's endpoints are in the contract.

5. **An HTTP road** (T-319, [TODO/roads.md](../TODO/roads.md); [#55](https://github.com/Azathothas/podssh/issues/55)).
   For a proxy that re-terminates TLS for the relay's name, refuses
   `Upgrade`, and still carries plain HTTPS requests (the proxy of a Claude
   Code cloud container documents such a refusal, T-311). The relay's
   part: session endpoints in the contract, with a session id, sequence
   numbers and acknowledgements, in two forms. The split form comes first:
   one streamed GET carries the bytes down, and a POST for each batch
   carries them up, on two connections at once (Q44 allows the second
   connection on this road only). The serial form is its fallback: one POST
   after another on one connection, each answered with the bytes that wait
   to go down, as meek does. The protocol that #55 proposes:
   - `POST {base}/s/{sid}/up?seq={seq}` carries one batch. `204`: stored,
     not consumed yet; `200`: stored and consumed; any other answer: the
     client sends the same `seq` with the same body again. An `X-Ack`
     header says that each `seq` below it is consumed.
   - `GET {base}/s/{sid}/down?ack={ack}` streams the chunks down, or
     answers `204` when nothing waits, and the client asks again. The
     client closes the GET and sends a new one before a proxy's time limit.
   - `seq` rises in each direction and is never used again. The relay
     deletes a chunk only after the consuming end acknowledged it, and
     holds a window with a bound, so a replay is always possible and the
     store does not grow without limit. A `204` is a whole answer, so a hop
     that buffers holds nothing open. The poll interval and the batch size
     come from the probe of item 6, not from constants.
   - The relay chooses the paths, and how a session opens and gets its id.
     podssh sends the token in a header only, never in a URL (URLs go into
     logs), so a session id in a path must not be enough to reach the
     session.

   Read in the research of 2026-10-30, not measured: a relay on Cloudflare
   streams responses with no time limit, and a Durable Object can join both
   directions of a session. podssh's check: 20 MiB each way, with equal
   digests, on each form, through a stand-in proxy that refuses `Upgrade`
   and buffers request bodies; then the live relay.
6. **Endpoints that `doctor` can measure** (T-325, [TODO/ws.md](../TODO/ws.md); [#54](https://github.com/Azathothas/podssh/issues/54)).
   On the relay's own host: one endpoint that sends a response in timed
   chunks, and one that takes a body in chunks and says when each chunk
   came. With them, `podssh doctor` measures what a path does to a stream:
   whether it holds a response to its end (the time of the first byte
   against the last), whether it holds a request body to its end (a stall
   between chunks), its cap on a body (a body that doubles until `413` or
   `431`), and its idle limit (a quiet stream, and the time and status when
   it ends; #54 names limits from 60 s to 15 minutes). Give each limit of
   the endpoints in the contract, so that a cut below it is the path's.
   Item 5 takes its poll interval and its batch size from these results.
7. **A cleartext upgrade on port 443** (T-326, [TODO/ws.md](../TODO/ws.md); [#56](https://github.com/Azathothas/podssh/issues/56)).
   For a proxy that tunnels CONNECT but intercepts TLS by its SNI or its
   certificate: an endpoint that takes the WebSocket upgrade with no TLS on
   port 443, with the paths and the token header of the forward road.
   Cloudflare's edge serves TLS on 443, so this needs another front (item
   12 is one). Measured on 2026-10-30 through a cloud container's proxy:
   `CONNECT tcp.ssh.relay.ajam.dev:443` got `200`, then a cleartext
   `GET /` was reset with no answer. Not measured: what Cloudflare's edge
   answers to cleartext on 443 from a path with no such proxy. podssh tries
   this road last, after the TLS road failed, with a token minted for that
   one session and never cached, as each hop can read the header (Q45). A
   token that the relay takes once, or that ends within minutes, would
   limit what a hop can do with it (#56): say in the contract whether a
   mint can ask for one.
8. **Extended CONNECT** (T-321, [TODO/roads.md](../TODO/roads.md); [#51](https://github.com/Azathothas/podssh/issues/51)).
   A WebSocket as one stream of an HTTP/2 connection (RFC 8441), so that
   many sessions share one TLS connection. Measured on 2026-10-30: the
   relay's edge (Cloudflare) chose `h2`, and its SETTINGS had
   `MAX_CONCURRENT_STREAMS` 256, `INITIAL_WINDOW_SIZE` 65536 and
   `MAX_FRAME_SIZE` 16777215, and no `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
   Only a relay with its own front can offer it (item 12). The relay's
   part: send `SETTINGS_ENABLE_CONNECT_PROTOCOL` with the value 1, and take
   a CONNECT with `:protocol` `websocket` and the `:scheme`, `:path` and
   `:authority` of the upgrade, with the token in a header, answered
   `200`. Through a proxy that does not end TLS, the relay alone must offer
   the setting; a proxy that ends TLS must implement RFC 8441 itself (RFC
   9113, section 8.5). podssh keeps the HTTP/1.1 upgrade where the setting
   is absent.

## Pairing

9. **Signed grants, used once** (T-226, [TODO/reverse.md](../TODO/reverse.md); [#35](https://github.com/Azathothas/podssh/issues/35)).
   Each token of a pair is a bearer token: whoever holds it can use it, as
   often as they like, until it expires, up to 72 h. The relay's part: an
   endpoint, in place of `POST /v1/pair`, that gives a signed grant. The
   grant names the node, the principals that may use it (key fingerprints,
   T-087), an expiry and a nonce. The relay records the nonce as spent, and
   refuses a second use. The entry proposes an SSHSIG signature in a fixed
   namespace of podssh, which `ssh-keygen -Y verify` can check. podssh
   keeps a grant in a 0600 file and sends it in a header, never in a URL.
   The live check: a second use of one grant gets the relay's refusal.
10. **Pairing by a short code** (T-086, [TODO/reverse.md](../TODO/reverse.md)).
    Today the node gives the operator a file with the relay host, the
    pair's name and its `connect_token`, and a person moves it over a
    trusted channel. The relay's part: a mailbox endpoint, where two
    clients that hold the same short code meet with no pair. It carries the
    messages of a SPAKE2 exchange keyed by the code, then the node's part
    for the operator (the relay host, the name, the `connect_token` and the
    expiry), sealed with the agreed key. The code never crosses the
    network: three words from a fixed list and a number, used once, valid
    for 10 minutes. The mailbox limits the attempts, and one failed
    exchange ends the code. podssh keeps the file as the fallback.

## The Tailscale relay

11. **Two node keys on the allowlist** (T-106, [TODO/ts.md](../TODO/ts.md)).
    The live test of `podssh ts` with two nodes, in `relay` mode, through
    the Tailscale relay `tcp.ts.relay.ajam.dev:443`, which closes a node key
    that is not on its allowlist with `1008 not authorized`. The test keeps
    two state files of `podssh ts`, as a new state file is a new node key,
    and needs the node key of each on the allowlist. That takes a Tailscale
    admin token and the relay's deployment credential, which only the
    operator has ([tailscale.md](tailscale.md)). Ask podssh's operator for
    the two nodes first: step 2 of the entry's Approach makes their state
    files, on podssh's operator's machine, which holds the tailnet's auth
    key. Never take a state file: it holds the node's private key. `podssh
    ts` prints the first 8 hex characters of a node key on its status line,
    and exits 77, with a hint, when the relay refuses the key.
    [tailscale.md](tailscale.md) also names the relay's `derpMap` runbook as
    open.

## Relays beyond the one deployment

12. **A relay that its users host** (T-169, [TODO/roads.md](../TODO/roads.md); [#18](https://github.com/Azathothas/podssh/issues/18), [#25](https://github.com/Azathothas/podssh/issues/25)).
    Offer the relay as one program that a user runs on a server of their
    own, on port 443, with the same contract, so that podssh needs no
    change: `--relay-host` names it. It needs:
    - the forward road: `/connect/<host>/<port>`, the token header,
      `/v1/mint`, an empty frame each 25 s, the limits (180 s idle, 12 h,
      64 MiB, frames of 262144 bytes), the close codes that
      [relay.md](relay.md) gives ("Errors and close codes"), and `/health`
      with the service name `tcp-ssh-relay`, which `podssh doctor` checks;
    - the reverse road: `/v1/pair`, `/v1/node/<name>`,
      `/v1/connect/<name>`, `/v1/stop/<name>`, the text control frames, the
      32-character ids, `409` for a second node, and the reverse close
      table;
    - the targets: public addresses only, checked after the name resolves;
      TLS with a certificate that the relay's owner gives; and rate limits
      and quotas for each address and each token.

    Such a front can offer what Cloudflare's edge cannot: items 7 and 8.
    The smallest form ([#60](https://github.com/Azathothas/podssh/issues/60)):
    the relay's forward road as a Worker that a user deploys under a free
    Cloudflare account of their own. #59 reports three public WebSocket forwarders that take the
    destination from the client; on 2026-10-31 each carried GitHub's SSH
    banner with no account. Two are Cloudflare Workers
    (`Mudlet/mudlet-web:worker/index.js`). They publish no limit and give no
    notice, and #59 ranks as its road 2 the same Worker, about 40 lines,
    under the user's own free account: one `wrangler deploy`, an e-mail
    address, no card. podssh's side is T-369
    ([TODO/roads.md](../TODO/roads.md)): `--forwarder TEMPLATE`, a road
    through a forwarder that the user names, which takes the target from its
    URL or from a first frame of JSON, and gets no relay token. podssh ships
    no forwarder of its own; by the operator's ruling on Q56 (2026-10-31),
    the binary will name the three of #59 and try them when each relay host
    fails (T-370). Item 15 holds for such a Worker too.
13. **An iroh relay of the operator's** (no entry; optional). podssh's iroh
    road (behind the cargo feature `iroh`, in each release binary since
    T-348) uses n0's public relays
    (`crates/podssh-iroh/src/relays.rs`), which n0 offers for development
    and hobby use ([design.md](design.md), section 7). The operator decided
    on 2026-10-08 that an iroh relay on the operator's own Cloudflare
    account goes first once it exists, with n0's relays after it
    ([decisions.md](decisions.md)): one line in podssh, with its
    measurement (T-165, T-157). podssh needs an `https://` origin with no
    path, which answers iroh's `/ping` and speaks the relay protocol of
    iroh 1.4. At least three projects run the iroh relay protocol on
    Workers and Durable Objects (read, not verified).
14. **A signed `/relays.json`, and a second deployment** (T-346, [TODO/relay.md](../TODO/relay.md)).
    Optional: do it if the relay's operator wants it. podssh's operator
    ruled on Q49 on 2026-10-31: a binary may use a relay outside
    `ssh.relay.ajam.dev` that speaks this contract, and it sends a token
    only to the deployment that minted it. podssh's side of T-346 is open.
    Relays that users bring (item 12, and the relay template of #60) and a
    coming `podssh update` (T-375) make a signed list of deployments less pressing.
    Today a binary in the field knows relay hosts under
    `ssh.relay.ajam.dev` only, unless its user names another, so a lapse of
    `ajam.dev` (RDAP gives its expiry as 2028-01-19) or an outage of
    Cloudflare stops each road but `--direct`. For a hedge: run a second
    deployment on another provider and under another domain, and name it
    in `/relays.json`; and sign the document with an offline Ed25519 key.
    The relay's operator chooses the form, and podssh follows it. T-346
    proposed a detached signature over the document's exact bytes, in a
    header or at `/relays.json.sig`; a `serial` and a `not_after` in the
    document; and two public keys compiled into podssh, the current one and
    the next, each by its id.
15. **Cloudflare's terms** (no entry; a question). Cloudflare's Self-Serve
    Subscription Agreement, section 2.2.1(j), forbids using its services
    "to provide a virtual private network or other similar proxy services"
    (<https://www.cloudflare.com/terms/>, last updated 2025-09-12). Read
    whether it applies to the relay, and to each relay of this section that
    runs on Cloudflare. [carriers.md](carriers.md) gives the study that
    found it. If it applies, a deployment on another provider (item 14)
    matters more.

## Larger work of the relay project

16. **Resumption in the relay for a standard sshd** (T-173, [TODO/roads.md](../TODO/roads.md)).
    A forward session to a standard sshd ends at each drop of the client's
    link, and only the relay can keep the TCP connection to sshd while the
    client connects again. The option of [design.md](design.md) (section 5,
    layer 3): a Durable Object that owns the target's socket across
    reconnections, a resume token in the `101`, and offset framing as a
    protocol version that the client selects; it costs Durable Object time
    for the whole session. podssh would propose the records of its
    resumable layer (T-151), so that the relay becomes the far end of that
    layer. podssh uses it only where `/relays.json` or `/health` says that
    the relay offers it, keeps the resume token in memory, and sends it in
    a header only. A resume must reach the same object, so only the hosts
    of one deployment can resume a session. Decide it with podssh's
    operator first ([design.md](design.md), section 8, question 1); its
    condition, the end of M6, holds since 2026-10-10.
17. **A local HTTP service published at `https://NAME`** (T-180, [TODO/pipe.md](../TODO/pipe.md); [#26](https://github.com/Azathothas/podssh/issues/26)).
    An endpoint that takes public HTTPS for a name, and hands each incoming
    connection to a node as a session of the reverse road (`open {id}`,
    `ready {id}`), so that a node serves it with today's runner
    (`podssh node NAME TARGET --publish`, to come). Publish it in the
    contract first: the name, its public host name, and the sessions. TLS
    ends at the relay, and podssh says so: "TLS ends at the relay; the
    relay can read this traffic." podssh parses no HTTP: the bytes pass,
    WebSocket upgrades too. Expiry and passwords are options of the relay;
    podssh passes them, and never prints a token.

## Questions about the contract

18. **What podssh reads outside the contract** (no entry). podssh depends
    on these facts, and the contract does not state them, or states them
    in two ways:
    - The forward road's close codes. The contract's table is for the
      reverse road only; podssh read the forward codes in the relay's
      source at `2026-10-03-r2` ([relay.md](relay.md), "Errors and close
      codes"): `1000`, `1001`, `1009`, `1011` and `1013`, each with its
      reasons. Publish them, as the reverse table is published.
    - `/llms.txt` has two facts that `/llms-full.txt` does not: `/v1/pair`
      can answer `409` (a name collision: retry with a new pair), and a new
      `MINT_SECRET` ends each minted token at once.
    - Port 25: the contract says that the platform refuses it on the direct
      road; `/relays.json` says "port 25 is refused on every road" (read on
      2026-10-31). Its `limits.allow_ports_note` names a deny list of ports
      that the contract does not give.
    - Web ports on the direct road: the contract says that the platform
      refuses a direct-road connect to ports 80 and 443. #59 reports a plain
      Workers `connect()` (Mudlet's Worker) to `ssh.github.com:443` that
      carried GitHub's SSH banner on 2026-10-31, and reads Cloudflare's
      documents (updated 2026-10-13) as refusing port 25, Cloudflare's
      ranges and private addresses only.
    - `?precheck`: the contract says "clamped to the server cap", and names
      no value; podssh measured about 400 ms (2026-10-01), and a value that
      is not a number is read as `0`, with no message.

## When an item is ready

Change the live contract (`/llms-full.txt`), give it a new version, and
tell podssh's operator which item it is, by its entry (T-NNN), or by its
title when it has none: the numbers of this page change when items come and
go. A podssh session then reads the new contract (`podssh relay spec`),
lifts the entry's blocker, builds the client's side, and tests it against
the live relay; it updates the pinned copy and [relay.md](relay.md) in the
same commit. For an item that changes no endpoint (a cause found, keys on
an allowlist, an answer to a question), a note to podssh's operator is
enough.

podssh reads the contract each day (`.github/workflows/relay-watch.yml`),
and opens an issue when one of its facts
([`relay-facts.toml`](../crates/podssh-probe/facts/relay-facts.toml))
changes or leaves its section: the paths `/v1/node/<name>` and
`/v1/connect/<name>` under "Exact addresses"; "no subprotocol" and the
binary frames under "Protocol (for other clients)"; and under "Reverse
close codes", the 15 s for a `ready`, and the row
`1009 bad multiplex frame` with its 65568 bytes. A new version that keeps
these facts opens no issue, so tell podssh's operator of it. Keep these
headings, or say first which ones move.

podssh also compares the five `limits` of
`/relays.json?host=github.com&port=22` (`connect_timeout_ms`,
`idle_timeout_ms`, `max_session_ms`, `max_session_bytes` and
`max_frame_bytes`) with its own copy
([`relay-limits.toml`](../crates/podssh-probe/facts/relay-limits.toml)), on
each push and each day (T-342). A binary narrows its budgets to smaller
limits, and takes larger frames up to 16 MiB, from the document at run
time, but a changed value fails podssh's checks until its operator moves
the copy and the compiled constants. So say first when a limit changes.
