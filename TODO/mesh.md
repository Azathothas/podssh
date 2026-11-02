This file holds the work of milestone M10: podssh's own nodes as a mesh at parity with
Tailscale, and the relay as a role of podssh itself (the operator's ruling Q63, 2026-11-02;
`docs/mesh.md`). The relay role's forward road is T-169 (`TODO/roads.md`), and the entries that
waited for the relay's operator carry their Corrections in their own files.

# T-427: The relay's reverse road in podssh's relay role

**Source:** the operator's ruling Q63 (2026-11-02), `docs/mesh.md`, section 4.
**Category:** feature
**Milestone:** M10
**Priority:** P1
**Effort:** L
**Status:** open

## Problem

A node and its operator meet through the pairs of the default relay, or on the roads of iroh,
DERP and the quick tunnel. A user who runs podssh's own relay (`podssh relay serve`, T-169) has
no reverse road on it, so the items of the reverse road that the default deployment lacks (a
bound for a slow receiver, a frame in flight, a Close before a stop) have no server that podssh
controls.

## Premise

- The reverse road's contract is the pinned copy
  `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`; its close table is at
  `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`, which says "Over 1 MiB
  queued for a slow receiver".
- The contract is executable: `scripts/fake_reverse.py` serves the pairs, the node's socket and
  the operator's, as strictly as the live relay for an unknown id (T-412), and tells a frame in
  flight apart (T-420).
- The node's side of each frame and control is podssh's own (`crates/podssh-relay/src/reverse/`).

## Approach

1. `/v1/pair` (a `409` for a name in use), `/v1/node/<name>`, `/v1/connect/<name>`,
   `/v1/status/<name>` and `/v1/stop/<name>`, with the pair's tokens, in the program of T-169.
2. The text controls (`hello`, `open`, `close`, `ready`, `reject`), the 32-hex ids, the 15 s
   for a `ready`, frames of 65,568 bytes, a `409` for a second node, and the reverse close
   table, from the contract.
3. What the default deployment does not do: a bound of 1 MiB for a slow receiver, with
   `1011 relay backpressure` (T-336); a frame of an id closed in the last few seconds dropped,
   and `1003` kept for an id never given (T-421); `1012` to each socket before a planned stop
   (T-255).
4. Pairs kept in memory and, when the user names one, in a file of mode 0600, with the
   contract's expiry of 72 h.

## Decision

The role reuses the node's codecs (`crates/podssh-relay/src/reverse/wire.rs`) for the frames
that it reads and writes, so that the two sides cannot drift apart; the Python stand-in stays
the second reading of the contract, which podssh did not write in Rust.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair
cargo test -p podssh-cli --test node_live -- --ignored
```

The reverse road's offline tests run against the role as against the stand-in; on a GitHub
runner, `node_live` runs against `podssh relay serve` on the runner's loopback, and a client of
`v1.0.0` reaches a node through it. Planted: no bound for a slow receiver, and the test of
T-336 fails; no grace for a frame in flight, and the test of T-421 fails.

# T-428: The relay role behind a node's quick tunnel, with no listener

**Source:** the operator's ruling Q63 (2026-11-02), `docs/mesh.md`, section 4; the audit of
2026-11-02 (the quick tunnel's node is a server that needs no listener).
**Category:** feature
**Milestone:** M10
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

A host that can open no port cannot run `podssh relay serve` on a listener, yet many such hosts
reach Cloudflare's edge, where podssh's quick tunnel serves visitors. Such a host could be its
owner's relay.

## Premise

- The quick tunnel's node serves each visitor's WebSocket on the connection that podssh dialed,
  and "any other request gets 404 with no body, as podssh serves nothing else"
  (`crates/podssh-relay/src/quick/serve.rs:8`).
- A visitor's WebSocket passes the edge unchanged, so a client of the relay's contract reaches
  a quick tunnel's name as it reaches a relay host (T-300).

## Approach

1. A node with `--quick-tunnel --relay` routes the relay's paths (`/health`, `/v1/mint`,
   `/connect/<host>/<port>`, `/relays.json`, `/trace`, `/v1/...`) to the relay role of T-169
   and T-427, in place of the 404.
2. Its line on stdout names the relay host (`NAME.trycloudflare.com`), for `--relay-host`.
3. Its tokens are minted for the keys of its net (T-429), else for its owner's keys in an
   `--allow` file, and for anyone only when the user asks.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features quick
```

Offline, through the edge's stand-in of T-300: a client with `--relay-host` of the stand-in's
name carries GitHub's banner from a fixture through the node. In GitHub Actions
(`quick-tunnel-live.yml`, Q43): a client of `v1.0.0` reaches `github.com:22` through the node's
quick tunnel. Planted: the 404 kept, and the client fails.

# T-429: The net: an owner's signed list of its nodes, and their names

**Source:** the operator's ruling Q63 (2026-11-02): "full on tailscale-like parity";
`docs/mesh.md`, section 3.
**Category:** feature
**Milestone:** M10
**Priority:** P1
**Effort:** L
**Status:** open

## Problem

Each node of a user is set up alone: its pair, its `--allow` file, its tickets. Nothing says
which ends belong to one user, under which names, with which roles, so `podssh ssh NAME` cannot
find a node by name on each of its roads, and a removed device stays let in until each file is
edited by hand.

## Premise

- A node lets in the operator keys of its `--allow` file, read again for each session, on each
  road (`podssh node --help`); the end-to-end channel proves each end's Ed25519 key
  (`crates/podssh-relay/src/e2e/handshake.rs`).
- A node's record at a pkarr server names its iroh home relay
  (`crates/podssh-iroh/src/pkarr.rs:1`).

## Approach

1. The net's document: its name, a serial, an expiry, and its members, each with a name, an
   Ed25519 key, its roles (`node`, `exit`, `relay`, `share`) and its tickets; signed by the
   owner's key.
2. `podssh net init` (the owner's key, made by `podssh keygen` or named), `net add NAME KEY
   --roles ...`, `net rm NAME`, `net ls`, `net show`; each change signs a document with a
   higher serial.
3. Each member keeps the newest document that it was given, and takes one only with the
   owner's signature and a higher serial; two members that meet on any road give each other
   the newer one, inside the end-to-end channel.
4. A node's `--allow` defaults to the net's members that the policy lets in (T-430); a member
   removed from a newer document is refused.
5. `node://NAME` and `podssh ssh NAME` look the name up in the net first, then in the pairs
   and tickets kept under that name.

## Decision

The signature is OpenSSH's SSHSIG over the document's bytes, with the namespace `podssh-net`,
so that `ssh-keygen -Y verify` checks a document: software that podssh did not write. A JSON
document; no server of coordination, as Tailnet Lock's nodes trust the signing keys and not the
server.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test net
```

A document that `podssh net` signs verifies with OpenSSH's `ssh-keygen -Y verify`, and one
that `ssh-keygen -Y sign` signs is taken; an older serial, another key's signature and an
expired document are refused. Three ends on the stand-in relay: a member reaches a node by its
name; after `net rm`, the removed member is refused. Planted: the serial's check removed, and
the test of an older document fails.

# T-430: The net's policy: who may reach which node, share and exit

**Source:** the operator's ruling Q63 (2026-11-02): Tailscale's ACLs and grants;
`docs/mesh.md`, section 3.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

With a net (T-429), each member of the net could reach each node, each share and each exit. A
user needs to say who may reach what, as Tailscale's ACLs do, and a relay must not be the one
that decides.

## Premise

- The node is the end that decides today: it gives its verdict on the operator's key before it
  dials (`docs/reverse.md`, "The end-to-end channel").
- Routes name several services of one node (`podssh node NAME TARGET [ROUTE=TARGET]...`).

## Approach

1. Rules in the net's document: from a member or a tag, to a node, a route (share), an exit or
   a range of routes (T-432), allowed; nothing else when a rule list is present.
2. With no rule, each member reaches each other, as Tailscale's default policy.
3. Checked at the node that is reached, for each session, with the newest document it holds.
4. `podssh net policy check FROM TO` says what a rule list allows, with no connection.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test net
```

On the stand-in relay with three members: an allowed route is reached; a route that no rule
names is refused, with the rule's words; a newer document that removes a rule is in force at
the next session. Planted: the node that skips the check, and the refusal test fails.

# T-431: Exit mode: a node's egress for its owner's forward road

**Source:** the operator's ruling Q63 (2026-11-02): "exit mode"; `docs/mesh.md`, section 5.
**Category:** feature
**Milestone:** M10
**Priority:** P1
**Effort:** L
**Status:** open

## Problem

A user whose host reaches nothing but HTTPS may own another host that reaches the internet. The
forward road starts at the relay or at the client, never at that host, so the user cannot take
its egress, as a Tailscale exit node gives its own.

## Premise

- A node dials only its TARGET and its routes (`docs/reverse.md:16`, rule 4: "the node dials
  TARGET after the layer's handshake").
- `podssh ssh -D` serves SOCKS on a local listener that the user asks for (Q1).

## Approach

1. `podssh node NAME --exit`: an operator of the net that the policy lets in (T-430) names a
   target in the channel, and the node dials it: a public address, checked after the name
   resolves, as the relay checks it; private ranges only within `--routes` (T-432).
2. `--exit NAME` on `podssh ssh`, `proxy`, `cp` and `pipe`: the forward road starts at the
   node, on each road between the two ends.
3. `podssh exit NAME --listen ADDR`: a local SOCKS5 and HTTP CONNECT proxy for other programs,
   when the user asks for its listener and the probe allows the bind (Q1).
4. `doctor` names the exit and the road that reached it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test exit
```

Offline: a node with `--exit` on the stand-in relay carries a forward session to a test server
named by the operator; a private address is refused unless a route allows it. In GitHub
Actions: a node on the runner with `--exit`, and `podssh ssh --exit NAME git@github.com` reaches
GitHub's banner; `curl --proxy socks5h://...` through `podssh exit --listen` fetches a page.
Planted: the check of a public address removed, and the private target's test fails.

# T-432: Routes: a node reaches its private networks for the net

**Source:** the operator's ruling Q63 (2026-11-02): Tailscale's subnet routers;
`docs/mesh.md`, section 5.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

An exit node (T-431) reaches public addresses only. A user's node inside a private network
(a lab, a cluster) cannot give the net its other hosts, as a Tailscale subnet router gives its
routes.

## Premise

- An exit's targets are public addresses, checked after the name resolves (T-431).

## Approach

1. `podssh node NAME --routes CIDR,...`: the exit dials a private address inside one of the
   ranges, checked after the name resolves, for the members that the policy lets in (T-430).
2. The net's document lists each node's routes, so that `podssh ssh 10.1.2.3` with
   `--exit auto` finds the node that routes it.
3. Loopback and the node's own addresses stay refused unless named whole.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test exit
```

A test server on a private address of a container network is reached through a node with that
range; an address outside it is refused, and so is a name that resolves into a range that no
route names. Planted: the range's check removed, and the test fails.

# T-433: `podssh share`: a node's local services by name, for the net

**Source:** the operator's ruling Q63 (2026-11-02): "serve" (Tailscale's serve);
`docs/mesh.md`, section 5.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A node's routes are fixed at its start, on its command line, and an operator must know their
names. Tailscale's serve adds and removes a shared service while the node runs, and lists it.

## Premise

- Routes name several services of one node (`podssh node NAME TARGET [ROUTE=TARGET]...`), and
  the node reads its `--allow` file again for each session, a pattern that needs no control
  socket.
- `podssh serve` is M5's command (the server in the cage, T-248), so Tailscale's serve takes
  another word here.

## Approach

1. A node reads its share file (`--shares FILE`, default beside its key) again for each
   session: `NAME=TARGET` lines.
2. `podssh share add NAME=TARGET`, `share rm NAME`, `share ls`, which edit that file for a node
   of this host, under its lock.
3. The net's document lists each node's shares (T-429), so `podssh share ls --net` shows them,
   and an operator reaches one as `node://NODE/NAME`, within the policy (T-430).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test share
```

A share added while the node runs is reached at the next session, with no restart; a removed
one is refused; `share ls` lists what the node serves. Planted: the file read once at the
start, and the test of an added share fails.

# T-434: A member that relays between two other members

**Source:** the operator's ruling Q63 (2026-11-02); Tailscale's peer relays;
`docs/mesh.md`, section 4.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Two ends of a net that reach no common road (no UDP for iroh, a proxy that refuses the public
relays) have no way to meet, even when a third member that both reach could carry them.

## Premise

- `podssh ssh node://` races the iroh road, the pair's road and the DERP road, and each resume
  races them again (`crates/podssh-cli/src/ssh/roads.rs:1`).
- A member with the relay role serves the relay's pairs (T-169, T-427, T-428).

## Approach

1. A node registers its pair on each member of its net with the relay role, at most three, as
   it registers on the default relay.
2. A client races the pair's road through each of them with the other roads.
3. The end-to-end channel and the resumable layer stay above, so that the member that relays
   sees only bytes it cannot read.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test net
```

Three ends offline, the default relay's stand-in refused to two of them: the session goes
through the third member's relay role, and moves to another road when that one is killed.
Planted: no registration on member relays, and the session fails.

# T-435: `status`, `ping` and `doctor` for the net

**Source:** the operator's ruling Q63 (2026-11-02): Tailscale's `status`, `ping` and
`netcheck`; `docs/mesh.md`, section 1.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A user of a net needs to see its members, which road reaches each, and what this host can
reach, as `tailscale status`, `ping` and `netcheck` show.

## Premise

- `podssh status`, `podssh ping` and `podssh doctor` exist for the relay and the roads of one
  destination.

## Approach

1. `podssh status --net`: each member, its roles, the newest document's serial, and the road
   that last reached it.
2. `podssh ping NAME`: the roads raced to a member, each with its time, and the one that won.
3. `doctor`: the net's member relays (T-434) and the carriers of Q65 that this host reaches.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test net
```

Against three ends offline: the status lists each member and its road; `ping` names the road
that answered first; a member that is stopped shows as not reached. Planted: a road's time not
measured, and the test fails.

# T-436: The magic-wormhole transit relay as a carrier of a pair's road

**Source:** the operator's ruling Q65 (2026-11-02); the research of 2026-11-02 (public
carriers).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A node and its operator have no public carrier with no account that pairs two ends on port 443
other than the iroh relays and DERP, which some proxies refuse by category.

## Premise

- Read on 2026-11-02: the transit relay's protocol is a line, "please relay TOKEN for side
  SIDE" (TOKEN of 64 hex digits, SIDE of 16), answered `ok` to both sides once two sides meet,
  then the bytes copied each way, over TCP or a WebSocket.
- Read and measured on 2026-11-02: Least Authority's server answers on port 443 with a WebSocket
  (`wss://relay.mw.leastauthority.com`), and its terms let other applications use it.

## Approach

1. Both ends derive TOKEN from the pair's secret and take a random SIDE.
2. The carrier opens the WebSocket, sends the line, waits for `ok`, and carries the resumable
   layer and the end-to-end channel above it.
3. In the race after the DERP road; tried unasked (Q65), and `PODSSH_TRANSIT=no` turns it off.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test transit
```

Against magic-wormhole's own transit relay server (Python) on the loopback: two ends meet, and
a session carries 1 MiB each way and survives the carrier's loss by moving to another road.
Live, short (Q65): one session through Least Authority's server from GitHub Actions. Planted:
the wrong side's line, and the meeting fails.

# T-437: Piping Server, a road for a proxy that refuses the WebSocket upgrade

**Source:** the operator's ruling Q65 (2026-11-02); the research of 2026-11-02 (public
carriers).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A proxy that refuses the WebSocket upgrade leaves podssh with no public road with no account
(GitHub #55), as each relay, each forwarder and each public carrier uses the upgrade.

## Premise

- Read on 2026-11-02: Piping Server streams a `POST /path` into a `GET /path`, over plain HTTPS;
  `ppng.io` answers on 443 and offers HTTP/2.

## Approach

1. Two paths derived from the pair's secret, one each way; each end streams its POST and reads
   its GET, over HTTP/2 on one connection where the proxy passes it.
2. Numbered POSTs, one after another, where a proxy buffers a streamed body.
3. The resumable layer and the end-to-end channel above; tried unasked (Q65) when the probe
   finds the upgrade refused; `PODSSH_PIPING` names another server or `no`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test piping
```

Against nwtgck's `piping-server` and `piping-server-rust` in containers: a session carries
1 MiB each way, through the box's proxy that refuses the upgrade. Live, short (Q65): one
session through `ppng.io`. Planted: the paths swapped, and the session fails.

# T-438: Wisp: the demo server as a forwarder, and the Wisp protocol

**Source:** the operator's ruling Q65 (2026-11-02); the research of 2026-11-02 (public
carriers).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

The forward road's public forwarders are three (Q56), each one WebSocket for each session. Wisp
is a published protocol that carries many TCP streams over one WebSocket, with flow control and
close reasons, and its demo server takes the destination from the client.

## Premise

- Read on 2026-11-02: Wisp's protocol, version 2 (CONNECT, DATA, CONTINUE and CLOSE packets),
  and the demo server `wss://wisp.mercurywork.shop/`, "primarily for demo and testing", 500 kB/s
  for each address.
- The forwarders are words of `podssh_cli::forwarder` (`crates/podssh-cli/src/forwarder/mod.rs`).

## Approach

1. A Wisp client in `podssh-ws`: streams over one WebSocket, with CONTINUE's credit.
2. The word `wisp` for the demo server, tried after the three of Q56 when each relay host fails.
3. `--forwarder wisp+wss://HOST/` for a Wisp server that the user runs.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test wisp
```

Against the reference server (`wisp-server-python`) on the loopback: two streams at once on one
WebSocket, each with its bytes; a stream that the server closes gives its reason. Live, short
(Q65), from GitHub Actions: GitHub's banner through the demo server. Planted: the credit
ignored, and the test of flow control fails.

# T-439: HTTP CONNECT to a second proxy over TLS, HTTP/1.1 and HTTP/2

**Source:** the operator's ruling Q66 (2026-11-02); the research of 2026-11-02 (standard
protocols).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A user who runs a standard forward proxy over TLS (Caddy with forwardproxy, squid, h2o) cannot
use it as podssh's road: podssh speaks CONNECT and SOCKS5 to the host's own proxy only.

## Premise

- podssh's proxy kinds are HTTP CONNECT and SOCKS5 (`crates/podssh-ws/src/proxy.rs:9`), in
  cleartext to the proxy.

## Approach

1. `--via https://HOST[:PORT]` (and `PODSSH_VIA`): TLS to that proxy, through `HTTPS_PROXY`
   first when it is set, then CONNECT inside; credentials from a file of mode 0600.
2. HTTP/2's CONNECT (RFC 9113, section 8.5), several sessions on one TLS connection, where the
   proxy offers `h2`; HTTP/1.1 otherwise.
3. `doctor` names the second proxy and the version that it spoke.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test via
```

Against Caddy with forwardproxy and squid over TLS in containers, through the box's proxy:
GitHub's banner from a fixture through each, and two sessions on one HTTP/2 connection with
Caddy. Planted: the credential left out, and the `407` is said with its words.

# T-440: VLESS over a WebSocket and over XHTTP

**Source:** the operator's ruling Q66 (2026-11-02); the research of 2026-11-02 (standard
protocols).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

The largest base of servers that take the destination from their client, and that users run
on their own hosts and serverless accounts, speaks VLESS; its XHTTP transport carries a session
over plain HTTP requests where a proxy refuses the WebSocket upgrade (GitHub #55).

## Premise

- Read on 2026-11-02: VLESS's request (a version, a UUID, its add-ons, a command, a port and an
  address), its transports over a WebSocket and XHTTP (`packet-up`: numbered POSTs and one
  streamed GET; `stream-one`: one request on HTTP/2), in Xray-core's source.

## Approach

1. A VLESS client in `podssh-ws`, its UUID read from a file of mode 0600, as
   `--shadowsocks FILE` reads its key.
2. Its transports: a WebSocket, then XHTTP `stream-one` on HTTP/2, then `packet-up`.
3. `--vless FILE` with the server's URL in the file; `doctor` names the transport that passed.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test vless
```

Against Xray-core and shoes in containers: GitHub's banner from a fixture over each transport,
and `packet-up` through the box's proxy that refuses the upgrade. Planted: a wrong UUID, and
the server's refusal is said.

# T-441: wstunnel's protocol

**Source:** the operator's ruling Q66 (2026-11-02); the research of 2026-11-02 (standard
protocols).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

wstunnel is one static binary that a user can run as a server in one command, and that takes
the destination from its client; podssh cannot use it.

## Premise

- Read on 2026-11-02: wstunnel's client puts the destination and its token in the upgrade
  request, and its format changed between major versions in 2024.

## Approach

1. A client of wstunnel's current major version, from its source, with the version pinned in a
   test; `--wstunnel URL` with its secret in a file of mode 0600.
2. A server of another major version is refused with the version's words.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test wstunnel
```

Against wstunnel's own server binary of the pinned version in a container: GitHub's banner from
a fixture. Planted: the wrong secret, and the refusal is said.

# T-442: More public services and standard protocols that fit

**Source:** the operator's rulings Q65 and Q66 (2026-11-02): "any other ones that fit our
needs", "any other, as part of the new expansion".
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

The research of 2026-11-02 named more candidates than the first entries take: each one that
fits podssh's needs and its terms is a road.

## Premise

- Read on 2026-11-02 (`docs/carriers.md`): ntfy.sh and Least Authority's mailbox for pairing,
  Syncthing's public relays on port 443, upterm's community server, Yggdrasil's peers on 443;
  and the protocols chisel, Trojan, IETF's connect-tcp and Hysteria 2.

## Approach

1. For each: its terms, its limits, whether it passes an HTTPS-only proxy, a server to test
   against, and the size of podssh's side.
2. Each that fits: an entry, and its row in `docs/carriers.md`; each that does not: its reason
   in `docs/carriers.md`.

## Prove

The entries filed and the rows written; `cargo todo check` passes.

# T-443: The resumable layer's window on the pair's road is above the relay's bound

**Source:** the audit of 2026-11-02 (what podssh can do without the relay's operator).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

A layered session through the pair's road sends up to its window with no acknowledgement. The
relay's contract bounds what it holds for a slow receiver at 1 MiB, so a relay that enforces
its bound (podssh's own, T-427, or the default once it does) cuts a layered session whose
operator reads slowly, with a frame dropped, again and again.

## Premise

- `crates/podssh-relay/src/session/replay.rs:15` says "the relay holds at most 1 MiB for a
  slow", and the capacity is 4 MiB (`crates/podssh-relay/src/session/replay.rs:18`).
- A node queues twice the layer's window (`crates/podssh-relay/src/reverse/layered.rs:93`).
- The contract: `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`.

## Approach

On the pair's road, the bytes in flight stay under the relay's bound (a window below 1 MiB),
while the replay capacity stays 4 MiB for a resume; the other roads keep their window.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair
```

Against the stand-in in a strict mode that sends `1011 relay backpressure` at 1 MiB queued: a
session whose operator reads slowly finishes with no 1011. Planted: the window of 4 MiB, and
the test meets 1011.

# T-444: One TLS configuration for each trust in a process, so that TLS resumes

**Source:** the audit of 2026-11-02 (what podssh can do without the relay's operator).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

Each TLS connection of a run builds its own configuration, and rustls keeps its cache of
sessions in the configuration, so no connection of a run resumes TLS: `podssh each`, the
staggered failover, `cp --parallel` and each move of the layer pay a full handshake, and a CA
file is read again each time.

## Premise

- `config_for` builds a configuration for each call (`crates/podssh-ws/src/tls.rs:124`).

## Approach

A configuration kept for each trust in the process, made once; a CA file read once.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws
```

Two connections of one process to a rustls server on the loopback: the second resumes (the
server says so). Planted: a new configuration each time, and the test fails.

# T-445: A node's record names each of its roads

**Source:** the research of 2026-11-02 (pairing and the reverse road); the operator's ruling
Q63 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

A node's record at the pkarr server names its iroh home relay alone, so a client with the
node's key and no ticket finds the iroh road and no other: its DERP home and its quick tunnel's
name stay unknown.

## Premise

- `crates/podssh-iroh/src/pkarr.rs:1` says "A node's record at a server of pkarr (T-350): its
  home relay, signed with".

## Approach

The record also names the node's DERP home and its quick tunnel's name, as records that iroh's
tools ignore; a client races each road that it names.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh
```

A record with each road is read back whole; a client with the node's key alone reaches it over
DERP when iroh is refused. Planted: the DERP record dropped, and the test fails.

# T-446: The release of milestone M10: betas `v1.1.0-beta.N`, then `v1.1.0`

**Source:** the operator's ruling of 2026-11-02 ("`v1.0.0` now, and the expansion after it").
**Category:** release
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The expansion of Q63 needs releases that the testers can test while it grows, and a release
that closes it.

## Premise

- Betas and their rules: T-309; the check from end to end: T-251.

## Approach

1. Betas `v1.1.0-beta.N` from `main`, by the rules of T-309, each after a batch of M10's
   entries.
2. `v1.1.0` once each entry of M10 is done, checked as `v1.0.0` was (T-251), with M10's rows
   in the release check.

## Decision

The version is `1.1.0`: the expansion adds commands and roads and breaks none of `1.0.0`.

## Prove

```sh
sh scripts/release-check.sh v1.1.0
```

The release check passes on the published files, with M10's rows.
