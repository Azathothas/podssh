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
**Status:** partial

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

## Decision

- **A road in place of the relay, as `--shadowsocks` is.** `--via` takes the relay's place for
  `ssh`, each command of its road, `proxy`, `pipe` (`tcp:`, and `ssh:` through the resolver) and
  `doctor`; beside `--relay-host`, `--relay-failover`, `--forwarder`, `--shadowsocks`,
  `--direct`, `-4`, `-6` or a road of its own it is refused (64). Lost: a second proxy as a third
  kind of `ProxyKind` for the host's proxy (a chain), which would change the cleartext path that
  the brief keeps, and send the relay's WebSocket through it where Q66 asks for a road with no
  relay.
- **Credentials from a file, its one line `USER:PASSWORD`, or the password alone when the URL
  names the user** (`--via-auth-file`, `PODSSH_VIA_AUTH_FILE`), read as `--shadowsocks` reads
  its file (`podssh_relay::cache::read_private`). A URL with a password is refused, and a URL
  with a user and no file too: an empty password sent silently would be a 407 with no cause.
  Lost: the password in the URL (argv, `ps`), and a prompt (no terminal under `ProxyCommand`).
- **`PODSSH_VIA`** names the road where the command line names no other, as `PODSSH_FORWARDER`
  does, and is refused beside `PODSSH_RELAY` (78). `pipe`'s `tcp:` takes the flag alone: it is
  TCP from this host, which the variable of a road in place of the relay does not reach.
- **HTTP/2 kept for the process.** A client for each second proxy (`podssh_cli::via::client`)
  keeps HTTP/2's connection while it lasts, and dials one connection at a time, so that the
  sessions of `podssh each`, which start together, share it. Lost: a connection for each tunnel,
  which loses the sharing that the Approach asks for.
- **A fallback, as rule 7 asks:** a proxy that chose `h2` and reset the CONNECT for a reason other
  than `CONNECT_ERROR` (the proxy's word that the target failed) gets HTTP/1.1 on a connection
  of its own, and `-v` says why. `PODSSH_VIA_HTTP=1.1` or `2` offers one version alone, for a
  proxy whose HTTP/2 misbehaves in another way, and for the run of Caddy over HTTP/1.1.
- **The words of a `407`** are the host's proxy's (T-320, `proxy_auth::schemes`), with the flag
  of the file in place of the URL's credentials; on HTTP/2 the head is rebuilt from the answer's
  `Proxy-Authenticate` fields. `Proxy-Authorization` is sensitive on HTTP/2, so HPACK never
  indexes it.
- **The test against Caddy and squid is a harness of its own** (`scripts/interop-via.sh`, with
  `.github/workflows/via-interop.yml`): Docker or Podman on a runner, Caddy built from
  forwardproxy's commit 0aab84dad4fc (2026-03-21) in the Go image that `images/derper` pins, squid
  from Alpine's packages, OpenSSH's sshd as the target (in place of a fixture of GitHub's banner:
  the brief allows either), and a plain squid as the host's proxy in place of the box's. The
  gate's build image has no Caddy with the plugin, so a test of the crate cannot run it.

## Done

2026-11-02, partial: drafted in a worktree; nothing was built or run here (a drafting agent does
not build). Each result below is UNVERIFIED until the session that merges it runs it.

- podssh-ws, `crates/podssh-ws/src/via/`: the URL and its credentials, the versions offered, the
  client that keeps HTTP/2's connection and falls back to HTTP/1.1, and the words of a refusal
  (`mod.rs`); HTTP/1.1's CONNECT with its head read a byte at a time (`http1.rs`); HTTP/2's
  CONNECT and its stream as `AsyncRead` and `AsyncWrite` (`http2.rs`); unit tests (`tests.rs`).
  `crate::proxy::percent_decode` is `pub(crate)` for the URL's user; the host's proxy's path is
  otherwise unchanged. UNVERIFIED: `cargo test -p podssh-ws --lib via`, and the crate with
  `CC=/nonexistent CXX=/nonexistent`.
- `cargo test -p podssh-ws --test via`, 5 tests against stand-ins on the loopback, HTTP/2 by h2's
  own server: the credential with each CONNECT on both versions and the `407` with its words
  without it; two tunnels as two streams of one TLS connection; the host's proxy carrying the TLS
  by the second proxy's name; a reset on HTTP/2 that falls back to HTTP/1.1, and HTTP/2 alone
  refused by a proxy of HTTP/1.1; a 403, an unreachable target (502) and a certificate of another
  name. UNVERIFIED.
- podssh-cli, `crates/podssh-cli/src/via/`: the choice of the road and its refusals (`mod.rs`,
  with `tests.rs`), the road of `ssh` (`reach.rs`) and of `proxy` and `pipe`'s `tcp:`
  (`pipe.rs`); `Transport::Via` in the resolver; the section `via` of `doctor`
  (`crates/podssh-cli/src/doctor/via.rs`); the rows of `--via` and `--via-auth-file` in each table
  of `--shadowsocks` and in `pipe`'s (`crates/podssh-cli/src/flags/via.rs`); the manual (notes of
  `ssh`, `proxy`, `pipe` and `doctor`, a row of FILES, three variables) and `docs/cli.md` (a
  section), `docs/architecture.md` (the road). UNVERIFIED: `cargo test -p podssh-cli --lib`,
  `--test man_page`, `--test flag_table`, `--test proxy`, `--test man_flag_parity`, clippy, and
  `cargo todo remap` of the edited files that entries cite (`docs/architecture.md`,
  `crates/podssh-cli/src/flags.rs`, `crates/podssh-cli/src/ssh/resolve.rs`,
  `crates/podssh-cli/src/ssh/transport.rs`, `crates/podssh-cli/src/proxy.rs`,
  `crates/podssh-cli/src/dispatch.rs`, `crates/podssh-cli/src/tree.rs`,
  `crates/podssh-cli/src/doctor/mod.rs`, `crates/podssh-cli/src/man/notes.rs`,
  `crates/podssh-cli/src/man/notes_ssh.rs`).
- Against Caddy with forwardproxy and squid over TLS: `scripts/interop-via.sh`, 12 ids in
  `scripts/interop-baseline.txt`, run by `.github/workflows/via-interop.yml`: the banner and a
  session through each, HTTP/2 with Caddy and HTTP/1.1 with squid and with Caddy at
  `PODSSH_VIA_HTTP=1.1`; two sessions of `podssh each` on one HTTP/2 connection with Caddy; both
  proxies through a plain squid as the host's proxy; each `407` said with its words when the
  credential is left out; `doctor --via`; no output that holds the password. UNVERIFIED: not run;
  `dash -n` and shellcheck not run on the script either.
- Planted (`scripts/plants/t439-via-no-credential.plant`): the credential left out of each
  CONNECT; the test of the credential must fail with the stand-in's `407` in its words.
  UNVERIFIED; `git apply --check` of its patch passed here.

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
**Status:** done

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

## Decision

The draft's calls, 2026-11-02:

1. Where the window is held: the writer of each link
   (`crates/podssh-relay/src/session/pump/up.rs`) reads the application's bytes only while the
   replay buffer has room, and now also while the bytes not acknowledged are fewer than the
   link's window (`Link::room_within`). In flight is what the peer has not acknowledged, and an
   acknowledgement covers what the peer's application took (T-387), so what the relay holds for
   that receiver is at most the window.
2. The window belongs to the link, not to the session: the pump's `Watch` takes it from the
   settings of the link's own road (`Settings::window`, set by `on_the_pair`). A node's far end
   that shares one keeper between roads (T-164) then gives a session that iroh opened the pair's
   window on its links of the pair's road, and none on iroh's. Lost: a window kept in the
   session's `Link`, which a session resumed onto another road would carry wrongly; and a
   replay capacity under 1 MiB on the pair's road, which a resume onto another road and the
   node's budget need at 4 MiB.
3. The value, 768 KiB (`PAIR_WINDOW`): a quarter of the relay's 1 MiB stays free for the
   records' headers (13 bytes for each read of 32 KiB), the frames, and the `ACK` and `PING`
   records. Lost: 512 KiB, SSH's window, which would halve a raw stream's rate on a long round
   trip (`podssh operator`, `podssh pipe`) for no gain under the bound; a margin computed from
   the frames' sizes, which a change of a chunk would break.
4. The default of `podssh_cli::layered::settings()` is the pair's road; each other road takes
   `off_the_pair()`: the iroh and DERP roads, the quick tunnel's node and its client. A road
   that forgets it costs speed, never the bound. Lost: no window by default, with the pair's
   road taking one, where a forgotten call site would pass the bound.
5. The records that a resume sends again wait for the window of their link too
   (`Link::again_fits`): a buffer filled on a road with no window holds up to 16 MiB. A record
   with nothing in flight before it always goes, so a link always moves.
6. `podssh ssh node://` with more roads (T-164, T-379): the client has one set of settings for
   the session, and each resume races the roads again, so while the pair's road is in its race
   each link keeps the pair's window, iroh's and DERP's too. Lost: a window by link on the
   client, which needs the road of each link in `resume::run`, generic over its link.
7. What the window does not bound: the relay's queue for a node's socket carries each session
   of the node, 64 at most, so it can hold more than one window. That queue is the relay's to
   bound, by reading a sender only while its receiver's queue has room, as T-427 and T-336
   plan for podssh's relay role. The node's own queue (`Layered::queue_bytes`, twice the
   buffer) stays: it bounds what the node takes for a slow local side, above the window, and a
   client of another version can still send its whole buffer.
8. The tests: sans-IO checks of the window; a stand-in of the bound in podssh-relay's own test,
   which counts its queues with no socket of the network; and the stand-in relay's mode
   `strict:RATE` (`scripts/fake_reverse.py`), which closes with `1011 relay backpressure` as
   the contract says, against the binary. Its test runs `podssh operator --no-e2e`: SSH's own
   window (512 KiB) and the channel would bound what waits before the layer's window does.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair
cargo test -p podssh-cli --test node_window
```

Against the stand-in in a strict mode that sends `1011 relay backpressure` at 1 MiB queued: a
session whose operator reads slowly finishes with no 1011. Planted: the window of 4 MiB, and
the test meets 1011.

## Done

2026-11-02: drafted by an agent in a worktree of its own, and merged, built and measured here.

- podssh-relay: `PAIR_WINDOW`, 768 KiB (`crates/podssh-relay/src/session/replay.rs`), under the
  contract's 1 MiB for a slow receiver; the replay buffer stays 4 MiB for a resume. Each link
  takes its window from its road's settings (`on_the_pair` and `off_the_pair` in
  `crates/podssh-relay/src/session/mod.rs`); the writer, now in
  `crates/podssh-relay/src/session/pump/up.rs`, waits for the window, and each record that a
  resume sends again waits for it too. The iroh road, DERP and the quick tunnel keep the buffer's
  window; `podssh ssh node://` keeps the pair's while the pair's road is in its race.
- The stand-in relay: the mode `strict:RATE` of `scripts/fake_reverse.py`, the contract's bound:
  a frame that would put more than 1 MiB in a receiver's queue is dropped and the socket gets
  `1011 relay backpressure`. Its first draft ended a connection before its queue had gone out,
  so a Close that waited behind paced frames was lost and the operator saw "no Close" (exit 69);
  `settled()` now lets what waits go out before the handler returns.
- `cargo test -p podssh-relay --test session_window`: 4 passed. `cargo test -p podssh-relay
  --features pair --test reverse_window`: 1 passed (8 MiB each way, each queue at most 1 MiB),
  and 150 runs passed, 120 of them four at once. `cargo test -p podssh-cli --test node_window`:
  2 passed (6 MB to a slow operator with `--no-e2e`, exit 0, each byte, no `relay
  backpressure`).
- Planted, `PAIR_WINDOW` at `4 << 20`: `session_window` 2 of 4 failed, `reverse_window` failed,
  and `node_window` found `1011 relay backpressure` in the stand-in's log (1,080,898 bytes would
  have waited).
- `cargo test -p podssh-relay --features pair,quick,derp,serve` whole: 10 runs passed; one run
  before them counted a failed test that its quiet output did not name (T-449). The CLI's tests
  of the layered roads (`node`, `node_restart`, `m6_exit`, `derp_road`, `node_copy`, `attach`,
  `direct_fallback`) passed. Clippy and `cargo fmt --check`: clean.
- Not measured: the reverse cell of the throughput run on the live relay with the window; it
  runs with the release check of M10 (T-446).

# T-444: One TLS configuration for each trust in a process, so that TLS resumes

**Source:** the audit of 2026-11-02 (what podssh can do without the relay's operator).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Each TLS connection of a run builds its own configuration, and rustls keeps its cache of
sessions in the configuration, so no connection of a run resumes TLS: `podssh each`, the
staggered failover, `cp --parallel` and each move of the layer pay a full handshake, and a CA
file is read again each time.

## Premise

- `config_for` builds a configuration for each call (`crates/podssh-ws/src/tls.rs:124`).

## Approach

A configuration kept for each trust in the process, made once; a CA file read once.

## Decision

The draft's calls, 2026-11-02:

1. Where: behind `config_for` in `crates/podssh-ws/src/tls.rs`, a cache of the process
   (`crates/podssh-ws/src/tls/kept.rs`) keyed by the trust: the default one, and each CA file
   by its path. Each road that reaches TLS through `config_for` (the relay's connection, the
   HTTPS requests, DNS over HTTPS, `chat --irc`, the hops of `ssh+tls://`, Tor's transports)
   resumes with no change of its own. A caller's own configuration (`Trust::caller`) is already
   one `Arc` with its own cache, and passes as it is. Lost: a cache that each caller holds and
   passes down (the pool, `each`, `cp`), which the roads that call `config_for` deep inside
   would miss.
2. Nothing that varies by connection is in the shared configuration: the server's name goes
   with each connection; ALPN is set on a clone (`resolve::h2::config_h2`), and a clone shares
   the cache of sessions, as rustls keeps its store in an `Arc`, so DNS over HTTPS/2 resumes
   too; podssh writes no key log and offers no early data. The configurations that are not a
   trust's (the quick tunnel's edge with cloudflared's roots, WARP's with its client
   certificate, iroh's) are built apart, as before, and are not changed.
3. The key keeps trusts apart: a resumed handshake checks no certificate, so a session that one
   trust verified is never resumed under another, even one that holds the same roots.
4. A CA file is read again when its time or its length changed, so a node that runs for days
   takes a new CA of its proxy with no restart, and one that cannot be read fails as before.
   Lost: read once for the process, as the Approach says, which would keep an old CA until a
   restart; read for each connection, which is the defect.
5. Sixteen trusts at most, the oldest first out: a run names one or two, and a process given
   many CA files must not grow without a bound.
6. What a resumption shows: the server can link the connections of one run, which it can
   already by their address; and `podssh health` times a handshake that may be a resumed one
   after the first of a run.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws
cargo test -p podssh-ws --test tls_resume
```

Two connections of one process to a rustls server on the loopback: the second resumes (the
server says so). Planted: a new configuration each time, and the test fails.

## Done

2026-11-02: drafted by an agent in a worktree of its own, and merged, built and measured here.

- `config_for` (`crates/podssh-ws/src/tls.rs`) takes each trust's configuration from
  `crates/podssh-ws/src/tls/kept.rs`: made once, kept by the trust, and made again when a CA
  file's time or length changed, so that a long-running node takes a new CA; a failure is not
  kept.
- `cargo test -p podssh-ws --test tls_resume`: 3 passed against rustls's own server on the
  loopback: the second connection of a trust is `Resumed`, the first `Full`; another trust,
  even with the same root, resumes nothing of the first's.
- Planted, a configuration made for each call: the test failed with `[Full, Full]` for `[Full,
  Resumed]` (2 of 3 failed).
- `cargo test -p podssh-ws` whole passed; clippy and `cargo fmt --check`: clean.
- Not measured: the handshakes of a run against the live relay (`podssh each`, the staggered
  failover); it runs with the release check of M10 (T-446).

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

# T-447: `podssh relay serve` takes its certificate from ACME, and reads it again on SIGHUP

**Source:** the Correction of T-169 (2026-11-02), its Approach item 1, which T-169's first cut
left out.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A user who runs `podssh relay serve` on a host of their own needs a certificate that each client
trusts with no `--ca-file`. Today the role takes one from files alone, and keeps the one that it
read at its start, so a renewed certificate needs a restart, which ends each token and session.

## Premise

- The role reads `--cert` and `--key` once (`crates/podssh-cli/src/relay_serve.rs`), and serves
  one certificate for each client (`crates/podssh-ws/src/tls_server.rs`).

## Approach

1. SIGHUP reads `--cert` and `--key` again, and the next handshakes take them; a pair that does
   not load is said, and the old one stays.
2. `--acme NAME`: a certificate for NAME from Let's Encrypt by TLS-ALPN-01 on the role's own
   port, with a P-256 key that the role makes, kept in a private directory and renewed 30 days
   before its end; the ACME client in the binary crate, which links aws-lc already (rule 4 of
   `AGENTS.md` keeps C out of the library crates).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
```

A certificate replaced on disk and SIGHUP: the next client sees the new one, and a session that
was open goes on. ACME against Pebble, Let's Encrypt's test server, in a container: a client
that trusts Pebble's root reaches the role. Planted: no reload, and the test of the new
certificate fails.

# T-448: The relay role mints tokens for the keys of an allowlist or of the net

**Source:** the Correction of T-169 (2026-11-02), its Approach item 2, which T-169's first cut
left out.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`podssh relay serve` mints a token for anyone (`--mint anyone`) or for no one, so a relay that
its owner keeps for their own ends must be open to anyone who finds it, or its tokens must be
given out of band.

## Premise

- `/v1/mint` takes the contract's body `{}` and gives `{token, expires, scope}`
  (`docs/relay.md`, "Tokens"); the role's mint is `crates/podssh-relay/src/serve/mod.rs`.
- Each podssh end has an Ed25519 key (`podssh node --key`, the end-to-end channel).

## Approach

1. `--mint keys:FILE`: a key of the allowlist file (the format of `podssh node --allow`), or a
   member of the net (T-429), proves itself by signing the relay's challenge; then the role
   mints, and any other request gets `403`.
2. The client signs a mint when the relay's `/health` says that it wants one, with its own
   key, and caches the token as for the default relay.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
```

A client whose key is on the list gets a token and a session; another key gets `403`, and a
replayed signature is refused. Planted: the signature's check skipped, and the test of the other
key fails.

# T-449: A test of the podssh-relay suite failed once in 11 runs, unnamed

**Source:** the merge of T-443 and T-444 (2026-11-02).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

One run of `cargo test -p podssh-relay --features pair,quick,derp,serve` on 2026-11-02 counted
three lines of a failure (a test's `FAILED` and its panic) in its quiet output, which was counted
and not kept, so the test is not known. Ten runs after it passed, and 150 runs of the new
`reverse_window` (120 of them four at once) passed. A test that fails at random hides a defect,
or teaches the reader to rerun.

## Premise

- The run was the second of two in a row, at the merge of T-443 and T-444, with nothing else
  building or testing on the host.

## Approach

1. Run the suite in a loop with each log kept, here and on a GitHub runner (a workflow by hand,
   20 runs), and name the test.
2. Repair its cause, not its timing; a test that waits on time gets a condition instead.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,quick,derp,serve
```

The named test passes 50 runs in a row, here and on the runner, and its cause planted again
fails it.
