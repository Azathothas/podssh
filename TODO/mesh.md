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
**Status:** done

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

The draft's calls, 2026-11-02:

1. Where: `crates/podssh-relay/src/serve/reverse/` (the routes, the pairs, one writer for each
   socket, the node's socket, the operator's), behind the feature `serve`, which now brings
   `pair` for the codecs. Lost: a feature of its own, with which a role could serve half the
   contract.
2. The bound, toward an operator: what waits for its socket is counted, and a frame that would
   put more than 1 MiB in it is dropped; the operator gets `1011 relay backpressure` before what
   waits, and the node `close {id}` with that reason; the node's socket goes on. Toward the
   node, the role reads an operator's next frame only once the node's queue has room for it
   (1 MiB of bytes in all), so that queue never passes the bound and no session is cut for a
   slow node. Lost: `1011` on the node's socket, which would cut each of its sessions for one
   operator's bytes (T-443, its Decision 7); and reading the node only while each operator has
   room, where one slow operator would stall each other session of the node.
3. The grace (T-421): 2 s after the role forgets a session, for any reason (the operator's
   Close, its lost link, a `reject`, a `close`, the role's own ends), a frame or a `ready` of
   the node for it is dropped, and said once on stdout (`reverse in flight`); after it, or for
   an id never given, `1003 unknown session id`. Lost: the grace for a lost link alone, as the
   stand-in keeps it: an operator's clean Close crosses the node's frames too (T-388).
4. The tokens: 64 characters of `[0-9a-z]` from the system's randomness, kept as their
   SHA-256 and compared in constant time; `--pairs FILE` holds the digests, written through a
   private temporary file and a rename, and read back only when it is private. Lost: tokens as
   MACs under the run's secret, which a restart would end, as the file is there to prevent; and
   the tokens in the file, whose copy would be each credential.
5. Who may make a pair: whom the role mints for (`--mint`): anyone, or no one (`503`); T-448
   adds the keys of a list. Lost: pairs for anyone always, so that a role that mints for no one
   would still keep the pairs of strangers.
6. Liveness: the role pings each reverse socket every 20 s and drops one that answers nothing
   for 3 intervals. The default relay sends no keepalive but answers a Ping; without one, a
   node whose connection died with no FIN would hold its name, and the node that comes back
   would meet `409` for as long. Lost: an idle cut, which the contract does not have (T-061).
7. A planned stop: Ctrl-C or SIGTERM sends `1012 relay restarting` to each reverse socket
   before what waits for it, and waits up to 3 s for the Closes; the pairs stay, in the file
   too. podssh's node connects again on a code that is not `1001`, `1003` or `1009`, and the
   resumable layer resumes on a code that no row of the table names outside `1001` to `1003`
   and `1007` to `1010` (`crates/podssh-relay/src/reverse/closes.rs`). Lost: `1001`, whose two
   rows in the contract are a stop and an expiry, which each end takes as the pair's end.
8. The limits: 64 sessions a node, as `hello` says (`1011 node unavailable` past them), 4096
   pairs a role (`429`), and the contract's 64 MiB a session (`1009 session byte cap`), 65536
   bytes an operator's frame (`1009 frame byte cap`) and 15 s for a `ready` (`1013 node open
   timeout`).
9. The tests: raw sockets, written from the contract's table as the stand-in was, and podssh's
   own node and operator, against the role on plain ws:// in podssh-relay; the binary against
   the role over TLS with OpenSSH at both ends in podssh-cli; and the CLI's node tests of the
   stand-in against the role by `PODSSH_RELAY_UNDER_TEST=podssh`. The role's events go to the
   harness's log, so that a `1003` for an id that the role does not know fails a test there as
   the stand-in's line does (T-412).
10. The live run: `relay-live.yml` with `relay_serve_reverse` runs the role on the runner,
    `node_live`'s two short tests against it (`PODSSH_LIVE_RELAY`), and the `podssh operator`
    of `v1.0.0`'s binary through a node of the role's pair to GitHub's SSH port. The long tests
    of `node_live` (10 minutes, 200 MiB) stay with the release check (T-446).

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

## Correction

2026-11-02 (the drafting agent). The Decision above names
`crates/podssh-relay/src/reverse/wire.rs` as the node's codecs; that file is the client's wire
(TLS, or plain ws:// to the loopback). The codecs that the role reuses are
`crates/podssh-relay/src/reverse/framing.rs` (the id and the caps),
`crates/podssh-relay/src/reverse/framing/legs.rs` (the frames of each leg) and
`crates/podssh-relay/src/reverse/control.rs` (the text controls). The Prove's first command
builds no test of the role, which needs the features `serve` and `plain-ws`. The Prove that
runs, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_contract --test relay_serve_reverse
cargo test -p podssh-relay --features serve --lib serve::
cargo test -p podssh-relay --features pair
cargo test -p podssh-cli --test relay_serve_node --test relay_serve
PODSSH_RELAY_UNDER_TEST=podssh cargo test -p podssh-cli --test node_copy --test node_moves --test node_plain --test node_restart --test node_routes --test roost --test attach
sh scripts/plant-each.sh --here t427-no-bound t427-no-grace
```

Live, by hand (`relay-live.yml`, `test=relay_serve_reverse`): the role on the runner's loopback,
`node_live`'s `node_command_serves_a_tcp_target` and `ssh_to_a_node` against it, and the client of
`v1.0.0` reads GitHub's banner through a node of the role's pair.

## Done

2026-11-02: drafted by an agent of this session in a worktree, then merged, built and measured
here.

- The role's reverse road, `crates/podssh-relay/src/serve/reverse/`: `mod.rs` (the routes,
  `/v1/pair`, `/v1/status`, `/v1/stop`, the token from `X-Relay-Token` or `?token=`),
  `pairs.rs` (the pairs, their digests, the grace, the file, the planned stop), `outbox.rs`
  (one writer for each socket, the bound), `node.rs` and `operator.rs` (each socket, each row of
  the close table that it sends). `/health` says `"reverse": {"enabled": true}`.
- `podssh relay serve --pairs FILE` (`crates/podssh-cli/src/relay_serve.rs`), the flag's row,
  the manual's note (`crates/podssh-cli/src/man/notes_relay.rs`), and `1012` at Ctrl-C or
  SIGTERM; `docs/relay.md` ("The relay role's reverse road") and docs/mesh.md, section 4.
- `cargo test -p podssh-relay --features serve --lib serve::`: 16 passed (the pairs' shapes and
  tokens, the grace, the file of digests, the paths, the token's places, the frames that podssh's
  node reads, the bound of a writer).
- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_contract`: 10 passed
  (the statuses, `ready` first, a `reject` whole, `1003 binary frames required`, the seven faults
  of a node and the control cap, the frame in flight, `1013` at 15 s, `1011 node unavailable`,
  `1012` and the pair after it); `--test relay_serve_reverse`: 3 passed (two sessions of 2 MiB each
  way; a slow operator meets `1011 relay backpressure` while a second session goes on; the node
  joins again after `1012`).
- `cargo test -p podssh-cli --test relay_serve_node`: 3 passed (pair, status and `ssh node://`
  against the role; OpenSSH's ssh through `podssh operator` and `podssh node` to OpenSSH's sshd,
  with equal digests); `--test relay_serve`: 7 passed, unchanged.
- `PODSSH_RELAY_UNDER_TEST=podssh`, the node suites against the role in place of the Python
  stand-in: `node_copy` 6, `node_moves` 3, `node_plain` 2, `node_restart` 3, `node_routes` 2,
  `roost` 8 and `attach` 2 passed.
- Planted, `sh scripts/plant-each.sh --here t427-no-bound t427-no-grace`: 2 caught (the slow
  operator's test and the frame in flight's test failed).
- Clippy with `-D warnings` on podssh-relay and podssh-cli, and on podssh-relay with
  `serve,plain-ws` (the gate's new step): clean; `cargo fmt --check`: clean.
- `cargo test --no-fail-fast -p podssh-cli`: 1285 passed, 0 failed; `cargo test --no-fail-fast -p
  podssh-relay --features pair,quick,derp,serve,piping`: 488 passed, 0 failed.
- Live on a runner from the merge's branch (`relay-live.yml`): `relay_serve_reverse`
  (41407047641): `node_live`'s two short tests through a node of the role, and the client of
  `v1.0.0` (35a0d19) read GitHub's version line through a node of the role; `relay_serve`
  (41407050852): the forward road as before. The first run showed the transit road taking the
  pair relay's CA, a defect of T-436 repaired here (its Done says how).

# T-428: The relay role behind a node's quick tunnel, with no listener

**Source:** the operator's ruling Q63 (2026-11-02), `docs/mesh.md`, section 4; the audit of
2026-11-02 (the quick tunnel's node is a server that needs no listener).
**Category:** feature
**Milestone:** M10
**Priority:** P1
**Effort:** M
**Status:** done

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
   and T-427, in place of the 404, over HTTP/2 and over QUIC: each request as cloudflared's
   proxy sends one to an origin of HTTP/1.1, and the role's answer back as cloudflared's writer
   sends an origin's (the Correction).
2. Its line on stdout names the relay host (`https://NAME.trycloudflare.com`, which
   `--relay-host` takes as it is).
3. Its tokens are minted for its owner's keys in its `--allow` file (T-448's keys of a list),
   or as `--mint` says, and for anyone only when the user asks; the keys of its net are
   T-455's.

## Decision

The draft's calls, 2026-11-02, each with what lost:

1. **The role as the tunnel's origin of HTTP/1.1, in the process.** The node gives each request
   of a relay's path to `podssh_relay::serve::serve_named` on a pipe of its own
   (`crates/podssh-relay/src/serve/behind.rs`), as cloudflared gives a request to an origin of
   HTTP, so the role of T-169, T-427 and T-448 serves it unchanged. Lost: a second entry of the
   role that takes a parsed head and answers through a trait, which would change each answer of
   the role and the path that its listener's tests measured; and a listener of the role on the
   loopback, which rule 2 of `AGENTS.md` forbids and the entry's title rules out.
2. **The request and the answer as cloudflared's** (`proxy/proxy.go`, `connection/http2.go`,
   `connection/quic_connection.go` at 2026.10.6; `crates/podssh-relay/src/quick/origin.rs`): the
   visitor's headers but those of one hop and the edge's own (`cf-cloudflared-*`); for a
   WebSocket, `Connection: Upgrade`, `Upgrade: websocket` and `Sec-WebSocket-Version: 13`, as
   cloudflared's proxy sets them whatever came; any other request's body read whole, 32 KiB at
   most, with its `Content-Length`; the answer's headers but those of one hop, the three of a
   101 kept, serialized over HTTP/2 with `content-length` beside them and a 101 as 200, and over
   QUIC each in the metadata with the 101 as it is. After a 101 each byte goes as it came, both
   ways, as the edge passes a WebSocket's frames unchanged. Lost: decoding the visitor's frames
   and encoding them again for the role, a copy that changes nothing; a body streamed to the
   role, as no request of the contract carries more than 4 KiB.
3. **Which paths.** The role's own, as `serve::serves` says beside the match that routes them:
   `/health`, `/v1/mint`, `/relays.json`, `/trace`, `/llms-full.txt`, `/connect/...` and each
   path under `/v1/`, whose unknown ones the role answers with its 404; a WebSocket at another
   path stays a visitor of TARGET (`cf://` asks for `/`), and a request of raw TCP stays 404. With
   no TARGET, each path is the role's. Lost: a prefix of the role's own (`/relay/...`), which no
   client of the contract sends; each path always, which would take `/` from TARGET.
4. **How the origin reaches the loop.** A trait `Visit`, which each closure of before has by a
   blanket impl, and `Visitors { visit, origin }` for a node with an origin; `serve`, `race`,
   `keep` and `Link::serve` take a `Visit`, so each test and caller that passes a closure stays
   as it was. `send_all` and the visitor's WebSocket moved to `quick/h2_stream.rs`, as
   `serve.rs` was at 500 lines. Lost: a parameter more for each of those functions, which each
   test's call would carry; a field of `Registration` or `Connector`, which are the
   registration's.
5. **The tunnel's name stands for the TLS's.** `serve_named` gets the tunnel's name as the name
   that a TLS asked for, and the request's `Host` is the edge's authority (`:authority` over
   HTTP/2, `HttpHost` over QUIC), so a key's signed mint or pair must name the tunnel (T-448).
   Lost: no name, with which a relay in the middle could pass on a request signed for itself.
6. **Whom it mints for.** The keys of the node's `--allow` by default (`Mint::Keys`), the list of
   who may reach the node, so that one line lets its owner in at both; `--mint` takes the words
   of `podssh relay serve` (`anyone`, `nobody`, `keys:FILE`). Lost: anyone by default, on a
   public name; no one by default, a role that no client could use with no other channel of
   tokens; the net's members, which are T-455's.
7. **The command line.** `podssh node NAME [TARGET] --quick-tunnel --relay`, with `--mint`,
   `--pairs` and `--allow-private` of `relay serve`, each refused without `--relay`, and
   `--relay` without `--quick-tunnel` (64); TARGET may be left out with `--relay`; `--allow`
   stays needed. Lost: `podssh relay serve --quick-tunnel`, to which each flag of the quick
   tunnel's node (`--warp`, `--detach`, `--install`, the key's) would have to come; and
   `--keepalive` on the node, whose default of 25 s serves.
8. **The line on stdout stays `https://NAME.trycloudflare.com`**, which `--relay-host` and
   `PODSSH_RELAY` take as they are, as they strip `https://`; the role's line on stderr says so.
   Lost: the bare name, which would change the line that scripts of the quick tunnel read.
9. **The role's events** (`mint`, `upgrade`, `close CODE`, `reverse ...`) are the node's lines on
   stderr, as `relay: ...`. Lost: stdout, as `relay serve` prints them, where the tunnel's name
   is the one line.
10. **A planned stop** closes each socket of the reverse road with `1012` within 3 s, as `relay
    serve` does (T-255), and then the tunnel unregisters.
11. **`--pairs FILE`** is kept, though a pair names its relay host and the tunnel's name is new
    at each run: it is `relay serve`'s, and a named tunnel (T-180) keeps its name.
12. **The tests.** Through the stand-in edge of T-300 (`tests/quick_harness/`) and a front of
    its own that plays the visitor's side of Cloudflare's edge, HTTP/1.1 in and HTTP/2 with
    cloudflared's headers out (`tests/quick_relay_harness/`): a client of the contract that
    podssh did not shape (plain ws:// and HTTP by hand), and podssh's own node and operator of
    the reverse road. The QUIC side on pipes (`tests/quick_relay_quic.rs`), with the metadata's
    names of the reference's fixture, as a QUIC stand-in carries a stream's bytes unchanged.
    podssh's client with `--relay-host` over TLS, and the client of `v1.0.0`, live.
13. **Rule 2 of `AGENTS.md`.** Nothing listens, and the node's own connections stay the two to
    the edge of T-414 (Q62); each dial of a target is a forward session's, which the role makes
    on a listener too (T-169).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features quick
```

Offline, through the edge's stand-in of T-300: a client with `--relay-host` of the stand-in's
name carries GitHub's banner from a fixture through the node. In GitHub Actions
(`quick-tunnel-live.yml`, Q43): a client of `v1.0.0` reaches `github.com:22` through the node's
quick tunnel. Planted: the 404 kept, and the client fails.

## Correction

2026-11-02 (the drafting agent). The Premise's first point holds
(`crates/podssh-relay/src/quick/serve.rs:8` said the 404). The second holds for a WebSocket's
frames, not for the requests: over HTTP/2 the edge sends the upgrade in a header of its own
(`cf-cloudflared-proxy-connection-upgrade`) and no `Upgrade` or `Connection`, which HTTP/2
forbids, and wants the answer's headers serialized; over QUIC a request is a `ConnectRequest`
whose metadata holds the method, the Host and the headers; and the relay's mint, pair, status
and stop are no WebSockets. So the node translates each request for the role as cloudflared's
proxy does for an origin (the Decision, 2), as Approach item 1 now says. Approach item 3 said
the keys of the net (T-429) first: the net's members' mint is T-455, so this entry mints for the
keys of `--allow` (T-448's keys of a list) and for `--mint`'s. Approach item 2 said the bare
name: the line stays `https://NAME.trycloudflare.com`, which `--relay-host` takes as it is. The
Prove's command builds no test of the role, which needs the features `serve` and `plain-ws`; and
its client is one of the contract on plain ws:// to the stand-in's front, the stand-in's name in
its `Host`, as the stand-in edge speaks no TLS; podssh's own client with `--relay-host` runs
live. The Prove that runs, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features quick,serve,plain-ws --test quick_relay --test quick_relay_quic
cargo test -p podssh-relay --features quick,serve --lib serve::behind
cargo test -p podssh-relay --features quick --lib quick::origin
cargo test -p podssh-relay --features quick --test quick_tunnel --test quick_tunnel_quic --test quick_resilience --test quick_small_frames
cargo test -p podssh-cli --test node_quick_relay --test node
sh scripts/plant-each.sh --here t428-keeps-404
```

Live, by hand (`quick-tunnel-live.yml`, Q43): a node with `--relay` and no TARGET, and the client
of `v1.0.0` reads GitHub's version line through it with `--relay-host https://NAME...`.

## Done

2026-11-02: drafted by an agent in a worktree, which built and ran nothing; merged and measured by
the main session the same day.

- The origin of a quick tunnel's node (`crates/podssh-relay/src/quick/origin.rs`, its tests in
  `origin_tests.rs`): the traits `Origin` and `Visit`, `Visitors`, and the heads between the
  edge and the origin; over HTTP/2 (`origin_h2.rs`) and over QUIC (`origin_quic.rs`); the
  routing in `serve.rs` and `quic_serve.rs`; `Visit` in `roads.rs`, `keep.rs` and `quic.rs`;
  `send_all` and the visitor's WebSocket moved to `h2_stream.rs`.
- The role behind the tunnel: `crates/podssh-relay/src/serve/behind.rs` and `serve::serves`.
- `podssh node --quick-tunnel --relay` with `--mint`, `--pairs` and `--allow-private`
  (`crates/podssh-cli/src/node_quick_relay.rs`, `node_quick.rs`, `node_args.rs`, the check in
  `node.rs`, the rows in `flags/node.rs`, TARGET's help); `relay serve`'s words of `--mint` and
  its stop's wait shared (`relay_serve.rs`); the manual's notes of `node` and `relay`, two
  examples; `docs/cli.md`, `docs/relay.md` ("The relay role behind a quick tunnel"),
  `docs/mesh.md`, section 4, and the row of `docs/STATUS.md`.
- The gate: clippy of the role's tests with `quick` too, and two new runs of tests
  (`scripts/gate.sh`). The live step in `quick-tunnel-live.yml`.
- The merge: the draft applied with one conflict (the row of T-448 in `docs/STATUS.md`, which
  the repair of `60b3070` had changed) and built at once. The help's check that no flag runs
  into its description failed on `--relay`, whose words named `--relay-host`: they name the
  relay host in other words now.
- `cargo test -p podssh-relay --features quick,serve,plain-ws --test quick_relay`: 4 passed (the
  keyed mint and a target's first line through the role, the node and the edge; the documents
  and the node's own paths; the relay alone; podssh's node and operator, 1 MiB each way);
  `--test quick_relay_quic`: 4 passed. Both again with no C compiler, as the gate runs them.
- `cargo test -p podssh-relay --features quick,serve --lib serve::`: 22 passed (`serve::behind`,
  2, again with no C compiler); `--features quick --lib quick::`: 74 passed.
- The quick tunnel's suites with `Visit`: `quick_tunnel` 12, `quick_tunnel_quic` 2,
  `quick_resilience` 8, `quick_small_frames` 7 passed; `--features warp-stand-in --test
  quick_edge_warp`: 2 passed.
- `cargo test -p podssh-cli --test node_quick_relay`: 3 passed; `--test node`: 17;
  `flag_table` 9, `man_flag_parity` 6, `man_json` 4, `man_page` 10; `--lib`: 568.
- Planted, `sh scripts/plant-each.sh --here t428-keeps-404` (the 404 kept): caught, the test of
  a target's first line through the role failed.
- Clippy with `-D warnings`: podssh-relay with `serve,plain-ws,quick`, and podssh-cli with
  podssh-relay, all targets: clean; `cargo fmt -p` of both.
- The whole suites: `cargo test --no-fail-fast -p podssh-cli`, 1310 passed, none failed (51
  ignored); `-p podssh-relay --features pair,quick,derp,serve,piping`, 509 passed, none failed
  (22 ignored). Each run of `quick_relay` left its list's scratch directory in the temporary
  directory, which the gate's step would count: the list is a guard now, which goes when the test
  ends, pass or fail, and none is left.
- Live (`quick-tunnel-live.yml`, Q43, from GitHub Actions): the first run after the merge failed
  before the role was asked anything, as the client of `v1.0.0` looked up the tunnel's new name
  before Cloudflare's DNS had it (NXDOMAIN); the step now waits up to 120 s for the role's
  `/health` at the name (`da323a3`). Then run 41440851652 passed: the client of `v1.0.0` read
  `SSH-2.0-` through the role behind the quick tunnel, and `podssh relay status` read the role's
  `/health` through the tunnel.
- Not done here: the role dials its targets from the node's host directly, so behind a quick
  tunnel on a host whose way out is only `HTTPS_PROXY` its forward road answers `502`, while its
  reverse road works: T-457.

# T-429: The net: an owner's signed list of its nodes, and their names

**Source:** the operator's ruling Q63 (2026-11-02): "full on tailscale-like parity";
`docs/mesh.md`, section 3.
**Category:** feature
**Milestone:** M10
**Priority:** P1
**Effort:** L
**Status:** done

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

The calls of the draft (2026-11-02), each with what lost:

- **One file, the document then its armoured signature**, replaced whole (`net.doc` of the
  cache, or `PODSSH_NET`); `podssh net show` and `show --signature` give the two parts that
  `ssh-keygen -Y verify` reads, and `take FILE` reads either form. Lost: two files, `net.json`
  and `net.json.sig`, which a node that reads them for each session could see half replaced.
- **The owner is trusted at the first `take`** (or `init`), which `--owner KEY` can check; each
  later document must have the same owner, so a document of the channel never starts a net.
  Lost: a separate pin of the owner's key, which says what the document held says already; and
  a new owner by a document of the old one, which a lost key could not stop (a new net is the
  remedy, as a new tailnet is).
- **Fields that this podssh does not know stay** when the owner signs a change (the document is
  edited as JSON, not rebuilt), and `requires` names each part that an end must read to take it.
  Lost: a version number for each addition, which would make each later podssh's document
  unreadable to the ends of before even where they lose nothing; and dropping unknown fields,
  which would let an older owner's podssh erase a policy (T-430).
- **Member names have no dot**, so that `podssh ssh NAME` can try the net first and no DNS name
  is ever a member's; a `Host` block that sets `HostName` for a member's name is refused, as for
  `node://NAME`. Lost: dotted names, which would take hosts of DNS; and the ssh_config first,
  which would need the file read before the destination is known for a node.
- **The passage of a document inside the end-to-end channel**, negotiated so that an end of
  `v1.0.0` never meets a form that it does not read: the operator's first Noise message carries
  `podssh-net/1` in clear (a node of before sets that payload aside), and only then do the proofs
  take a third form, which names the owner (the SHA-256 of its fingerprint) and the serial,
  encrypted. The operator's newer document is a message before the verdict, so that it holds for
  its own session; the node's goes after a verdict that let the operator in. Each goes only to a
  member of the document sent. Lost: a request of its own after the session's bytes (a second
  round trip, and nothing for the session that brought it); a document in the clear message (the
  relay would read the members); and the documents in the library (`podssh-relay` would need
  SSHSIG, and so C).
- **One net for each host's cache**, as one tailnet for each `tailscaled`; `PODSSH_NET` names
  another file for another. Lost: several nets in one store, which no command of this entry needs.
- **A node whose key is a member** admits the members beside `--allow`; a node of no net keeps its
  door as before. A document that ended, or one that is there and fails its check, admits nobody
  by the net, and `--allow` stays the fallback. Lost: admitting each operator with the pair's
  token when the document cannot be read (a removed member would come back), and refusing each
  key of `--allow` with it (a server that only the node reaches could be locked out by its net).
- **A year** for each document by default (`--days`, at most ten years), and `podssh net renew`.
  Lost: no end, which would keep a removed member in at a node that never got the newer document.
- **The owner's key** for a change: `--owner-key`, else the agent's, else a key of `~/.ssh` whose
  public half is the owner; for `init`, `~/.ssh/id_ed25519`. podssh keygen's signer is used as it
  is (`crates/podssh-cli/src/keygen_sign.rs`).

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

## Correction

The Premise holds, with two reads that the Approach did not name. The iroh road has a door of its
own before the channel: `podssh node --iroh` lets in the client keys of its allowlist at each
connection, and none with no `--allow` (`crates/podssh-cli/src/node_iroh.rs`), so the net's members
are let in there too. And `podssh node --derp` needs `--allow` to start
(`crates/podssh-cli/src/node_derp.rs`): with the net, its door is the allowlist and the members,
but the flag is still asked for, as the draft left that check as it was.

## Done

2026-11-02: drafted by an agent of this session in a worktree, then merged, built and measured
here.

- `podssh net` (`crates/podssh-cli/src/net/`): the document (`doc.rs`), its SSHSIG (`sign.rs`),
  the store and the rule of a new document (`store.rs`), the commands (`mod.rs`, `edit.rs`), the
  node's door and the passage in the channel (`admit.rs`), the names (`lookup.rs`); the verb, its
  table (`crates/podssh-cli/src/flags/node.rs`), its notes (`crates/podssh-cli/src/man/notes_net.rs`),
  `PODSSH_NET` (`crates/podssh-cli/src/man/facts/net.rs`), an example and `net.doc` in FILES.
- The channel (`crates/podssh-relay/src/e2e/net.rs`, `handshake.rs`, `channel.rs`): the offer, the
  third form of a proof, the message `NET`.
- The doors: `crates/podssh-cli/src/channel.rs` (the pair's road and the quick tunnel),
  `crates/podssh-cli/src/node_derp.rs`, `crates/podssh-cli/src/node_iroh.rs` (the channel's door and
  the iroh road's own), and the routes of each (`crates/podssh-cli/src/node.rs`).
- The names: `node://NAME` and `NAME` alone (`crates/podssh-cli/src/ssh/node.rs`), the member's key
  in place of the pins (`crates/podssh-cli/src/channel.rs`, and `crates/podssh-cli/src/ssh/roads.rs`
  for a run with tickets), its iroh ticket (`crates/podssh-cli/src/ssh/iroh.rs`) and its DERP
  ticket (`crates/podssh-cli/src/ssh/derp.rs`).
- Captured: OpenSSH_9.6p1's `ssh-keygen -Y sign` over a document written by hand, by its owner, by
  another key and in another namespace, and an expired one (`crates/podssh-cli/src/net/testdata/`).
- `cargo test -p podssh-cli --lib net`: 12 passed (the captured signatures read and refused, a
  document signed here read back, unknown fields kept, `requires`, each fault of a document, the
  names and roles, `PODSSH_NET`'s forms).
- `cargo test -p podssh-cli --test net`: 6 passed: OpenSSH_9.6p1's `ssh-keygen -Y verify -n
  podssh-net` verifies what `podssh net` signed, and refuses a changed byte; what `ssh-keygen -Y
  sign` signed is taken; and three ends on the stand-in relay: two members reach a node of no
  `--allow` by its name alone, the owner removes one, the other brings the new document to the
  node in its next session, and the removed member is refused.
- `cargo test -p podssh-relay --test e2e_net` 4 and `--lib e2e::net` 2 passed; the channel's and
  the roads' suites, for ends with no documents: `--features pair --test e2e` 10, `e2e_faults` 7,
  `e2e_layered` 4, `routes` 2; `podssh-cli --test node_routes` 5 and `channel_cli` 9 passed.
- `cargo test -p podssh-cli --test flag_table --test man_page --test man_flag_parity` and `--lib
  man` (58) passed.
- Planted, `sh scripts/plant-each.sh --here t429-net-serial t429-net-owner t429-net-gossip`: 3
  caught (an older serial taken; another key's signature taken; the operator kept the older
  document).
- Repairs at the merge: the test read `ssh-keygen -Y verify`'s verdict on stderr, where OpenSSH 9.6
  says it on stdout (it reads both now); a test's closure needed its error type named; clippy's
  `type_complexity` on the decoded proof (a type alias now); the draft predates T-437, so the node
  of the Piping Server road takes the net's members for its routes too, and node.rs keeps T-437's
  order and its TARGET checks in `node_target.rs`. The build with `--features iroh` checks clean;
  clippy with `-D warnings` on podssh-relay and podssh-cli: clean.
- `cargo test --no-fail-fast -p podssh-cli`: 1282 passed, 0 failed; `cargo test --no-fail-fast -p
  podssh-relay --features pair,quick,derp,serve,piping`: 480 passed, 0 failed.
- Filed for the merge: T-452 (a node of the DERP road whose key is a member starts with no
  `--allow`) and T-453 (`podssh cp` and `podssh sftp` reach a member by its name alone).

# T-430: The net's policy: who may reach which node, share and exit

**Source:** the operator's ruling Q63 (2026-11-02): Tailscale's ACLs and grants;
`docs/mesh.md`, section 3.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

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

## Decision

The calls of the draft (2026-11-02), each with what lost:

- **One field `policy` of the document, set whole from a file of JSON** (`policy set FILE`),
  given back by `policy show` in a form that `set` takes again, as Tailscale's policy file is
  edited whole: `rules`, each with `from`, `to` and an optional `note`, and `tags`, each a list
  of members' names. Lost: a command for each rule (`policy allow FROM TO`, `policy rm N`), whose
  numbers move under the user, and a file reviewed as one; tags on the members (`net add
  --tags`), which `net add` of an existing member would drop, and which would scatter the policy
  over the members.
- **`NODE` is the whole node**: its target with no route and each route, as Tailscale's
  `host:*`; `NODE/ROUTE` is one route, as `node://NODE/ROUTE` reaches it (a share of T-433 is
  reached so). Lost: `NODE` as the target with no route alone, beside `NODE/*` for the routes,
  which lets in less than a user who names a node means and needs two forms of each tag; a user
  who wants one service alone gives it a route.
- **The words**: `from` is `*`, a member's name or `tag:TAG`; `to` is `*`, `NODE`,
  `NODE/ROUTE`, `tag:TAG` (each member of the tag, as `NODE`), `exit:NODE`, `exit:*` and a range
  `ADDR/BITS` or one address. `*` in `to` reaches each node, route, exit and range, as
  Tailscale's `*:*`, so that `from * to *` is no policy; a tag reaches its members' services,
  not their exits, as Tailscale's `tag:x:*` is the devices and not the internet through them.
  Lost: Tailscale's `autogroup:` words and ports, which have no counterpart in a net whose
  services are named routes.
- **A rule only allows, and what this podssh does not read allows nothing**: a word of no known
  form names nobody and reaches nothing; a rule with a field that this podssh does not read lets
  nobody in, as the field may narrow it; a field of the policy beside `rules` and `tags` is kept
  and not read. A later podssh whose part narrows a rule, or denies, names that part in
  `requires`, so that this one refuses the document. A fault of the policy's form (not an
  object, a list that is not one, a word that is not text) refuses the document whole, as each
  other fault of a document's form does (T-429). Lost: refusing a document for an unknown word,
  which would keep each end of before on an older document that may let in more; a deny rule,
  whose order would matter and which Tailscale's grants do not have either.
- **A policy with no `rules` lets nobody in**, as `rules: []` does; only a document with no
  policy at all lets each member reach each. Lost: no list read as no policy, which would let a
  later podssh's policy that keeps its rules elsewhere open the whole net here.
- **`policy set` puts `policy` in `requires`, and `clear` takes it out**, so that a podssh of
  before T-430 refuses a document with a policy and keeps the one before, never skipping the
  rules (the rule of T-429). Lost: no part in `requires`, with which an end of before would take
  the document and let in each member.
- **The node's admission sees the route** (`crates/podssh-relay/src/e2e/ends.rs`: `Admit` takes
  the route that the operator named, or none), so one check at the node gives the verdict for
  the key and what it asks, and its refusal is the channel's `NotAllowed`, which names no route
  to the operator, while the node's line gives the policy's words. Lost: the admission by key
  and the route's grant as they were, as the grant is asked for a named route only
  (`crates/podssh-relay/src/reverse/routes.rs`), so a member let in for one route would reach
  the target with no route; and a grant asked for the target with no route too, with the
  admission told whether the node has routes: two checks for one verdict, and the grant's words
  are dropped there, so the node could not say which rule failed.
- **The iroh road's door**, before the channel and with no route known, lets in a member that a
  rule lets reach anything of the node (`Want::AnyOf`): a route of it, the node, its exit, or a
  range, as which node routes a range is T-432's; the channel then checks what it asks. Lost:
  membership alone, with which a member that the policy refuses whole still costs the node a
  connection; and the whole check there, which cannot know the route.
- **The keys of `--allow` are not narrowed**: a member that the policy refuses comes in when the
  node's own file names its key, as T-429 kept `--allow` the fallback beside the net. Lost: the
  policy over the file, which would make the node's operator edit the net's policy to let in a
  key of its own list.
- **`policy check FROM TO`**: FROM a member's name, key or fingerprint, as a node's line names
  the key; TO `NODE` (as `node://NODE`, its target with no route), `NODE/ROUTE`, `exit:NODE` or
  an address; one line on stdout, `allowed` or `refused`, a tab and the rule or the reason; 0 or
  77 (`EX_NOPERM`, as `operator` exits when the channel refuses), and 64 for a FROM or a TO that
  is no member. It reads the rules alone: the summary on stderr says an ended document, which a
  node refuses by its end. Lost: exit 1, which podssh keeps for no refusal (`docs/cli.md`,
  "Exit codes").
- **`policy set` is strict**: a field, a form or an undefined tag is refused (65) and nothing is
  signed; a name that no member has, and `exit:NODE` of a member with no role `exit`, are said
  on stderr, not refused, as the member may come later; `rules: []` is taken, and said. Lost:
  refusing an unknown name, which would make the owner add the member before its rule.
- **Exits and ranges**: their words are read and checked now, and `policy check` answers them;
  the node that serves them is T-431's and T-432's, which ask `policy::check` with
  `Want::Exit(NODE)` and `Want::Addr(ADDR)`. The role `exit` is said by `set`, and enforced by
  T-431.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test net
```

On the stand-in relay with three members: an allowed route is reached; a route that no rule
names is refused, with the rule's words; a newer document that removes a rule is in force at
the next session. Planted: the node that skips the check, and the refusal test fails.

## Correction

The Premise holds: the node gives its verdict before it dials (`docs/reverse.md`, "The
end-to-end channel", rule 3), and its routes are `podssh node NAME TARGET [ROUTE=TARGET]...`.
One read that the Approach did not name: the node's admission (`Admit` of
`crates/podssh-relay/src/e2e/ends.rs`) saw the operator's key alone, and the grant of a route
(`crates/podssh-relay/src/reverse/routes.rs`) was asked for a named route only, so nothing
checked the target with no route by itself. The admission takes the route named now (the
Decision), on each road, as each road's node serves the channel through it.

## Done

2026-11-02: drafted by an agent in a worktree, which built and ran nothing; merged and measured by
the main session the same day.

- The policy (`crates/podssh-cli/src/net/policy.rs`): its form read from the document, its
  check (`policy::check`, the rule or the reason), and the strict check of a policy that the
  owner sets; the words of a rule and the ranges (`crates/podssh-cli/src/net/policy_words.rs`).
  The document holds it (`crates/podssh-cli/src/net/doc.rs`: `Doc::policy`, `field`,
  `next_whole`), and `policy` is a part that `requires` may name.
- The commands (`crates/podssh-cli/src/net/policy_cmd.rs`): `policy check FROM TO`, `show`,
  `set FILE` and `clear`, the last two signed as each change of the owner
  (`crates/podssh-cli/src/net/edit.rs`); the flags of the owner go with `policy set` and `policy
  clear` (`crates/podssh-cli/src/net/mod.rs`).
- The node (`crates/podssh-cli/src/net/admit.rs`): the verdict for what is asked (a route, the
  target with no route, or anything at a road's door), in the admission, the routes' grant and
  the iroh road's door; the node's first line counts the policy's rules. The channel's admission
  takes the route (`crates/podssh-relay/src/e2e/ends.rs`), and each admission of the binary and
  of the tests with it (`crates/podssh-cli/src/channel.rs`, `crates/podssh-cli/src/node_temp.rs`,
  `crates/podssh-cli/src/ssh/cloudflare/layer.rs`, `crates/podssh-relay/tests/e2e_harness/mod.rs`);
  the operator's words of a refusal name the policy.
- The manual: the notes (`crates/podssh-cli/src/man/notes_net.rs`), the flags' words
  (`crates/podssh-cli/src/flags/node.rs`), the arguments (`crates/podssh-cli/src/positionals.rs`),
  the usage (`crates/podssh-cli/src/help.rs`), an example (`crates/podssh-cli/src/man/examples.rs`)
  and 77 in EXIT STATUS (`crates/podssh-cli/src/man/data.rs`). The documents: `docs/cli.md`
  ("`podssh net`"), `docs/mesh.md` (section 3), `docs/reverse.md` ("The end-to-end channel"),
  `docs/STATUS.md`.
- Tests: `crates/podssh-cli/src/net/policy_tests.rs` (7: no policy, rules and tags, an empty
  list, the words, the ranges, the strict check, a later podssh's words and a wrong form), and
  the module `net_policy` of `crates/podssh-cli/tests/net.rs` (2: the commands with no
  connection; three ends on the stand-in relay). `crates/podssh-cli/src/net/tests.rs` names
  another part than `policy` for a part that this podssh does not read.
- Planted: `scripts/plants/t430-policy-skipped.plant` (the node lets in each member that the policy
  refuses).

Measured at the merge, 2026-11-02:

- The draft applied with no conflict and built at once; `cargo fmt -p` of podssh-cli and
  podssh-relay; clippy with `-D warnings` on both, all targets, and on podssh-cli with
  `iroh-test`: clean. The build with `--features iroh`: done.
- `cargo test -p podssh-cli --lib net`: 19 passed. `--test net`: 8 passed (the 6 of T-429 and
  the 2 here: the commands with no connection, and three ends on the stand-in relay, where an
  allowed route is reached, one that no rule names is refused with the rule's words, and a newer
  document that removes a rule is in force at the next session); no scratch directory left.
- `cargo test -p podssh-relay --features pair --test e2e --test e2e_faults --test e2e_layered
  --test e2e_net --test routes`: 10, 7, 4, 4 and 2 passed; `cargo test -p podssh-cli --test
  node_routes --test channel_cli`: 5 and 2; `--lib ssh::cloudflare`: 5.
- The manual: `--lib man` failed once on the synopsis of `podssh net`, 84 characters, wider than
  the page; it is `[OPTIONS] SUBCOMMAND [NAME [KEY] | FILE | FROM TO]` now, and the policy's verbs
  are in its notes: 59 passed. `--test flag_table`, `man_flag_parity`, `man_json`, `man_page` and
  `leading_dash`: passed.
- Planted, `sh scripts/plant-each.sh --here t430-policy-skipped`: caught, "a target that no rule
  names was reached".
- The whole suites: `cargo test --no-fail-fast -p podssh-cli`, 1307 passed, none failed (51
  ignored); `-p podssh-relay --features pair,quick,derp,serve,piping`, 495 passed, none failed (22
  ignored); the temporary directory held as many entries after them as before.
- 2026-11-03, `plants.yml` at `3bb42ea` (run 41563969423): `t430-policy-skipped` missed, as the
  build image has no Python and the test said it did not run; the plant installs Python and
  openssl first since then, and in the build image `sh scripts/plant-each.sh t430-policy-skipped`:
  caught ("a target that no rule names was reached").

# T-431: Exit mode: a node's egress for its owner's forward road

**Source:** the operator's ruling Q63 (2026-11-02): "exit mode"; `docs/mesh.md`, section 5.
**Category:** feature
**Milestone:** M10
**Priority:** P1
**Effort:** L
**Status:** done

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

## Decision

The calls of the draft (2026-11-02), each with what lost:

- **The operator names its target in the word of its proof**, where a route's name goes (T-089):
  `HOST:PORT`, an IPv6 address in brackets, which its `:` tells from each route's name, as no
  route's name holds one (`crates/podssh-relay/src/e2e/ask.rs`). The library reads the word as a
  typed `Ask` (the target with no route, a route, or an exit's target); the channel's admission
  takes it (`Admit` of `crates/podssh-relay/src/e2e/ends.rs` gets `&Ask` in place of the route),
  and `serve_asked` hands it to the node's opener, so the compiler makes each admission and each
  opener say what it does with an exit's target; `serve_routed` and `serve_node` stay, and refuse
  one. The word travels encrypted, so the relay sees neither the target nor a byte. A node of
  before T-431 refuses a proof whose word it does not read, whole: its operator sees the session
  end before a verdict. Lost: a request of its own after the verdict, a line in the channel's data,
  which costs a round trip more and leaves the verdict unable to say that the target was refused;
  a new version of the proof, one more form for each end, where the word's field already carries
  255 bytes; a route reserved for the exit with the target in the data, which a user's route of
  that name would take.
- **Who may go out**: a member of a net that gives this node the role `exit`, which its owner
  signs (T-430's Decision left the role to this entry), and that the policy lets reach the
  egress. The node refuses to start without the role (78), and checks it again for each session,
  so a newer document that takes it away lets nobody out. At the door, before the name resolves,
  the policy's `Want::Egress` lets in a member that a rule lets reach `exit:NODE`, `exit:*`, `*`
  or a range (`crates/podssh-cli/src/net/policy.rs`); for each address, `exit:NODE` for a public
  one and the address itself (`Want::Addr`) for a private one. A key of `--allow`, and an operator
  of the pair's connect token alone, never reach the exit (`admit_of` of
  `crates/podssh-cli/src/channel.rs`), whatever they reach of the node. Lost: a word `exit` after
  a key of the allowlist, as a comment of a line may already hold that word and an earlier podssh
  reads it as one; an exit open to each operator of the connect token, an open proxy for whoever
  holds the token, which a node of no `--allow` would be.
- **The address that is checked is the address that is dialled** (DNS rebinding): the node
  resolves the name once with podssh's resolver (`podssh_ws::resolve::resolve`: a literal, the
  pins, the system resolver, the cache of addresses, DNS over HTTPS), checks each address, and
  dials those addresses alone as IP literals, directly or by `CONNECT ADDRESS:PORT` through
  `HTTPS_PROXY`, never the name again (`crates/podssh-cli/src/node_exit.rs`). Lost: the name
  handed to the node's proxy, which would resolve it where the node cannot check it (a proxy of a
  company reaches its own network); the system resolver alone, as the relay role's
  `Policy::addresses` asks it, where podssh's fallbacks serve a host whose resolver is broken; a
  refusal of each name when a proxy is set, which the sandboxes that podssh serves would meet.
- **A public address is the relay role's** (`podssh_relay::serve::policy::public`, T-169): its
  ranges are the relay's limits of `docs/relay.md`, and a name with one address that fails is
  refused whole, as the relay refuses it. No port is refused: the relay's port 25 keeps strangers
  from mail, and an exit's members are its owner's. Lost: `Policy::addresses` whole, for its port
  25 and its resolver.
- **`--routes RANGES` comes here in its first form**: the private ranges that the exit dials too,
  `ADDR/BITS` or one address, as a rule of the policy names a range, each for a member that the
  policy lets reach the address. The Prove's "unless a route allows it" needs it, and the offline
  test's servers are on the loopback. T-432 keeps the rest: the net's document that lists each
  node's routes, `--exit auto`, and the rule that the loopback and the node's own addresses go
  through only when a range names them whole. Lost: a switch of the tests for the loopback,
  which each build would carry as a door.
- **The roads**: each road whose node serves routes (`Routes::exit` of
  `crates/podssh-relay/src/reverse/routes.rs`, filled by `routes_of`): the pair's, the transit
  relay's, the Piping Server's, the DERP and the iroh roads, so an exit with no TARGET of its own
  serves each session by its routes. The quick tunnel's node serves no routes, and refuses
  `--exit` (64): T-459. `--no-e2e`, `--temporary` and a `udp:` TARGET are refused with it too.
- **`podssh ssh --exit NAME`** resolves to the node's own transport, `Transport::Node`, with the
  exit's word for the first hop (the destination, or `-J`'s first, with its `HostName` and port;
  `crates/podssh-cli/src/ssh/exit_road.rs`), so each runner of a node carries it: the roads raced
  as for `node://NAME`, the resume, SSH's keepalives off under the layer; the host key is the
  host's, under its own name. `cp`, `scp` and `sftp` take it through their node's path (the pair's
  road). Lost: a transport of its own, a second copy of each runner of a node.
- **`podssh proxy --exit`, `pipe`'s `relay:` with `--exit`, and `podssh exit --listen`** open
  each connection over the pair's road, in the layer and the channel
  (`crates/podssh-cli/src/exit/open.rs`), and learn the node's verdict before they answer: the
  channel touches the plain side of a session only once the node let it in and reached the
  target, so that first touch is the verdict, and SOCKS and CONNECT answer as `-D` does, success
  only once the target was reached. Lost: racing the other roads there too, as `ssh::roads` runs
  the SSH client inside and gives no stream yet; an answer at once, before the verdict.
- **`podssh exit NAME --listen ADDR:PORT`** is a listener that the user asks for (rule 2 of
  `AGENTS.md`, Q1), bound by `podssh pipe`'s listener, whose attempt is the probe, and refused by
  `PODSSH_LISTEN=no` before any bind; on a loopback address alone; SOCKS5, SOCKS4a (as `-D` reads
  them) and HTTP CONNECT (as `http-listen:` reads it) on one port, by the first byte. No question
  for the operator: Q1 allows the listener, and the exit's dials are a node's dials of its
  targets. Lost: an address of another host with credentials, as the SOCKS of `-D` takes none
  (a later entry may add them, as `--proxy-auth-file` of `http-listen:`); two ports, one for each
  protocol.
- **`doctor` names the exit and the road** (item 4 of the Approach) moves to T-458: doctor opens
  no session through a node today, and its line needs one, with the node's verdict.

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

## Correction

The Premise holds: rule 4 of `docs/reverse.md:16` dials TARGET after the layer's handshake, and
`-D` serves SOCKS on a listener that the user asks for (T-038). Three reads that the Approach did
not name: the relay's check of a public address is code since T-169
(`crates/podssh-relay/src/serve/policy.rs`), which the exit takes; the Prove's offline part
reaches only servers on the loopback, a private address, so the node's `--routes` comes here in
its first form, and T-432 builds on it (the Decision); item 4, `doctor`, is T-458.

## Done

2026-11-02: drafted by an agent in a worktree, which built and ran nothing; merged and measured by
the main session the same day.

- The channel's word (`crates/podssh-relay/src/e2e/ask.rs`, `handshake.rs`, `ends.rs`): `Ask`,
  the proof's word read as a route or an exit's target; `Admit` takes `&Ask`; `serve_asked`; a
  node that is no exit refuses an exit's target (`NO_EXIT`). The node's routes take the exit's
  dial (`crates/podssh-relay/src/reverse/routes.rs`: `ExitDial`, `Routes::exit`). Tests:
  `ask.rs` (3), and `crates/podssh-relay/tests/routes.rs` (an exit's target reaches only a node
  that serves each ask); the admissions of the tests take `&Ask`
  (`crates/podssh-relay/tests/e2e_harness/mod.rs`, `crates/podssh-cli/src/ssh/cloudflare/layer.rs`).
- The node (`crates/podssh-cli/src/node_exit.rs`, with `node_exit_tests.rs`): `--exit` and
  `--routes`, checked first (`crates/podssh-cli/src/node.rs`), the start's line or its refusal
  (78), the resolution, the check of each address and the dial of those alone; TARGET optional;
  each road's routes (`node.rs`, `node_derp.rs`, `node_piping.rs`, `node_iroh.rs`), the first
  line (`node_target.rs`), `--install` keeps both flags (`node_install/text.rs`). The net
  (`crates/podssh-cli/src/net/admit.rs`): `Asks::Egress` and `Asks::Dial`, the role `exit`,
  `exit_ready`; `Want::Egress` (`net/policy.rs`, `net/policy_words.rs`); `admit_of` refuses an
  exit's target to the keys of `--allow` (`crates/podssh-cli/src/channel.rs`).
- The clients: `ssh --exit` (`crates/podssh-cli/src/ssh/exit_road.rs`, `ssh/servers.rs`,
  `ssh/args.rs`), `proxy --exit` and `--client-key` (`crates/podssh-cli/src/proxy.rs`), `pipe
  --exit` (`crates/podssh-cli/src/pipe/remote.rs`, and `http-listen:`'s `relay:%h:%p` in
  `pipe/gateway.rs`), the verb `exit` (`crates/podssh-cli/src/exit/`:
  `mod.rs`, `open.rs`, `listen.rs`), `podssh_ssh::socks` public; the parse and the dispatch
  (`parsed.rs`, `tree.rs`, `dispatch.rs`, `positionals.rs`, `help.rs`), doctor's list of
  listeners (`doctor/listeners.rs`); the listener scan's allowance of `exit/listen.rs`
  (`scripts/repo_listeners.py`).
- The manual: the flags (`crates/podssh-cli/src/flags/node.rs`, `flags.rs`, `flags/copy.rs`,
  `flags/scp.rs`, `flags/relay.rs`, `flags/pipe.rs`); the notes of `exit`
  (`crates/podssh-cli/src/man/notes_net.rs`), of `node` (`notes_pair.rs`), of `ssh`
  (`notes_roads.rs`), of `pipe` (`notes_pipe.rs`) and of `proxy`, moved to `notes_proxy.rs` for
  the length of `notes.rs`; two examples (`man/examples.rs`). The documents: `docs/cli.md` ("The
  exit of the net"), `docs/mesh.md` (section 5), `docs/reverse.md` ("The end-to-end channel"),
  `SECURITY.md`, `docs/STATUS.md`.
- Tests: `crates/podssh-cli/tests/exit.rs` (2: the refusals with no connection; on the stand-in
  relay, an exit with `--routes 127.0.0.1/32` and two members, by `proxy --exit`, `ssh --exit`
  and `exit --listen`, by SOCKS5 and CONNECT, and curl when found), the units of
  `node_exit_tests.rs` (5), `exit/mod.rs` (1) and `ssh/exit_road.rs` (2).
- Planted: `scripts/plants/t431-exit-public-check.plant` (each address taken for a public one).
- GitHub Actions: `.github/workflows/exit-live.yml`, by hand: a node of the net on the runner,
  GitHub's banner through `proxy --exit`, GitHub's host key through `ssh --exit`, and a page of
  GitHub's through `podssh exit --listen` with curl, by SOCKS5 and CONNECT.
- Filed: T-458 (`doctor --exit NAME`, item 4 of the Approach) and T-459 (the quick tunnel's node
  as an exit).

The merge (2026-11-02):

- Applied onto `2ba9e5c` with four conflicts, each a union: the index and the work order, the
  entries T-457 (from the merge of T-428) and T-458, T-459 (this draft) at the end of this file,
  and TARGET's help, which names `--quick-tunnel --relay` and `--exit` both.
- Three defects that the tests found, repaired: `ssh --exit NAME --client-key FILE` was refused,
  as the check of the channel's flags did not count an exit as a road whose far end is podssh
  (`crates/podssh-cli/src/ssh/resolve.rs`; its refusal names `--exit NAME` now); the test gave
  curl `--proxy=URL`, which curl does not read; the manual's topic `exit-status` kept the alias
  `exit`, which the command takes now, as `relay` took its own (`man/facts.rs`, and the test of a
  section by its name); and the verb `exit` joined the dispatched verbs of `flag_table`.
- `cargo build -p podssh-cli`: built. Clippy with `-D warnings`, all targets: podssh-relay with
  `pair,serve,plain-ws,quick`, podssh-ssh, podssh-cli, and podssh-cli with `iroh`: clean;
  `cargo fmt -p` of the three.
- `cargo test -p podssh-relay --features pair --lib e2e`: 5 passed; `--test e2e` 10, `e2e_faults`
  7, `e2e_layered` 4, `e2e_net` 4, `routes` 3 (among them `an_exit_s_target_reaches_only_a_node_that_serves_each_ask`), each passed.
- `cargo test -p podssh-cli --test exit`: 3 passed (the refusals with no connection; the exit on
  the stand-in relay with `--routes 127.0.0.1/32` and two members, by `proxy --exit`, `ssh
  --exit` and `exit --listen` by SOCKS5 and CONNECT, and curl 8.5.0 by `socks5h://` and by
  `--proxytunnel`). `--lib -- node_exit exit ssh::exit_road net doctor::listeners man`: 105
  passed. `--test proxy` 9, `net` 8, `node_routes` 2, `channel_cli` 5, `flag_table` 9,
  `man_flag_parity` 6, `man_json` 4, `man_page` 10, `leading_dash` 3, `pipe_http` 6 (1 ignored),
  each passed.
- Planted, `sh scripts/plant-each.sh --here t431-exit-public-check` (each address taken for a
  public one): caught, "a private target was reached: 0 web".
- The whole suites: `cargo test --no-fail-fast -p podssh-cli`, 1343 passed, none failed (51
  ignored); `-p podssh-relay --features pair,quick,derp,serve,piping`, 520 passed, none failed (22
  ignored); the temporary directory held the same entries after them as before.
- Live (`exit-live.yml`, from GitHub Actions): the first run, at `23a40b4`, carried each leg
  (GitHub's banner through `proxy --exit`, the SSH login through `ssh --exit` up to GitHub's
  refusal of a key, and curl's pages by SOCKS5 and by CONNECT through `podssh exit --listen`),
  and failed only its own check that GitHub's host key went into the test's file: the runner's
  image knows that key in `/etc/ssh/ssh_known_hosts`, so podssh wrote nothing. The step now names
  `GlobalKnownHostsFile=/dev/null` (`94be1bb`), and run 41479877820 passed each check.
- 2026-11-03, `plants.yml` at `3bb42ea` (run 41563969423): `t431-exit-public-check` missed, as
  the build image has no Python and the test said it did not run; the plant installs Python and
  openssl first since then, and in the build image `sh scripts/plant-each.sh
  t431-exit-public-check`: caught ("a private target was reached").

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
**Status:** done

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

## Decision

- **The token is the pair's, not each link's.** TOKEN and the key of a proof come from the
  pair's connect token and name by HKDF-SHA256 (salt `podssh transit, version 1`), which both
  ends hold. Lost: a token for each link from both ends' keys (`docs/carriers.md`, Inferred),
  as the two ends would need a channel of signals to agree on each link, which is missing when
  the pair's relay is down, the case that this carrier is for.
- **A proof of the pair after `ok`.** The relay sees TOKEN, and a node with no `--allow` lets
  in each operator that has the pair, as the pair's relay checks the connect token. So each end
  sends its part (`N` or `C`) and a nonce, then an HMAC-SHA256 of both nonces under the proof
  key; a peer whose proof fails is refused before the layer. Lost: `--allow` required, as on the
  DERP road, which would leave the default node off the road; the channel's allowlist alone,
  which a node with no allowlist does not have.
- **The parts.** The relay pairs any two sides of one TOKEN, so two clients of one pair meet each
  other while the node's wait is taken: a hello of the same part parts them, and each tries
  again within its wait. Lost: a TOKEN for each direction, which the relay cannot pair.
- **One wait at a time at the node**, the next opened at each meeting, with one SIDE for the
  run, so that its own connections never meet. Lost: a wait only after a signal, which has no
  channel when the pair's relay is down; several waits, which load a free service whose relay
  drops the spare ones at each meeting.
- **Last in the race, only when each road before it failed** (`Start::WhenAllFailed`), as a
  kept DERP ticket is (Q50): it costs Least Authority nothing while the pair's road works. Lost:
  the 250 ms head start of a road that the user asked for.
- **`podssh ssh node://NAME` with a good pair goes through the race of
  `crates/podssh-cli/src/ssh/roads.rs`** when the road is on, the default, as a run with a kept
  DERP ticket did: the race is where each resume tries each road again. A run with no pair, or
  an expired one, keeps the words of the pair's road alone; the warning an hour before the
  expiry moved into the race too. Lost: the transit road in the resume of the pair's road alone
  (`layered::next_leg`), a second race.
- **The node of the pair's road, and the node of `--derp` with a pair, wait there**, not the
  node of `--iroh`, `--quick-tunnel`, `--plain`, `--no-e2e` or a `udp:` TARGET: the iroh road's
  node and the quick tunnel's have roads of their own without the relay of the pair, and the
  others have no layer or no channel under which a stranger's relay may carry the bytes.
- **Tests switch the road off** in the harnesses of the offline and stand-in tests
  (`PODSSH_TRANSIT=no`), so that no test of another road reaches Least Authority's relay.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test transit
```

Against magic-wormhole's own transit relay server (Python) on the loopback: two ends meet, and
a session carries 1 MiB each way and survives the carrier's loss by moving to another road.
Live, short (Q65): one session through Least Authority's server from GitHub Actions. Planted:
the wrong side's line, and the meeting fails.

## Done

2026-11-02: drafted by an agent of this session in a worktree, then merged, built and measured
here.

- Measured, with no build of podssh: magic-wormhole-transit-relay 0.5.0 (Twisted 26.10.0,
  Autobahn 26.10.2), run as `python -m twisted transitrelay --websocket=tcp:PORT` on the
  loopback, with a WebSocket client written by hand: `ok\n` to both sides as a binary message,
  none for two connections of one side, Pings answered while a side waits, and the bytes before
  a side's Close reached the other side before a Close 1000. The Premise holds; at the merge,
  Python's `websockets` met two sides at Least Authority's relay through this session's proxy 26
  times of 26.
- `crates/podssh-relay/src/transit/`: the words (`token.rs`), the meeting (`meet.rs`), the link
  over the WebSocket (`link.rs`), the node (`far.rs`) and the client (`client.rs`), pure Rust,
  through `HTTPS_PROXY`. `crates/podssh-cli/src/node_transit.rs`: the node's road beside the
  pair's road with one keeper (`podssh node`, and `--derp` with a pair), the client's dialer,
  and `PODSSH_TRANSIT` (78 for a value that is none of its forms, which is not echoed).
  `crates/podssh-cli/src/ssh/roads.rs`: the road last in the race.
- Repairs at the merge: `node_derp.rs` moved its line writer into the channel before the transit
  road took it (it did not build); the test of a session that moves held the layer's future on
  the test thread's stack, which overflowed in a debug build (it is on the heap now), and named a
  temporary that did not live long enough; `scripts/interop-roost.sh` turns the road off, so that
  no interop run reaches Least Authority's relay.
- `cargo test -p podssh-relay --lib -- transit`: 4 passed (the token and the proof key equal to
  Python's `hmac` and HKDF written out, recomputed at the merge; a proof for its part and order
  alone; the line; the variable).
- `cargo test -p podssh-relay --test transit` against magic-wormhole's own relay on the loopback
  (`PODSSH_TRANSIT_TEST_SERVER=required`): 5 passed: two ends meet and carry 1 MiB each way; a
  session of the layer moves to another road when the relay stops; two ends of one side never
  meet, and the client gives up within its wait; a side that knows the token alone is refused;
  two clients never take each other for the node.
- `cargo test -p podssh-cli --test node`: 4 passed, with the variable's refusal. The whole suite
  of podssh-cli passed, as `ssh node://` with a pair now goes through the race.
- Planted (`scripts/plants/t436-transit-same-side.patch`, group `host-transit`):
  `sh scripts/plant-each.sh --here t436-transit-same-side`: caught, the 1 MiB test FAILED.
- Live, short (Q65), from this cloud session's host through its proxy:
  `cargo test -p podssh-relay --test transit -- --ignored`, ten runs in a row: two ends met at
  Least Authority's relay and carried 1 MiB each way, and a session of the layer echoed 1 MiB,
  each time (2 passed, 6 s); planted there (`PODSSH_TRANSIT_TEST_PLANT=same-side`), both ends
  waited alone and the test failed, as it must. The first three runs, before them, met nobody
  within 20 s; their cause is not found, and the test now names both ends' results: T-450.
  `transit-live.yml` runs them each week and by hand.
- 2026-11-02, after (the merge of T-427): the live run of the relay role on a runner
  (`relay-live.yml`, 41407047641) showed the node dialing Least Authority's relay with the pair
  relay's own trust, so a pair whose relay has a private CA could never reach the public transit
  relay (`UnknownIssuer`). Repaired: Least Authority's relay takes the host's trust
  (`SSL_CERT_FILE`, `CaFile`, else the default stores), never `--ca-file`; a relay that
  `PODSSH_TRANSIT` names keeps the pair's (`crates/podssh-cli/src/node_transit.rs`, `trust_for`,
  with its unit test). In that run `SSL_CERT_FILE` itself named the private CA, which replaces
  each root by design, so its transit road still could not pass there.

# T-437: Piping Server, a road for a proxy that refuses the WebSocket upgrade

**Source:** the operator's ruling Q65 (2026-11-02); the research of 2026-11-02 (public
carriers).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

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

## Decision

2026-11-02 (the drafting agent), each a defensible call by `AGENTS.md`, section 2:

1. **The meeting point is the pair's secret.** The key is the HMAC of the connect token over the
   pair's name (`crates/podssh-relay/src/piping/paths.rs`): both ends hold the token (the node the
   whole pair, an operator its part), and no path shows it. The node waits at a door, a GET of one
   path of the key; a client's hello there names a random link id, with a tag of the key, and the
   link's two ways have paths of that id, each beginning with a mark that the receiver checks.
   Lost: two fixed paths, as go-piping-duplex has (one link at a time, and the link of a resume or
   a second client would meet the first on its paths); the node's identity, as the DERP road's
   ticket (the client of `node://NAME` holds the pair, not a ticket; a ticket of this road can
   come with the node's record, T-445).
2. **Unasked, the road follows a probe.** A node probes once at its start: an upgrade of its
   socket's path at the relay with no token, which the relay refuses with its own word
   (`403 reverse: forbidden`, docs/relay.md); a refusal of 400, 403, 405 or 501 in words that are
   not the relay's, or a `426`, is a refusal on the way (`crates/podssh-relay/src/piping/probe.rs`).
   Then the node serves the road alone, until the pair expires (77). A connection that ends with no
   answer, or a gateway's `5xx`, is no cue: a relay that went away, as in the CLI's tests of a
   stand-in relay, looks the same, and the road would then reach `ppng.io` from a test. A client takes the road when its pair's leg finds the
   same, and races it after the pair's road when `PODSSH_PIPING` asks. Lost: a door at `ppng.io`
   for each node always (a load on a server that one person runs, and Q65 names the road for a
   proxy that refuses the upgrade); the pair's road's own failures as the cue at the node (a
   proxy's `403` reads there as a stopped pair, and a node deletes a stored pair on it).
3. **Numbered pieces after a streamed POST with no answer.** A Piping Server answers a sender at
   once (nwtgck/piping-server:src/piping.ts), so a streamed POST with no answer within 15 s is
   held on the way; the client asks for numbered pieces from then on, and the node follows the
   hello's mode. A failed POST of a piece ends the link, as the piece may have gone or not; the
   layer sends again what was not acknowledged. Lost: an acknowledgement of each piece in the
   link, which the layer already gives.
4. **Q44 and the connections.** Over HTTP/2, which `ppng.io` takes, each end has one connection:
   the node's door and each link are streams of it, within rule 2 of `AGENTS.md`. Over HTTP/1.1,
   which a server or a proxy may impose, a link holds a connection for each way: the shape and the
   condition of Q44 (a probe found the upgrade refused; the numbered form is the fallback), which
   Q44 names for the split HTTP road (T-319) and Q65 names Piping Server for, so the road falls
   under Q44. The draft left a question for the merge: the node's door on HTTP/1.1 is one more
   connection while a session runs, which no ruling names. Decided at the merge (2026-11-02, the
   main session), within Q44 and with no question to the operator: over HTTP/1.1 the node closes
   its door while a link runs (`crates/podssh-relay/src/piping/far.rs`, one link at a time), and a
   streamed way ends each idle kept connection before it dials
   (`crates/podssh-relay/src/piping/exchange.rs`), so each end holds two connections at most.
   Lost: the door kept open on HTTP/1.1 while a session runs (a third connection, beyond Q44; a
   second client waits for the first link's end instead); one HTTP/1.1 connection for the door and
   each way in turn (a link that waits for the door's next answer).
5. **Two fallbacks in the race (the merge).** The transit relay's road (T-436) and this road are
   both last in `podssh ssh node://`'s race when unasked. A proxy that refuses the upgrade refuses
   the transit relay's WebSocket too, so the unasked Piping Server road comes after it; asked, it
   comes 250 ms after the pair's road, before the transit relay's, whose start waits for each road
   before it to fail. The node of an asked Piping Server road waits at the transit relay too,
   beside the pair's road, as the node of the pair's road does. Lost: the Piping Server road before
   the transit relay's when unasked (a load on `ppng.io` where a WebSocket passes).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test piping
```

Against nwtgck's `piping-server` and `piping-server-rust` in containers: a session carries
1 MiB each way, through the box's proxy that refuses the upgrade. Live, short (Q65): one
session through `ppng.io`. Planted: the paths swapped, and the session fails.

## Correction

2026-11-02 (the drafting agent). The Premise holds, read in the source of both servers
(docs/carriers.md, item 5 of the reverse road, [N25] and [N26]): one sender meets `?n=` receivers
(1 by default) on a path, a second gets `400`, and a sender's answer comes at once and ends once
its receiver took the body. nwtgck's server speaks HTTP/2 on its TLS port alone; the Rust server
speaks it on its plain port too, by prior knowledge.

The Prove above names no feature, and the road is behind the feature `piping`. Its servers run
as processes, named by `PODSSH_TEST_PIPING_JS` and `PODSSH_TEST_PIPING_RUST`, not in containers:
no image of either is pinned under `images/`, and `.github/workflows/piping.yml` installs both,
the Rust one by the SHA-256 that its release publishes. The box's proxy (`scripts/box/proxy.py`)
carries CONNECT and never sees an upgrade, as it does not end TLS: the harness's stand-in proxy
refuses the upgrade and holds each request's body, and the live run goes through the box's proxy
of names to show the road on `HTTPS_PROXY`. The new Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features piping --lib piping
PODSSH_TEST_PIPING_JS=piping-server PODSSH_TEST_PIPING_RUST=/path/of/piping-server \
    cargo test -p podssh-relay --features piping --test piping
cargo test -p podssh-cli --lib piping
cargo test -p podssh-relay --features piping --test piping_live -- --ignored
```

A session of the layer carries 1 MiB each way through an echo over HTTP/1.1 through nwtgck's
server, over HTTP/2 and HTTP/1.1 through the Rust server, and in numbered pieces through the
stand-in proxy that holds bodies; a client of another pair finds no node; the stand-in's refusal
of the upgrade is the road's cue. Live, short (Q65): 64 KiB each way through `ppng.io`, directly
and through the box's proxy of names (`piping.yml`). Planted: the client's two ways swapped
(`scripts/plants/t437-paths-swapped.plant`), and the test of the ends' paths and each session
fail.

## Done

2026-11-02: drafted by an agent of this session in a worktree, then merged, built and measured
here.

- The road in `crates/podssh-relay/src/piping/` (feature `piping`, which podssh-cli enables): the
  server's URL, the paths and the hello, TLS with ALPN `h2` and `http/1.1`, HTTP/1.1's framing,
  HTTP/2 on one connection with PINGs, the exchanges with a kept HTTP/1.1 connection, the
  streamed and the numbered links, the client and its `carry`, the node at its door, and the
  probe of the upgrade. The CLI: `crates/podssh-cli/src/piping_road.rs`,
  `crates/podssh-cli/src/node_piping.rs`, the dispatch in `crates/podssh-cli/src/node.rs`, and
  `node://NAME` in `crates/podssh-cli/src/ssh/`; the manual, docs/reverse.md, docs/carriers.md,
  docs/development.md; the feature in the gate's library steps; `.github/workflows/piping.yml`.
- Five defects found and repaired at the merge. The roost's tests found that the node probed
  the relay for the unasked road before it checked TARGET, so a node whose TARGET failed still
  reached the relay: the node of the pair's road now decides on the unasked road once TARGET
  passed (`crate::node_piping::unasked`), with TARGET's line, which it dials once, and only an
  asked road is the node of `node_piping::run`; the TARGET checks moved to
  `crates/podssh-cli/src/node_target.rs`, for the length of node.rs. The other four, each by a
  test against nwtgck's servers:
  nwtgck's piping-server (the server of `ppng.io`) answers neither a sender nor its receiver
  before the sender's first byte, so both ends waited for their POST's answer before sending
  their mark and fell to numbered pieces after 15 s: the mark now goes with the POST's head
  (`Http::post_stream`'s first bytes, on HTTP/1.1 and HTTP/2); piping-server-rust 0.18.0 says
  "halfway disconnected" to a sender whose receiver took the whole hello, so the client knocked
  again and the node opened one link twice ("Another receiver has been connected"): the client
  takes that answer to a hello as its delivery, and the node opens a link's id once in 120 s; the
  layer's future overflowed a test thread's stack in a debug build (`carry` holds it on the heap
  now, as does the transit road's); and the merge with T-436 put the transit relay's road and
  this one in one race (Decision 5), and the node of an asked Piping Server road waits at the
  transit relay too.
- Decision 4, decided at the merge within Q44: over HTTP/1.1 the node closes its door while a link
  runs, and a streamed way ends each idle kept connection first, so each end holds two
  connections at most.
- `cargo test -p podssh-relay --features piping --lib piping`: 18 passed.
- `cargo test -p podssh-relay --features piping --test piping`, with `PODSSH_TEST_PIPING_JS`
  (nwtgck/piping-server 1.12.9 from npm) and `PODSSH_TEST_PIPING_RUST` (piping-server-rust v0.18.0,
  its archive's SHA-256 equal to its release's `sha256sums.txt`): 6 passed: a session of the
  layer carries 1 MiB each way through an echo over HTTP/1.1 through nwtgck's server, over HTTP/2
  and over HTTP/1.1 through the Rust server, and in numbered pieces through a stand-in proxy that
  holds each body; a client of another pair finds no node; a proxy's refusal of the upgrade is
  told from the relay's own word.
- Live, short (Q65), from this cloud session's host through its proxy:
  `cargo test -p podssh-relay --features piping --test piping_live -- --ignored`, three runs: a
  session through `ppng.io` carried 64 KiB each way each time (about 4 s).
- `cargo test --no-fail-fast -p podssh-cli`: 1268 passed, 0 failed (the roost's tests found the
  order above first). Clippy with `-D warnings` on podssh-relay and podssh-cli, and on podssh-relay
  with `piping` alone: clean, after two lints repaired (`is_multiple_of`, `expect_err`).
- Planted (`sh scripts/plant-each.sh --here t437-paths-swapped`, both servers named): caught; the
  test of the ends' paths failed, and so did the three sessions through the servers.
- Left, as entries: the commands from end to end through a proxy that refuses the upgrade, and
  the box (T-451); `doctor`'s line of the road (T-435); a row of `piping.yml` in the release
  check's catalog (T-446).

# T-438: Wisp: the demo server as a forwarder, and the Wisp protocol

**Source:** the operator's ruling Q65 (2026-11-02); the research of 2026-11-02 (public
carriers).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

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

## Decision

- The protocol is spoken by podssh-ws itself, from its document, branch v2 of
  MercuryWorkshop/wisp-protocol:protocol.md, in `crates/podssh-ws/src/wisp/`. Lost: the crate `wisp-mux`
  (LGPL-3.0-only, a relinking duty on a static 0BSD binary, and a dependency tree of its own),
  and any code of wisp-server-python (AGPL-3.0), which the tests run and nothing copies.
- A Wisp server is a forwarder of the list, `wisp+wss://HOST/PATH/`, so `--forwarder`,
  `PODSSH_FORWARDER`, `Forwarder` of the settings file, `doctor --forwarder` and the fallback
  take it unchanged. Lost: a flag of its own, which would be a second road beside the list.
- One WebSocket for each session, with one stream on it, as each forwarder's session is: the
  session's end closes its WebSocket, and its lines are a forwarder's. The client multiplexes
  (`podssh_ws::wisp::Wisp::open`, tested with two streams at once) for a road that holds several
  streams later. Lost: one WebSocket shared by the sessions of a run, which no command of today
  holds open across sessions.
- The upgrade offers `Sec-WebSocket-Protocol: wisp-v2`, the value of Mercury Workshop's own
  client; a server that refuses it with HTTP 400 is dialed once more with none (rule 7, as that
  client falls back to version 1). Version 1 is spoken where the server's `CONTINUE` comes first.
- The credit is kept as the document says: the count of the last `CONTINUE`, less one for each
  `DATA`, and no `DATA` at zero. The server gives this side no credit: each stream keeps 64
  packets of the server's, then the WebSocket's reader waits for its caller.
- A path that does not end with `/` is refused (64), not amended: a Wisp server reads it as the
  older wsproxy's form, another endpoint.
- A server that requires a password or a key is refused with a `CLOSE 0x04` on stream 0: no
  credential goes in a URL, and none was asked for.
- The end of the caller's bytes sends a `CLOSE 0x02` on `ssh`'s road (the session is done), and
  none on `proxy`'s, which waits for the server's end, as Wisp has no half-close.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test wisp
```

Against the reference server (`wisp-server-python`) on the loopback: two streams at once on one
WebSocket, each with its bytes; a stream that the server closes gives its reason. Live, short
(Q65), from GitHub Actions: GitHub's banner through the demo server. Planted: the credit
ignored, and the test of flow control fails.

## Correction

The words are a table of `podssh_ws::forwarder::builtin` (`crates/podssh-ws/src/forwarder/builtin.rs`),
which `podssh_cli::forwarder` parses and whose fallback it runs
(`crates/podssh-cli/src/forwarder/fallback.rs`). Version 2 has a fifth packet, `INFO`, which opens
the connection where the upgrade offers a protocol; the demo server runs wisp-server-python, whose
version 0.9.0 speaks version 1 only (read in its source on 2026-11-02, [carriers.md](../docs/carriers.md)).

## Done

2026-11-02: drafted by an agent of this session in a worktree, then merged, built and measured
here.

- The client: `crates/podssh-ws/src/wisp/` (the packets, the opening of version 1 and 2, the
  streams with the credit, the forwarder's road); `wisp+wss://` and `wisp+ws://` in
  `crates/podssh-ws/src/forwarder/template.rs`; the word `wisp` last in
  `crates/podssh-ws/src/forwarder/builtin.rs`; `Sec-WebSocket-Protocol` offered by
  `podssh_ws::url::dial_offering`.
- `cargo test -p podssh-ws --lib`: 140 passed (the codec against byte strings written from the
  document's tables, the answer to an `INFO`, the template, the words).
- `cargo test -p podssh-ws --test wisp`, with `PODSSH_TEST_WISP_PYTHON` naming a virtualenv of
  `wisp-python==0.9.0` and `websockets==15.0.1`, and `PODSSH_TEST_WISP_REQUIRED=1`: 8 passed,
  against the stand-in of `crates/podssh-ws/tests/wisp_support/mod.rs` and two against
  wisp-server-python 0.9.0 on the loopback (two streams at once each carry their bytes; a stream
  that the server closes gives its reason).
- `cargo test -p podssh-ws --test forwarder` 5 and `--test live_forwarder` (built, its four live
  tests ignored) passed; `cargo test -p podssh-cli --test forwarder_cli` 12 (the word `wisp`
  through a stand-in of the demo server, and the demo server last in the fallback), `--lib
  forwarder` 8, and the manual's tests (`man_page`, `man_json`, `man_flag_parity`, `flag_table`)
  passed.
- Planted, `sh scripts/plant-each.sh --here t438-wisp-credit` (the credit ignored): caught, the
  test of flow control failed.
- Live, short (Q65), from this cloud session's host through its proxy:
  `cargo test -p podssh-ws --test live_forwarder -- --ignored --exact
  live_wisp_gives_github_s_version_line`: GitHub's version line through
  `wisp+wss://wisp.mercurywork.shop/` (0.7 s). The three forwarders of Q56 stay to GitHub
  Actions (`forwarder-live.yml`, by hand).
- At the merge: a lint of the tests' stand-in repaired (`is_multiple_of`), and the notes of
  `podssh ssh` split in two lists that one constant joins at compile time
  (`crates/podssh-cli/src/man/notes_ssh_more.rs`), as the file passed 500 lines; the manual came
  out byte for byte the same. Clippy with `-D warnings` on podssh-ws and podssh-cli: clean.
- `cargo test --no-fail-fast -p podssh-cli`: 1269 passed, 0 failed; `cargo test --no-fail-fast -p
  podssh-ws` (the Wisp tests against wisp-server-python): 407 passed, 0 failed.

# T-439: HTTP CONNECT to a second proxy over TLS, HTTP/1.1 and HTTP/2

**Source:** the operator's ruling Q66 (2026-11-02); the research of 2026-11-02 (standard
protocols).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

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

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test via
```

Against Caddy with forwardproxy and squid over TLS in containers, through the box's proxy:
GitHub's banner from a fixture through each, and two sessions on one HTTP/2 connection with
Caddy. Planted: the credential left out, and the `407` is said with its words.

## Done

2026-11-02: drafted by an agent in a worktree of its own, and merged, built and measured here;
the run against Caddy and squid in containers ran in GitHub Actions
(`.github/workflows/via-interop.yml`, run 41389960690 at `5b62f4e`): 12 passed, 0 failed:
sshd's banner, a session over HTTP/2's CONNECT, one over HTTP/1.1's (`PODSSH_VIA_HTTP=1.1`) and
two sessions of `podssh each` on one HTTP/2 connection through Caddy 2.11.7 with forwardproxy;
the banner and a session over HTTP/1.1 through squid's `https_port`; each proxy's `407` said
with its words when the credential is left out (exit 77); the host's own squid carrying the TLS
to each proxy by its name; `podssh doctor --via` naming Caddy and HTTP/2; and no output holding
the proxies' password. This host's containers reach Go's module proxy and Alpine's packages only
through the session's own proxy, so the whole run is the runner's.

- podssh-ws, `crates/podssh-ws/src/via/`: the URL and its credentials, the versions offered, the
  client that keeps HTTP/2's connection and falls back to HTTP/1.1, and a refusal's words
  (`mod.rs`); HTTP/1.1's CONNECT (`http1.rs`); HTTP/2's CONNECT as `AsyncRead` and `AsyncWrite`
  (`http2.rs`). podssh-cli, `crates/podssh-cli/src/via/`: the road of `ssh`, `proxy` and `pipe`'s
  `tcp:`, the section `via` of `doctor`, `--via`, `--via-auth-file`, `PODSSH_VIA`,
  `PODSSH_VIA_AUTH_FILE` and `PODSSH_VIA_HTTP`, the manual and `docs/cli.md`.
- Two repairs at the merge. A proxy with no protocol in common ends TLS with the alert
  `no_application_protocol` (rustls's and Go's servers do), where the draft expected a handshake
  with none chosen; with HTTP/2 alone asked, that alert now says "it did not choose HTTP/2 by
  ALPN (h2)". A note of the manual named HTTP/2's flag `END_STREAM`, which the manual's check
  read as a variable of podssh; it says "the end of the stream" now.
- `cargo test -p podssh-ws --test via`: 5 passed (the credential with each CONNECT and the `407`
  with its words without it; two tunnels on one TLS connection; the host's proxy carrying the
  TLS by the second proxy's name; HTTP/2's reset falling back to HTTP/1.1, and HTTP/2 alone
  refused by a proxy of HTTP/1.1; a 403, a 502 and a certificate of another name).
  `cargo test -p podssh-ws --lib via`: 9 passed. `cargo test -p podssh-cli --lib`: 542 passed;
  `--test flag_table`, `man_flag_parity`, `man_page`, `man_json`, `leading_dash`, `doctor`,
  `proxy` and `pipe_http` passed. Clippy (`-D warnings`, one needless borrow repaired) and
  `cargo fmt --check` of the packages: clean.
- Planted (`scripts/plants/t439-via-no-credential.plant`): the test of the credential failed
  with "refused CONNECT 127.0.0.1:...: 407 Proxy Authentication Required; it asks for Basic".
- The first run of `via-interop.yml` (41386992760, at the merge's push) failed on three faults
  of the script, none of podssh's: forwardproxy's module has no `cmd/caddy` at the pinned
  commit (its README's `go install` path is stale), so Caddy's container ended at once; the
  check of each proxy took a TCP connection, which Docker's own proxy of a published port
  accepts with nobody behind it; and squid ends a tunnel at the client's TLS close, which an
  empty stdin sent before sshd's banner came back. Squid's session, its `407` and the host's
  proxy to squid passed. Repaired: Caddy is built as xcaddy builds it (a main of Caddy's command
  with the plugin, at forwardproxy's commit and Caddy v2.11.7, as the 2.8.4 that forwardproxy's
  go.mod names panics at its start when Go 1.27 builds it), in a container of its own whose
  failure shows its log; each proxy must answer a TLS handshake with the run's CA, or a request,
  while its container runs; the banners keep stdin open for 3 s, as OpenSSH keeps a
  ProxyCommand's. Here, through this session's proxy (`PODSSH_VIA_BUILD_NET=host` and
  `PODSSH_VIA_BUILD_CA`), Caddy built and answered TLS; squid's container cannot install its
  package from this host, so the run goes on in Actions.

# T-440: VLESS over a WebSocket and over XHTTP

**Source:** the operator's ruling Q66 (2026-11-02); the research of 2026-11-02 (standard
protocols).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** L
**Status:** done

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

## Decision

- **A file of share links, as `--shadowsocks` reads its own.** `--vless FILE`, a private file
  (`podssh_relay::cache::read_private`), a `vless://` link on each line, the form of XTLS/Xray-core
  discussion 716 that panels and clients give out, its servers tried in order (rule 7). No message
  shows a line or an ID; a refusal names the line's number. Lost: the link on the command line,
  which argv shows; the server's URL in the flag and its ID in a second file, as `--via` does, where
  a share link holds both; a variable `PODSSH_VLESS`, as `--shadowsocks` has none either.
- **Each setting that changes the bytes and that podssh does not make is refused by its name**:
  a flow (`xtls-rprx-vision`), REALITY (`security=reality`, `pbk`), VLESS's encryption,
  `type=tcp`, and a key of XHTTP's `extra` that moves the padding, the session, the number or the
  data. `extra`'s `headers`, `xPaddingBytes`, `noGRPCHeader`, `scMaxEachPostBytes` and `mode` are
  followed; its keys that only pace or pool Xray-core's own client, or tune the server, are
  passed over. Lost: ignoring them, as the server would then wait for bytes where podssh does not
  put them and fail with no cause; reading Xray-core's JSON outbound, a whole client's
  configuration for one server.
- **XHTTP on HTTP/2 alone**: `h2` by ALPN over TLS, or HTTP/2 with prior knowledge with
  `security=none`, which Xray-core's server takes (`hub.go`, `SetUnencryptedHTTP2`); each request
  a stream of one connection. packet-up and stream-up over HTTP/1.1 need a second connection at
  once (the streamed GET down while the POSTs go up), which rule 2 allows on the split road of
  Q44 alone, and stream-one over HTTP/1.1 meets Go's server, which reads a request's whole body
  before it answers there. A server that chooses HTTP/1.1 is refused with its words (78). Lost: the
  second connection, which is the operator's (the question below).
- **`mode=auto` is packet-up**, as Xray-core's client decides with TLS and no REALITY
  (XTLS/Xray-core:transport/internet/splithttp/dialer.go), and `doctor` tries each of the three
  modes of such a link and names each that carried a session. Lost: stream-one first and
  packet-up after it, as a pipe has no answer to wait for, so a stream-one that a front end holds
  cannot be told from a target that waits for its client.
- **POSTs one at a time**, each after the 200 of the last, at most 1,000,000 bytes each, so they
  come in order and the server's queue of 30 never fills; what waits meanwhile goes in the next.
  Lost: several in flight, as Xray-core's client sends them, whose order the server restores
  (shoes's README reports that Xray-core's own uploader on HTTP/1.1 loses pipelined requests).
- **VLESS's answer is awaited, as `--shadowsocks` awaits its first chunk.** The server sends it
  with the target's first bytes, and ends the session with none for an ID that it does not know
  (`inbound.go`). An SSH session waits 10 s for it, so that a refused ID is said and the next
  server tried; a pipe of `proxy` takes the stream after 3 s with no end, as its client may speak
  first. Lost: the stream at once, where a refused ID would end SSH's handshake with no cause.
- **The tests**: the crate's against stand-ins on the loopback, h2's own server for XHTTP, as
  T-439's; Xray-core and shoes in a harness of their own (`scripts/interop-vless.sh`,
  `.github/workflows/vless-interop.yml`), their projects' release binaries pinned by version and
  SHA-256 (Xray-core v26.10.21, shoes v0.3.6, both read on 2026-11-02), fetched and checked
  (`xray run -test`, `shoes --dry-run`) in steps whose failure prints the log, and each server
  ready when it answers a TLS handshake with the run's CA while its container runs. The client is
  in `podssh-ws`, with no new dependency (h2, http, sha1 and serde_json were there), and each
  HTTP/2 stream is `--via`'s (`via::Stream`).

A question for the operator (Q67 in `TODO/PROGRESS.md`, its work T-456): **XHTTP over HTTP/1.1.**
packet-up and stream-up over HTTP/1.1 need a second connection at once, the shape of the split
road that Q44 allows on that road alone. Where a server, or a proxy on the client's side that
re-terminates TLS, speaks HTTP/1.1 alone (squid's `ssl_bump` does), this road is refused.
Recommendation: allow that second connection for XHTTP too, as another exception of rule 2,
tried only after HTTP/2 was refused. Until a ruling the refusal stands (78), and the rest of this
entry does not wait for it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test vless
```

Against Xray-core and shoes in containers: GitHub's banner from a fixture over each transport,
and `packet-up` through the box's proxy that refuses the upgrade. Planted: a wrong UUID, and
the server's refusal is said.

## Correction

2026-11-02 (the drafting agent). The Prove's "the box's proxy that refuses the upgrade": the
box's proxy (`scripts/box/proxy.py`) takes CONNECT and carries a TLS that it does not open, so
it refuses no upgrade. The run puts the refusal where a server that the user runs meets it, in a
front end: nginx over TLS and HTTP/2 in front of Xray-core, which passes no `Upgrade` header to
the WebSocket and streams XHTTP, with a plain squid as the host's proxy; sshd is the target in
place of a fixture of GitHub's banner, as T-439's run has it. A proxy on the client's side that
re-terminates TLS with HTTP/1.1 alone waits for the question of the Decision.

The Premise holds, read at Xray-core v26.10.21 (XTLS/Xray-core:proxy/vless/encoding/encoding.go,
XTLS/Xray-core:proxy/vless/inbound/inbound.go, and `hub.go`, `config.go`, `xpadding.go`,
`dialer.go`, `client.go` and `upload_queue.go` of XTLS/Xray-core:transport/internet/splithttp),
with two facts more: each XHTTP request carries a padding that the server checks, `Referer` with
a query `x_padding=` of 100 to 1000 characters, and a 400 otherwise; and the server answers with
the target's first bytes, and ends the session with no answer for an ID that it does not know.

## Done

2026-11-02: drafted by an agent in a worktree of its own (branch `worktree-agent-t440-vless`),
which built and ran nothing; merged and measured by the main session the same day.

- podssh-ws, `crates/podssh-ws/src/vless/`: the share link and its ID (`link.rs`), `extra`
  (`extra.rs`), VLESS's request and the reader of its answer (`header.rs`), the WebSocket
  (`ws.rs`), XHTTP's connection, padding and streamed modes (`xhttp.rs`), packet-up
  (`packet.rs`), the stream of two halves (`split.rs`), and the dial, the errors and the modes of
  `doctor` (`mod.rs`); `via::Stream::from_parts` for XHTTP's streams. podssh-cli,
  `crates/podssh-cli/src/vless/`: the file, the road of `ssh` in place of the relay and its
  refusals beside another road, `proxy`'s pipe, and the section `vless` of `doctor`; `--vless` in
  each table of `ssh`'s road, of `proxy` and of `doctor`, the manual (`man/notes_vless.rs`, FILES)
  and docs/cli.md.
- The merge repaired three defects that the draft could not see: the reader of the answer's
  `match` was not exhaustive (a guard does not count), a unit test's helper was shadowed by a
  local of its own name, and a test's iterator was not `mut`. The stand-in of XHTTP refused a
  stream-up POST that came before its GET (404): the client sends both at once on one connection,
  and Xray-core's `hub.go` makes the session for whichever comes first (`upsertSession`); the
  stand-in now does the same, for a packet too.
- `cargo test -p podssh-ws --test vless`: 6 passed, three runs in a row (each transport and mode,
  a wrong ID, a refused upgrade with a wrong path and HTTP/1.1, a pipe's silence, the host's
  proxy). `cargo test -p podssh-ws --lib vless`: 11 passed; `--test via`: 5 passed.
  `cargo test -p podssh-cli --lib`: 555 passed; `--test doctor`, `flag_table`, `leading_dash`,
  `man_flag_parity`, `man_json`, `man_page` and `proxy`: 13 (2 ignored), 9, 3, 6, 4, 10 and 9
  passed (cargo runs them by name, and the commit of the merge gave these counts in the order of
  its command line, which was not theirs).
  Clippy (`-D warnings`, all targets) of both packages: clean; `cargo fmt -p` of both.
- Planted (`sh scripts/plant-each.sh --here t440-vless-refusal-unsaid`): caught, exit 101, "the
  wrong ID was taken over Ws: no refusal said".
- The pins of `scripts/interop-vless.sh`: Xray-core v26.10.21's `Xray-linux-64.zip` and shoes
  v0.3.6's `shoes-x86_64-unknown-linux-musl.tar.gz`, fetched from GitHub on 2026-11-02, have the
  SHA-256 that the script pins.
- The whole suites: `cargo test --no-fail-fast -p podssh-cli`, 1290 passed, none failed (51
  ignored); `-p podssh-ws`, 424 passed, none failed (11 ignored).
- `scripts/interop-vless.sh` in `.github/workflows/vless-interop.yml`, against Xray-core
  v26.10.21, shoes v0.3.6 and nginx in containers (15 checks): runs on the push of the merge, as
  GitHub starts a new workflow by hand only from the default branch; this entry stays `partial`
  until it passes.
- Its first run (41414411915, at `33ccb11`): 5 passed, 10 failed. Each of shoes's three sessions
  passed, and so did `doctor --vless` through Xray-core to `github.com:22`; each session through
  Xray-core to `sshd.test`, in the run's private network, waited its 10 s with no answer.
  Xray-core's `freedom` outbound blackholes a private address for a VLESS inbound unless a final
  rule allows it (`getDefaultFinalRule`, `proxy/freedom/freedom.go` at v26.10.21). Shown on this
  host: Xray-core on the loopback in front of a banner, through `podssh proxy --vless`, gave no
  byte, and with `finalRules` allowing `127.0.0.0/8` gave the banner. The run's Xray-core now
  allows the private ranges, which `xray run -test` takes (and refuses an unknown action). Three
  other checks waited for 69 or 78 from `ssh`, which exits 255 for a first hop that it did not
  reach, as OpenSSH does; their words were right, and they now wait for 255. The line of a silent
  server names Xray-core's rule, as a user's own private target meets it too, and the manual and
  `docs/cli.md` say so, and that `proxy` exits 78 for HTTP/1.1 where `ssh` exits 255.
- Its run at `28cba8a` (41418123743): 15 passed, 0 failed, against Xray-core v26.10.21 (a
  WebSocket, stream-one, stream-up and packet-up; sshd's banner through `proxy --vless`; another
  ID and a server of HTTP/1.1 alone refused with their words), shoes v0.3.6 (a WebSocket,
  packet-up and stream-one), nginx in front of Xray-core (the refused upgrade names XHTTP, and
  packet-up passes), the host's squid by name, `doctor --vless`, and no output holding the ID;
  `cargo todo interop --logs` scores it 15 of the floor of 14.
- The question of the Decision is Q67 (`TODO/PROGRESS.md`); its work is T-456, blocked on it.

# T-441: wstunnel's protocol

**Source:** the operator's ruling Q66 (2026-11-02); the research of 2026-11-02 (standard
protocols).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

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

## Decision

The drafting agent's calls (2026-11-02), from wstunnel's source at v11.1.0 (2026-10-19), and at
v10.0.1 and v9.7.4 (read through the services of web.pkgforge.dev):

- **A road in place of the relay, as `--via` is** (`crates/podssh-cli/src/wstunnel/`), for
  `ssh`, each command of its road and `proxy`; beside `--relay-host`, `--relay-failover`,
  `--forwarder`, `--shadowsocks`, `--via`, `--direct`, `-4`, `-6` or a road of its own it is
  refused (64). Its resolution runs before `--via`'s, so that its flag wins over `PODSSH_VIA`, as
  each road's flag wins over another's variable. Lost: a scheme of `--via`'s URL, which would mix
  a forward proxy and a tunnel server under one flag.
- **One token for 9.1 to 11.** wstunnel's client signs its JWT with a key of each process since
  10.1 (its commit 1522882, 2024-08-26), and its server checks no signature since then; 9.1 to
  10.0 sign and check with the key `champignonfrais` of their public source. podssh signs with
  that key (`crates/podssh-ws/src/wstunnel/token.rs`), so that each server from 9.1 reads the
  token. It is a constant that each of those clients sends, no credential. Lost: a random key, as
  v11's client, which a server of 10.0 refuses with the same 400 as a wrong secret.
- **The secret file** (`--wstunnel-secret-file`, `PODSSH_WSTUNNEL_SECRET_FILE`), read as
  `--via-auth-file` is: `path-prefix PREFIX` (the server's `--restrict-http-upgrade-path-prefix`,
  or a restrictions file's `!PathPrefix`, which wstunnel's own help calls the secret),
  `credentials USER[:PASSWORD]` (Basic of the trimmed text, as `--http-upgrade-credentials`
  encodes it) or `authorization VALUE` (a restrictions file's `!Authorization`, as a header file
  of wstunnel's client gives it); or one line, the prefix alone. A prefix holds only the
  characters that a path segment holds as they are, as the server compares the raw segment. The
  URL takes no path: the prefix is the secret. With no file, wstunnel's defaults (`v1`). A secret
  over `ws://` goes to the loopback alone. Lost: the prefix in the URL (argv, `ps`); a header file
  of any headers, which no restriction of wstunnel's reads but `Authorization`.
- **The WebSocket alone.** Each server serves its WebSocket and its HTTP/2 on one port, and
  detects which; `https://` and `wts://` are refused with the scheme that the same server takes.
  Lost for now: the HTTP/2 transport (a POST with a streamed body, the JWT in `Cookie`), which
  passes only where a proxy re-terminates TLS and refuses the upgrade, as `--via`'s HTTP/2 and
  Piping Server (T-437) already do; and WebTransport, which needs UDP.
- **A key of zero for each frame's mask.** wstunnel's server calls fastwebsockets 0.10's
  `set_auto_apply_mask(websocket_mask_frame)`, false by default, which covers reads
  (`denoland/fastwebsockets:src/lib.rs`, `read_frame_inner`): a masked payload goes to the target
  as it came. A key of zero reads the same whether the server applies masks or not, and keeps the
  mask bit that RFC 6455 asks of a client
  (`crates/podssh-ws/src/session.rs`, `with_zero_mask`); the bytes are SSH's, or TLS's under
  `wss://`, which no intermediary reads. Lost: frames with no mask, as wstunnel's client sends by
  default, which an intermediary that checks the bit refuses; a fresh key, which corrupts each
  byte at a server of the defaults.
- **The session is the forwarders' carry** (`crates/podssh-ws/src/forwarder/carry.rs`), with
  the peer's name in its words, as a wstunnel server sends binary frames and Pings, and dials the
  target before its 101. Lost: a copy of its two tasks.
- **The version's words.** Each refusal is a 400 whose body names no cause: "Invalid request"
  from 10 (`bad_request`), "Invalid upgrade request" before. podssh quotes it and says what it
  can mean in that version, and that the server's log names which; exit 77, as a refusal of the
  server's (a wrong secret is the common one, and a retry repeats it). A 101 without the
  subprotocol `v1` is no wstunnel server that podssh speaks to (69), and the tries stop.
- **No `doctor` line and no `pipe` `tcp:`** in this entry: neither is in its Approach, and both
  would touch files that other drafts of M10 touch now. A user's `ProxyCommand` reaches the same
  road through `podssh proxy --wstunnel`.
- **The manual's note of `ssh`** goes in `crates/podssh-cli/src/man/notes_roads.rs`, joined
  after `notes_ssh.rs`'s at build time, as that file holds 499 lines; the rows of the flags beside
  `--via`'s (`crates/podssh-cli/src/flags/via.rs`), as `flags.rs` holds 499.
- **The test against wstunnel's own server is a harness of its own**
  (`scripts/interop-wstunnel.sh`, `.github/workflows/wstunnel-interop.yml`): the static binary
  of v11.1.0's release, checked by the SHA-256 of its `checksums.txt`, on the box's Alpine; three
  servers (the defaults on `ws://`, `--websocket-mask-frame`, and TLS with a restrictions file
  that holds the prefix and the Basic, so that no secret goes in argv); OpenSSH's sshd as the
  target in place of a fixture of GitHub's banner, as T-439's run does; and a plain squid as the
  host's proxy. The crate's test runs stand-ins that read a client as v11.1.0's and 10.0.1's
  servers do (`crates/podssh-ws/tests/wstunnel.rs`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test wstunnel
```

Against wstunnel's own server binary of the pinned version in a container: GitHub's banner from
a fixture. Planted: the wrong secret, and the refusal is said.

## Correction

2026-11-02 (the drafting agent), read in wstunnel's source: the request of a client is the same
from 9.1 to 11 but for the JWT's signature. 10.0.1 (2024-08-16) is the release that wstunnel calls
breaking, for its reverse tunnels; 10.1 (2024-08-26) stopped checking the token's signature; 9.1
gave the protocol `Tcp` its field `proxy_protocol`, which a server of 9.0 or before cannot read;
v11.0.0 (2026-09-19) changed no wire ("not a breaking change release"). So Approach 2 reads: a
server before 9.1 refuses the token in the words of 9 and before ("Invalid upgrade request"),
which podssh names, and a server that is no wstunnel of 7 or later answers without the
subprotocol `v1`, which podssh refuses with words of its own (69).

## Done

2026-11-02: drafted by an agent in a worktree of its own (branch `worktree-agent-t441-wstunnel`),
which built and ran nothing; merged onto T-440 and measured by the main session the same day.

- podssh-ws, `crates/podssh-ws/src/wstunnel/`: the server's URL, the secret file and its check,
  the error and its lines, and `open` (`mod.rs`); the JWT, its claims and the UUID (`token.rs`);
  the request and the answer in the words of its version (`upgrade.rs`); unit tests with vectors
  of Python's hmac (`tests.rs`). `RelaySession::with_zero_mask` (`session.rs`, `wire.rs`); the
  forwarders' carry names its peer (`forwarder/carry.rs`). podssh-cli,
  `crates/podssh-cli/src/wstunnel/`: the road of `ssh` and `proxy`, `--wstunnel`,
  `--wstunnel-secret-file`, `PODSSH_WSTUNNEL`, `PODSSH_WSTUNNEL_SECRET_FILE`; the manual (the
  rows, a note of `ssh` and of `proxy`, the variables, the file), `docs/cli.md`,
  `docs/architecture.md` and `docs/STATUS.md`.
- The merge met T-440, drafted beside it with no sight of it: each list of roads took both
  (the flags' tables, the transports, `proxy`'s order and the manual), the forwarders' carry kept
  T-438's tasks with T-441's peer, and `--vless` and `--wstunnel` now refuse each other (64), on
  `ssh` and on `proxy`, before a file is read; `PODSSH_WSTUNNEL` gives way to `--vless`. The
  server roads' chain moved to `crates/podssh-cli/src/ssh/servers.rs` and the note of `proxy
  --wstunnel` to `man/notes_roads.rs`, so that `ssh/resolve.rs` and `man/notes.rs` stay at 500
  lines. A row of FILES lacked its close; four `.err().expect()` became `expect_err` (clippy).
- `cargo test -p podssh-ws --test wstunnel`: 4 passed (the banner and 200 KiB back through a
  server of 11, of 10.0 that checks the signature, and one that applies masks, each frame with a
  key of zero; the prefix and the Basic sent, and a wrong secret, none, and the default each
  refused in the words of 10; the words of 9, and a 101 with no `v1`; `wss://` checked for the
  server's name). `--lib`: 158 passed; `--test forwarder`, `rfc6455` and `session`: 5, 27 and 16.
- `cargo test -p podssh-cli --lib`: 561 passed; `--test doctor`, `flag_table`, `leading_dash`,
  `man_flag_parity`, `man_json`, `man_page` and `proxy`: 13 (2 ignored), 9, 3, 6, 4, 10 and 9;
  `--test one_road` (new: `--vless` beside `--wstunnel` on `ssh` and on `proxy`, either order, is
  64 with no file read; `PODSSH_WSTUNNEL` gives way to `--vless`): 2 passed. Clippy (`-D
  warnings`, all targets) of both packages: clean; `cargo fmt -p` of both. `cargo todo interop`:
  676 ids of 50 harnesses meet the baseline.
- Planted, `sh scripts/plant-each.sh --here t441-wstunnel-wrong-secret` (the prefix of the secret
  left out of the request): caught, the 400 in the words of wstunnel 10 and later. Planted,
  `t441-vless-beside-wstunnel` (`--vless` forgets `--wstunnel`): caught, `one_road` failed.
- The pin of `scripts/interop-wstunnel.sh`: wstunnel 11.1.0's
  `wstunnel_11.1.0_linux_amd64.tar.gz`, fetched on 2026-11-02, has the SHA-256 that the script
  pins and that the release's `checksums.txt` lists.
- The whole suites: `cargo test --no-fail-fast -p podssh-cli`, 1298 passed, none failed (51
  ignored); `-p podssh-ws`, 435 passed, none failed (11 ignored).
- `scripts/interop-wstunnel.sh` in `.github/workflows/wstunnel-interop.yml`, against wstunnel
  11.1.0's own server, its first run at `28cba8a` (41418123818): 12 passed, 0 failed (its
  version; sshd's banner through `proxy --wstunnel`; a session and 1 MiB each way with equal
  digests through the server of the defaults; one with `--websocket-mask-frame`; over `wss://`
  with the path prefix and the credentials of a restrictions file; a wrong prefix and no secret,
  each the server's 400 in its version's words (77), which the server's log names; the host's
  squid by name; no output holding the secret); `cargo todo interop --logs` scores it 12 of 12.

# T-442: More public services and standard protocols that fit

**Source:** the operator's rulings Q65 and Q66 (2026-11-02): "any other ones that fit our
needs", "any other, as part of the new expansion".
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

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

## Done

2026-11-02: drafted by an agent in a worktree of its own (branch `worktree-agent-t442-carriers`),
which built, ran and measured nothing of podssh: it read the services' terms and documents, the
protocols' specifications and their servers' sources, through the services of
<https://web.pkgforge.dev/llms.txt> (read, forge, search and domain), each fact cited in
docs/carriers.md ([S1] to [S19], and [N8] and [N12] again). The main session runs
`cargo todo counts` and `cargo todo check`, and closes this entry.

What each candidate became:

| Candidate | Verdict | Where |
| --- | --- | --- |
| ntfy.sh, for pairing | fits: no account, 4,096 bytes a message, 250 a day, no upgrade (a JSON stream by GET) | T-496, on T-086 |
| Least Authority's mailbox, for pairing | fits: Winden's terms (section 1.6) cover it | T-086 already, its second mailbox |
| Syncthing's relays on 443 | does not fit: 5 of 100 on 443, each an IP literal; session mode is plain text that cannot start as TLS | docs/carriers.md, "Ruled out" |
| upterm's community server | fits: a wss:// door on 443 at both ends, with upterm's own host at the far end | T-495 |
| Yggdrasil's peers on 443 | does not fit: 26 of 365 on 443, 9 online; no Rust implementation; the peers ask for few nearby links | docs/carriers.md, "Ruled out" |
| a second Piping Server, `piping.onrender.com` | fits, as the second server | T-497 |
| HTTP Relay's demo server | does not fit: no streaming, a demo that answered 503 | docs/carriers.md, "Ruled out" |
| chatmail's iroh relays | does not fit: a mail account to learn the URL, and iroh-relay 0.35 | docs/carriers.md, "Ruled out" |
| MASQUE servers of others | does not fit: WARP is built (T-352); CONNECT-UDP carries UDP, and masque-go needs HTTP/3 | docs/carriers.md, "Ruled out" |
| chisel | fits | T-490 |
| Trojan | fits | T-491 |
| Shadowsocks 2022 | fits | T-492 |
| Outline's Shadowsocks in a WebSocket, and `ssconf://` keys | fits | T-493 |
| NaiveProxy's server | fits, through `--via` | T-494 |
| frp | fits, a reverse road through the user's frps | T-498 |
| IETF's connect-tcp | waits: draft 17, its wire still moves, and no server over HTTP/2 speaks it | T-499, parked until it is an RFC |
| Hysteria 2 | does not fit: QUIC alone, so UDP | docs/carriers.md; the question below |

The entries take T-490 to T-499, the ids that the main session gave this draft; T-496 and
T-499 are parked (`TODO/PROGRESS.md`, "Parked open work"). docs/mesh.md (section 6) and the work
order of `TODO/PROGRESS.md` name them.

A question for the operator, for the main session to number:

- **Roads over UDP, for hosts where UDP passes** (Hysteria 2, and TUIC and MASQUE over HTTP/3 of
  the same kind). The hosts of podssh's design have TCP through a proxy alone
  (docs/target-environment.md), and where UDP passes the iroh road speaks QUIC already.
  Recommendation: no entry; a road over UDP for another proxy's server waits for a tester's
  request, and docs/carriers.md keeps the reason.

Unsure, for the entries to settle: whether `piping.onrender.com` runs on Render's free tier (it
would sleep after 15 minutes with no traffic); the form of `trojan://` lines (read in the
clients that make them, T-491); frp's control connection's cipher and multiplexing (T-498).

Merged by the main session on 2026-11-02 (record only: `cargo todo counts` and `cargo todo
check`, which agree; the draft's `docs/carriers.md` applied onto the triage of the sweep by its
hunks, each placed by hand where the fuzz put it off). The operator's rulings of the same day
change three verdicts above: roads over UDP where UDP passes, Hysteria 2 among them (Q82); and
each service that needs no account and carries bytes is a last fallback, whatever its terms (Q77,
Q78), so the items above that "do not fit" for their terms or their operators come back as
entries of their own, filed apart; those that need an account, carry no stream or answer on no
port that the host reaches stay out.


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
- A node queues twice the layer's window (`crates/podssh-relay/src/reverse/layered.rs:99`).
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
**Status:** done

## Problem

A node's record at the pkarr server names its iroh home relay alone, so a client with the
node's key and no ticket finds the iroh road and no other: its DERP home and its quick tunnel's
name stay unknown.

## Premise

- `crates/podssh-iroh/src/pkarr.rs:1` says "A node's record at a server of pkarr (T-350"; read at
  `f8d15bf`, before this entry, the line went on "): its home relay, signed with", and
  `Record::of` read iroh's `EndpointInfo` alone.

## Approach

The record also names the node's DERP home and its quick tunnel's name, as records that iroh's
tools ignore; a client races each road that it names.

## Decision

2026-11-02, the draft (each call with the alternatives that lost):

- The names: podssh's roads go in a TXT of their own, `_podssh` in the node's zone, beside
  iroh's `_iroh`, in the same signed packet; its values are RFC 1464's `KEY=VALUE`, as `_iroh`'s
  are: `derp=TICKET` and `quick=NAME.trycloudflare.com`. iroh-dns 1.4.1 reads `_iroh` alone
  (`TxtAttrs::from_pkarr_signed_packet` asks `txt_records(IROH_TXT_NAME)`), so iroh's tools and
  n0's DNS pass `_podssh` by; n0's server keeps a whole packet whatever its names
  (`n0-computer/iroh:iroh-dns-server/src/http/pkarr.rs`, read on `main` through
  <https://web.pkgforge.dev/llms.txt>). Lost: more keys under `_iroh`, which iroh's reader refuses
  whole (`AttrFromString` for a key that `IrohAttr` lacks), so iroh would read no relay of a
  podssh record; iroh's `user-data=`, which iroh carries to each reader of the node as its own,
  holds 245 bytes at most, and is the application's single slot, not a list of roads.
- The DERP home is the node's DERP ticket, as the node prints it: it holds the node's DERP key
  and its server, which a client needs, and the node's identity, which a client checks against
  the record's key, so a ticket of another node is set aside. Lost: the server alone, from which
  a client cannot send (the DERP key is derived from the node's secret seed); the DERP key and
  the server in a form of their own, a second parser of what `Ticket::parse` reads.
- The packet: iroh-dns builds one name a packet (`SignedPacket::from_txt_strings`), so podssh
  builds it with simple-dns 0.12, the crate that iroh-dns builds and reads with (in the lock: no
  crate is added), signs it as pkarr signs (BEP 44's `3:seqi..e1:v..:`, the same bytes as T-350's
  forged-record test), and reads it back with iroh-dns's checked `SignedPacket::from_bytes`
  before it is put, so a fault of the signature is never sent. The `_iroh` values are the words
  that iroh-dns writes for the relay (taken from iroh's own packet), so iroh reads them as its
  own. A ticket longer than a DNS string goes in pieces of 254 bytes, which a reader of TXT
  joins again (simple-dns's `TXT::try_from(&str)` and `String::try_from(TXT)`). Lost: a DNS
  packet written by hand, a second encoder of DNS in podssh.
- What a client takes of a record: a relay that `relays::parse_url` takes, as before; a DERP
  ticket that parses and names the record's key; one label of letters, digits and `-` under
  `trycloudflare.com`, as `quick::api` takes the name from Cloudflare's API, so that a record
  never sends a client to a host outside Cloudflare's edge. Each other value is set aside, with
  its reason for `-v` and never its text, and the record keeps its other roads; a record with no
  road that passes is refused. A key of a later podssh under `_podssh` passes by in silence.
  Lost: a record refused whole for one bad value, which one bad road would cost the others.
- Who keeps the roads: a node of `--iroh --derp` names its DERP home once its DERP road is online
  and again at each move (`Online::telling`, beside `far::Roam`'s `moved`), in the record that
  it keeps by T-350's rules. A node of `--quick-tunnel` or of the DERP road alone has no iroh
  endpoint and no relay, so Q57, which gives n0's server to a node whose relays are n0's, gives
  it none: it keeps its record only at the server that `PODSSH_IROH_PKARR` names, in a build
  with the iroh road (`crates/podssh-cli/src/node_record.rs`). Lost: n0's server by default for
  them too, a change of Q57 that belongs to the operator (a question, if wanted: may a node with
  no iroh road put its record at n0's server unasked? Recommendation: yes, as the names are
  public, the quick tunnel's and tailcat's); `--quick-tunnel` with `--iroh`, a node of two
  runtimes that this entry does not need. **Ruled, Q81 (2026-11-02):** yes; such a node keeps its
  record at n0's server unless `PODSSH_IROH_PKARR` names another or `off`, which the merge wrote
  (`node_record::named`).
- One loop keeps the record (`pkarr::keep_roads`), fed by a `watch` of the roads; `pkarr::keep`
  follows the endpoint's home relay into it, and the node's other roads tell it through
  `node_record::Tell`. The record goes again when a road changes, each 5 minutes, and after a
  failure as T-350 said; its line names each road once. Lost: a second loop for a node with no
  endpoint.
- The client with the node's key alone is `podssh ssh node://NAME` of a member that the net names
  by its key (T-429; a fingerprint alone is no key to ask by). Its roads race after the roads of
  its tickets: the first once each of them failed, as T-350 asks the record only when the
  ticket's relay fails, at once when there is none; each next 250 ms after; the iroh road of the
  record only with no iroh ticket, its DERP road only with no DERP ticket given, of the net or
  kept, and not with `PODSSH_DERP=no`; never with `--no-e2e`, as the channel checks the
  member's key on each road. The record is kept 30 s, its names' life (`pkarr::TTL`), then asked
  again at the next race, so a resume after a move finds the new home. The iroh road of a record
  has the record's finder too (T-350), and a DERP home that a later record names gets a dialer
  of its own while the older one stays. Lost: a lookup before the race, which would hold the
  pair's road for up to 10 s; a lookup at each race, a request to n0's server for each resume;
  the record of a key pinned under a label with no net, which no entry asks for; the record in
  `podssh cp`, whose road to a node is the pair's alone (`crates/podssh-cli/src/ssh/node.rs`,
  `reach`), as T-453 brings it a member's name.
- The quick tunnel of a record is a link of the race (`Road::Tunnel`) on `cf://`'s own WebSocket
  (`ssh::cloudflare::open`), with no credential of Access, as a quick tunnel has none.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh
```

A record with each road is read back whole; a client with the node's key alone reaches it over
DERP when iroh is refused. Planted: the DERP record dropped, and the test fails.

## Done

2026-11-02: drafted by an agent in a worktree of its own (branch `worktree-agent-t445-record`),
which built nothing; merged and measured by the main session the same day.

- `crates/podssh-iroh/src/pkarr_record.rs`: `Roads` (what a node puts), `Record` (moved from
  `pkarr.rs`, with `derp`, `quick` and `set_aside`), `packet` and its signature, `quick_name`;
  its tests with no network in `crates/podssh-iroh/src/pkarr_record_tests.rs`.
- `crates/podssh-iroh/src/pkarr.rs`: `publish` takes `Roads`; `keep` takes the node's other roads
  (`None` for the home relay alone), `keep_roads` for a node with no endpoint.
  `crates/podssh-iroh/src/client.rs`: a record with no iroh relay is said so. podssh-iroh builds
  podssh-relay with `derp` (pure Rust), and simple-dns; its tests take crypto_box for the stand-in
  DERP server; the lock's entry of `podssh-iroh` gained the two names by hand.
- `crates/podssh-iroh/tests/record_roads.rs`: a record with each road through the stand-in server
  of pkarr, read back by podssh and by iroh's `PkarrRelayClient`; a node that keeps its record as
  its DERP road comes online at podssh-relay's stand-in DERP server, and a client with its key
  alone that races the record's iroh road (a relay where nothing listens) and DERP road, and
  gets its echo over DERP. `tests/pkarr_lookup.rs` moved to the new signatures.
- The command line: `crates/podssh-cli/src/node_record.rs` (`Tell`, `Kept`, `keep`, `alone`,
  `named`); `node_iroh.rs` keeps the record through it and tells it of the DERP home;
  `node_derp.rs` (`Online::telling`) and `node_quick.rs` keep theirs at a named server.
  `crates/podssh-cli/src/ssh/iroh/record.rs` (`record_ask`, `RecordRoads`, with unit tests), a
  stub of each in `ssh/iroh.rs` for a build with no iroh road; `ssh/roads.rs` races them
  (`Kind::Record`), `ssh/road_link.rs` has `Road::Tunnel`, `ssh/mod.rs` asks before anything
  connects; `ssh/iroh/race.rs`'s `IrohRoad` owns its race and takes a finder.
- The manual: `iroh record` in THE RELAY and `PODSSH_IROH_PKARR`
  (`crates/podssh-cli/src/man/facts/iroh_road.rs`); the notes of `node` (`--iroh`, `--derp`,
  `--quick-tunnel`), of `ssh` (node://NAME of a member) and of `net`. `docs/mesh.md` (section 3),
  `docs/design.md` (section 7) and `docs/STATUS.md` name it.
- Planted: `scripts/plants/t445-record-no-derp.patch`, the DERP home left out of the packet; the
  test of the client with the key alone must fail, waiting for it.
- The merge: applied onto `582b1bf`; its conflicts with T-428's relay behind the quick tunnel
  (`node_quick.rs`: the role and the record side by side, the optional TARGET kept),
  T-431's exit (`node_derp.rs`) and T-428's note of `node` resolved by hand, and its moved
  citations of other entries taken from `main` and remapped. Q81 (2026-11-02) applied: a node
  with no iroh road keeps its record at n0's server unless `PODSSH_IROH_PKARR` names another or
  `off` (`node_record::named`, with a unit test of the three choices), and the manual's item `iroh
  record` and the variable's row say so. Two repairs: the node's notes named
  `PODSSH_IROH_PKARR`, which a build with no iroh road does not list in ENVIRONMENT (the notes'
  check failed), so they name "its variable" and send the reader to `iroh record`; and clippy's
  `explicit_auto_deref` in `ssh/iroh/record.rs`. `derp_road`'s node now runs with
  `PODSSH_IROH_PKARR=off`, so that a test never puts a record at n0's server.
- `cargo test -p podssh-iroh`: each passed (the library 23, `keys` 3, `pkarr_lookup` 4,
  `proxy_env` 2, `record_roads` 2, `relays` 7, `road` 2, `tickets` 9, `version` 2).
- `cargo test -p podssh-cli --features iroh --lib -- ssh::iroh::record node_record`: 4 passed;
  `--lib -- node_record man` with no feature: 60 passed, and `--features iroh --lib -- man`: 59.
- `cargo test -p podssh-cli --features iroh-test --test pipe_iroh_record --test iroh_road --test
  derp_road`: 2, 2 (1 ignored) and 4 passed.
- Planted, `sh scripts/plant-each.sh --here t445-record-no-derp`: caught, "no record that names
  its DERP home within 60 s".
- Clippy with `-D warnings`, all targets: podssh-iroh with `test-relay`, podssh-cli, and
  podssh-cli with `iroh-test`: clean; `cargo fmt -p` of both.
- The whole suite, `cargo test --no-fail-fast -p podssh-cli`: 1344 passed, none failed (51
  ignored); the temporary directory held the same entries after it as before.
- Not measured: `podssh ssh node://NAME` from end to end over a record's road, a test of the
  command line with a net, the stand-ins and a node of `--iroh --derp` that this draft does not
  write.

# T-446: The release of milestone M10: betas `v1.1.0-beta.N`, then `v1.1.0`

**Source:** the operator's ruling of 2026-11-02 ("`v1.0.0` now, and the expansion after it").
**Category:** release
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** partial

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

## Done

Not done: `v1.1.0` waits for each other entry of M10. The betas so far:

2026-11-03: `v1.1.0-beta.1` is published, a prerelease at `5d95e5f`
(https://github.com/Azathothas/podssh/releases/tag/v1.1.0-beta.1, 08:31:08 UTC), by the run by
hand with `publish` on the branch `beta/v1.1.0-beta.1` at that commit (41600702626), as `main`
held newer commits, and the tag's run (41601111029). It carries `v1.0.1` and the repairs of GitHub
#112, #114 and #118 (T-586, T-588, T-593). Checked by Q88: before the tag, the gate at that commit
(run 41594979098), the release workflow by hand on it (41594987549), and the short form on the dry
run's static x86_64 binary, whose zip's SHA-256 was the artifact's digest
(`scripts/release-short.sh BINARY --net`: the version and its commit, the manual, keygen, the
iroh road and WARP's, and GitHub's banner through the live relay); after it, `update-live.yml`
(41604126246) and `release-proofs.yml` (41605128705). Twelve files: eight binaries,
`SHA256SUMS`, its signature, the provenance and the licenses.

The first run of the proofs (41604119398) failed on a defect of the proof, not of the release:
its newest release came from `gh release list`, which holds prereleases, so it expected
`v1.0.1`'s plain `podssh update` to take the beta, where a build of a release follows releases
alone, as the beta's notes say ("podssh 1.0.1 is the newest release: nothing to do"). The proof
now takes the newest release that is not a prerelease, and reaches a beta by `--version`
(`279a283`); its run again passed.

# T-447: `podssh relay serve` takes its certificate from ACME, and reads it again on SIGHUP

**Source:** the Correction of T-169 (2026-11-02), its Approach item 1, which T-169's first cut
left out.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

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

## Decision

The draft's calls, 2026-11-02:

1. The keys and the signatures of ACME are aws-lc-rs's, in the binary, as the Approach says: the
   account's ES256 JWS (the fixed form of r and s), the CSR's and the challenge certificate's
   ECDSA in DER, and each new P-256 key, as PKCS #8 from aws-lc's own source of randomness. The
   role's handshakes stay podssh-ws's, signed by p256, which reads the same PKCS #8 in PEM as it
   reads `--key`; so the test of ACME is a test of a stored key too. Lost: p256 in the binary
   (in the build already, through podssh-ws, but its keys need its `getrandom` feature, and the
   entry asked for aws-lc); ring, which rcgen's default features bring, and which compiles C.
2. The DER of the CSR and of the challenge's certificate is rcgen 0.14's, with no default
   features, now a dependency of the binary (it was a dev-dependency of the same version, and is
   in the lock): it writes RFC 8737's acmeIdentifier (`CustomExtension::new_acme_identifier`)
   as rustls-acme does, and signs through a trait that aws-lc-rs serves. It brings rcgen, yasna
   and bit-vec into the release binary, each pure Rust. Lost: the DER written by hand (two fixed
   shapes, about 150 lines of podssh's own that no CA would have read before the merge);
   instant-acme, rustls-acme and tokio-rustls-acme, each with an HTTP client of its own that does
   not take podssh's road through `HTTPS_PROXY`, and a crypto provider of rustls's (ring or
   aws-lc) beside podssh's own.
3. Each request to the CA is a connection of its own, through `HTTPS_PROXY` when it is set, with
   podssh-ws's TLS and `http::exchange`, as `podssh update` fetches a file (rule 2 of `AGENTS.md`:
   one outbound connection at a time); the nonce of each answer goes into the next request, and a
   `badNonce` is sent again with the next nonce, 8 times at most (Pebble refuses 5 % of good ones
   by default, and the harness 15 %). The trust of the directory is `--ca-file`, else the store
   that each command of podssh trusts. Lost: one connection kept alive for an order (`exchange`
   closes; an order is about 15 requests a renewal).
4. TLS-ALPN-01, on the role's own listener: its resolver (`Served`,
   `crates/podssh-ws/src/tls_server/served.rs`) gives the challenge's certificate only to a hello
   whose one protocol is `acme-tls/1`, and only for the name of the validation; the listener
   offers `acme-tls/1` after `http/1.1`, and only with `--acme`; a connection that chose it is
   closed after its handshake, as RFC 8737 asks. Lost: HTTP-01, which needs a listener on port 80
   that the user did not ask for (Q1); DNS-01, which needs a DNS provider's API and its
   credential; an acceptor of its own for each hello (tokio-rustls's `LazyConfigAcceptor`), more
   code for the same choice.
5. The state is in the cache, so that a restart serves the certificate kept and asks the CA for
   nothing (Let's Encrypt allows 5 certificates a week for one set of names): `acme/HOST-DIGEST/`
   for each directory URL (mode 0700), `account.key` made once, and `NAME.pem`, the
   certificate's key and its chain in one file (mode 0600), replaced whole by a rename; the
   directory that holds the CA's account already is taken first. `PODSSH_CACHE_DIR` names the
   place, and its `none` refuses `--acme` (78); no directory that can be made private, 73. Lost:
   `cert.pem` and `key.pem` apart, which a read between two renames would pair wrong; a flag of
   its own for the directory, which `PODSSH_CACHE_DIR` gives already.
6. The renewal: 30 days before the end, or at a third of the life left when that is shorter, as
   Let's Encrypt advises (its certificates of 6 days, and the 45 days that it plans; Pebble's of
   180 s in the harness), with a new key each time. A renewal that fails is said, and asked again after 5
   minutes, then twice as long each time up to 6 hours; the certificate of before stays. When no
   certificate is held and the first order fails, the role stops with the CA's reason (69), so
   that the user, or the supervisor that starts it again, sees it at once. Lost: ACME's renewal
   information (RFC 9773), which a later entry can add; a role that waits with no certificate,
   asking for ever, which a script that reads the exit code never sees.
7. SIGHUP reads the files again (`--cert` and `--key`, or ACME's `NAME.pem`): the pair must load,
   and its key must be its leaf's (rustls's `keys_match`, now that podssh-ws's key gives its
   public half), else the line says why and the pair of before stays; the handshakes after it
   take the new pair, and each open connection keeps its own. The role also looks at the
   modification time and the length of `--cert` and `--key` each minute, and reads them again
   when either changed: a renewal by certbot with no hook is taken, and Windows, which has no
   SIGHUP, gets this way (Ctrl-Break lost: a service has no console). SIGHUP is taken before
   the port file is written, so that a harness's SIGHUP never ends the role; it no longer stops
   the role at all. Lost: SIGHUP alone, which leaves Windows a restart; the watch of ACME's own
   file, which the role writes and serves itself.
8. The flags: `--acme NAME` in place of `--cert` and `--key` (both: 64), `--acme-directory URL`
   (Let's Encrypt's by default; its staging directory, or Pebble, for a test), and `--ca-file`
   with `serve` as the trust of that directory alone (with files it does nothing, so 64). NAME is
   a DNS name of two labels at least, lower-cased: no wildcard (TLS-ALPN-01 cannot prove one) and
   no address (RFC 8738's IP identifiers wait). A new account agrees to the CA's terms, which the
   role names as it makes the account, and gives no contact: RFC 8555 makes it optional, and Let's
   Encrypt sends no mail of expiry since 2025. A CA that asks for an external account binding
   (ZeroSSL) is refused by name.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
```

A certificate replaced on disk and SIGHUP: the next client sees the new one, and a session that
was open goes on. ACME against Pebble, Let's Encrypt's test server, in a container: a client
that trusts Pebble's root reaches the role. Planted: no reload, and the test of the new
certificate fails.

## Correction

2026-11-02 (the drafting agent). The Premise holds: `prepare` reads both files once, and the
resolver `One` gave one certificate for each hello. The Prove that runs, in place of the one
above (the reload's test is `serve_certs`, a module of `tests/relay_serve.rs`):

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
cargo test -p podssh-cli --lib -- acme:: relay_serve::
cargo test -p podssh-ws --lib tls_server
sh scripts/plant-each.sh --here t447-no-reload
sh scripts/interop-acme.sh target/debug/podssh
```

The last runs Pebble v2.10.1 and its DNS in containers of images/box's Alpine on the host's
network, and by hand or on a push in `.github/workflows/acme-interop.yml`. The renewal is 30 days
before the end, or at a third of a shorter life (Decision 6); SIGHUP comes with a watch of the
files each minute (Decision 7).

## Done

2026-11-02: drafted by an agent in a worktree, which built and ran nothing; merged and measured by
the main session the same day.

- The resolver that changes: `crates/podssh-ws/src/tls_server/served.rs` (`Served`: the pair
  served now, and the challenges of TLS-ALPN-01, each for its name and for a hello whose one
  protocol is `acme-tls/1`); `tls_server::certified`, which refuses a key that is not the
  leaf's, and `acceptor_for`, in `crates/podssh-ws/src/tls_server.rs`. No C in the library crate.
- The role: `crates/podssh-cli/src/relay_serve.rs` (the flags, SIGHUP taken before the port
  file, the watch, the lines of ACME said on stderr, a TLS-ALPN-01 connection closed after its
  handshake, the stop with 69 when the first order fails) and `relay_serve/certs.rs` (the source
  of the flags, NAME's check, the reload, `Hangups`).
- The ACME client: `crates/podssh-cli/src/acme/` (`jws.rs`, `client.rs`, `order.rs`,
  `certs.rs`, `store.rs`, and the renewals in `mod.rs`); rcgen moved to the binary's
  dependencies (`crates/podssh-cli/Cargo.toml`).
- The manual: the rows of `--acme` and `--acme-directory`, and `--cert`, `--key` and `--ca-file`
  (`crates/podssh-cli/src/flags/relay.rs`); two notes of `podssh relay`
  (`crates/podssh-cli/src/man/notes_relay.rs`), and the row of `acme/` in FILES
  (`crates/podssh-cli/src/man/data.rs`). `docs/cli.md`, `docs/relay.md`, `docs/mesh.md` (section
  4), `SECURITY.md` (the keys kept) and the row of `docs/STATUS.md`.
- `cargo test -p podssh-ws --lib tls_server`: 4 passed (the next hello takes the pair set
  last, a challenge goes to a validation of its name alone).
- `cargo test -p podssh-cli --lib -- acme:: relay_serve::`: 21 passed (RFC 7517's key gives
  the thumbprint that other JOSE libraries give; a JWS of ES256 verifies under p256 with its
  nonce, URL and `jwk` or `kid`; the CSR names its name alone and verifies; the challenge's
  certificate holds one name and a critical acmeIdentifier of the digest; a key of another pair
  is refused; the directory and the problems of RFC 8555's examples; Pebble's `badNonce`; the
  times of renewal and of retry; the store's account made once and its file replaced whole, each
  private; NAME's check and the flags).
- `cargo test -p podssh-cli --test relay_serve`: 10 passed (the reload: the first CA's pair,
  then the second's after SIGHUP while a session through `podssh proxy` goes on, and a key of
  another pair said while the second stays; the refusals of `--acme` beside `--cert`, of
  `localhost`, and of `--acme` with another subcommand).
- Planted, `sh scripts/plant-each.sh --here t447-no-reload` (the pair read and not served):
  caught, the test of SIGHUP failed.
- `sh scripts/interop-acme.sh target/debug/podssh` against Pebble v2.10.1, its 8 checks
  (`acme.issued`, `acme.private`, `acme.status`, `acme.s-client`, `acme.sighup`, `acme.kept`,
  `acme.renewed`, `acme.refused`; `scripts/interop-baseline.txt`): here, with podman, 8 passed,
  0 failed (Pebble validated TLS-ALPN-01 on the role's listener; the state private; `relay status`
  and `openssl s_client` verify the chain to Pebble's root; SIGHUP; a second start orders nothing;
  the renewal before its end; a role that Pebble cannot reach stops with 69 and Pebble's reason).
  `acme-interop.yml` runs it on GitHub on the push of the merge.
- The merge: one conflict in `crates/podssh-cli/src/relay_serve.rs` with T-428, which had moved
  the words of `--mint` into `mint_of` and `minting_for`; both kept, with this entry's source of
  certificates. Two imports of the tests were unused (clippy). `cargo fmt -p` of both packages;
  clippy with `-D warnings` on podssh-ws and podssh-cli, all targets: clean.
- `cargo test -p podssh-cli --lib`: 589 passed; `--test man_page`, `man_flag_parity`, `flag_table`
  and `man_json`: passed. The whole suites: `cargo test --no-fail-fast -p podssh-cli`, 1332 passed,
  none failed (51 ignored); `-p podssh-ws`, 437 passed, none failed (11 ignored); none left a
  directory in the temporary directory.

# T-448: The relay role mints tokens for the keys of an allowlist or of the net

**Source:** the Correction of T-169 (2026-11-02), its Approach item 2, which T-169's first cut
left out.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

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

## Decision

The draft's calls, 2026-11-02:

1. The proof answers a challenge of the role's, not a time that the client signs: no clock of
   the client's is trusted (a sandbox's clock drifts, T-345), and the role takes each challenge
   once, for a minute. A challenge is `c1.<end-ms>.<nonce>.<mac>` under the role's secret, so
   that no state waits for an answer, and only the challenges answered are kept, until their
   end. Lost: one request with a signed time, which needs a clock within a bound and a list of
   the signatures seen in it anyway.
2. When the client signs: when the answer to `{}` is `401` with a challenge, not after a read of
   `/health`: no request more for each mint at each relay, the default one too, and no race with
   a role that restarted with another `--mint`. `/health` still says who the role mints for
   (`"mint": "keys"`). Lost: the read of `/health` first, of Approach item 2.
3. The key: the client's of the cache (`client.key`), loaded or made by
   `crates/podssh-relay/src/identity/file.rs` as the end-to-end channel loads it, so that one
   line on a node's list and on a relay's lets a user in. `--client-key` of `podssh ssh` names
   the channel's key and does not reach the mint, as `MintContext` has no key and its callers
   none at hand. Lost: a key on `MintContext`, which each caller of the mint would have to give;
   a key of the relay's own, a second line for each user.
4. What is signed: a label of the purpose and its version, the `Host` that the request sends,
   the path and the challenge (`crates/podssh-relay/src/keyed.rs`), so that a signature for a
   mint makes no pair, and one for a relay no token at another; the role refuses a `Host` that is
   not the name that the connection's TLS asked for, as a relay in the middle would pass on
   another's challenge and the signature made for it. Lost: the role's names read from its
   certificate, which the role does not parse (rustls takes the chain as it is), and which a
   role behind a quick tunnel (T-428) would not hold.
5. The list: the format of `podssh node --allow` (`crates/podssh-relay/src/identity/allow.rs`),
   its routes unread; read again for each request, as a node reads its own, so that a key added
   counts at once and one taken away at the next mint. A list that cannot be read stops the
   start (78), and later each proof gets `403`, which does not name the owner's file.
6. Pairs: with `--mint keys:FILE`, `/v1/pair` takes the same proof, so that a relay for a list
   keeps no pair of a stranger's. Lost: pairs for anyone on such a relay.
7. A `403` names the key's fingerprint, which is no secret, so that the user gives the owner the
   line for the list: the first run of a client against the role says it.
8. The net's members (Approach item 1, its second half) wait for the net's document (T-429): the
   proof is the same, and `Mint` takes a second source of keys then. This entry stays `partial`
   until it does.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
```

A client whose key is on the list gets a token and a session; another key gets `403`, and a
replayed signature is refused. Planted: the signature's check skipped, and the test of the other
key fails.

## Correction

2026-11-02 (the drafting agent). Approach item 2 is done another way (Decision 2): the client
signs when the relay's answer to the contract's `{}` is `401` with a challenge, and reads no
`/health` first. The Prove that runs, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve --lib serve::
cargo test -p podssh-relay --lib keyed
cargo test -p podssh-cli --test relay_serve
sh scripts/plant-each.sh --here t448-no-signature-check
```

2026-11-02, at the merge: the net's members, the second half of Approach item 1, move to
T-455. T-429's document landed after this draft, and a member's mint needs its own calls (which
roles mint, a document read again when it changes); the keys of a list are this entry's.

## Done

2026-11-02: drafted by an agent of this session in a worktree, then merged, built and measured
here; the net's members are T-455 (Correction).

- The role: `--mint keys:FILE` (`crates/podssh-cli/src/relay_serve.rs`, the list read at the
  start and its keys said), the proof of `crates/podssh-relay/src/serve/keys.rs` for `/v1/mint`
  and `/v1/pair`, the challenges of `crates/podssh-relay/src/serve/tokens.rs`, the TLS name
  given to the role (`serve_named`), `"mint"` in `/health`.
- The client: `crates/podssh-relay/src/keyed.rs`, which the mint (`token.rs`) and the pair
  (`pair.rs`) go through; `Identity::sign` and `PublicKey::verifies`
  (`crates/podssh-relay/src/identity/mod.rs`). The manual's note, the flag's row, `docs/relay.md`
  ("Tokens for the keys of a list") and docs/mesh.md, section 4.
- `cargo test -p podssh-relay --features serve --lib serve::`: 20 passed (a key of the list
  proves itself once; another key, a forged signature, another path, another relay, another TLS
  name, a late answer and another relay's challenge are refused; a challenge is the relay's until
  its end and no token).
- `cargo test -p podssh-relay --lib keyed`: 3 passed (the message, a proof that verifies under its
  key alone, a `401` with a challenge as the one ask).
- `cargo test -p podssh-cli --test relay_serve`: 9 passed, among them a client whose key is not
  listed gets `403` that names it, and no byte; listed, it mints, carries the session and makes a
  pair; a replayed signature, a forged one and another key get `403`. `--test relay_serve_node`: 3
  passed, unchanged.
- Planted, `sh scripts/plant-each.sh --here t448-no-signature-check` (the signature's check
  skipped): caught, the test of another key, signature, relay or late answer failed.
- Clippy with `-D warnings` on podssh-relay and podssh-cli, and on podssh-relay with
  `serve,plain-ws`: clean.
- `cargo test --no-fail-fast -p podssh-cli`: 1288 passed, 0 failed; `cargo test --no-fail-fast -p
  podssh-relay --features pair,quick,derp,serve,piping`: 495 passed, 0 failed.
- The gate's libs step at `b76548c` (41411781367) failed on two directories that the unit tests of
  `serve/keys.rs` left in the temporary directory (`podssh-keys-PID-THREAD`), which the merge's
  runs had not counted. Repaired the same day: the scratch list is a guard that removes its
  directory when its test ends, pass or fail; `cargo test -p podssh-relay --features serve --lib
  serve::`, 20 passed, and none left.

# T-449: A test of the podssh-relay suite failed once in 11 runs, unnamed

**Source:** the merge of T-443 and T-444 (2026-11-02).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

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

## Correction

2026-11-02, the gate's libs step at `0b6fcdb` (41406146247) named a test of the relay suite that
fails at random: `derp_link`'s `a_node_whose_home_went_away_moves_and_a_client_of_the_old_ticket_finds_it`
waited its whole 180 s for a move, and the same commit's next push passed it. The cause, confirmed:
the DERP stand-in (`crates/podssh-relay/tests/derp_stand_in/mod.rs`) answered a client before it
registered the client's key, so the test's cut of that key, right after the client had its answer,
found no client and did nothing; planted, a delay of 200 ms between the answer and the
registration failed the test the same way at its 180 s. Repaired: the stand-in registers first;
with the same delay after its answer the test passes, and 15 runs in a row passed. Its time fits
the failure that this entry counted, which is not proven to be the same test: the loop of the
Approach still runs.

## Done

2026-11-02: `.github/workflows/suite-repeat.yml`, a suite run after run on one runner (1 to 50
runs, podssh-relay with `pair,quick,derp,serve,piping` by default), each run going on after a
failure, each log kept as an artifact, with the count of each failed test by name; its inputs are
checked before they reach a shell.

- The test is named: the gate's libs step at `0b6fcdb` named `derp_link`'s
  `a_node_whose_home_went_away_moves_and_a_client_of_the_old_ticket_finds_it`, its cause the
  stand-in's registration after its answer, repaired in `a2c418e` (the Correction).
- On a runner, after the repair: 20 runs of the whole suite (41418291280) and then 50
  (41422747538), each run passed, no test failed.
- Here, 2026-11-02: `cargo test -p podssh-relay --features pair,quick,derp,serve,piping --test
  derp_link`, 50 runs in a row, each passed (383 s in all).
- Planted, `sh scripts/plant-each.sh --here t449-derp-registered-late` (the stand-in registers
  the key 200 ms after its answer, as before the repair): caught, the named test failed after
  its 180 s.

# T-450: Three live runs of the transit road met nobody within 20 s

**Source:** the merge of T-436 (2026-11-02).
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

At the merge of T-436, the first three runs of the live tests through Least Authority's transit
relay (`cargo test -p podssh-relay --test transit -- --ignored`, from this cloud session's host)
met nobody: the node waited 20 s alone, and the client said nothing that the test kept. Each run
after them met at once: ten runs of both live tests, 20 pairs of Python's `websockets` through the
same proxy, and a node of podssh with a Python side. A carrier that misses at random leaves the
race's last road empty when it is needed.

## Premise

- The failed runs were in the first minutes of the session's use of the relay, while a build of
  podssh-cli ran on the host; the test's message named the node's result alone then, and now
  names both ends' (`no meeting: the node ..., the client ...`).

## Approach

1. Read each run of `transit-live.yml` (each week, and by hand) for a run that met nobody, and
   the two results that it names.
2. If the relay is the cause (a backend that lost a side, or a limit), the node opens its wait
   again after a bound, and the client dials again within its wait; if podssh is, repair that.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test transit -- --ignored
```

Twenty runs in a row meet, from GitHub Actions and this host; the cause, planted, fails one.

# T-451: The Piping Server road from end to end: `podssh node` and `ssh node://` behind a proxy that refuses the upgrade

**Source:** the merge of T-437 (2026-11-02).
**Category:** measurement
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

T-437's tests run the road's node and client as library calls against nwtgck's two servers, and
the live run against `ppng.io`. No test runs the commands: `podssh node`'s probe of the upgrade at
its start, its fallback to the road alone, and `podssh ssh node://NAME`'s cue from a refused
upgrade, together, through a proxy that refuses the WebSocket upgrade, nor the box like the
target sandbox with such a proxy.

## Premise

- `crates/podssh-cli/src/node_piping.rs` probes the relay's socket with no token, and serves the
  road alone where a refusal comes in words that are not the relay's; `crates/podssh-cli/src/ssh/roads.rs`
  cues the road from the pair's leg's refusal.

## Approach

1. A stand-in proxy of the tests (the one of `crates/podssh-cli/tests/stand_harness/`) that
   refuses each upgrade with a 403 of its own words, a stand-in relay behind it, and nwtgck's
   piping-server on the loopback named by `PODSSH_PIPING`.
2. `podssh node` says the road alone; `podssh ssh node://NAME 'echo ok'` runs through it; a
   resume after the Piping Server's restart.
3. The box (`scripts/test_in_box.sh`) with a proxy that ends TLS and refuses the upgrade.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_piping
```

The session runs; planted, the node's probe that reads the relay's own refusal as a proxy's, and
the node serves the pair's road alone, so the test fails.

# T-452: A node of the DERP road whose key is a member of the net starts with no `--allow`

**Source:** the merge of T-429 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The DERP road's node requires `--allow`, as a DERP server lets any key send and the channel's
allowlist is its only door. Since T-429 a node whose key is a member of the net lets the net's
members in beside `--allow`, so the net is a door too; the DERP road still refuses to start
without the file.

## Premise

- `crates/podssh-cli/src/node_derp.rs` refuses a node with no `--allow`, before it reads the net.

## Approach

1. Where the node's key is a member of the net that this host holds, the net's members are the
   door, and the node starts with no `--allow`, saying so on its first line.
2. A node of no net and no `--allow` is refused as before.

## Decision

The calls of the draft (2026-11-02), each with what lost:

- **The door is read before the key is made.** A key made now is in no net, so the node reads
  the key where it is kept with no write (`existing` in `crates/podssh-relay/src/identity/file.rs`,
  the search of `load_in` with nothing made), and asks the net whether its document names it
  (`member_door` in `crates/podssh-cli/src/net/admit.rs`): a node with no key yet, a key for this
  run only, `PODSSH_NET=no`, no net held, a document that fails its check, one that does not name
  the key and one that ended are each refused as before (64, the words of before and then the
  net's reason). Lost: loading the key first, which leaves a new key file behind each refused run,
  against "the key is made only once each check passed"; making it and removing it again, which
  races another run of the same node.
- **With no `--allow`, the door fails closed** (`members_only`): a member that the policy lets
  comes in; each other key is refused, also where the net says nothing because the node was
  removed from it or its document went away while it ran. Lost: the admission of T-429 with no
  allowlist, which lets each operator in where the net says nothing; that is right on the pair's
  road, whose relay's connect token is a door, and wrong on the DERP road, where any key sends.
- **One door for each road of the node.** The DERP node's pair's road, and the iroh node's
  channel with `--iroh --derp`, take the same closed door, as one channel serves each road and a
  session resumes on any (`doors`, with `any_key` for the DERP road). Lost: the closed door on
  the DERP road alone, which would let a session that a key opened on the pair's road with no
  check of the net resume onto the DERP road.
- **`--iroh --derp` reads the door too** (`node_derp::door` from `node_iroh.rs`), as
  `node_derp::check` no longer refuses a node with no `--allow`. Lost: keeping `--allow` needed
  there, which would make a node of both roads the only DERP node that the net cannot open.
- **The unasked road of Q50 takes the net as a door too**: a node with no pair, no `--allow`
  and a key that the net names serves the DERP road unasked. Q58 says that a node with no pair
  serves the road unasked; the allowlist was what the road needed for a door, and the net is now
  one. Lost: `--derp` alone, which would leave a member with no pair refused for "no pair is
  stored" when its net could let its members in.
- **A document that ended is no door at the start**, with the owner's remedy (`podssh net
  renew`). Lost: starting and letting nobody in until a member brings a newer document, which
  hides the fault behind a node that seems to serve; a node that runs keeps T-429's behaviour.
- **The first line says it**: the serving line ends `with no --allow, the members of the net
  NAME are its door`, no line of an allowlist follows (`who_may` would speak of a pair's connect
  token), and the net's line of T-429 follows the ticket. Lost: a line of its own, which a
  reader of the first line would miss.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test derp_road
```

A member reaches a DERP node of no `--allow` by its name; a stranger's key is refused. Planted, a
door with no member check, and the stranger's test fails.

## Done

2026-11-02: drafted by an agent in a worktree (DRAFT T-452), which built nothing; merged and
measured by the main session the same day.

- `crates/podssh-cli/src/node_derp.rs`: `Door` and `door` (the keys of `--allow`, else the net
  that names the kept key), read in `prepare` before the key is made; `check` keeps the flags'
  refusals; `unasked` takes a node whose net names its key (`net_door`); `serve` says the door on
  the serving line, and takes `doors(.., true)` for the channel and the routes of both roads.
- `crates/podssh-cli/src/net/admit.rs`: `member_door`, `members_only` (the closed door) and
  `doors`. `crates/podssh-cli/src/node_iroh.rs`: `--iroh --derp` reads the door, and its channel
  and routes take `doors(.., derp)`. `crates/podssh-relay/src/identity/file.rs`: `existing` and
  `existing_in`.
- The manual (`crates/podssh-cli/src/flags/derp.rs`, `man/notes_pair.rs`, `man/notes_net.rs`),
  `docs/cli.md`, `docs/mesh.md` (section 3) and `docs/STATUS.md`.
- The merge: applied onto `94be1bb` beside T-431's exit and T-445's record, which had touched the
  same lines: `members_only` now takes the channel's `Ask` of T-431 (so a member reaches an exit
  through the closed door as the policy lets it), the DERP node keeps T-445's record and T-431's
  exit check and `routes_of` with its fourth argument, `--iroh --derp` keeps the exit's dial; the
  draft's moved citations of other entries were taken from `main` and remapped. The plant's patch
  was made again for the new signature.
- `cargo test -p podssh-cli --features iroh-test --test derp_road`: 6 passed, among them
  `derp_net::a_member_reaches_a_derp_node_of_no_allow_by_its_name_and_a_stranger_is_refused` and
  `derp_net::a_node_of_no_net_and_no_allow_is_refused_and_a_member_with_no_pair_serves_unasked`;
  `cargo test -p podssh-relay --test identity_file`: 10 passed.
- Planted, `sh scripts/plant-each.sh --here t452-derp-door` (the closed door lets in each key that
  the net refuses): caught, "a key that the net does not name reached the node".
- Clippy with `-D warnings`, all targets: podssh-cli, podssh-cli with `iroh-test`, podssh-relay
  with `pair,serve,plain-ws,quick,derp`: clean; `cargo fmt -p` of both.
- The whole suite, `cargo test --no-fail-fast -p podssh-cli`: 1345 passed and 1 failed, the
  notes' check, as the note of `net` named `--allow` with no verb; it says `podssh node --allow`
  now, and the 59 tests of `--lib -- man` passed, with `man_page` 10, `man_json` 4 and
  `man_flag_parity` 6; the temporary directory held the same entries after it as before.
- Filed: T-550, the quick tunnel's node with the net's members as its door, which the draft named.

# T-453: `podssh cp` and `podssh sftp` reach a member of the net by its name alone

**Source:** the merge of T-429 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Since T-429 `podssh ssh NAME` reaches a member of the net by its name alone; `podssh cp` and
`podssh sftp` take it only as `node://NAME`.

## Premise

- The copies resolve their destinations through their own parser, which does not ask the net.

## Approach

1. The copies resolve `NAME:PATH` and `NAME` as `podssh ssh` does, the net first for a name with
   no dot. (Corrected below: they already do, by `ssh`'s own resolution, which stays theirs.)
2. The copies' own test of one server reads a node as that resolution reads it, so that
   `NAME:PATH` and `node://NAME:PATH` are one server for `mv` and `cp`.
3. A test through the stand-in relay proves each copy by the member's name, and the manual and
   the documents say it, with the limit that a copy takes the pair's road alone.

## Decision

The calls of the draft (2026-11-02), each with what lost:

- **The copies keep `ssh`'s resolution**: they read `NAME:PATH` with their own parser, as scp
  reads an operand, and hand `NAME` to `resolve_or_refuse`, which asks the net first. Lost: a
  lookup of the net in the operand's parser, a second copy of the resolution that would drift
  from `ssh`'s (a `Host` block, `podssh each`'s groups, `PODSSH_NET=no`).
- **One server is one node, however it is named**: `Remote::same_server` asks
  `crate::ssh::node::destination` for each side's node, after a test with no net for two operands
  typed the same. Lost: marking a member's operand as a node in the parser, which is the second
  copy above; leaving the test as it was, by which `mv NAME:a node://NAME:b` copies through this
  host and removes the source, where the server could rename it, and `mv NAME:a node://NAME:a` is
  not refused as one file before anything connects.
- **A copy keeps the pair's road alone** (`crates/podssh-cli/src/ssh/node.rs:350` says "the
  pair's road is its only one"), and the manual says so. Lost: racing the net's iroh and DERP
  tickets for a copy as `ssh` races them, which needs `roads::connect` to give a stream in place
  of running SSH itself: more than this entry's effort, in a file of 463 of its 500 lines; it is
  the merge's to file as an entry of its own.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test net
```

`podssh cp FILE lab:/tmp/` and `podssh sftp lab` reach the member `lab` through the stand-in
relay. Planted, the net's lookup skipped, and the test fails.

## Correction

The copies do ask the net (read 2026-11-02). Each reads its operand with its own parser
(`crates/podssh-cli/src/cp/operand.rs:114`), and hands the server to `ssh`'s resolution
(`crates/podssh-cli/src/cp/mod.rs:299`, `crates/podssh-cli/src/sftp/mod.rs:216`,
`crates/podssh-cli/src/edit/mod.rs:153`), which reads the destination's node before its host
(`crates/podssh-cli/src/ssh/resolve.rs:146`), and a name alone there in the net
(`crates/podssh-cli/src/ssh/node.rs:44` says "crate::net::lookup::bare(text)"); the copy's link then reaches `Transport::Node` through the pair
(`crates/podssh-cli/src/cp/link.rs:161-162`). So `podssh cp FILE lab:PATH` and `podssh sftp lab`
already resolve to the member's node. What was missing: a test that proves it, the manual's and
the documents' words, and the copies' own test of one server, which compared the operands as
typed (`crates/podssh-cli/src/cp/operand.rs`, lines 59-64 at `f8d15bf`), so that `lab:` and
`node://lab:` were two servers. The Approach above is corrected to match.

## Done

Drafted 2026-11-02 (DRAFT T-453), which built nothing; merged and measured by the main session the
same day.

- `crates/podssh-cli/src/cp/operand.rs`: `same_server` takes a member by its name and
  `node://NAME` for one node, by `ssh`'s resolution (`node_name`), after a test with no net for
  operands typed the same; the module's words say how a member's name is read.
- Test: `crates/podssh-cli/tests/net_copy/mod.rs`, a module of `tests/net.rs`: three ends on the
  stand-in relay, the node `lab` with no `--allow`, and the member `a`; by the name alone, `cp`
  up and down, `scp` up and `sftp`'s put and get agree with the disk; `mv tester@lab:F
  node://tester@lab:G` is the server's rename, with no word of two hosts, and `mv` of one file
  named both ways is refused (64) and keeps it. Each run within 180 s.
- Planted: `scripts/plants/t453-copy-name.plant` (the net's lookup of a name alone skipped in
  `ssh`'s resolution; the test must fail with "the copy up by the member's name alone"). It
  needs an `sftp-server` in the image of its group, else the test does not run.
- The manual (`crates/podssh-cli/src/man/notes.rs`, the notes of `cp`, `scp` and `sftp`;
  `man/notes_net.rs`), `docs/cli.md` ("`podssh cp`", "`podssh scp` and `podssh sftp`", "`podssh
  net`"), `docs/mesh.md` (sections 1 and 3) and `docs/STATUS.md`; the citations of the files
  changed moved by a line diff against the draft's parent, as `cargo todo remap` moves them: to
  be checked with `cargo todo check` at the merge.
- The merge: applied onto `a88524b` beside T-445's text of the net's notes (the record of
  pkarr) and T-431's notes of `exit`, which it kept; the draft's moved citations of other entries
  were taken from `main` and remapped.
- `cargo test -p podssh-cli --test net`: 8 passed, among them
  `net_copy::copies_reach_a_member_by_its_name_alone`, against OpenSSH's
  `/usr/lib/openssh/sftp-server`.
- Planted, `sh scripts/plant-each.sh --here t453-copy-name`: caught, "the copy up by the member's
  name alone".
- Clippy with `-D warnings` of podssh-cli, all targets: clean; `cargo fmt -p podssh-cli`.
- The whole suite, `cargo test --no-fail-fast -p podssh-cli`: 1347 passed, none failed (51
  ignored); the temporary directory held the same entries after it as before.
- Filed: T-551, the copies' race of the roads that the net names, which the draft named (a copy
  reaches a node on its pair's road alone, where `podssh ssh NAME` races the iroh and DERP
  tickets).
- 2026-11-03, `plants.yml` at `3bb42ea` (run 41563969423): `t453-copy-name` missed, as the build
  image has no Python and the test said it did not run; the plant installs Python, openssl and
  OpenSSH's sftp-server first since then, and in the build image `sh scripts/plant-each.sh
  t453-copy-name`: caught ("the copy up by the member's name alone").

# T-454: The relay role brakes `/v1/mint` and `/v1/pair` for each address

**Source:** the merge of T-427 (2026-11-02); T-169's Approach, which promised it.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh relay serve` mints a token, and makes a pair, for each request that its `--mint` allows,
as fast as they come. T-169's Approach named a brake of 120 requests a minute for each address,
which neither T-169 nor T-427 built, so one client can fill the role's table of pairs or spend
its CPU on tokens.

## Premise

- `crates/podssh-relay/src/serve/mod.rs` answers `/v1/mint` and `/v1/pair` with no count of the
  requests of an address.

## Approach

1. A count for each address over a sliding minute, kept small (the oldest addresses dropped
   first); past 120, `429` with `Retry-After`, as the contract's client reads it.
2. The same for the reverse road's `/v1/pair`; `/health` and the forward road unbraked.

## Decision

The draft's calls, 2026-11-02:

1. The count: for each address, the times of the requests let through in the last minute, 120 at
   most, so that `Retry-After` is the wait itself and the first request after it passes
   (`crates/podssh-relay/src/serve/brake.rs:105`). Only a request let through adds a time: a
   client that asks again too soon is told the same end, never a later one. Lost: a minute that
   starts again (240 requests across its edge); two counts weighted by their overlap, three
   numbers an address, whose wait is an estimate, so a client told 60 s could meet a second
   `429`.
2. `/v1/mint` and `/v1/pair` share one count, as on the default relay
   (`crates/podssh-relay/src/pair.rs:96` says "the brake that pairs share with mints"; the
   contract's limits, `docs/relay.md`, "Limits that users see": "mint, pair, upgrades with no
   token"). Each request at the two paths counts, whatever its answer: a keyed mint's `401`
   (T-448), a `403`, `--mint nobody`'s `503`. Lost: a count for each path, which lets one client
   make 120 pairs and 120 tokens a minute.
3. Not braked, as the Approach says: `/health`, `/relays.json`, `/trace`, `/llms-full.txt` and
   each socket of both roads, which needs a token or a pair that the brake let through and is
   checked with a MAC or a digest and no state. Lost: a brake of the upgrades with no token, as
   the default relay counts them: the role's refusal of one costs less than the count.
4. The address: the listener's TCP peer (`crates/podssh-cli/src/relay_serve.rs:197`), never a
   header, which each client of a listener writes, and would make up anew for each request.
   Behind the quick tunnel (T-428) the peer is Cloudflare's edge, so the hook for T-428 is
   `serve::serve_from(stream, cfg, sni, from)` (`crates/podssh-relay/src/serve/mod.rs:158`),
   with `from` read by `brake::edge_visitor` (`crates/podssh-relay/src/serve/brake.rs:52`) from
   the `cf-connecting-ip` of the edge's own request, which reaches the node only on the
   connection that podssh dialed to the edge. Lost: the role reading that header itself when a
   switch of `Config` says it sits behind the tunnel, a switch that a listener could be given by
   mistake; a flag `--trust-header NAME` for a role behind a reverse proxy of the owner's, which
   trusts each client that reaches the listener around the proxy, for a deployment that the
   record does not hold (the role ends TLS itself). Cloudflare's page of HTTP headers, read
   2026-11-02, says that `CF-Connecting-IP` "provides the client IP address connecting to
   Cloudflare to the origin web server", and not whether the edge replaces a value that the
   visitor sent: T-428's run through the edge should show it.
5. An IPv6 address counts by its first 64 bits, as a host is commonly given a /64; an IPv4
   address in IPv6's form as the IPv4 one. Lost: each IPv6 address apart, which a host with a /64
   escapes; a /48, which may hold many users of one site.
6. A request whose caller gives no address (`serve_connection`, `serve_named`) shares one count
   with each other such request: a road that loses the address is braked as a whole, never not
   at all. Lost: no brake for them.
7. The bound: 4096 addresses, the bound of the table of pairs, each with 120 times of 8 bytes at
   most (under 4 MiB in all). A new address that meets a full table first forgets each address
   whose minute is over, then the one whose last request let through is the oldest
   (`crates/podssh-relay/src/serve/brake.rs:186`): a scan of 4096 counts at most, and only then.
   Lost: a list kept in order, more code for no measured need.
8. The clock: monotonic, the milliseconds since the role's start, and a `brake::Clock` that a test
   sets by hand, so that no test waits a minute and a step of the wall clock neither frees an
   address nor holds one. Lost: tokio's paused clock, which moves on to the next timer while the
   test's request waits on the role, and would fire the role's own waits; the wall clock of the
   tokens (`tokens::now_ms`).
9. The answer: `429` with `Retry-After` in whole seconds, rounded up, 1 at least, the form that
   podssh's client reads (`crates/podssh-relay/src/token.rs:210`, and `pair.rs` the same) and says
   ("retry in N s"); its words name the path, the limit and the wait. The request's body is read
   first, as for each answer of the role. The first refusal of an address since it was last let
   through is one line of the role's events, which does not name the address. Lost: a line for
   each refusal, a flood of stdout under a flood of requests; the address in the line, as the
   owner's stdout is often a log.
10. No flag: 120 is the contract's figure, which each client of the default relay meets; a
    `Brake` takes other numbers for a test. Lost: `--brake N`, which nobody asked for.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve --lib serve::
```

The 121st mint of an address within a minute is a `429`, another address's is not, and the
first after the minute passes. Planted, the brake removed, and the test fails.

## Correction

2026-11-02 (the drafting agent). The Premise holds; the Approach needs two facts that it does not
name. `/v1/pair` is answered in the reverse road, where `serve/mod.rs` routes it:
`crates/podssh-relay/src/serve/reverse/mod.rs:151` says "async fn pair". And the role had no
address to count by: at `33ccb11`,
`podssh relay serve` dropped the peer of each connection that it accepted
(`let Ok((tcp, _)) = accepted` in `crates/podssh-cli/src/relay_serve.rs`). So the brake stands in
the role's dispatch, before both paths (`crates/podssh-relay/src/serve/mod.rs:171`), and
`serve_from` takes the address, which the listener gives. The Prove that runs, in place of the
one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve --lib serve::
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_contract --test relay_serve_reverse
cargo test -p podssh-cli --test relay_serve --test relay_serve_node
sh scripts/plant-each.sh --here t454-no-brake
```

## Done

2026-11-02: drafted by an agent in a worktree, which built and ran nothing; merged and measured by
the main session the same day.

- The brake: `crates/podssh-relay/src/serve/brake.rs` (the count of each address, its bound, the
  clock, `edge_visitor` for T-428) and its tests, `crates/podssh-relay/src/serve/brake_tests.rs`;
  in `crates/podssh-relay/src/serve/mod.rs`, `Config::brake`, `serve_from`, and the `429` before
  `/v1/mint` and `/v1/pair`; `podssh relay serve` gives the TCP peer
  (`crates/podssh-cli/src/relay_serve.rs`), and so does the harness of the role's tests
  (`crates/podssh-relay/tests/role_harness/mod.rs`).
- The manual's note of `podssh relay` (`crates/podssh-cli/src/man/notes_relay.rs`), `docs/relay.md`
  ("The relay role's brake"), docs/mesh.md, section 4, and the row of `docs/STATUS.md`.
- `cargo test -p podssh-relay --features serve --lib serve::`: 25 passed (5 tests more: the
  121st request of an address waits until its oldest is a minute old, sliding, and a refusal is
  not counted; an IPv6 address by its /64, a mapped IPv4 one as IPv4, the requests with no
  address in one count; the bound of addresses, the least lately heard forgotten first; the paths
  braked and the edge's visitor; through the role and podssh's own HTTP client, the 121st mint of
  an address is a `429` with `Retry-After: 60`, a pair of it too, another address's mint is a
  `200`, `/health` and a `/connect/` with no token get their own answers, one line is said, and
  the first mint and pair after the minute pass).
- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_contract --test
  relay_serve_reverse`, and `cargo test -p podssh-cli --test relay_serve --test
  relay_serve_node`: 10, 3, 10 and 3 passed (unchanged tests, the role now given each peer).
- Planted, `sh scripts/plant-each.sh --here t454-no-brake` (the brake skipped): caught.
- Clippy with `-D warnings` on podssh-relay with `serve,plain-ws,quick`, and on podssh-cli with
  podssh-relay, all targets: clean; `cargo fmt -p` of both.
- The merge met T-428, drafted beside it: the role behind a quick tunnel served each request with
  no address, so each visitor of the tunnel would have shared one count. `Origin::connect` now
  takes the visitor that the edge names in `CF-Connecting-IP` (`quick::origin::visitor_of`, over
  HTTP/2 and over QUIC), and the role behind the tunnel counts it (`serve::behind`). `cargo test
  -p podssh-relay --features quick,serve --lib -- serve::behind quick::origin`: 12 passed, among
  them two visitors that count apart and the header's forms; planted, the visitor dropped
  (`sh scripts/plant-each.sh --here t454-edge-visitor-dropped`): caught. The node's role and the
  tests' configurations take the brake; `quick_relay` 4 and `quick_relay_quic` 4 passed.
- The whole suites: `cargo test --no-fail-fast -p podssh-cli`, 1332 passed, none failed (51
  ignored); `-p podssh-relay --features pair,quick,derp,serve,piping`, 516 passed, none failed (22
  ignored); none left a directory.

# T-455: The relay role mints for the members of the net

**Source:** the merge of T-448 (2026-11-02), the second half of its Approach item 1.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh relay serve --mint keys:FILE` mints for the keys of a list (T-448). An owner of a net
(T-429) who runs the role for the net's nodes keeps a second list by hand, which drifts from the
net's document.

## Premise

- `crates/podssh-relay/src/serve/keys.rs` checks a proof against the keys of one list, read at the
  start; `crates/podssh-cli/src/net/` holds the net's document of the host.

## Approach

1. `--mint net`, and `keys:FILE` beside it: a member of the net that the host holds proves itself
   by the same signature of T-448; a member that the owner removed is refused from the document's
   next serial on, read again when it changes.
2. Which roles of a member mint is the net's policy's (T-430): until then, each member.

## Decision

The draft's calls, 2026-11-03, each with what lost:

1. **The policy decides, with a word of its own** (Approach item 2: T-430 is done, so "until then"
   has passed). `relay:NODE` names the relay role behind NODE's quick tunnel, `relay:*` each relay
   role of the net, `podssh relay serve`'s too, and `*` reaches them as it reaches each thing; with
   no policy each member mints, as each member reaches each. A relay's forward road lends its
   host's egress, as an exit does, so the owner says who may use it as `exit:NODE` says who may go
   out; this is Tailscale's grant of `tailscale.com/cap/relay` for a peer relay. Neither word opens
   a door of NODE (`Want::AnyOf` is not reached by it), and a word that a podssh of before does not
   read allows nothing there. Lost: each member always, which leaves the owner no say over a
   relay's egress; the member's roles (`node`, `exit`, ...), which say what a member offers the
   net, not what it may use; a rule to NODE as a node, which would let a member that may use the
   relay into the node's services too.
2. **`podssh relay serve` has no name in the net**: it has no key of its own (its TLS key is a
   certificate's), so only `relay:*` and `*` name it; the node of `--quick-tunnel --relay` names
   itself by its node key, which the net names. Lost: the cache's `client.key` as the role's key,
   which would make a key at the start of a role that needs none, and tie the role's name to the
   client of the host; a flag that names the role's member, a word more for a case that
   `relay:*` covers.
3. **The words of `--mint`**: `net`, and `net,keys:FILE` for both, FILE the rest of the word, so a
   path may hold commas. Lost: a second `--mint`, which clap's single value overrides; `keys:FILE,net`,
   whose FILE would end at a comma.
4. **The document is read, and its owner's signature checked, for each request**, as the node's
   door reads it for each session (`store::held`), so a member removed counts from that serial on
   and nothing caches a stale one. A mint is braked at 120 a minute for each address (T-454), so the
   cost of an SSHSIG's check stays small. Lost: a copy kept until the file's time changes, a second
   reading of the store that could disagree with the node's.
5. **The signature is checked before whom the key is.** The net's refusal names the net and the
   member, and a member's key is public: before, anyone could send a member's key with no
   signature and read its policy's words. The list's refusal of T-448 is unchanged in its words,
   and now comes after the signature too. A key that is no member hears neither the net's name nor
   its members, only its key and the document's serial; a member, the policy's words. Lost: the
   order of T-448, which named the list's refusal first, before the signature's.
6. **A token minted before a removal lives on**, until its end or the role's stop, as a token of a
   list's key does (T-448, Decision 5): the contract's token, `ephm1.<expiry>.forward.<mac>`, names
   no key, so the role cannot ask the net again at the upgrade. Lost: a table of the tokens of each
   key, kept in the role and checked at each upgrade, a second state to bound and lose at a
   restart, for a gap of 72 h at most that a restart of the role closes.
7. **A net that the host does not hold, that fails its check, that ended, or `PODSSH_NET=no`, stops
   the start (78)**, as a list that cannot be read does; once running, such a net gives each request
   a `403` that names no file, and `podssh net ls` on the host says why. The node's role is made
   after its key is loaded, so that `relay:NAME` names it; its word is checked before (64), so a
   usage error still comes before anything is made.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
```

A member mints and pairs; a stranger, and a member removed by a newer document, get `403`.
Planted, the member check skipped, and the stranger's test fails.

## Correction

2026-11-03 (the drafting agent). The Premise's first point is wrong in one part: the role reads the
list of `keys:FILE` again for each request (`crates/podssh-relay/src/serve/keys.rs`, `Whom::admits`,
before this change `Allowlist::read` in `prove`), and only the binary reads it once at the start,
to say its keys and refuse one that cannot be read (`crates/podssh-cli/src/relay_serve.rs`,
`list_shown`). The second holds: `crates/podssh-cli/src/net/` holds the host's document
(`store::held`). The Approach is unchanged, and item 2 is done by the policy's word (Decision 1).
The Prove that runs, beside the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve --lib serve::
cargo test -p podssh-cli --lib net::
cargo test -p podssh-cli --test node_quick_relay --test net
sh scripts/plant-each.sh --here t455-member-check-skipped
sh scripts/plant-each.sh --here t448-no-signature-check
```

## Done

2026-11-03: drafted by an agent in a worktree; merged and measured on this machine the same day.

- The library: `Mint::Net` and the trait `keys::Members`, which the binary answers; `keys::Whom`,
  the list, the net or both; the signature checked before whom the key is; `"mint": "net"` or
  `"net,keys"` in `/health`; the event names the member (`crates/podssh-relay/src/serve/keys.rs`,
  `serve/mod.rs`). The plant `t448-no-signature-check` moved with its lines.
- The binary: `crates/podssh-cli/src/net/mint.rs` (the verdict, the start's line), the words
  `relay:NODE` and `relay:*` of the policy (`net/policy.rs`, `net/policy_words.rs`) and of `policy
  check` (`net/policy_cmd.rs`), `--mint net` and `net,keys:FILE` (`relay_serve.rs`,
  `node_quick_relay.rs`, `node_quick.rs`); the flag rows of `relay` and `node`; the manual's notes
  of `relay`, `node` and `net`; `docs/relay.md` ("Tokens for the members of the net"),
  `docs/mesh.md`, `docs/cli.md`.
- The tests: `cargo test -p podssh-relay --features serve --lib serve::keys` (a member mints, a
  stranger hears the net only by its own signature, the list and the net beside it): passed,
  with `serve::` 29. `cargo test -p podssh-cli --lib net::` (`net::mint`, 3; `net::policy_tests`, the
  words of a relay): passed, `--lib` 794. `cargo test -p podssh-cli --test relay_serve` (`serve_net`: a
  member mints and pairs, a stranger gets `403` with its key and no name of the net, the member
  removed by serial 3 gets `403`; a host with no net, and `PODSSH_NET=no`, stop the start with 78;
  the words of `--mint some`): 12 passed. `cargo test -p podssh-cli --test node_quick_relay`
  (`--mint net` on a host with no net, 78; the new words of `--mint everyone`): 3 passed.
- Planted, `sh scripts/plant-each.sh --here t455-member-check-skipped` (a stranger taken as the
  net's first member): caught; `t448-no-signature-check`, again on its moved lines: caught.
- Clippy with `-D warnings` and `cargo fmt --check` of both crates: clean.

What the merge repaired (2026-11-03):

- The node of `--quick-tunnel --relay` built its role after its key, so that `relay:NAME` names it,
  and so read the list of `--mint keys:FILE` after the check of `PODSSH_OFFLINE`: a list that cannot
  be read gave 69 where `a_list_that_cannot_be_read_stops_the_start` asks 78. The list and the net
  are now read before anything else (`node_quick_relay::precheck`), and the role is still built
  after the key.
- The test harness's relay role always passed `--mint anyone`, and `serve_net` named its own
  `--mint`, which the parser refuses twice: the harness passes its default only when the test names
  none (`throughput_harness/cells.rs`).
- Twelve plants had a SETUP of `apk add` alone, which a host with no apk refuses, so `--here` missed
  them (this one among them): each runs `apk` only where it exists, as in the build image.
- `relay_serve_contract` 10 and `relay_serve_reverse` 4 passed with the new `Mint`.

# T-456: XHTTP over HTTP/1.1, on a second connection

**Source:** the merge of T-440 (2026-11-02), its question for the operator (Q67).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

`--vless` refuses XHTTP where the server, or a front end that re-terminates TLS (squid's
`ssl_bump`), speaks HTTP/1.1 alone (exit 78). Xray-core's packet-up and stream-up over HTTP/1.1
carry the upload and the download on two connections at once: a second connection that rule 2 of
`AGENTS.md` does not allow this road.

## Premise

- `crates/podssh-ws/src/vless/xhttp.rs:19-21` says why HTTP/1.1 is refused, and
  `crates/podssh-ws/src/vless/xhttp.rs:76-82` refuses a server that did not choose `h2` by ALPN.
- Q44 (`docs/decisions.md`) allows the second connection of the split HTTP road alone.

## Approach

1. With a ruling for it: once HTTP/2 was refused, packet-up on HTTP/1.1, the GET of the download
   on one connection and the POSTs of the upload on a second, each kept alive; stream-up the same
   with one chunked POST.
2. stream-one stays refused on HTTP/1.1: Go's server reads a whole body before it answers.
3. The line of `doctor --vless` names the second connection when it opens one.

## Decision

The operator ruled Q67 (2026-11-02, `docs/decisions.md`): XHTTP over HTTP/1.1 may open its second
connection, another exception of rule 2 of `AGENTS.md`, tried only after HTTP/2 was refused, to the
same server, and named by `doctor --vless`. The Blocker that waited for it is gone.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test vless
```

The stand-in of HTTP/1.1 carries a session over packet-up on two connections; `scripts/interop-vless.sh`'s
server of HTTP/1.1 alone (Xray-core's port with `alpn` `http/1.1`) carries one, where its check of a
refusal stands today. Planted, the second connection not opened, and the session fails.

# T-457: The relay role dials its targets through the host's `HTTPS_PROXY`

**Source:** the merge of T-428 (2026-11-02), its drafting agent's note.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The relay role dials each target of its forward road from its host directly, as on a listener.
Behind a quick tunnel (T-428) the role runs on hosts whose only way out may be an HTTP CONNECT
proxy: there its forward road answers `502` for each target, while its reverse road, which dials
nothing, works.

## Premise

- `crates/podssh-relay/src/serve/forward.rs:140` dials the resolved addresses with
  `TcpStream::connect`, and `crates/podssh-relay/src/serve/docs.rs:109` does the same for
  `/trace`; neither reads `HTTPS_PROXY`.
- Rule 2 of `AGENTS.md`: one outbound connection, through `HTTPS_PROXY` when it is set.

## Approach

1. Where `HTTPS_PROXY` is set (and `NO_PROXY` does not name the target), the role dials each
   target through it with a CONNECT to `HOST:PORT`, as the client dials its relay, and carries
   the bytes of the tunnel; a proxy's refusal is the role's `502` with its status said.
2. The role's policy (private addresses refused unless `--allow-private`) checks the name as it
   resolves on the role's host before the CONNECT, and the proxy's own answer is the last word;
   the Decision says what a proxy that resolves the name otherwise means for that check.
3. `/trace` reports the proxy's leg as it is.

## Decision

The draft's calls, 2026-11-03, each with what lost:

1. **The proxy is asked for each checked address, never for the name** (Approach item 2's
   question). The role resolves the name on its host, checks each address by its policy, and sends
   `CONNECT ADDR:PORT` for each in turn, so Approach item 1's `HOST:PORT` is the address that was
   checked: a proxy whose resolver answers otherwise (its own DNS, a split horizon inside a company,
   a name that rebinds between the two lookups) reaches nothing that the policy did not check, as
   the exit of T-431 dials its addresses. Lost: the name after the check, which leaves the check to
   the proxy's resolver, so that a name of an attacker's that rebinds reaches the proxy's private
   network; the name where this host cannot resolve it, which checks nothing at all.
2. **Where nothing is checked, the name goes as it came.** With `--allow-private` the policy checks
   no address, so the role sends `CONNECT HOST:PORT` and the proxy resolves it, as podssh's client
   gives the proxy its relay's name: a host with no DNS, as the target environment's
   (`docs/target-environment.md`), reaches each target that its proxy reaches. With `?family=4|6`
   the role resolves it, as a proxy takes no family. Lost: a resolution here always, which a host
   with no DNS cannot make; a flag of its own for the name, a word more for what `--allow-private`
   already says.
3. **The variables are the client's**, podssh-ws's `PROXY_VARS` and `NO_PROXY_VARS`, the lower-case
   name first and an empty value unset, read once as the role starts, so that a proxy that cannot be
   read stops the start (78) and the first line names the proxy by its host and port. SOCKS5
   (`ALL_PROXY=socks5h://...`) comes with them, as podssh-ws dials either. The loopback goes
   directly, as no proxy reaches this host's loopback (the client's rule, from podbox's `405`), and
   `NO_PROXY` is matched against the name and against each address. Lost: a read for each dial, for
   a host's environment that does not change while the role runs.
4. **The egress is the role's configuration** (`serve::Config::egress`), which the binary takes from
   the host's variables and a test from its stand-in proxy. Lost: the library reading the
   environment at each dial, which a test could not set without the process's variables, shared by
   each test that runs at once.
5. **A refusal is the role's `502`, with the proxy's status** (Approach item 1), in words that say
   what the proxy answered and never where it is: the proxy of a host is often an address of the
   host's own network, which a client of a role that mints for anyone is not to learn. The role's
   own line (`proxy: the proxy HOST:PORT refused CONNECT ...`) names it for the owner, never its
   credentials, which `Proxy`'s `Display` and `Debug` never show. The proxy's answer is the last
   word: what it lets through is the role's session. Lost: podssh-ws's words as they are, which name
   the proxy's address; no line for the owner.
6. **`/trace` names the leg** (Approach item 3): `"road": "proxy"` and `"proxy": "http"` or
   `"socks5"`, the address asked of the proxy in `dialed` (the name, with `address_family` null,
   where the proxy resolved it), and the proxy's refusal in `error`. `podssh relay trace` prints
   `road proxy` with no change. Lost: the proxy's place in the answer (item 5).
7. **Rule 2 of `AGENTS.md`**: each forward session of the role is one connection, now through the
   proxy where one is set; nothing new listens, and the node behind a quick tunnel takes the same
   proxy for its targets as for its dial of the edge.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_contract
```

Through a stand-in proxy of the tests: the forward road's target is reached by a CONNECT, and the
proxy's 403 is the role's 502 with its status. Planted: the proxy skipped, and the test of the
CONNECT fails.

## Correction

2026-11-03 (the drafting agent). The Premise holds at `d629249`: the dial of the forward road and
the one of `/trace` began at the two cited lines, each with `TcpStream::connect` of the resolved
addresses, and neither read `HTTPS_PROXY`; the dial is now `crates/podssh-relay/src/serve/egress.rs`.
Approach item 1's `HOST:PORT` is the checked address, or the name where nothing is checked
(Decision 1 and 2). The Prove that runs, beside the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve --lib serve::
cargo test -p podssh-cli --test relay_serve -- serve_proxy
cargo test -p podssh-relay --features quick,serve,plain-ws --test quick_relay --test quick_relay_quic
cargo test -p podssh-relay --features pair,serve --test reverse_carrier
sh scripts/plant-each.sh --here t457-proxy-skipped
```

## Done

2026-11-03: drafted by an agent in a worktree; merged and measured on this machine the same day.

- The library: `crates/podssh-relay/src/serve/egress.rs` (the host's variables, the hosts that go
  directly, the dial of a plan through the proxy, the client's words and the owner's line) and its
  tests `egress_tests.rs`; `Policy::plan` and `Policy::by_name` (`serve/policy.rs`); the forward
  road's dial and its lazy dial (`serve/forward.rs`) and `/trace` (`serve/docs.rs`) through it;
  `Config::egress` in each configuration of the role and of its tests.
- The binary: `podssh relay serve` and `podssh node --quick-tunnel --relay` read the host's proxy
  as they start and name it in their first line (`crates/podssh-cli/src/relay_serve.rs`,
  `node_quick_relay.rs`); the manual's notes of `relay` and `node`; `docs/relay.md` ("The relay
  role's way out"), `docs/mesh.md`, section 4, `docs/cli.md`.
- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_contract`: the three new
  tests (a name, an address, an IPv6 address by `?dial=lazy` and `/trace` through the stand-in
  proxy, the loopback directly, and a public address of the default policy by its address; the
  proxy's `403` as the role's `502` with its status, never the proxy's place or credentials, the
  owner's line, the credentials sent as Basic, `/trace`'s `error`; a private address, the
  loopback and port 25 refused before any CONNECT): 13 passed, the three new ones among them.
- `cargo test -p podssh-relay --features serve --lib serve::` (`serve::egress`, 5: the variables,
  the hosts that go directly, the first line, the client's words, the plan): 34 passed.
- `cargo test -p podssh-cli --test relay_serve -- serve_proxy` (the role started with
  `HTTPS_PROXY` names it with no credentials, and `podssh proxy` reads a target's line through it;
  a proxy that cannot be read stops the start, 78): `relay_serve` 14 passed.
- The suites whose configuration took the field: `quick_relay`, `quick_relay_quic`,
  `reverse_carrier`, `relay_serve_reverse`, `-p podssh-cli --test node_quick_relay`: 4, 4, 7, 4
  and 3 passed, and `serve::behind` 3; on this host, whose `HTTPS_PROXY` the CLI's roles now read,
  the tests' targets on the loopback went directly, as `NO_PROXY` says.
- Planted, `sh scripts/plant-each.sh --here t457-proxy-skipped` (the role reads no proxy):
  caught.
- Clippy with `-D warnings` and `cargo fmt --check` of both crates: clean. `cargo test -p
  podssh-cli --lib`: 794 passed.
- Repaired 2026-11-03, after the gate's job `windows` at `5f79906`: Windows has one variable for
  `https_proxy` and `HTTPS_PROXY`, so the role names the proxy by `https_proxy`, the name that
  podssh reads first, and the two tests of `serve_proxy` that looked for `HTTPS_PROXY` failed
  there. They take either name on Windows (`says_variable`); `cargo test -p podssh-cli --test
  relay_serve`: 14 passed on Linux; on Windows, the gate's job.

# T-458: `podssh doctor --exit NAME`: the exit, its verdict and the road that reached it

**Source:** T-431, item 4 of its Approach, filed at its draft (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

A user whose `--exit NAME` fails cannot tell from `podssh doctor` whether the pair, the road, the
node's net or its policy refused, or what the exit's host reaches: doctor opens no session through
a node today.

## Premise

- `podssh doctor` has a line for each road that a flag names (`--forwarder`, `--shadowsocks`,
  `--via`, `--vless`), and none for a node or an exit (`crates/podssh-cli/src/flags/relay.rs`,
  `DOCTOR_FLAGS`).
- The client's side of an exit learns the node's verdict before it answers
  (`crates/podssh-cli/src/exit/open.rs`).

## Approach

1. `podssh doctor --exit NAME`: the exit's line in the net held (a member, the role `exit`, what
   the policy lets this client), the pair under NAME, and one session to a public target of the
   exit (`github.com:22` by default, `--exit-target HOST:PORT`), with the node's verdict and the
   road that carried it.
2. A refusal says whose it is: the relay's, the channel's, the net's policy, or the exit's check
   of an address.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test exit
```

On the stand-in relay: doctor's line of an exit that lets this client out is ok, with the road;
a member that the policy refuses gets FAIL with the policy's words; a node with no `--exit` gets
FAIL that names it.

# T-459: The quick tunnel's node lends its egress (`--exit` with `--quick-tunnel`)

**Source:** T-431, its Decision on the roads, filed at its draft (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`podssh node NAME --exit` lends its egress on the pair's, the transit, the Piping Server, the DERP
and the iroh roads, and refuses `--quick-tunnel` (64): the quick tunnel's node serves no routes, so
no session of its visitors reaches the exit's dial.

## Premise

- The quick tunnel's node takes one TARGET with no route, and opens it by a `TcpHandler`
  (`crates/podssh-cli/src/node_quick.rs`).
- Each other road's node takes the exit's dial through its routes (`crate::node::routes_of`,
  `Routes::exit` of `crates/podssh-relay/src/reverse/routes.rs`).

## Approach

1. The quick tunnel's node serves its sessions through `Routes` when `--exit` is given, with the
   exit's dial, as the other roads do; its visitors' keys come in as the net's members.
2. `podssh ssh --exit NAME` with a `cf://HOST` of the node, and `podssh exit` over it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test exit
```

A node of the quick tunnel's stand-in edge with `--exit` carries a session to a target of the
range that its `--routes` names, for a member; a private address of no range is refused.

# T-530: OpenTunnel, a blind TLS tunnel with no account, as a carrier of the reverse road

**Source:** the triage of the operator's sweep of public relays (2026-11-02); the operator's
ruling Q65 ("each other public service that fits these needs").
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

Each carrier of the reverse road with no account takes a WebSocket or an HTTP request at both
ends, and a client behind a proxy that refuses the WebSocket upgrade has Piping Server alone.
OpenTunnel gives a node, with no account, a public name whose TLS ends at the node itself: the
node's leg is a WebSocket through `HTTPS_PROXY`, and a client's leg is TLS by name on port 443,
with no upgrade. podssh does not speak it.

## Premise

- Read on 2026-11-02 (`docs/carriers.md`, the reverse road, item 6; MIT;
  `anomalyco/opentunnel:docs/protocol.md`, `anomalyco/opentunnel:docs/server.md` and its README):
  `POST /api/tunnel` with `{}` and no account gives a tunnel `<id>.opentunnel.xyz` and a bearer
  token, shown once; the client makes a P-256 key and a CSR with `CN=<hostname>` and the names
  `<hostname>` and `*.<hostname>`, keeps that identity before it binds the CSR
  (`POST /api/tunnel/:id/certificate`), and polls each 2 s until the certificate is `ready`; the
  server renews it with the same CSR. The bridge is one WebSocket with the subprotocol
  `opentunnel` at `/api/tunnel/:id/connect`: JSON in text frames (`attach` with the token and its
  routes within 10 s; `attached` with `heartbeat_ms` and `idle_timeout_ms`; `open` with `conn`,
  `peer`, `sni` and `alpn`; `end`, `reset`, `ping`, `pong`, `drain`), and binary frames of a
  big-endian `u32` connection id and at most 32 KiB; 256 connections a bridge at most. A visitor's
  connection comes as `open`, then its bytes from the ClientHello on, and the node ends TLS with
  its own key. The limits: 30 tunnels an hour and 10 at once from one address; 5 new
  certificates a day for one tunnel.
- The node's TLS can be podssh-ws's server, which signs P-256 in pure Rust:
  `crates/podssh-ws/src/tls_server.rs:1` says "TLS for a server of podssh's". The CSR of a name is
  made by the binary's ACME client, on aws-lc-rs: `crates/podssh-cli/src/acme/certs.rs:91` says
  "pub fn csr". The crate `opentunnel` takes rustls with ring
  (`anomalyco/opentunnel:crates/opentunnel/Cargo.toml`), C that rule 4 of `AGENTS.md` (section 5)
  keeps out of the library crates.
- Each carrier of the reverse road is a module of `podssh-relay` behind a feature of its own
  (`crates/podssh-relay/Cargo.toml`, its `[features]`: `derp`, `piping`).

## Approach

1. A module `opentunnel` of `podssh-relay`, behind a feature of that name: the API over
   podssh-ws's HTTP client through `HTTPS_PROXY`, with the retries of the protocol's table; the
   bridge over podssh-ws's WebSocket, offering `opentunnel`; its control messages, its frames, the
   heartbeat and the idle bound; each `open` a stream whose TLS podssh-ws's server ends, with the
   end-to-end channel and the resumable layer above it, as on each carrier.
2. A node's tunnel (its id, its name, its token, its key and its CSR) is kept in the cache, mode
   0600, and written before the bind, as the protocol asks, so that a node keeps one tunnel for
   its key's life and never spends the 5 certificates of a day. The key and the CSR come from
   the binary through a trait of the module, so that the library holds no C. The token is never
   in argv, a line of output or a URL.
3. A client: TLS by name to `ROUTE.<id>.opentunnel.xyz:443` through `HTTPS_PROXY`, checked
   against the public roots as each name is, then the channel to the node's pinned key. The
   route is a random label of the node's (Inferred: the README says that route names never reach
   the logs of Certificate Transparency, where the tunnel's name does).
4. The words of each refusal: `bad_token`, `cert_not_ready`, `route_conflict`,
   `too_many_routes`, a `429` of the API with its `Retry-After`, and a close `1008` or `1009`.

## Decision

Made by the drafting agent of 2026-11-03, each with the alternative that lost:

1. A `429` or a `503` whose `Retry-After` is longer than the 8 s that a retry of the protocol waits
   is said at once, with its wait (`crates/podssh-relay/src/opentunnel/retry.rs`, `too_long`). Lost:
   six retries of 8 s, as OpenTunnel's own clients make them: none can pass a limit of half an hour,
   and each costs the service a request.
2. A kept tunnel whose token the service refuses (`401`) or that it does not know (`404`) is made
   again, and the start says why. Lost: a refusal that ends the node, which a user would repair by
   deleting a file of the cache by hand; the new tunnel costs one of the 30 an hour.
3. `cert_not_ready`, which the protocol calls final, is tried again after 60 s by a node whose
   certificate was ready when it started, as the service may say it while it moves a record;
   `bad_token` and a `404` at the bridge's upgrade end the road with their words. Lost: the end of
   the road at `cert_not_ready`, which a node that runs for months would meet at a deploy.
4. The node's route is 26 random letters of base32 (130 bits, from the system's source), kept with
   the tunnel; the node claims it alone and never `@`, so a visitor of the tunnel's name, which the
   logs of Certificate Transparency show, is closed by the service before the node hears of it.
   Lost: the route `@`, which each scanner of those logs reaches.
5. The record is one private file of the cache, `opentunnel-HOST-LABEL.json`, by the service's
   host and the node's label, so that a record of another service never replaces it; it holds the
   token and the key, mode 0600, as the relay token's file does. Lost: OpenTunnel's own layout
   under `$XDG_DATA_HOME/opentunnel/`, which its CLI would share: a podssh node then competes with
   that CLI for the routes of one tunnel.
6. The node's TLS offers no ALPN, and the client offers none: the link carries the layer, not
   HTTP. A stop deletes no tunnel: one tunnel for the node's life (Q76).
7. The test of the library runs the resumable layer over the road; the end-to-end channel above it
   is the command line's, and T-531's test carries it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features opentunnel --test opentunnel_link
```

Against OpenTunnel's own server (`anomalyco/opentunnel:crates/opentunnel-server` at the tag
v0.6.1, built from its source in a container, with MySQL 8 and its local test CA, `ISSUER=local`), through a plain squid
as the host's proxy: a node makes a tunnel and attaches, a client reaches it by TLS by name, and
1 MiB goes each way under the channel; a node started again keeps its tunnel and binds no new
CSR; a wrong token is named. Planted: the node's tunnel not kept, and the test of the second
start fails, as it binds a new CSR.

## Correction

Read again on 2026-11-03 at the cited lines and in `anomalyco/opentunnel` at the tag v0.6.1
(its documents of the protocol and of the server, the crate of its client and its vectors), through the
services of web.pkgforge.dev:

- The CSR: `crates/podssh-cli/src/acme/certs.rs:91` says "pub fn csr", but that CSR has no subject
  and one name, as an ACME order takes it; the service refuses each CSR whose common name is not
  the tunnel's name or whose names are not exactly that name and its wildcard
  (`anomalyco/opentunnel:docs/server.md`, "Only a tunnel's own names"). So the binary needs a CSR of its own form beside it (T-531), behind
  the trait `Credentials` of `crates/podssh-relay/src/opentunnel/record.rs`.
- Not each carrier is behind a feature: `crates/podssh-relay/src/lib.rs` builds `transit` with
  none. The derp and piping roads are, and so is this one, `opentunnel`.
- The hosted API sits behind Cloudflare (`anomalyco/opentunnel:docs/protocol.md`, "Retries and
  errors"; `anomalyco/opentunnel:docs/server.md`: "opentunnel.xyz is proxied by Cloudflare"), so the node's API and its bridge reach Cloudflare's
  edge first, which answers its own `520` to `527`; the names of the tunnels reach the service on
  Fly.io directly. The retries follow the protocol's table and its vectors
  (`anomalyco/opentunnel:spec/vectors/api-retry.json`).
- The bridge's frames, control messages, routes and names follow the protocol's vectors
  (`anomalyco/opentunnel:spec/vectors/control.json`, and its `frames.json`, `names.json` and
  `routes.json`), which the unit tests
  of `crates/podssh-relay/src/opentunnel/wire.rs` hold. The documents leave open what the service
  answers to a bridge's upgrade for an unknown tunnel: the code takes a `404` there as final, and
  each other refusal as worth a retry.
- The Prove's run against OpenTunnel's server in containers is `.github/workflows/opentunnel-interop.yml`:
  the server built from its source at v0.6.1 on the runner, with the runner's MySQL 8 and squid, and
  no container image, as `scripts/check-repo.py` reads images from `images/` alone. Its dials go to
  the server's address through squid, with the test's domain in TLS alone, as no resolver knows that
  domain. The native test is against a stand-in written from the documents,
  `crates/podssh-relay/tests/opentunnel_stand_in/`.

## Done

2026-11-03, drafted (`DRAFT T-530`) by an agent that does not build; merged, built and run the same
day, and run against OpenTunnel's own server in Actions.

What changed:

- `crates/podssh-relay/src/opentunnel/` (new, feature `opentunnel`, pure Rust): `mod.rs` (the
  service, `PODSSH_OPENTUNNEL`), `wire.rs` (the control messages, the data frames, the routes),
  `retry.rs` (the protocol's retries), `api.rs` (the HTTP API on podssh-ws's HTTP/1.1), `dial.rs`
  (TLS to the API through the proxy; TCP to a tunnel's name), `record.rs` (the record, its store,
  the trait `Credentials`), `provision.rs` (the tunnel made once and kept), `conn.rs` (a visitor's
  connection as a stream), `bridge.rs` (the upgrade, `attach`, the loop), `far.rs` (the node, its
  TLS, its renewals), `client.rs` (the name, the dialer, `carry`).
- `crates/podssh-relay/Cargo.toml`, `crates/podssh-relay/src/lib.rs`: the feature and the module;
  `scripts/gate.sh`: the feature in the build and the tests of the library crates with no C
  compiler, and in the check on their minimum Rust.
- `crates/podssh-relay/tests/opentunnel_stand_in/` (new): the stand-in server, its CA and the
  credentials of a test's node; `crates/podssh-relay/tests/opentunnel_link.rs` (new): 7 tests;
  `crates/podssh-relay/tests/opentunnel_interop.rs` (new): the run against OpenTunnel's server;
  `.github/workflows/opentunnel-interop.yml` (new), by hand.
- `scripts/plants/t530-tunnel-not-kept.patch` and `.plant`: the record never saved.
- `docs/carriers.md` (the reverse road, item 6), `docs/STATUS.md` (a section of the road).

Results:

- `cargo test -p podssh-relay --features opentunnel --lib opentunnel`: 22 passed.
- `cargo test -p podssh-relay --features opentunnel --test opentunnel_link`: 7 passed.
- `cargo clippy -p podssh-relay --features opentunnel --all-targets -- -D warnings`, and the gate's
  steps of the library crates with no C compiler and on Rust 1.89: clean, and `cargo +1.89 check`
  with `CC=/nonexistent` of podssh-relay with the gate's features passed. The merge repaired a
  borrow of a temporary (`bridge.rs`, the upgrade's request) that did not compile, and boxed the
  large variant of `Refreshed` (clippy's `large_enum_variant`).
- `opentunnel-interop.yml` against OpenTunnel's own server v0.6.1, built from its source, with
  MySQL 8, its local CA and squid (run 41675551360 at `69df297`): the node kept its tunnel and a
  client echoed 1 MiB through squid (1 passed); the planted CSR of the tunnel's name alone failed,
  "certificate not valid for name", as it must.
- Planted (`scripts/plants/t530-tunnel-not-kept.plant`): caught:
  `a_node_started_again_keeps_its_tunnel_and_binds_no_new_csr` failed.

# T-531: The OpenTunnel road in the command line: `podssh node --opentunnel` and `ssh node://`

**Source:** T-530, as T-379 followed T-349; the triage of the operator's sweep of public relays
(2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

T-530 builds OpenTunnel's link in `podssh-relay`; no command uses it.

## Premise

- `crates/podssh-cli/src/ssh/roads.rs:1` says "over more roads than the pair's": the race of
  `podssh ssh node://NAME`; each carrier's node has a file of its own (`crates/podssh-cli/src/node_piping.rs`,
  `crates/podssh-cli/src/node_transit.rs`, `crates/podssh-cli/src/node_derp.rs`).
- A DERP server lets any key send, so the DERP road needs `--allow` and the end-to-end channel
  (T-379's Decision); a tunnel's name is in the logs of Certificate Transparency, so anyone may
  open a connection to it (`docs/carriers.md`, the reverse road, item 6).
- The operator ruled Q76 (2026-11-02, `docs/decisions.md`): podssh tries OpenTunnel unasked, for a
  node with no other road, one tunnel for each node, off with `PODSSH_OPENTUNNEL=no`, with short
  live tests from GitHub Actions and the session's own host.

## Approach

1. `podssh node NAME TARGET --opentunnel`: the road alone, or beside the pair's road with one
   keeper of sessions; it needs `--allow`, or the net (T-452's door), and the end-to-end channel;
   it says its name on stderr, and its record names the road once T-445 is done.
2. `podssh ssh node://NAME --opentunnel-name HOST`, and a name kept under NAME as a DERP ticket is
   kept: a road of the race, 250 ms after the road before it.
3. As the operator answers question 3: the unasked fallback of Q65, for a node with no other road
   and for a client once each road before it failed, with `PODSSH_OPENTUNNEL=no` to turn it off;
   or the road when the user asks for it alone.
4. `doctor` says whether the API's host answers, and makes no tunnel. The manual, `docs/mesh.md`,
   `docs/carriers.md`, `docs/reverse.md`, `SECURITY.md` (what the service sees: the SNI, the
   times and the sizes, never the plaintext) and `docs/STATUS.md`.

## Decision

Made by the drafting agent of 2026-11-03 (Q76 answered the question that item 3 waited for), each
with the alternative that lost:

1. Unasked means a node with no other road: no pair stored under NAME (or an expired one), a door
   (`--allow`, or a net that names its key), no flag of another road, and the DERP road off
   (`PODSSH_DERP=no`), as the DERP road of Q50 serves such a node unasked first
   (`crates/podssh-cli/src/node_opentunnel.rs`, `unasked`). A node whose DERP servers do not
   answer names `--opentunnel` in its refusal (69). Lost: OpenTunnel beside the DERP road unasked,
   two services of third parties for each node where Q76 says "no other road"; and a hand-over
   from the DERP road's run to this one when no DERP server answers, which would make
   `node_derp.rs` run a second road inside its own.
2. `--opentunnel` with `--derp` or `--iroh` is refused (64): one road beside the pair's in each
   node's run, as each of those runs owns its roads; a second node under the same NAME, with the
   same key, serves the other. So are `--plain`, `--no-e2e`, a `udp:` TARGET and `--exit`, which
   the road does not carry. Lost: three roads in one process, which no run of today serves.
3. A client's TLS is checked with the host's trust for a name of `opentunnel.xyz`, whose
   certificates are public, and with the run's `--ca-file` for a name of another service, which
   may be the user's own; the node's API takes the same rule. Lost: the host's trust alone, which
   could not check a service under the user's own CA.
4. The road's place in the race is right after the DERP road: 250 ms after the road before it when
   `--opentunnel-name` gives the name, else, with a name kept under NAME, once each road before it
   failed (Q76's fallback of a client). The name is kept as a DERP ticket is, in a private file,
   `opentunnel-NAME.name`: an address, not a credential.
5. `doctor` asks the API's host for `/health` once, in a section of its own before DERP's, and
   makes no tunnel; `--quick` leaves it out. Lost: a probe of a tunnel's name, which needs a tunnel.
6. The live run deletes its throwaway tunnel at its end (`DELETE /api/tunnel/ID`, AGENTS.md's
   throwaway keys), and runs each week as transit-live.yml does; a node never deletes its own.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test opentunnel_road
```

Against T-530's server in containers, with a stand-in proxy on the client's side that refuses each
upgrade: `podssh node NAME TARGET --opentunnel` and `podssh ssh node://NAME 'echo ok'`, the
pair's road down and the race on OpenTunnel. Live, short, from GitHub Actions through
`opentunnel.xyz`, if the operator allows it (question 3). Planted: the road started with no
`--allow`, and the test of its refusal fails.

## Correction

Read again on 2026-11-03 at the cited lines and in the code:

- Approach, item 1: "its record names the road once T-445 is done". T-445 is done, but its record
  names three roads, the iroh home relay, the DERP home and the quick tunnel
  (`crates/podssh-iroh/src/pkarr_record.rs:50` says "pub struct Roads"), and a member's client
  races those three alone. Naming the OpenTunnel name there is a new kind of road in that record,
  in its reader and in the client's race: T-611.
- Approach, item 3: the operator's ruling Q76 answered question 3: the unasked fallback, for a node
  with no other road, one tunnel for each node, off with `PODSSH_OPENTUNNEL=no`, with short live
  tests from GitHub Actions and the session's own host. The road that the user asks for alone is
  `--opentunnel`, beside the pair's road when a pair is stored.
- Prove: the test of the command line runs T-530's stand-in server on the loopback, not
  OpenTunnel's server in containers, which T-530's `opentunnel-interop.yml` runs; and a proxy of
  CONNECT cannot see an upgrade inside TLS, so the test's proxy refuses each CONNECT but to the
  service's names, which fails each road that reaches another host as a proxy that refuses the
  upgrade fails it, and passes the OpenTunnel road's TLS by name unread.
- The files at their limit: `crates/podssh-cli/src/ssh/roads.rs` held 478 lines, `ssh/mod.rs` 494,
  `ssh/resolve.rs` 499 and `node.rs` 498. The words of a race's end moved to `ssh/road_link.rs`,
  the dispatch of a `node://` destination and the checks of its roads to `ssh/node.rs`, and the
  iroh road's refusals to `node_flags.rs`, each with no change of behaviour.

## Done

2026-11-03, drafted (`DRAFT T-531`) by an agent that does not build; merged after T-530, built and
run the same day.

What changed:

- `crates/podssh-cli/src/node_opentunnel.rs` (new): the node of the road, its flags, its door,
  `unasked` (Q76), the binary's `Keys` (the key and the CSR of a tunnel), its lines, the pair's road
  beside it with one keeper; unit tests.
- `crates/podssh-cli/src/acme/certs.rs`: `tunnel_csr`, the CSR of a tunnel's name and its
  wildcard; a test in `crates/podssh-cli/src/acme/certs_tests.rs` reads it with x509-parser.
- `crates/podssh-cli/src/ssh/opentunnel.rs` (new): `--opentunnel-name`, the name kept under NAME,
  the dialer; `crates/podssh-cli/src/ssh/roads.rs` and `crates/podssh-cli/src/ssh/road_link.rs`:
  the road in the race; `crates/podssh-cli/src/ssh/node.rs`: `run` and `resolved`, moved from
  `ssh/mod.rs` and `ssh/resolve.rs`; `crates/podssh-cli/src/ssh/exit_road.rs`,
  `crates/podssh-cli/src/ssh/carried.rs`, `crates/podssh-cli/src/ssh/args.rs`: the field and its
  refusals.
- `crates/podssh-cli/src/node.rs`, `crates/podssh-cli/src/node_flags.rs`,
  `crates/podssh-cli/src/node_derp.rs` (`door_of`, the refusal of `--opentunnel` beside `--derp`),
  `crates/podssh-cli/src/node_args.rs`, `crates/podssh-cli/src/node_carrier.rs`,
  `crates/podssh-cli/src/node_quick.rs`, `crates/podssh-cli/src/node_temp.rs`,
  `crates/podssh-cli/src/node_install/mod.rs`, `crates/podssh-cli/src/node_install/text.rs`: the
  dispatch, and `--opentunnel` refused or passed on by each other mode.
- `crates/podssh-cli/src/doctor/opentunnel.rs` (new) and `crates/podssh-cli/src/doctor/sections.rs`:
  the section `opentunnel`.
- `crates/podssh-cli/src/flags/opentunnel.rs` (new), `crates/podssh-cli/src/flags.rs`,
  `crates/podssh-cli/src/flags/node.rs`: the rows; `crates/podssh-cli/src/man/notes_pair.rs`,
  `crates/podssh-cli/src/man/notes_ssh.rs`, `crates/podssh-cli/src/man/notes_doctor.rs`,
  `crates/podssh-cli/src/man/facts/roads.rs`: the notes and `PODSSH_OPENTUNNEL`.
- `crates/podssh-relay/src/opentunnel/api.rs`: `remove`, for the live run's throwaway tunnel.
- `crates/podssh-cli/tests/opentunnel_road.rs` (new): 3 tests;
  `crates/podssh-relay/tests/opentunnel_live.rs` (new, ignored) and
  `.github/workflows/opentunnel-live.yml` (new), by hand.
- `scripts/plants/t531-no-door.patch` and `.plant`.
- `docs/cli.md`, `docs/reverse.md` ("The OpenTunnel road"), `docs/carriers.md`, `docs/mesh.md`,
  `SECURITY.md`, `docs/STATUS.md`.

Results:

- `cargo test -p podssh-cli --test opentunnel_road`: 3 passed.
- `cargo test -p podssh-cli --lib` (the node's flags and keys, the client's race, the doctor's
  sections, the CSR, the notes of the manual): 777 passed.
- `cargo test -p podssh-cli --test flag_table --test man_flag_parity --test doctor_jobs --test
  derp_road --test road_race --test node_carrier`: 9, 6, 3, 6, each passed, `node_carrier` 14 and
  `node` 17. The merge found that `derp_road`'s node with no pair and `PODSSH_DERP=no`, which
  must refuse with 78, took the OpenTunnel road unasked (Q76, which the operator kept on
  2026-11-03) and waited past the test's minute on the service: the test now turns the road off
  (`PODSSH_OPENTUNNEL=no`), as it turns transit and pkarr off, and an unasked node's first tunnel
  has a bound of 20 s (`UNASKED_LIMIT`), so that a node that cannot reach the service ends soon.
- `cargo clippy --all-targets -p podssh-cli -- -D warnings`: clean, once `Transport::Node`'s new
  field was boxed (clippy's `large_enum_variant`).
- `opentunnel-live.yml` (Q76, Q91, short), run 41679059624 at `54b124b`: passed. A throwaway
  tunnel through `opentunnel.xyz`, 256 KiB echoed through it with the same digest, a second start
  that made and bound nothing new, then deleted (1 passed, 44 s). The planted route that no bridge holds (`PODSSH_OPENTUNNEL_TEST_PLANT=other-route`)
  failed, as it must (exit 101: TLS by that name ended with no node behind it), and its tunnel was
  deleted before the test's verdict.
- Planted (`scripts/plants/t531-no-door.plant`): caught:
  `a_node_of_the_road_with_no_door_is_refused_before_it_makes_a_tunnel` failed.

# T-532: `podssh funnel` through OpenTunnel, with TLS that ends at the node

**Source:** the triage of the operator's sweep of public relays (2026-11-02); T-180.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

T-180's `podssh funnel` publishes through the quick tunnel: TLS ends at Cloudflare's edge, and a
node in a cage reaches the edge inside WARP's tunnel alone. OpenTunnel publishes a name whose TLS
ends at the node, over a WebSocket through `HTTPS_PROXY`, so a funnel could leave a cage of an
HTTPS proxy with no WARP, and no third party reads its traffic.

## Premise

- T-180's Correction: its funnel prints "TLS ends at Cloudflare's edge; Cloudflare can read this
  traffic.", and a node in a cage reaches the edge inside WARP's tunnel (T-374).
- `docs/carriers.md`, the reverse road, item 6: a visitor's bytes come over the bridge from the
  ClientHello on; the service reads the SNI alone; a route `@` is the tunnel's own name.

## Approach

1. `podssh funnel TARGET --opentunnel`: T-530's node, whose route `@` ends TLS and serves each
   request to TARGET as T-180's route does (HTTP/1.1 heads, the bodies as bytes, an upgrade
   passed through).
2. The URL `https://<id>.opentunnel.xyz/` and one line: "TLS ends at this host; OpenTunnel sees
   the names, the times and the sizes." No `--allow`: the URL is public.
3. ALPN `http/1.1`, and `h2` only where podssh-ws's server serves it.
4. As Q76 rules, a funnel that the quick tunnel cannot carry tries this road unasked.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test funnel_opentunnel
```

Against T-530's server in containers: curl, software that podssh did not write, GETs and POSTs
through the tunnel to Python's `http.server`; a WebSocket echo answers an upgrade; stderr has the
line about TLS. Planted: TLS ended with a certificate of another name, and curl refuses it, so
the test fails.

## Start condition

T-180 and T-530 are done: `podssh funnel` and OpenTunnel's link exist.

# T-533: The manual says which public services podssh tries last, and which it never names

**Source:** the triage of the operator's sweep of public relays (2026-11-02).
**Category:** docs
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The sweep offers, as changes with no code, Tailscale's main DERP fleet through `--derp-server` and
32 public Wisp servers through `--forwarder`. The manual names the servers that podssh tries, but
says nothing of those that it never names, nor why, so a user who reads such a list has no word
of podssh's.

## Premise

- `crates/podssh-cli/src/man/notes_pair.rs:165` says "Tailscale's free servers for tailcat", and
  `crates/podssh-cli/src/man/notes_ssh.rs:233` says "Four words name public forwarders".
- `docs/carriers.md` (the forward road, item 7 and its "Ruled out"; the reverse road, item 2):
  Tailscale's main fleet serves Tailscale's clients; the public Wisp lists come from web proxies
  that serve a network's users against that network's own filter, with no operator, terms or
  limits; the public proxy nodes of aggregator lists have no operator who answers for them; file
  hosts forbid automated uploads.
- `crates/podssh-cli/src/man/notes_ssh.rs` has 456 of its 500 lines.

## Approach

1. The notes of `--derp-server`: after tailcat's servers, podssh tries Tailscale's main fleet
   (Q74), which serves Tailscale's clients under Tailscale's terms, and says so.
2. The notes of `--forwarder`: the public Wisp servers that podssh tries after the demo server
   (Q75), and the last fallbacks of Q78, each with the words that tell the user that the target
   goes to a third party that nobody vouches for.
3. One sentence: podssh never uses or names a domain that looks taken over (a school's, a
   church's, a shop's, or a name made to look like one), Q79.
4. A file of notes of its own where a file would pass 500 lines, as T-438 made
   `crates/podssh-cli/src/man/notes_ssh_more.rs`.

## Decision

The manual tells what this binary does (2026-11-03, the draft): one note of `podssh ssh`, after
the forwarders', names the public services that podssh tries when the user named none, each after
its own roads, says that each is a third party that nobody vouches for and what it sees, names the
kinds of server that podssh never names and why, and gives the sentence of Q79; the DERP note of
`podssh node` says that Tailscale may withdraw tailcat's servers and that podssh names none of its
main fleet. Each road of Q74, Q75 and Q78 that comes later (T-534, T-535, T-574, and the last
fallbacks after them) moves its servers into that note, in its words, in the change that builds it,
as T-534's item 4 asks. Lost: sentences now that podssh tries Tailscale's main fleet or the public
Wisp servers, which this binary does not do, so the manual would tell of roads that it lacks, as
GitHub #121 found `docs/STATUS.md` did (T-594); and this entry kept open until each of those roads is
built, which would leave the manual silent on today's services meanwhile.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test man_page
```

The pages hold the sentences; `man_json` and `man_flag_parity` pass. Planted: one sentence
removed, and the test that names it fails.

## Correction

The operator ruled Q74, Q75, Q77, Q78 and Q79 on 2026-11-02 (`docs/decisions.md`), against the
triage's recommendation that podssh name none of these: Tailscale's main DERP fleet is tried after
tailcat's, once a short test shows that it lets podssh in (Q74); the public Wisp servers that their
operators run for that use are fallbacks (Q75); each public service is a last fallback whatever
its terms, the lists of public proxy nodes among them (Q78); and a domain that looks taken over is
never used and never published (Q79). The entry now says what podssh tries last, and why, and
which hosts it never names; the roads themselves are the entries that those rulings file.

Read at `38f424c` (2026-11-03): `crates/podssh-cli/src/man/notes_ssh.rs` has 482 lines, so the
note is in a file of its own, `crates/podssh-cli/src/man/notes_public.rs`, which one line of
`notes_ssh.rs` names after the forwarders' note. T-534, T-535 and T-574 are open: this binary tries
no server of Tailscale's main fleet, no public Wisp server but the demo server, and no public proxy
node, so the note says that it names none of them (the Decision).

## Done

Drafted 2026-11-03 (built nothing; the main session merges and measures it):

- `crates/podssh-cli/src/man/notes_public.rs` (new, `mod notes_public` in
  `crates/podssh-cli/src/man/mod.rs`): the note `PUBLIC`, which `crates/podssh-cli/src/man/notes_ssh.rs`
  puts after the forwarders' note: the services that podssh tries when the user named none (the
  four forwarders, wisp last; tailcat's DERP servers, Least Authority's transit relay, ppng.io and
  n0's server of pkarr), each a third party that nobody vouches for, which sees the target or the
  two ends, the sizes and the times, may log them and may stop; the kinds that podssh never names
  (Tailscale's main DERP fleet, community DERP servers, the Wisp servers of web proxies' lists,
  the public proxy nodes of aggregators' lists); a server that the user names is the user's to
  trust; and Q79's sentence. Its unit test, `the_note_of_the_public_services_follows_the_forwarders`.
- `crates/podssh-cli/src/man/notes_pair.rs`: the DERP note says that Tailscale may withdraw
  tailcat's servers at any time, and that podssh names no server of its main fleet.
- `crates/podssh-cli/tests/man_page.rs`:
  `the_manual_says_which_public_services_podssh_tries_and_which_it_never_names`, on the pages of
  `ssh` and `node` with their lines joined.
- `scripts/plants/t533-taken-over-unsaid.patch` and `.plant`: the sentence of Q79 removed; the test
  of the pages must fail.
- `docs/STATUS.md`: the row of this entry, `unreleased`.

At the merge (2026-11-03): `cargo test -p podssh-cli --test man_page`, 11 passed; `--lib man`
(the notes' names, the new unit test), 40; `--test man_json`, 4; `--test man_flag_parity`, 6; the
lib, 754; clippy clean. The plant `t533-taken-over-unsaid` (`sh scripts/plant-each.sh --here`):
caught; its run in the build image waits (Q88).

# T-490: chisel's protocol: a chisel server as the road

**Source:** T-442 (2026-11-02); the operator's ruling Q66 ("the others that the expansion of Q63
needs").
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

chisel is one MIT binary that users run on their own hosts, often behind TLS on port 443, and
that takes the destination from its client; podssh cannot use it.

## Premise

- Read at chisel v1.13.0 (2026-10-11; `jpillora/chisel:share/version.go`,
  `jpillora/chisel:client/client_connect.go`, `jpillora/chisel:server/server_handler.go`,
  `jpillora/chisel:share/tunnel/tunnel_out_ssh.go`, `jpillora/chisel:share/tunnel/tunnel_in_proxy.go`;
  docs/carriers.md, "Servers that a user runs"): a WebSocket with the subprotocol `chisel-v3`,
  which the server requires; SSH in its binary messages, the server's version
  `SSH-chisel-v3-server`, password authentication by `--auth user:pass` or an authfile of the
  targets that each user may reach, and the server's key checked by a fingerprint, SHA-256 in
  base64 of 44 characters; a global request `config`, JSON of the client's version and its
  remotes; a channel `chisel` for each tunnel, its extra data `HOST:PORT`, which the server dials
  before it accepts; `ping` requests both ways.
- The roads of servers that the user names in place of the relay are chained in one place:
  `crates/podssh-cli/src/ssh/servers.rs:15` says "pub(super) fn or_relay".
- russh links aws-lc, which rule 4 of `AGENTS.md` (section 5) keeps out of podssh-ws.

## Approach

1. `--chisel URL` (`https://` or `wss://`; `http://` to the loopback alone), with its
   `user:pass` and the server's fingerprint in a file of mode 0600 (`--chisel-auth-file`), read
   as `--via-auth-file` is: a road in place of the relay for `ssh`, each command of its road and
   `proxy`, refused beside another road (64).
2. podssh-ws's WebSocket through `HTTPS_PROXY`, with the subprotocol; russh's client over it, in
   the binary's crates; the `config` request with the one remote; a channel `chisel` for each
   session, so that the sessions of `podssh each` share one connection; `ping` answered.
3. The server's refusals in their words: a 101 with no `chisel-v3`, a wrong password, a
   fingerprint that does not match (77), the authfile's "access denied" for the target, and the
   dial's failure in the channel's refusal.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test chisel
```

Against chisel's own server, the binary of v1.13.0's release checked by its
`chisel_1.13.0_checksums.txt`, in a container behind TLS, through a plain squid as the host's
proxy (a harness as T-441's): sshd's banner and 1 MiB each way; a wrong password, a wrong
fingerprint and a target that the authfile does not allow, each refused with its words.
Planted: the fingerprint not checked, and the test of the wrong fingerprint fails.

# T-491: Trojan over TLS and over a WebSocket

**Source:** T-442 (2026-11-02); the operator's ruling Q66.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Trojan servers (trojan-gfw, trojan-go, Xray-core, sing-box) are a large base that users run on
port 443 behind a real certificate, and they take the destination from the client; podssh speaks
VLESS (T-440) but not Trojan, whose request is smaller.

## Premise

- Read at <https://trojan-gfw.github.io/trojan/protocol> (2026-11-02): after a real TLS
  handshake, `hex(SHA224(password))`, CRLF, a request of SOCKS5's shape (CONNECT `0x01`, an
  address's type, the address, the port), CRLF, then the payload in the same write; a server that
  reads a wrong password or request hands the connection to a preset endpoint, an HTTP server by
  default. Xray-core writes the same request (`XTLS/Xray-core:proxy/trojan/protocol.go` at
  v26.10.21), and serves it over TLS and over a WebSocket; trojan-go's WebSocket mode carries it
  through a CDN.
- `--vless` reads share links, with TLS and a WebSocket among its transports:
  `crates/podssh-ws/src/vless/link.rs:3` says "vless://ID@HOST:PORT?type=ws|xhttp".

## Approach

1. `--trojan FILE`, a private file of `trojan://PASSWORD@HOST:PORT?security=tls&sni=&type=ws&host=&path=#NAME`
   lines, tried in order (Inferred: the form that clients give out, beside `vless://`; read in
   Xray-core's and its clients' share links before it is fixed), read as `--vless` reads its file.
2. Two transports: TLS by name, and a WebSocket over TLS (`type=ws`); each setting that changes
   the bytes and that podssh does not make is refused by its name, as T-440 does.
3. A wrong password: the server's fallback answers with an `HTTP/` line, or closes; podssh names
   that (77), and never shows the password or its hash.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test trojan
```

Against trojan-gfw's own server (release 1.16.0, its signature and a pinned SHA-256), trojan-go
0.10.6 over a WebSocket, and Xray-core v26.10.21 (pinned in `scripts/interop-vless.sh`) over TLS
and a WebSocket, in containers through a plain squid: sshd's banner through each, and a wrong
password named. Planted: the hash written in upper case, and each server's fallback answers.

# T-492: Shadowsocks 2022 (SIP022) for `--shadowsocks`

**Source:** T-442 (2026-11-02); the operator's ruling Q66.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

The servers of shadowsocks-rust, sing-box and Xray-core give out keys of the 2022 methods, which
`--shadowsocks` (T-373) refuses.

## Premise

- `crates/podssh-ws/src/shadowsocks/mod.rs:110` says "which podssh does not speak", for a method
  of `2022-blake3-`, and a test holds that refusal:
  `crates/podssh-cli/tests/shadowsocks_cli.rs:75` says "a_plugin_shadowsocks_2022".
- Read at <https://shadowsocks.org/doc/sip022.html> (2026-11-02): a pre-shared key of 16 or 32
  bytes in base64; each stream's key by BLAKE3's `derive_key` with the context "shadowsocks 2022
  session subkey" over the key and the salt; a request of a salt, a fixed header (a type, a
  timestamp, a length) and a header of the address with padding or payload; the response's
  header holds the request's salt; a timestamp more than 30 s off is a replay; AES-128-GCM and
  AES-256-GCM mandatory, ChaCha20-Poly1305 optional.
- `blake3` 1.8.7 with its feature `pure` builds no C and no assembly
  (`BLAKE3-team/BLAKE3:build.rs`).

## Approach

1. The three TCP methods in podssh-ws's Shadowsocks module, with `blake3` and `pure` (rule 4 of
   `AGENTS.md`, section 5); the key read from the `ss://` line as SIP002 gives it.
2. The response's salt checked against the request's; a refusal by a server whose clock differs
   by more than 30 s named with this host's clock (`crates/podssh-ws/src/clock.rs`).
3. SIP023's identity headers, for a server of several users (`IPSK:UPSK`), read and made, or
   refused by their name, as the entry decides.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test shadowsocks
PODSSH_TEST_SSSERVER=/usr/bin/ssserver cargo test -p podssh-cli --test shadowsocks_cli
```

Against shadowsocks-rust's `ssserver` (the gate's image installs it), with each 2022 method: a
session and 1 MiB each way; a wrong key ends at the first chunk with the server named. Planted:
the timestamp in milliseconds, and the server refuses each session.

# T-493: Shadowsocks in a WebSocket, as Outline's servers serve it, and `ssconf://` keys

**Source:** T-442 (2026-11-02); the operator's ruling Q66.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`--shadowsocks` dials raw TCP, which a proxy that waits for TLS on port 443 does not carry.
Outline's servers carry Shadowsocks in a WebSocket over TLS, and give their users `ssconf://`
keys that name it; podssh reads neither.

## Premise

- `crates/podssh-ws/src/shadowsocks/mod.rs:14` says "TCP through the proxy of the environment".
- Read on 2026-11-02 (docs/carriers.md, "Servers that a user runs"): outline-ss-server since
  1.9.0 has the listeners `websocket-stream` and `websocket-packet`, each on a path of a web server
  of its own that a TLS front such as Caddy covers
  (`OutlineFoundation/outline-ss-server:cmd/outline-ss-server/config_example.yml`); the Outline
  SDK carries the stream in binary messages (`Jigsaw-Code/outline-sdk:x/websocket/endpoint.go`);
  a dynamic key is `ssconf://` read as `https://`, its body JSON (`server`, `server_port`,
  `password`, `method`) or a YAML whose TCP part names `$type: websocket` and a `wss://` URL.
- `--shadowsocks` already fetches a subscription:
  `crates/podssh-cli/src/shadowsocks/subscription.rs:30` says "A subscription's URL".

## Approach

1. `ssconf://` lines (and `https://` ones marked as a key) in `--shadowsocks`'s file, fetched as
   a subscription is, through `HTTPS_PROXY`, never shown; the JSON form, and the YAML form's TCP
   part (a reader of that subset, or a pure-Rust YAML crate that the entry chooses).
2. An endpoint `$type: websocket`: the AEAD stream in binary messages of podssh-ws's WebSocket to
   its `wss://` URL. A key with no WebSocket stays raw TCP.
3. A refused upgrade, a wrong path and a wrong key, each named.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test shadowsocks_cli
```

Against outline-ss-server v1.9.2 (its release's `checksums.txt`) behind Caddy or nginx with TLS,
in containers through a plain squid: an `ssconf://` key served over HTTPS, then sshd's banner and
1 MiB each way in the WebSocket. Planted: text messages in place of binary ones, and the server
ends the stream.

# T-494: `--via` against NaiveProxy's server, and the words of a probe-resistant proxy

**Source:** T-442 (2026-11-02).
**Category:** measurement
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

NaiveProxy's server, Caddy with klzgrad's fork of forwardproxy, is a common HTTP/2 CONNECT proxy
over TLS. `--via` (T-439) should reach it, but no test runs it; and with `probe_resistance` a
CONNECT whose credentials fail is answered as a web server answers, which `--via` does not name.

## Premise

- Read on 2026-11-02: NaiveProxy's padding is opted into by a `padding` header in the CONNECT and
  its answer, and its servers "should interoperate with any regular HTTP/2 clients"
  (klzgrad/naiveproxy's README); the fork serves the next handler where probe resistance is on
  and authentication failed, else a `407`, and pads only a request with the header
  (`klzgrad/forwardproxy:forwardproxy.go`, its branch `naive`).
- `crates/podssh-ws/src/via/mod.rs:348` says "if status == 407": the words of a refusal explain
  a `407` alone.

## Approach

1. Run `--via` against the fork's release v2.11.7-naive2, with and without `probe_resistance`.
2. A CONNECT answered with a page (a status other than 2xx and 407, from a server that chose
   `h2`) while credentials were sent: the words say that a probe-resistant proxy answers so when
   its credentials do not match.
3. No padding: the server talks to a client with none.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test via
```

Against the fork's Caddy (its release's tarball, a pinned SHA-256) in a container, added to
`scripts/interop-via.sh`: sshd's banner and two sessions on one HTTP/2 connection; a wrong
password with `probe_resistance` named in the words of step 2. Planted: those words removed, and
the check of them fails.

# T-495: `-J upterm://SESSION@HOST`: a session of upterm's host as the first hop

**Source:** T-442 (2026-11-02); the operator's ruling Q65 (public services with no account).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

upterm's host (`upterm host`) opens a reverse tunnel from a machine with no inbound port to
uptermd, over a WebSocket on port 443 through `HTTPS_PROXY`; its community server
`uptermd.upterm.dev` needs no account. A podssh in a cage could reach the user's own machine
through it, at both ends through 443, but podssh's first hops of `-J` are the relay and three
tunnels: `crates/podssh-cli/src/ssh/jump.rs:100` says "The first hop's tunnel".

## Premise

- Read on 2026-11-02 in upterm's default branch, whose release v0.41.0 came the same day (its
  README, `owenthereal/upterm:ws/client.go`, `owenthereal/upterm:upterm/const.go`;
  docs/carriers.md, the forward road, item 9): a guest's SSH ends at uptermd, which checks the
  guest's key against the host's list, mints a short-lived user certificate and makes its own SSH
  connection to the host's server through the tunnel; over a WebSocket the guest sends
  `Authorization: Basic` of the session's ID and its node, and `Upterm-Client-Version`, then SSH
  in binary messages; uptermd's host key is a certificate under an `@cert-authority` line of its
  README; a guest forwards to the host's loopback where the host allows
  `--allow-forwarding=loopback`, and `--authorized-keys` or `--authorized-user` lets in listed
  keys alone.
- Its author's page calls the community server one "for your convenience (please put it into
  good use!)"; no terms and no limits were found.

## Approach

1. `upterm://SESSION[@HOST[:PORT]]` as the first hop of `-J`, `uptermd.upterm.dev` when no host
   is named: podssh-ws's WebSocket through `HTTPS_PROXY` with the two headers, and podssh's SSH
   client to uptermd as the user `SESSION`, with the user's keys, checking uptermd's certificate
   against `known_hosts`' `@cert-authority` line.
2. The next hop in a `direct-tcpip` channel to the host's loopback (`127.0.0.1:22` by default),
   so that the host's own sshd checks the user end to end, as each hop of `-J` does.
3. Words for uptermd's refusal of an unknown session, and for the host's refusal of a forward.
4. No `podssh node` as an upterm host: it needs an SSH server in the node for uptermd's hop, and
   podssh's own nodes have roads on 443.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test upterm_hop
```

Against uptermd and `upterm host --allow-forwarding=loopback` of v0.41.0's release (checked by
its `checksums.txt`) in containers, with sshd on the host's loopback and a plain squid as the
host's proxy: `podssh ssh -J upterm://SESSION@uptermd.test user@127.0.0.1 'echo ok'`. Live, a
short run from GitHub Actions through `uptermd.upterm.dev`, with an upterm host on the runner
(Q65). Planted: the certificate's authority not checked, and a stand-in of another authority is
taken, so the test fails.

# T-496: ntfy.sh, a meeting point of the pairing where a proxy refuses the WebSocket upgrade

**Source:** T-442 (2026-11-02); the operator's ruling Q65.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

T-086's pairing by a short code meets at magic-wormhole's mailboxes, which are WebSockets.
Behind a proxy that refuses the upgrade, a node and an operator cannot pair, though the Piping
Server road (T-437) carries their sessions there afterwards.

## Premise

- Read on 2026-11-02 (docs/carriers.md, "Meeting points"): ntfy.sh may be used "without creating
  an account", under rate limits; its topics are public, and "your topic name functions as a
  password"; 4,096 bytes a message, 60 requests at once then one each 5 s, 250 messages a day; a
  topic read as a JSON stream by a plain GET (`TOPIC/json`), polled with `poll=1` and `since=`,
  and written by a POST. Its server is Apache-2.0 and GPLv2, release v2.36.0 with
  `checksums.txt`.
- T-086's exchange (SPAKE2, then its phases) runs over a mailbox that stores and forwards
  messages of two sides.

## Approach

1. A carrier of T-086's messages over an ntfy topic: each message one JSON body of a side, a
   phase and the payload, under 4,096 bytes; the topic derived from the code's nameplate alone,
   never from the words that SPAKE2 takes, so that ntfy learns nothing of the code (Inferred
   from magic-wormhole's nameplate); the other side's messages read as a JSON stream with
   `since=` the code's start.
2. One connection: on HTTP/2 the stream's GET and the POSTs share it; on HTTP/1.1 a poll and a
   POST in turn.
3. Tried after the mailboxes, or first where a probe found the upgrade refused, as the Piping
   Server road is; `PODSSH_PAIR_NTFY` names another ntfy server, or `no`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,code --test pair_ntfy
```

Against ntfy's own server (v2.36.0's release binary, checked by its `checksums.txt`) on the
loopback: two peers with one code pair through it; a wrong code fails both sides and ends the
code; a stranger's message on the topic changes nothing; the topic holds no word of the code.
Live, a short run through ntfy.sh (Q65). Planted: the topic derived from the whole code, and the
test of the topic fails.

## Start condition

T-086 is done: the pairing's exchange exists over a mailbox.

# T-497: A second public Piping Server, `piping.onrender.com`

**Source:** T-442 (2026-11-02); the operator's ruling Q65.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The Piping Server road knows one public server, so when `ppng.io` is down the one road through a
proxy that refuses the WebSocket upgrade has no server.

## Premise

- `crates/podssh-relay/src/piping/server.rs:10` says "DEFAULT_HOST".
- Read on 2026-11-02 (docs/carriers.md, the reverse road, item 5): Piping Server's README lists
  `ppng.io`, `piping.onrender.com` and `piping.glitch.me` as public servers;
  `piping.onrender.com/version` answered `1.12.9`, the version of `ppng.io`; `piping.glitch.me`
  answered 410. Render spins a free web service down after 15 minutes with no inbound traffic,
  and may suspend one for an uncommonly high volume of traffic; whether this one is free was not
  read.

## Approach

1. The road's public servers in order, `ppng.io` then `piping.onrender.com`, each tried once the
   one before failed (a dial, TLS, a 5xx, or a page that is no Piping Server's), never both at
   once (rule 2 of `AGENTS.md`, section 5).
2. The node waits at the first server that answers; a client that meets nobody at the first
   within a bound tries the second; both then meet where the node waits.
3. `PODSSH_PIPING` naming a server keeps that server alone, as now.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test piping
cargo test -p podssh-relay --features piping --test piping_live -- --ignored
```

Two of nwtgck's servers on the loopback, the first stopped: the node and the client meet at the
second. Live, short runs through both public servers (Q65). Planted: the client's bound at the
first server removed, and the test waits past its limit.

# T-498: frp's protocol: a podssh node behind the user's frps, and its visitor

**Source:** T-442 (2026-11-02); the operator's ruling Q66.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

frp is the reverse proxy that most users run themselves (Apache-2.0, about 110,000 stars), and
many already have a frps on a public host, over a WebSocket on port 443 where they need one. A
podssh node cannot be reached through it, and `podssh ssh node://` cannot visit through it, so
such a user runs podssh's relay role beside it.

## Premise

- Read on 2026-11-02 in frp's README and, at v0.71.1 (2026-10-14),
  `fatedier/frp:pkg/util/net/websocket.go` and `fatedier/frp:pkg/msg/msg.go` (docs/carriers.md,
  "Servers that a user runs"): transports `tcp`, `kcp`, `quic`, `websocket` and `wss`, the
  WebSocket at `/~!frp` in binary frames; messages of a type byte and JSON, `Login` with a
  `privilege_key`; STCP, a service with a `secretKey` and no public port, which a visitor reaches
  with the same key (`NewVisitorConn`, a `sign_key` and a timestamp); TLS on by default since
  0.50. The control connection's cipher and multiplexing are not read.
- The roads of `podssh ssh node://` race in `crates/podssh-cli/src/ssh/roads.rs:1`.

## Approach

1. Read frp's client in its source, and pin the versions that podssh speaks.
2. `podssh node NAME --frp URL`, with the token and the STCP secret in a file of mode 0600: the
   node logs in as a frpc over `wss://` through `HTTPS_PROXY`, registers an STCP service of its
   name, and serves each work connection with the end-to-end channel and the resumable layer.
3. `podssh ssh node://NAME` with the same file visits it as an STCP visitor, one road of the race.
4. frps's refusals (a wrong token, a wrong secret, a name taken) in its words.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test frp_road
```

Against frps and frpc of v0.71.1's release (checked by `frp_sha256_checksums.txt`) in
containers, through a plain squid: a podssh node reached by `podssh ssh node://NAME` through frps
over `wss://`; podssh's visitor to a real frpc's STCP service of an sshd; a wrong secret refused
in frps's words. Planted: the sign key of another timestamp, and the visit is refused.

# T-499: IETF's connect-tcp, once it is an RFC

**Source:** T-442 (2026-11-02); the operator's ruling Q66.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

The IETF's template-driven TCP proxying (draft-ietf-httpbis-connect-tcp) is the standard form of
CONNECT for proxies of HTTP/2 and HTTP/3; `--via` speaks classic CONNECT alone (T-439), and the
draft's wire still moves.

## Premise

- Read on 2026-11-02 (docs/carriers.md, "Servers that a user runs"): draft 17 (2026-10-29), a URI
  template with `target_host` and `target_port`; `Upgrade: connect-tcp` on HTTP/1.1, an extended
  CONNECT with `:protocol = connect-tcp` on HTTP/2 and HTTP/3; the payload in capsules DATA and
  FINAL_DATA; the token `connect-tcp-12` for the interop of this version. masque-go's fork speaks
  HTTP/3 alone and cites draft 09; erlang_masque carries raw bytes with no capsules.
- `crates/podssh-ws/src/via/mod.rs:8` says "HTTP/2's CONNECT (RFC 9113, section 8.5)".

## Approach

1. `--via` takes a template (`https://HOST/PATH{?target_host,target_port}`): an extended CONNECT
   on HTTP/2 where the proxy's SETTINGS allow it, the Upgrade on HTTP/1.1, and the capsules.
2. The test runs a server of a project that tracks the RFC.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test via
```

Against that server in a container: sshd's banner through a template on HTTP/2 and on HTTP/1.1.
Planted: a DATA capsule's length read as a byte, and the session's first megabyte fails.

## Start condition

draft-ietf-httpbis-connect-tcp is an RFC, and a server over HTTP/2 or HTTP/1.1 implements it.

# T-550: The quick tunnel's node takes its net's members as its door, with no `--allow`

**Source:** the merge of T-452 (2026-11-02), its drafting agent's note.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A node of the DERP road whose key is a member of the net starts with no `--allow`, its net's
members its whole door (T-452). The quick tunnel's node, whose name is public in the same way,
still refuses to start with no `--allow`, so a member of a net must keep a list of keys beside
the net that already names them.

## Premise

- `crates/podssh-cli/src/node_quick.rs:132`, where the node with no `--allow` was refused: its
  name is public, so only the operator keys of the file came in.
- `crates/podssh-cli/src/node_derp.rs:114` says "pub(crate) fn door(allow: Option<&Path>, place: &Place) -> Result<Door, Refusal>",
  the door of T-452 that the quick tunnel's node can take too.

## Approach

1. The quick tunnel's node reads its door as the DERP road's does: `--allow`, else the net held
   here that names its key; the channel takes `net::admit::doors(.., true)`, the members alone.
2. Its serving line names the door; with neither, the refusal of now, naming the net too.
3. The manual's note of `--quick-tunnel` and `docs/mesh.md` say it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_quick_relay --test node
```

A quick tunnel's node of a member starts with no `--allow` through the stand-in edge, a member
reaches it and a stranger's key is refused at the node; a node of no net and no `--allow` is
refused as now. Planted: the closed door that lets each key in, and the stranger's test fails.

## Correction

2026-11-03. The Prove's run "through the stand-in edge" cannot be made from the binary: the API's
host is a constant (`crates/podssh-relay/src/quick/api.rs:28`), so no test points the node at the
stand-in edge of T-300, which runs in the relay crate's own process. The node's door is the DERP
road's, `net::admit::doors(None, KEY, true)`, whose test of a member and a stranger runs end to
end through stand-in DERP servers (`crates/podssh-cli/tests/derp_net/mod.rs`); here the door is
proven by the start, offline, and by a unit test of the channel that the node builds.

## Done

2026-11-03. The quick tunnel's node reads its door as the DERP road's does (`door_of`): `--allow`,
else the net held here when it names the node's key, whose members alone then come in, also after
the node leaves the net; with neither, the refusal names both ways in (64). Its serving line says
"with no --allow, the members of the net NAME are its door"; with `--relay` and no `--mint`, the
role mints for the same door (`--mint net`).

- `cargo test -p podssh-cli --test node`: 18 passed. A node whose key the net names, with no
  `--allow`, passes each check that needs no network and stops at `PODSSH_OFFLINE` (69); with no
  net held, it is refused, 64, naming `--allow FILE`, the net, and "this host holds no net".
- `cargo test -p podssh-cli --lib node_quick`: 2 passed; the channel of the net's door refuses a
  key that no net names. `--lib`: 796 passed. `--test node_quick_relay` 3 passed, `--test
  derp_road` 6 (the member and the stranger of T-452 among them), the manual's tests 21.
- Planted (`sh scripts/plant-each.sh --here t550-net-door-open`, the door of a node with no list):
  caught, the stranger's test failed.
- `cargo clippy -p podssh-cli --all-targets -- -D warnings` and `cargo fmt --check`: clean.

Waits (Q88): a member through the live quick tunnel, in `quick-tunnel-live.yml`.


# T-551: A copy to a node races the roads that `podssh ssh` races, not the pair's road alone

**Source:** the merge of T-453 (2026-11-02), its drafting agent's note.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

`podssh ssh NAME` of a member races the pair's road with the iroh and DERP roads that its
tickets and its record of pkarr name, so a member whose relay is refused is still reached. A copy
to the same member (`cp`, `mv`, `scp`, `sftp`, `edit`) takes the pair's road alone, and fails
where `ssh` would reach it.

## Premise

- `crates/podssh-cli/src/cp/link.rs:161` says "Transport::Node { label, pair_file, trust, channel, .. } => {",
  and the copy reaches the node by `crate::ssh::node::reach`, the pair's road.
- `crates/podssh-cli/src/ssh/roads.rs:1` says "`podssh ssh node://NAME` over more roads than the pair's (T-164, T-379):".

## Approach

1. The copies' link to a node takes the race of `ssh::roads` (the pair's road, the iroh road, the
   DERP road, the transit relay and Piping Server, and the record's roads), with the same order
   and delays, and keeps the road that answered first for the run.
2. A copy that resumes on another road, as the layer allows, says so at `-v`.
3. The manual's notes of the copies say that they reach a node as `ssh` does.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test net
```

With the pair's road refused at the stand-in relay, `cp` to a member by its name reaches it over
the DERP road that the net names; planted, the race skipped for the pair's road alone, and the
test fails.

## Correction

2026-11-03 (the main session, read before any change). The copies take a stream from `reach` and
keep it for the whole run (`crates/podssh-cli/src/cp/link.rs:161`), while the race of
`ssh::roads::connect` runs SSH itself over the layered stream, its roads borrowing the run's
locals (`crates/podssh-cli/src/ssh/roads.rs:238-246`). So the copies need the race in a task of
its own, which owns what the roads borrow. Measured: `Transport` is `Clone`
(`crates/podssh-cli/src/ssh/resolve.rs:24`), and each road's future is `Send` already (the type
`Going` with `+ Send` compiled with no change elsewhere). The Approach's item 1 is then: the body
of `connect` as a function that hands the layered stream to a closure in the place of
`podssh_ssh::run`; `connect` passes SSH, and a copy's `reach` spawns it with a clone of the
transport and a pipe to the copy, as the pair's road alone does (`crates/podssh-cli/src/ssh/node.rs:351`).
`roads.rs` is at its 500 lines, so the order's words move to `road_link.rs` first.

# T-534: Tailscale's main DERP fleet after tailcat's: a short test that it lets podssh in, then the fallback

**Source:** the operator's ruling Q74 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The DERP road knows tailcat's four servers alone, one in each of four regions, so a node whose
four servers are down, slowed or refused has no DERP road. Tailscale's main fleet has many more
servers, and the operator ruled that podssh tries them after tailcat's, once a short test shows
that they let podssh in.

## Premise

- `docs/decisions.md:29` says "Q74: Tailscale's main DERP fleet, after tailcat's".
- `crates/podssh-relay/src/derp/servers.rs:15` says "The servers of tailcat's map, in the order
  of its regions: New York,", and `crates/podssh-relay/src/derp/servers.rs:97` says "pub fn
  for_client(home: &Server) -> Vec<Server> {": a client tries the ticket's server, then the
  rest of tailcat's four.
- `docs/carriers.md:485` says "88 servers in 28 regions in Tailscale's map, 85 of which
  answered", and `docs/carriers.md:486` says "derper admits each": a `200` on `/` says nothing
  of who may relay, and whether Tailscale's servers run with `--verify-clients` was not read.
  Headscale's documents read the map at `https://controlplane.tailscale.com/derpmap/default`
  (`docs/carriers.md`, the reverse road, item 2).
- `crates/podssh-relay/src/derp/key.rs:126` says "acknowledge, and the name of the program,
  which a server may count by,": a server may refuse podssh by the name of its program.
- `crates/podssh-relay/tests/derp_live.rs:3` says "server of the fleet whose probe answers
  through the proxy of the": the live test of tailcat's fleet, 64 KiB each way, run by hand.
- `AGENTS.md:259` says "session's own host: Tailscale's main DERP fleet, to learn whether it
  lets": short runs from GitHub Actions and the session's host.

## Approach

1. The test first, short (Q74), from GitHub Actions and this host: the first server of each
   region of the map, read on the test's day, one after another; for each, DERP's handshake with
   a random key and podssh's program name, then a node and a client in one process exchange
   64 KiB each way through it, as `derp_live` does for tailcat's. The result of each server (it
   relayed; it closed after the client's info; it never sent its own info) goes into
   `docs/carriers.md` and `docs/STATUS.md`.
2. Where the test shows that the main fleet lets podssh in: its servers in the binary, after
   tailcat's four, as a list read from the map on a date and cited with its source (Q79); the
   node's home is the first of the whole list whose probe answers, and a client's order is the
   ticket's server, then the rest of the list, as now.
3. The node's line names the fleet of its home, and says that the main fleet serves Tailscale's
   clients and that podssh tries it last; `PODSSH_DERP=no` turns the road off as now, and
   `PODSSH_DERP_MAIN=no` keeps tailcat's four alone.
4. `doctor`'s DERP section says which fleet answered. The manual's words are T-533's.
5. Where the test shows that no server lets podssh in: the entry is done with that measurement,
   and the binary names no server of the main fleet, as Q74 asks.

## Decision

- **A server lets podssh in when it relays**: DERP's handshake gets the server's info, and a
  packet between two keys of podssh crosses it. Lost: a `200` on `/` or on `/derp/probe`, which
  says nothing of who may relay.
- **The list is in the binary, with its date and its source**, not the map read at each start:
  one host less on each run, and a name that a proxy may refuse by category. The test runs again
  when the list is read again. Lost: the map at run time, which follows Tailscale's changes.
- **One server of each region first**, so that a node in a cage probes at most one server of a
  region before the next region; the other servers of a region follow the first round.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features derp --lib derp::servers
cargo test -p podssh-relay --features derp --test derp_live -- --ignored
```

Offline: the list's order (tailcat's four, then one server of each region of the main fleet, then
the rest), a client's order for a home of either fleet, and `PODSSH_DERP_MAIN=no`; a stand-in
derper on the loopback that closes after the client's info, as one with `--verify-clients` does,
sends the node on to the next server. Live, short (Q74): the test of step 1. Planted: the main
fleet put before tailcat's, and the test of the order fails.

# T-535: The public Wisp servers that their operators run for that use, as forwarders after the demo server

**Source:** the operator's ruling Q75 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The forward road's fallback to other products' forwarders ends at one Wisp server, Mercury
Workshop's demo server, which its operator offers for demo and testing. When it is down or slowed,
the fallback has no Wisp server more. The operator ruled that podssh tries the public Wisp servers
that their operators run for that use, after the other forwarders, and never a domain that looks
taken over.

## Premise

- `docs/decisions.md:28` says "Q75: the public Wisp servers that are made for it, as fallbacks",
  and `docs/decisions.md:24` says "A domain that looks taken over (a school's, a church's, a
  shop's, or a name made to look like one) is never used and never published".
- `crates/podssh-ws/src/forwarder/builtin.rs:7` says "After them, and never first, by the
  operator's ruling Q65: the demo", and
  `crates/podssh-cli/src/forwarder/fallback.rs:4` says "stderr with each one's name; the Wisp
  demo server last, never first, by".
- `docs/carriers.md:239` says "sweep took 76 more Wisp servers from the server lists of web
  proxies on", and `docs/carriers.md:247` says "No host names an operator, terms or limits. The
  sweep flagged 54 of": the sweep's hosts give no operator, and most are domains of other
  parties, so none of them is a source for this entry.
- `AGENTS.md:260` says "podssh in (Q74); the public Wisp servers that their operators run for
  that": short live runs may reach them.

## Approach

1. The research first, through the services of web.pkgforge.dev: Wisp servers whose operator
   says, on a page of the operator's own, that the server is public for the use of others, as
   Mercury Workshop's page says of its demo server. For each: its operator, its page, its terms
   and limits, its software (wisp-server-python, wisp-js, or another), the version of Wisp that it
   speaks, whether it filters port 22, and its category in a filter list. Never a server list of
   a web proxy, and never a host that the sweep flagged (Q79). Each fact and its source go into
   `docs/carriers.md`.
2. Each server that passes: a short live run (Q75) from GitHub Actions and this host, GitHub's
   version line through it, then a word of `crates/podssh-ws/src/forwarder/builtin.rs` after
   `wisp`, with its note, in the order that the research gives.
3. The fallback tries them after the demo server, each with its name on stderr, as now.
4. Where no server passes: the entry is done with the research, and the fallback keeps the demo
   server alone.

## Decision

A server passes when its operator names it on a page of the operator's own as offered to others,
with no account, and the domain is the operator's own. Lost: the 53 hosts of the sweep that took
a bare upgrade, which no operator offers.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --lib forwarder::builtin
cargo test -p podssh-cli --test forwarder_cli
cargo test -p podssh-ws --test live_forwarder -- --ignored
```

The words in their order, each new one after `wisp`; the fallback through stand-ins tries them
after the demo server; live, GitHub's version line through each new server (Q75). Planted: a new
server put before the demo server, and the test of the order fails.

# T-536: NetBird: whether its relays or its signal server carry a podssh session with no account

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The operator ruled that podssh uses the fallbacks that exist: each overlay network that the sweep
of 2026-11-02 named gets a research entry, for a host with TCP to 443 alone or where UDP passes,
and each that passes becomes a road tried unasked after podssh's own. NetBird's relays answer on
port 443 over a WebSocket.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:914` says "NetBird's relays, 67 over a WebSocket on TCP 443," and
  `docs/carriers.md:917` says "so each peer needs an account": a relay admits a peer with a token
  of NetBird's management server alone.
- `crates/podssh-iroh/src/probe.rs:1` says "Whether this host's UDP goes out and comes back
  (T-359). A sandbox can": podssh probes UDP before it takes it.

## Approach

1. Read NetBird's parts in its source and documents: the management server and how a peer joins
   (a setup key, an account of netbird.io's cloud, or a server that the user runs), the signal
   server and whether it passes messages between two keys with no account, and the relays and
   their tokens.
2. For each part: whether it answers on 443 by name, with TLS or a WebSocket, through an HTTP
   CONNECT proxy, or needs UDP.
3. podssh's side: what a podssh end would speak (gRPC of the signal server, the relay's
   messages), in pure Rust in the library crates (rule 4 of `AGENTS.md`, section 5), and its size.
4. The verdict in `docs/carriers.md` with its sources: a road or a meeting point, with a feature
   entry, tried unasked after podssh's own roads (Q77); or out, for need of an account, no stream,
   or no port that the host reaches.

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where NetBird passes.

# T-537: Firezone: whether its relays or its portal carry a podssh session with no account

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

Firezone is an overlay network that the sweep of 2026-11-02 named; the operator's ruling Q77 gives
it a research entry, for a host with TCP to 443 alone or where UDP passes.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:918` says "Firezone's relays are TURN on UDP, behind an account".

## Approach

1. Read Firezone's parts in its source and documents: its portal and how a client or a gateway
   joins, its relays (TURN, and whether over TCP or TLS on 443), and what a user's own Firezone
   gives a podssh node.
2. For each part: an account or none, the port and the transport, through an HTTP CONNECT proxy
   or not, and where UDP passes.
3. podssh's side: its size, in pure Rust.
4. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes (Q77).

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where Firezone passes.

# T-538: ZeroTier: whether its roots and its TCP relay on 443 carry a podssh session

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

ZeroTier's roots use UDP, but ZeroTier Inc. runs a TCP relay on port 443 that its agent falls
back to where UDP fails. Whether a podssh end can join a ZeroTier network through it, with no
account, and carry a session, was not read.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:918-919` says "ZeroTier's roots use UDP 9993", and
  `docs/carriers.md:925-926` says "ZeroTier Inc. runs a TCP relay that ZeroTier One falls back
  to where it cannot use UDP": an IP literal on port 443, which its document calls slow.

## Approach

1. Read ZeroTier's protocol (its packets, its identities, the roots, a network's controller and
   how it admits a member) and the TCP relay's framing, in ZeroTierOne's source and in pylon's.
2. Whether a member joins with no account: a network whose controller the user runs (a podssh
   node as its controller), or a public network; and what ZeroTier's license allows.
3. Through a proxy: the TCP relay by its IP literal on 443, which a proxy that waits for TLS or
   that allows listed names refuses (Inferred, as for Syncthing's relays); and where UDP passes.
4. podssh's side: a Rust implementation of ZeroTier, or the size of one in pure Rust, and a
   stream over its frames under the resumable layer.
5. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes (Q77).

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where ZeroTier passes.

# T-539: Tox: whether its TCP relays on 443 carry a podssh session between two keys

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Tox's TCP relays try port 443 first, and a few nodes of its public list listen there. Two Tox
keys reach each other through them with no account; whether that carries a podssh session was not
read.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:920-921` says "Tox's TCP relays try port 443 first", and
  `docs/carriers.md:922` says "but they speak Tox's own handshake, not TLS".

## Approach

1. Read Tox's TCP relay protocol (`irungentoo/toxcore:docs/TCP_Network.txt`), its friend
   connections and the size of a lossless packet, and the public list of nodes with their ports.
2. Through a proxy: a CONNECT to a node's IP literal on 443, then Tox's handshake; which proxies
   refuse it (one that waits for TLS, one that allows listed names); and where UDP passes, Tox's
   DHT.
3. podssh's side: a maintained Rust implementation of Tox, or the size of the TCP client and the
   friend connection in pure Rust; a stream over its packets under the resumable layer.
4. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes (Q77).

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where Tox passes.

# T-540: Yggdrasil again, under Q77: a port of its links and routing, over its peers on 443

**Source:** the operator's ruling Q77 (2026-11-02); T-442's verdict.
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

T-442 left Yggdrasil out: no Rust crate implements it, its peers ask for few nearby links, and
podssh's own roads on 443 carry the same pairs. The operator's ruling Q77 asks for each fallback
that exists, so the verdict is read again: whether a podssh end can reach another through one or
two public peers on 443, and at what cost.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:848` says "Of its 365 entries, 20 are", and `docs/carriers.md:852` says "No
  Rust crate implements the network"; `docs/carriers.md:855-856` says "Out, as the roads of
  podssh's own nodes on 443 carry the same pairs".

## Approach

1. Count the public peers again on `wss://` and `tls://` on 443 by name, and those online.
2. Read the parts that a podssh end needs: a peer link over a WebSocket, the handshake, the
   routing and the sessions of two keys, in Yggdrasil's Go source (its license read too), and the
   size of a port in pure Rust; or a smaller part that two podssh ends need alone (one peer each,
   the same peer for both).
3. The peers' etiquette ("a small number of NEARBY peers"): one peer for each end, for the time
   of a session.
4. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes (Q77),
   tried after podssh's own roads.

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where Yggdrasil passes.

# T-541: croc: whether a public croc relay carries a podssh session from a host with 443 alone

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

croc pairs two ends by a code through a public relay, with no account. Its relay listens on TCP
9009, which a host with 443 alone cannot reach; whether a public croc relay answers on 443, and
whether its rooms carry a podssh session, was not read.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:919` says "croc's relay uses TCP 9009".

## Approach

1. Read croc's relay protocol (its rooms, its ports, its PAKE) and its documents: the default
   public relay, its ports, and whether a relay may listen on 443.
2. Through a proxy: croc's own client takes a proxy for its relay connection (read); a port that
   a proxy of 443 alone refuses.
3. podssh's side: the room protocol in pure Rust under the channel and the layer, or croc's
   relay as a meeting point of the pairing.
4. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes (Q77).

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where croc passes.

# T-542: HyperDHT: whether Holepunch's DHT and its relays reach a podssh end by its key

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

HyperDHT finds a peer by its public key and punches a hole between two ends, with no account. Its
bootstrap nodes use UDP; whether a podssh end with UDP can reach a node through it, and whether
any part of it answers over TCP on 443, was not read.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:919-920` says "the bootstrap nodes of HyperDHT, Cabal and Hyphanet use UDP
  or other ports".
- `crates/podssh-relay/src/quick/probe.rs:1` says "The probe of UDP before QUIC (T-400): one QUIC
  packet of a reserved": podssh probes UDP before a road over it.

## Approach

1. Read HyperDHT's protocol (its RPC over UDP, the announce and lookup of a key, the hole
   punching, the Noise handshake, and its relays: blind relays through a third peer) and its
   public bootstrap nodes.
2. Where UDP passes: whether two podssh ends meet by a key derived from the pair's secret, and a
   stream between them under the layer. With TCP to 443 alone: whether any part answers there.
3. podssh's side: a Rust implementation, or the size of one in pure Rust.
4. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes (Q77).

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where HyperDHT passes.

# T-543: Cabal: whether it adds a carrier or a meeting point beyond HyperDHT

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

Cabal is a chat of peers that the sweep of 2026-11-02 named among the overlay networks; its
bootstrap nodes use UDP or other ports. Whether it has a part of its own that carries bytes from
a host with 443 alone, or only what HyperDHT gives (T-542), was not read.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:919-920` says "the bootstrap nodes of HyperDHT, Cabal and Hyphanet use UDP
  or other ports".

## Approach

1. Read Cabal's stack and its public parts: the swarm that it joins, and any server of its own (a
   seeder, a bridge to the web) that answers on 443 by name.
2. Each part: an account or none, the port and the transport, and whether it carries bytes
   between two keys.
3. The verdict in `docs/carriers.md` with its sources: a road or a meeting point with a feature
   entry (Q77), the same as T-542's, or out.

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where Cabal adds a part.

# T-544: Hyphanet: whether a podssh end can use it with no node of its own

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

Hyphanet (formerly Freenet) stores and forwards signed and keyed data between peers over UDP. Its
seed nodes use UDP or other ports; whether a podssh end can use it as a carrier or a meeting point
from a host with 443 alone, or where UDP passes, was not read.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:919-920` says "the bootstrap nodes of HyperDHT, Cabal and Hyphanet use UDP
  or other ports".

## Approach

1. Read Hyphanet's protocol (its node's transport over UDP, its keys, its client protocol FCP)
   and its public parts: a gateway that answers on 443, or seed nodes.
2. Whether a podssh end can use it with no Hyphanet node of its own (a node is Java, another
   program, which rule 3 of `AGENTS.md`, section 5, forbids podssh to start), and with what
   latency for the messages of the pairing or of a session.
3. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes (Q77).

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where Hyphanet passes.

# T-545: Nostr's ephemeral events as a meeting point of the pairing by a short code

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

T-086's pairing by a short code meets at magic-wormhole's mailboxes. When both are down, or
refused by a proxy's filter, two ends cannot pair. The operator ruled that Nostr's ephemeral
events become a meeting point of the pairing, tried unasked after podssh's own.

## Premise

- `docs/decisions.md:26` says "Nostr's ephemeral events and the trackers become meeting points of
  the pairing, in the same order".
- `docs/carriers.md:760` says "relays need not store ephemeral events (kinds 20000 to 29999)";
  `docs/carriers.md:763` says "has BIP-340 signatures", of the pure-Rust `k256`, where the
  `nostr` crate needs a C library.
- `docs/carriers.md:765` says "Each relay has its own operator and its own policy", and
  `docs/carriers.md:766` says "which its NIP-11 document gives".
- `TODO/reverse.md:1137` says "The meeting point: magic-wormhole's mailbox": T-086's exchange
  runs over a mailbox that stores and forwards the messages of two sides.

## Approach

1. The research first: public relays whose NIP-11 document asks no authentication, no payment and
   no restricted writes, that take ephemeral events and pass them to each subscriber, on 443 by
   name; each with its operator and its source (Q79), in `docs/carriers.md`.
2. A carrier of T-086's messages: each message one event of an ephemeral kind that podssh fixes,
   signed with BIP-340 by a key made for that code alone, with a tag derived from the code's
   nameplate alone, never from the words that SPAKE2 takes, as T-496 derives its topic; each
   under the size that the relay's NIP-11 gives.
3. NIP-01 over podssh-ws's WebSocket through `HTTPS_PROXY`: `REQ` with a filter of the kind and
   the tag from the code's start, `EVENT` to publish, and `OK`, `CLOSED` and `NOTICE` read for a
   refusal.
4. One relay at a time, in the order of the binary's list: both ends start at the first relay that
   answers, and an end that hears nothing within a bound moves to the next and sends again.
5. Tried after the mailboxes and after ntfy (T-496); `PODSSH_PAIR_NOSTR` names another relay, or
   `no`.

## Decision

BIP-340 by `k256`, pure Rust, and NIP-01's JSON written by podssh. Lost: the `nostr` crate, whose
`secp256k1` is C (`docs/carriers.md`, the meeting points).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,code --test pair_nostr
```

Against a Nostr relay of another project (nostr-rs-relay or strfry) in a container: two peers with
one code pair through it; a wrong code fails both sides and ends the code; a stranger's event with
the same tag changes nothing; the tag holds no word of the code; the signatures pass the test
vectors of BIP-340. Live, a short run through one public relay (T-548's Decision). Planted: the tag derived
from the whole code, and the test of the tag fails.

## Start condition

T-086 is done: the pairing's exchange exists over a mailbox.

# T-546: Trackers as meeting points: whether a BitTorrent or WebTorrent tracker passes the pairing's messages

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The operator ruled that the trackers become meeting points of the pairing, after Nostr's. A
tracker gives the peers of one torrent each other's addresses, and a WebTorrent tracker passes
offers between them over a WebSocket; whether either carries the messages of T-086's pairing, or a
node's roads, from a host with 443 alone, was not read.

## Premise

- `docs/decisions.md:26` says "Nostr's ephemeral events and the trackers become meeting points of
  the pairing, in the same order".
- `docs/carriers.md:941-942` says "a tracker gives a peer list, or passes WebRTC's offers between
  the peers of one torrent".

## Approach

1. Read the tracker protocols: HTTP's announce (BEP 3), UDP's (BEP 15), and WebTorrent's
   WebSocket tracker (`webtorrent/bittorrent-tracker`): the fields of an offer and an answer, their
   sizes, whether a tracker checks that an offer is WebRTC's, and how long it keeps one.
2. Whether two ends meet by an infohash derived from the code's nameplate, and pass T-086's few
   messages as offers and answers; or a node's tickets, read by a client of its pair.
3. The trackers on 443 by name, each with its operator and its source, and their categories
   (Q79).
4. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes, tried
   after Nostr's (Q77).

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where a tracker passes.

# T-547: The pub/sub networks and the public MQTT brokers, as carriers or meeting points

**Source:** the operator's ruling Q77 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

The sweep of 2026-11-02 named pub/sub networks (Bluesky's relays, ActivityPub's relays, the Waku
Network, XMTP, Farcaster's hubs), and `docs/carriers.md` has the public MQTT brokers. Each was
read in part; which of them carries a message from one podssh end to another with no account, on
443, was not settled.

## Premise

- `docs/decisions.md:26` says "Q77: use the fallbacks that exist".
- `docs/carriers.md:930-931` says "relays send each record to each consumer, and a record is
  written to a PDS by an account"; `docs/carriers.md:931` says "ActivityPub's relays take a
  server's posts"; `docs/carriers.md:934` says "takes a message from a member alone" (the Waku
  Network); `docs/carriers.md:938` says "an inbox that a wallet's signature registered" (XMTP);
  `docs/carriers.md:938-939` says "The Farcaster hubs of the sweep were gone".
- `docs/carriers.md:870` says "none is reachable on 443 in practice" (the public MQTT brokers).

## Approach

1. For each network: whether a message goes from one end to another with no account of the
   user's (a PDS or a server that takes posts with none, a fleet that relays with no membership, a
   key that registers itself), its port and transport on 443 by name, its sizes and its limits.
2. The public MQTT brokers again: each that answers over a WebSocket on 443, with its operator and
   its terms.
3. The verdict for each in `docs/carriers.md` with its sources; each that passes becomes a feature
   entry, a meeting point of the pairing or a carrier, tried after podssh's own (Q77).

## Prove

```sh
cargo todo check
```

The verdicts and their sources in `docs/carriers.md`; a feature entry filed for each that passes.

# T-548: Pinggy as a last fallback of the reverse road: SSH inside TLS on 443, and a TLS tunnel that ends at the node

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

Pinggy gives a tunnel with no account. Its node's leg is SSH inside TLS on port 443, also through
an HTTP proxy, and its TLS tunnels on 443 are routed by SNI, so a client's leg is TLS by name with
no upgrade and the TLS ends at the node: both ends pass a cage of an HTTPS proxy, a proxy that
refuses the upgrade among them. podssh does not use it. The operator ruled that each public
service that needs no account and carries bytes is a last fallback, whatever its terms.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:885-887` says "Pinggy's leg need not be raw SSH, as it takes SSH inside TLS
  on ports 443 and 7878, also through an HTTP proxy, and gives TLS tunnels on 443 that it routes
  by SNI", and `docs/carriers.md:891-892` says "Pinggy's free tunnels end at 60 minutes".
- `crates/podssh-ssh/src/remote.rs:4` says "podssh joins it to the forward's target": podssh's
  SSH client asks a remote forward and takes its `forwarded-tcpip` channels (`-R`).
- `crates/podssh-ws/src/tls_server.rs:1` says "TLS for a server of podssh's": the node can end a
  visitor's TLS itself.

## Approach

1. Read first, in Pinggy's documents: the user name and the forward that a TLS tunnel with no
   account asks for, how the tunnel's name comes back, the limits of a free tunnel and its terms.
2. The node: podssh's SSH client to Pinggy on 443 inside TLS, through `HTTPS_PROXY`, asks the
   remote forward of a TLS tunnel; each `forwarded-tcpip` channel is a visitor's TLS, which
   podssh-ws's server ends, then the end-to-end channel and the resumable layer above, as on
   each carrier.
3. A free tunnel's name changes at each tunnel: the node puts it in its record (T-445) and the
   net's list, and a client reads it there; a tunnel that ends at 60 minutes is opened again, and
   the layer moves its sessions.
4. The client: TLS by name to the tunnel's name on 443 through `HTTPS_PROXY`, then the channel to
   the node's pinned key: a road of `podssh ssh node://NAME`'s race, last.
5. A last fallback (Q78): tried after podssh's own roads and after the services of Q65 that allow
   the use; a line on stderr names Pinggy and says that a third party that nobody vouches for
   carries the session, and that SSH and the end-to-end channel keep its bytes private;
   `PODSSH_PINGGY=no` turns it off, and so does the switch of the Decision.

## Decision

- **One switch for all the last fallbacks of Q78**, `PODSSH_LAST_RESORT=no`, beside each road's
  own variable; the first of T-548, T-549 and T-565 to T-579 to be built adds it, and T-533's
  manual names it. Lost: a variable for each road alone, which leaves a user who wants none of
  them a dozen to set.
- **Short live tests against the services of Q77 and Q78, for the operator to confirm (Q86).**
  Q78 lets a binary in the field try each of them unasked, but `AGENTS.md` (section 4) names no
  live target for them, as it names Q74's, Q75's and Q76's. The call: a short run for each, as
  Q65 allows for its services (one node and one client, a few MiB at most, throwaway keys, the
  service's tunnel or name given up at the end), from GitHub Actions and the session's own host;
  no throughput run, and no host that looks taken over (Q79). Each entry of T-545, T-548, T-549
  and T-565 to T-579 that names a live run takes this one. Lost: no live run until the operator
  rules, which leaves each road tested against stand-ins alone, and the protocol of a service
  that has no published server (Serveo's alias, `ssh-j.com`) tested against nothing that podssh
  did not write.
- **The node's certificate is its own, self-signed, and the client checks the channel's key**, as
  a free tunnel's name changes each hour, where a certificate of ACME for each name would spend
  its limits. Inferred: a proxy that re-terminates TLS on the client's side refuses that
  certificate, so the road there needs a proxy that passes TLS; the entry measures it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test pinggy_road
```

Against a stand-in of Pinggy in containers, software that podssh did not write: OpenSSH's sshd
behind stunnel on 443 for the node's leg, and HAProxy that routes the forward's port by SNI for
the client's, with a plain squid as the proxy at both ends: `podssh node NAME TARGET` makes its
tunnel there, and `podssh ssh node://NAME 'echo ok'` passes through it with the pair's road down;
stderr has the line about the third party. Live, short, through Pinggy (the Decision). Planted: the
client's check of the node's key skipped, and the test of a stranger's node fails.

# T-549: Serveo as a last fallback: a node's alias by SSH, and a client's hop through it

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Serveo forwards SSH to a private alias with no account, over raw SSH on port 22 or 443: a node
asks for an alias, and a client jumps to it through Serveo. Raw SSH on 443 passes a proxy that does
not wait for TLS. podssh does not use it; Q78 makes it a last fallback, whatever its terms.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:887-888` says "Serveo documents private SSH forwarding by alias with no
  account, over raw SSH on 22 or 443", and `docs/carriers.md:892` says "Serveo's anonymous TCP at
  10 minutes".
- `crates/podssh-ssh/src/remote.rs:4` says "podssh joins it to the forward's target", and
  `crates/podssh-cli/src/ssh/jump.rs:100` says "The first hop's tunnel": the remote forward and the
  first hop of `-J` exist.

## Approach

1. Read first, in Serveo's documents: the form of a private alias, how a client reaches it, the
   bound of anonymous TCP, its terms.
2. The node: podssh's SSH client to Serveo on 443 (then 22), raw SSH through `HTTPS_PROXY`'s
   CONNECT, asks the remote forward of an alias derived from the node's key, so that a client
   computes it; an alias that another took is named, and the node takes the next of its series.
3. The client: Serveo as the first hop of `node://NAME`'s road, a `direct-tcpip` channel to the
   alias, then the end-to-end channel to the node's pinned key, so a stranger at the alias is
   refused.
4. The 10-minute bound: the node asks again before it, and the layer moves its sessions.
5. A last fallback (Q78), with the line of T-548's step 5; `PODSSH_SERVEO=no`, and the switch of
   T-548's Decision.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test serveo_road
```

Against a stand-in written from Serveo's documents (its alias forward is not OpenSSH's), with a
plain squid as the proxy: a node's alias, a client's hop, 1 MiB each way under the channel; a
stranger at the alias refused. Live, short, through Serveo (T-548's Decision), the test that software that
podssh did not write needs. Planted: the alias not derived from the key, and the test of the
client's alias fails.

# T-565: localhost.run as a last fallback: the relay role behind a tunnel of HTTP made by `ssh -R`

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

localhost.run makes a public HTTPS name for a node with no account: the node asks a remote forward
of port 80 over SSH, and the service ends HTTPS on 443 and sends plain HTTP down the tunnel. A
client in a cage reaches the name on 443. podssh's relay role already serves behind a quick tunnel
with no listener; behind this tunnel it would give the node a road where its egress reaches SSH.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:896` says "which names no port, so SSH on port 22 (Inferred)", and
  `docs/carriers.md:896-897` says "a free domain carries HTTP alone, changes after a few hours
  and has a speed limit"; `docs/carriers.md:898` says "443 ends at its edge, which sends plain
  HTTP down the tunnel".
- `crates/podssh-relay/src/serve/behind.rs:1` says "The relay role behind a node's quick tunnel
  (T-428): the role's routes as"; `crates/podssh-ssh/src/remote.rs:4` says "podssh joins it to
  the forward's target".

## Approach

1. Measure first, short (T-548's Decision): how the free domain comes back, how long it lasts, and whether the
   service's edge passes a WebSocket upgrade and a streamed body, which the relay's contract and
   the split road need.
2. A module for a tunnel of HTTP made by `ssh -R`, which T-566 and T-567 take too: podssh's SSH
   client to the service with a remote forward of port 80; each `forwarded-tcpip` channel a
   visitor's plain HTTP, served by the relay role as T-428's origin serves the quick tunnel's.
3. The node puts its domain in its record (T-445) and the net's list; a client takes the relay
   road to `https://DOMAIN` as to a relay of another deployment (Q49), with the node's pinned key.
4. A last fallback (Q78), with the line of T-548's step 5; `PODSSH_LOCALHOST_RUN=no`, and the
   switch of T-548's Decision.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_tunnel_http
```

Against a stand-in in containers, software that podssh did not write: OpenSSH's sshd that takes
the remote forward, behind nginx that ends TLS and sends HTTP to it, with a plain squid as the
proxy: `podssh node NAME TARGET` behind it and `podssh ssh node://NAME 'echo ok'` with the pair's
road down. Live, short, through localhost.run (T-548's Decision). Planted: the visitor's channel joined to
TARGET in place of the relay role, and the test of the contract fails.

# T-566: srv.us as a last fallback: an HTTPS name derived from the node's SSH key

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

srv.us makes HTTPS names for a node's remote forward over SSH, with no account, and its README says
that the names derive from the SSH key, so a node's name could stay the same from run to run, and
a client that knows the node's key could know its name. podssh does not use it.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:954` says "derived from your SSH key", with no account and with a key
  required; `docs/carriers.md:948` says "on port 22 in their own commands" of the SSH tunnel
  providers of the sweep.

## Approach

1. Read first, in srv.us's source (0BSD): how the name derives from the key, its limits, and
   whether its edge passes a WebSocket upgrade and a streamed body.
2. A word of T-565's module: the remote forward that srv.us asks for, with a key of the node's own
   for that service.
3. Where the name is a function of the key: the client computes it from the node's pinned key, and
   needs no meeting point (Inferred, to read); else the node's record (T-445) carries it.
4. A last fallback (Q78), with the line of T-548's step 5; `PODSSH_SRV_US=no`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_tunnel_http -- srv_us
```

The name computed from a key equals srv.us's own derivation, on vectors from its source; the word
through T-565's stand-in. Live, short, through srv.us (T-548's Decision). Planted: a wrong derivation, and the
test of the vectors fails.

## Start condition

T-565 is done: the module for a tunnel of HTTP made by `ssh -R` exists.

# T-567: tunnl.gg as a last fallback, a word of the tunnel of HTTP made by `ssh -R`

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

tunnl.gg gives HTTPS names for a remote forward over SSH on port 22, with no account. It has the
shape of localhost.run's tunnel; podssh does not use it.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:948` says "on port 22 in their own commands", and
  `docs/carriers.md:950` says "gives HTTPS URLs alone".

## Approach

1. Read first, in tunnl.gg's README and source (MIT): its command, its names and their life, its
   limits, and whether its edge passes a WebSocket upgrade and a streamed body.
2. A word of T-565's module; the node's record (T-445) carries the name.
3. A last fallback (Q78), with the line of T-548's step 5; `PODSSH_TUNNL=no`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_tunnel_http -- tunnl
```

The word through T-565's stand-in. Live, short, through tunnl.gg (T-548's Decision). Planted: the word's
forward of another port, and the test of the stand-in fails.

## Start condition

T-565 is done: the module for a tunnel of HTTP made by `ssh -R` exists.

# T-568: localtunnel as a last fallback: the relay role behind `localtunnel.me`

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

localtunnel's public server gives a node an HTTPS name with no account: the node asks for a tunnel
over HTTPS, then opens raw TCP connections to a port that the server names, and each carries a
visitor's HTTP. A client in a cage reaches the name on 443. podssh does not use it.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:956` says "a port and a URL, then opens raw TCP to that port", and
  `docs/carriers.md:957` says "request meets a reminder page unless it carries the header".
- `crates/podssh-relay/src/serve/behind.rs:1` says "The relay role behind a node's quick tunnel
  (T-428): the role's routes as".

## Approach

1. Read first, in localtunnel's client and server (both MIT): the answer of `?new` (its id, its
   port, its count of connections, its URL), how the server joins a visitor to a connection,
   whether it passes a WebSocket upgrade, and the tunnel password of its public server.
2. The node: the request over HTTPS through `HTTPS_PROXY`, then the connections to the named port,
   directly where the egress reaches it or by a CONNECT that the proxy allows; each connection
   served by the relay role, as T-428's origin serves the quick tunnel's.
3. The client: the relay road to the URL with the header `Bypass-Tunnel-Reminder`, and the node's
   pinned key; the URL in the node's record (T-445).
4. A last fallback (Q78), with the line of T-548's step 5; `PODSSH_LOCALTUNNEL=no`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test localtunnel_road
```

Against localtunnel's own server (`localtunnel/server`) in a container, with a plain squid:
`podssh node NAME TARGET` behind it and `podssh ssh node://NAME 'echo ok'` with the pair's road
down. Live, short, through `localtunnel.me` (T-548's Decision). Planted: the header left out, and the live
client meets the reminder page (the test names it).

# T-569: bore.pub as a last fallback: a raw TCP port for the node, reached by the client's other roads

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

bore.pub gives a node a public TCP port with no account: the node's control connection is on port
7835, and the public port is one that the server names. A node whose egress reaches 7835 gets a
port; a client reaches it directly where its egress allows, or through the forward road's
forwarders (Q56) where a proxy allows 443 alone. podssh does not use it.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:903-904` says "JSON messages ended by a zero byte on the control port 7835",
  and `docs/carriers.md:900-901` says "isn't meant for long-lived connections".

## Approach

1. The node: TCP to the server's port 7835 (directly, or by a CONNECT that the proxy allows),
   `Hello` with port 0, the server's `Hello` with the public port; each `Connection` taken on a
   new connection with `Accept`, then the end-to-end channel and the layer above, raw.
2. The public port in the node's record (T-445); the client dials it directly, or through a
   forwarder of Q56 that takes the target from its URL, which reaches a port that the client's
   proxy refuses.
3. The server's restarts: the node registers again, and the layer moves its sessions.
4. A last fallback (Q78), with the line of T-548's step 5; `PODSSH_BORE=no`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features bore --test bore_link
```

Against bore's own server (`bore server` of its release, checked by its sums) in a container:
a node registers, a client reaches its port, and 1 MiB goes each way under the channel; a server
that restarts makes the node register again. Live, short, through bore.pub (T-548's Decision). Planted: the
`Accept` sent on the control connection, and the test of a second visitor fails.

# T-570: `ssh-j.com` as a last fallback: a public SSH jump and forward by name

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`ssh-j.com` is a public SSH server for jumps and forwards, with no account, over raw SSH on port
22: a node forwards a name to itself, and a client jumps to that name. podssh does not use it.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:946-947` says "a public SSH jump and forwarding server with no account", and
  `docs/carriers.md:948` says "on port 22 in their own commands".
- `crates/podssh-cli/src/ssh/jump.rs:100` says "The first hop's tunnel".

## Approach

1. Read first, in its author's pages: the forms of a forward and of a jump, its names, its limits.
2. The node: podssh's SSH client to it on port 22 (directly, or by a CONNECT that the proxy
   allows), a remote forward of a name derived from the node's key.
3. The client: it as the first hop of `node://NAME`'s road, directly or through a forwarder of
   Q56 where the client's proxy refuses port 22, then the channel to the node's pinned key.
4. A last fallback (Q78), with the line of T-548's step 5; `PODSSH_SSH_J=no`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_j_road
```

Against a stand-in in a container: OpenSSH's sshd as the jump, with a remote forward of the
node's; a client's hop through it; 1 MiB each way under the channel. Live, short, through
`ssh-j.com` (T-548's Decision). Planted: the name not derived from the key, and the test of the client's name
fails.

# T-571: Syncthing's relays on 443 as a last fallback of the reverse road

**Source:** the operator's ruling Q78 (2026-11-02); T-442's verdict.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Syncthing's relays are run by volunteers for any client, and their protocol invites other
programs. A few of the pool listen on 443, each as an IP literal; their session mode is plain
TCP. T-442 left them out; Q78 makes them a last fallback.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:833-834` says "87 of the pool's 100 relays use port 22067 and only 8 use 443,
  each as an IP literal", and `docs/carriers.md:835-836` says "session mode is raw TCP while the
  protocol mode needs client certificates"; `docs/carriers.md:842` says "session mode cannot
  start as TLS does".
- `crates/podssh-ws/src/tls_server.rs:1` says "TLS for a server of podssh's": a certificate of
  podssh's own, whose digest would be the node's device ID.

## Approach

1. Read relay-v1 again for its messages (join a relay, a session's invitation, a request to
   connect to a device, join a session) and the pool's list at `relays.syncthing.net/endpoint`.
2. The node: protocol mode to a relay of the pool on 443 (TLS with a certificate of its own,
   whose digest is its device ID), waits for an invitation; the client: a request to connect to
   the node's device ID, then session mode to the address that the invitation names, raw; the
   end-to-end channel and the layer above.
3. The relays on 443 alone, each by its IP literal through a CONNECT that names it; the node's
   relay in its record (T-445), so that both ends use the same one.
4. A last fallback (Q78), with the line of T-548's step 5; `PODSSH_SYNCTHING_RELAY=no`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features strelay --test strelay_link
```

Against Syncthing's own relay server (`strelaysrv` of its release, checked by its sums) in a
container on port 443: two podssh ends meet, and 1 MiB goes each way under the channel; a request
for another device ID gets no session. Live, short, through one relay of the pool on 443 (T-548's Decision).
Planted: the invitation's key ignored, and the join of the session fails.

# T-572: File hosts and paste sites as a carrier that stores and forwards: the research

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

File hosts and paste sites take an upload with no account and give it to anyone with its link.
Each piece of a session could be one upload, sealed by the end-to-end channel, where a proxy
refuses each other road. Their APIs, limits and terms were not read for that use; Q78 makes them a
last fallback, whatever their terms.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:390-391` says "each keeps whole uploads, for hours or days, where anyone with
  the link reads them".
- `docs/carriers.md:644-645` says "makes the client ask for numbered pieces": the Piping Server
  road already carries a session as a series of whole uploads.

## Approach

1. Pick the hosts: those of the sweep and others, 0x0.st among them, that take an upload over
   HTTPS on 443 with no account and serve it by URL; for each, its API, the size and the life of
   an upload, whether the uploader names the path, whether it deletes, its limits, its terms, its
   category, and its operator (Q79: no domain that looks taken over).
2. The design: each piece of the layer's link one upload, sealed and numbered; how the other end
   learns each URL where the host names it (a meeting point of T-496 or T-545, or a paste that
   lists them) or derives it where the uploader names it; the latency, the cost to the host, and
   the delete after a read.
3. The verdict in `docs/carriers.md` with its sources, and a feature entry for the carrier with
   the hosts that pass, the last of the last fallbacks (Q78).

## Prove

```sh
cargo todo check
```

The verdict, the hosts and their sources in `docs/carriers.md`; a feature entry filed for the
carrier where hosts pass.

# T-573: VMess's protocol: the research, for the public proxy nodes that speak it alone

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The public lists of proxy nodes give VLESS, VMess and Trojan nodes. podssh speaks VLESS (T-440)
and will speak Trojan (T-491); VMess's protocol was not read, so the nodes that speak it alone
are out of T-574's reach.

## Premise

- `docs/decisions.md:25` says "and the lists of public proxy nodes (VLESS, VMess, Trojan) are a
  last fallback".
- `crates/podssh-ws/src/vless/mod.rs:1` says "VLESS (T-440, the operator's ruling Q66): a server
  that the user runs,".

## Approach

1. Read VMess's protocol in V2Ray's and Xray-core's documents and source: its form with an AEAD
   header, the older form that servers refuse, its ciphers and keys, its use over a WebSocket and
   TLS.
2. The ciphers that it needs against those of podssh-ws (rule 4 of `AGENTS.md`, section 5).
3. The share of the nodes of the lists that T-574 picks that speak VMess alone, counted on a day.
4. The verdict in `docs/carriers.md` with its sources: VMess joins T-574's fallback by a feature
   entry, or stays out with its reason.

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where VMess passes.

# T-574: The public proxy nodes of aggregator lists (VLESS, Trojan) as a last fallback of the forward road

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Public lists on GitHub give proxy nodes, VLESS and Trojan among them, over a WebSocket or TLS on
443, each of which dials the target that a client names. Their operators are anonymous, and a list
changes within hours. podssh speaks VLESS for a server that the user names; the operator ruled
that the lists of public proxy nodes are a last fallback.

## Premise

- `docs/decisions.md:25` says "and the lists of public proxy nodes (VLESS, VMess, Trojan) are a
  last fallback".
- `docs/carriers.md:376-377` says "operators are anonymous and answer for nothing, and a list
  changes within hours".
- `crates/podssh-ws/src/vless/mod.rs:1` says "VLESS (T-440, the operator's ruling Q66): a server
  that the user runs,".

## Approach

1. The research first: the lists (each with its source and how often it changes), the forms of
   their lines (`vless://`, `trojan://`), and the share on 443 by name over TLS or a WebSocket.
2. At run time: the list fetched over HTTPS through `HTTPS_PROXY` into the cache, the lines that
   podssh speaks parsed (VLESS; Trojan once T-491 is done; VMess as T-573 rules), those on 443
   kept, each tried in turn once each other road of the forward road failed; the SSH host key
   check stands.
3. Q79 at run time, as the Decision says.
4. A last fallback (Q78): a line on stderr names the node's host and says that the target goes to
   a third party that nobody vouches for; `PODSSH_PROXY_LISTS=no`, and the switch of T-548's
   Decision.

## Decision

**Q79 at run time, for the operator to confirm (Q86).** Q79 names each host that podssh uses,
with its source, and never uses a domain that looks taken over; a list's nodes change within
hours, and no person screens them. The call: the binary names each list that it fetches (its URL
and its source), never a node, and the repository publishes no node. At run time a node is kept
when its address is an IP literal, or when its host, its SNI and its `Host` are one name that is
under no suffix of a school's, a church's or a government's (`.edu`, `.k12.`, `.ac.`, `.sch.`,
`.gov`, `.mil`, and those that the research of step 1 adds); a node whose SNI or `Host` is another
party's name is skipped. Lost: each node as the list gives it, which may front a name that is
taken over; and no list at all, which Q78 rules out.

- The operator's ruling Q90 (2026-11-03) changes the call that the binary names no node: it
  ships a short list of nodes, taken from the public lists, as the fallback when no list can be
  fetched; each node is checked live before each release and dropped when it fails, and the
  filters above still hold (no node that fronts another party's name, or sits under a school's,
  a church's or a government's suffix). Lost: no node in the binary, which leaves the road with
  nothing where the lists' hosts are blocked.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test proxy_lists
```

Against Xray-core (the version of T-440's tests) in a container, serving VLESS over a WebSocket,
named in a list that a stand-in HTTP server serves: the fallback takes the node and reaches sshd's
banner; a line that fronts another name is skipped; stderr has the line about the third party.
Planted: the skip removed, and the test of the fronted line fails.

# T-575: serv00's public Piping Server as the third server of the Piping Server road

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The sweep found a third public Piping Server, on serv00, whose terms forbid tunnels. Q78 makes it a
last fallback whatever its terms, after `ppng.io` and T-497's `piping.onrender.com`.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:962` says "The last runs on serv00, whose terms forbid to", of
  `p.kokoro.serv00.net`.
- `crates/podssh-relay/src/piping/server.rs:10` says "pub const DEFAULT_HOST: &str =".

## Approach

1. Measure first, short (T-548's Decision): its version page, whether it is a Piping Server and which, and
   whether it streams.
2. The third server of T-497's order, tried once the two before failed, as a last fallback: the
   line of T-548's step 5 names it.
3. `PODSSH_PIPING` naming a server keeps that server alone, as now.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test piping
cargo test -p podssh-relay --features piping --test piping_live -- --ignored
```

Three of nwtgck's servers on the loopback, the first two stopped: the node and the client meet at
the third. Live, a short run through it (T-548's Decision). Planted: the third server tried before the second,
and the test of the order fails.

## Start condition

T-497 is done: the road has public servers in order.

# T-576: HTTP Relay's demo server as a last fallback, in the Piping Server road's pieces

**Source:** the operator's ruling Q78 (2026-11-02); T-442's verdict.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

HTTP Relay meets a POST and a GET on one path, as Piping Server does, but each request is a whole
message: no stream. The Piping Server road's numbered pieces are whole messages too, so they could
go through it. Its demo server answered 503 on 2026-11-02. T-442 left it out; Q78 makes it a last
fallback.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:859` says "each request is a whole message", and
  `docs/carriers.md:860` says "answered 503 on 2026-11-02".
- `docs/carriers.md:644-645` says "makes the client ask for numbered pieces".

## Approach

1. Measure first, short (T-548's Decision): whether the demo server answers its health and one exchange on a
   link, on three days. Where it never answers, the entry is done with that measurement, and the
   binary names it not (Q79 names the hosts that podssh uses).
2. Where it answers: the Piping Server road's numbered pieces over its `/link/` paths, after each
   Piping Server, as a last fallback with the line of T-548's step 5; `PODSSH_HTTPRELAY=no`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features piping --test httprelay_pieces
```

Against HTTP Relay's own server (its last release) in a container: the pieces of a session meet,
1 MiB each way. Live, a short run (T-548's Decision) where the demo answers. Planted: a piece's number dropped,
and the test of the order of the pieces fails.

# T-577: Bare servers as a hop to a WebSocket road: the research

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A Bare server fetches a URL for a web proxy in a browser, and opens a WebSocket to a URL that its
client names. Through that WebSocket, podssh's relay road, a forwarder's or Wisp's could reach a
host that a proxy's filter refuses by name. The research of the sweep read the protocol for its
HTTP form alone.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:382` says "URL, or opens a WebSocket to a", of TompHTTP's Bare protocol.

## Approach

1. Read the WebSocket form of the Bare protocol's versions (TompHTTP's specifications): how a
   client names the far URL and its headers, whether binary messages pass both ways, and whether
   a server refuses a far host by a list.
2. The public Bare servers (openbare's network and others): their operators, their terms, and
   whether they are run for the use of others; Q79 (no domain that looks taken over).
3. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes, a hop
   of the WebSocket roads tried last (Q78).

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where a Bare server
passes.

# T-578: Tor's onion services: a node reached by its onion address, through the Tor road

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

An onion service reaches a node by a key with no account and no listener of the node's, through
volunteers' relays. It was ruled out because Tor's TLS fails through a proxy that re-terminates
TLS and WebTunnel needed another program; both changed when the Tor road ran meek_lite and
WebTunnel in its own process. podssh's Tor road dials out alone.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms", and
  `docs/decisions.md:42` says "Q60: the Tor road's live test may reach the public Tor network".
- `docs/carriers.md:876-877` says "the purpose fits, but Tor's TLS fails through a proxy that
  re-terminates TLS", and `docs/carriers.md:881-882` says "Both reasons changed on 2026-11-01:
  T-385 runs meek_lite and WebTunnel in podssh's own process".
- `crates/podssh-tor/src/lib.rs:8` says "Bridges (T-385) take their first hops in place of the
  directory's".

## Approach

1. Read first: Arti's onion service in the version that podssh-tor takes (its crate, its feature
   of arti-client, its keys and its restricted discovery), and whether its C stays SQLite alone.
2. The node: an onion service of a key of its own for the service, kept in the cache, whose
   virtual port the node's road serves, with the end-to-end channel and the layer; restricted
   discovery for the net's members where the net knows them.
3. The client: `node://NAME` races a road to the onion address through the Tor road, with
   bridges where the cage needs them; the address from the node's record (T-445) or the net.
4. A last fallback (Q78), with a line that names the Tor network; `PODSSH_ONION=no`.

## Decision

**The live run, for the operator to confirm (Q86).** Q60 lets a live test reach the public Tor
network with one bootstrap and one stream; an onion service also publishes its descriptor and
keeps circuits to its introduction points. The call: one short run from GitHub Actions and the
session's own host, a throwaway key for the service, one bootstrap at each end, one stream of
1 MiB at most each way, and the service stopped at the end, so that its descriptor expires
unused. Lost: no live run, which leaves the onion road tested on chutney alone; and a node's
service kept up for a day, which Q60's short runs do not cover.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-tor --test onion_service
```

Against a private Tor network on the loopback (chutney, as T-353's tests run it): a node's onion
service reached by a client, 1 MiB each way under the channel; a client outside the restricted
discovery cannot find it. Live, short, on the public Tor network, as the Decision says. Planted:
the service's key not kept, and the test of a second start, which must keep its address, fails.

# T-579: libp2p's public circuit relays: whether links of 128 KiB and 2 minutes carry a session

**Source:** the operator's ruling Q78 (2026-11-02).
**Category:** research
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

libp2p's circuit relays carry bytes between two peers with no account, but Kubo's defaults bound
each circuit to 2 minutes and 128 KiB each way, made for hole punching. The resumable layer moves
a session to a new link, so a session could ride many short circuits; whether public relays answer
on 443, and at what cost, was not read.

## Premise

- `docs/decisions.md:25` says "Q78: each service is a last fallback, whatever its terms".
- `docs/carriers.md:868-869` says "Kubo's defaults are 2 minutes and 128 KiB in each direction".

## Approach

1. Read relay v2's protocol (a reservation, a circuit, their limits) and the transports of public
   nodes that serve it: a WebSocket or TLS on 443 by name.
2. The cost: a new circuit for each 128 KiB, under the layer, and the load that it puts on a
   volunteer's node; the Rust crate `libp2p` and its C.
3. The verdict in `docs/carriers.md` with its sources, and a feature entry where it passes, last
   (Q78).

## Prove

```sh
cargo todo check
```

The verdict and its sources in `docs/carriers.md`; a feature entry filed where libp2p's relays
pass.

# T-580: Hysteria 2 as a client road over QUIC, where a probe found that UDP passes

**Source:** the operator's ruling Q82 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

Where UDP passes, a Hysteria 2 server that the user runs, or that its operator gives the user,
dials any target over QUIC, and looks like an HTTP/3 server to one who has no password. podssh
speaks QUIC on the iroh road and the quick tunnel alone. The operator ruled that Hysteria 2, TUIC
and MASQUE over HTTP/3 become client roads, tried only where a probe found that UDP passes, after
the roads over TCP.

## Premise

- `docs/decisions.md:21` says "Q82: roads over UDP where UDP passes".
- `docs/carriers.md:1140-1141` says "a client's first request is an HTTP/3", a `POST /auth` with
  `Hysteria-Auth`; `docs/carriers.md:1142` says "answers status 233", then each TCP stream opens
  with a request of ID 0x401 and the address; `docs/carriers.md:1136` says "UDP alone, which the
  hosts of podssh's design do not have".
- `crates/podssh-relay/src/quick/probe.rs:1` says "The probe of UDP before QUIC (T-400): one QUIC
  packet of a reserved", and `crates/podssh-relay/Cargo.toml:38` says "The quick tunnel over
  QUIC (src/quick/quic.rs, T-301): noq, the QUIC of the": a probe of UDP and a QUIC with no C
  exist.

## Approach

1. Read first: the form of the lines that Hysteria's clients share (`hysteria2://`, `hy2://`),
   its obfuscation Salamander, and the server's answers to a wrong password and a refused target.
2. `--hysteria FILE`, a private file of such lines, as a road of the forward road, as `--vless`
   is: QUIC on noq with podssh-ws's provider, TLS checked for the server's name or the pin that
   the line gives, datagrams on; an HTTP/3 client of that one request (QPACK's static table
   alone), its status 233 checked; then a bidirectional stream for each session, its request and
   the server's status.
3. A probe of UDP to the server's port first, as T-400's probe of the edge: one QUIC packet of a
   reserved version; with no answer, podssh says that UDP does not pass, and takes no QUIC wait.
4. Salamander where it is small; else refused by its name. `doctor --hysteria FILE`.

## Decision

A server that the user names is tried as asked once the probe found UDP; with no answer to the
probe, the road ends at once with its words (69). Unasked, a road over UDP comes after the roads
over TCP (Q82). Lost: QUIC's own handshake as the probe, which waits 5 s for each address.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --features quic --test hysteria
```

Against Hysteria's own server (`HyNetworks/hysteria`, MIT, its release binary checked by its sums)
on the loopback: sshd's banner through it; a wrong password meets the server's web answer, any
status but 233, and the road is refused; a stand-in that drops UDP makes the probe say so with no
wait for QUIC. Planted: the check of the status 233 removed, and the test of the wrong password
fails.

# T-581: TUIC version 5 as a client road over QUIC, where a probe found that UDP passes

**Source:** the operator's ruling Q82 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

TUIC is a proxy protocol over QUIC whose servers (mihomo, sing-box, shoes and others) dial a target
for a client with a UUID and a password. Where UDP passes, a TUIC server that the user runs is a
road with no relay. podssh does not speak it (Q82).

## Premise

- `docs/decisions.md:21` says "Q82: roads over UDP where UDP passes".
- `docs/carriers.md:1147-1148` says "a token of 32 bytes that the TLS keying material exporter
  derives", and `docs/carriers.md:1150-1151` says "as the server never answers a command";
  `docs/carriers.md:1153` says "are mihomo, shoes, sing-box and Itsusinn's tuic".
- `crates/podssh-relay/Cargo.toml:38` says "The quick tunnel over QUIC (src/quick/quic.rs,
  T-301): noq, the QUIC of the".

## Approach

1. Read first: the form of the lines that TUIC's clients share (`tuic://`), the ALPN and the
   congestion control that its servers expect, and how each server answers a wrong token and a
   refused target.
2. `--tuic FILE`, a private file of such lines, as a road of the forward road: QUIC on noq, TLS
   checked for the server's name; `Authenticate` on a unidirectional stream with the token of the
   TLS exporter (the UUID as its label, the password as its context); `Connect` on a
   bidirectional stream, the session's bytes after it at once; `Heartbeat` datagrams while it
   runs.
3. The server never answers a command: a target that it cannot reach is a stream that it closes,
   and a wrong token a connection that it closes; podssh names each by what it saw.
4. T-580's probe of UDP first, and T-580's Decision on the order.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --features quic --test tuic
```

Against a TUIC server of another project (sing-box, or `Itsusinn/tuic`) in a container: sshd's
banner through it; a wrong password closes the connection, and podssh says so. Planted: the
exporter's label and context swapped, and the test of the banner fails.

# T-582: MASQUE over HTTP/3: WARP's connect-ip on UDP, where a probe found that UDP passes

**Source:** the operator's ruling Q82 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

WARP's road speaks MASQUE's connect-ip over HTTP/2 on TCP port 443. WARP's endpoint and the open
clients of it speak it over HTTP/3 too, with each IP packet in a QUIC datagram, which is faster
and keeps no TCP inside TCP. The MASQUE servers that others run speak it over HTTP/3 alone. podssh
does not speak HTTP/3 (Q82).

## Premise

- `docs/decisions.md:21` says "Q82: roads over UDP where UDP passes".
- `crates/podssh-warp/src/lib.rs:1` says "WARP's MASQUE road over HTTP/2 (T-352): Cloudflare's
  own"; `docs/carriers.md:85` says "connect-ip over HTTP/2 to 162.159.198.2:443".
- `docs/carriers.md:96-97` says "The mode with no IP stack works over QUIC only", and
  `docs/carriers.md:357-358` says "masque-go speaks it over HTTP/3 alone, which needs UDP".
- `crates/podssh-relay/src/quick/probe.rs:1` says "The probe of UDP before QUIC (T-400): one QUIC
  packet of a reserved".

## Approach

1. Read first: usque's road over HTTP/3 and the fork of connect-ip-go that it takes (the extended
   CONNECT with the protocol `connect-ip`, HTTP Datagrams with their context, the capsules), and
   WARP's endpoint on UDP 443.
2. podssh-warp over HTTP/3: QUIC on noq with the device's key and the endpoint's pinned key; the
   extended CONNECT; IP packets in QUIC datagrams; TCP inside on smoltcp, as now.
3. Where a probe of UDP to the endpoint answers: HTTP/3 after the road over HTTP/2 failed, unasked
   (Q82), or first where the user asks for it (`warp://` with a word for HTTP/3).
4. A server of connect-ip that the user runs, over HTTP/3, by its URL: the same code.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-warp --features h3 --test connect_ip_h3
```

Against quic-go's connect-ip-go (MIT), as a proxy of connect-ip over HTTP/3 in a container: sshd's
banner through it, and 1 MiB each way. Live, short, through WARP's endpoint over UDP from GitHub
Actions (Q52, Q59). Planted: a datagram's context ID dropped, and the test of the banner fails.

# T-592: A pair that its owner renews in podssh's relay role, so that a node of the role outlives 72 h with its operators' file unchanged

**Source:** GitHub #117 (a tester's agent, 2026-11-02): `relay pair --renew NAME --operator-file
F`, to extend the same pair, so that the operator's file keeps working. T-591 holds the rest of
the issue.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Each pair ends within 72 h. A node that should run longer needs a new pair each 3 days, and its
operators a new file each time, which a person must bring them. On the default relay that is its
contract; on podssh's own relay role (Q63) podssh decides it, and can let the owner extend the
pair that its operators hold.

## Premise

- Read: the role keeps the contract's 72 h (`crates/podssh-relay/src/serve/reverse/pairs.rs:26-27`,
  set as the pair is made, `:241`), and serves `/v1/pair`, `/v1/node/`, `/v1/connect/`,
  `/v1/status/` and `/v1/stop/` alone (`crates/podssh-relay/src/serve/reverse/mod.rs`, line 57 at
  `b02d8c4`).
- Read: the default relay renews no pair (T-395's Correction: no such request in its document); a
  change of that deployment is an item of `docs/relay-operator.md`, which no entry waits for
  (Q63).
- Read: the node takes the next pair of the store at the expiry (T-395), so a pair that keeps its
  name needs no new start of the node.

## Approach

1. The role: `POST /v1/renew/<name>` with the pair's stop token, which its owner alone holds. The
   expiry becomes 72 h from now (never less than it was), its three tokens the same: `200` with
   `{"expires": ...}`; `403` for another token; `404` for no such pair. The file of `--pairs`
   keeps the new expiry. The role's `/v1/status/<name>` gives `expires` beside the contract's
   fields, so that an operator's `relay status` (T-591) shows the new date.
2. The client: `podssh relay pair --renew NAME` asks the relay of the stored pair. A relay with no
   renewal (`404` or `405` at the path) gets the words that it renews no pair, with T-591's way,
   `relay pair NAME` in the last 24 h, and exit 69. The operator's file is never touched: its
   tokens hold.
3. The node renews its own pair in its last 24 h where its relay renews (at the start of that
   window, then each hour until it took), and says each renewal; where the relay renews none, the
   lines of T-395 as now.
4. `docs/relay.md` (the role's request beside the contract), `docs/reverse.md`, `docs/mesh.md`,
   the manual, `docs/STATUS.md`.

## Decision

For the operator to confirm (Q86):

- A renewal keeps the three tokens, so that each operator's file keeps working, as the issue asks;
  the stop token alone renews, so an operator, who holds the connect token, cannot keep a pair
  alive against its owner. Lost: new tokens at each renewal, which is a new pair, the issue's
  problem.
- No cap on the renewals: the owner ends the pair at any time with its stop token
  (`relay revoke`). Lost: a cap on a pair's whole life, which brings the lockout on a date back
  for a node that is meant to run; a connect token that leaked lives as long as the owner renews,
  and `relay revoke` with a new pair ends it.
- The node renews by itself where its relay renews, so that a node that its owner left running
  stays reachable. Lost: renewal by hand alone, which nobody runs in time on a server that only
  the node reaches (T-395's reason for the next pair).

Calls of the draft (2026-11-03), for the operator to confirm with the rest (Q86):

- Each failed renewal gets the `403 reverse: forbidden` of each failed authentication: another
  token, a pair that does not exist, one that ended. Lost: Approach item 1's `404` for no such
  pair, which a client could not tell from a relay that has no renewal (item 2) and which would
  confirm a pair's name to whoever asks.
- Past the end that its file names, an operator asks its relay's status once, and takes the later
  end that podssh's role names there; offline, or where the relay names none (a relay of the
  contract), refuses the token or cannot be asked, the part is refused as expired (77), as before.
  The status goes with the trust of `SSL_CERT_FILE` or the settings' `CaFile`, as the part's
  reader takes no `--ca-file`. Lost: a check that stays local, which would stop each operator's
  file at its old end, the issue's problem; a dial with no check, where the default relay's `403`
  would lose the date of the end; `--ca-file` passed through each of the nine readers of a part.
- A node of `--pair-file` renews too, at its relay and in its own memory, and says that its file
  names the old end; podssh rewrites no file that the user named. Lost: no renewal for such a
  node, which would end at 72 h where its relay could have kept it.
- A renewal that did not take is tried again each hour, with a line that names the end; the lines
  of T-395 come once the relay is known to renew none (404, 405) or refused the stop token. Lost:
  those lines at each failure too, which would send the owner to make a next pair that the
  renewal makes needless.
- `relay pair --renew` refuses `--operator-file` and `--relay-host` (64): the renewal keeps the
  operators' files, and asks the relay that made the stored pair. Lost: a renewal that writes a
  new operator's file, which the issue does not need.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_reverse
cargo test -p podssh-cli --test relay_serve_node
cargo test -p podssh-relay --features serve --lib serve::reverse
cargo test -p podssh-relay --features pair --lib pair::renew
cargo test -p podssh-cli --lib relay_renew
cargo test -p podssh-cli --test node_expiry --test operator --test node
```

New tests: in `relay_serve_reverse`,
`a_renewal_by_the_stop_token_extends_the_pair_and_keeps_its_tokens` (on a paused clock, the
connect token works past the old expiry; another token gets 403); in `relay_serve_node`,
`a_node_renews_its_pair_in_its_last_day` (the role with a pair of 23 h: the node renews it and
says so, and past the old expiry the operator's first file still reaches the node) and
`renew_on_a_relay_with_none_says_so` (the stand-in relay, which has no such path: 69, and its
words). Planted: `t592-renewal-new-tokens` (a renewal that draws new tokens): the first test fails
at the old connect token.

## Correction

Read at `b02d8c4` (2026-11-03), for the draft:

- The Premise holds at each cited line.
- Approach item 1's `404` for no such pair: the role answers each failed renewal with the `403
  reverse: forbidden` of each failed authentication (Decision), as item 2 reads `404` or `405` as a
  relay with no renewal; the stand-in answers `404` at the path, as at each path that it lacks
  (`scripts/fake-relay.py`).
- Approach item 2, "The operator's file is never touched: its tokens hold": the tokens hold at the
  relay, but each reader of an operator's part refused one past the end that its file names, before
  any dial (`operator_part` of `crates/podssh-cli/src/pairs.rs`), so the operator's file stopped
  at its old end all the same. The draft asks the relay's status once past that end, and the role
  names `expires` in it (item 1).
- A pair's end in the role was a plain field, which the timers of the node's socket and of each
  operator's leg read once at their start; a renewal moves it, so it is atomic, and a timer that
  fires waits again for a later end (`renewed` of `crates/podssh-relay/src/serve/reverse/node.rs`).
- The Prove's "on a paused clock": the role reads the wall clock (`tokens::now_ms`), which a
  paused clock of tokio does not move; the test makes a pair as if made 72 h less 3 s before, and
  waits past its old end.
- The Prove's `a_node_renews_its_pair_in_its_last_day`, "the role with a pair of 23 h": the role's
  pairs live 72 h, and no flag shortens them. The test sets the end that the store's file names to
  23 h and the operator's file's to 2 s, as a pair in its last day and a file past its end name
  them; the role's own end, past which a token holds, is the library's test.
- `crates/podssh-relay/src/pair.rs` was at 496 lines: the renewal, and a status that reads the
  role's `expires`, are its submodule `crates/podssh-relay/src/pair/renew.rs` (`Status`, beside
  the contract's `Presence`). The role's `pairs.rs` gives its tests to `pairs_tests.rs`.
- `relay status --pair-file` read the part before it set the pins of `--relay-addr` and
  `PODSSH_RELAY_ADDR`; it sets them first, as a part past its end asks its relay.

## Done

2026-11-03, drafted (`DRAFT T-592`), merged and measured on this machine the same day.

What changed:

- `crates/podssh-relay/src/serve/reverse/pairs.rs`: a pair's end is atomic (`Pair::expires_ms`);
  `Pairs::renew`, 72 h from then and never earlier, the tokens kept, the file of `--pairs` written,
  the old end kept when the file took no write; the tests in `pairs_tests.rs` (new), with one of
  the renewal and one of the file after it.
- `crates/podssh-relay/src/serve/reverse/mod.rs`: `/v1/renew/` among the role's paths; `renew`,
  `POST` with the stop token, `{"expires": ...}`, 403 for each failure and 503 for a file that
  took no write, 405 for another method; the status names `expires`.
- `crates/podssh-relay/src/serve/reverse/node.rs` and `operator.rs`: the timer of a pair's end
  waits again when a renewal moved it (`renewed`).
- `crates/podssh-relay/src/pair.rs` and `crates/podssh-relay/src/pair/renew.rs` (new): `renew`
  (`Renewed::Until`, `Renewed::NotServed` for 404 or 405), `Pair::with_expiry`, `Status` and
  `status`; unit tests.
- `crates/podssh-cli/src/relay_renew.rs` (new): `relay pair --renew NAME`, its refusals, its line,
  the store; unit tests. `crates/podssh-cli/src/relay_cmd.rs` (`RelayArgs::renew`, its dispatch,
  `--renew` with another subcommand, 64), `crates/podssh-cli/src/tree.rs`,
  `crates/podssh-cli/src/lib.rs`, `crates/podssh-cli/src/flags/relay.rs` (the row).
- `crates/podssh-cli/src/node_expiry.rs`: `Renewer`, the node's renewal in its last day, then each
  hour until it took, the store's copy, the lines; `watch` takes the trust of the relay, in
  `crates/podssh-cli/src/node.rs`, `node_derp.rs`, `node_iroh.rs` and `node_piping.rs`.
- `crates/podssh-cli/src/pairs.rs`: `renewed` and `ended_at`, the status past a part's end;
  `crates/podssh-cli/src/relay_status.rs`: the relay's end, and the pins first;
  `crates/podssh-cli/src/layered.rs`: the operator's warning names the renewal.
- `crates/podssh-cli/src/man/notes_relay.rs`, `notes_pair.rs`, `facts.rs` and `examples.rs`.
- `crates/podssh-relay/tests/relay_serve_reverse.rs`:
  `a_renewal_by_the_stop_token_extends_the_pair_and_keeps_its_tokens`;
  `crates/podssh-relay/tests/role_harness/mod.rs`: `pair_made_at`.
- `crates/podssh-cli/tests/relay_serve_node.rs`: `a_node_renews_its_pair_in_its_last_day` and
  `renew_on_a_relay_with_none_says_so`.
- `scripts/plants/t592-renewal-new-tokens.patch` and `.plant` (`git apply --check`: applies).
- `docs/relay.md`, `docs/reverse.md`, `docs/mesh.md`, `docs/cli.md` and `docs/STATUS.md`.

Measured at the merge (2026-11-03, Linux, `CARGO_BUILD_JOBS=4`):

- `cargo test -p podssh-relay --features serve,pair,plain-ws --test relay_serve_reverse`: 4
  passed, the renewal among them.
- `cargo test -p podssh-cli --test relay_serve_node`: 5 passed. The renewal's test first failed
  at random: the node's line `online` and the line of the renewal come in either order, and the
  test waited for them one after the other. It now waits for both in one read (`both`).
- `cargo test -p podssh-relay --features serve,pair --lib serve::reverse pair::renew`: 12 passed.
- `cargo test -p podssh-cli --lib` (with `relay_renew`, `node_expiry` and `man::examples`): 779
  passed.
- `cargo test -p podssh-cli --test node_expiry --test operator --test node --test relay`: 17, 4,
  12 and 9 passed, the lines of T-395 and the offline refusals of an expired pair among them.
- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_contract`: 10 passed,
  the status with `expires`.
- `cargo test -p podssh-cli --test man_page --test man_flag_parity --test flag_table`: 9, 6 and
  11 passed.
- clippy `--all-targets -D warnings` of `podssh-relay` (`serve,pair,plain-ws,blocking`) and of
  `podssh-cli`: clean. The merge also gave `watch` of `node_opentunnel.rs` (T-531, merged before)
  the trust of the relay.
- The plant `t592-renewal-new-tokens` (a renewal that mints new tokens): caught by
  `a_renewal_by_the_stop_token_extends_the_pair_and_keeps_its_tokens`; the tree is clean again.

# T-595: A carrier of the node's road over a byte stream that exists already (`stdio`, `fd:N`, `exec:CMD`), for a host whose every road out is closed

**Source:** GitHub #124 (a tester's agent, 2026-11-02), with `podssh 1.0.0 (35a0d19)` in a
container whose egress allows a list of names (github.com, pypi.org, deb.debian.org and a few
more) and resets the relay, the iroh relays, the DERP fleet, Cloudflare's edge and WARP's API;
the platform's own `ssh` into the container worked, and a framed multiplexer of the tester's, 329
lines over that exec channel, gave the container an HTTP CONNECT proxy, then egress through WARP.
It asks for `podssh node --stdio NAME TARGET`, and
`podssh proxy --carrier exec:'ssh -T sandbox podssh node --stdio NAME' node://NAME`. Read at
`3bb42ea`.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

Each road of podssh dials a public endpoint, so a host whose egress is a list of allowed names has
none. Such a host often grants one channel: an exec channel of the platform's own SSH, or of an
API, reliable and both ways. podssh cannot run a node or a client over a stream that is there
already: `pipe` joins two streams but carries no node's road, and `proxy` reaches its target
through a relay. A feature of the mesh (Q63; Q77, the fallbacks that exist).

## Premise

- Read: the node's side of the reverse road runs over any `RelaySession<S>`
  (`crates/podssh-relay/src/reverse/serve.rs:134`), and a `RelaySession` is made over any stream,
  with no HTTP in it (`crates/podssh-ws/src/session.rs:98-102`).
- Read: podssh's relay role serves the relay's side of a node's socket and of an operator's
  (`crates/podssh-relay/src/serve/reverse/mod.rs:1-3`, T-427).
- Read: `pipe`'s local addresses are `stdio` (or `-`), `fd:N` and `exec:CMD`, a program with no
  shell (`crates/podssh-cli/src/pipe/address.rs:19-24`), the words that the issue asks for.
- Read: `pipe` does not refuse a terminal on stdin (no such check in `crates/podssh-cli/src/pipe/`
  at `3bb42ea`); the issue's "as `pipe` does" is not this code's.
- Read: the exit lends its egress on the node's roads
  (`crates/podssh-cli/src/man/notes_pair.rs:259-269`); a carrier is one more road for it (T-596).

## Approach

1. `--carrier ADDR` on `podssh node` and on the clients of a node (`ssh node://`, `proxy node://`
   of T-587, `operator`, and `pipe`'s `node:` side). ADDR is `stdio` (or `-`), `fd:N` (Unix) or
   `exec:CMD`, read as `pipe` reads them; the end that names `exec:` starts the stream, and either
   end may be the node.
2. On the stream, the node's socket of the reverse road, its WebSocket frames with no HTTP before
   them: the node runs `reverse::serve` as on the relay's socket, and the client's end runs the
   relay role's side of that socket in its own process, for this one node, with its operator's
   leg a pipe in the process to the role. The client's end speaks first (`hello`), as the relay
   does. So the layer, the end-to-end channel, the routes and the sessions are the pair's road's,
   and no protocol is new.
3. No relay, no pair and no token: the stream is the door, as whoever holds it reached the node
   through the platform that carries it. The end-to-end channel stays on by default, with the
   node's key pinned under NAME, so a stream that something else answers is seen; `--allow` holds
   where it is given; `--no-e2e` and `--plain` as on the pair's road. NAME is a label alone.
4. One stream for the node's life: at its end, the sessions end with their reason, and the node
   exits 0, or 69 for a stream that failed. A client of `exec:` starts the command again as the
   new link of a resume; a node of `stdio` has one link, and its sessions resume only while the
   stream lives (the layer's heartbeats tell a dead one).
5. `--carrier stdio` refuses a terminal on stdin (64): a node would read a person's keys as
   frames. A node of a carrier takes no `--pair-file`, `--iroh`, `--derp`, `--quick-tunnel`,
   `--install` or `--detach` (64): its stream is its parent's.
6. The relay's limits do not hold (no 64 MiB, no 12 h), only the layer's and the stream's.
7. The notes of `node` and of a node's clients, `docs/mesh.md`, `docs/carriers.md` (a carrier
   with no endpoint), `docs/reverse.md`, `docs/STATUS.md`.

## Decision

For the operator to confirm (Q86):

- One flag, `--carrier ADDR`, at both ends, in `pipe`'s words. Lost: the issue's `--stdio` on the
  node and `--carrier` on the client, two names for one thing; a new kind of address in `pipe`
  alone, which would carry no node's road.
- The relay's side of the socket in the client's process, from the role of T-427, so that the
  node's code is the same on each road. Lost: a framing of the tester's kind, new code at each end
  that the tests of the relay's contract do not reach.
- The stream is the door, with no allowlist needed, as the pair's road lets in each operator of
  its connect token. Lost: a door required, as on the DERP road, where any key may send; here only
  the holder of the stream can.

Calls of the draft (2026-11-03), for the operator to confirm with the rest (Q86):

- The node's first frame is a WebSocket Ping, sent once its TARGET answered, and the client's role
  opens no leg before it, 60 s at most. Lost: an `open` at once, which the role ends after 15 s
  with `1013 node open timeout` where a program starts the node slowly (a login, then the node's
  dial of TARGET); a message of the node's own, which would be a protocol of the carrier's.
- A stream of `exec:` that ended is started again once for each wait of a leg, so a program that
  ends at once is said in that wait (69), and the layer's own wait comes between two starts. Lost:
  a start each time the wait looks, many in a second.
- `--exit` with `--carrier` is refused (64) until T-596 builds its client. Lost: let it run, as the
  node's routes would carry it, with no client that reaches it and no test.
- The role is a handle for the process's life (`Door`, a `&'static` of `Box::leak`), as `Wire` is
  `Copy` and a command runs one carrier. Lost: a lifetime on `Wire`, which each `OperatorConfig`
  of the code would carry; a table of roles by number, the same handle with more code.

Calls of the draft of the next steps (2026-11-03), for the operator to confirm with the rest
(Q86):

- The clients of a node share one client of the carrier for the command (`crate::carrier::shared`):
  one program, one node, and each connection of a copy, each session of `ssh`, a leg of its own,
  as the role carries many legs; the command's end sends the node its Close
  (`crate::carrier::end_shared`, from `crate::ssh::transport::settled`, which `cp` and `sftp` now
  run in). Lost: a program for each connection, which would log in to the platform again for each
  step of a copy (a move across hosts makes three), and leak a role each time.
- A client's `--carrier stdio` is refused (64), as for `operator`: its stdin and stdout are its
  session's or its lines'. Lost: stdio at a client, which is T-596's `exit --listen` alone.
- A carrier is the node's one road: `ssh --carrier` races no other, and the flags of a relay, a
  pair, the tickets, `--derp-server`, a server's road, `--exit` and `--upgrade` are refused with it
  (64), in its own words, before those of a node's other roads. Lost: the race of the carrier with
  the pair's road, for a node that has both, which no tester asked for and which would make the
  stream's program start for a session that the pair carries.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,serve --test reverse_carrier
cargo test -p podssh-cli --test node_carrier
```

New test files: reverse_carrier (the node's `serve` and the role's side over a pair of pipes, two
sessions of 2 MiB each way with equal digests) and node_carrier (`podssh ssh --carrier
exec:'podssh node --carrier stdio NAME 127.0.0.1:PORT' node://NAME` to the test's OpenSSH sshd,
`true` exits 0; OpenSSH's client with `ProxyCommand="podssh proxy --carrier exec:... node://NAME"`;
a pinned key that the far end does not have, refused with 77; a terminal on stdin refused, 64;
each says that it did not run where this host has no OpenSSH). Planted: `t595-carrier-no-channel`
(the end-to-end channel skipped on a carrier with no `--no-e2e`): the test of the pin fails; and
`t595-ssh-carrier-skipped` (`ssh --carrier` sent to the pair's road): the test of the node that
`ssh` starts and closes fails; `t595-proxy-carrier-dropped` (`proxy node://` given no carrier): the
test of `proxy --carrier` fails; `t595-pipe-carrier-ignored` (`pipe`'s node side on the pair's
road beside `--carrier`): the test of `pipe - node:box --carrier` fails.

## Correction

Read at `477b47c` (2026-11-03), for the draft of the first step:

- The Premise holds at each cited line.
- `proxy node://` of T-587, which Approach item 1 names, is not built: T-587 is open. `proxy
  --carrier` waits for it.
- `operator --carrier stdio` is refused (64): the operator's stdin and stdout carry the session's
  bytes. `stdio` is a carrier for the node's end, and for a client whose stdio is free (T-596's
  `exit --listen`).
- Approach item 4, "a client of `exec:` starts the command again as the new link of a resume": the
  command starts a new node, which by item 4's own rule has one stream for its life, so it knows no
  session of the node before it, and the session ends with that node's reason; the new stream
  serves the legs after it. A session resumes over the stream that carries it, whose legs are pipes
  in the client's process.
- The first step's `node_carrier` runs OpenSSH's client with `podssh operator --carrier` as its
  ProxyCommand, to OpenSSH's sshd; the Prove's `podssh ssh --carrier` comes with the next step, and
  its test joins `node_carrier` then.

Read at `38f424c` (2026-11-03), for the draft of the next steps:

- `proxy node://` of T-587 is built (`crates/podssh-cli/src/proxy_node.rs`), and its `to_operator`
  gave `carrier: None`; `proxy --carrier` is its flag now, which `operator`'s checks take.
- `operator --carrier` took `--ConnectTimeout` and did nothing with it: `carrier::prepare` did not
  read `connect_timeout`, though the manual says that the flag bounds `operator`'s open. The draft
  of `proxy --carrier` gives the carrier the bound, for both verbs: the node's read of the stream,
  its ready, then the layer and the channel.
- A copy (`cp`, `scp`, `sftp`) opens a connection at a time, and more than one in a run (a move
  across hosts makes three), each through `crate::ssh::node::reach`; so a carrier's client is one
  for the command, not one for each connection (Decision).

## Done

2026-11-03, drafted (`DRAFT T-595`), the first step: the carrier in the library, `podssh node
--carrier ADDR` and `podssh operator --carrier ADDR`; merged and run by the main session the same
day. The entry stays open for the steps below.

What changed:

- `crates/podssh-relay/src/serve/reverse/carrier.rs` (new): `Role`, the relay role's side of one
  node's socket on a stream (`Link`), in the client's process: `attach`, `open` of an operator's
  leg (a pipe to `operator::leg`), the wait for the node's first frame, `start_again` through
  `Again` for a stream that the client started (else `410`), `close` (1000); `Door`, the role as
  the wire of a leg; `node_socket` and `greet`, the node's end.
- `crates/podssh-relay/src/serve/reverse/node.rs`: `join` split into its upgrade and `socket`;
  `carried`, a node's socket with no upgrade; the cap of a session is `pair.session_bytes`.
- `crates/podssh-relay/src/serve/reverse/operator.rs`: `join` split into its upgrade and `leg`; the
  cap is `pair.session_bytes`.
- `crates/podssh-relay/src/serve/reverse/pairs.rs`: `Pair::session_bytes` (the contract's 64 MiB
  for a pair of the role), `Pair::carried` (no expiry, no cap, no token), a unit test.
- `crates/podssh-relay/src/serve/reverse/mod.rs`: the module `carrier`.
- `crates/podssh-relay/src/reverse/wire.rs`: `Wire::Carrier(Door)` and `Socket::Carrier`, feature
  `serve`; `crates/podssh-relay/src/reverse/operator.rs` and `crates/podssh-relay/src/reverse/node.rs`:
  their arms.
- `crates/podssh-relay/tests/reverse_carrier.rs` (new): 5 tests (two sessions of 2 MiB each way
  and the Close of 1000; one life of a stream given; a stream started again; no `open` before the
  node's first frame; no node's path).
- `crates/podssh-cli/src/carrier.rs` (new): `--carrier`'s words, the refusal of a terminal, the
  stream; `Client`, the role over a stream with `exec:` started again; `operator --carrier`, its
  checks, and the words of its end; unit tests.
- `crates/podssh-cli/src/node_carrier.rs` (new): `check` of the flags that a node of a carrier
  takes none of (also in `node_install::dispatch`, before an `--install`), and the node over the
  stream: TARGET's probe, the key, the first Ping, `reverse::serve` with the handlers of the pair's
  road, its end (0 or 69); unit tests.
- `crates/podssh-cli/src/node.rs`, `crates/podssh-cli/src/node_args.rs`,
  `crates/podssh-cli/src/node_install/mod.rs`, `crates/podssh-cli/src/operator.rs`,
  `crates/podssh-cli/src/tree.rs`, `crates/podssh-cli/src/lib.rs`: the field `carrier`, and the
  dispatch to the new modules.
- `crates/podssh-cli/src/flags/node.rs`, `crates/podssh-cli/src/flags/operator.rs`: the rows of
  `--carrier ADDR`; `crates/podssh-cli/src/man/notes_pair.rs`: a note of `node` and one of
  `operator`; `crates/podssh-cli/src/man/examples.rs`: OpenSSH through a node on an exec channel.
- `crates/podssh-cli/tests/node_carrier.rs` (new): 6 tests (an echo server's 1 MiB through
  `operator --carrier exec:'podssh node --carrier stdio ...'`; the pin, 77; a program that ends at
  once, 69; the refused flags, 64; a terminal on the node's stdin, 64, in a pty of Linux; OpenSSH's
  client to OpenSSH's sshd, or that it did not run).
- `scripts/plants/t595-carrier-no-channel.patch` and `.plant`: the channel skipped at both ends.
- `docs/cli.md`, `docs/mesh.md`, `docs/carriers.md`, `docs/reverse.md` ("A carrier") and
  `docs/STATUS.md`.

Measured, 2026-11-03:

- `cargo test -p podssh-relay --features pair,serve --test reverse_carrier`: 5 passed.
- `cargo test -p podssh-relay --features serve --lib serve::reverse`: 9 passed.
- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_reverse --test
  relay_serve_contract`, the role after the split of `join`: 10 and 3 passed.
- `cargo build -p podssh-relay --features blocking,serve`, the facade's arms of `Socket::Carrier`:
  built.
- `cargo test -p podssh-cli --test node_carrier`: 6 passed, the test of OpenSSH among them
  (`openssh_logs_in_to_its_sshd_through_a_node_on_a_carrier`, OpenSSH's client to its sshd
  through `operator --carrier`).
- `cargo test -p podssh-cli --lib carrier`, 5 passed, and `--lib man::examples`, 4 passed; the
  whole lib, 714.
- `cargo test -p podssh-cli --test man_flag_parity --test flag_table --test operator --test roost`:
  6, 9, 9 and 11 passed; `--test proxy` and `--test man_page`, 15 and 10.
- `cargo clippy` of both crates with `-D warnings` (and the role's `serve`, `pair`): clean.
- Planted (`sh scripts/plant-each.sh --here t595-carrier-no-channel`, the channel skipped at
  both ends): caught.
- The merge joined T-587's and T-589's changes of `operator.rs`, `flags/operator.rs` and
  `tree.rs` with the draft's (`--carrier` first, then `to_node`; `--ConnectTimeout` beside
  `--carrier`), and gave `proxy_node`'s `OperatorArgs` no carrier, as `proxy --carrier` is step 2.

What remained after the first step:

1. `podssh ssh --carrier ADDR node://NAME`, and `cp`, `scp` and `sftp` to `node://NAME` on one,
   on `crate::carrier::Client` and `Wire::Carrier`; its test joins `node_carrier`, as the Prove
   names it.
2. `podssh proxy --carrier ADDR node://NAME`, once T-587 gives `proxy node://`.
3. `pipe`'s `node:` side with `--carrier`.
4. The exit over a carrier is T-596, which lifts the refusal of `--exit` here.

2026-11-03, drafted (`DRAFT T-595: ssh, cp, scp and sftp to node://NAME on a carrier`), step 1 of
the list above; merged here with the two after it, and the results are the merge's.

What changed:

- `crates/podssh-cli/src/ssh/carried.rs` (new): `flags`, the refusals of `--carrier` beside a flag
  of a relay, a pair or another road, and of `stdio` (64), called from `node::transport` first;
  `check`, `--carrier` with a destination that is no node, or with `--exit` (64), called from
  `servers::check`; `connect`, `ssh` to the node over the shared client, a first leg, then
  `node::run_on`, and the node's Close at the end; `reach`, a copy's stream over a leg of the
  shared client, in a task, as `node::reach` carries one over the pair's; a unit test.
- `crates/podssh-cli/src/ssh/node.rs`: `connect` split into its pair's part and `run_on` (with
  `Leg`), the session over a first leg, which the carrier's `connect` runs too; `transport` checks
  the carrier's flags first and sets `carrier` of `Transport::Node`.
- `crates/podssh-cli/src/ssh/resolve.rs`: the field `carrier` of `Transport::Node`;
  `crates/podssh-cli/src/ssh/exit_road.rs`: `carrier: None` for an exit's road.
- `crates/podssh-cli/src/ssh/args.rs`: `SshArgs::carrier`, read by its id, and once only.
- `crates/podssh-cli/src/ssh/mod.rs`: the module `carried`, and the dispatch of a node on a
  carrier, before the race of the other roads; `crates/podssh-cli/src/ssh/servers.rs`: `check`
  calls `carried::check` first.
- `crates/podssh-cli/src/cp/link.rs`: the arm of a node on a carrier; `crates/podssh-cli/src/cp/mod.rs`
  and `crates/podssh-cli/src/sftp/mod.rs`: the run inside `transport::settled`, so that the shared
  client ends with the command; `crates/podssh-cli/src/ssh/transport.rs`: `settled` ends it.
- `crates/podssh-cli/src/carrier.rs`: `shared` and `end_shared`, the client of a command's legs;
  `Client::end`; `for_a_client`, `parse` with no stdio (also `operator`'s check); `said`, the words
  of a leg's end for `ssh`; `refusal_of` for the crate; the node's ready a step of
  `--ConnectTimeout` in `Client::config`; a unit test.
- `crates/podssh-cli/src/flags/operator.rs`: `SSH_CARRIER`, in the tables of `ssh`
  (`crates/podssh-cli/src/flags.rs`), `cp` and `mv` (`crates/podssh-cli/src/flags/copy.rs`), `scp`
  and `sftp` (`crates/podssh-cli/src/flags/scp.rs`); `crates/podssh-cli/src/flags/node.rs`: the
  node's row names the new clients.
- `crates/podssh-cli/src/man/notes_pair.rs`: `SSH_CARRIER`, the note of `ssh`, which
  `crates/podssh-cli/src/man/notes_ssh.rs` names, and the node's note names the clients;
  `crates/podssh-cli/src/man/notes.rs`: a sentence each for `cp`, `scp` and `sftp`;
  `crates/podssh-cli/src/man/examples.rs`: `cp --carrier` to the node's sshd.
- `crates/podssh-cli/tests/node_carrier.rs`: 4 tests (`ssh --carrier` starts the node of its
  carrier, whose TARGET closes at once, 255, and the node hears the Close, on each host; `ssh
  --carrier` runs `echo carried` on OpenSSH's sshd behind the node; `cp` up and down, `scp` up and
  `sftp`'s put and get through the sshd's own SFTP, each file whole; the refusals, 64);
  `crates/podssh-cli/tests/live_harness/sshd.rs`: `start_with`, a line more of the sshd's
  configuration (`Subsystem sftp internal-sftp`).
- `scripts/plants/t595-ssh-carrier-skipped.patch` and `.plant`: `ssh --carrier` sent to the pair's
  road, which the test of the node that `ssh` starts must catch.
- `docs/cli.md`, `docs/mesh.md`, `docs/reverse.md` (item 6 of "A carrier") and `docs/STATUS.md`.

Measured at the merge: see the last step's line below, which covers the three; the plant
`t595-ssh-carrier-skipped` (`sh scripts/plant-each.sh --here`): caught.

What remained after it:

1. `podssh proxy --carrier ADDR node://NAME` (T-587 gave `proxy node://`).
2. `pipe`'s `node:` side with `--carrier`.
3. The exit over a carrier is T-596, which lifts the refusal of `--exit` here.

2026-11-03, drafted (`DRAFT T-595: proxy node://NAME on a carrier`), step 1 of the list above.

What changed:

- `crates/podssh-cli/src/proxy_node.rs`: `Flags::carrier`, read by its id, one of the flags of a
  node (`--carrier` with another target, 64); `to_operator` gives it to `operator`, and `run` runs
  `operator::run_as`; its unit test.
- `crates/podssh-cli/src/operator.rs`: `run_as`, the pipe of either verb on the pair's road or on a
  carrier, which `run_operator` and `proxy node://` call.
- `crates/podssh-cli/src/carrier.rs`: `operator` takes the verb of its lines, and `--ConnectTimeout`
  (the Correction): `prepare` parses the bound, `operator` watches it from the node's read of the
  stream, and `carry` names the step of the node's ready.
- `crates/podssh-cli/src/flags/operator.rs`: `PROXY_CARRIER`, in `proxy`'s table
  (`crates/podssh-cli/src/flags/relay.rs`); `crates/podssh-cli/src/flags/node.rs`: the node's row
  names `proxy`.
- `crates/podssh-cli/src/man/notes_proxy.rs`: a sentence of `proxy --carrier`, with OpenSSH's
  ProxyCommand; `crates/podssh-cli/src/man/notes_pair.rs`: operator's note says the bound and the
  same pipe of `proxy`, and the node's note names `proxy`.
- `crates/podssh-cli/tests/node_carrier.rs`: OpenSSH's test runs `proxy --carrier ... node://box`
  as its ProxyCommand too; 2 tests (an echo server's 1 MiB through `proxy --carrier`, both ends 0;
  `--ConnectTimeout 1` of `exec:sleep 5`, 69 at the bound, Unix); the refusals of `proxy
  --carrier` (stdio, `--pair-file`, a target that is no node), 64.
- `scripts/plants/t595-proxy-carrier-dropped.patch` and `.plant`: `proxy node://` given no
  carrier, which the test of `proxy --carrier` must catch; `scripts/plants/t595-carrier-no-channel.patch`
  moved to the lines of `carrier.rs` now.
- `docs/cli.md`, `docs/mesh.md`, `docs/reverse.md` and `docs/STATUS.md`.

Measured at the merge: `--lib proxy_node` 3 passed, `--test proxy` 15, `--test operator` 9; the
plants `t595-proxy-carrier-dropped` and `t595-carrier-no-channel` (its context moved): caught.

What remained after it:

1. `pipe`'s `node:` side with `--carrier`.
2. The exit over a carrier is T-596, which lifts the refusal of `--exit` here.

2026-11-03, drafted (`DRAFT T-595: pipe's node: side on a carrier`), step 1 of the list above, the
last step of the Approach that is this entry's: each client of a node takes the carrier now.
Merged with the two before it.

What changed:

- `crates/podssh-cli/src/pipe/node.rs`: `Legs`, the relay of a pair or the shared client of a
  carrier, each with the config of its legs and the words of a first leg's refusal; `open` takes
  the carrier's legs when `--carrier` is given (the stream starts after the channel, the pair is
  not read); `Session` judges a carrier's end in its words. `udp:node:` comes through `open` too.
- `crates/podssh-cli/src/pipe/remote.rs`: `carrier`, the checks of `--carrier` (stdio, no node
  side, `--pair-file`: 64), from `settings`; the first step of `--ConnectTimeout` names the
  carrier's node.
- `crates/podssh-cli/src/flags/operator.rs`: `PIPE_CARRIER`, in `pipe`'s table
  (`crates/podssh-cli/src/flags/pipe.rs`), by `ssh`'s id, which `SshArgs` reads.
- `crates/podssh-cli/src/man/notes_pipe.rs`: a note of `--carrier`, with a listening side for the
  node's sshd.
- `crates/podssh-cli/tests/node_carrier.rs`: 2 tests (an echo server's 1 MiB through `pipe -
  node:box --carrier ...`, 0, and the node's Close; two clients of a listening `pipe` on one node,
  started once, each one's bytes back whole); the refusals of `pipe --carrier` (stdio, no node
  side, `--pair-file`), 64.
- `scripts/plants/t595-pipe-carrier-ignored.patch` and `.plant`: `pipe`'s node side on the pair's
  road beside `--carrier`, which the test of `pipe - node:box --carrier` must catch.
- `docs/cli.md`, `docs/mesh.md`, `docs/reverse.md` and `docs/STATUS.md`.

Measured at the merge (2026-11-03): `cargo test -p podssh-cli --test node_carrier`, 14 passed
(OpenSSH's sshd through a node on a carrier: `ssh`, and `cp` up and down, `scp` and `sftp`
through its own SFTP); `--test pipe` 10, `pipe_remote` 6, `pipe_udp` 4, `pipe_listen` 8,
`pipe_http` 7, `pipe_ws` 5, `proxy` 15, `operator` 9, `node_copy` 3, `ssh_args` 36, `cp_args` 10,
`man_page` 11, `man_flag_parity` 6, `flag_table` 9; `--lib carrier` 7, `proxy_node` 3, `pipe` 42,
the lib 756; `podssh-relay`'s `reverse_carrier` 6; clippy, all targets, `-D warnings`: clean. The
plant `t595-pipe-carrier-ignored`: caught. The merge: the tests' `cp` had no `--timeout`, which
`cp` asks for with no terminal (T-139), where `scp` and `sftp` need none (T-508); `sftp` keeps
T-508's bound inside the carrier's `settled`; the two tests of the clients move to
`tests/node_carrier/clients.rs`, as the file passed 500 lines.

What remains: the exit over a carrier is T-596, which lifts the refusal of `--exit` here; the
operator's answer to Q86 on the calls of the Decision.

# T-596: The exit over a carrier: a host that grants an exec channel alone gets egress through its other end

**Source:** GitHub #124 (a tester's agent, 2026-11-02): the issue's case, a container whose one
channel is the platform's `ssh`, got egress from a CONNECT proxy over that channel; it asks that a
carrier (T-595) go with the exit (T-431).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

With T-595, a carrier reaches a node's TARGET. The tester's need was the other way: the closed
host's programs reach the internet through the other end of the channel. podssh has that as the
exit (`podssh exit NAME --listen` at the client, `node --exit` at the egress), on the node's
roads, and a carrier must be one of them.

## Premise

- Read: the exit goes on the pair's, the iroh, the DERP, the transit and the Piping Server roads
  (`crates/podssh-cli/src/man/notes_pair.rs:268-269`), and needs the net's role exit, signed by
  its owner (`:266-267`).
- Read: `podssh exit NAME --listen` gives SOCKS5, SOCKS4a and HTTP CONNECT on a loopback address
  (`docs/STATUS.md:92`).
- In the issue's case the end with egress starts the channel (`ssh -T sandbox CMD`), so the node
  of the exit runs there with `--carrier exec:...`, and the closed host runs the client,
  `podssh exit NAME --listen 127.0.0.1:1080 --carrier stdio`.

## Approach

1. `node --exit --carrier ADDR`, and `exit NAME --listen ... --carrier ADDR`, on T-595's road; the
   net's rule of the exit holds as on each road (a member's key, a rule to `exit:NAME`).
2. The closed host's listener is the user's ask (`--listen`), after a probe of the bind (Q1).
3. The manual gives the issue's case as a recipe: at the end with egress, `podssh node NAME --exit
   --carrier exec:'ssh -T sandbox podssh exit NAME --listen 127.0.0.1:1080 --carrier stdio'`; in
   the sandbox, `HTTPS_PROXY=http://127.0.0.1:1080`. `docs/mesh.md`, `docs/STATUS.md`.

## Decision

The net's rule of the exit holds on a carrier too: the role exit is the owner's grant, whatever
carries the session. Lost: an exit open to whoever holds the stream, which would make a stream
that something else reaches an open proxy.

Calls of the draft (2026-11-03), for the operator to confirm with the rest (Q86):

- `exit --listen --carrier` takes `stdio` (or `-`), the one client of a carrier that does, as
  T-595's Decision foresaw: nothing else of it reads stdin or writes stdout. Lost: `exec:` and
  `fd:N` alone, which would leave the issue's case, where the end with egress starts the channel,
  with no client in the sandbox.
- The proxy starts its stream with its listener, before a first connection: the node pings each
  10 s and drops a socket that answers nothing for 30 s. Lost: a start at the first connection,
  which would end the node while the sandbox's programs had not asked.
- A stream of `stdio` or `fd:N` ends the proxy when its node leaves, with a line and 0, as no
  connection could start at the exit again; one of `exec:` is started again for the next
  connection, as for each client of T-595. Lost: a proxy that listens on and refuses each
  connection (410), a process that the channel's end leaves behind; and 69 for a stream that
  failed, which needs the role to keep the node's Close, where the node's own end says it.
- Ctrl-C at the proxy closes the stream with 1000, which ends the node (0), as at each client of
  a carrier. Lost: a node that outlives its proxy, which no client could reach on that stream.
- `ssh`, `proxy` and `pipe` keep refusing `--exit` beside `--carrier` (64), in words that name
  `exit --listen --carrier`: their programs reach the exit through that proxy. Lost: `--exit` of
  each client over a carrier, which the issue did not ask for.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test exit
cargo test -p podssh-relay --features pair,serve --test reverse_carrier
```

New test: `an_exit_over_a_carrier_lends_its_egress` (a node of the role exit with `--carrier
exec:` that starts `podssh exit NAME --listen 127.0.0.1:0 --carrier stdio`: curl through the
listener's CONNECT reaches an HTTP server of the test, where curl is on PATH; a member with no rule
is refused). Planted: `t596-carrier-rule-skipped` (the exit's rule not checked on a carrier): the
refusal fails.

## Correction

Read at `b02d8c4` (2026-11-03), for the draft:

- The Premise holds at each cited line; the citation of the manual takes the sentence of the
  carrier that this change adds to it.
- The rule of the exit is checked at the node by code that each road shares: the net's verdict
  (`crates/podssh-cli/src/net/admit.rs:70`) at the channel's admission and again for each address
  of the dial (`crates/podssh-cli/src/node_exit.rs`). So the node of a carrier needed none of its
  own: T-595 refused `--exit` beside `--carrier` (`node_carrier::check`), and the node's part is
  to lift it and say the exit's line as each road does. The plant of the Prove, "the exit's rule
  not checked on a carrier", has no seam of the carrier's own: it skips the rule in the net's
  verdict, on each road, and the test of the carrier must catch it.
- The proxy needs to know when the stream of one life ended: the relay role on a carrier now
  says whether its node is joined (`Role::joined`), with a test of `reverse_carrier`, which the
  Prove names.

## Done

2026-11-03, drafted (`DRAFT T-596`), merged and measured on this machine the same day.

What changed:

- `crates/podssh-cli/src/node_carrier.rs`: `check` no longer refuses `--exit`; `prepare` says the
  exit's line, or why the node cannot be one (78), once its key is loaded, as each road does; the
  unit test of the refused flags takes `--exit` as one that goes with `--carrier`.
- `crates/podssh-cli/src/exit/mod.rs`: `--carrier ADDR` of `exit` (`ExitArgs::carrier`, read by
  its id) and its checks (`carrier`: a relay's and a pair's flags, 64; `pipe`'s words, `stdio`
  among them; a terminal on stdin, 64), given to `To::carrier`; a unit test.
- `crates/podssh-cli/src/exit/open.rs`: `Road`, the pair kept under NAME or the shared client of
  the carrier (`crate::carrier::shared`); a session over a carrier is a leg of the role, with no
  expiry, its refusals and its end in the carrier's words (`crate::carrier::refusal_of`,
  `crate::carrier::judged`); `To::of_ssh` gives no carrier.
- `crates/podssh-cli/src/exit/listen.rs`: `serve` starts the carrier once the bind passed, names
  it in its first line, ends when the node of a stream of one life left (`left`), and closes the
  stream at each end (`crate::carrier::end_shared`).
- `crates/podssh-cli/src/carrier.rs`: `Client::left` and the field `one_life`.
- `crates/podssh-relay/src/serve/reverse/carrier.rs`: `Role::joined`.
- `crates/podssh-cli/src/ssh/carried.rs`, `crates/podssh-cli/src/ssh/exit_road.rs`: the words of
  `ssh --exit NAME --carrier ADDR` (64) name `exit --listen --carrier`.
- `crates/podssh-cli/src/flags/node.rs`: the row `--carrier ADDR` of `exit`; the node's row names
  the exit's client.
- `crates/podssh-cli/src/man/notes_net.rs`: a note of `exit --carrier`, with the issue's recipe;
  `crates/podssh-cli/src/man/notes_pair.rs`: the node's notes of the exit and of the carrier;
  `crates/podssh-cli/src/man/examples.rs`: the recipe.
- `crates/podssh-cli/tests/exit.rs`: `an_exit_over_a_carrier_lends_its_egress` (SOCKS5, CONNECT
  and curl to a page through the node; a member with no rule refused, SOCKS 2 and HTTP 403, its
  target never dialled; the node's end ends the proxy); three more rows of the refusals (`exit
  --carrier` with `--pair-file`, with `tcp:`, and `ssh --exit --carrier`).
- `crates/podssh-relay/tests/reverse_carrier.rs`: `the_role_says_when_its_node_left_the_stream`.
- `scripts/plants/t596-carrier-rule-skipped.patch` and `.plant` (`git apply --check`: applies).
- `docs/cli.md` ("The exit of the net", and the carrier's item), `docs/mesh.md`, `docs/reverse.md`
  (item 7 of "A carrier") and `docs/STATUS.md`.

Measured at the merge (2026-11-03, Linux, `CARGO_BUILD_JOBS=4`, curl on PATH):

- `cargo test -p podssh-cli --test exit`: 4 passed, `an_exit_over_a_carrier_lends_its_egress`
  among them.
- `cargo test -p podssh-relay --features pair,serve --test reverse_carrier`: 7 passed,
  `the_role_says_when_its_node_left_the_stream` among them.
- `cargo test -p podssh-cli --lib` (with `exit::` and `node_carrier`): 780 passed. The check of
  the names in the manual's notes found that the node's note named `--listen` after `podssh exit
  NAME`, where it reads a flag of the verb just before it: the note now says `podssh exit --listen
  ADDR:PORT --carrier ADDR NAME`, which `exit` parses as the other order (both 64 with a `tcp:`
  carrier, measured).
- `cargo test -p podssh-cli --test node_carrier`: 14 passed.
- `cargo test -p podssh-cli --test man_page --test man_flag_parity --test flag_table`: 9, 6 and
  11 passed.
- clippy `--all-targets -D warnings` of `podssh-cli` and of `podssh-relay`
  (`serve,pair,plain-ws,blocking`): clean.
- The plant `t596-carrier-rule-skipped`: caught; the test failed at the refusal of the member
  with no rule (SOCKS 2); the tree is clean again.
- `ssh`, `proxy` and `pipe` beside `--exit` with `--carrier` are T-614's (Q90).

# T-614: `ssh`, `proxy` and `pipe` take `--exit` beside `--carrier`, as `exit --listen` does

**Source:** the operator's ruling Q90 (2026-11-03) on T-596's call that only `podssh exit
--listen --carrier` lends a node's egress over a carrier: "also ssh/proxy/pipe".
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

Over a carrier, a node's egress reaches only the exit client's own listener: `ssh --exit NAME
--carrier ADDR`, `proxy --exit NAME --carrier ADDR` and `pipe`'s exit side refuse the pair with
64, so a session that needs the exit and has only a carrier opens a second command.

## Premise

- Read: T-596's draft (`draft/t596-t592-mesh`) keeps the refusal of `--exit` beside `--carrier` in
  `ssh`, `proxy` and `pipe`, naming `exit --listen --carrier` in its words.

## Approach

1. After T-596 is merged: each of the three opens the carrier's stream, takes the exit's leg on it
   as `exit --listen` does, and carries its own session through the node's egress; one stream for
   each command, started again for each leg of `exec:` as T-595's legs are.
2. The refusals go, and their words with them; the manual and `docs/cli.md` say the form.

## Decision

Calls of the draft (2026-11-03):

- `stdio` stays refused for the three (64): their stdin and stdout are the session's or the pipe's.
  They take `exec:CMD` and `fd:N`, for a host that starts the channel itself; the issue's case,
  whose end with egress starts the channel, stays `exit --listen --carrier stdio`'s. Lost: none,
  as one stdio cannot carry both the stream and the session.
- `ssh --exit NAME --carrier ADDR` builds the exit's transport with the carrier as its one road and
  reads no other (no iroh ticket, no DERP road, no transit or Piping Server road, no record of
  pkarr), as `node://NAME --carrier` races none; a flag of another road is refused in the carrier's
  words, after `--exit NAME:`. Lost: the races of the exit's other roads computed and left unused,
  which would refuse a bad variable of a road that the run never takes.
- The copies take it too (`cp`, `mv`, `scp`, `sftp`): they share `ssh`'s resolver, and each takes
  `--exit` and `--carrier` already. Lost: a refusal of the pair for them alone, code with no
  reason.
- `proxy --exit NAME --carrier ADDR` refuses `--relay-addr` and `--ca-file` (64), as `exit --listen
  --carrier` does, and the other flags of a node (`--pair-file`, `--node-key`, `--no-e2e`,
  `--resume-deadline`) stay `node://NAME`'s alone. Lost: let them pass, unused.
- A `pipe` with a `node:` side and `--exit` on one `--carrier` is refused (64): one node is at the
  other end of a stream, which the two sides would pin under two labels. Lost: both sides on the
  one stream; a carrier for each side, which needs a second flag. `pipe` keeps `--relay-addr` and
  `--ca-file` beside it, for the road of its other side (an `ssh:` hop).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test exit
cargo test -p podssh-cli --test node_carrier
cargo test -p podssh-cli --lib -- exit_road carried proxy_node notes_tests
```

`ssh --exit box --carrier exec:...` reaches OpenSSH's sshd through the node's egress, `proxy` an
echo server's 1 MiB back whole, `pipe` the same; planted, the refusal kept: the tests fail
(`t614-ssh-exit-carrier-refused`, `t614-proxy-exit-carrier-refused`,
`t614-pipe-exit-carrier-refused`).

## Correction

Read at `d629249` (2026-11-03), for the draft:

- T-596 is merged and done, so its refusals are in `main`, not on a draft's branch. Only `ssh`'s
  words named `exit --listen --carrier` (`check` of `crates/podssh-cli/src/ssh/carried.rs`, and
  `--exit` was among the flags that its `flags` refused beside `node://NAME`). `proxy` refused
  `--carrier` as a flag of a node beside a target that is no node ("goes with node://NAME, the node
  of a pair or of a carrier", `run` of `crates/podssh-cli/src/proxy_node.rs`), and `pipe` refused
  it with no `node:` side (`carrier` of `crates/podssh-cli/src/pipe/remote.rs`); neither named the
  exit. The Approach holds: each refusal goes in its own place.
- The exit's session is a leg of the command's shared stream already (`Road` of
  `crates/podssh-cli/src/exit/open.rs`, T-596), so `proxy` and `pipe` needed the carrier in their
  `To` and their checks alone; `proxy`'s run of the exit now ends inside
  `crate::ssh::transport::settled`, which closes the shared stream (the node's Close), as `pipe`'s
  run did already. `ssh` resolves `--exit` to the node's transport
  (`crates/podssh-cli/src/ssh/exit_road.rs`), and a node's transport with a carrier runs on it
  alone (`run` of `crates/podssh-cli/src/ssh/node.rs`), so the exit's transport takes the carrier,
  and the channel's word names the host, with no new road.
- Found on the way: the plant `t595-ssh-carrier-skipped` was stale, as its patch named lines of
  `crates/podssh-cli/src/ssh/mod.rs` from which a later merge had moved the node's dispatch to
  `crates/podssh-cli/src/ssh/node.rs` (`git apply --check` failed); its patch plants the same defect
  there now.

## Done

2026-11-03, drafted (`DRAFT T-614`), merged and measured on this machine the same day.

What changed:

- `crates/podssh-cli/src/ssh/exit_road.rs`: `or_exit` gives `--exit NAME --carrier ADDR` to
  `carried`, the exit's transport with the stream as its one road (the carrier's flags first, no
  other road read); a unit test (`the_exit_over_a_carrier_is_its_one_road`).
- `crates/podssh-cli/src/ssh/carried.rs`: `flags` no longer refuses `--exit`; `check` refuses
  `--carrier` with a destination that is no node and no `--exit`, in words that name both; the unit
  test takes `--exit` as one that goes with `--carrier`.
- `crates/podssh-cli/src/proxy_node.rs`: `Flags::refused_beside`, each flag of a node beside
  another target but `--carrier` beside `--exit`; a unit test.
- `crates/podssh-cli/src/proxy.rs`: the exit's arm gives the carrier to `To` (`exit_to`), names the
  carrier's step of `--ConnectTimeout`, and `exit_alone` refuses `--relay-addr`, `--ca-file` and
  stdio beside it (64).
- `crates/podssh-cli/src/exit/mod.rs`: `no_relay`, the refusal of a relay's and a pair's flags
  beside `--carrier`, which `exit --listen` and `proxy --exit` share.
- `crates/podssh-cli/src/exit/open.rs`: `To::of_ssh` gives `pipe`'s carrier; `run_proxy` runs
  inside `crate::ssh::transport::settled`, so that the stream ends with it.
- `crates/podssh-cli/src/pipe/remote.rs`: `carrier` takes `--exit NAME` in place of a `node:` side,
  and refuses both on one stream (64).
- `crates/podssh-cli/src/node_carrier.rs`: its words name the new clients.
- `crates/podssh-cli/src/flags/node.rs` (the rows `--exit` of `ssh` and the copies, of `proxy` and
  of `pipe`, and the node's `--carrier`), `crates/podssh-cli/src/flags/operator.rs` (the rows
  `--carrier` of `ssh`, `proxy` and `pipe`) and `crates/podssh-cli/src/flags/pipe.rs` (the row
  `--client-key`, which the exit takes).
- `crates/podssh-cli/src/man/notes_pair.rs` (`ssh`'s note of the carrier, with the form; the
  node's note), `crates/podssh-cli/src/man/notes_roads.rs` (`ssh --exit`),
  `crates/podssh-cli/src/man/notes_proxy.rs`, `crates/podssh-cli/src/man/notes_pipe.rs`,
  `crates/podssh-cli/src/man/notes_net.rs` (`exit`) and `crates/podssh-cli/src/man/notes.rs`
  (`cp`).
- `crates/podssh-cli/tests/exit/clients.rs` (new, a module of `crates/podssh-cli/tests/exit.rs`): 3
  tests (`ssh` to a host that speaks no SSH, 255, the node online and closed, and a member with no
  rule refused; then OpenSSH's sshd, Unix, `echo carried` with the host key under its name and `scp`
  up whole; `proxy`'s 1 MiB of an echo server back whole and the member with no rule refused, its
  target never dialled; `pipe`'s `relay:` side the same 1 MiB); `crates/podssh-cli/tests/exit.rs`:
  the row of `ssh --exit --carrier` refused goes, 8 rows of the refusals that stay (stdio, a flag
  of another road, a node side beside the exit), and the module `live_harness` for the sshd.
- `crates/podssh-cli/tests/node_carrier/clients.rs`: the row of `ssh --carrier --exit` refused
  becomes one with `--pair-file`, which stays refused.
- `scripts/plants/t614-ssh-exit-carrier-refused.patch`,
  `scripts/plants/t614-proxy-exit-carrier-refused.patch` and
  `scripts/plants/t614-pipe-exit-carrier-refused.patch`, each with its `.plant` (`git apply
  --check`: each applies); `scripts/plants/t595-ssh-carrier-skipped.patch` moved to
  `crates/podssh-cli/src/ssh/node.rs` (applies).
- `docs/cli.md` (the carrier's item, and "The exit of the net"), `docs/mesh.md`, `docs/reverse.md`
  (item 8 of "A carrier") and `docs/STATUS.md`.

Measured at the merge (2026-11-03, Linux, `CARGO_BUILD_JOBS=4`, OpenSSH's sshd here):

1. `cargo test -p podssh-cli --test exit`: 7 passed, the three tests of `clients` among them; the
   part of OpenSSH ran (`echo carried` through the exit, the host key under `127.0.0.1`, and `scp`
   of 300,000 bytes up, whole).
2. `cargo test -p podssh-cli --test node_carrier`: 14 passed.
3. `cargo test -p podssh-cli --lib`: 787 passed, `the_exit_over_a_carrier_is_its_one_road`,
   `a_carrier_goes_with_an_exit_and_each_other_flag_of_a_node_with_a_node_alone`, the test of
   `carried` and `each_name_in_a_note_exists` among them.
4. `cargo test -p podssh-cli --test man_page --test man_flag_parity --test flag_table`: 9, 6 and
   11 passed.
5. `cargo fmt -p podssh-cli -- --check` and clippy `--all-targets -D warnings` of `podssh-cli`:
   clean.
6. `sh scripts/plant-each.sh --here t614-ssh-exit-carrier-refused t614-proxy-exit-carrier-refused
   t614-pipe-exit-carrier-refused t595-ssh-carrier-skipped`: 4 caught, 0 missed, 0 stale.

# T-602: The relay role's test of two sessions of 2 MiB each way fails under load, on the limits of a road with no flow control

**Source:** the session of 2026-11-03: `cargo test -p podssh-relay --features
pair,quick,derp,serve,piping,blocking,plain-ws --no-fail-fast` failed one test, at random:
`relay_serve_reverse::two_sessions_carry_their_bytes_whole_through_the_role` (its digest of
session a). Then, six copies of its binary at once on this host's 4 CPUs: 50 of 150 runs failed
with the code of `ac1ed74`, 43 of 150 with T-601's; one at a time, 30 of 30 passed with each.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A test that fails at random. Each failure is a limit that the road keeps on purpose, met when
the host is slow: the node ends a session whose local side does not read (1000, "the node's local
side does not read"), the operator ends one whose input passed 1 MiB before the node was ready
(`NeverReady`), and the role ends a socket whose node reads too slowly (1011, "relay
backpressure"). The test sends 2 MiB each way at once with no window above the road, so on a
loaded host it measures the host, not the role.

## Premise

- Measured, 50 failures of 150: 18 "the node's local side does not read", 6 `NeverReady` ("more
  than 1048576 bytes of input came before the node was ready"), 2 "relay backpressure"; the rest
  of the 50 by the same digests, unread.
- Read: `crates/podssh-relay/tests/relay_serve_reverse.rs`, `operate` writes the whole input at
  once; `Local` takes the node's default queue.

## Approach

1. The test waits for the session's ready before it writes, and writes in pieces that the echo
   gives back (a window of its own, as the layer keeps), so that no limit of the road is met;
   the limits keep their own tests.
2. 150 runs, six at a time, pass.

## Prove

```sh
cargo test -p podssh-relay --features serve --test relay_serve_reverse
```

150 runs of its binary, six at once, pass.

## Correction

One cause was the role's, not the test's. With the window, 1 of 150 runs failed with `1008
wait for ready` on session b: the role marks the session ready and queues `ready` to the operator
under the pair's lock, then answers the leg's loop; an operator that writes as soon as it hears
`ready` (podssh's does) could have its first frame read by that loop before the answer, and its
phase still `Opening` refused it. The road's contract asks the operator to wait for `ready`, and
it had.

## Done

2026-11-03.

- `crates/podssh-relay/tests/relay_serve_reverse.rs`: an echoed session keeps 256 KiB at most in
  flight (`WINDOW`), under each bound of the road, as the layer's window does.
- `crates/podssh-relay/src/serve/reverse/operator.rs`: a binary frame that the leg's loop reads
  before it heard the node's answer is the session's when the pair's state says the node readied
  it (`readied`); before that, `1008 wait for ready` as the contract says (`relay_serve_contract`,
  10 passed).
- Six copies of the binary at once, on 4 CPUs: 0 of 300 runs failed, where the code before failed
  50 of 150 and the window alone 1 of 150 (the `1008` above). `relay_serve_reverse` 3 passed,
  `reverse_carrier` 6.
- Planted, the window removed (`usize::MAX`), with the role's repair: 2 of 60 runs failed, six at
  once. The role's half is a race of one poll, seen once in 150 runs before it and in none of 300
  after; it has no test that forces the order.

# T-611: A node's record of pkarr names its OpenTunnel name, and a member's client races it

**Source:** T-531's Correction (2026-11-03): T-531's Approach, item 1, "its record names the road
once T-445 is done".
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A node of the OpenTunnel road says its name on stderr, and a client dials it when the user gives
it, or when a run kept it under NAME. A member of the net whose client never saw the name has no
way to it: the node's record of pkarr names its other roads alone.

## Premise

- `crates/podssh-iroh/src/pkarr_record.rs:50` says "pub struct Roads": the iroh home relay, the
  DERP home and the quick tunnel's name, which `crates/podssh-cli/src/node_record.rs` keeps up to
  date (`Tell`, its `derp` and `quick`).
- `crates/podssh-cli/src/node_opentunnel.rs` knows the node's name once its tunnel is ready.

## Approach

1. `Roads` gains the OpenTunnel name, a record's text of its own, read back by its parser, with
   the length and the checks of a name (`podssh_relay::opentunnel::Name`).
2. The node of the road tells its record of its name, as the DERP road tells its home, at n0's
   server unless `PODSSH_IROH_PKARR` names another or `off` (Q81).
3. A member's client races the OpenTunnel road of its record, after the roads of its tickets, as it
   races the record's DERP home (T-445), never with `--no-e2e`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh --lib pkarr
cargo test -p podssh-cli --features iroh --test opentunnel_road
```

A record that names an OpenTunnel name is read back whole; a member's client with no name given
reaches the node of the stand-in server through the name of its record.
