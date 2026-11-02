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
**Status:** partial

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
- SUITES_448

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
**Status:** open

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

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test derp_road
```

A member reaches a DERP node of no `--allow` by its name; a stranger's key is refused. Planted, a
door with no member check, and the stranger's test fails.

# T-453: `podssh cp` and `podssh sftp` reach a member of the net by its name alone

**Source:** the merge of T-429 (2026-11-02).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

Since T-429 `podssh ssh NAME` reaches a member of the net by its name alone; `podssh cp` and
`podssh sftp` take it only as `node://NAME`.

## Premise

- The copies resolve their destinations through their own parser, which does not ask the net.

## Approach

1. The copies resolve `NAME:PATH` and `NAME` as `podssh ssh` does, the net first for a name with
   no dot.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test net
```

`podssh cp FILE lab:/tmp/` and `podssh sftp lab` reach the member `lab` through the stand-in
relay. Planted, the net's lookup skipped, and the test fails.

# T-454: The relay role brakes `/v1/mint` and `/v1/pair` for each address

**Source:** the merge of T-427 (2026-11-02); T-169's Approach, which promised it.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** open

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

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve --lib serve::
```

The 121st mint of an address within a minute is a `429`, another address's is not, and the
first after the minute passes. Planted, the brake removed, and the test fails.

# T-455: The relay role mints for the members of the net

**Source:** the merge of T-448 (2026-11-02), the second half of its Approach item 1.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** open

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

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
```

A member mints and pairs; a stranger, and a member removed by a newer document, get `403`.
Planted, the member check skipped, and the stranger's test fails.
