This file holds milestone M4, the reverse road (`docs/ROADMAP.md:148-172`): pairing, the node and
operator runners and a blocking facade in `podssh-relay`, the move of the codecs, the commands
`podssh node`, `podssh operator` and `podssh ssh NODE`, and the exit measurement. It also holds the
backlog work on that road: pairing by a code, node identity, end-to-end encryption, routes,
finding a node, and signed grants. M4 starts after M3 is complete (`docs/ROADMAP.md:7-9`); in M4,
the defects of `TODO/transport.md` come first, in the work order of `TODO/PROGRESS.md`. The rules
for the node and the operator are in `docs/reverse.md`; the wire format is in `docs/relay.md:192-214`
and in the pinned contract (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:123-193`).

# T-078: Pairing in `podssh-relay`: pair, stop and status

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-152`); `docs/design.md:89-100` (`pair`, cargo feature
`pair`); `docs/relay.md:192-214`. Read here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A node needs a pair name and a `node_token`; its operator needs the `connect_token`. podssh cannot get
them: no code calls `POST /v1/pair`, `POST /v1/stop/<name>` or `GET /v1/status/<name>`. podbox pairs
through `curl` (`docs/design.md:107-108`), which a sandbox may not have.

## Premise

Read: `POST /v1/pair` with `{}` returns `{name, node_token, connect_token, stop_token, expires}`, within
72 h; `/v1/status/<name>` gives presence with a token; `POST /v1/stop/<name>` stops the node and its
sessions; tokens go in `X-Relay-Token` (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:125-137`).
Pair creation shares the brake of 120 attempts per minute per address with mint (`:235-238` there).
These endpoints are on the "control host only" (`:23-24`, `:130`); no pool host was measured for them.

Read: `/v1/pair` can answer `409` (pair again), and a new mint secret ends each token at once
(`docs/relay.md:188-190`). `/v1/stop` once answered `{"stopped": false}` and still destroyed the
credentials (`docs/relay.md:209-212`); then the other tokens get `403 reverse: forbidden`
(`docs/reverse.md:51-52`). Which token `/v1/status` accepts is not known (`docs/reverse.md:53`); a local
copy of podbox at `5bd8cb0` says `connect_token` only (`Azathothas/podbox:crates/podbox-ssh/src/mux.rs`).

Read: `podssh-relay` has no pairing code (`crates/podssh-relay/src/lib.rs:14-21`). `https_post_json`
sends fixed headers, and `https_request`, which takes headers, is private
(`crates/podssh-ws/src/client.rs:251-303`). The private files of the token cache can hold a pair
(`crates/podssh-relay/src/cache.rs:92-119`, `:187-206`).

## Approach

1. Add crates/podssh-relay/src/pair.rs behind the feature `pair` (`docs/design.md:93`). Declare it in
   `crates/podssh-relay/Cargo.toml:10-21`, enable it in `podssh-cli`, and build it in the library step
   of the gate (`scripts/gate.sh:61`), so the no-C check covers it.
2. `pair::create` returns a `Pair`: relay host, name, the three tokens, expiry. Keep each token in
   `Zeroizing` with a redacted `Debug`, as `token::Token` does (`crates/podssh-relay/src/token.rs:27-53`).
   Check the name with T-076, and each token with `cache::valid_token`
   (`crates/podssh-relay/src/cache.rs:52-56`). Never quote a 2xx body (`crates/podssh-relay/src/token.rs:175`).
3. Answers: `409`, pair again once; `429`, report `Retry-After`; `503`, stop. Refuse a pair with less
   than 10 min left, as the token cache does (`crates/podssh-relay/src/cache.rs:15-16`).
4. `pair::stop` sends `stop_token` to `/v1/stop/<name>`, then deletes the local copy whatever the
   answer. Never print the `stop_token` (`docs/reverse.md:48-49`).
5. `pair::status` tries `connect_token`, then `node_token`; record the one that works in
   `docs/reverse.md:53`.
6. Add to `podssh-ws` a public request with one token header (`crates/podssh-ws/src/client.rs:281-303`).
   Invariant: the header value never reaches an error.
7. Store a pair as one private file (`cache::store_file`) under the local label of T-083. The
   operator's part (relay host, name, `connect_token`, expiry) goes to a file that the user names
   (create-new, mode 0600), never to stdout.
8. Use the control host only (`tcp.ssh.relay.ajam.dev`, or one host that the user names). No failover
   to pool hosts until a measurement shows that they serve `/v1/*`.
9. In the same commit: `docs/relay.md:192-214`, `docs/reverse.md:46-53`, and the FILES section of the
   manual (`crates/podssh-cli/src/man/facts.rs:93`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test pair
cargo test -p podssh-relay --features pair --test pair_live -- --ignored
sh scripts/dev.sh check
```

The offline tests in crates/podssh-relay/tests/pair.rs parse a `/v1/pair` body captured from the live
relay, with the tokens replaced by test strings. They refuse a bad name and a bad token, find no token
in `{:?}` or in an error, and check the mode 0600. Plant: print a token in `Debug`; the redaction test
must fail. The live test pairs, asks for status with each token, stops, and asserts `403` for the other
tokens, in one run that prints no token. The gate shows that the feature adds no C.

# T-079: The node runner

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-158`); `docs/design.md:94-97`; `docs/reverse.md:8-28`; GitHub #19
(a design input). Read here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

A host whose only egress is the relay cannot offer a service: podssh has no node. A node keeps one WebSocket to
`/v1/node/<name>`, answers each `open` with `ready` or `reject`, and carries many sessions on it by their
32-character ids. One mistake closes the socket and ends every session on it (`docs/reverse.md:10-14`).

## Premise

Read: the rules (`docs/reverse.md:10-28`): one writer, with the id and the payload in one frame; stop the writes
of a session at its `close`; never close the socket for one session; `ready` only after the local side
accepts; route by id after a check of the hex; exit on `409`; do not depend on `hello`; no keepalives come on
reverse sockets; connect again with a jitter.

Read: the codecs exist, with tests: node frames and chunks (`crates/podssh-transport/src/framing/legs.rs:26-58`,
`:113-123`), control messages (`crates/podssh-transport/src/control.rs:155-238`), a limit of 16 sessions when
no `hello` comes (`crates/podssh-transport/src/control.rs:111-137`), and the close table
(`crates/podssh-transport/src/closes.rs:60-88`, `:159-229`). They carry the defects of T-071, T-072, T-073,
T-075 and T-076.

Read: `RelaySession` has text, binary, Ping and Close writes and a liveness watcher
(`crates/podssh-ws/src/session.rs:86-166`); `podssh_relay::open::backoff` has a jitter
(`crates/podssh-relay/src/open.rs:263-277`). Not measured: whether the relay answers a Ping on a reverse socket
(`docs/relay.md:71-73` is the forward path), and its idle cut there (`docs/relay.md:186-187`, T-061). A node
that connects again ends each operator session on it (`docs/design.md:174-177`).

Read in a local copy of podbox at `5bd8cb0` (`docs/design.md:66` names `452d792`): `run_node` owns the socket in
one thread, drops late bytes of a closed id, and dials again with a backoff
(`Azathothas/podbox:crates/podbox-ssh/src/mux.rs`). It also needs `hello`, accepts upper-case ids, and has no
`409` rule; do not port these (`docs/reverse.md:17-21`,
`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:174`). GitHub #19 cites syq's receive mode, one
persistent connection that the far side opens (`greaber/syq:src/conn/reverse_tcp.rs`; read in the report, not
verified here).

## Approach

1. crates/podssh-relay/src/reverse/node.rs: `node::run(config, handler)`; `handler.open(id)` gives a byte stream
   or a reason to reject. It uses the codecs of `podssh-transport` until T-082. Invariant: no protocol above
   bytes (`docs/architecture.md:92-94`).
2. One task owns the write half; sessions send `(id, bytes)` through one bounded channel, cut by
   `chunk_for_node`. Invariant: no frame without its id; none for an id not readied, or closed.
3. On `open`: call the handler with a limit under 15 s
   (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:190`); then `ready`, or `reject` with the
   reason. Over the session limit, `reject` at once.
4. On `close {id}`: stop the writes of that session, shut its local stream, drop its late bytes. Never send a
   Close frame for one session.
5. Liveness: measure whether the relay answers a Ping on a node socket; if it does, use `watch_liveness`. Never
   send an empty binary frame: under 32 bytes is `1009 bad multiplex frame` (`:182` of the contract).
   Pitfall: no idle read limit while no probe exists; the forward opener sets 90 s
   (`crates/podssh-relay/src/open.rs:232`), and a quiet socket would reconnect.
6. Close actions, by code and reason (`docs/reverse.md:42-44`): `409`, exit, no retry;
   `1001 operator stopped reverse relay`, exit and delete the pair; `1001 pair expired`, or a `403` after the
   stored expiry, a re-pair hook that is off by default; `1003` and `1009`, exit with the reason, never a loop;
   any other close, connect again with `open::backoff`.
7. A clean stop (SIGTERM or Ctrl-C): `close {id}` with a reason for each session, a Close `1000`, then exit 0.
8. A TCP handler dials with `podssh_ws::dial::dial` (`crates/podssh-ws/src/dial.rs:207`), which keeps loopback
   off the proxy (`crates/podssh-ws/src/dial.rs:138-145`).
9. Record each rule in `docs/reverse.md`, and each measurement in `docs/STATUS.md`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_node
cargo test -p podssh-relay --features pair --test reverse_live -- --ignored node_serves_two_sessions_at_once
```

Offline: the runner runs over an in-memory stream, against a scripted relay that writes real WebSocket frames
(`RelaySession::new` takes any stream: `crates/podssh-ws/src/session.rs:64-68`). The cases: two mixed sessions
with exact bytes; late bytes after `close` dropped, the socket kept; no data before `ready`; one exit on `409`;
the hook on `1001 pair expired`; exit and a deleted pair on `1001 operator stopped reverse relay`. Plant: send
`ready` before the handler returns; that test must fail. Live: pair (T-078), run an echo node, open two
sessions at once with T-080, compare the digests of 1 MiB each way, and stop the pair.

# T-080: The operator runner

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-158`); `docs/design.md:94-97`; `docs/reverse.md:30-44`.
Read here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

An operator outside the cage cannot reach a node: podssh has no operator leg. The operator connects
to `/v1/connect/<name>`, waits for the text `ready`, then moves raw bytes with no framing. Bytes sent
before `ready` end the session, and a `reject` must reach the user with the node's full reason.

## Premise

Read: the rules (`docs/reverse.md:30-44`). Never add or remove the 32-byte id. A `reject` text
frame carries the full reason before the close, whose reason is cut to 123 bytes. Wait longer than
the relay's 15 s for `ready`. A session that never got `ready` never exits 0. After `ready`, `1003`
and `1009` exit with a code that is not zero. Use the code and the reason.

Read: data before `ready` closes the operator with `1008 wait for ready`, a text frame from the
operator closes it with `1003`, a frame carries at most 65536 bytes, and a session at most 64 MiB
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:141-148`, `:178-184`, `:190`, `:192`).
The relay sends no keepalives on reverse sockets (`docs/reverse.md:22-24`).

Read: the codecs: `encode_operator_frame` and `chunk_for_bare`
(`crates/podssh-transport/src/framing/legs.rs:60-76`, `:125-133`), and `parse_operator_control`
(`crates/podssh-transport/src/control.rs:209-216`). `podssh proxy` has the pump to follow: stdin and
stdout, liveness, the close reason (`crates/podssh-cli/src/proxy.rs:180-275`).

Read in a local copy of podbox at `5bd8cb0`: `run_operator` waits 20 s for `ready`, queues at most
1 MiB of input before it, sends a Close after the end of input and waits 10 s for the answer, and
fails on each close but `1000` (`Azathothas/podbox:crates/podbox-ssh/src/mux.rs`).

## Approach

1. Module crates/podssh-relay/src/reverse/operator.rs: `operator::run(config, io) -> Outcome`, for
   any `AsyncRead + AsyncWrite`. Invariant: bytes pass unchanged; no id is added or removed.
2. Before `ready`: queue the input up to 1 MiB, then fail; send no data frame. Wait 20 s for
   `ready`, which is more than the relay's 15 s, then fail with "the node did not answer".
3. On `ready`: send the queue, then copy both ways in chunks of 65536 bytes (`chunk_for_bare`).
   Ignore an empty binary frame.
4. On a `reject` text frame: keep its full reason; the Close after it gives the code. After `ready`,
   a text `close` keeps its reason. Never send a text frame.
5. Outcome: `NeverReady { code, reason }`, `Ended { code, reason }` or `LocalEnd`. Never ready is a
   failure; `1000` after `ready` is success; each other code after `ready` is a failure that names
   the code and the reason (`docs/reverse.md:39-44`).
6. End of input: send a Close `1000`, and wait up to 10 s for the relay's answer, so the last bytes
   arrive.
7. Liveness as in T-079: `watch_liveness` only if the relay answers a Ping on this leg; no idle read
   limit until then (the relay sends no keepalives here).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_operator
cargo test -p podssh-relay --features pair --test reverse_live -- --ignored operator_sees_reject_with_full_reason
```

The offline tests use the scripted relay of T-079. Input before `ready` is queued, not sent, then
sent in order; `1008`, `1003` and `1009` after `ready` give a failure with the code and the reason; a
`reject` reason longer than 123 bytes reaches the outcome whole; no `ready` in 20 s fails; no
outcome is a success without `ready`. Plant: send the queue before `ready`; the first test must
fail. The live test runs a node whose handler rejects with a 200-byte reason, and asserts that the
operator's outcome holds all 200 bytes.

# T-081: A blocking facade of `podssh-relay`, for podbox

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-152`, `:176-177`); `docs/design.md:98-108`. Read here
on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podbox is synchronous and has no async runtime, so it cannot call `podssh-relay`, whose functions
are `async` on tokio. Until it can, podbox keeps its own WebSocket, TLS and dial code. That code has
no HTTPS proxy support, so its node cannot leave a sandbox whose only egress is a CONNECT proxy.

## Premise

Read: podbox's reverse legs work live; it has no HTTPS proxy support; it is synchronous; it builds
`ring`; its MSRV is 1.85; it is made for TLS-intercepting proxies (`docs/design.md:70-80`). The plan
is a synchronous facade that owns a current-thread runtime (`docs/design.md:98-99`); then podbox
pins `podssh-relay` by git revision and removes its own `ws.rs`, `tls.rs`, direct dial and pairing
through `curl` (`docs/design.md:107-108`).

Read: `podssh-relay` declares the workspace minimum, Rust 1.88 (`crates/podssh-relay/Cargo.toml:5-6`,
`Cargo.toml:45-48`), above podbox's 1.85. `podssh proxy` already runs async code from sync code with
a current-thread runtime and `shutdown_background` (`crates/podssh-cli/src/proxy.rs:79-92`).

Read: podbox keeps `ring` and TLS 1.2 through a `rustls::ClientConfig` that it supplies
(`docs/design.md:102-104`); that is T-066, not this entry.

## Approach

1. Module crates/podssh-relay/src/blocking.rs, feature `blocking`: `Relay::new(config)` builds one
   current-thread runtime with IO and time. Methods: `pair`, `stop`, `status`, `run_node(handler)`,
   `run_operator(io)`, `open_forward(target)`; each calls `block_on`.
2. Invariant: no method runs inside a tokio runtime. Check with `Handle::try_current` and return an
   error; never panic.
3. podbox's side is `std::io::Read + Write`. Bridge each session to the async runner with one thread
   per session, bounded by the session limit.
4. Errors are plain types with the relay's code and reason; no tokio type in the public API.
5. Accept the caller's `rustls::ClientConfig` through T-066; else use podssh's own provider.
6. MSRV: measure whether `podssh-relay` with these features builds on Rust 1.85. If it does not,
   it needs 1.88, and podbox follows (the operator's ruling of 2026-10-08). Write the result in
   `docs/design.md` (section 3).
7. Document the facade in `docs/design.md:89-108` and in the crate's header
   (`crates/podssh-relay/src/lib.rs:1-12`); add the feature to the gate (`scripts/gate.sh:61`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,blocking --test blocking
sh scripts/dev.sh check
```

The new tests call each method from a plain `#[test]` with no runtime: a forward session against a
stand-in, a node and an operator against the scripted relay of T-079, and the refusal inside a
runtime. Plant: remove the `try_current` check; the test inside a runtime must fail (a panic). The
gate shows the feature adds no C. The podbox side is proved in T-085.

# T-082: Move the codecs of `podssh-transport` into `podssh-relay`

**Source:** ROADMAP M4 (`docs/ROADMAP.md:153-154`); `docs/design.md:105-106`; the former defects
page (`git show 3ee70dc:docs/defects.md`), section "podssh-transport". Read here on `3ee70dc`.
**Category:** chore
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The relay protocol lives in two crates. `podssh-relay` opens forward sessions and handles tokens;
`podssh-transport` holds the reverse framing, the control messages and the close table, mostly
unused. Two crates for one protocol drift: they already disagree on the backoff (T-077) and on
`403` and `503` (T-075).

## Premise

Read: about 600 lines of `podssh-transport` are used outside its tests (the former defects page),
and `docs/STATUS.md:209` gives 2.8k source and 2.2k test lines. Only examples use it:
`crates/podssh-cli/examples/live_irc.rs:20-22`, `crates/podssh-cli/examples/live_irc/support.rs:11-16`
and `crates/podssh-transport/examples/live_forward.rs:23-25`; `podssh-cli` depends on it
(`crates/podssh-cli/Cargo.toml:34`). The plan: "`podssh-transport` moves into `podssh-relay`. Its
unused backpressure module goes." (`docs/design.md:105-106`).

Read: the comments of the crate break rule 6 of `AGENTS.md:193-194`: they carry the stop-sign marker,
session history and line numbers of documents, for example `crates/podssh-transport/src/socket.rs:1-11`
and `crates/podssh-transport/src/control.rs:3-14`. The close rows cite lines of the pinned contract,
and a test reads that copy to check them (`crates/podssh-transport/src/closes.rs:45-59`).

## Approach

1. Order: after T-083 and T-084, as the work order of `TODO/PROGRESS.md` says. The runners of T-079
   and T-080 use the repaired codecs as a dependency until then.
2. Move into crates/podssh-relay/src/reverse/: `framing.rs` and `framing/legs.rs`, `control.rs`,
   `closes.rs`, the retry parts of `error.rs`, and the name check of T-076, with their tests. Keep
   each file at 500 lines or fewer (`AGENTS.md:191-192`).
3. Delete, do not move: the backpressure module (T-074), the `Transport` trait and `backoff.rs`
   (T-077), and `RelayConfig` (`podssh-relay` has `Relay` and `RelayList`,
   `crates/podssh-relay/src/relay.rs:28-50`).
4. Rewrite the comments of the moved code to `AGENTS.md:193-194`: why, in few words; no markers, no
   history, no line numbers. Keep the check of the close rows against the pinned copy as a test
   (T-060 decides where the copy lives).
5. Move the examples to `podssh_relay::open`, the forward path that the commands use. Then remove
   the crate: `Cargo.toml:6`, `Cargo.toml:24`, `Cargo.toml:55-58`, `crates/podssh-cli/Cargo.toml:34`,
   `scripts/gate.sh:61`, `scripts/plant.sh:39`.
6. Update in the same commit: `AGENTS.md:188-190` and `AGENTS.md:234`, `docs/architecture.md:75` and
   `:92-102`, `docs/development.md:13-14` and `:240`, `docs/STATUS.md:206`, `:208` and `:218`. The list
   of library crates in `docs/decisions.md:34` is a fact of a decision row: correct it, and move the
   old text to Superseded (the operator's ruling of 2026-10-08).

## Decision

Recommendation: move the codecs and delete the crate, as `docs/design.md:105-106` plans. The
alternative, keep `podssh-transport` as a codec crate under `podssh-relay`, lost: it keeps two error
types and two retry tables for one protocol, which is how `403` and `503` already diverged (T-075).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --all-features --no-fail-fast
cargo build --examples -p podssh-cli
git grep -n "podssh-transport\|podssh_transport" -- crates scripts Cargo.toml .github ; test $? -eq 1
sh scripts/dev.sh check
python scripts/check-repo.py
```

The moved tests pass in `podssh-relay` with their names. `git grep` exits 1 when no code, script or
workflow names the old crate. The gate shows that the library crates still build with no C
compiler. Plant: leave one `use podssh_transport` in an example; the build must fail.

# T-083: `podssh node NAME TARGET`

**Source:** ROADMAP M4 (`docs/ROADMAP.md:163-164`); `crates/podssh-cli/src/positionals.rs:42`; GitHub #19, and
GitHub #18 for zuko's doctor (read in the reports, not verified here). Measured here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A user in a cage cannot offer a local TCP service to an operator outside. `podssh node` refuses with exit 70
and takes no TARGET; `podssh relay pair` and `revoke` refuse too.

## Premise

Measured on `3ee70dc`, offline (`PODSSH_OFFLINE=1`, stdin from `/dev/null`):
`podssh node mynode` gives `'node' is not implemented yet; nothing was done.` and exit 70;
`podssh node mynode 127.0.0.1:22` gives `'127.0.0.1:22' is not an argument this verb takes.` and exit 64;
`podssh node --help` shows `podssh node NAME` and only `--help`; `podssh relay pair` gives the `--timeout`
refusal of T-008 (exit 64), and `podssh relay --timeout 5s pair` exit 70.

Read: `node` has no flags (`crates/podssh-cli/src/flags.rs:393-394`) and one positional, `NAME`
(`crates/podssh-cli/src/positionals.rs:42`). `relay` lists `pair` and `revoke` (`:39-41` there), and its
`--relay-host` takes a URL, not the `HOSTS` list of the other verbs (`crates/podssh-cli/src/flags.rs:311-319`).
Both are rows of `VERB_OWNER` (`crates/podssh-cli/src/flags.rs:426-434`).

Read: the relay names an agent-created pair; only an admitted name is chosen, by the relay's operator
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:90-91`, `:130-134`). In the measured sandbox
nothing can listen, and `connect()` to loopback failed with `EACCES` (`docs/target-environment.md:22`, `:25`).
So a local TCP TARGET exists only where the host allows it; `podssh serve` (M5) serves in the process
(`docs/reverse.md:25-28`).

## Approach

1. Parse `podssh node NAME TARGET`: NAME is a local label, TARGET is `HOST:PORT`
   (`crates/podssh-cli/src/positionals.rs:42`). Flags (`crates/podssh-cli/src/flags.rs:393-394`):
   `--relay-host HOST` (one host, T-078), `--relay-addr`, `--ca-file`, and `--pair-file FILE` to import a pair.
   No `--timeout`: a node is a service.
2. Load the pair stored under NAME (T-078); refuse an expired one with the remedy; then run `node::run` (T-079)
   with a TCP handler that dials TARGET for each `open`.
3. `podssh relay pair NAME [--operator-file FILE]` creates and stores the pair, writes the operator's part to
   FILE, and prints only the label and the expiry. `podssh relay revoke NAME` stops the pair and deletes the
   local copies. `podssh relay status NAME` gives presence; agree on the form with T-058, whose `relay status`
   has no NAME.
4. Exit codes as `podssh proxy` (`docs/cli.md:185`): 64 usage; 69 the relay or TARGET cannot be reached; 77 a
   refused pair (`403`); 78 no usable pair; 0 after a stop by a signal. Add the rows to
   `crates/podssh-cli/src/man/facts.rs:192`.
5. `doctor`: one line for each stored pair, with its expiry and its presence, as in
   `crates/podssh-cli/src/doctor/relay_checks.rs:39-64` (zuko's doctor checks its ticket and state).
6. Remove `node` and `relay` from `VERB_OWNER`, and add them to `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:95`). New variables go in `VARIABLES`
   (`crates/podssh-cli/src/man/facts.rs:45`), files in FILES (`:93` there), examples in
   `crates/podssh-cli/src/man/examples.rs:8-42`; update `docs/cli.md`, `docs/reverse.md` and
   `docs/STATUS.md:48-50`.
7. Pitfalls: `podssh man relay` shows the command; the topic THE RELAY has its own key since
   T-234 (`relay-facts`, `crates/podssh-cli/src/man/facts.rs:38`), so keep the two apart. Never
   print a token: a test runs the binary with tokens in the
   environment and in the store, and searches stdout and stderr.

## Decision

Recommendation: NAME is a local label for a stored pair, because the relay picks the pair's name and changes it
with each new pair; a label keeps a script stable. The alternative, NAME as the relay's name, lost: a user
cannot choose it, and it lasts 72 h at most.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node
cargo test -p podssh-cli --test man_page --test man_flag_parity --test flag_table
XDG_CACHE_HOME=$(mktemp -d) timeout 20 target/debug/podssh node lab 127.0.0.1:22 </dev/null; echo "exit=$?"
cargo test -p podssh-relay --features pair --test reverse_live -- --ignored node_command_serves_a_tcp_target
```

crates/podssh-cli/tests/node.rs checks the parse (TARGET required; a bad label or port is 64 before a
connection), the refusal with no stored pair (78, naming `podssh relay pair`), and that no token reaches stdout
or stderr. The binary line must exit 78 and name `podssh relay pair lab`. The live test runs the binary as a
node in front of a public TCP service and reaches it through T-080. Plant: print the pair file in
`relay pair`; the redaction test must fail.

# T-084: `podssh operator NAME` and `podssh ssh NODE`

**Source:** ROADMAP M4 (`docs/ROADMAP.md:163-164`); `crates/podssh-cli/src/flags.rs:395-396`. Measured
here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

An operator cannot reach a node. `podssh operator` refuses with exit 70, and `podssh ssh` cannot name
a node: `node:lab` reads as host `node` with a port that is not a number.

## Premise

Measured on `3ee70dc`, offline: `podssh operator mynode` gives exit 70;
`podssh ssh -T node:lab true` gives `"node:lab": "lab" is not a port` and exit 64;
`podssh ssh -T node:22 true` reaches the connect step for host `node`, port 22 (exit 255 from
`PODSSH_OFFLINE`); `podssh ssh -T node://lab true` gives `"//lab" is not a port` and exit 64.

Read: `parse_hop` strips `ssh://` and reads `host:PORT` (`crates/podssh-cli/src/ssh/resolve.rs:347-388`).
`Transport` is `Relay` or `Direct` (`crates/podssh-cli/src/ssh/resolve.rs:19-27`, chosen at `:220-245`).
`connect_and_run` gives `relay_stream::spawn` to russh (`crates/podssh-cli/src/ssh/mod.rs:72-119`), and
`relay_stream` closes with 1002 on a text frame (`crates/podssh-ssh/src/relay_stream.rs:130-136`); the
operator leg receives text frames (`docs/relay.md:205-208`). A host key is recorded under the target
host, never the relay's name (`SECURITY.md:50-55`); `HostKeyAlias` exists
(`crates/podssh-cli/src/ssh/resolve.rs:264`). `podssh ssh` uses the exit codes of OpenSSH, and
`podssh proxy` sysexits (`docs/cli.md:181-185`).

## Approach

1. `podssh operator NAME`: load the operator's part of the pair under NAME (T-078, T-083), and run
   `operator::run` (T-080) on stdin and stdout: a byte pipe as `podssh proxy`
   (`crates/podssh-cli/src/proxy.rs:180-275`). stdout carries data only; never 0 without `ready`.
2. `podssh ssh node://[user@]NAME`: `parse_hop` reads `node://` as it reads `ssh://`; add
   `Transport::Node` (`crates/podssh-cli/src/ssh/resolve.rs:19-27`).
3. For a node, `connect_and_run` opens the operator leg and waits for `ready` (T-080), then gives
   russh the raw stream. Do not give the leg to `relay_stream::spawn` as it is: reuse its pump after
   `ready`, with text frames read as control.
4. Host keys: record and check the node's key under the name `node://NAME`, which no DNS name can be;
   `-o HostKeyAlias` still wins.
5. Refuse by name a node as a `-J` hop, and `-W` through a node; record them for later.
6. Flags: `--pair-file FILE` for `operator` and `ssh` (`crates/podssh-cli/src/flags.rs:112-233`,
   `:395-396`). Update the manual's examples and notes, `docs/cli.md:62-75` and `docs/reverse.md`.

## Decision

Recommendation: `node://[user@]NAME`, read as `ssh://` is (`crates/podssh-cli/src/ssh/resolve.rs:352`),
because it changes no destination that works today (measured above). The alternative `node:NAME`, the
address form of `podssh pipe` (`docs/design.md:249`), lost: `podssh ssh node:22` already means host
`node`, port 22. A flag such as `--node NAME` lost: `podssh ssh` takes its destination as a word, as
OpenSSH does.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- node_destinations
cargo test -p podssh-cli --test operator
XDG_CACHE_HOME=$(mktemp -d) timeout 20 target/debug/podssh ssh -T node://lab true </dev/null; echo "exit=$?"
cargo test -p podssh-relay --features pair --test reverse_live -- --ignored ssh_to_a_node
```

`node_destinations` checks `node://lab` and `node://u@lab`, and that `node:22` stays host `node`, port
22. `operator.rs` runs the binary with no stored pair (78, naming `podssh relay pair`), and checks
that stdout stays empty. The binary line must exit 255, name `podssh relay pair lab`, and open no
connection. The live test runs `podssh ssh node://lab 'exit 3'` through a node whose TARGET is
`railway.new:22` (an anonymous SSH service, `docs/STATUS.md:62`), and expects 3. Plant: read `node:`
with no slashes as a node; `node_destinations` must fail.

# T-085: M4 exit: two sessions at once into a node in another sandbox, and the facade for podbox

**Source:** the exit criteria of M4 (`docs/ROADMAP.md:167-172`). Read here on `3ee70dc`.
**Category:** measurement
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

M4 ends with two measurements: two sessions at the same time through the live relay, from a sandbox
whose only egress is a CONNECT proxy, to a node in another such sandbox; and the blocking facade for
podbox, passing a test with two clients in this repository. Neither can run yet. podbox pins the
facade later, as an operator action (the operator's ruling of 2026-10-08).

## Premise

Read: the box like the target sandbox has one CONNECT proxy for ports 443, 80 and 8443 as its only
way out, refuses `bind` and UDP, and has no `/dev/ptmx` (`docs/development.md:130-172`,
`scripts/test_in_box.sh`). It allows `connect()` to loopback, which the real sandbox refuses
(`docs/development.md:171-172`, `docs/target-environment.md:22`).

Read: in such a sandbox nothing can listen (`docs/target-environment.md:25`, `:74-77`), so a node
there has no local TCP service to offer before `podssh serve` (M5). Its TARGET must be a host that
its proxy allows (`docs/target-environment.md:21`).

Read: podbox's reverse legs carried two sessions at once over the live relay on 2026-09-28
(`docs/design.md:72-73`). Its own test with two clients is in its repository (`Azathothas/podbox`),
not here.

## Approach

1. Inputs: T-078 to T-084, and T-066 for podbox.
2. A new script scripts/reverse-in-boxes.sh starts two boxes from the image, proxy and seccomp
   profile of `scripts/test_in_box.sh`. Box B: `podssh relay pair m4`, then `podssh node m4 TARGET`,
   with TARGET a public HTTPS or HTTP service that its proxy allows. The script copies the operator's
   file from B to A, as a user would over a trusted channel.
3. Box A: start two `podssh operator m4` at the same time. Each sends a fixed request and saves the
   reply. Record both replies with digests, the start and end times, and the close codes.
4. A run from the operator's real sandbox follows the release, as an operator action.
5. The facade of T-081: a test in this repository with two clients that use the blocking facade at
   once, each through the box's proxy. podbox runs its own test when the operator pins the facade.
6. Record the commands and the results in `docs/STATUS.md` (a section "The reverse road, measured"),
   and update `docs/ROADMAP.md:167-172`.

## Prove

```sh
sh scripts/reverse-in-boxes.sh path/to/podssh-x86_64-unknown-linux-musl; echo "exit=$?"
```

The script exits 0 only when both sessions return the expected bytes with equal digests, their
times overlap, the relay closed each with `1000`, and the pair was stopped at the end. Plant: start
the second operator after the first ends; the overlap check must fail. The facade half is the test of
step 5.

## Start condition

M3 is complete and T-078 to T-084 are done.

# T-086: Pairing by a short one-time code, given out of band

**Source:** GitHub #18 (reports on zuko, warren, GPU-Share and quic-ssh) and GitHub #19 (report on
slingshot); read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** blocked

## Problem

After T-083, the node gives the operator a file with the relay name and a `connect_token` that lasts
up to 72 h, and a person must move that file over a trusted channel. A short code that a person can
read aloud, used once, is easier; but the code must not become a weak credential for the relay.

## Premise

Read in the reports (not verified here): zuko pairs once with a two-word code
(`adonm/zuko:docs/pairing-flow.md`); slingshot's pairing line holds a code that never crosses the
network (`ado11231/slingshot:crates/slingshot-core/src/keys.rs`); warren's enrollment codes work
once, for 10 min (`willykeenan/warren:docs/protocol.md`); GPU-Share signs codes with identity and
address hints (`arjun988/GPU-Share:crates/gpumesh-core/src/handshake.rs`); quic-ssh pairs with a
one-time code and pins `known_hosts` (`VLOD-ZDOV/quic-ssh:src/pair.rs`).

Read: the relay picks the name and the three tokens of a pair
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:130-136`), and the contract says to
accept a connect token only over a trusted channel (`:137-138` there). The relay has no endpoint that
exchanges a code for a token. An operator cannot reach a node before it has the `connect_token`, so
a code exchange needs a meeting point that both reach with no pair.

INFERRED: a code of 2 to 4 words (about 20 to 45 bits) cannot resist a guess offline once data
sealed with it leaks. Only an online exchange, a password-authenticated key exchange (PAKE), keeps a
short code safe.

## Approach

1. Keep the file of T-083 as the base and as the fallback.
2. SPAKE2 between node and operator, keyed by the code; then the node sends the operator's part
   (relay host, name, `connect_token`, expiry), sealed with the agreed key. The code never crosses
   the network.
3. A meeting point that both reach with no pair: see the Decision.
4. The code: three words from a fixed list and a number, used once, valid for 10 min. The node shows
   it only on its terminal, never in stdout, a log or argv; the operator types it at a prompt.
5. A pure-Rust SPAKE2 crate, built under `CC=/nonexistent` before it is chosen (`AGENTS.md:188-190`).
6. Pitfalls: limit the attempts at the meeting point; one failed exchange ends the code; check the
   received part as T-076 and T-078 check a pair.

## Decision

Recommendation: SPAKE2 through a mailbox in the relay, when the relay's operator adds one (the relay
stays a separate project, ruled on 2026-10-08; signed grants wait for it too, T-226). The alternative, a pairing string
sealed with a key from the short code, lost: whoever copies the string can guess the code offline. A
public mailbox of another project, reached through the forward road, lost for now: podssh would
depend on a service that it does not run for each pairing. Keep it as the fallback if the relay's
operator declines.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,code --test pair_code
cargo test -p podssh-relay --features pair,code --test pair_code_live -- --ignored
```

Offline: two peers in one process with the same code agree and move the operator's part; a wrong
code fails both sides and ends the code; a second use fails; a code older than 10 min fails; the
code is in no output. Plant: accept a second use; the single-use test must fail. Live: a node and an
operator on two hosts pair by code through the mailbox, then `podssh operator` reaches the node.

## Blocker

The relay's operator: a mailbox endpoint for the pairing (the relay is a separate project:
`docs/decisions.md`). The operator ruled on 2026-10-08 that sessions skip this entry until then.

# T-087: Node identity and access: a node key, an allowlist, an expected fingerprint, revocation

**Source:** GitHub #18 (reports on iroh-ssh, GPU-Share, warren and zuko); read in the reports, not
verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

On the reverse road, each holder of the `connect_token` reaches the node, and the operator trusts
whatever answers at the pair's name. The relay issues both tokens. For an SSH target (`podssh serve`,
M5), host keys and user keys give identity and access; for any other TARGET there is none.

## Premise

Read: credentials are HMAC tokens scoped to a name and a role, issued by the relay
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:128-129`); accept a connect token only
over a trusted channel (`:137-138`); the node chooses what to expose (`:245-246`).

Read: `podssh ssh` checks host keys with `known_hosts`, and never records one under the relay's name
(`SECURITY.md:28-32`, `:50-55`). `podssh serve` keeps its host key in a state file and takes
authorized keys from a flag or a file (`docs/ROADMAP.md:176-181`, T-107).

Read in the reports (not verified here): iroh-ssh warns about an ephemeral node key
(`rustonbsd/iroh-ssh:src/ssh.rs`); GPU-Share keeps an Ed25519 identity in a state directory and a
default-deny allowlist (`arjun988/GPU-Share:crates/gpumesh-core/src/node.rs`); warren pins a key on
first sight, has `trust NAME --expect FINGERPRINT` and revocation, and exits 7 on a mismatch
(`willykeenan/warren:src/cli.rs`); zuko stores device authorization for each peer
(`adonm/zuko:src/store.rs`). iroh identifies endpoints by Ed25519 keys (`docs/design.md:269-271`).

## Approach

1. Node key: Ed25519, made on the first run, in a private state file of the chain of
   `crates/podssh-relay/src/cache.rs:58-73`. One key for each road, shared with T-163, so the
   identity does not depend on the road.
2. Operator key: the same form, on the operator's side.
3. Proof: both ends prove their keys at the start of each session, inside the channel of T-088
   (Noise IK uses these static keys). Before T-088, a raw TARGET has no proof; the manual says so.
4. Allowlist on the node: when the allowlist file exists, deny by default. One fingerprint for each
   line, with a comment. A refused operator gets `reject {id, "not allowed"}` and no byte of the
   TARGET.
5. Expected fingerprint on the operator: `--expect SHA256:...`, or the value pinned in the pair
   file. The first sight pins it in a file like `known_hosts`. A mismatch refuses with both
   fingerprints and its own exit code.
6. Revocation: remove a fingerprint from the allowlist; `podssh relay revoke` (T-083) stops the pair.
7. For a `podssh serve` target, SSH gives this already: decide in T-107 whether the node key is also
   the host key; the allowlist is then `authorized_keys`.

## Decision

Recommendation: one Ed25519 node key for each host, proved inside the channel of T-088, because one
identity then covers each TARGET and each road. The alternative, identity through SSH only
(`podssh serve` with `known_hosts` and `authorized_keys`), lost as the only answer: a raw TCP TARGET
(T-083) and chat (T-099) have no SSH. Keep SSH's keys for SSH targets.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,identity --test identity
cargo test -p podssh-relay --features pair,identity --test reverse_live -- --ignored a_changed_node_key_is_refused
```

Offline: a pinned key matches; a changed key refuses with both fingerprints; an operator outside the
allowlist gets a `reject` and no byte of the TARGET; a removal applies to the next session; the key
file has mode 0600 and is never printed. Plant: skip the allowlist check; the refusal test must
fail. Live: a second node with another key under the same label is refused by the operator.

# T-088: End-to-end encryption between two podssh ends

**Source:** GitHub #18 (report on warren; read in the report, not verified here);
`docs/design.md:334-340`, `:353-357`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

The relay sees the bytes of each reverse session. SSH protects itself: an SSH session through a node
is encrypted from the operator's client to the server. A raw TCP TARGET of `podssh node` (T-083),
`podssh pipe` with `node:` (M7) and chat on the roads (T-099) are plain text to the relay.

## Premise

Read: the relay sees the target, the time and volume of the traffic, and the start of an SSH
connection; after the key exchange it sees only ciphertext (`SECURITY.md:11-21`). It can drop, delay
or add frames (`SECURITY.md:23-26`).

Read: the road between two podssh ends carries SSH, `cp`, `pipe` and chat (`docs/design.md:334-340`);
for chat, the operator chose the roads, end to end encrypted, after M6 (`docs/design.md:356-358`).
The resumable layer of M6 runs under SSH (`docs/design.md:186-198`).

Read in the report (GitHub #18, not verified here): warren uses `Noise_IK_25519_ChaChaPoly_BLAKE2s`
so that the relay cannot read a stream (`willykeenan/warren:src/noise.rs`).

Read: the library crates must build with no C compiler (`AGENTS.md:188-190`, `scripts/gate.sh:61`).

## Approach

1. A Noise IK channel for each reverse session, in crates/podssh-relay/src/reverse/e2e.rs. The
   operator knows the node's static key from the pair file or a pin (T-087); the node's allowlist
   lists the operators' keys.
2. Library: the `snow` crate with its pure-Rust resolver only. Check it under `CC=/nonexistent` in
   the gate before it is chosen; else RustCrypto parts with the IK handshake written here, and the
   test vectors of the Noise specification.
3. Messages: each Noise message at most 65535 bytes, with a length prefix, inside the session's
   bytes. The relay's frames on the operator leg stay bare (`docs/reverse.md:32`).
4. Layers with M6 (T-151, T-153): either Noise for each connection under the resumable layer (a
   resume makes a new handshake and proves the resume secret inside it), or above it. Decide in
   T-151, and record the choice in `docs/design.md` (section 5).
5. On by default between two podssh ends. A flag that turns it off names the risk. SSH inside it is
   encrypted twice; the relay, not the CPU, limits the throughput.
6. Pitfalls: a nonce never repeats (a reconnection is a new handshake). End the session on each
   decryption error; never skip a frame, because the relay can drop or add frames.

## Decision

Recommendation: Noise IK between two podssh ends, on by default, because one layer then covers raw
TCP, `pipe`, `cp` and chat, with the keys of T-087. The alternative, "only SSH crosses the reverse
road" (each payload as a channel of `podssh serve`, T-109), lost: it needs an SSH server at the far
end for each use, and a raw `podssh node` TARGET (M4) stays readable by the relay until M5.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,e2e --test e2e
sh scripts/dev.sh check
cargo test -p podssh-relay --features pair,e2e --test reverse_live -- --ignored e2e_through_the_live_relay
```

Offline: the IK handshake against the test vectors of the Noise specification; a flipped bit, a
dropped frame, a repeated frame and a frame out of order each end the session with an error; a wrong
node key fails the handshake. A stand-in relay that records the payloads it carries finds no
plaintext marker. Plant: skip the tag check; the flipped-bit test must fail. The gate shows no C;
the live test runs one session through the real relay.

# T-089: A node offers several named targets, each with its own grant

**Source:** GitHub #19 (report on syq) and GitHub #18 (report on warren); read in the reports, not
verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

`podssh node NAME TARGET` offers one TARGET. A host that offers SSH and a web service needs two
pairs, two node sockets and two operator files. Each operator of a pair reaches its whole TARGET.

## Premise

Read in the reports (not verified here): syq has named routes with restricted grants
(`greaber/syq:src/conn/reverse_tcp.rs`); in warren, the destination decides what is reachable, and
only `share PORT` opens a port.

Read: one name holds one node socket
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:152-154`); tokens are scoped to a name
and a role (`:128-129`). The operator leg has no framing, so a route cannot travel in the relay's
frames (`docs/reverse.md:32`). Data needs `ready` first (`:180` of the contract), and `ready` comes
after the local side accepts (`docs/reverse.md:16`). So a route that the operator names reaches the
node only after `ready`.

## Approach

1. Routes on the command line: `podssh node NAME ROUTE=TARGET...`, where ROUTE has the form of a
   node name (T-076). The operator writes `podssh operator NAME/ROUTE` or
   `podssh ssh node://NAME/ROUTE`.
2. Before T-087 and T-088: one pair for each route. The relay then enforces each grant by its token,
   and `ready` still follows the local accept. The cost is one node socket for each route.
3. With T-088: one pair, one socket. The operator names the route in the first message of the Noise
   handshake. The node checks the grant of that operator's key (T-087), dials the TARGET, and answers
   in the handshake. `ready` then means "the node's podssh layer is up"; record that change in
   `docs/reverse.md:16`.
4. Grants: a file on the node, one line for each fingerprint and its routes; deny by default.

## Decision

Recommendation: one pair for each route until T-088 exists, then routes inside the handshake. The
first keeps the measured rule "ready after accept" and needs no protocol of podssh's own. The
alternative, a route header after `ready` before T-088, lost: it changes the meaning of `ready` and
adds a framing with no authentication of the operator.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,e2e --test routes
cargo test -p podssh-cli --test node -- routes
```

Offline: two routes reach their own TARGET; an unknown route, and a route that the operator's key
may not use, end with a reason and no dial of a TARGET; a change of the grant file applies to the
next session. Plant: ignore the grant; the refusal test must fail.

# T-090: Find a node by name with no payload leak

**Source:** GitHub #18 (reports on GPU-Share and iroh-ssh) and GitHub #23 (report on cubic); read in
the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A pair's name is random and lasts 72 h at most; each new pair has a new name. An operator who wants
"my lab node" needs a new file after each new pair. A directory of nodes would help, but a directory
shows who has nodes, when and where, and it must never carry payload or tokens.

## Premise

Read: pairs expire within 72 h (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:133-134`);
`/v1/status/<name>` gives presence with a token (`:126-127`); the relay hibernates idle sockets
(`:240-241`).

Read in the reports (not verified here): GPU-Share publishes a registry of metadata only, never
workloads (`arjun988/GPU-Share`); iroh-ssh has an open request for local discovery with mDNS (issue
56 of `rustonbsd/iroh-ssh`); cubic names and lists remote state (`cubic-vm/cubic:docs/howto/snapshots.rst`).

Read: the measured sandbox refuses UDP (`docs/target-environment.md:23`), so mDNS cannot work there,
and podssh must probe before it uses UDP (`AGENTS.md:175-176`).

## Approach

1. Local names first: the operator keeps labels in the private store (T-083), and
   `podssh relay status LABEL` shows presence. No directory on the network.
2. A new pair (T-079's hook) makes a new operator's part; deliver it with T-086 or a file. With
   T-087, the operator pins the node's key, not the name, so a new pair from the same key needs no
   new trust step.
3. A directory only from the relay's operator (the relay is a separate project, ruled on 2026-10-08):
   a lookup by the node key's fingerprint
   that gives only the current pair name. Never tokens or payload; a limit on the rate; written only
   with a proof of the node key.
4. mDNS: only where a probe shows that multicast UDP works; off by default; it announces a
   fingerprint, never a token or a payload.
5. State in `docs/reverse.md` what each method shows to whom; the relay sees names and times in
   each case.

## Decision

Recommendation: local labels and key pinning (steps 1 and 2), because they show nothing new to
anyone and need no change of the relay. The alternative, a directory in the relay, lost for now: it
needs the relay's operator, and it gives the relay a list of all nodes. mDNS lost as a default:
the target sandbox refuses UDP.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node -- labels_survive_a_new_pair
cargo test -p podssh-relay --features pair,identity --test identity -- a_new_pair_from_a_pinned_key_needs_no_new_trust
```

Offline: a label maps to the newest pair; a new pair with the same node key updates the operator's
label with no prompt; a new pair with another key is refused (T-087); no file, output or log holds a
token outside the private store. Plant: accept a new key with a new pair; the second test must fail.

# T-226: Pairing grants that are signed and used once, not bearer tokens that can be replayed (GitHub #35)

**Source:** GitHub #35 (2026-10-08) and the reporter's own comment; each cited line checked here on `3ee70dc`.
Not measured: no pairing ran.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** blocked

## Problem

Each credential of the relay is a bearer token: whoever holds it can use it, as often as they like, until it
expires; the three tokens of a pair too. Nothing binds a token to a peer, limits it to one use, or finds a
replay. A token that leaks from a log, a shell history or a copied file stays valid for up to 72 h.

## Premise

Read: `POST /v1/mint` gives `{token, expires, scope}` as `ephm1.<expiry-ms>.forward.<mac>`, checked at each
upgrade, 72 h at most (`docs/relay.md:96-100`); `POST /v1/pair` gives the three tokens of a pair, 72 h at most
(`docs/relay.md:197-198`). The contract scopes reverse tokens to a name and a role, and states no single use and
no binding to a peer (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:128-129`). A new mint secret
ends each token at once (`docs/relay.md:188-190`). A text frame from the operator closes its socket with
`1003`, and the operator leg carries no framing (`docs/relay.md:205-208`, `docs/reverse.md:32`).

Measured: `grep -rni sshsig crates scripts docs Cargo.toml` finds nothing (exit 1). The wider `sign(` hits are
tests of primitives (`crates/podssh-ws/tests/crypto_vectors.rs:138-175`,
`crates/podssh-ws/tests/signatures.rs:29-192`); the comment's `crypto_vectors.rs:192` is not one. Read: the
issue's "rule 8" is rule 6 (`docs/architecture.md:114-116`), and its "section 2" sentence about an allowlist of
keys is in section 7 (`docs/design.md:297-298`). Read in the report (not verified here): syq signs a grant in a
fixed namespace and redeems it at most once with `flock`, `O_EXCL`, `linkat` and `fsync` (lines 55 and
1416-1492 of `greaber/syq:src/delegation.rs`). The reporter's correction: a signed grant leaks as a token does
(lines 11-12); signing buys scope, single use and non-repudiation, not safety after a leak.

Read, what a leaked token gives today. `connect_token`: sessions to the node; an SSH server's own
authentication still stands, but a raw TCP TARGET (T-083) has no other gate. `node_token`: an impersonated node
while the real one is away (one socket for each name, and a new node gets the new sessions: `:152-156` of the
contract); for SSH, the operator's host-key check finds it (`SECURITY.md:28-32`). `stop_token`: a denial of
service; the node, its sessions and the pair end (`docs/relay.md:209-212`).

## Approach

The operator ruled on 2026-10-08: not in M4; M4 keeps the relay's tokens, the trust is end to end (T-087,
T-107), and the relay stays a separate project (`docs/decisions.md`). The two shapes, for the relay's operator:
1. On the relay: an endpoint in place of `POST /v1/pair` that returns a signed grant naming the node, the
   principals that may use it (key fingerprints, T-087), an expiry and a nonce. The relay records the nonce as
   spent and refuses a second use. podssh caches the grant and sends it in a header or a 0600 file, never in
   a URL (`docs/relay.md:101-103`, `docs/architecture.md:114-116`).
2. On the client: keep the pair's tokens, and add a signed grant inside the operator leg, which the relay has
   authenticated. A text frame closes that leg with `1003`, so the grant needs a typed binary header at the
   start of the session: a change of the framing in `crates/podssh-transport/src/framing/legs.rs:60-76`. The
   node checks the grant before it dials the TARGET, so the dial moves after `ready` (`docs/reverse.md:16`):
   the seam of T-088 and T-089. Spent nonces are create-new private files
   (`crates/podssh-relay/src/cache.rs:222-236`).
3. Both shapes: an SSHSIG signature in a fixed podssh namespace, which `ssh-keygen -Y verify` can check
   (T-020), with the keys of T-087, in pure Rust (`AGENTS.md:188-190`).
4. Relations: T-078 makes the pair that a grant protects; T-086 can deliver a grant in place of the
   `connect_token`; T-087 gives the keys that a grant names.

## Decision

Recommendation: the relay's shape, after M4 and by the relay's operator, as the ruling leaves it, because only
the relay can make a token single use for each client. The alternative, the client's shape, lost: the relay
still accepts a replayed `connect_token`, so that grant protects only the TARGET, which the allowlist of T-087
already protects, at the cost of a framing on a leg that the contract keeps bare.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,grant --test grant
cargo test -p podssh-relay --features pair,grant --test grant_live -- --ignored
```

Offline: a grant verifies once; a second use of its nonce fails; a grant for another node or principal, or
after its expiry, fails; a grant in a URL is refused before a request exists. Plant: skip the spent-nonce
check; the replay test must fail. Live, the relay's shape only: a second use of one grant gets its refusal.

## Blocker

The relay's operator: an endpoint that gives a signed grant, used once. The operator ruled on 2026-10-08 that
M4 keeps the relay's tokens (`docs/decisions.md`).
