This file holds milestone M4, the reverse road (`docs/ROADMAP.md:148-173`): pairing, the node and
operator runners and a blocking facade in `podssh-relay`, the move of the codecs, the commands
`podssh node`, `podssh operator` and `podssh ssh NODE`, and the exit measurement. It also holds the
backlog work on that road: pairing by a code, node identity, end-to-end encryption, routes,
finding a node, and signed grants. M4 starts after M3 is complete (`docs/ROADMAP.md:7-9`); in M4,
the defects of `TODO/transport.md` come first, in the work order of `TODO/PROGRESS.md`. The rules
for the node and the operator are in `docs/reverse.md`; the wire format is in `docs/relay.md:202-238`
and in the pinned contract (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:123-193`).

# T-078: Pairing in `podssh-relay`: pair, stop and status

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-152`); `docs/design.md` lines 89-100 at `0d92eef` (`pair`, cargo feature
`pair`); `docs/relay.md:202-238`. Read here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A node needs a pair name and a `node_token`; its operator needs the `connect_token`. podssh cannot get
them: no code calls `POST /v1/pair`, `POST /v1/stop/<name>` or `GET /v1/status/<name>`. podbox pairs
through `curl` (`docs/design.md:124-125`), which a sandbox may not have.

## Premise

Read: `POST /v1/pair` with `{}` returns `{name, node_token, connect_token, stop_token, expires}`, within
72 h; `/v1/status/<name>` gives presence with a token; `POST /v1/stop/<name>` stops the node and its
sessions; tokens go in `X-Relay-Token` (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:125-137`).
Pair creation shares the brake of 120 attempts per minute per address with mint (`:235-238` there).
These endpoints are on the "control host only" (`:23-24`, `:130`); no pool host was measured for them.

The lines of the files that this entry changed are those of `3632dcb`.

Read: `/v1/pair` can answer `409` (pair again), and a new mint secret ends each token at once
(`docs/relay.md` lines 188-190). `/v1/stop` once answered `{"stopped": false}` and still destroyed
the credentials (lines 209-212 there); then the other tokens get `403 reverse: forbidden`
(`docs/reverse.md` lines 51-52). Which token `/v1/status` accepts is not known (line 53 there); a
local copy of podbox at `5bd8cb0` says `connect_token` only
(`Azathothas/podbox:crates/podbox-ssh/src/mux.rs`).

Read: `podssh-relay` has no pairing code (`crates/podssh-relay/src/lib.rs` lines 14-21).
`https_post_json` sends fixed headers, and `https_request`, which takes headers, is private
(`crates/podssh-ws/src/client.rs` lines 261-313). The private files of the token cache can hold a
pair (`crates/podssh-relay/src/cache.rs` lines 126-153 and 221-240).

## Approach

1. Add crates/podssh-relay/src/pair.rs behind the feature `pair` (`docs/design.md` line 93 at `0d92eef`). Declare it in
   `crates/podssh-relay/Cargo.toml` (lines 10-21 at `3632dcb`), enable it in `podssh-cli`, and build it
   in the library step of the gate (`scripts/gate.sh` line 61 at `3632dcb`), so the no-C check covers
   it.
2. `pair::create` returns a `Pair`: relay host, name, the three tokens, expiry. Keep each token in
   `Zeroizing` with a redacted `Debug`, as `token::Token` does (`crates/podssh-relay/src/token.rs:27-53`).
   Check the name with T-076, and each token with `cache::valid_token`
   (`crates/podssh-relay/src/cache.rs` lines 52-56 at `3632dcb`). Never quote a 2xx body
   (`crates/podssh-relay/src/token.rs:167`).
3. Answers: `409`, pair again once; `429`, report `Retry-After`; `503`, stop. Refuse a pair with less
   than 10 min left, as the token cache does (`cache.rs` lines 15-16 at `3632dcb`).
4. `pair::stop` sends `stop_token` to `/v1/stop/<name>`, then deletes the local copy whatever the
   answer. Never print the `stop_token` (`docs/reverse.md` lines 48-49 at `3632dcb`).
5. `pair::status` tries `connect_token`, then `node_token`; record the one that works in
   `docs/reverse.md` (line 53 at `3632dcb`).
6. Add to `podssh-ws` a public request with one token header (`crates/podssh-ws/src/client.rs` lines
   291-313 at `3632dcb`). Invariant: the header value never reaches an error.
7. Store a pair as one private file (`cache::store_file`) under the local label of T-083. The
   operator's part (relay host, name, `connect_token`, expiry) goes to a file that the user names
   (create-new, mode 0600), never to stdout.
8. Use the control host only (`tcp.ssh.relay.ajam.dev`, or one host that the user names). No failover
   to pool hosts until a measurement shows that they serve `/v1/*`.
9. In the same commit: `docs/relay.md` (lines 192-214 at `3632dcb`), `docs/reverse.md` (lines 46-53 at
   `3632dcb`), and the FILES section of the manual (`crates/podssh-cli/src/man/facts.rs:115`).

## Decision

2026-10-09:

1. `pair::status` sends `connect_token` only: measured, the relay answers `node_token` and
   `stop_token` with `403`. Lost: step 5's try of both, a second request that the relay refuses.
2. `pair::revoke(label)` stops the pair and deletes the local copy whatever the relay answered,
   as step 4 says; when the relay could not be reached it answered nothing, and the copy stays,
   because its `stop_token` is the only way to stop the pair before it expires. `pair::stop`
   alone deletes nothing: it takes a pair, not a label.
3. A pair is kept as `pair-<label>.json` among the private files of the cache, and a label must be
   a name that T-076 accepts, so it cannot leave the directory. The operator's file is created new
   with `cache::create_new_private` (mode 0600, no symbolic link followed), which became public.
4. The FILES section is made in `crates/podssh-cli/src/man/data.rs`; it names the file of a pair
   with `pair::file_name`, and says that no command writes one yet.

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

## Done

2026-10-09, in the commit "Pairs of the reverse road, made, asked about and stopped".

- Measured first, on the live relay, with a client of the Python standard library that printed
  no token: `/v1/pair` answered 200 with `{name, node_token, connect_token, stop_token, expires}`
  (each token 64 characters of `[0-9a-z]`; the name `p-` and 32 hex characters; `expires` in ms,
  72 h ahead); `/v1/status/<name>` answered 200 `{"online":false,"sessions":0}` to
  `connect_token` and `403 reverse: forbidden` to `node_token`, `stop_token` and no token;
  `/v1/stop/<name>` answered 200 `{"stopped":false,"sessions":0}`, then each token got 403, and a
  second stop 403.
- `crates/podssh-relay/src/pair.rs` (new, feature `pair`): `Pair` (the tokens in `Zeroizing`, a
  `Debug` that shows none), `parse`, `create` (`409` once more; `429` with `Retry-After`; `503`;
  under 10 minutes left refused), `status`, `stop`, `revoke(label)`, `store`, `load`, `remove`
  and `write_operator_file`. `podssh-ws`: `client::https_with_token`. `cache`: `remove_named_from`;
  `create_new_private` is public.
- The feature is on in `podssh-cli`, and the gate's library steps build and test it with no C
  compiler. `docs/relay.md`, `docs/reverse.md` and the manual's FILES say so.
- Prove: `cargo test -p podssh-relay --features pair --test pair`: 7 passed (the answer read;
  bad names, bad tokens and other bodies refused with no token in the error; under 10 minutes
  refused; no token in `Debug`; the private file under a label, mode 0600 on Unix, and a bad label
  refused; the operator's file new, with `connect_token` only). `cargo test -p podssh-relay
  --features pair --test pair_live -- --ignored`: 1 passed, with no token printed (made, status
  `online: false`, stopped, then status and a second stop `Forbidden`). `CC=/nonexistent
  CXX=/nonexistent cargo test -p podssh-relay --features pair`: 34 passed, 0 failed, 3
  ignored. `cargo test --no-fail-fast`: 817 passed, 0 failed, 8 ignored. The gate of the
  commit runs in CI.
- Plant: a token in the `Debug` of `Pair`: `no_token_is_in_debug_or_in_an_error` failed.

# T-079: The node runner

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-158`); `docs/design.md` lines 94-97 at `0d92eef`; `docs/reverse.md:8-36`; GitHub #19
(a design input). Read here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

A host whose only egress is the relay cannot offer a service: podssh has no node. A node keeps one WebSocket to
`/v1/node/<name>`, answers each `open` with `ready` or `reject`, and carries many sessions on it by their
32-character ids. One mistake closes the socket and ends every session on it (`docs/reverse.md:10-14`).

## Premise

Read: the rules (`docs/reverse.md` lines 10-28 at `9811e0d`): one writer, with the id and the payload in one frame; stop the writes
of a session at its `close`; never close the socket for one session; `ready` only after the local side
accepts; route by id after a check of the hex; exit on `409`; do not depend on `hello`; no keepalives come on
reverse sockets; connect again with a jitter.

Read: the codecs exist, with tests: node frames and chunks (crates/podssh-transport/src/framing/legs.rs lines 26-58 at `e8bbd4d`,
lines 113-123), control messages (crates/podssh-transport/src/control.rs lines 155-254 at `e8bbd4d`), a limit of 16 sessions when
no `hello` comes (crates/podssh-transport/src/control.rs lines 111-137 at `e8bbd4d`), and the close table
(crates/podssh-transport/src/closes.rs lines 60-88 at `e8bbd4d`, lines 156-229). They carry the defects of T-071, T-072, T-073,
T-075 and T-076 (each repaired 2026-10-09).

Read: `RelaySession` has text, binary, Ping and Close writes and a liveness watcher
(`crates/podssh-ws/src/session.rs:81-174`); `podssh_relay::open::backoff` has a jitter
(`crates/podssh-relay/src/open.rs:262-276`). Not measured: whether the relay answers a Ping on a reverse socket
(`docs/relay.md:76-78` is the forward path), and its idle cut there (`docs/relay.md` lines 191-192 at `cd75137`, T-061). A node
that connects again ends each operator session on it (`docs/design.md:191-194`).

Read in a local copy of podbox at `5bd8cb0` (`docs/design.md:66` names `452d792`): `run_node` owns the socket in
one thread, drops late bytes of a closed id, and dials again with a backoff
(`Azathothas/podbox:crates/podbox-ssh/src/mux.rs`). It also needs `hello`, accepts upper-case ids, and has no
`409` rule; do not port these (`docs/reverse.md` lines 17-21 at `9811e0d`,
`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:174`). GitHub #19 cites syq's receive mode, one
persistent connection that the far side opens (`greaber/syq:src/conn/reverse_tcp.rs`; read in the report, not
verified here).

## Approach

1. crates/podssh-relay/src/reverse/node.rs: `node::run(config, handler)`; `handler.open(id)` gives a byte stream
   or a reason to reject. It uses the codecs of `podssh-transport` until T-082. Invariant: no protocol above
   bytes (`docs/architecture.md:98-100`).
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
   (`crates/podssh-relay/src/open.rs:231`), and a quiet socket would reconnect.
6. Close actions, by code and reason (`docs/reverse.md:103-105`): `409`, exit, no retry;
   `1001 operator stopped reverse relay`, exit and delete the pair; `1001 pair expired`, or a `403` after the
   stored expiry, a re-pair hook that is off by default; `1003` and `1009`, exit with the reason, never a loop;
   any other close, connect again with `open::backoff`.
7. A clean stop (SIGTERM or Ctrl-C): `close {id}` with a reason for each session, a Close `1000`, then exit 0.
8. A TCP handler dials with `podssh_ws::dial::dial` (`crates/podssh-ws/src/dial.rs:189`), which keeps loopback
   off the proxy (`crates/podssh-ws/src/dial.rs:138-142`).
9. Record each rule in `docs/reverse.md`, and each measurement in `docs/STATUS.md`.
10. The runner takes a `RelaySession` over any stream, not only TLS, so that the tests of podbox
    run it over a plain `ws://` session to the loopback (`podssh_ws::plain`, T-068).

## Decision

2026-10-09:

1. The runner uses `RelaySession` itself, not the `Leg` of `podssh-transport`: a reader and a
   writer run at once, and a `Leg` takes `&mut` for each. The writer owns a
   `podssh_transport::sessions::Sessions`, the state that a `Leg` keeps (its mutators became
   public), so the state has one owner. Lost: the `Leg`, behind a lock that would serialise the
   reads and the writes.
2. The data for each session goes to its local side through a bounded channel (32 frames): a slow
   local side slows the reader of the socket, and so the other sessions. Lost: an unbounded queue,
   which a fast relay could grow without end; the shared budget of T-074 comes later.
3. Liveness: the relay answers a Ping on a node socket (measured), so the node pings every 10 s and
   drops the socket after 3 silent intervals, and has no idle read limit.
4. The re-pair hook is an async function in `NodeConfig`, `None` by default; with none, an expired
   pair ends the node (`Exit::PairExpired`).
5. The live test opens its two sessions with a minimal operator over `podssh_ws::connect`; the
   operator runner is T-080.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_node
cargo test -p podssh-relay --features pair --test reverse_live -- --ignored node_serves_two_sessions_at_once
```

Offline: the runner runs over an in-memory stream, against a scripted relay that writes real WebSocket frames
(`RelaySession::new` takes any stream: `crates/podssh-ws/src/session.rs:65-69`). The cases: two mixed sessions
with exact bytes; late bytes after `close` dropped, the socket kept; no data before `ready`; one exit on `409`;
the hook on `1001 pair expired`; exit and a deleted pair on `1001 operator stopped reverse relay`. Plant: send
`ready` before the handler returns; that test must fail. Live: pair (T-078), run an echo node, open two
sessions at once with T-080, compare the digests of 1 MiB each way, and stop the pair.

## Done

2026-10-09, in the commit "The node of the reverse road".

- Measured first, on the live relay, with `python scripts/capture-reverse.py` (new; the Python
  standard library, no token printed): the node's socket gets
  `{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}` first; a Ping on it is
  answered with a Pong of the same payload; an operator's connection gives the node
  `{"type":"open","id":"<32 hex>"}`; the node's `ready` reaches the operator as
  `{"type":"ready","id":"<the same id>"}`; data comes to the node as the id and the payload in
  one frame, and goes to the operator as the payload alone; the operator's Close gives the node
  `{"type":"close","id":"<the id>"}`. One run's stop timed out after 10 s (the next took under
  3 s); its pair, with no node, lives until it expires.
- `crates/podssh-relay/src/reverse/` (new, feature `pair`, which now brings `podssh-transport`):
  `serve` (one socket: the writer, the reader that routes by id, an opener per `open`), `run`
  (connect, serve, and the action for each end: `409`, `1001` stopped or expired, `1003`,
  `1009`, else reconnect with `open::backoff`), `after_close`, the `Handler` trait and
  `TcpHandler`, which dials with `podssh_ws::dial::dial`.
- `docs/reverse.md` (rules 7 and 8 measured, and how the node keeps the rules), `docs/relay.md`
  and `docs/development.md` say so.
- Prove: `cargo test -p podssh-relay --features pair --test reverse_node`: 6 passed (two sessions
  with exact bytes both ways, then a stop that closes each session and the socket; late bytes of
  a closed session dropped while the other goes on; `ready` only after the handler returned, and
  before data; a refusal and a session over a `hello` limit of 1 get `reject`; a Close of the
  relay ends the socket with its code and reason; the action for each close).
  `cargo test -p podssh-relay --features pair --test reverse_live -- --ignored`: 1 passed (two
  sessions at once, 1 MiB each way through an echo node, came back whole; the node and the pair
  stopped). `CC=/nonexistent CXX=/nonexistent cargo test -p podssh-relay --features pair`:
  40 passed. `cargo test --no-fail-fast`: 823 passed, 0 failed, 9 ignored.
- Plants, each restored: `ready` queued before the handler returns: 4 tests failed,
  `ready_waits_for_the_handler_and_comes_before_data` among them ("nothing before the handler
  returns"); the writer without its check of the session's state: the late-bytes test failed.

# T-080: The operator runner

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-158`); `docs/design.md` lines 94-97 at `0d92eef`; `docs/reverse.md:63-105`.
Read here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

An operator outside the cage cannot reach a node: podssh has no operator leg. The operator connects
to `/v1/connect/<name>`, waits for the text `ready`, then moves raw bytes with no framing. Bytes sent
before `ready` end the session, and a `reject` must reach the user with the node's full reason.

## Premise

Read: the rules (`docs/reverse.md` lines 50-64 at `c3a3ca9`). Never add or remove the 32-byte id. A `reject` text
frame carries the full reason before the close, whose reason is cut to 123 bytes. Wait longer than
the relay's 15 s for `ready`. A session that never got `ready` never exits 0. After `ready`, `1003`
and `1009` exit with a code that is not zero. Use the code and the reason.

Read: data before `ready` closes the operator with `1008 wait for ready`, a text frame from the
operator closes it with `1003`, a frame carries at most 65536 bytes, and a session at most 64 MiB
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:141-148`, `:178-184`, `:190`, `:192`).
The relay sends no keepalives on reverse sockets (`docs/reverse.md:24-32`).

Read: the codecs: `encode_operator_frame` and `chunk_for_bare`
(crates/podssh-transport/src/framing/legs.rs lines 60-76 at `e8bbd4d`, lines 125-133), and `parse_operator_control`
(crates/podssh-transport/src/control.rs lines 223-230 at `e8bbd4d`). `podssh proxy` has the pump to follow: stdin and
stdout, liveness, the close reason (`crates/podssh-cli/src/proxy.rs:183-281`).

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
   the code and the reason (`docs/reverse.md:100-105`).
6. End of input: send a Close `1000`, and wait up to 10 s for the relay's answer, so the last bytes
   arrive.
7. Liveness as in T-079: `watch_liveness` only if the relay answers a Ping on this leg; no idle read
   limit until then (the relay sends no keepalives here).

## Decision

2026-10-09:

1. A node's `reject` and `close` keep the whole reason, cut only when the frame would pass the 4 KiB
   control cap. The codec of `podssh-transport` cut it to 123 bytes, the bound that spec line 192 sets
   for the relay's own Close only; the same line says that the `reject` text frame keeps the full
   reason. With the cut, no operator could get more than 123 bytes. Lost: the cut at the node;
   `truncate_reason` stays, for display.
2. The socket and the input are each read by their own task, into a channel, and one loop selects on
   the channels, the deadline and the liveness. Lost: a `select!` on the reads themselves:
   `RelaySession::read_frame` writes the answer to a Ping or a Close before it returns, so a read that
   another branch cancels can lose the frame that it took.
3. Liveness: the relay answers a Ping on the operator's socket, before `ready` too (measured), so the
   operator pings as the node does (every 10 s, 3 silent intervals) and has no idle read limit. Lost:
   an idle read limit, which ends a quiet session, as no keepalive comes on a reverse socket.
4. A broken socket, a read error or a lost liveness after `ready` is `Ended` with `1006`, the code for
   a connection that ended with no Close (RFC 6455, section 7.1.5), and the error's text. Lost: a
   fourth outcome, which each caller would have to turn into an exit code.
5. `PairError::NotIssued` keeps what the relay said (a `503` has no token): a live run got a `503`
   from `/v1/pair` once, and the next request got a pair. Lost: the bare `503`, which said nothing
   of the cause.
6. The live test of T-079 opens its two sessions with `operator::run`, as its Prove asked; the
   minimal operator over `podssh_ws::connect` is gone.

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

## Done

2026-10-09, in the commit "The operator of the reverse road".

- `crates/podssh-relay/src/reverse/operator.rs` (new, feature `pair`): `operator::run` connects to
  `/v1/connect/<name>` with the connect token, and `operator::exchange` carries a byte stream over a
  `RelaySession` on any stream. Before `ready` it keeps up to 1 MiB of input (`QUEUE_BEFORE_READY`)
  and sends nothing, for 20 s at most; a `reject` keeps its whole reason, and the Close after it gives
  the code. After `ready` it sends what it kept, then copies both ways in frames of at most 64 KiB
  with no id (`chunk_for_bare`); it ignores an empty frame, and a text `close` keeps its reason. At
  the end of its input it sends a Close `1000` and waits 10 s for the answer. The outcome is
  `NeverReady { code, reason }`, `Ended { code, reason }` or `LocalEnd`; `is_success` holds only for
  `Ended` with `1000`, and for `LocalEnd`.
- crates/podssh-transport/src/control.rs at `e8bbd4d`: `reject` and `close` keep the whole reason (Decision 1);
  crates/podssh-transport/tests/framing.rs at `e8bbd4d` asserts 200 bytes whole and a cut on a character
  boundary for a reason over 4 KiB.
- Measured with `python scripts/capture-reverse.py`, which now pings the operator's socket too: the
  relay answers it, before `ready` as well. Live: a node's reason of 200 bytes reached the operator
  whole, with a Close `1011`.
- `docs/reverse.md` (how the operator keeps the rules, and both measurements), `docs/relay.md` and
  `docs/development.md` (the live tests of the reverse road) say so.
- Prove: `cargo test -p podssh-relay --features pair --test reverse_operator`: 7 passed (input
  before `ready` kept, with no data frame before `ready`, then sent in order; `1008`, `1003` and
  `1009` after `ready`, each a failure with its code and reason; a `reject` reason of 200 bytes whole
  in the outcome; no `ready` in time, a failure and never a success; more than 1 MiB before
  `ready`, a failure; a text `close` keeps its reason; the end of the input sends a Close and still
  gets the last bytes). `cargo test -p podssh-relay --features pair --test reverse_live --
  --ignored`: 2 passed (two sessions at once through an echo node, 1 MiB each way, came back whole,
  both `LocalEnd`; `NeverReady { code: Some(1011), .. }` with all 200 bytes of the reason).
  `CC=/nonexistent CXX=/nonexistent cargo test -p podssh-relay --features pair`: 47 passed.
  `cargo test --no-fail-fast`: 830 passed, 0 failed, 10 ignored.
- Plants, each restored: the kept input sent before `ready`: 2 tests failed,
  `input_before_ready_is_kept_then_sent_in_order` among them ("no data frame before ready"); the
  cut of 123 bytes put back in `reject`: the framing test failed ("the whole reason").

# T-081: A blocking facade of `podssh-relay`, for podbox

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-152`, `:177-178`); `docs/design.md:112-125`. Read here
on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podbox is synchronous and has no async runtime, so it cannot call `podssh-relay`, whose functions
are `async` on tokio. Until it can, podbox keeps its own WebSocket, TLS and dial code. That code has
no HTTPS proxy support, so its node cannot leave a sandbox whose only egress is a CONNECT proxy.

## Premise

Read: podbox's reverse legs work live; it has no HTTPS proxy support; it is synchronous; it builds
`ring`; its MSRV is 1.85; it is made for TLS-intercepting proxies (`docs/design.md:70-80`). The plan
is a synchronous facade that owns a current-thread runtime (`docs/design.md:112-113`); then podbox
pins `podssh-relay` by git revision and removes its own `ws.rs`, `tls.rs`, direct dial and pairing
through `curl` (`docs/design.md:124-125`).

Read: `podssh-relay` declares the workspace minimum, Rust 1.88 (`crates/podssh-relay/Cargo.toml:5-6`,
`Cargo.toml` lines 45-48 at `0d92eef`), above podbox's 1.85. `podssh proxy` already runs async code from sync code with
a current-thread runtime and `shutdown_background` (`crates/podssh-cli/src/proxy.rs:82-95`).

Read: podbox keeps `ring` and TLS 1.2 through a `rustls::ClientConfig` that it supplies
(`docs/design.md:117-121`); that is T-066, not this entry.

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
7. Document the facade in `docs/design.md` (lines 89-110 at `0d92eef`) and in the crate's header
   (`crates/podssh-relay/src/lib.rs:1-18`); add the feature to the gate (`scripts/gate.sh:96`).

## Decision

2026-10-09:

1. The client is `blocking::Client`, not `Relay`: the crate has `relay::Relay`, a relay host, at its
   root already, and two types of one name would need an alias at each use. Lost: the name of step 1.
2. Two threads carry each session, not one: a blocking reader and a blocking writer each wait, and
   one thread cannot wait on both. One reads the reader into a pipe, one writes what comes out of the
   other pipe; at most 128 for the relay's 64 sessions. The handler opens each session on a thread of
   its own, with no runtime, so it may block, and may call the client. Lost: one thread per session
   that polls with read timeouts, as podbox does, which needs a timeout from each reader and adds
   latency.
3. `run_node` takes `&mut Pair`: the caller keeps its pair, and gets back the one that the node ended
   with (a new one after a re-pair), to stop it. The async `run` takes `&mut NodeConfig` for this.
   Lost: a pair taken by value, which a refused call (inside a runtime) would have dropped with its
   stop token.
4. The offline tests reach the runners over plain `ws://`: `NodeConfig` and `OperatorConfig` have a
   `wire`, `Wire::PlainLoopback` under the feature `plain-ws`, so the run loops (the reconnection,
   the close actions, the re-pair) are tested, not only `serve` and `exchange`. They are in their own
   file, `--features blocking,plain-ws --test blocking_plain`; `--test blocking` has the tests with
   no network. Lost: a facade call that takes a connected session, which would put a tokio stream
   type in the API.
5. A forward session is a `Forward` stream, with `Read` and `Write` on `&Forward` too, for two
   threads at once, as on `&TcpStream`. A Close `1000` reads as the end; another code is an error of
   the kind `ConnectionAborted` that holds `Closed { code, reason }`. Measured: the relay keeps the
   target's bytes coming after the client's Close, and closes when the target is idle 15 s; so
   `shutdown_write` sends the Close and the reads go on, and `close` sends it with no wait. Lost: a
   `close` that waits for the answer, which waited 10 s in vain on GitHub's server.
6. A call is refused when `Handle::try_current` finds a runtime, also on a thread of
   `spawn_blocking`, where a call would work: tokio does not tell the two apart, and refusing is the
   safe side. The runtime is shut with `shutdown_background`, which does not panic inside an async
   context, so a client may be made and dropped anywhere.
7. The library crates and podssh-todo declare Rust 1.85: they pass `cargo check --locked
   --all-targets` on 1.85.0 and 1.85.1, and no locked dependency of theirs declares a newer minimum.
   The gate installs the version that `Cargo.toml` declares and checks them on it; a version that it
   cannot read fails the gate, as `cargo +` would run the default toolchain. Lost: 1.88, which podbox
   would have had to follow for nothing, as cargo refuses a dependency that declares a newer minimum
   than the toolchain. T-217 keeps the checks of 1.89 and 1.92.
8. Defects found here, and repaired: a node that cannot connect as it is set up (a plain host that
   is not the loopback, a bad proxy setting) connected again for ever (T-079), and now exits with
   `Exit::Unusable`; an operator whose input had ended took any Close of the relay as the answer to
   its own, `1011` too, as a success (T-080); `exchange` left the write side of its stream open after
   a failure, so a bridged writer waited for an end; `RelaySession::send_binary` sent data after its
   own Close (RFC 6455, section 5.5.1).

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

## Done

2026-10-09, in the commit "A blocking facade for podbox".

- `crates/podssh-relay/src/blocking/` (new, feature `blocking`, which brings `pair`): `Client` (`new`,
  `pair`, `status`, `stop`, `run_node`, `run_operator`, `open_forward`, and `forward_on_loopback` under
  `plain-ws`), `Config`, `Error`, `Stopper`, `NodeOptions` (a label, the settings, a blocking re-pair
  hook) and `Operator`; `bridge.rs`: `Local` (`new`, `tcp`, `on_finish`), `BlockingHandler` (also
  each closure of its shape) and the two threads of a session; `forward.rs`: `Forward` and `Closed`.
- `crates/podssh-relay/src/reverse/wire.rs` (new): `Wire`. `NodeConfig.wire`, `OperatorConfig.wire`,
  `run(&mut NodeConfig, ..)`, `Exit::Unusable`; `exchange` ends its stream's write side and its
  reading tasks at each end; a Close that crosses the operator's with a code other than `1000` is
  `Ended`. `crates/podssh-ws/src/session.rs`: no data frame after its own Close.
- Measured on the live relay with `python scripts/capture-close.py --client-close` (new): after a
  client's Close on the forward path, GitHub's answer, 800 bytes, came 0.4 s later, and the relay's
  Close `1000 client half-closed, target idle for 15s` 15.4 s later.
- Rust 1.85: `rust-version = "1.85"` in `Cargo.toml`; two steps of `scripts/gate.sh` install it and
  check the library crates and podssh-todo on it; the gate also builds and tests with `blocking`,
  and runs `blocking_plain`. `docs/design.md` (section 3), `docs/reverse.md`, `docs/relay.md` and
  `docs/development.md` say so; T-217 has a Correction.
- Prove: `cargo test -p podssh-relay --features pair,blocking --test blocking`: 5 passed (each call
  refused on a current-thread runtime, a multi-thread one and a thread of `spawn_blocking`, with a
  client made and dropped there, and the caller keeps its pair; the types shared between threads; a
  stop kept; no token in a debug text or an error; a target that the relay cannot take refused
  before a connection). `cargo test -p podssh-relay --features blocking,plain-ws --test
  blocking_plain`: 10 passed, 12 runs in a row (a node: two sessions, a TCP one whose peer reads the
  end at the relay's `close`, then a stop; an operator: its input kept until `ready`, its last bytes
  in the writer before the outcome; a Close `1011` after `ready`; two operator sessions at once on
  one client; a forward stream: an empty frame skipped, `1011` as `Closed`, `1000` as the end,
  `close`, and a half-close that reads on; a stop that came first; a node that cannot connect as set
  up exits; an expired pair replaced by the hook and given back). `cargo test -p podssh-relay
  --features blocking --test blocking_live -- --ignored`: 2 passed (a pair, an echo node, two
  operator sessions at once, 1 MiB each way, came back whole, both `LocalEnd`; GitHub's banner, then
  800 bytes after the half-close, and the relay's Close after 15.3 s); the live tests of T-078,
  T-079 and T-080: 3 passed again. `cargo +1.85.0 check --locked --all-targets` of the library crates
  and podssh-todo: exit 0, and on 1.85.1. `sh scripts/dev.sh check`: each step passed, the new
  ones too (the library crates with `blocking`, `blocking_plain`, Rust 1.85 installed and the check
  on it; interop 103 of 103; the binary 4,200,960 bytes), but the two of the record: the run's copy
  of the tree was made before the citations of this change moved (`TODO/ssh.md` quotes
  `docs/design.md` at a line that moved). They pass after the move, here and in CI.
  `cargo test --no-fail-fast`: 832 passed, 0 failed, 10 ignored.
- Plants, each restored: no `try_current` check: the refusal test panicked ("Cannot start a runtime
  from within a runtime"); no `Exit::Unusable`: the node connected again for ever, and its test
  failed at its bound; no `finish` of a TCP side: the node test failed ("the TCP side read the end of
  the session"); any crossing Close as the answer: the operator test failed (`LocalEnd` for `1011`);
  data after the own Close: `control_frames` ("no data after the Close") and the half-close test ("no
  write after the Close: 4") failed; `Vec::pop_if` (Rust 1.86) in podssh-core: the check on 1.85
  failed with `E0658`.

# T-082: Move the codecs of `podssh-transport` into `podssh-relay`

**Source:** ROADMAP M4 (`docs/ROADMAP.md:153-154`); `docs/design.md` lines 122-123 at `e8bbd4d`; the former defects
page (`git show 3ee70dc:docs/defects.md`), section "podssh-transport". Read here on `3ee70dc`.
**Category:** chore
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The relay protocol lives in two crates. `podssh-relay` opens forward sessions and handles tokens;
`podssh-transport` holds the reverse framing, the control messages and the close table, mostly
unused. Two crates for one protocol drift: they already disagree on the backoff (T-077) and on
`403` and `503` (T-075, repaired 2026-10-09).

## Premise

Read: about 600 lines of `podssh-transport` are used outside its tests (the former defects page),
and `docs/STATUS.md` line 158 at `3ee70dc` gives 2.8k source and 2.2k test lines. Only examples use it:
`crates/podssh-cli/examples/live_irc.rs` lines 20-22 at `e8bbd4d`, `crates/podssh-cli/examples/live_irc/support.rs`
lines 11-16 at `e8bbd4d`
and crates/podssh-transport/examples/live_forward.rs lines 23-25 at `e8bbd4d`; `podssh-cli` depends on it
(`crates/podssh-cli/Cargo.toml` line 34 at `e8bbd4d`). The plan: "`podssh-transport` moves into `podssh-relay`. Its
unused backpressure module goes." (`docs/design.md` lines 122-123 at `e8bbd4d`).

Read: the comments of the crate break rule 6 of `AGENTS.md:194-195`: they carry the stop-sign marker,
session history and line numbers of documents, for example crates/podssh-transport/src/socket.rs lines 1-11 at `e8bbd4d`
and crates/podssh-transport/src/control.rs lines 3-14 at `e8bbd4d`. The close rows cite lines of the pinned contract,
and a test reads that copy to check them (crates/podssh-transport/src/closes.rs lines 45-59 at `e8bbd4d`).

## Approach

1. Order: after T-083 and T-084, as the work order of `TODO/PROGRESS.md` says. The runners of T-079
   and T-080 use the repaired codecs as a dependency until then.
2. Move into crates/podssh-relay/src/reverse/: `framing.rs` and `framing/legs.rs`, `control.rs`,
   `closes.rs`, the retry parts of `error.rs`, and the name check of T-076, with their tests. Keep
   each file at 500 lines or fewer (`AGENTS.md:192-193`).
3. Delete, do not move: the backpressure module (T-074), the `Transport` trait and `backoff.rs`
   (T-077), and `RelayConfig` (`podssh-relay` has `Relay` and `RelayList`,
   `crates/podssh-relay/src/relay.rs:28-50`).
4. Rewrite the comments of the moved code to `AGENTS.md:194-195`: why, in few words; no markers, no
   history, no line numbers. Keep the check of the close rows against the pinned copy as a test
   (T-060 decides where the copy lives).
5. Move the examples to `podssh_relay::open`, the forward path that the commands use. Then remove
   the crate: `Cargo.toml` lines 6, 24 and 57-60, `crates/podssh-cli/Cargo.toml` line 34, `scripts/gate.sh`
   line 61 and `scripts/plant.sh` line 39, all at `e8bbd4d`.
6. Update in the same commit, at the lines of `e8bbd4d`: `AGENTS.md` lines 189-191 and 235,
   `docs/architecture.md` lines 82 and 99-109, `docs/development.md` lines 14-15 and 265, `docs/STATUS.md`
   lines 212, 215 and 226. The list of library crates in `docs/decisions.md` line 34 is a fact of a
   decision row: correct it, and move the
   old text to Superseded (the operator's ruling of 2026-10-08).

## Decision

Recommendation: move the codecs and delete the crate, as `docs/design.md` lines 122-123 at `e8bbd4d` plan. The
alternative, keep `podssh-transport` as a codec crate under `podssh-relay`, lost: it keeps two error
types and two retry tables for one protocol, which is how `403` and `503` already diverged (T-075).

2026-10-09, in the work:

1. Moved, as the runners use them: the session id and the frames of the node and operator legs, the
   control messages, the close table with `Retry` and `SessionAction`, and the state of each session
   (`Sessions`), each in its own file under `crates/podssh-relay/src/reverse/`.
2. Deleted with the crate, beside T-074 and T-077, as no runner used them: the socket layer
   (`WsSocket`, `Leg`, `FrameQueue`, the trait `WsSession` and its adapter, and with them
   `Control`, `LegShape` and `Limits`, which T-077 meant to keep for that layer), the forward
   framing (the forward path is `podssh_relay::open` and `RelaySession`), the endpoint builder and
   `RelayConfig`, and `TransportError` with its table of HTTP answers (`HttpFailure`, `Asked`,
   `Retry::NewToken`, `Retry::ReverseForbidden`). Lost: move the socket layer too. The runners read
   and write `RelaySession` themselves, so it would be a second road to the same socket.
3. The relay paths of the reverse legs are `relay::node_path` and `relay::operator_path`, beside the
   forward path, with the name checks of `podssh_ws::names` (T-076).
4. The rules of T-075 hold where the answers are read. The forward opener mints a new token once for
   a refused cached one, and never after a policy refusal (`crates/podssh-relay/src/open.rs:235-243`).
   A node exits on a `409`, pairs again on a `403` after the expiry, and stops on a `403` before it
   (`crates/podssh-relay/src/reverse/node.rs:148-151`). A node connects again after a `503`, as
   after each other failure: the contract's rules for a `503` name the forward leg's authentication
   and the mint (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:99-103`), and a node
   outlives a restart of the relay. The deleted table said "never on this host" for each leg, but
   no caller read it.
5. The comments follow rule 6 of `AGENTS.md`. The rows of the close table keep their line of the
   pinned contract (`spec_line`), and a codec error names its row: these are data, which
   `crates/podssh-relay/tests/reverse_closes.rs` checks against the pinned copy (Approach, step 4).
   The copy stays in `crates/podssh-probe/tests/spec/` until T-060 decides.
6. The Close captured from the live relay is a fixture of `podssh-ws`, which reads the Close
   (`crates/podssh-ws/tests/control_frames.rs`).
7. The examples open their session through `podssh_relay::open`, as the commands do, and take a
   token from the environment, the cache or a mint: `crates/podssh-relay/examples/live_forward.rs`
   replaces the crate's example, and `crates/podssh-cli/examples/live_irc.rs` uses podssh's own
   trust when no `--bundle FILE` is given, in place of its list of bundle paths.

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

## Done

2026-10-09, in the commit "The codecs of the reverse road in podssh-relay". T-074 and T-077 closed in it.

- Moved: `crates/podssh-relay/src/reverse/framing.rs`, `crates/podssh-relay/src/reverse/framing/legs.rs`,
  `crates/podssh-relay/src/reverse/control.rs`, `crates/podssh-relay/src/reverse/closes.rs` and
  `crates/podssh-relay/src/reverse/sessions.rs` (86 to 295 lines each), with their tests in
  `crates/podssh-relay/tests/reverse_framing.rs`, `crates/podssh-relay/tests/reverse_closes.rs` and
  `crates/podssh-relay/tests/reverse_plants.rs`. Of the crate's 84 tests, 43 moved with their names,
  one with a new name (`podssh-ws` reads a Close with no code as `None`, not `1005`), and 40 went
  with the code that they tested: 7 of the backpressure module, 2 of the backoff, 1 of the HTTP
  table, 6 of the endpoint builder, 7 of the forward framing, 2 of the adapter and 15 of the socket
  layer. What the runners need of that layer, their tests check: a control leaves as a text frame
  (`crates/podssh-relay/tests/reverse_node.rs:133-136`), data waits for `ready`
  (`ready_waits_for_the_handler_and_comes_before_data`, `plant_data_before_ready`,
  `input_before_ready_is_kept_then_sent_in_order`), a Close keeps its code and reason
  (`a_close_of_the_relay_ends_the_socket_with_its_code_and_reason`), and the token travels in its
  header (`crates/podssh-ws/tests/rfc6455.rs:280`).
- Deleted: crates/podssh-transport, its lines in `Cargo.toml`, `Cargo.lock` and
  `crates/podssh-cli/Cargo.toml`, and its name in the library lists of `scripts/gate.sh` and
  `scripts/plant.sh`. The comments that named it in `podssh-core`, `podssh-ws` and a test of
  `podssh-relay` name the crates that remain.
- The documents: `AGENTS.md` (rule 4, the map), `docs/architecture.md` (the table of crates, rules 2
  and 4), `docs/development.md` (the library list, the fixture, the examples), `docs/design.md` (the
  plan, done), `docs/decisions.md` (the library list in the row of the SSH client; the old text in
  Superseded) and `docs/STATUS.md` (the row of the crate merged into that of `podssh-relay`, each
  count of lines measured again, the library list). The row of `podssh-relay` said that no command
  used the reverse road, which T-083 and T-084 had made false; it names T-061 now.
- The 84 citations of the crate's files in `TODO/` are history forms at `e8bbd4d`, with the paths
  out of backticks, as the files are gone (`TODO/RULES.md`, "Citations are checked"). Of the other
  citations of the changed files, `cargo todo remap` moved 59 and left 47 for review: each was read,
  and moved by hand or written as a history form where its lines are gone.
- Prove: `cargo test -p podssh-relay --all-features --no-fail-fast`: 109 passed, 0 failed, 7
  ignored (the live tests). `cargo build --examples -p podssh-cli`: exit 0. The `git grep` of the
  Prove: exit 1. `sh scripts/dev.sh check`: green, each build and test step (the library crates
  with no C compiler, the blocking facade, the check on Rust 1.85, the work record); interop 103 of
  103; the man page 6 of 6; a static binary of 4,442,624 bytes. `python scripts/check-repo.py`: ok. `cargo test --no-fail-fast`: 810
  passed, 0 failed, 12 ignored (850 before: the crate's 84 tests went, and 44 came).
- Plant: `use podssh_transport;` at the end of `crates/podssh-cli/examples/live_irc.rs`: the build
  failed with `E0432` (exit 101). Restored, it builds (exit 0).

# T-083: `podssh node NAME TARGET`

**Source:** ROADMAP M4 (`docs/ROADMAP.md:164-165`); `crates/podssh-cli/src/positionals.rs` line 42 at `af0a163`; GitHub #19, and
GitHub #18 for zuko's doctor (read in the reports, not verified here). Measured here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A user in a cage cannot offer a local TCP service to an operator outside. `podssh node` refuses with exit 70
and takes no TARGET; `podssh relay pair` and `revoke` refuse too.

## Premise

Measured on `3ee70dc`, offline (`PODSSH_OFFLINE=1`, stdin from `/dev/null`):
`podssh node mynode` gives `'node' is not implemented yet; nothing was done.` and exit 70;
`podssh node mynode 127.0.0.1:22` gives `'127.0.0.1:22' is not an argument this verb takes.` and exit 64;
`podssh node --help` shows `podssh node NAME` and only `--help`; `podssh relay pair` gives the `--timeout`
refusal of T-008 (exit 64), and `podssh relay --timeout 5s pair` exit 70.

Read: `node` has no flags (`crates/podssh-cli/src/flags.rs` lines 403-404 at `af0a163`) and one positional, `NAME`
(`crates/podssh-cli/src/positionals.rs` line 42 at `af0a163`). `relay` lists `pair` and `revoke` (lines 39-41 there), and its
`--relay-host` takes a URL, not the `HOSTS` list of the other verbs (`crates/podssh-cli/src/flags.rs` lines 311-319 at `af0a163`).
Both are rows of `VERB_OWNER` (`crates/podssh-cli/src/flags.rs` lines 436-443 at `af0a163`).

Read: the relay names an agent-created pair; only an admitted name is chosen, by the relay's operator
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:90-91`, `:130-134`). In the measured sandbox
nothing can listen, and `connect()` to loopback failed with `EACCES` (`docs/target-environment.md:22`, `:25`).
So a local TCP TARGET exists only where the host allows it; `podssh serve` (M5) serves in the process
(`docs/reverse.md:33-36`).

## Approach

1. Parse `podssh node NAME TARGET`: NAME is a local label, TARGET is `HOST:PORT`
   (`crates/podssh-cli/src/positionals.rs` line 42 at `af0a163`). Flags (`crates/podssh-cli/src/flags.rs` lines 403-404 at `af0a163`):
   `--relay-host HOST` (one host, T-078), `--relay-addr`, `--ca-file`, and `--pair-file FILE` to import a pair.
   No `--timeout`: a node is a service.
2. Load the pair stored under NAME (T-078); refuse an expired one with the remedy; then run `node::run` (T-079)
   with a TCP handler that dials TARGET for each `open`.
3. `podssh relay pair NAME [--operator-file FILE]` creates and stores the pair, writes the operator's part to
   FILE, and prints only the label and the expiry. `podssh relay revoke NAME` stops the pair and deletes the
   local copies. `podssh relay status NAME` gives presence; agree on the form with T-058, whose `relay status`
   has no NAME.
4. Exit codes as `podssh proxy` (`docs/cli.md:261`): 64 usage; 69 the relay or TARGET cannot be reached; 77 a
   refused pair (`403`); 78 no usable pair; 0 after a stop by a signal. Add the rows to
   `crates/podssh-cli/src/man/facts.rs:214`.
5. `doctor`: one line for each stored pair, with its expiry and its presence, as in
   `crates/podssh-cli/src/doctor/relay_checks.rs:42-78` (zuko's doctor checks its ticket and state).
6. Remove `node` and `relay` from `VERB_OWNER`, and add them to `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:92-93`). New variables go in `VARIABLES`
   (`crates/podssh-cli/src/man/facts.rs:45`), files in FILES (`:115` there), examples in
   `crates/podssh-cli/src/man/examples.rs:8-66`; update `docs/cli.md`, `docs/reverse.md` and
   `docs/STATUS.md` (lines 48-50 at `af0a163`).
7. Pitfalls: `podssh man relay` shows the command; the topic THE RELAY has its own key since
   T-234 (`relay-facts`, `crates/podssh-cli/src/man/facts.rs:38`), so keep the two apart. Never
   print a token: a test runs the binary with tokens in the
   environment and in the store, and searches stdout and stderr.

## Decision

Recommendation: NAME is a local label for a stored pair, because the relay picks the pair's name and changes it
with each new pair; a label keeps a script stable. The alternative, NAME as the relay's name, lost: a user
cannot choose it, and it lasts 72 h at most.

2026-10-09, before the work:

1. NAME is a local label, as recommended above.
2. The exit codes follow the table of `crates/podssh-cli/src/exitmap.rs` (E24): an expired pair is
   77, a stopped one 69, a refused one (`403`) 77, a fault of the node (`1003`, `1009`) 70, no
   stored pair or a node that cannot connect as it is set up 78, the relay or TARGET out of reach
   69. Lost: 78 for an expired pair (step 4), which that table gives 77; one table for each command
   is the point of it.
3. `relay` loses its `--timeout` and `--jsonl` rows, as T-058 recommends: each request has its own
   bound of 30 s, so a script needs no `--timeout`, and JSON is T-049's. Its flags become
   `--relay-host` (the first host is the control host), `--relay-addr` and `--ca-file` as for
   `proxy`, and `--operator-file FILE` for `pair`. Lost: the gate of `--timeout`, which refuses
   `podssh relay pair lab` in each script that leaves it out.
4. `relay status NAME` gives the pair's presence. `relay status` with no NAME (T-058's `/health`),
   `info`, `spec` and `trace` refuse with 70 until T-058.
5. `node` dials TARGET once before it registers, and exits 69 when it cannot: such a node would
   take each session only to refuse it. Lost: no probe, where each operator gets a `reject`.
6. `node --pair-file FILE` reads a pair of the store's form and uses it, without storing it, so
   the tokens have no second copy; with no store, no copy is deleted when the pair is stopped.
7. `relay pair NAME` refuses when a pair that has not expired is stored under NAME (78, naming
   `podssh relay revoke NAME`): a second pair would leave the first without a holder, and it keeps
   its name for 72 h. An expired one is replaced. When the pair cannot be stored, or its operator
   file cannot be written, the new pair is stopped at once.
8. `relay revoke NAME`: a `403` means that the pair has ended already; the copy is deleted, and
   the command exits 0 with a note, as the end it asked for is reached. A relay out of reach keeps
   the copy: its stop token is the one way to stop the pair before it expires.
9. The live test is in podssh-cli (`tests/node_live.rs`), whose tests run the binary; a test of
   podssh-relay cannot. The plant of the redaction test prints the stored pair in `relay status`,
   which reaches the store offline; `relay pair` reaches no pair offline.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node
cargo test -p podssh-cli --test man_page --test man_flag_parity --test flag_table
XDG_CACHE_HOME=$(mktemp -d) timeout 20 target/debug/podssh node lab 127.0.0.1:22 </dev/null; echo "exit=$?"
cargo test -p podssh-cli --test node_live -- --ignored
```

crates/podssh-cli/tests/node.rs checks the parse (TARGET required; a bad label or port is 64 before a
connection), the refusal with no stored pair (78, naming `podssh relay pair`), and that no token reaches stdout
or stderr. The binary line must exit 78 and name `podssh relay pair lab`. The live test runs the binary as a
node in front of a public TCP service and reaches it through T-080. Plant: print the pair file in
`relay pair`; the redaction test must fail.

## Correction

2026-10-09: `podssh relay pair` with no `--timeout` now exits 70 ("'relay' is not implemented
yet; nothing was done."), before the gate of `--timeout`, since T-008; not 64. The other
measurements of the Premise hold for the binary of `af0a163`.

## Done

2026-10-09, in the commit "The node and the pairs on the command line".

- `podssh node NAME TARGET` (`crates/podssh-cli/src/node.rs`, new): the pair under NAME, or
  `--pair-file`; an expired one refused (77) with the remedy; TARGET dialed once (69 when it cannot);
  then `reverse::run` with a `TcpHandler`, until Ctrl-C or SIGTERM (0) or an end of the relay, each
  with its code by the table of E24. Flags `--relay-addr`, `--ca-file` and `--pair-file`.
- `podssh relay pair NAME [--operator-file FILE]`, `revoke NAME` and `status NAME`
  (`crates/podssh-cli/src/relay_cmd.rs` and `crates/podssh-cli/src/pairs.rs`, new): stdout holds the
  label with the expiry or the presence, never a token. `status` with no NAME, `info`, `spec` and
  `trace` exit 70 (T-058, which has a Correction). `relay` lost `--timeout` and `--jsonl`, and took
  `--relay-host HOSTS`, `--relay-addr`, `--ca-file` and `--operator-file`.
- `doctor`: a section `pairs`, with a line for each stored pair: its expiry and its node's presence;
  an expired pair is a FAIL; offline, the presence is `????`.
- podssh-relay: `pair::read_file` (a private file, as ssh reads a key; an operator's part is named as
  such), `pair::labels`, `cache::names_from` and `cache::read_private`.
- The manual: the notes of `node` and `relay`, the rows of 69, 70, 77 and 78, the cache's row of
  FILES, three examples. `docs/cli.md`, `docs/reverse.md`, `docs/STATUS.md` and the first lines of
  `AGENTS.md` say so.
- Prove: `cargo test -p podssh-cli --test node`: 8 passed (a missing NAME or TARGET, a bad label or
  port, a word too many: 64 before any connection; no stored pair: 78, naming `podssh relay pair
  lab`; an expired pair: 77; a stored pair gets as far as the network, which `PODSSH_OFFLINE` stops
  (69), with a token in the environment and in the store, and no output holds a token; a revoke that
  reaches no relay keeps the copy; an operator file that exists: 64, unchanged; the other
  subcommands: 70; a pair file in place of the store, and an operator's part refused, 78; the
  doctor's lines). `cargo test -p podssh-cli --test man_page --test man_flag_parity --test
  flag_table`: 19 passed. The binary line, with a scratch cache: exit 78, naming `podssh relay pair
  lab`. `cargo test -p podssh-cli --test node_live -- --ignored`: 1 passed (the binary made a pair;
  a node of the binary in front of `github.com:22`; an operator that held the operator's file alone
  read `SSH-2.0-3bc2e72` through it, `LocalEnd`; `relay status lab`: online; `relay revoke lab`:
  stopped, and the stored copy gone). `cargo test -p podssh-relay --features pair --test pair`: 10
  passed. `cargo test --no-fail-fast`: 843 passed, 0 failed, 11 ignored.
- Plant, restored: the connect token printed in `relay status`: the redaction test failed ("a token
  is in ...").

# T-084: `podssh operator NAME` and `podssh ssh NODE`

**Source:** ROADMAP M4 (`docs/ROADMAP.md:164-165`); `crates/podssh-cli/src/flags.rs` lines 418-419 at `3cbf215`. Measured
here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

An operator cannot reach a node. `podssh operator` refuses with exit 70, and `podssh ssh` cannot name
a node: `node:lab` reads as host `node` with a port that is not a number.

## Premise

Measured on `3ee70dc`, offline: `podssh operator mynode` gives exit 70;
`podssh ssh -T node:lab true` gives `"node:lab": "lab" is not a port` and exit 64;
`podssh ssh -T node:22 true` reaches the connect step for host `node`, port 22 (exit 255 from
`PODSSH_OFFLINE`); `podssh ssh -T node://lab true` gives `"//lab" is not a port` and exit 64.

Read: `parse_hop` strips `ssh://` and reads `host:PORT` (`crates/podssh-cli/src/ssh/resolve.rs:379-427`).
`Transport` is `Relay` or `Direct` (`crates/podssh-cli/src/ssh/resolve.rs:19-30`, chosen at `:232-270`).
`connect_and_run` gives `relay_stream::spawn` to russh (`crates/podssh-cli/src/ssh/mod.rs:73-116`), and
`relay_stream` closes with 1002 on a text frame (`crates/podssh-ssh/src/relay_stream.rs:131-137`); the
operator leg receives text frames (`docs/relay.md:227-230`). A host key is recorded under the target
host, never the relay's name (`SECURITY.md:63-68`); `HostKeyAlias` exists
(`crates/podssh-cli/src/ssh/resolve.rs:296`). `podssh ssh` uses the exit codes of OpenSSH, and
`podssh proxy` sysexits (`docs/cli.md:257-261`).

## Approach

1. `podssh operator NAME`: load the operator's part of the pair under NAME (T-078, T-083), and run
   `operator::run` (T-080) on stdin and stdout: a byte pipe as `podssh proxy`
   (`crates/podssh-cli/src/proxy.rs:183-281`). stdout carries data only; never 0 without `ready`.
2. `podssh ssh node://[user@]NAME`: `parse_hop` reads `node://` as it reads `ssh://`; add
   `Transport::Node` (`crates/podssh-cli/src/ssh/resolve.rs:19-30`).
3. For a node, `connect_and_run` opens the operator leg and waits for `ready` (T-080), then gives
   russh the raw stream. Do not give the leg to `relay_stream::spawn` as it is: reuse its pump after
   `ready`, with text frames read as control.
4. Host keys: record and check the node's key under the name `node://NAME`, which no DNS name can be;
   `-o HostKeyAlias` still wins.
5. Refuse by name a node as a `-J` hop, and `-W` through a node; record them for later.
6. Flags: `--pair-file FILE` for `operator` and `ssh` (`crates/podssh-cli/src/flags.rs:112-235`,
   lines 418-419 at `3cbf215`). Update the manual's examples and notes, `docs/cli.md` (lines 62-75 at `3cbf215`) and `docs/reverse.md`.

## Decision

Recommendation: `node://[user@]NAME`, read as `ssh://` is (`crates/podssh-cli/src/ssh/resolve.rs:384`),
because it changes no destination that works today (measured above). The alternative `node:NAME`, the
address form of `podssh pipe` (`docs/design.md:266`), lost: `podssh ssh node:22` already means host
`node`, port 22. A flag such as `--node NAME` lost: `podssh ssh` takes its destination as a word, as
OpenSSH does.

2026-10-09:

1. `node://[user@]NAME`, as recommended. The destination's host is `node://NAME`, so the messages
   and the known hosts name the node so, with no alias; the `%` tokens keep NAME.
2. The SSH client runs over a pipe whose other end is the operator of T-080, which waits for
   `ready`, keeps the early bytes and reads the text frames. `operator::start` (new) connects first,
   so a refused connection is reported before the SSH client starts. Lost: the pump of
   `relay_stream` with text frames read as control (step 3), which would copy the operator's rules.
3. `ssh` takes `--pair-file FILE`, as `operator` does: a pair, or its operator's part
   (`pair::read_operator_file`, `pair::OperatorPart`, new). The operator's file of `relay pair` is
   all that an operator outside needs.
4. With a node, `-p`, `-o Port`, `-o HostName`, `-4`, `-6`, `--direct`, `-J` (either way) and `-W`
   are refused by name (64).
5. `operator` exits by the faults of E24, as `node` does: 0 only after `ready` and a normal end;
   69, 77, 70 and 78 else. `ssh node://` keeps the codes of OpenSSH (255), and adds a line with the
   node's reason when the leg gives one.
6. The live test is in podssh-cli (`tests/node_live.rs`, `ssh_to_a_node`), as for T-083; the
   offline tests of both entries share `crates/podssh-cli/tests/pair_harness/mod.rs`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- node_destinations
cargo test -p podssh-cli --test operator
XDG_CACHE_HOME=$(mktemp -d) timeout 20 target/debug/podssh ssh -T node://lab true </dev/null; echo "exit=$?"
cargo test -p podssh-cli --test node_live -- --ignored ssh_to_a_node
```

`node_destinations` checks `node://lab` and `node://u@lab`, and that `node:22` stays host `node`, port
22. `operator.rs` runs the binary with no stored pair (78, naming `podssh relay pair`), and checks
that stdout stays empty. The binary line must exit 255, name `podssh relay pair lab`, and open no
connection. The live test runs `podssh ssh node://lab 'exit 3'` through a node whose TARGET is
`railway.new:22` (an anonymous SSH service, `docs/STATUS.md:66`), and expects 3. Plant: read `node:`
with no slashes as a node; `node_destinations` must fail.

## Done

2026-10-09, in the commit "The operator, and ssh to a node".

- `podssh operator NAME` (`crates/podssh-cli/src/operator.rs`, new): the operator's part of the pair
  under NAME, or of `--pair-file`; `operator::run` over stdin and stdout; flags `--relay-addr`,
  `--ca-file` and `--pair-file` (the table `PAIR_FLAGS`, shared with `node`).
- `podssh ssh node://[user@]NAME` (`crates/podssh-cli/src/ssh/node.rs`, new): `Transport::Node`, the
  refusals of Decision 4, and the SSH client over `operator::start` (new in
  `crates/podssh-relay/src/reverse/operator.rs`); `--pair-file` for `ssh`.
- podssh-relay: `pair::OperatorPart` and `pair::read_operator_file`, which reads an operator's file
  or a whole pair.
- The manual: the notes of `operator` and of `node://` for `ssh`, the exit rows, two examples; the
  start of the manual picks the `proxy` example by name. `docs/cli.md`, `docs/reverse.md`,
  `docs/STATUS.md` and the first lines of `AGENTS.md` say so.
- Prove: `cargo test -p podssh-cli --test ssh_args -- node_destinations`: 1 passed (`node://lab`,
  `node://u@lab` and `node://lab/` are the node `lab`, named `node://lab`; `--pair-file`; `node:22`
  stays host `node`, port 22, and `node:lab` a bad port; ten refusals). `cargo test -p podssh-cli
  --test operator`: 5 passed (no stored pair: 78 for `operator`, 255 for `ssh`, each naming `podssh
  relay pair lab`, and no connection; an expired pair; a stored pair gets as far as the network, with
  stdout empty and no token in the output; a pair file of either form; the parse). The binary line:
  exit 255, `node://lab: no pair is stored under "lab"; make one with podssh relay pair lab, ...`,
  with no `PODSSH_OFFLINE` and no connection. `cargo test -p podssh-cli --test node_live --
  --ignored`: 2 passed; `ssh_to_a_node`: `podssh ssh node://test@lab 'exit 3'` exited 3 through a
  node in front of `railway.new:22` (a throwaway key, deleted with the scratch directory), the host
  key recorded under `node://lab`, and `podssh operator lab` carried that server's banner, then
  exited 0 at the end of stdin. `cargo test -p podssh-relay --features pair --test pair`: 11 passed.
  `cargo test --no-fail-fast`: 850 passed, 0 failed, 12 ignored.
- Plant, restored: `node:` read as a node with no slashes: `node_destinations` failed (`node:22`
  became `node://22`).

# T-085: M4 exit: two sessions at once into a node in another sandbox, and the facade for podbox

**Source:** the exit criteria of M4 (`docs/ROADMAP.md:168-173`). Read here on `3ee70dc`.
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
way out, refuses `bind` and UDP, and has no `/dev/ptmx` (`docs/development.md:234-276`,
`scripts/test_in_box.sh`). It allows `connect()` to loopback, which the real sandbox refuses
(`docs/development.md:275-276`, `docs/target-environment.md:22`).

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
   and update `docs/ROADMAP.md:168-173`.

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
5. A pure-Rust SPAKE2 crate, built under `CC=/nonexistent` before it is chosen (`AGENTS.md:189-191`).
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
(`SECURITY.md:38-42`, `:63-68`). `podssh serve` keeps its host key in a state file and takes
authorized keys from a flag or a file (`docs/ROADMAP.md:177-182`, T-107).

Read in the reports (not verified here): iroh-ssh warns about an ephemeral node key
(`rustonbsd/iroh-ssh:src/ssh.rs`); GPU-Share keeps an Ed25519 identity in a state directory and a
default-deny allowlist (`arjun988/GPU-Share:crates/gpumesh-core/src/node.rs`); warren pins a key on
first sight, has `trust NAME --expect FINGERPRINT` and revocation, and exits 7 on a mismatch
(`willykeenan/warren:src/cli.rs`); zuko stores device authorization for each peer
(`adonm/zuko:src/store.rs`). iroh identifies endpoints by Ed25519 keys (`docs/design.md:286-288`).

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
`docs/design.md:351-357`, `:370-374`.
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
connection; after the key exchange it sees only ciphertext (`SECURITY.md:21-31`). It can drop, delay
or add frames (`SECURITY.md:33-36`).

Read: the road between two podssh ends carries SSH, `cp`, `pipe` and chat (`docs/design.md:351-357`);
for chat, the operator chose the roads, end to end encrypted, after M6 (`docs/design.md:373-375`).
The resumable layer of M6 runs under SSH (`docs/design.md:203-215`).

Read in the report (GitHub #18, not verified here): warren uses `Noise_IK_25519_ChaChaPoly_BLAKE2s`
so that the relay cannot read a stream (`willykeenan/warren:src/noise.rs`).

Read: the library crates must build with no C compiler (`AGENTS.md:189-191`, `scripts/gate.sh:96`).

## Approach

1. A Noise IK channel for each reverse session, in crates/podssh-relay/src/reverse/e2e.rs. The
   operator knows the node's static key from the pair file or a pin (T-087); the node's allowlist
   lists the operators' keys.
2. Library: the `snow` crate with its pure-Rust resolver only. Check it under `CC=/nonexistent` in
   the gate before it is chosen; else RustCrypto parts with the IK handshake written here, and the
   test vectors of the Noise specification.
3. Messages: each Noise message at most 65535 bytes, with a length prefix, inside the session's
   bytes. The relay's frames on the operator leg stay bare (`docs/reverse.md:65`).
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
frames (`docs/reverse.md:65`). Data needs `ready` first (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:180`), and `ready` comes
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
and podssh must probe before it uses UDP (`AGENTS.md:176-177`).

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
upgrade, 72 h at most (`docs/relay.md:101-105`); `POST /v1/pair` gives the three tokens of a pair, 72 h at most
(`docs/relay.md:210-213`). The contract scopes reverse tokens to a name and a role, and states no single use and
no binding to a peer (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:128-129`). A new mint secret
ends each token at once (`docs/relay.md:198-200`). A text frame from the operator closes its socket with
`1003`, and the operator leg carries no framing (`docs/relay.md:227-230`, `docs/reverse.md:65`).

Measured: `grep -rni sshsig crates scripts docs Cargo.toml` finds nothing (exit 1). The wider `sign(` hits are
tests of primitives (`crates/podssh-ws/tests/crypto_vectors.rs:125-159`,
`crates/podssh-ws/tests/signatures.rs:29-163`); the comment's `crypto_vectors.rs:192` is not one. Read: the
issue's "rule 8" is rule 6 (`docs/architecture.md:120-122`), and its "section 2" sentence about an allowlist of
keys is in section 7 (`docs/design.md:314-315`). Read in the report (not verified here): syq signs a grant in a
fixed namespace and redeems it at most once with `flock`, `O_EXCL`, `linkat` and `fsync` (lines 55 and
1416-1492 of `greaber/syq:src/delegation.rs`). The reporter's correction: a signed grant leaks as a token does
(lines 11-12); signing buys scope, single use and non-repudiation, not safety after a leak.

Read, what a leaked token gives today. `connect_token`: sessions to the node; an SSH server's own
authentication still stands, but a raw TCP TARGET (T-083) has no other gate. `node_token`: an impersonated node
while the real one is away (one socket for each name, and a new node gets the new sessions: `:152-156` of the
contract); for SSH, the operator's host-key check finds it (`SECURITY.md:38-42`). `stop_token`: a denial of
service; the node, its sessions and the pair end (`docs/relay.md:232-236`).

## Approach

The operator ruled on 2026-10-08: not in M4; M4 keeps the relay's tokens, the trust is end to end (T-087,
T-107), and the relay stays a separate project (`docs/decisions.md`). The two shapes, for the relay's operator:
1. On the relay: an endpoint in place of `POST /v1/pair` that returns a signed grant naming the node, the
   principals that may use it (key fingerprints, T-087), an expiry and a nonce. The relay records the nonce as
   spent and refuses a second use. podssh caches the grant and sends it in a header or a 0600 file, never in
   a URL (`docs/relay.md:106-108`, `docs/architecture.md:120-122`).
2. On the client: keep the pair's tokens, and add a signed grant inside the operator leg, which the relay has
   authenticated. A text frame closes that leg with `1003`, so the grant needs a typed binary header at the
   start of the session: a change of the framing in crates/podssh-transport/src/framing/legs.rs lines 60-76 at `e8bbd4d`. The
   node checks the grant before it dials the TARGET, so the dial moves after `ready` (`docs/reverse.md:16`):
   the seam of T-088 and T-089. Spent nonces are create-new private files
   (`crates/podssh-relay/src/cache.rs:305-318`).
3. Both shapes: an SSHSIG signature in a fixed podssh namespace, which `ssh-keygen -Y verify` can check
   (T-020), with the keys of T-087, in pure Rust (`AGENTS.md:189-191`).
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

# T-256: A local side that does not read stops every session of the node

**Source:** a reading of `crates/podssh-relay/src/reverse/serve.rs` on
2026-10-09, while T-118 was planned.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The node's socket reader gives each data frame to its session's queue, and
waits while that queue is full. A local side that reads nothing (a stuck
target, a program that does not read its input) fills its queue, and then the
reader waits on it: no frame of any session is read, controls included, until
the liveness watcher finds the socket silent and the node connects again,
which ends every session.

## Premise

Read: the reader awaits the queue of the session
(`crates/podssh-relay/src/reverse/serve.rs` lines 133-134 at `1f89a82`), which
holds 32 chunks (line 182 there). The relay has no flow
control for one session of a socket: it closes a leg with `1011 relay
backpressure` when more than 1 MiB waits for a slow receiver
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`).

## Approach

1. The reader offers the data with `try_send`. On a full queue that session
   ends: its two copies stop, its route goes, and the writer sends
   `close {id}` with the reason "the local side does not read". The other
   sessions go on.
2. The local reader starts only after `ready` is queued, as now, so that its
   first bytes are not dropped.
3. A test against the scripted relay (`crates/podssh-relay/tests/reverse_node.rs`):
   session A's local side reads nothing while the relay sends it 40 frames of
   64 KiB; session B still carries bytes both ways, and A gets the `close` with
   the reason.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_node
```

Plant: the reader awaits the full queue again. The test must fail at its time
limit, not hang.

## Done

2026-10-09, in the commit "A stalled local side ends its own session, not the
node's".

- `crates/podssh-relay/src/reverse/serve.rs`: the reader gives a frame to its
  session with `try_send` (`offer`). On a full queue the session ends: its two
  copies stop (each route keeps their abort handles), its route goes, and the
  writer sends `close {id}` with the reason "the node's local side does not
  read". The local reader starts once `ready` is queued, as before.
- Test: `a_local_side_that_does_not_read_ends_its_session_and_not_the_others`
  in `crates/podssh-relay/tests/reverse_node.rs`: A's local side reads
  nothing while the relay sends it 40 frames of 64 KiB; B carries bytes both
  ways, A gets the `close` with its reason, and at the stop only B is closed.
- Prove: `cargo test -p podssh-relay --features pair --test reverse_node`:
  7 passed, 0 failed. Plant, restored: the reader awaits the full queue
  again; the test failed at its limit of 20 s ("a stalled session stopped
  the socket"), exit 101.
- Also, from T-255's commit: the doc comment of `connect_refusal` in
  `crates/podssh-cli/src/pairs.rs` is above its function again
  (`session_end` had gone in between).
