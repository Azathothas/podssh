This file holds milestone M4, the reverse road (`docs/ROADMAP.md:148-173`): pairing, the node and
operator runners and a blocking facade in `podssh-relay`, the move of the codecs, the commands
`podssh node`, `podssh operator` and `podssh ssh NODE`, and the exit measurement. It also holds the
backlog work on that road: pairing by a code, node identity, end-to-end encryption, routes,
finding a node, and signed grants. M4 starts after M3 is complete (`docs/ROADMAP.md:7-9`); in M4,
the defects of `TODO/transport.md` come first, in the work order of `TODO/PROGRESS.md`. The rules
for the node and the operator are in `docs/reverse.md`; the wire format is in `docs/relay.md:598-640`
and in the pinned contract (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:123-193`).

# T-078: Pairing in `podssh-relay`: pair, stop and status

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-152`); `docs/design.md` lines 89-100 at `0d92eef` (`pair`, cargo feature
`pair`); `docs/relay.md:598-640`. Read here on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A node needs a pair name and a `node_token`; its operator needs the `connect_token`. podssh cannot get
them: no code calls `POST /v1/pair`, `POST /v1/stop/<name>` or `GET /v1/status/<name>`. podbox pairs
through `curl` (`docs/design.md:592-593`), which a sandbox may not have.

## Premise

Read: `POST /v1/pair` with `{}` returns `{name, node_token, connect_token, stop_token, expires}`, within
72 h; `/v1/status/<name>` gives presence with a token; `POST /v1/stop/<name>` stops the node and its
sessions; tokens go in `X-Relay-Token` (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:125-137`).
Pair creation shares the brake of 120 attempts per minute per address with mint (`:235-238` there).
These endpoints are on the "control host only" (`:23-24`, `:130`); no pool host was measured for them.

The lines of the files that this entry changed are those of `3632dcb`.

Read: `/v1/pair` can answer `409` (pair again), and a new mint secret ends each token at once
(`docs/relay.md` lines 188-190 at `9811e0d`). `/v1/stop` once answered `{"stopped": false}` and still destroyed
the credentials (lines 209-212 at `9811e0d` there); then the other tokens get `403 reverse: forbidden`
(`docs/reverse.md` lines 51-52 at `9811e0d`). Which token `/v1/status` accepts is not known (line 53 at `9811e0d` there); a
local copy of podbox at `5bd8cb0` says `connect_token` only
(`Azathothas/podbox:crates/podbox-ssh/src/mux.rs`).

Read: `podssh-relay` has no pairing code (`crates/podssh-relay/src/lib.rs` lines 14-21 at `9811e0d`).
`https_post_json` sends fixed headers, and `https_request`, which takes headers, is private
(`crates/podssh-ws/src/client.rs` lines 261-313 at `9811e0d`). The private files of the token cache can hold a
pair (`crates/podssh-relay/src/cache.rs` lines 126-153 and 221-240 at `9811e0d`).

## Approach

1. Add crates/podssh-relay/src/pair.rs behind the feature `pair` (`docs/design.md` line 93 at `0d92eef`). Declare it in
   `crates/podssh-relay/Cargo.toml` (lines 10-21 at `3632dcb`), enable it in `podssh-cli`, and build it
   in the library step of the gate (`scripts/gate.sh` line 61 at `3632dcb`), so the no-C check covers
   it.
2. `pair::create` returns a `Pair`: relay host, name, the three tokens, expiry. Keep each token in
   `Zeroizing` with a redacted `Debug`, as `token::Token` does (`crates/podssh-relay/src/token.rs:28-57`).
   Check the name with T-076, and each token with `cache::valid_token`
   (`crates/podssh-relay/src/cache.rs` lines 52-56 at `3632dcb`). Never quote a 2xx body
   (`crates/podssh-relay/src/token.rs:197`).
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
   `3632dcb`), and the FILES section of the manual (`crates/podssh-cli/src/man/facts.rs:313`).

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

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-158`); `docs/design.md` lines 94-97 at `0d92eef`; `docs/reverse.md:8-51`; GitHub #19
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
(`crates/podssh-ws/src/session.rs:220-331`); `podssh_relay::open::backoff` has a jitter
(`crates/podssh-relay/src/open.rs:404-418`). Not measured: whether the relay answers a Ping on a reverse socket
(`docs/relay.md:365-367` is the forward path), and its idle cut there (`docs/relay.md` lines 191-192 at `cd75137`, T-061). A node
that connects again ends each operator session on it (`docs/design.md:659-662`).

Read in a local copy of podbox at `5bd8cb0` (`docs/design.md:534` names `452d792`): `run_node` owns the socket in
one thread, drops late bytes of a closed id, and dials again with a backoff
(`Azathothas/podbox:crates/podbox-ssh/src/mux.rs`). It also needs `hello`, accepts upper-case ids, and has no
`409` rule; do not port these (`docs/reverse.md` lines 17-21 at `9811e0d`,
`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:174`). GitHub #19 cites syq's receive mode, one
persistent connection that the far side opens (`greaber/syq:src/conn/reverse_tcp.rs`; read in the report, not
verified here).

## Approach

1. crates/podssh-relay/src/reverse/node.rs: `node::run(config, handler)`; `handler.open(id)` gives a byte stream
   or a reason to reject. It uses the codecs of `podssh-transport` until T-082. Invariant: no protocol above
   bytes (`docs/architecture.md:254-256`).
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
   (`crates/podssh-relay/src/open.rs:365`), and a quiet socket would reconnect.
6. Close actions, by code and reason (`docs/reverse.md:470-472`): `409`, exit, no retry;
   `1001 operator stopped reverse relay`, exit and delete the pair; `1001 pair expired`, or a `403` after the
   stored expiry, a re-pair hook that is off by default; `1003` and `1009`, exit with the reason, never a loop;
   any other close, connect again with `open::backoff`.
7. A clean stop (SIGTERM or Ctrl-C): `close {id}` with a reason for each session, a Close `1000`, then exit 0.
8. A TCP handler dials with `podssh_ws::dial::dial` (`crates/podssh-ws/src/dial.rs:201`), which keeps loopback
   off the proxy (`crates/podssh-ws/src/dial.rs:105-109`).
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
(`RelaySession::new` takes any stream: `crates/podssh-ws/src/session.rs:107-111`). The cases: two mixed sessions
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

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-158`); `docs/design.md` lines 94-97 at `0d92eef`; `docs/reverse.md:118-472`.
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
The relay sends no keepalives on reverse sockets (`docs/reverse.md:37-47`).

Read: the codecs: `encode_operator_frame` and `chunk_for_bare`
(crates/podssh-transport/src/framing/legs.rs lines 60-76 at `e8bbd4d`, lines 125-133), and `parse_operator_control`
(crates/podssh-transport/src/control.rs lines 223-230 at `e8bbd4d`). `podssh proxy` has the pump to follow: stdin and
stdout, liveness, the close reason (`crates/podssh-cli/src/pipe/relay.rs:107-247`).

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
   the code and the reason (`docs/reverse.md:467-472`).
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

**Source:** ROADMAP M4 (`docs/ROADMAP.md:150-152`, `:180-181`); `docs/design.md:580-593`. Read here
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
`ring`; its MSRV is 1.85; it is made for TLS-intercepting proxies (`docs/design.md:538-548`). The plan
is a synchronous facade that owns a current-thread runtime (`docs/design.md:580-581`); then podbox
pins `podssh-relay` by git revision and removes its own `ws.rs`, `tls.rs`, direct dial and pairing
through `curl` (`docs/design.md:592-593`).

Read: `podssh-relay` declares the workspace minimum, Rust 1.88 (`crates/podssh-relay/Cargo.toml:5-6`,
`Cargo.toml` lines 45-48 at `0d92eef`), above podbox's 1.85. `podssh proxy` already runs async code from sync code with
a current-thread runtime and `shutdown_background` (`crates/podssh-cli/src/proxy.rs:242-255`).

Read: podbox keeps `ring` and TLS 1.2 through a `rustls::ClientConfig` that it supplies
(`docs/design.md:585-589`); that is T-066, not this entry.

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
   (`crates/podssh-relay/src/lib.rs:1-62`); add the feature to the gate (`scripts/gate.sh:133`).

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

Read: the comments of the crate break rule 6 of `AGENTS.md:312-313`: they carry the stop-sign marker,
session history and line numbers of documents, for example crates/podssh-transport/src/socket.rs lines 1-11 at `e8bbd4d`
and crates/podssh-transport/src/control.rs lines 3-14 at `e8bbd4d`. The close rows cite lines of the pinned contract,
and a test reads that copy to check them (crates/podssh-transport/src/closes.rs lines 45-59 at `e8bbd4d`).

## Approach

1. Order: after T-083 and T-084, as the work order of `TODO/PROGRESS.md` says. The runners of T-079
   and T-080 use the repaired codecs as a dependency until then.
2. Move into crates/podssh-relay/src/reverse/: `framing.rs` and `framing/legs.rs`, `control.rs`,
   `closes.rs`, the retry parts of `error.rs`, and the name check of T-076, with their tests. Keep
   each file at 500 lines or fewer (`AGENTS.md:310-311`).
3. Delete, do not move: the backpressure module (T-074), the `Transport` trait and `backoff.rs`
   (T-077), and `RelayConfig` (`podssh-relay` has `Relay` and `RelayList`,
   `crates/podssh-relay/src/relay.rs:80-102`).
4. Rewrite the comments of the moved code to `AGENTS.md:312-313`: why, in few words; no markers, no
   history, no line numbers. Keep the check of the close rows against the pinned copy as a test
   (T-060 decides where the copy lives).
5. Move the examples to `podssh_relay::open`, the forward path that the commands use. Then remove
   the crate: `Cargo.toml` lines 6, 24 and 57-60 at `cd75137`, `crates/podssh-cli/Cargo.toml` line 34 at `cd75137`, `scripts/gate.sh`
   line 61 at `9811e0d` and `scripts/plant.sh` line 39 at `cd75137`, all at `e8bbd4d`.
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
   a refused cached one, and never after a policy refusal (`crates/podssh-relay/src/open.rs:370-382`).
   A node exits on a `409`, pairs again on a `403` after the expiry, and stops on a `403` before it
   (crates/podssh-relay/src/reverse/node.rs, lines 148-151 at `fb228e9`; T-261 later made a `409`
   after a loss a wait). A node connects again after a `503`, as
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
  (`crates/podssh-relay/tests/reverse_node.rs:144-147`), data waits for `ready`
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
(`docs/reverse.md:48-51`).

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
4. Exit codes as `podssh proxy` (`docs/cli.md:5211`): 64 usage; 69 the relay or TARGET cannot be reached; 77 a
   refused pair (`403`); 78 no usable pair; 0 after a stop by a signal. Add the rows to
   `crates/podssh-cli/src/man/facts/exit.rs:8`.
5. `doctor`: one line for each stored pair, with its expiry and its presence, as in
   `crates/podssh-cli/src/doctor/relay_checks.rs:42-94` (zuko's doctor checks its ticket and state).
6. Remove `node` and `relay` from `VERB_OWNER`, and add them to `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:110-143`). New variables go in `VARIABLES`
   (`crates/podssh-cli/src/man/facts.rs:46`), files in FILES (`:313` there), examples in
   `crates/podssh-cli/src/man/examples.rs:8-309`; update `docs/cli.md`, `docs/reverse.md` and
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

Read: `parse_hop` strips `ssh://` and reads `host:PORT` (`crates/podssh-cli/src/ssh/hop.rs:30-78`).
`Transport` is `Relay` or `Direct` (`crates/podssh-cli/src/ssh/resolve.rs:23-76`, chosen at `:313-375`).
`connect_and_run` gives `relay_stream::spawn` to russh (`crates/podssh-cli/src/ssh/mod.rs` lines 73-116 at `6483366`), and
`relay_stream` closes with 1002 on a text frame (`crates/podssh-ssh/src/relay_stream.rs:274-280`); the
operator leg receives text frames (`docs/relay.md:623-626`). A host key is recorded under the target
host, never the relay's name (`SECURITY.md:222-232`); `HostKeyAlias` exists
(`crates/podssh-cli/src/ssh/resolve.rs:420`). `podssh ssh` uses the exit codes of OpenSSH, and
`podssh proxy` sysexits (`docs/cli.md:5207-5211`).

## Approach

1. `podssh operator NAME`: load the operator's part of the pair under NAME (T-078, T-083), and run
   `operator::run` (T-080) on stdin and stdout: a byte pipe as `podssh proxy`
   (`crates/podssh-cli/src/pipe/relay.rs:107-247`). stdout carries data only; never 0 without `ready`.
2. `podssh ssh node://[user@]NAME`: `parse_hop` reads `node://` as it reads `ssh://`; add
   `Transport::Node` (`crates/podssh-cli/src/ssh/resolve.rs:23-76`).
3. For a node, `connect_and_run` opens the operator leg and waits for `ready` (T-080), then gives
   russh the raw stream. Do not give the leg to `relay_stream::spawn` as it is: reuse its pump after
   `ready`, with text frames read as control.
4. Host keys: record and check the node's key under the name `node://NAME`, which no DNS name can be;
   `-o HostKeyAlias` still wins.
5. Refuse by name a node as a `-J` hop, and `-W` through a node; record them for later.
6. Flags: `--pair-file FILE` for `operator` and `ssh` (`crates/podssh-cli/src/flags.rs:116-291`,
   lines 418-419 at `3cbf215`). Update the manual's examples and notes, `docs/cli.md` (lines 62-75 at `3cbf215`) and `docs/reverse.md`.

## Decision

Recommendation: `node://[user@]NAME`, read as `ssh://` is (`crates/podssh-cli/src/ssh/hop.rs:35`),
because it changes no destination that works today (measured above). The alternative `node:NAME`, the
address form of `podssh pipe` (`docs/design.md:1093`), lost: `podssh ssh node:22` already means host
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
`railway.new:22` (an anonymous SSH service, `docs/STATUS.md:157`), and expects 3. Plant: read `node:`
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
way out, refuses `bind` and UDP, and has no `/dev/ptmx` (`docs/development.md:461-503`,
`scripts/test_in_box.sh`). It allows `connect()` to loopback, which the real sandbox refuses
(`docs/development.md:502-503`, `docs/target-environment.md:22`).

Read: in such a sandbox nothing can listen (`docs/target-environment.md:25`, `:99-102`), so a node
there has no local TCP service to offer before `podssh serve` (M5). Its TARGET must be a host that
its proxy allows (`docs/target-environment.md:21`).

Read: podbox's reverse legs carried two sessions at once over the live relay on 2026-09-28
(`docs/design.md:540-541`). Its own test with two clients is in its repository (`Azathothas/podbox`),
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

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

# T-086: Pairing by a short one-time code, given out of band

**Source:** GitHub #18 (reports on zuko, warren, GPU-Share and quic-ssh) and GitHub #19 (report on
slingshot); read in the reports, not verified here.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

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
5. A pure-Rust SPAKE2 crate, built under `CC=/nonexistent` before it is chosen (`AGENTS.md:307-309`).
6. Pitfalls: limit the attempts at the meeting point; one failed exchange ends the code; check the
   received part as T-076 and T-078 check a pair.

## Decision

Recommendation: SPAKE2 through a mailbox in the relay, when the relay's operator adds one (the relay
stays a separate project, ruled on 2026-10-08; signed grants wait for it too, T-226). The alternative, a pairing string
sealed with a key from the short code, lost: whoever copies the string can guess the code offline. A
public mailbox of another project, reached through the forward road, lost for now: podssh would
depend on a service that it does not run for each pairing. Keep it as the fallback if the relay's
operator declines.

Decided in the work (2026-11-03, the draft; the Correction below made the public mailboxes the meeting
point):
- The code: the mailbox's nameplate, then three words of the PGP list, odd and even in turn, as
  magic-wormhole's own `choose_words` gives them: 24 bits, against one online guess for each code
  (`SECURITY.md`, "A code of the pairing"). Lost: magic-wormhole's default of two words (16 bits, one
  in 65,536 for a guess that wins a connect token and a line of `--allow`); four words or more (32
  bits and up, harder to read aloud, for an attacker who gets one try anyway); digits alone (a
  person mishears them, and nothing tells a dropped one, where the two lists do).
- Its life: 10 minutes at the giver, then it releases the nameplate and closes `lonely`; a taker
  waits 20 s for the giver's `pake`, which the mailbox keeps, and 60 s for each later step. Lost: a
  life as long as the pair (a code on a sticky note would be a credential for 72 h).
- Its attempts: one. The giver leaves after the first exchange, whatever its end; a `version` that
  does not open ends the code at both ends (`scary`); the mailbox takes two sides of a nameplate,
  a third gets `crowded`; and podssh's relay role brakes each connection to its mailbox as a
  request of `/v1/pair`. Lost: a giver that waits on for the right taker after a wrong one (each
  wrong code would be another guess), and a count of failures at the giver (the mailbox's two
  sides already end the code).
- How a taker finds its giver: each mailbox in order, by its `list`; one that lists others has no
  giver of the code, and claiming there would spend a stranger's code, so it is passed; one that
  lists none (a server of `--disallow-list`) is claimed, and the giver's `pake` comes at once or not
  at all. Lost: a mark of the mailbox in the code (a word more to read aloud), and claiming at each
  mailbox in turn (a stranger's code spent at a mailbox that the giver could not reach).
- The crates: `spake2` 0.4 (RustCrypto's PAKEs, the one that magic-wormhole's Rust port uses, which
  interoperates with python-spake2), on the curve25519-dalek 4, hkdf 0.12 and sha2 0.10 that
  crypto_box and snow keep in the lock, its `getrandom` off and its scalar from podssh's own source
  through rand_core 0.6; and `crypto_secretbox` 0.1, which crypto_box builds. Each is pure Rust, and
  they build under `CC=/nonexistent` (measured at the merge: `cargo check -p podssh-relay --features
  code,pair,serve` with no C compiler). Lost: `spake2` 0.5.0-pre.0,
  on the workspace's newer curve, a prerelease whose API may move; the `magic-wormhole` crate, whose
  EUPL-1.2 and size podssh does not need for a few messages (docs/carriers.md, [N14]).
- A proof of work that a mailbox asks (`permission-required` with no `none`): not made; that
  mailbox is passed for the next. Lost for now: hashcash, which no mailbox that podssh uses asks.
- What moves: the giver's label, the node's key and the operator's part; the taker's key back; the
  giver's last word of what it did with that key. The taker pins the key under its own label before
  any session, and keeps the part as `operator-NAME.json`, which each client of a pair reads where no
  whole pair is stored under NAME. The giver adds the key's line to the allowlist that
  `--allow FILE` names, which the node reads again for each session; with none, it says that the
  connect token is the door. Lost: the node's roads (iroh and DERP tickets, a quick tunnel's name): a `relay pair`
  holds none, as only a running node knows them, and an operator's host keeps no tickets by label;
  a member of the net gets them from the net's document (T-429). Lost: a grant of T-226 in place of
  `--allow` (a grant lets in one session; `podssh node NAME --grant-to KEY` mints one once the key is
  known), and the routes of an allowlist line (the user adds `routes=` to the line that the code
  wrote). The net's own join by this code, the Correction's `podssh net invite`, is no command of
  T-429: it is the net's work on this exchange, for an entry of its own.
- The commands: `podssh relay pair NAME --code` (the stored pair while it has 10 minutes left, else
  the next one, made as `pair NAME` makes it) and `podssh relay join NAME`, beside the pair's other
  verbs. Lost: a flag of `podssh node` (its file is at its 500 lines, and the code would wait on a
  node that runs), and a verb of its own (the pair's verbs are under `relay`).
- The code's terminal: stderr when it is a terminal, else the process's terminal (`/dev/tty`,
  `CONOUT$`), else a refusal (64) before a pair is made; the taker reads a prompt on a terminal, or
  one line of a pipe for a script, never argv. Lost: stdout (a script's capture is a log).
- The role's mailbox: at `/v1/mailbox`, for podssh's AppID alone, in memory, one table for each role
  (a field of its pairs, so that no caller of the role changes). Lost: a table for the process (two
  roles of one process, as the tests run them, would share nameplates), and a mailbox of each AppID
  (the role would be a public mailbox of other programs).

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

## Correction

2026-11-02 (the drafting agent). Until that day this entry was blocked, and its `## Blocker`
read, moved here as `cargo todo check` refuses a Blocker on an open entry:

> The relay's operator: a mailbox endpoint for the pairing (the relay is a separate project:
> `docs/decisions.md`). The operator ruled on 2026-10-08 that sessions skip this entry until then.

Lifted on 2026-11-02 by Q63 and Q65: see below.

The Premise holds at its lines. By Q63 (2026-11-02, `docs/decisions.md`; docs/mesh.md,
section 3) the relay is a role of podssh itself, so this entry is podssh's work; and by Q65 (the
same day) podssh may use the public magic-wormhole mailboxes when the user did not ask. The
Decision above kept "a public mailbox of another project" as the fallback if the relay's
operator declined; Q65 makes it the meeting point, and the net's `podssh net invite` (T-429)
pairs by this code.

The meeting point: magic-wormhole's mailbox (its rendezvous protocol), a WebSocket on port 443:
`wss://relay.magic-wormhole.io/v1`, then Least Authority's `wss://mailbox.mw.leastauthority.com/v1`
(read in the research of 2026-11-02; `docs/carriers.md`). The mailbox stores and forwards; the two
ends run SPAKE2 keyed by the whole code, so the mailbox learns nothing and can change nothing,
and an active attacker gets one guess for each run. podssh's relay role (T-427) may serve the
same protocol for a user who names it.

What the client does: the protocol as magic-wormhole writes it, so that the tests run the
Python mailbox server and the Python client, which podssh did not write.

The new Approach, in place of the one above:

1. Items 1, 4 and 6 above hold.
2. The mailbox's client in `podssh-relay`, on podssh-ws's WebSocket, through `HTTPS_PROXY`, with
   podssh's TLS and DNS fallbacks: `bind` with an AppID of podssh's own, `allocate` or `claim`,
   `open`, `add`, `release`, and `close` with a mood.
3. The client's protocol: the `pake` phase (SPAKE2 of the pure-Rust `spake2` crate, which
   python-spake2 interoperates with), the encrypted `version` phase, then phases in NaCl
   SecretBox under keys of HKDF-SHA256.
4. The code: the mailbox's nameplate, then three words of the PGP lists; valid for 10 minutes,
   shown only on the node's terminal; one failed confirmation ends it on both sides.
5. What moves after the key is confirmed: the node's Ed25519 key, pinned under the label, and
   its roads (iroh and DERP tickets, a quick tunnel's name, the pair's part where a pair exists);
   the operator's Ed25519 key back, which the node adds to its `--allow` with the routes that
   its command names, or answers with a grant of T-226.
6. The mailboxes in order: the two above, then one that `--pair-mailbox URL` names (a podssh
   relay role of the user's, T-427). What `tcp.ssh.relay.ajam.dev` lacks here is no blocker: a
   note of docs/relay-operator.md (item 10).

The new Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,code --test pair_code
cargo test -p podssh-relay --features pair,code --test pair_code_live -- --ignored
```

Offline, against Python's `magic-wormhole-mailbox-server` on the loopback: two podssh peers with
one code agree and move each part; a podssh peer and the Python `wormhole` library, with podssh's
AppID, finish the `pake` and `version` phases; a wrong code fails both sides and ends the code;
a second use fails; a code older than 10 minutes fails; the code is in no output. Planted: a
second use accepted; the single-use test fails. Live, a short run from a GitHub runner and from a
session's own host (Q65): a node and an operator pair through `wss://relay.magic-wormhole.io/v1`,
then `podssh operator` reaches the node.

2026-11-03 (the drafting agent). The Premise holds at its lines
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:130-136`, and `:137-138` says "Accept
a connect token only"). The Prove gains the feature `serve`, as its tests run against podssh's relay
role's mailbox beside magic-wormhole's server (the gate has no Python), and the commands' tests; the
Prove that ran is in `## Done`.

## Done

Drafted 2026-11-03 (`7a0c97f`), merged and measured by the main session on 2026-11-04.

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features code --lib code::
cargo test -p podssh-relay --features serve --lib serve::mailbox
cargo test -p podssh-relay --features pair,code --lib pair::part
cargo test -p podssh-relay --features pair,code,serve --test pair_code
cargo test -p podssh-relay --features pair,code --test pair_code_live -- --ignored
cargo test -p podssh-cli --lib relay_code
cargo test -p podssh-cli --test relay_code --test relay_code_role
sh scripts/plant-each.sh --here t086-third-side t086-code-said t086-version-unchecked
```

- `--lib code::`: 22 passed (the word lists of magic-wormhole's `_wordlist.py`; the phase keys of
  HKDF-SHA256 equal to Python's `hmac` and `hashlib`; SecretBox; SPAKE2 of one code agreeing and of
  two not; a scalar whose draw failed never used).
- `--lib serve::mailbox`: 6 passed; `pair::part`: 2 passed.
- `--test pair_code`, against podssh's relay role, and against magic-wormhole-mailbox-server and a
  peer of magic-wormhole's Python library (`PODSSH_MAILBOX_TEST_SERVER=required`, `pair-code.yml`;
  here magic-wormhole 0.24.0 and its mailbox server from PyPI in a venv): 9 passed (two podssh ends of one code agree and move each part; a wrong code fails both and
  spends the code; a second use and a code past its life find nobody; a third end is refused while
  two hold the code; no line and no `Debug` holds the code; the Python peer takes podssh's code,
  gives one that podssh takes, and a wrong code fails both).
- The plants: `t086-third-side` (the role takes a third side), `t086-code-said` (the giver says its
  code in a line) and `t086-version-unchecked` (a `version` that does not open is taken): 3 caught,
  each by its test.
- `podssh-cli`: `--lib relay_code` 2, `--test relay_code` 5, `--test relay_code_role` 1 passed (each flag where it means nothing, 64; no terminal, 64 before a pair; the
  code read from a pipe and never said; `no`, 78; a whole pair under NAME, 78; a part kept under NAME
  found by `relay status` and `operator`; through `podssh relay serve` on a pty, a code given, taken,
  the node's key pinned, the operator's key in `--allow`, and the status asked by the label).
- Live, a short run (Q65): `--test pair_code_live -- --ignored` through
  `wss://relay.magic-wormhole.io/v1` and Least Authority's mailbox: 1 passed in 4.9 s, "two ends
  paired by a code" at each.
- Repairs at the merge: `Cargo.lock` gains `spake2` 0.4.0 (`cargo deny`: advisories, bans, licenses
  and sources ok); two tests of `Offer`, which has no `Debug` as it can hold a pair's part, take its
  error with `let Err(..) = .. else`; the test that no typed word is echoed checks the words of each
  typed code, as the refusal of an empty code names a fixed example; the case where podssh takes a
  code that magic-wormhole's Python library gives runs on two workers, as it waits on the peer's line
  with no await while podssh's relay role in the same process must answer the peer; the harness's
  `Config` of the role sets T-173's new field; the mailbox's `bind` command is `bind_side`, which the
  repository's check of listeners took for a socket's; clippy's `needless_question_mark` in the hex
  of a code's test. Clippy of both crates with `-D warnings`, and rustfmt: clean. The relay crate's
  whole suite with `serve,plain-ws,quick,pair,grant,piping,code`: no failure; the CLI's `relay` 12,
  `node` 18, `relay_serve` 16, `status` 7, `operator` 12, `net` 9: passed.
- Waits: from end to end on the live relay, `podssh relay pair lab --code` on one host, `podssh
  relay join lab` on another, then `podssh operator lab` through `podssh node lab TARGET`, with the
  release's checks (Q88).

Repaired after the merge (2026-11-04), as the gate of `1ca77a1` failed in three ways that the
merge's runs did not reach: the row of `relay --allow` named `--allow FILE` in its own words, which
the help's check of each flag refuses (`help::tests::no_flag_runs_into_its_description`; the CLI's
whole `--lib` passed after, 837); `OperatorPart::from_wire`, read by the exchange alone, is dead in a
build with `pair` and no `code` (clippy of `--features serve,plain-ws,quick`), and is now of the
feature `code`; and `tests/relay_code_role.rs` used the pty harness, Linux's, on macOS, and is now
Linux's too.

# T-087: Node identity and access: a node key, an allowlist, an expected fingerprint, revocation

**Source:** GitHub #18 (reports on iroh-ssh, GPU-Share, warren and zuko); read in the reports, not
verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

On the reverse road, each holder of the `connect_token` reaches the node, and the operator trusts
whatever answers at the pair's name. The relay issues both tokens. For an SSH target (`podssh serve`,
M5), host keys and user keys give identity and access; for any other TARGET there is none.

## Premise

Read: credentials are HMAC tokens scoped to a name and a role, issued by the relay
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:128-129`); accept a connect token only
over a trusted channel (`:137-138`); the node chooses what to expose (`:245-246`).

Read: `podssh ssh` checks host keys with `known_hosts`, and never records one under the relay's name
(`SECURITY.md:92-96`, `:222-232`). `podssh serve` keeps its host key in a state file and takes
authorized keys from a flag or a file (`docs/ROADMAP.md:180-185`, T-107).

Read in the reports (not verified here): iroh-ssh warns about an ephemeral node key
(`rustonbsd/iroh-ssh:src/ssh.rs`); GPU-Share keeps an Ed25519 identity in a state directory and a
default-deny allowlist (`arjun988/GPU-Share:crates/gpumesh-core/src/node.rs`); warren pins a key on
first sight, has `trust NAME --expect FINGERPRINT` and revocation, and exits 7 on a mismatch
(`willykeenan/warren:src/cli.rs`); zuko stores device authorization for each peer
(`adonm/zuko:src/store.rs`). iroh identifies endpoints by Ed25519 keys (`docs/design.md:1146-1148`).

## Approach

1. Node key: Ed25519, made on the first run, in a private state file of the chain of
   `crates/podssh-relay/src/cache.rs`, lines 61-76 at `4dd52f8`. One key for each road, shared with
   T-163, so the
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

Decided in the work (2026-10-10):
- One Ed25519 key for each role, the same on both roads: a node's for each label, a client's for
  each user. They are the key files of T-163, kept now by `podssh-relay` (no C) under names of no
  road, `node-LABEL.key` and `client.key`; a file under the names of T-163 is still found and used.
  Lost: new keys for the pair's road, which would give one node two identities and two pins.
- A key is shown by its SHA256 fingerprint, in OpenSSH's form (the digest of the key's SSH encoding
  as `ssh-ed25519`), on both roads. An allowlist line, `--node-key` and a pin take the fingerprint
  or the key itself (iroh's hex or base32). Lost: iroh's hex alone (64 digits, which no SSH tool
  shows); fingerprints alone (an iroh ticket carries the key).
- The node's allowlist is `--allow FILE`, for each road, with `--iroh-allow` as its other name.
  With none, the pair's road lets in each operator that holds the connect token, as before (the
  token is the credential), and the node says each operator's fingerprint; a named file that is
  missing or cannot be read lets nobody in. The iroh road still needs the file (T-163). Lost: a
  default file whose presence turns on the refusal: a file in a cache directory must not change
  who gets in unseen.
- The operator pins in `known-nodes`, in the cache's directories: one line for each label, `LABEL
  FINGERPRINT`. The first sight pins (trust on first use, as the relay's contract asks of a connect
  token); a changed key refuses, with the file, the line and both fingerprints, and is never
  replaced. `--node-key KEY` checks against that key, and neither reads nor writes the pins; with
  an iroh ticket, the ticket's key is the one expected. Lost: a pin in the pair file, which would
  rewrite a file that the user names, and gives two places to look.
- A changed node key, and an operator key that the node refuses, exit 77 for `podssh operator` and
  `podssh pipe node:` (the code of a refused host key in `cp`), and 255 for `podssh ssh` (OpenSSH's
  code). Lost: a new code: 76 (`EX_PROTOCOL`) says a fault of the protocol, which this is not, and
  warren's 7 is outside sysexits.
- Approach 7 waits for T-107, which the operator holds: whether the node key is also the host key
  of `podssh serve` is decided there.

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

## Correction

2026-10-10, read in the tree:
- T-163 keeps an Ed25519 key for each role of the iroh road already, in a private file of the
  cache's directories (`crates/podssh-iroh/src/keys.rs`), and an allowlist of client keys
  (`crates/podssh-iroh/src/allow.rs`). This entry shares them, rather than making keys of its own.
- A refused operator cannot get `reject {id, "not allowed"}`: the node answers `ready` before it
  knows the operator's key, which only the channel's handshake gives (the operator's input waits for
  `ready`, and with the layer `ready` goes out at once, `crates/podssh-relay/src/reverse/layered.rs`).
  The refusal is the channel's verdict, encrypted, then the session's close.
- The features `identity` and `e2e` of the Prove are not made: the keys and the channel build in
  each build of `podssh-relay`, with no C, and the commands drop them.

## Done

2026-10-10, built with T-088, whose channel carries the proof, in `8e31960` (the libraries) and the
commit that closes this entry (the ends of `podssh`). The identity of each end is
`crates/podssh-relay/src/identity/` (no C): one Ed25519 key for each role, the key files of T-163
moved from `podssh-iroh` and named `node-LABEL.key` and `client.key`, with the names of T-163 still
read; a key shown by its SHA256 fingerprint, as OpenSSH shows one; a node's allowlist of keys or
fingerprints (`--allow`, read again for each session); an operator's pins (`known-nodes`: the first
sight pins, a changed key is refused with both fingerprints, the file and the line, and no pin is
replaced). In `podssh`: `node --key`, `--ephemeral-key`, `--allow` (with the flags of T-163 as their
other names, now of each road), and `--no-e2e`; `operator`, `ssh node://`, `ssh iroh:` and `pipe
node:`/`iroh:` take `--client-key`, `--node-key` and `--no-e2e`; an iroh ticket names the node's key
on its paths. A changed node key and a refused operator key exit 77 (`operator`, `pipe`) and 255
(`ssh`); a conflict of the flags is a usage error, 64, before anything is read. The node says its
key's fingerprint as it starts, and each operator's key as it comes in or is refused. The facade for
podbox has the same, on by default (`NodeChannel`, `OperatorChannel`). The manual, `docs/cli.md`,
`SECURITY.md` and `docs/STATUS.md` say so.
- Native, Windows 11: `cargo test -p podssh-relay --test identity --test identity_file`: 16 passed
  (two more run on Unix only): the fingerprint of a throwaway key equal to OpenSSH 10.3p1's
  `ssh-keygen -lf`; iroh's hex and base32; the Noise key derived and signed; the allowlist read
  again; the pins. `cargo test -p podssh-cli --test channel_cli`: 5 passed: each conflict of the
  flags is 64 and makes no key; a node key that differs is refused with both keys; each failure of
  the channel has its exit. The refusals of the channel, with no byte of the target, are T-088's
  tests (`a_node_lets_in_only_its_allowlist_and_its_target_sees_no_one_else`). Planted, each check
  fails its test: the fingerprint's encoding, base32's last bits, the signature, a changed pin
  taken, the allowlist skipped, T-163's names not read, the node's admission skipped, a refused key
  exiting 70, a conflict of the flags let through, a named key not checked.
- Live, the live relay: `cargo test -p podssh-relay --features pair --test reverse_live --
  --ignored a_changed_node_key_is_refused`: a first node's key pinned at its first sight; a second
  node with another key under the same pair refused, the line naming both fingerprints and the pin's
  file and line, and the second node's handshake ended before the operator's proof. `cargo test -p
  podssh-cli --test node_live -- --ignored node_command_serves_a_tcp_target`: GitHub's SSH banner
  through `podssh node`, to an operator that expected the key that the node said; planted, the
  channel dropped at the operator, the banner was the node's magic and nothing of the target. By
  hand, the binaries through railway.new: `ssh node://` pinned the node's key and logged in through
  the node; `podssh operator` read the SSH banner and exited 0 (railway.new then refused anonymous
  trials, "temporarily disabled", so `node_live`'s `ssh_to_a_node` could not check `exit 3`; it now
  names that refusal).
- `cargo test --workspace --no-fail-fast`: 1257 passed, 0 failed, 41 ignored. With the
  iroh road: 446 passed, 0 failed, 29 ignored. clippy with `-D warnings`, default, with
  the iroh road and with `ts`: no warning.
- CI's gate at `8e31960` (run 38057438513): its step `libs` built and tested the library crates with
  `CC=/nonexistent` in the build image, the tests of the identity on Linux with them (the key file's
  mode 0600, an allowlist that others can change refused); `msrv` checked Rust 1.85. The push of
  this commit runs the gate again.
# T-088: End-to-end encryption between two podssh ends

**Source:** GitHub #18 (report on warren; read in the report, not verified here);
`docs/design.md:1404-1410`, `:1533-1537`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

The relay sees the bytes of each reverse session. SSH protects itself: an SSH session through a node
is encrypted from the operator's client to the server. A raw TCP TARGET of `podssh node` (T-083),
`podssh pipe` with `node:` (M7) and chat on the roads (T-099) are plain text to the relay.

## Premise

Read: the relay sees the target, the time and volume of the traffic, and the start of an SSH
connection; after the key exchange it sees only ciphertext (`SECURITY.md:21-31`). It can drop, delay
or add frames (`SECURITY.md:33-36`).

Read: the road between two podssh ends carries SSH, `cp`, `pipe` and chat (`docs/design.md:1404-1410`);
for chat, the operator chose the roads, end to end encrypted, after M6 (`docs/design.md:1536-1538`).
The resumable layer of M6 runs under SSH (`docs/design.md:674-686`).

Read in the report (GitHub #18, not verified here): warren uses `Noise_IK_25519_ChaChaPoly_BLAKE2s`
so that the relay cannot read a stream (`willykeenan/warren:src/noise.rs`).

Read: the library crates must build with no C compiler (`AGENTS.md:307-309`, `scripts/gate.sh:133`).

## Approach

1. A Noise IK channel for each reverse session, in crates/podssh-relay/src/reverse/e2e.rs. The
   operator knows the node's static key from the pair file or a pin (T-087); the node's allowlist
   lists the operators' keys.
2. Library: the `snow` crate with its pure-Rust resolver only. Check it under `CC=/nonexistent` in
   the gate before it is chosen; else RustCrypto parts with the IK handshake written here, and the
   test vectors of the Noise specification.
3. Messages: each Noise message at most 65535 bytes, with a length prefix, inside the session's
   bytes. The relay's frames on the operator leg stay bare (`docs/reverse.md:120`).
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

Decided in the work (2026-10-10):
- Noise XX, not IK: at the first contact the operator has no node key to start from (trust on first
  use, T-087), and XX carries both static keys encrypted. One pattern for each session, for half a
  round trip more: `Noise_XX_25519_ChaChaPoly_SHA256`. Lost: IK, which needs the node key first,
  with XX as a fallback (two patterns to test).
- The library is `snow` 0.10 with its own resolver, and only ChaChaPoly, SHA-256 and Curve25519
  (`default-features = false`): its feature `std` turns on `ring`, which compiles C. Lost: a
  handshake written here, which would be protocol code that only podssh tests.
- The channel runs above the resumable layer: one handshake for each session, and a resume carries
  the same channel on, as the layer gives each byte once and in order. The relay sees the layer's
  records (offsets, acknowledgements, heartbeats) and ciphertext. Lost: a channel for each link,
  under the layer: a handshake at each resume, with the resume's proof inside it, for nothing that
  the relay learns less.
- The Noise static key is derived from the Ed25519 seed (HKDF-SHA256, a label of its own), and the
  Ed25519 key signs it; the Ed25519 key and the signature go in the handshake's encrypted payloads.
  The identity is then T-087's key on both roads, and no key does two jobs. Lost: the Ed25519 key's
  Montgomery form as the Noise key, one key for signatures and for key exchange, which
  `ed25519-dalek` advises against.
- On the wire: `podssh-e2e/1` and a newline, then frames of a 2-byte length and one Noise message
  (65535 bytes at most). Each message of the transport has a type: the node's verdict (let in, or
  refused with the reason), data, or the clean end of one direction. A stream that ends with no
  such end is a cut, never a clean end: the relay can drop the last frames.
- On by default between two podssh ends, on both roads, the facade for podbox included. `--no-e2e`
  turns it off, at both ends: an end with the channel refuses a peer without it, and never falls
  back to plain text, which the relay could force.

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

## Correction

2026-10-10, read in the tree:
- T-151 closed without the choice of Approach 4 (its entry names no channel); this entry makes it
  (the Decision), and `docs/design.md` (section 5) records it.
- The channel lives in crates/podssh-relay/src/e2e/ (new), not under `reverse/`: a node serves the
  iroh road's sessions with the same keeper as the pair's (T-164), so the channel serves both.
- XX replaces IK (the Decision), and the vectors are those of `Noise_XX_25519_ChaChaPoly_SHA256`.
- No feature `e2e` is made (T-087's correction); the commands drop it.

## Done

2026-10-10, built with T-087, in `8e31960` (the libraries) and the commit that closes this
entry. The channel is `crates/podssh-relay/src/e2e/`: Noise XX through `snow` 0.10 with ChaChaPoly,
SHA-256 and Curve25519 only (no `ring`, no `cc` in the tree); each end sends its magic first, the
node at once; the handshake with each end's proof of its key; the node's verdict (let in, or
refused: not allowed, no target, other); data, and the clean end of each direction, with the stream
shut when both ended (the half-close of TCP, which the layer alone lacks); a cut is never an end.
It runs above the resumable layer, one handshake for each session (`docs/design.md`, section 5),
on both roads: the node's handler `podssh_relay::reverse::E2e`, and in `podssh` each session of the
node is a pipe whose channel reaches TARGET once the operator's key is let in, on the iroh road too,
as one keeper serves both. Each client of a node runs it: `operator`, `ssh node://` (and its race),
`ssh iroh:`, `pipe node:` and `pipe iroh:`, and the facade. On by default; `--no-e2e` at both ends
turns it off, and an end with the channel refuses a peer without it. `docs/reverse.md`,
`SECURITY.md`, the manual and `docs/STATUS.md` say so.
- Native, Windows 11: `cargo test -p podssh-relay --features pair --test e2e --test e2e_faults --test
  e2e_layered`: 19 passed, and 10 runs in a row: the cacophony vector of
  `Noise_XX_25519_ChaChaPoly_SHA256`; 3 MiB through a stand-in relay that recorded no plain text; a
  changed bit, a dropped, a repeated and a moved frame, and a cut, each ending the session with no
  byte of the bad frame given on; a wrong node key refused before this end's proof; a replayed proof
  of another key refused; a peer with no channel refused at both ends; a stream that ends before the
  peer's magic is a cut, so the road's reason is said (the iroh road's suite found the defect: a
  client that the node's allowlist refused was told that the node spoke no channel); the node speaks
  first; 8 MiB
  each way above the layer through cut links, with one handshake and one connection to the target.
  `cargo test -p podssh-cli --test node_plain`: a node with no layer and the channel, through the
  stand-in relay of the tests, in 2 s (before the node spoke first, the layer's client and the node
  waited for each other for 30 s). `cargo tree -p podssh-relay -i ring` prints nothing, and
  `CC=/nonexistent cargo build -p podssh-relay --features blocking,plain-ws` passes. Planted, each
  check fails its test: the tag's check skipped (a bad frame passed over), the signature's check
  skipped, the operator's check skipped, a cut taken for an end, the admission skipped, the magic
  not checked, the node silent first, an end before the magic taken for a peer with no channel.
- Live, the live relay: `cargo test -p podssh-relay --features pair --test reverse_live -- --ignored
  e2e_through_the_live_relay`: 1 MiB each way over the channel, a clean close. `--features blocking
  --test blocking_live -- --ignored`: the facade's node and two operator sessions at once over the
  channel, 1 MiB each way. The binaries: see T-087.
- The gate, as `sh scripts/dev.sh check` runs it, passed in CI at `8e31960` (run 38057438513): the
  step `libs` built and tested `podssh-relay` with the channel and `snow` with `CC=/nonexistent` in
  the build image, `msrv` checked it on Rust 1.85, and `plant` still failed on a planted C crate.
  The push of this commit runs the gate again.
# T-089: A node offers several named targets, each with its own grant

**Source:** GitHub #19 (report on syq) and GitHub #18 (report on warren); read in the reports, not
verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

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
frames (`docs/reverse.md:120`). Data needs `ready` first (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:180`), and `ready` comes
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

2026-10-12, the calls made in the work, with T-087 and T-088 done:

- Routes inside the channel, one pair and one socket (step 3). The route
  rides in the operator's proof of its key, the third message of Noise XX,
  not in the first (step 3's words): the first message is in clear, so the
  relay would read the route there, and the third is encrypted and bound to
  the operator's key. A proof that names a route has a version of its own
  (2); a node of an earlier podssh refuses it as a proof that it does not
  read, and an operator that names no route sends the proof of before.
- `ready` already meant "the node's podssh layer is up" since T-153 and
  T-088: the node answers it at once, and dials only after the layer's
  handshake and the channel's verdict. `docs/reverse.md` says so now.
- The node checks the key first (the allowlist, as before), then the route:
  a route that the node does not have and one that the key may not use are
  refused with the same words, so that an operator learns no route that it
  may not use, and nothing is dialled. An operator that names no route
  reaches the TARGET with no route, and is refused when the node has none.
- The grants are in the allowlist of T-087, not in a file of their own: a
  word `routes=A,B` after the key, or `routes=*`. Each line of before keeps
  its meaning, as the words after a key were a comment: a key with no
  `routes=` reaches the TARGET with no route alone (deny by default). A key
  on two lines has the routes of both; a list that is not one makes its
  line a bad one. With no allowlist, each operator with the pair's connect
  token may use each route, as it may reach the TARGET today.
- The operator names a route as `NAME/ROUTE` in `podssh operator`, in
  `podssh ssh node://[user@]NAME/ROUTE` and in `iroh:TICKET/ROUTE`; both
  roads of a node take routes, as a session may move from one to the other
  (T-164). The known hosts keep each route's host key under
  `node://NAME/ROUTE`, as each route may be another SSH server. `pipe`'s
  `node:` and `iroh:` addresses name no route yet: a new entry if asked.
- Each TARGET is dialled once at the start, and the node exits 69 when one
  cannot be reached, as it did for the one TARGET.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,e2e --test routes
cargo test -p podssh-cli --test node -- routes
```

Offline: two routes reach their own TARGET; an unknown route, and a route that the operator's key
may not use, end with a reason and no dial of a TARGET; a change of the grant file applies to the
next session. Plant: ignore the grant; the refusal test must fail.

## Done

2026-10-12. The route in the channel's handshake: the proof that names one
at `crates/podssh-relay/src/e2e/handshake.rs:27-32`, made at
`crates/podssh-relay/src/e2e/handshake.rs:303-312` and read at
`crates/podssh-relay/src/e2e/handshake.rs:339-417`; the node's side of a
routed session at `crates/podssh-relay/src/e2e/ends.rs:103-203`, and the
operator's at `crates/podssh-relay/src/e2e/ends.rs:194-202`. The grants at
`crates/podssh-relay/src/identity/allow.rs:33-64` and
`crates/podssh-relay/src/identity/allow.rs:114-122`. The routes of a node,
their check and their dial in `crates/podssh-relay/src/reverse/routes.rs:1-126`.
The command line: the targets at `crates/podssh-cli/src/node.rs:210-246`,
`NAME/ROUTE` at `crates/podssh-cli/src/node.rs:248-263`, the dial of each
target at `crates/podssh-cli/src/node_target.rs:14-39`, the routes at
`crates/podssh-cli/src/node.rs:267-275`; the channel's glue at
`crates/podssh-cli/src/channel.rs:331-340` and
`crates/podssh-cli/src/channel.rs:384-403`; `node://NAME/ROUTE` at
`crates/podssh-cli/src/ssh/node.rs:36-67`, and `iroh:TICKET/ROUTE` at
`crates/podssh-cli/src/ssh/iroh.rs:59-80`. The manual's notes of `node`
and `operator`, the file of `--allow`, `docs/cli.md` and
`docs/reverse.md`.

The test `crates/podssh-cli/tests/node_routes.rs` (not `node.rs`, whose
tests run with no stand-in relay), through the stand-in relay on the
loopback: one pair, a node with the routes `web`, `db` and `ssh` and an
allowlist; this client's key is refused while the list has no key, then
`podssh operator lab/web` gets the bytes of `web` alone; `lab/db` (not
granted), `lab/nope` (no such route) and `lab` (no TARGET with no route)
are refused with their words, and `db` saw no connection but the node's
first; `routes=*` in the list lets `lab/db` in at the next session; and
`podssh ssh node://tester@lab/ssh greet` logs in to the tests' SSH server,
its host key kept under `node://lab/ssh`. In `crates/podssh-relay/tests/routes.rs`,
over the channel: the node gets the route that the operator named, with
the operator's key, and its target; a route that the node refuses, and one
named to a node with no routes, end with the refusal and no target; a name
that is not a route never leaves the operator. In `tests/identity.rs`, the
grants of `routes=`, `routes=*`, two lines and a bad list. In
`crates/podssh-cli/tests/node.rs`, the refusals of the command line (64):
a route given twice, two TARGETs with no route, a name that is not a
route, a TARGET with no port, and a route with `--no-e2e`, for `node`,
`operator` and `ssh`. Planted defect: the node ignores the grant; the test
of the routes failed at `lab/db`. Here, clippy of `podssh-relay` and
`podssh-cli`, with and without the feature `iroh`: no warning; the suites
of `podssh-relay`, `podssh-cli` and `podssh-ssh`: 1039 passed, 0 failed, 45
ignored (the live tests); with the feature `iroh-test`, those of
`podssh-iroh` and `podssh-cli`: 669 passed, 0 failed, 37 ignored, once
five tests of the iroh road made their scratch directories private: this
host's temporary directory lets another account change its files, and the
node refused their allowlists (`others can change it`), as it should.

# T-090: Find a node by name with no payload leak

**Source:** GitHub #18 (reports on GPU-Share and iroh-ssh) and GitHub #23 (report on cubic); read in
the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

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
and podssh must probe before it uses UDP (`AGENTS.md:277-278`).

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

2026-10-12, the calls made in the work: steps 1 and 2 were built by T-083
and T-087, and this entry proves them and states them (step 5). The pins
name a label and a key, never a pair, so a new pair from the same node key
needs no new trust step with no code of its own; the node keeps its key
across its pairs (`node-NAME.key`). The delivery of a new operator's part
through the relay waits for T-086 (the relay's operator); a file does it
now. No directory and no mDNS are built, as the Decision says; mDNS as an
option is not built either, as no sandbox that podssh serves lets UDP out.
The relay's test runs with the feature `pair` alone: there is no feature
`identity`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node -- labels_survive_a_new_pair
cargo test -p podssh-relay --features pair,identity --test identity -- a_new_pair_from_a_pinned_key_needs_no_new_trust
```

Offline: a label maps to the newest pair; a new pair with the same node key updates the operator's
label with no prompt; a new pair with another key is refused (T-087); no file, output or log holds a
token outside the private store. Plant: accept a new key with a new pair; the second test must fail.

## Done

2026-10-12. `docs/reverse.md`, "Finding a node": what a label, a pin, a
new pair's operator's part, a directory and mDNS show to whom. The test
`labels_survive_a_new_pair` (`crates/podssh-cli/tests/node.rs`): an
expired pair under `lab` is a FAIL of `doctor`; a new pair kept under the
same label takes its place, `doctor` gives its expiry, and `operator lab`
and `node lab` find it and go as far as the network (69, offline), with no
word of an expired or missing pair; no output names a token. The test
`a_new_pair_from_a_pinned_key_needs_no_new_trust`
(`crates/podssh-relay/tests/identity.rs`, feature `pair`): the first pair
pins the node's key by label; after a second pair under the label, the
label's pair is the second, the same key is known with no new pin, another
key is refused, and the pins hold no token and no pair's name. Planted
defect: a changed key accepted with a new pair; the second test failed.
`cargo test -p podssh-relay --features pair --test identity`: 10 passed,
0 failed; `cargo test -p podssh-cli --test node`: 11 passed, 0 failed.

# T-226: Pairing grants that are signed and used once, not bearer tokens that can be replayed (GitHub #35)

**Source:** GitHub #35 (2026-10-08) and the reporter's own comment; each cited line checked here on `3ee70dc`.
Not measured: no pairing ran.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

Each credential of the relay is a bearer token: whoever holds it can use it, as often as they like, until it
expires; the three tokens of a pair too. Nothing binds a token to a peer, limits it to one use, or finds a
replay. A token that leaks from a log, a shell history or a copied file stays valid for up to 72 h.

## Premise

Read: `POST /v1/mint` gives `{token, expires, scope}` as `ephm1.<expiry-ms>.forward.<mac>`, checked at each
upgrade, 72 h at most (`docs/relay.md:430-434`); `POST /v1/pair` gives the three tokens of a pair, 72 h at most
(`docs/relay.md:606-609`). The contract scopes reverse tokens to a name and a role, and states no single use and
no binding to a peer (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:128-129`). A new mint secret
ends each token at once (`docs/relay.md:594-596`). A text frame from the operator closes its socket with
`1003`, and the operator leg carries no framing (`docs/relay.md:623-626`, `docs/reverse.md:120`).

Measured: `grep -rni sshsig crates scripts docs Cargo.toml` finds nothing (exit 1). The wider `sign(` hits are
tests of primitives (`crates/podssh-ws/tests/crypto_vectors.rs:125-159`,
`crates/podssh-ws/tests/signatures.rs:29-172`); the comment's `crypto_vectors.rs:192` is not one. Read: the
issue's "rule 8" is rule 6 (`docs/architecture.md:289-294`), and its "section 2" sentence about an allowlist of
keys is in section 7 (`docs/design.md:1367-1368`). Read in the report (not verified here): syq signs a grant in a
fixed namespace and redeems it at most once with `flock`, `O_EXCL`, `linkat` and `fsync` (lines 55 at `22c3b88` and
1416-1492 of `greaber/syq:src/delegation.rs`). The reporter's correction: a signed grant leaks as a token does
(lines 11-12 at `22c3b88`); signing buys scope, single use and non-repudiation, not safety after a leak.

Read, what a leaked token gives today. `connect_token`: sessions to the node; an SSH server's own
authentication still stands, but a raw TCP TARGET (T-083) has no other gate. `node_token`: an impersonated node
while the real one is away (one socket for each name, and a new node gets the new sessions: `:152-156` of the
contract); for SSH, the operator's host-key check finds it (`SECURITY.md:92-96`). `stop_token`: a denial of
service; the node, its sessions and the pair end (`docs/relay.md:634-638`).

## Approach

The operator ruled on 2026-10-08: not in M4; M4 keeps the relay's tokens, the trust is end to end (T-087,
T-107), and the relay stays a separate project (`docs/decisions.md`). The two shapes, for the relay's operator:
1. On the relay: an endpoint in place of `POST /v1/pair` that returns a signed grant naming the node, the
   principals that may use it (key fingerprints, T-087), an expiry and a nonce. The relay records the nonce as
   spent and refuses a second use. podssh caches the grant and sends it in a header or a 0600 file, never in
   a URL (`docs/relay.md:440-442`, `docs/architecture.md:289-294`).
2. On the client: keep the pair's tokens, and add a signed grant inside the operator leg, which the relay has
   authenticated. A text frame closes that leg with `1003`, so the grant needs a typed binary header at the
   start of the session: a change of the framing in crates/podssh-transport/src/framing/legs.rs lines 60-76 at `e8bbd4d`. The
   node checks the grant before it dials the TARGET, so the dial moves after `ready` (`docs/reverse.md:16`):
   the seam of T-088 and T-089. Spent nonces are create-new private files
   (`crates/podssh-relay/src/cache.rs:352-370`).
3. Both shapes: an SSHSIG signature in a fixed podssh namespace, which `ssh-keygen -Y verify` can check
   (T-020), with the keys of T-087, in pure Rust (`AGENTS.md:307-309`).
4. Relations: T-078 makes the pair that a grant protects; T-086 can deliver a grant in place of the
   `connect_token`; T-087 gives the keys that a grant names.

## Decision

Recommendation: the relay's shape, after M4 and by the relay's operator, as the ruling leaves it, because only
the relay can make a token single use for each client. The alternative, the client's shape, lost: the relay
still accepts a replayed `connect_token`, so that grant protects only the TARGET, which the allowlist of T-087
already protects, at the cost of a framing on a leg that the contract keeps bare.

2026-11-03 (the drafting agent), for what the Correction below leaves open. No row of `docs/decisions.md`
settles these and none changes one: Q4 keeps the relay's tokens and the trust end to end, which a grant is.

1. The reader of the certificate is podssh's own (`crates/podssh-relay/src/grant/cert.rs`), not the `ssh-key`
   crate. Only the Ed25519 certificate is a grant, its form is a page of OpenSSH's PROTOCOL.certkeys, and the
   crate (the patched copy in `vendor/ssh-key`) would bring its features and a change of `Cargo.lock` into a
   library crate that the gate builds with no C. The same bytes as `ssh-keygen -s` gives are its test. Lost:
   the crate, for those reasons.
2. A grant's use is recorded by the SHA-256 of what its issuer signed, which holds the issuer's random nonce,
   not by its serial: `ssh-keygen -s` gives serial 0 unless `-z` is given, so a record by serial would refuse
   each grant after an issuer's first. The serial names a grant in the lines and in `--revoked`. Lost: by
   serial (that reason); by issuer and serial, with 0 refused (one more flag at each mint).
3. A grant decides alone: one that fails is refused, also for a key that `--allow` names, as the operator
   asked by it. A node that reads no grant (the temporary node of `--upgrade`, chat) sets one aside and goes
   by its door. Lost: a failed grant that falls back to the allowlist, which hides the refusal from its user.
4. The issuers are the node's own key, and a key of `--allow` or a member of the net for what that key may
   reach itself, with no word of its own on the allowlist's line; a node with no `--allow` and no net trusts
   its own key alone. A key of the allowlist can carry its own access to another already, so a grant gives
   it nothing more. Lost: a mark on the line, as sshd's `cert-authority`, a new form of the file that the
   allowlist's readers of T-087 refuse.
5. The use is recorded before the dial: a TARGET out of reach spends the grant, and its issuer mints another,
   as a retry with the same grant is a replay to the node. Lost: the record after the dial, where a replay
   reaches TARGET's door.
6. The operator hears one sentence for each refused grant (`GRANT_REFUSED`, exit 77), and the node's log the
   reason, as a reason can name the node's files. Lost: the reason itself in the verdict.
7. A grant must end (no `valid_before` of forever), with 5 minutes of skew at each end of its window; `podssh
   node --grant-to` gives 1 h, and takes 1 minute to 30 days. A record goes after its grant's end and the
   skew, when the window refuses the grant.
8. A client reads its grant once, before anything connects, and the run's first channel takes it: a grant
   lets in one session, so a copy of several files or a listening `pipe` sends it in its first. `cp`, `mv`,
   `scp` and `sftp` take no `--grant`.
9. The proof's version is 4, around a proof of each other form, as version 3 is the net's (T-429). A node of
   before refuses it whole, and an operator sends it only with `--grant`. Lost: a message of its own after the
   handshake, which a node of before reads as a fault of the channel.
10. `podssh node NAME --grant-to KEY` in the place of `podssh node grant`: `node` takes NAME first, as
    `--install` does, and a node may be labelled `grant`.
11. In the relay role, the connect token of a pair of `--once` is spent at the first upgrade that the role
    takes, and refused at the status too after it; the status before it spends nothing. The file of `--pairs`
    keeps the use, and one that takes no write refuses the upgrade. `?once=1` asks for it, as the body stays
    the contract's `{}` and the proof of a key (T-448) signs the path. A connect token for each session, and a
    stop token that the node rotates, which the Correction names, are T-615: they need frames of the node's
    socket that the contract does not have.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,grant --test grant
cargo test -p podssh-relay --features pair,grant --test grant_live -- --ignored
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_once
```

Offline: a grant verifies once; a second use of its nonce fails; a grant for another node or principal, or
after its expiry, fails; a grant in a URL is refused before a request exists. Plant: skip the spent-nonce
check; the replay test must fail. Live, the relay's shape only: a second use of one grant gets its refusal.

## Correction

2026-11-02 (the drafting agent). Until that day this entry was blocked, and its `## Blocker`
read, moved here as `cargo todo check` refuses a Blocker on an open entry:

> The relay's operator: an endpoint that gives a signed grant, used once. The operator ruled on
> 2026-10-08 that M4 keeps the relay's tokens (`docs/decisions.md`).

Lifted on 2026-11-02 by Q63: see below.

The Premise holds at its lines. By Q63 (2026-11-02, `docs/decisions.md`; docs/mesh.md,
sections 1 and 3) the relay is a role of podssh itself, so this entry is podssh's work, in two
parts, and the Decision above (the relay's shape, by the relay's operator) gives way to both:

- At the node. The seam that the client's shape lacked exists: the e2e channel carries an
  encrypted proof of the operator's key, with a version byte
  (`crates/podssh-relay/src/e2e/handshake.rs:28-32`), so a third version carries a grant that no
  relay sees. A grant is an OpenSSH user certificate over the grantee's Ed25519 key, signed by an
  issuer that the node's allowlist names (`crates/podssh-relay/src/identity/allow.rs:1-8`) or by
  the node's own key: a principal `node:SHA256:<the node's key>` (with `/ROUTE`), a validity
  window that it must have, a random serial, and the critical option `once@podssh`. OpenSSH's
  `ssh-keygen -s ... -O critical:once@podssh` mints one, and so does `podssh keygen -s`
  (`crates/podssh-cli/src/keygen_cert.rs:1-6`). The node checks it before it dials, records the
  serial in a create-new private file (`crates/podssh-relay/src/cache.rs:352-358`), and refuses
  a second use. Bound to the grantee's key, a leaked grant is worth nothing without that key,
  which answers the reporter's correction; a resume of the layer runs no new handshake, so a
  used grant ends no resumed session.
- In podssh's relay role (T-427): the pair's tokens used once where the pair asks for it, a
  `connect_token` for each session, and a `stop_token` that the node rotates inside the e2e
  channel, so a leaked token dies at the next rotation. A replayed token reaches the node's door
  at most, and the grant and the allowlist hold it.

The new Approach, in place of the one above:

1. A grant's reader and a store of spent serials in `podssh-relay`, pure Rust (the `ssh-key`
   crate with `ed25519` alone, or a reader of the Ed25519 certificate if that crate brings C);
   the proof's version 3 in the e2e handshake.
2. The node's check, in this order: the key that Noise proved is the certificate's; the
   issuer's signature; the type user; a principal for this node (and route); the window, with 5
   minutes of skew; each critical option known; then the spent record, written and synced, and
   only then the admission. A crash between the two burns the grant.
3. `--grant FILE` on `podssh operator`, `ssh node://` and `pipe node:`; `podssh node grant` on
   the node; a raw TCP TARGET with no `--allow` gets a warning. Revocation: remove the issuer's
   line, or name the serial in a file that the node reads for each session.
4. Tokens used once in podssh's relay role (T-427), offered in `/relays.json` and asked for at
   the pair's making.
5. What `tcp.ssh.relay.ajam.dev` lacks here is no blocker: a note of docs/relay-operator.md
   (item 9).

The new Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,grant --test grant
cargo test -p podssh-relay --features pair,grant --test grant_live -- --ignored
```

Offline: a grant that OpenSSH's `ssh-keygen -s` minted, software that podssh did not write,
admits its key once; a second use, another node's principal, a window that ended, an unknown
critical option, and a certificate of another key are refused; a grant in a URL is refused
before a request exists; through podssh's relay role (T-427) on the loopback, a `connect_token`
of one use is refused at its second upgrade. Planted: the spent check skipped; the replay test
fails. Live, on a GitHub runner where `podssh relay serve` runs: a node and an operator, one
grant used, then refused.

2026-11-03 (the drafting agent). Read at `d262613`: the proof's version 3 is the net's form (T-429,
`NET_PROOF` in `crates/podssh-relay/src/e2e/handshake.rs`), so a grant is the proof's version 4, around a
proof of each other form (Decision 9). Item 3 of the new Approach is `podssh node NAME --grant-to KEY`,
with `--grant-route` and `--grant-for` (Decision 10), and `--revoked FILE` names the serials. Item 4 is a
pair of `--once` in podssh's relay role (`POST /v1/pair?once=1`); the connect token for each session and
the stop token that the node rotates moved to T-615 (Decision 11). The Prove adds the role's test,
`relay_serve_once`, which needs the features `serve` and `plain-ws` on the loopback. The offline grants are
certificates that OpenSSH 9.6's `ssh-keygen -s` minted, kept with their issuer's public key alone
(`crates/podssh-relay/tests/fixtures/grant/`), so the test needs no `ssh-keygen` where it runs; the live
test runs through the live relay, which carries the channel as each relay does, in the place of a runner
of `podssh relay serve`.

## Done

2026-11-03, drafted (`DRAFT T-226`, `d4da618`) and merged by the main session, which repaired two
findings of clippy (a `contains`, and a type of the test's cases) and formatted two files.

- The grant in `podssh-relay` (feature `grant`, `crates/podssh-relay/src/grant/`): the reader and the writer
  of the Ed25519 user certificate, the node's door in the order of the Approach, and the record of each grant
  used; the proof's version 4 in `crates/podssh-relay/src/e2e/handshake.rs`, the door's hook `Redeem` of
  `crates/podssh-relay/src/e2e/ends.rs`, and a route that a grant named in
  `crates/podssh-relay/src/reverse/routes.rs`. `cargo test -p podssh-relay --features pair,grant --test
  grant`: 9 passed (a grant that `ssh-keygen -s` of OpenSSH 9.6 minted lets its key in once, the relay never
  sees it, a second use is refused, also by a node started again; another node, a window that ended or is to
  come, an unknown critical option, no `once@podssh`, no end, a host certificate, another key, an issuer not
  trusted, a changed serial and no certificate are refused before the dial; the node's own key issues; a
  route's grant; no grant, and a node that reads none; a revoked serial; podssh's writer gives the bytes of
  `ssh-keygen -s`; a URL is refused). `cargo test -p podssh-relay --features pair,grant,serve --lib`: 191
  passed.
- In the relay role: `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_once`: 2
  passed (a connect token of one use refused at its second upgrade and at the status, a pair of before,
  `/relays.json`).
- In the binary (`crates/podssh-cli/src/grants.rs`): `--grant FILE` of `operator`, `proxy node://`, `ssh
  node://` and `pipe`'s `node:` side; `podssh node NAME --grant-to KEY`, `--grant-route`, `--grant-for` and
  `--revoked FILE`; each node's door on the pair's, the DERP, the OpenTunnel and the iroh roads; `podssh
  relay pair NAME --once`. `cargo test -p podssh-cli --lib`: 801 passed; `--test flag_table` 9, `--test
  node` 18, `--test operator` 12, `--test net` 9, `--test derp_road` 6, `--test relay_serve_node` 5, the
  manual's 21.
- The relay crate's whole suite with the feature, target by target: 73 targets, 632 passed, none failed.
- Live, from this session's host: `cargo test -p podssh-relay --features pair,grant --test grant_live --
  --ignored`: passed (5 s); one grant let its key in through the live relay, and its second use was
  refused, "used already". The live relay answered the pair's stop with `stopped: false`; the pair ends at
  its 72 h.
- Planted (`sh scripts/plant-each.sh --here t226-spent-skipped t226-key-unbound t226-once-reused
  t226-route-unmarked`): 4 caught.
- `cargo clippy -p podssh-relay --features serve,plain-ws,quick,pair,grant --all-targets` and `-p
  podssh-cli --all-targets`, with `-D warnings`, and `cargo fmt --check`: clean. The gate's check on the
  libraries' Rust takes the feature `grant` too.

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

# T-271: A client can reach a node before it is online, and a node takes a slow local side of the layer for a stopped one

**Source:** CI's gate at `a220c13` (run 38016375327, step `m6`), and native runs on 2026-10-10.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The control of M6's exit, `with_no_fault_the_layer_carries_the_session`, fails at random: in CI
the relay refused its client with `1011 node unavailable`, and on a loaded host its session lost
a link with no fault, which the control refuses. The gate is red when either comes, and a user's
session through a node loses a link that it need not lose.

## Premise

- Measured: CI's step `m6` at `a220c13` failed in that test with `relay close 1011: node
  unavailable`; the step had passed at each push since T-156.
- Read: `podssh node` prints its `serving` line after its probe of TARGET, before its socket to
  the relay opens (`crates/podssh-cli/src/node.rs:317-322`), and the tests waited for that line
  (`crates/podssh-cli/tests/m6_exit.rs:99`, `crates/podssh-cli/tests/node_plain.rs:41`,
  `crates/podssh-cli/tests/pipe_remote.rs:194`).
- Measured, native, 2026-10-10: on a host at 42 % of its CPU, the control lost a link in each of
  7 runs, at HEAD too, and the node had closed the session with `the node's local side does not
  read`. The node's queue for a local side held 32 frames, about 1 MiB, and a client of the
  resumable layer sends up to its replay window, 4 MiB, with no acknowledgement
  (`crates/podssh-relay/src/session/replay.rs:15-18`).

## Approach

1. The node says `online` once the relay has its socket (`online again` after a loss), and each
   test that starts a client after a node waits for that line.
2. The node's queue for each local side counts bytes, not frames, and its handler says how many
   (`Handler::queue_bytes`: 1 MiB by default, as before); the layered handler holds twice its
   window.
3. The control prints the stand-ins' logs when it fails, and the stand-in relay's stderr goes to
   a log of the session.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_node
cargo test -p podssh-cli --test m6_exit -- --ignored --test-threads 1
```

A local side that reads late keeps its session within its handler's window, and one that stops
still ends alone. The control passes where it failed. Plant: wait for `serving` alone with the
node's tunnel stalled 4 s, and the client gets `node unavailable`; a node that ignores the
handler's window fails the new test.

## Done

2026-10-10. Two causes, each repaired.
- The node says `online: the relay takes this pair's sessions` once its socket is open
  (`online again` after a loss; `crates/podssh-relay/src/reverse/node.rs`), and the tests that
  start a client after a node wait for it: the control of M6's exit, `node_plain`,
  `pipe_remote`, and `road_race`, which waits for the ticket and that line in either order.
  The notes of `node`, `docs/cli.md` and `docs/reverse.md` say so.
- The node's queue for each local side counts bytes (`crates/podssh-relay/src/reverse/serve.rs`),
  as many as its handler says (`Handler::queue_bytes`): 1 MiB by default, as the 32 frames held
  before, and for the resumable layer twice its window
  (`crates/podssh-relay/src/reverse/layered.rs`), so a local side that reads late is not taken
  for a stopped one.
- The control prints the stand-ins' logs when it fails, and the stand-in relay's stderr goes to
  a log of the session (`crates/podssh-cli/tests/throughput_harness/cells.rs`): its frames
  showed the node's close and its reason.
- Native, Windows 11: `cargo test -p podssh-relay --features pair --test reverse_node`, 8
  passed, the new `a_slow_local_side_keeps_its_session_within_its_handler_s_window` with them,
  and the old test of a local side that stops; planted, a node that ignores the handler's
  window fails the new one. The control: 4 runs in a row passed on the host where it had lost a
  link in each of 7; the whole of `--test m6_exit -- --ignored`, 7 passed in 387 s. Planted, the
  node's tunnel stalled 4 s and the wait for `serving` alone: `relay close 1011: node
  unavailable`, as in CI. `cargo test --workspace`: 1119 passed, 0 failed, 37
  ignored.
- Linux, in the build image: clippy with no warning, `podssh-relay` with each feature; the node
  tests. T-177's checks of the gate ran there too, with a user `podtest`: both passed.
- CI at `9460b4e` (run 38019504447): the step `m6` passed, 11 of 11 in 671 s, the control with them.

# T-395: A pair's expiry ends a node for good: warn before it, and pair again where the relay allows

**Source:** the operator, 2026-11-01: the study of Nemo-010/d-mon (T-389's Source); its seventh
finding.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A node whose pair expires exits 77, which its unit does not restart: a lockout on a date that
podssh knew in advance, and said nowhere.

## Premise

- Read, at `ea2bd4f`: a unit of T-121 does not restart after 77 (`crates/podssh-cli/src/node_install/text.rs:108`).
- Read: the node's hook for a new pair is unset (`crates/podssh-cli/src/node.rs:347`, `repair:
  None`).

## Approach

Read the pair's expiry from its record; a line at start and each day once fewer than 14 days
remain, and `podssh status` names it. Where the relay renews a pair (`docs/relay.md`), the node
renews it 7 days before the expiry, and keeps the new record; else the line says the command that
renews it by hand.

## Decision

2026-11-01, by the facts of the Correction:

1. The node's lines at 24 h, 6 h and 1 h before the expiry, the first at once when the node starts
   inside one of them, each naming `podssh relay pair NAME --operator-file FILE`. Lost: a line each
   day from 14 days, as a pair never lives 3 days.
2. The relay renews no pair, so the node renews none: a new pair has a new name and a new connect
   token, which reach the operator by a person (T-086 waits for the relay's operator). Lost: the
   node making its own next pair at the expiry and writing the operator's part to a file of its
   own; nobody reads that file on time, and a pair made that way would leave the operator with a
   dead name all the same.
3. `podssh relay pair NAME` makes the next pair in the last 24 h of the stored one, which it
   replaces in the store; the node takes it at the expiry through the repair hook of
   `reverse::run`, which T-079 left unset, with no new start. Lost: refusing until the expiry, as
   before: then the next pair can only come after the node ended, and on a server that only the
   node reaches nobody can run the command any more. The old pair's stop token goes with the
   replaced record: it ends at its expiry, within 24 h; keeping it beside would need a second
   record per label.
4. With no next pair at the expiry the node still exits 77: a unit starts it again (T-393), and
   the next start takes a pair made later. A detached `--restart` run stops there (T-390's 77);
   the lines before the expiry are its remedy.
5. A node that the relay stops deletes the stored pair only while it is the node's own, since the
   label may hold the next one.
6. `podssh status` gives `pairs`: each label, its expiry, `expired`, and `next_now`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_expiry
cargo test -p podssh-cli --test node -- the_next_pair_may_be_made_in_the_last_day_only status_names_each_stored_pair
cargo test -p podssh-cli --lib node_expiry
```

## Correction

Since T-393 the unit starts the node again after 77 too, each 5 s, as do the LaunchAgent, the
crontab's line each 5 minutes and the Windows task: a pair made again with `podssh relay pair
NAME` is taken at the next start, with no new `--install`. The expiry still stops the service
until somebody makes that pair, and says nothing before it: the Problem stands.

And the Approach's times do not fit: a pair lives 72 h at most (`docs/relay.md`, the reverse path:
`POST /v1/pair` gives `expires`, 72 h ahead), so "fewer than 14 days" holds from its start; and
the relay renews no pair (no such request in its document). Before this entry, `podssh relay pair
NAME` refused while a pair under NAME lived (read at `e837c63`, `make` in `crates/podssh-cli/src/relay_cmd.rs`), so the
next pair could only be made once the node had ended. The Prove's test needs the stand-in relay
and the CLI's node, so it is a file of its own, `tests/node_expiry.rs`, not `tests/node.rs`,
whose tests run offline.

## Done

2026-11-01: the node says its pair's expiry before it comes, and goes on with the next pair.

- `crates/podssh-cli/src/node_expiry.rs` (new): the lines at 24 h, 6 h and 1 h before the expiry
  ("the pair expires in 22 h 59 min, at ..., and the relay renews none: `podssh relay pair lab
  --operator-file FILE` makes the next one now, which this node takes at the expiry; FILE goes to
  its operators"; for a node of `--pair-file`, that it needs a new FILE and a new start), and the
  repair hook: at the expiry the pair stored under the label since, if it expires later, with a
  line, else 77 as before. `node.rs`, `node_iroh.rs` and `node_derp.rs` run both with the pair's
  road.
- `crates/podssh-cli/src/relay_cmd.rs`: `relay pair NAME` makes the next pair in the last 24 h of
  the stored one, says so, and puts the old record back when the next one cannot be kept;
  `crates/podssh-relay/src/reverse/node.rs`: a stopped node deletes the stored pair only while it
  is its own. `podssh status` gives `pairs`. The manual's notes of `node` and `relay`,
  `docs/reverse.md`, `docs/relay.md` and `docs/cli.md` say the rules.
- `scripts/fake_reverse.py`, the stand-in's mode `expirefirst:SECONDS`: the first pair says 23 h,
  and ends after SECONDS with `1001 pair expired` on each of its sockets, its tokens refused after.
- `cargo test -p podssh-cli --test node_expiry`: 3 passed, the two new ones in 12.5 s:
  `a_node_says_its_pairs_expiry_before_it_and_takes_the_next_pair` (the node said "the pair
  expires in 22 h 59 min" with the command; `relay pair lab --operator-file` made the next pair
  while the first lived; at the first one's end the node said that the next took its place, came
  "online again", and a client logged in through it by the label) and
  `a_stopped_node_leaves_the_next_pair_in_the_store` (the old pair stopped by its stop token under
  a second label: the node exited 69, the next pair stayed under `lab`). `--test node`: 16 passed,
  with `the_next_pair_may_be_made_in_the_last_day_only` and
  `status_names_each_stored_pair_and_its_expiry`; `--lib node_expiry`: 5 passed.
- Planted, each failed its test: the hook with no next pair (the node exited 77 at the expiry), no
  lines, the window of `relay pair` past 72 h, the stopped node's delete with no check of the name,
  and `next_now` from the expiry alone.
- `cargo test -p podssh-cli --lib`: 520 passed; the node, routes, plain, operator, detach, status
  and manual suites: passed; `--features pair --test reverse_node`: 9 passed; clippy `-D warnings`
  with and without `iroh`: clean.

# T-412: The stand-in relay drops a frame of an unknown session, which the live relay answers with 1003

**Source:** the session of 2026-11-01, after T-410: the races of the node's road showed only on the
live relay, from GitHub's network, as the stand-in relay forgives what the live one does not.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The offline tests of the node's road run against the stand-in relay, which drops a binary frame of
the node whose session id it does not know. The live relay closes the node's whole socket with
`1003 unknown session id` for it (T-410's trace), which ends each session of the socket. A race of
that kind passes each offline test and shows only on the live relay.

## Premise

- Read: the stand-in passes a frame on only when the id is known, and drops it silently otherwise
  (`node` in `scripts/fake_reverse.py`, at `abf1322`).
- Measured on the live relay (T-410): a frame of the node for an id that the relay forgot closed
  the node's socket with `1003 unknown session id`, forwarded to each operator.
- Read: the stand-in already ends a session whose node gives no `ready` within 15 s (`1013 node
  open timeout`), as the live relay does.

## Approach

The stand-in closes the node's socket with `1003 unknown session id` for a frame of an unknown id,
in each mode but a new `lenient`, and says so on its stderr. Each suite that runs the stand-in's
reverse road must pass with it; a failure is a race of podssh, repaired before this entry closes.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_moves
cargo test -p podssh-cli --test node_detach --test node_expiry --test node_copy --test node_plain \
  --test node_routes --test pipe_remote --test pipe_udp --test roost --test upgrade --test attach
```

## Correction

A node closed with `1003` connects again since T-409, and its layered sessions resume, so the
strict stand-in alone fails no test: the harness must look. And no suite before this entry put
48 MiB through a node offline, so none moved a session, where T-410's race was.

## Done

2026-11-01: the stand-in relay is as strict as the live one, and the offline tests see it.

- `scripts/fake_reverse.py`: a binary frame of the node for an id that the stand-in does not know
  closes the node's socket with `1003 unknown session id` and a line on its stderr, in each mode
  but the new `lenient`.
- `crates/podssh-cli/tests/throughput_harness/mod.rs`: when a test's session ends, a line of that
  kind in the stand-in's logs fails the test, with the lines.
- `crates/podssh-cli/tests/node_moves.rs` (new):
  `a_bulk_session_through_a_node_moves_with_no_frame_of_a_forgotten_id` puts 100 MiB down from the
  test's server through a node, `ssh -v`, which moves at 48 MiB: passed in 52 s. Planted, T-410's
  defect back (the client's half-close of a retired link): failed 2 of 2, "the node sent frames of
  ids that the stand-in relay did not know: [... unknown id 316a3e72: 1003]".
- Each suite of the Prove with the strict stand-in, three rounds: passed, and no frame of an
  unknown id in any of them. A node's check of a closed session taken out of its writer was not
  reached by them (no session there has bytes after the relay's close), so it is not this entry's
  plant.

# T-420: The strict stand-in failed the test of a stopped relay host at random: a frame in flight

**Source:** CI's job `gate (m6)` at `a94718a` (run 41337008739, 2026-11-01), which changed nothing
of the node: `the_layer_survives_a_stopped_relay_host` failed, "the node sent frames of ids that
the stand-in relay did not know: [... unknown id 68b5d96e: 1003]"; T-412's check.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A test that fails at random keeps the gate red at the commit of a beta, and hides the next real
failure.

## Premise

- Measured here: 1 run of 6 failed so, and 1 of 6 again; the stand-in's logs of a failing run
  (kept by a local patch) showed the proxy's RST of each tunnel, then the line of the unknown id.
- Read: the fault ends the client's link and the node's with an RST, not at one instant
  (`crates/podssh-cli/tests/m6_exit.rs`). When the operator's link of a session ends,
  `scripts/fake_reverse.py` forgets the id at once and sends the node `close {id}`; a frame that
  the node sent before that `close` reached it then meets an id that the stand-in forgot, and the
  socket gets 1003. The node cannot know of the loss before the relay's `close`, so no repair of
  the node removes such a frame; T-412's check means to catch a frame that the node could have
  held back, as T-410's (the client's own early close of a link).

## Approach

The stand-in keeps when each session's operator link was lost (an error, not its Close frame), and
a frame of the node for that id within 2 s of the loss is said apart, "in flight"; the socket still
gets 1003, as on the live relay (T-421). The harness counts the other line alone: a frame after a
clean close of the operator, or later than 2 s after a loss.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test m6_exit -- --ignored --exact the_layer_survives_a_stopped_relay_host
cargo test -p podssh-cli --test node_moves
```

12 runs of the first; T-410's defect planted (the client's shutdown of a retired link) against the
second.

## Done

2026-11-01: `scripts/fake_reverse.py`: `Pair.lost` and `IN_FLIGHT` (2 s); a frame of the node for an
id whose operator's link was lost within them gives "a frame of the node for ID, whose operator's
link was lost N ms before (in flight): 1003", the socket closed as before.

- `the_layer_survives_a_stopped_relay_host`, 12 runs: none failed; one of them met the case, "lost
  0 ms before (in flight)", which failed the test before.
- T-410's defect planted (`closes = true` in `session/pump/outbox.rs`), `--test node_moves` 6 times:
  3 failed, each with "a frame of the node for an unknown id ...", and the 3 that passed had no
  frame of a forgotten id at all, neither kind: the new line hides none of that defect's frames,
  which come after the client's clean close.

# T-409: A node that the relay closes for a fault (1003, 1009) ends for good

**Source:** the run of `relay-live.yml` (`node_live`, run 41289022291 at `ea2bd4f`, 2026-11-01),
from GitHub's network: after the first move of T-155's test the node was offline for the 600 s
that the client tried, with the operator's lines "HTTP 503: reverse: node offline"; and the study
of d-mon's theme, a podssh that ends in production locks a server out.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A node exits when the relay closes its socket with `1003` or `1009`, a fault of the node's own
bytes. One frame for an id that the relay forgot (T-388's race) then ends the node, and a server
that only the node reaches is locked out until somebody starts it again.

## Premise

- Read: `after_close` gives `Next::Exit("fault")` for `1003` and `1009`
  (`crates/podssh-relay/src/reverse/node.rs:140`), and `run` returned `Exit::Fault` for it.
- Measured: the run of 41289022291: the node offline from the move on; the node's own lines were
  not printed by the workflow.

## Approach

`run` takes a fault for a lost socket: a line that names the close, then a new socket with the
jittered backoff; the layer resumes the socket's sessions on it. `Exit::Fault` goes. The stand-in
relay gets a mode `fault1003`, whose first node socket of each pair gets `1003 unknown session
id`; `relay-live.yml` prints the node's lines (`PODSSH_TEST_NODE_LINES=1`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_detach a_node_closed_for_a_fault_comes_back
cargo test -p podssh-relay --features pair --test reverse_node
```

## Done

2026-11-01: a node closed for a fault connects again. `crates/podssh-relay/src/reverse/node.rs`:
the fault of `after_close` is a line ("the relay closed the node for a fault of this node: 1003
unknown session id; connecting again") and a reconnection; `Exit::Fault` and the CLI's words for it
are gone. `scripts/fake_reverse.py`'s mode `fault1003`. `tests/node_detach.rs`,
`a_node_closed_for_a_fault_comes_back`: the node said the close, came online again and served a
login: passed; planted, the node's end at the fault: the test failed ("the node ended after the
fault"). `docs/reverse.md` says the rule. The race that sends the frame (T-388's, still seen from
GitHub's network) is T-410; `relay-live.yml` now prints the node's lines for it.


# T-416: A node that starts right after the pair's last node ended meets 409 and exits

**Source:** the run of `box.yml` (`run: chat`, job 124857212234 on `draft/t251-plants-2`,
2026-11-01), from GitHub's runner: box B's second node (`b2`) started at once after the first
(`b1`) quit, and printed "another node serves this pair (409), or the relay held this node's lost
socket for too long"; "FAIL: box A exited 22".
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The relay holds a node's socket for a moment after the node ends. A node of the same pair that
starts in that moment (a restart by a service manager, a script that starts the next node, a
second `--detach` after a stop) meets `409` at its first registration, and exits. A server that
only the node reaches is then locked out until somebody starts it again.

## Premise

- Read: the `409` arm of `run` gave `Exit::NameInUse` when the node had lost no socket
  (`crates/podssh-relay/src/reverse/node.rs:277-295`); only after a loss did it connect again.
- Measured: the run of job 124857212234: `b2` exited at its first `409`.

## Approach

`Settings::first_conflict` (30 s, `crates/podssh-relay/src/reverse/serve.rs`): a `409` at the
first registration is taken as the old socket that the relay still holds, and the node connects
again with the jittered backoff for that time from the first `409`, with a line for each, then
exits as before. A node of the pair that really serves still keeps the name: the new one ends
after 30 s. The rule of `docs/reverse.md` and the manual's notes of `podssh node` say it.

## Decision

30 s, not the 10 minutes of a lost socket: a second node of a pair that serves must still end
soon with the words that say why, and the relay frees a closed node's name in well under a
second. Lost: retry for ever (a second node would hang with no word), and no retry (the defect).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_restart
cargo test -p podssh-relay --features blocking,plain-ws --test blocking_plain
```

## Done

2026-11-01: a node connects again for 30 s after a `409` at its first registration.
`crates/podssh-relay/src/reverse/node.rs`, the `409` arm; `serve.rs`, `Settings::first_conflict`
and `FIRST_CONFLICT`. `tests/node_restart.rs`,
`a_node_that_meets_409_at_its_start_connects_again_and_serves_once_the_old_socket_ends`: the
second node said the `409`, stayed up, and served a login once the first was killed: passed;
planted, `first_conflict` zero: the node exited 69 at the `409`, and the test failed.
`blocking_plain.rs`: `conflict_at_the_first_registration_exits_after_its_grace` (2 s) and
`conflict_at_the_first_registration_connects_again_and_serves` passed; the plant failed the
second. box.yml's chat run on the runner waits for the merge of `draft/t251-plants-2` (T-251).

# T-587: `podssh proxy` takes no `node://NAME`, and its help never names `operator`, the ProxyCommand form of a node

**Source:** GitHub #113 (a tester's agent, 2026-11-02), with `podssh 1.0.0 (35a0d19)`:
`podssh proxy node://NAME 2222` is refused, and `proxy --help` has no `--pair-file`,
`--node-key`, `--client-key` or `--no-e2e`; it asks that `proxy` take `node://NAME` with the pair's
and the keys' flags of `ssh`, or that `proxy --help` name `operator`. Read at `3bb42ea`.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`proxy` is the ProxyCommand form of each road but the reverse one. A user who names a node as
`node://NAME` for `ssh`, `cp` and the other verbs writes `proxy node://NAME` in a ProxyCommand,
and gets a refusal that reads as a bad port. The node's ProxyCommand is `operator NAME` (or
`pipe - node:NAME`), which `proxy`'s help and its refusal never name. A feature: what `proxy`
documents works; the form that a user expects is missing.

## Premise

- Read: with one word, `proxy` splits `node://NAME` at its last `:`
  (`crates/podssh-cli/src/proxy.rs:398`) and says that `"//NAME"` is not a port (`:368-369`), the
  issue's words; with a second word, that `"node://NAME"` is not a host name or an IPv6 address
  (`crates/podssh-ws/src/names.rs:41`). The issue's prefix `podssh ssh:` is not this code's,
  which writes `podssh proxy:` (`crates/podssh-cli/src/proxy.rs:143`); not reproduced.
- Read: `operator NAME` is "the ProxyCommand of OpenSSH for a node"
  (`crates/podssh-cli/src/man/notes_pair.rs:300-302`), and `pipe` takes `node:NAME`
  (`crates/podssh-cli/src/pipe/address.rs:32-33`); the about of `proxy` is "ProxyCommand form: a
  byte pipe, not an SSH client" (`crates/podssh-cli/src/flags.rs:386`), with no word of a node.
- Read: `proxy` takes other schemes of its own, each with no PORT: `cf://HOST`, and the roads of
  `iap://`, `eice://`, `warp://` and `tor://` (`crates/podssh-cli/src/proxy.rs:124-139`).

## Approach

1. `podssh proxy node://NAME[/ROUTE]` is the pipe of `operator NAME[/ROUTE]`: the same pair
   (stored, or `--pair-file`), the end-to-end channel and its flags (`--client-key`, `--node-key`,
   `--no-e2e`), `--resume-deadline`, and the same exit codes. One function serves both verbs, so
   that they cannot drift.
2. A PORT is refused (64), with why: the node's TARGET or route names the service, as `cf://HOST`
   takes no PORT. The relay's flags, `--forwarder`, `--shadowsocks`, `--via`, `--vless`,
   `--wstunnel` and `--exit` are refused with it (64), as each takes the relay's place.
3. The flags of the pair and of the channel join the rows of `proxy`, each saying that it goes with
   `node://`; one of them with a target that is not `node://` is refused (64).
4. A refusal of `proxy` for a word that starts with `node:` names `proxy node://NAME`,
   `operator NAME` and `pipe - node:NAME`.
5. The notes of `proxy` and `operator`, `docs/cli.md`, `docs/reverse.md` and `docs/STATUS.md`.

## Decision

For the operator to confirm (Q86): `proxy` takes `node://NAME`, and `operator` stays, the same
pipe by its first name. `node://` is the destination form of `ssh`, `cp` and the other verbs, so
a ProxyCommand that names it reads as the rest do. Lost: `operator` alone with a word in
`proxy --help` (the issue's second choice), which leaves one verb whose destination form differs;
and `proxy NAME` with no scheme, which a host of the same name would take.

The calls of the draft (2026-11-03). A word of `node:` and a NAME that is no port is meant as a
node, as `pipe` writes one, and is refused with the three forms; `node:22`, one word, stays the
host `node` and its port, as before. Lost: each word of `node:` refused, which would break a host
named `node` in the one-word form. `--idle-warn` is refused with `node://`: it warns before the
idle cut of the relay's forward road, and the operator's leg pings the relay. Lost: the flag taken
and doing nothing. A run of `node://` adds its line to the log of the sessions, with the road
`node`, as each run of `proxy` that names a destination does, and the line says that it opened
when the run exits 0. Lost: no line, as `operator` writes none, which would leave a run of `proxy`
out of the log.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test proxy
cargo test -p podssh-cli --test operator
```

New tests, through the stand-in relay of the reverse road:
`proxy_carries_a_session_to_a_node_by_its_name` (a node in front of a target that echoes:
`proxy node://NAME` carries 1 MiB each way with equal digests, and exits 0);
`proxy_of_a_node_refuses_a_port_and_the_relay_s_flags` (64, each with its words); and, against
OpenSSH, `openssh_through_proxy_node_reaches_the_node_s_sshd` (`ssh -o ProxyCommand='podssh proxy
node://NAME' HOST true` exits 0; it says that it did not run where this host has no OpenSSH).
Planted: `t587-node-read-as-host` (`proxy` reads `node://` as a host again): the first test
fails.

## Done

Drafted 2026-11-03, in the commit "DRAFT T-587"; merged and run by the main session the same day.

- `crates/podssh-cli/src/proxy_node.rs` (new): `run`, the first step of `proxy`. A target of
  `node://NAME[/ROUTE]` becomes the `OperatorArgs` of its name and route, `--relay-addr`,
  `--ca-file`, `--pair-file`, `--client-key`, `--node-key`, `--no-e2e` and `--resume-deadline`, and
  goes to `operator::to_node` with the verb `proxy`. A PORT (a second word, or
  `node://NAME:PORT`), a user, an empty NAME, and `--relay-host`, `--relay-failover`,
  `--forwarder`, `--shadowsocks`, `--via`, `--vless`, `--wstunnel`, `--exit` and `--idle-warn` are
  refused (64), each refusal with the three forms of a node's ProxyCommand on a second line; a
  flag of a node beside another target is refused (64). Its unit tests: 3 passed.
- `crates/podssh-cli/src/operator.rs`: `run_operator` is `to_node(args, "operator", err)`, and
  `to_node` is its old body, each line naming the verb that runs it.
- `crates/podssh-cli/src/proxy.rs`: `ProxyArgs::node`; `proxy_node::run` before each other road;
  `--client-key` alone names `node://NAME` beside `--exit NAME`; the usage line names
  `node://NAME`.
- `crates/podssh-cli/src/parsed.rs`, `crates/podssh-cli/src/tree.rs` and
  `crates/podssh-cli/src/dispatch.rs`: `Parsed::Proxy` carries `node`, read by
  `proxy_node::Flags::from_matches`; `crates/podssh-cli/src/lib.rs` names the module.
- The rows: `crates/podssh-cli/src/flags/node.rs` and `crates/podssh-cli/src/flags/relay.rs`, the
  rows `--pair-file`, `--node-key`, `--no-e2e` and `--resume-deadline` of `proxy`, each beginning
  `node://NAME:`, and `--client-key` with `--exit, and node://NAME`;
  `crates/podssh-cli/src/flags.rs`, the about of `proxy` names `node://NAME` and `operator NAME`;
  `crates/podssh-cli/src/positionals.rs` and `crates/podssh-cli/src/help.rs`, the help of HOST and
  PORT, and the usage tail.
- The manual: `crates/podssh-cli/src/man/notes_proxy.rs`, a note of `proxy node://NAME`;
  `crates/podssh-cli/src/man/notes_pair.rs`, the first note of `operator` names it.
- `docs/cli.md` (a rule in the section of the reverse road), `docs/reverse.md` (the operator's
  section) and `docs/STATUS.md` (a row).
- Tests: `crates/podssh-cli/tests/proxy.rs`, `proxy_of_a_node_refuses_a_port_and_the_relay_s_flags`
  (in memory); `crates/podssh-cli/tests/proxy/to_node.rs` (new), through the stand-in relay,
  `proxy_carries_a_session_to_a_node_by_its_name`, and `openssh_through_proxy_node_reaches_the_node_s_sshd`
  (OpenSSH's client with `ProxyCommand=podssh proxy node://NAME`): each passed. The merge gave
  `mod to_node` its `#[path]`, as a test's root looks for its modules beside it.
- Planted (`scripts/plants/t587-node-read-as-host.patch`): its SETUP installs with `apk`, so it ran by
  hand: caught, `proxy_carries_a_session_to_a_node_by_its_name` failed.

Measured, 2026-11-03: `cargo test -p podssh-cli --test proxy`, 14 passed; `--test operator`, 7
passed; `--test relay`, 10 passed; `--lib proxy_node`, 3 passed; the whole lib, 706; `man_page` 10
and `flag_table` 9; `cargo clippy --all-targets -D warnings`: clean.

# T-589: `operator` and `proxy` take no `--ConnectTimeout`, so a ProxyCommand has no bound of its own on reaching its far end

**Source:** GitHub #115 (a tester's agent, 2026-11-02), with `podssh 1.0.0 (35a0d19)`:
`podssh operator --ConnectTimeout 25 NAME` is an unknown flag (64); it asks for `--ConnectTimeout`
on `operator` and `proxy`, with the meaning of `ssh`'s. Read at `3bb42ea`.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A program that runs `operator` or `proxy`, as a ProxyCommand or as a pipe of its own, cannot say
how long podssh may take to reach the far end: each wait has podssh's own limit, which the user
cannot shorten, and a `timeout` around podssh kills it with no word of what it waited for. `ssh`
takes `--ConnectTimeout`; its two pipes do not. A feature: the waits have limits, which a user
cannot set.

## Premise

- Read: the rows of `operator` are "a pipe, with no `--timeout`"
  (`crates/podssh-cli/src/flags/operator.rs` line 9 at `d629249`, before T-613 gave it one), and
  have no ConnectTimeout; `ssh` has one
  (`crates/podssh-cli/src/flags.rs:173-174`).
- Read: `operator`'s waits are 30 s for each request of the relay
  (`crates/podssh-cli/src/operator.rs:142`, `crates/podssh-cli/src/pairs.rs:18`) and 20 s for the
  node's `ready` (`crates/podssh-relay/src/reverse/operator.rs:59`); `proxy`'s, 20 s for each
  relay host (`crates/podssh-relay/src/open.rs:31`), in the order of the failover.
- Inferred, which the Prove measures: OpenSSH's ConnectTimeout bounds the wait for the server's
  version line through a ProxyCommand too (`openssh/openssh-portable:sshconnect.c`, where
  `ssh_login` gives it to `kex_exchange_identification`), but not the ProxyCommand's own start,
  and its end then gives no word of podssh's; the issue's "does not apply" holds for that part.

## Approach

1. `--ConnectTimeout SECONDS` on `operator`, on `proxy` (each of its roads) and on `pipe` when a
   side is `node:`, `relay:` or `ssh:`: one bound on the time from the start to the session's
   open. For `proxy`, the relay's answer (each host's dial, TLS, the upgrade, the relay's dial of
   the target) or the answer of the road that takes the relay's place; for `operator` and a node,
   the relay's answer, the node's `ready`, and the handshakes of the layer and of the channel. The
   bytes after the open are never bounded: a pipe may wait.
2. Each step keeps its own limit too; the first limit to pass ends the wait. 0 is refused (64); with
   none given, the waits are as now.
3. Past the bound, one line names the step that waited ("the node did not answer ready within
   25 s", "no relay host answered within 25 s"), and the exit is that of a far end out of reach: 69
   for `proxy`, the code of an unreachable relay for `operator`.
4. These verbs take no `-o`, so `-o ConnectTimeout=N` stays refused. The rows and the notes of
   `proxy`, `operator` and `pipe`, `docs/cli.md`, `docs/STATUS.md`.

## Decision

For the operator to confirm (Q86): the flag is `ssh`'s, `--ConnectTimeout SECONDS`, its meaning
taken to a pipe: the time to the session's open, never the bytes after it. Lost: `--timeout`,
which bounds the whole run on `cp`, `mv` and `job`, and a pipe's run has no end to bound; and
`PODSSH_TIMEOUT` as its default, which bounds whole runs (T-012). Lost: a bound on the far end's
first byte, as a TARGET may speak second (HTTP).

The calls of the draft (2026-11-03). The bound is a watch on a thread of its own, which ends the
run with 69 and the words of the step that waited once it passed with no session open; each road
says its open (each road of `proxy` through `session_log::opened`, a node through its layer and
its channel, a pipe once both sides opened), and a session that opened is never cut. Lost: a
timeout around the open of each road, which needs a change in each of a dozen roads and leaves
the steps inside the leg's task unbounded. The node's `ready` is named by a hook of the leg,
`OperatorLimits::on_ready`, a function pointer, as that task hides the moment. Lost: one word for
`ready` and the greeting together, which names no step. After `ready`, the node's first bytes are
a step: the layer's greeting, or from a node of `--plain` its TARGET's, which the bound waits for
too, so a speak-second TARGET behind `--plain` takes no bound. Lost: the open at `ready`, which
leaves the layer's handshake unbounded. The bound is 1 to 86400 s, with an `s` after the number
taken, as `ssh` reads its ConnectTimeout. Lost: no top, where an `Instant` far ahead overflows.
`pipe` watches a `node:` or `relay:` side, and an `ssh:` side's hops take the flag as their own
ConnectTimeout by `ssh`'s id; a listening side and a pipe with none of the three refuse it (64);
beside a `node:` or `relay:` side a question of an `ssh:` hop on the terminal counts against the
watch. Lost: a bound for each client of a listener from its accept, which one watch of the
process cannot carry.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test operator
cargo test -p podssh-cli --test proxy
```

New tests: `operator_s_connect_timeout_ends_a_wait_for_ready` (a stand-in relay that takes the
operator's socket and never sends `ready`: with `--ConnectTimeout 3`, the operator ends within 5 s
with its code and a line that names `ready`); `proxy_s_connect_timeout_ends_a_silent_relay` (a
port that takes TCP and never answers TLS: 69 within 5 s); `a_connect_timeout_of_zero_is_refused`
(64). And the Premise's reading of OpenSSH, measured: `ssh -o ConnectTimeout=3 -o
ProxyCommand='sleep 30' HOST true` ends within 5 s, its exit and words in the Done. Planted:
`t589-bound-not-applied` (the flag read, and not used): the first two tests fail.

## Done

Drafted 2026-11-03, in the commit "DRAFT T-589"; merged and run by the main session the same day. The
Premise holds at the cited lines (read at `5494bdd`).

- `crates/podssh-cli/src/connect_bound.rs` (new): `parse` (whole seconds, an `s` taken, 1 to
  86400; 0 and the rest refused, 64), `watch` (the guard of one run; its thread waits on a
  condition variable until the bound, then names the step on stderr and exits 69), `step`,
  `opened` (past the bound it parks, so no byte of a session goes out), `ready`,
  `channel_follows` and `layer_up`; the steps' logic on `State`, which its unit tests hold on a
  state of their own: 2 passed.
- `crates/podssh-relay/src/reverse/operator.rs`: `OperatorLimits::on_ready`, called as `ready`
  comes; a never-ready session says "the node did not answer ready within N s".
  `crates/podssh-relay/tests/reverse_operator.rs`: its limits name the new field.
- `crates/podssh-cli/src/operator.rs`: `OperatorArgs::connect_timeout`, parsed first in `prepare`;
  `to_node` watches, and names the steps (the relay, then `ready` after the socket); its limits
  take the hook. `crates/podssh-cli/src/proxy_node.rs` passes the flag on to a node's run.
- `crates/podssh-cli/src/proxy.rs`: `ProxyArgs::connect_timeout`, parsed after the other
  refusals; one watch for each road, the step of each (the road of the target, the exit, the
  VLESS, wstunnel, `--via`, Shadowsocks and forwarder roads, the relay, and the forwarders after
  it). `crates/podssh-cli/src/session_log.rs`: `opened` ends the bound, as each road of `proxy`
  says its open there.
- `crates/podssh-cli/src/layered.rs` (`layer_up` once the layer started) and
  `crates/podssh-cli/src/channel.rs` (`channel_follows`, and the check of the node's key, passed,
  is the open).
- `crates/podssh-cli/src/pipe/mod.rs` (`connect_bound`: the flag's value of `ssh`'s id, refused
  with a listener or with no `node:`, `relay:` or `ssh:` side; the watch of a pipe that does not
  listen; the open once both sides opened, but a node's), `crates/podssh-cli/src/pipe/remote.rs`
  (the steps of `relay:`, `ssh:` and `node:`), `crates/podssh-cli/src/pipe/node.rs` (the hook and
  the step of `ready`).
- `crates/podssh-cli/src/parsed.rs`, `crates/podssh-cli/src/tree.rs`,
  `crates/podssh-cli/src/dispatch.rs`, `crates/podssh-cli/src/lib.rs`: the field and the module.
- The rows: `crates/podssh-cli/src/flags/operator.rs` (`OPERATOR_CONNECT_TIMEOUT`,
  `PROXY_CONNECT_TIMEOUT`, `PIPE_CONNECT_TIMEOUT`), taken by `PAIR_FLAGS`,
  `crates/podssh-cli/src/flags/relay.rs` and `crates/podssh-cli/src/flags/pipe.rs`.
- The manual: a note in each of `crates/podssh-cli/src/man/notes_proxy.rs`,
  `crates/podssh-cli/src/man/notes_pair.rs` (operator) and `crates/podssh-cli/src/man/notes_pipe.rs`.
- The stand-in relay's mode `noready` (`scripts/fake_reverse.py`, named in
  `scripts/fake-relay.py`): the operator's socket taken and never readied.
- `docs/cli.md` (the reverse road's section and `pipe`'s), `docs/reverse.md`, `docs/STATUS.md` (a
  row).
- Tests: `crates/podssh-cli/tests/operator.rs`, `operator_s_connect_timeout_ends_a_wait_for_ready`
  (through `noready`), and `a_connect_timeout_of_zero_is_refused` (each verb, and a listening
  pipe); `crates/podssh-cli/tests/proxy.rs`, `proxy_s_connect_timeout_ends_a_silent_relay`: each
  passed.
- The plant `scripts/plants/t589-bound-not-applied.plant`: its SETUP installs with `apk`, so it ran
  by hand: caught, `operator_s_connect_timeout_ends_a_wait_for_ready` and
  `proxy_s_connect_timeout_ends_a_silent_relay` failed, each after 20 s.

The Premise's reading of OpenSSH, measured at the merge (OpenSSH_9.6p1 of this cloud session's
host): `ssh -o ConnectTimeout=3 -o ProxyCommand='sleep 30' HOST true` exits 255 after 3.0 s,
"Connection timed out during banner exchange": OpenSSH bounds its own banner's wait, and the
ProxyCommand's side now has a bound of its own. `cargo test -p podssh-cli --test operator`, 9
passed; `--test proxy`, 15 passed; `--lib connect_bound`, 2 passed; the whole lib, 708; `cargo
test -p podssh-relay --features pair --test reverse_operator`, 10 passed; the `pipe` suites,
`node_detach` 8, `node_moves` 2 and `roost` 11 passed, as the stand-in relay gained `noready`.
Clippy on Linux: clean, once `Parsed`, which the new flags made 512 bytes in `Proxy`, takes
`allow(clippy::large_enum_variant)`, as `keygen`'s `KeyFile` does (one value of it is made for
each run); Windows: the gate's job `windows`.

# T-613: `operator`, `proxy` and `pipe`'s remote sides take `--timeout` and `PODSSH_TIMEOUT` as other names of `--ConnectTimeout`

**Source:** the operator's ruling Q90 (2026-11-03) on T-589's call that these commands take no
`--timeout`: "also take --timeout", with the meaning of `--ConnectTimeout`.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

`podssh operator`, `proxy` and `pipe`'s remote sides refuse `--timeout` and pass over
`PODSSH_TIMEOUT`, which the copies and `run` take, so a user who sets the one variable gets no
bound on the open of those three.

## Premise

- Read: T-589's `## Decision` and its `## Done`: `--ConnectTimeout SECONDS` alone bounds the open on
  these commands (`TODO/reverse.md`, T-589).

## Approach

1. `--timeout SECONDS` and `PODSSH_TIMEOUT` set the same bound as `--ConnectTimeout` there: the time
   to the session's open, never the bytes after it; `--ConnectTimeout` wins when both are given,
   as the more precise name, and the flag's flag row says so.
2. The manual's notes and `docs/cli.md`.

## Decision

The calls of the draft (2026-11-03):

- `--timeout` and `PODSSH_TIMEOUT` take the duration of the other commands' `--timeout` (`30s`,
  `2m`, `1h`, `500ms`, a bare number of seconds), in whole seconds rounded up, as a user who set
  the variable for the copies set it so. Lost: `--ConnectTimeout`'s whole seconds alone, which
  would refuse with 78 a variable of `2m` that `cp` takes.
- The flag takes a day at most, as `--ConnectTimeout` does (64 past it); the variable is held to a
  day, with no refusal, as it bounds whole runs of other commands, which may be longer. Lost: the
  variable refused past a day, which would end an `operator` for a setting of the copies.
- `--ConnectTimeout` wins over `--timeout`, and either over the variable, which is read only with
  no flag, as each command reads it; a bad `--timeout` beside `--ConnectTimeout` is still refused,
  as a typo. Lost: the first given wins, an order of the command line that clap does not keep.
- The line past the bound names the name that set it: `within 2 s (--timeout)`, `(PODSSH_TIMEOUT)`,
  `(--ConnectTimeout)`, so that a user who never typed `--ConnectTimeout` sees what bound the run.
  Lost: `(--ConnectTimeout)` for each, which a user of the variable alone would not recognise.
- `pipe`: `--timeout` has `--ConnectTimeout`'s refusals (a listening side, no `node:`, `relay:` or
  `ssh:` side) and is each `ssh:` hop's ConnectTimeout too, in whole seconds. The variable bounds
  the open of a `node:` or `relay:` side where no side listens, and nothing else: it refuses no pipe
  and is no hop's ConnectTimeout. Lost: the variable as the flag, which would refuse each listening
  pipe of a user who set it for copies, and give a hop a ConnectTimeout longer than its own 60 s.
- The three rows are `optional`, as `scp`'s and `sftp`'s: never required, with no terminal either.
  These verbs never reach the gate of `--timeout` (their `Parsed` is their own), so the mark is the
  table's word, as `docs/cli.md` says. Lost: rows that look required.
- `OperatorArgs` is read in `operator.rs` (`OperatorArgs::from_matches`), as `NodeArgs` is, to keep
  `tree.rs` under its 500 lines; and the tests of `operator.rs` through the stand-in relay (T-586's,
  T-612's) went to `tests/operator_relayed/mod.rs`, unchanged but for their paths, for the same
  reason. The plant of T-589 (`t589-bound-not-applied`) follows `watch`, which now takes the bound
  and its name.

## Prove

```sh
cargo test -p podssh-cli --test operator
```

`operator --timeout 2` to a carrier that starts no node ends with 69 at 2 s, as `--ConnectTimeout
2` does; `PODSSH_TIMEOUT=2` the same; planted, the name ignored: the test fails.

## Done

Drafted 2026-11-03; merged and measured on this machine the same day.
The Premise holds: T-589's `## Decision` takes `--ConnectTimeout` alone, and lost `--timeout`
and `PODSSH_TIMEOUT` (`TODO/reverse.md`, T-589).

- `crates/podssh-cli/src/connect_bound.rs`: `Bound` (the limit and the name that set it),
  `of_connect_timeout`, `chosen` (`--ConnectTimeout`, else `--timeout`, else `PODSSH_TIMEOUT`),
  `variable_bound`; `watch` takes a `Bound`, and the line past it names it. Its unit test
  `timeout_and_the_variable_are_other_names_of_the_bound`.
- `crates/podssh-cli/src/operator.rs`: `OperatorArgs::timeout`, `OperatorArgs::from_matches` (out
  of `tree.rs`) and `OperatorArgs::bound`, which `prepare` and `carrier.rs`'s `prepare` read.
  `proxy.rs` (`ProxyArgs::timeout`, read by `chosen`), `proxy_node.rs` (to operator), `parsed.rs`,
  `dispatch.rs` and `tree.rs` (the field of `proxy` and of `pipe`). `pipe/mod.rs`:
  `PipeArgs::timeout`; `connect_bound` takes `--timeout` with the refusals of `--ConnectTimeout`,
  and the variable for a `node:` or `relay:` side where no side listens; `hops_timeout` gives the
  `ssh:` hops `ConnectTimeout=SECONDS` of `--timeout`.
- The rows: `flags/operator.rs` (`TIMEOUT` of `operator` and `proxy`, `PIPE_TIMEOUT`, both
  `optional`), in `flags/relay.rs` and `flags/pipe.rs`; `flags.rs`, the words of `optional`.
- The manual: `man/notes_pair.rs` (operator), `man/notes_proxy.rs`, `man/notes_pipe.rs`,
  `man/facts.rs` (`PODSSH_TIMEOUT`). `docs/cli.md` (the bullets of the reverse road and of pipe, and
  "Prompts and time limits"), `docs/reverse.md`, `docs/STATUS.md` (a row).
- Tests: `crates/podssh-cli/tests/operator.rs`, `a_bad_timeout_is_refused_by_its_name` (each verb,
  offline: 64 for the flag, 78 for the variable, `pipe`'s listening side, and a pipe with no side of
  a node or the relay that reads no variable) and, on Unix,
  `timeout_and_podssh_timeout_bound_the_open_as_connect_timeout_does` (a carrier of `sleep 10`:
  each name ends the run with 69 at 2 s, its line naming it; `--ConnectTimeout` wins).
  `tests/pair_harness/mod.rs` removes `PODSSH_TIMEOUT` from each run, as the variable now reaches
  these verbs. The tests through the stand-in relay moved to `tests/operator_relayed/mod.rs`.
- The plants: `scripts/plants/t613-timeout-ignored.plant` (GROUP=cli-tests), and
  `scripts/plants/t589-bound-not-applied.patch` and `scripts/plants/t595-proxy-carrier-dropped.patch`
  moved with the code; `scripts/plants/t595-ssh-carrier-skipped.patch`, which no longer applied
  since its code moved to `crates/podssh-cli/src/ssh/node.rs` at `54b124b`, follows it. Each takes
  `git apply --check`; each caught (below).

Measured at the merge (2026-11-03, Linux, `CARGO_BUILD_JOBS=4`):

- `cargo test -p podssh-cli --test operator`: 12 passed, once the merge repaired what the draft's
  own test found. Over a carrier whose program never starts a node (`exec:sleep 10`), the bound
  ended podssh at 2 s with 69 and its line, but the run's stderr stayed open for 10 s: the bound
  ends the process with `exit`, which drops nothing, and the carrier's program, which holds the
  stderr that it inherited, outlived podssh. A run of `exec:ssh -T host ...` would have left its ssh
  behind the same way. The bound now runs what was registered to end with it before it exits
  (`connect_bound::at_give_up`), and the carrier's client registers the kill of its program
  (`carrier::Client::start`), so the program ends with the run. Planted, the stops not run
  (`scripts/plants/t613-carrier-program-left.plant`): caught.
- `cargo test -p podssh-cli --lib`: 790 passed. `--test proxy --test pipe --test node_carrier`:
  15, 10 and 14 passed (`tests/proxy.rs` took the new field of `Parsed::Proxy`, which the draft
  had not given it); `--test non_interactive --test man_flag_parity --test flag_table --test
  man_page`: each passed.
- clippy `--all-targets -D warnings` of `podssh-cli` (the test's tuple of cases named by a type of
  its own) and rustfmt: clean.
- The plants `t613-timeout-ignored`, `t613-carrier-program-left`, `t589-bound-not-applied` and
  `t595-proxy-carrier-dropped`: 4 caught.

# T-591: An operator's host cannot see its pair's expiry: `relay status` reads the store alone, and `relay pair` does not say the way past the expiry

**Source:** GitHub #117 (a tester's agent, 2026-11-02), with `podssh 1.0.0 (35a0d19)`:
`relay pair NAME --operator-file F` printed an expiry three days out, and "the expiry is not
shown by `relay status NAME`"; it asks for `relay pair --renew` (T-592), the expiry in
`relay status`, and, if a new pair is the way, words where the expiry is printed. Read at
`3bb42ea`.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The owner of a node sees its pair's expiry in `relay status NAME`. An operator who holds only the
operator's file cannot run `relay status` at all, so a check on an operator's host cannot see the
end coming; and the line of `relay pair` gives a date with no word of what happens then, or of how
to go on. A feature.

## Premise

- Read: `relay status NAME` prints the expiry beside online or offline
  (`crates/podssh-cli/src/relay_cmd.rs` lines 235-239 at `2608b91`), as it did at `35a0d19`; the
  issue's claim holds where no pair is stored under NAME, as on an operator's host.
- Read: it reads the pair from the store alone (`crates/podssh-cli/src/relay_cmd.rs` line 229 at
  `2608b91`, `crates/podssh-cli/src/pairs.rs:36-44`); `relay` takes no `--pair-file`, and `--operator-file`
  goes with `pair` alone (`crates/podssh-cli/src/relay_cmd.rs:135-138`).
- Read: the relay answers `/v1/status/<name>` to the connect token
  (`crates/podssh-relay/src/pair.rs:200-204`), which the operator's part holds.
- Read: `relay pair` prints the label and its expiry and nothing more
  (`crates/podssh-cli/src/relay_cmd.rs:306`); in the last 24 h of a stored pair it makes the next
  one, which the node takes at the expiry (T-395, `crates/podssh-cli/src/relay_cmd.rs:235-258`);
  the operator's part of the next pair is a new file, and the default relay renews no pair (T-395's
  Decision, item 2).

## Approach

1. `relay status --pair-file FILE [NAME]`: the pair, or its operator's part, from FILE, as
   `operator --pair-file` reads it; NAME, when given, is the label shown. `--json` with a NAME too:
   one object, `label`, `online`, `sessions`, `expires` (RFC 3339) and `seconds_left`, for a check.
2. `relay pair` keeps its one line on stdout, for scripts, and says on stderr: "in its last 24 h,
   podssh relay pair NAME --operator-file NEW makes the next pair, which the node takes at the
   expiry; NEW goes to each operator".
3. A pair with less than 24 h left: `relay status` says how long beside the date ("expires in
   5 h, at ..."), on the owner's host and on the operator's.
4. The notes of `relay`, `docs/reverse.md`, `docs/cli.md` and `docs/STATUS.md`.

## Decision

`--pair-file` is the name of the same file for `node` and `operator`. Lost: `--operator-file`
for `status`, whose meaning on `pair` is a new file to write. The line on stdout of `relay pair`
stays one line, as scripts read it, and the words go to stderr.

The calls of the draft (2026-11-03). With `--pair-file` and no NAME, the label shown is FILE as
given. Lost: the relay's name of the pair (`p-...`), which no user typed, and a refusal that asks
for a NAME, which an operator's host has no use for. The JSON object of a pair carries `schema`
(1) and `podssh` too, as each other `--json` of `relay` does. Lost: the five fields alone, an
object of another form than its siblings. `pair::status` takes the operator's part (`OperatorPart`)
in place of a whole pair, so that a stored pair and an operator's file go one way. Lost: a second
function for the part, in a file at its 500 lines. The words of `relay pair` go on stderr at each
pair, not only with `--operator-file`: the owner needs the way past the expiry either way.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay
cargo test -p podssh-cli --test node_expiry
```

New tests, against the stand-in relay: `relay_status_of_an_operator_s_file_names_the_expiry` (a
pair made, its operator's part alone in a file, the store emptied: `status --pair-file` names
online or offline and the expiry, and `--json` gives `seconds_left`);
`relay_pair_says_the_way_past_the_expiry` (the words on stderr, and one line on stdout). Planted:
`t591-pair-file-ignored` (`status` reads the store again): the first test fails.

## Done

Drafted 2026-11-03, in the commit "DRAFT T-591"; merged and run by the main session the same day. The
Premise holds at the cited lines (read at `2608b91`).

- `crates/podssh-cli/src/relay_status.rs` (new): `pair`, the status of the pair stored under NAME
  or of the file of `--pair-file` (a pair, or its operator's part, read as `operator` reads it;
  NAME then the label shown, else FILE): online or offline, the sessions and the expiry, or with
  `--json` one object (`schema`, `podssh`, `label`, `online`, `sessions`, `expires`,
  `seconds_left`); `expiry`, which in the last 24 h says how long is left (`expires in 5 h, at
  ...`), by `node_expiry::left_words`. Its unit test: 1 passed.
- `crates/podssh-cli/src/relay_cmd.rs`: `RelayArgs::pair_file`; `status NAME`, and `status` with
  `--pair-file` and no NAME, go to `relay_status::pair`; `--json` goes with each `status`;
  `--pair-file` with another subcommand is refused (64); `relay pair` keeps its one line on
  stdout and says the way past the expiry on stderr. The old `status` function went into the new
  module.
- `crates/podssh-relay/src/pair.rs`: `status` takes the operator's part. Its callers:
  `crates/podssh-relay/src/blocking/mod.rs`, `crates/podssh-cli/src/doctor/pairs.rs` and
  `crates/podssh-relay/tests/pair_live.rs`.
- `crates/podssh-cli/src/tree.rs` (the field), `crates/podssh-cli/src/lib.rs` (the module),
  `crates/podssh-cli/src/flags/relay.rs` (the row `--pair-file` of `relay`, and `--json`'s words).
- The manual: `crates/podssh-cli/src/man/notes_relay.rs`, the notes of `pair`, `status NAME` and
  `--json`.
- `docs/cli.md` (the section of the reverse road), `docs/reverse.md` (the node's section) and
  `docs/STATUS.md` (a row).
- Tests: `crates/podssh-cli/tests/relay.rs`, through the stand-in relay,
  `relay_status_of_an_operator_s_file_names_the_expiry` (an operator's host with another HOME and
  an empty store) and `relay_pair_says_the_way_past_the_expiry`; the refusals before anything
  connects now hold `pair --json` and `pair --pair-file` in place of `status NAME --json`, which
  works: 12 passed. `crates/podssh-cli/tests/node_expiry.rs`,
  `status_in_a_pair_s_last_day_says_how_long_is_left` (the stand-in's `expirefirst`, from the
  store and from the operator's file): 4 passed.
- Planted (`scripts/plants/t591-pair-file-ignored.patch`): its SETUP installs with `apk`, so it ran
  by hand: caught, `relay_status_of_an_operator_s_file_names_the_expiry` failed.

Measured, 2026-11-03: `cargo test -p podssh-cli --test relay`, 12 passed; `--test node_expiry`, 4
passed; `--lib relay_status`, 1 passed; `--test doctor`, 13 passed and 2 ignored (its lines of
pairs changed); the whole lib, 709; `cargo test -p podssh-relay --features blocking --test
blocking`, 5 passed, and `--features pair --lib pair`, 2 passed; `man_page` 10 and `flag_table`
9; `cargo clippy --all-targets -D warnings`: clean.


# T-601: A node's `serve` that is dropped leaves its writer holding the socket, so the far side never sees the node go while a session of it lives

**Source:** the gate at `38f424c` (run 41620927795, its job `macos`): `podssh-relay`'s
`reverse_carrier::a_stream_that_the_client_was_given_has_one_life` gave "a leg still opened"
after 30 s; it passed on Linux there and here. Read at `38f424c`.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A test that fails at random on macOS, and a defect under it. `reverse::serve` spawns the one
writer of the node's socket with a clone of the socket, and each session's tasks hold clones of
its outbox. When the future of `serve` is dropped (its task aborted, as the test ends a node;
any caller that drops it), the read loop goes, but the writer lives as long as a session's task
holds the outbox, and so does the socket: the far side (the relay, a carrier's role) never sees
the node go, and each leg after waits for a node that reads nothing. On Linux the test's first
session had ended before the abort; on the macOS runner its tasks still lived.

## Premise

- Read, at `38f424c`: `crates/podssh-relay/src/reverse/serve.rs`, `serve` spawns
  `write(session.clone(), ...)` and awaits it only at its own end, 5 s at most; `open` and its
  copies hold `tx.clone()`.
- Read: `crates/podssh-relay/tests/reverse_carrier.rs`, the test aborts the node's task and
  expects the role to refuse the next leg with 410 within 30 s.

## Approach

1. The writer's handle in a guard that aborts it when `serve` is dropped; the end of `serve`
   still waits for it 5 s.
2. A test of the order that the macOS runner met: a node that holds a session open, its task
   aborted; the role must see the stream end, and refuse the next leg with 410.

## Prove

```sh
cargo test -p podssh-relay --features serve --test reverse_carrier
```

Each passes; planted, the guard that aborts nothing: the new test fails.

## Done

2026-11-03.

- `crates/podssh-relay/src/reverse/serve.rs`: `Writer`, the writer's task, aborted when `serve`
  is dropped.
- `crates/podssh-relay/tests/reverse_carrier.rs`: `a_node_that_goes_with_a_session_open_ends_the_stream`,
  with a handler that holds each session open.
- `cargo test -p podssh-relay --features serve --test reverse_carrier`: 6 passed. The whole
  crate with `pair,quick,derp,serve,piping,blocking,plain-ws`: 584 passed, and 1 failed at random,
  `relay_serve_reverse`'s two sessions of 2 MiB, which fails as often with the code before (T-602).
- Planted, `Drop` that aborts nothing: the new test failed ("the role sees the stream end").

# T-615: A connect token for each session, and a stop token that the node rotates, in podssh's relay role

**Source:** T-226's Correction (2026-11-02) and its draft (2026-11-03), which built the connect token
of one upgrade and left these two.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A pair's connect token on podssh's relay role takes each upgrade for 72 h, or one alone with
`podssh relay pair --once`, which then carries one session with no resume. A pair's stop token lasts
as long as the pair. A token that leaks, from a proxy that logs the headers of a request, stays good
until then; a grant (T-226) holds the node's door behind it, but the relay's own door stays open to
whoever holds the token.

## Premise

Read at `d262613` and in the draft of T-226: the role keeps the SHA-256 of each of a pair's three
tokens, and a pair of `once` spends its connect token at its first upgrade
(`crates/podssh-relay/src/serve/reverse/pairs.rs`). The node's socket carries the contract's text
frames alone (`hello`, `open`, `close`, `ready`, `reject`; `docs/relay.md`, "The reverse path"), so a
token that the node gives its operators needs a frame of podssh's own, sent only to a relay that offers
it in `/relays.json`. A resume of the layer opens a new leg, which needs a token of its own.

## Approach

1. In the relay role: a frame of the node's socket, `{"type":"token","digest":HEX,"expires":MS}`, which
   the role takes only where its `/relays.json` offers it, and which registers a connect token of one
   upgrade by its digest; the role answers each upgrade with such a token once, as for a pair of
   `once`.
2. At the node: once the channel let an operator in, the node draws the next token of its session, sends
   its digest to the role, and gives the token to the operator inside the channel; the operator's next leg
   (a resume) takes it, so that each leg has a token that no other leg can use.
3. The stop token: `POST /v1/rotate/<name>` with the stop token answers a new one, and the node rotates its
   own at each start and each day, inside the private file of its pair; an operator never holds it.
4. A node of a relay that offers neither keeps the pair's tokens, as now.

## Decision

2026-11-04 (the drafting agent). No row of `docs/decisions.md` settles these, and none changes one: Q4
keeps the relay's tokens and the trust end to end, and Q63 makes the relay a role of podssh's, whose
contract beside the default relay's is podssh's own. Each call is weighed against `SECURITY.md`: a token
is a credential, never in a URL, a log, argv or a file of the relay's, and the relay sees no secret of
the channel.

1. **How the token reaches the operator: a seed in the node's verdict, and a token for each leg derived
   from it**, HMAC-SHA256 under the seed of `podssh leg token, version 1` and the leg's number, 64 hex
   digits (`crates/podssh-relay/src/e2e/legs.rs`). The verdict that lets a session in carries the seed as
   an item after its code, which `frame::answer` of a podssh of before reads past
   (`crates/podssh-relay/src/e2e/frame.rs`), so no word of either end is needed first, and no token
   crosses a wire before its own leg. Lost: a message of the channel with each next token, as the
   Approach had it, because an operator of before ends its session at a message type that it does not
   know (`crates/podssh-relay/src/e2e/channel.rs`), so each end would first have to say that it reads it,
   and a leg lost before the next token came would have none for its resume; a record of the layer,
   which the relay reads, and so does a proxy that ends TLS, before the token's use; tokens derived from
   the layer's secret, which needs no byte more but takes that secret out of the layer's code at both
   ends, and serves `--no-e2e`, whose node has no door but the pair's token anyway.
2. **The offer: two fields of the role's `hello`, `"legTokens": true` and `"stopRotation": true`, which
   the node reads on the socket itself**; `/relays.json` says the same (`reverse.leg_tokens`,
   `reverse.rotate`) for a client that asks. A node of before keeps the fields and reads nothing of them
   (`crates/podssh-relay/src/reverse/control.rs`, `Hello::extra`). Lost: `/relays.json` alone, a second
   request at each socket, which a host behind a balancer may answer apart from the one that holds the
   socket. A carrier's role (T-595) offers neither: its stream is the door, and its legs take no token.
3. **What the role keeps, and how many**: the SHA-256 of each token that the node registers, by a text
   frame of its socket (`{"type":"token","digest":HEX,"expires":MS}`, an end of 0 withdraws one), never a
   token; a window of 4 for each session, and at most 256 live and 256 spent ones for each pair (64
   sessions of a node), those that end first making room
   (`crates/podssh-relay/src/serve/reverse/legs.rs`). Lost: one token at a time, as a leg that the role
   took while the node missed its word would leave none for the next; a window for each pair, for which
   the sessions of one node would race; no bound, as a node's frames would grow the role without one.
4. **Their life: a day at the role, from each registration**, which the node makes again at each token
   taken and at each new socket, and which a session's end withdraws; at its use, the pair's end holds
   too. Lost: the pair's life, as a crashed node's tokens would hold room for 72 h and more after a
   renewal; minutes, as a session that runs an hour with no move would find none at its resume.
5. **When a token is taken: at the upgrade, only while the node is joined with room for a session, which
   hears `{"type":"spent","digest":HEX}` before the session's `open`; with no node, `503` and nothing
   taken.** The role keeps each spent digest until its end, and refuses it when the node registers it
   again. Lost: a token taken at each upgrade, as an operator that retries while its node connects again
   would spend the whole window with no word to the node; no record of the spent ones, as a node that
   registers its window again on its next socket would bring back a token that a leg spent while it was
   away. The role's records live in memory: a node registers its own again on its next socket, after a
   planned stop's `1012`. Lost: the file of `--pairs`, written whole at each leg, and up to 4096 pairs of
   512 digests in it. The window that remains (`SECURITY.md`): after a restart of the role, a token that
   a leg spent while the node did not hear of it is good once more, for the node's door alone, which the
   channel holds.
6. **The operator's side**: the first leg takes the pair's connect token, as no session exists before
   it; each next leg (a resume, a move, a spare) takes the next token by
   `podssh_relay::reverse::legs::start`, from the CLI's layered client and the race of `ssh node://`'s
   roads (`crates/podssh-cli/src/layered.rs`, `crates/podssh-cli/src/ssh/roads.rs`). A 403 of a token is
   no refusal of the pair: the next leg tries it once more, as the node may not have registered it again
   after a restart, then the next one; after 8 in a row (twice the window) the legs take the pair's
   token, as with a node that gave no seed. Lost: the pair's token at the first refusal, which ends a
   session of a pair of `--once` at a restart of the role.
7. **The stop token's rotation: the node draws the next token, names its SHA-256 at `POST
   /v1/rotate/<name>` by the token now, keeps the new one in the store, then uses it once**, which makes
   it the pair's and ends each before it (`crates/podssh-relay/src/pair/rotate.rs`,
   `crates/podssh-cli/src/node_rotate.rs`). The role takes both the token now and the one to come until
   that use, so a node that stops at any step keeps a token that the role takes, and the new token
   crosses no wire before its first use; the file of `--pairs` keeps both. A 403 of the new one at its
   first use (another rotation took its place) puts the one before back in the store. Lost: a new token
   that the role draws and answers, as the Approach had it, because the answer crosses the wire, which a
   proxy that ends TLS logs, and a node that stops before it kept the answer loses its stop token for
   good.
8. **Its period: at the node's first socket that heard the offer, and each 24 h after; an hour after a
   try that did not take.** A node that missed a day (it was stopped) rotates at its next start; the role
   forces none, so a token that no node rotates stays as before T-615. Lost: each start alone, as a node
   that runs for weeks would keep one token; each hour, a write of the store each hour for a token that
   no operator holds.
9. **A pair of `--pair-file` keeps its stop token**, and the node says so once: its file is the user's,
   which T-592 decided is never rewritten, and a copy of it elsewhere would stop working with no word.
   Lost: rewriting it.
10. **What a podssh of before does.** A relay of the contract offers neither: no registration, no
    rotation, the pair's tokens as before. A node of before with this role registers none, and its
    operators keep the pair's token. An operator of before with this node reads past the seed and takes
    the pair's token; the node withdraws that session's 4 registrations at its end.
11. **What gets a seed**: a session that the end-to-end channel lets in above the resumable layer, on any
    road of the node, so that one that came by another road resumes on the pair's; none of `--plain`,
    which has no later leg, or `--no-e2e`, which has no place for a seed.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_once
```

Offline, through the role on the loopback: a leg's token takes one upgrade, a resume takes the next one
that the node gave, and a replayed one is refused; a rotated stop token ends the old one. Planted: the
role takes a spent token; the replay test fails.

## Correction

2026-11-04 (the drafting agent). The Premise holds at its files: the role keeps the SHA-256 of each of a
pair's three tokens and spends the connect token of a pair of `once` at its first upgrade
(`crates/podssh-relay/src/serve/reverse/pairs.rs`), and closes the node's socket with `1003 unknown
control type` for a frame that is not `ready`, `reject` or `close`
(`crates/podssh-relay/src/serve/reverse/node.rs`). Two parts of it give way. The token does not travel
to the operator: its seed does, once, in the verdict (Decision 1). The offer that the node reads is its
socket's `hello` (Decision 2). And the stop token is drawn by the node, not answered by the role
(Decision 7).

The new Approach, in place of the one above:

1. The role: the fields of `hello` and of `/relays.json`; the node's `token` frame; an upgrade of
   `/v1/connect/<name>` by a live token, taken only while the node is joined, the node told by `spent`
   before the `open`, and a spent token refused, also when registered again; `POST /v1/rotate/<name>`
   with the stop token and `{"digest": HEX}`, and the stop token to come, which its first use makes the
   pair's.
2. The node: a seed in the verdict of each session let in above the layer, its window of 4 registered
   before the verdict goes, moved at each `spent`, withdrawn at the session's end, registered again at
   each new socket; the rotation of a stored pair's stop token at its first socket that heard the offer
   and each day.
3. The operator: each leg after the first with the session's next token, the pair's token after 8
   refusals in a row.

The new Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_once
cargo test -p podssh-relay --features serve --lib serve::
cargo test -p podssh-relay --features pair --lib -- e2e:: reverse:: pair::rotate
cargo test -p podssh-cli --lib -- node_expiry man::
cargo test -p podssh-cli --test relay_serve_node
```

Offline, through the role on the loopback: a token that a node registered takes one upgrade, the node
hears which before the `open`, and a replay is refused, also once registered again; a token waits while
its node is away; through podssh's own node and operator, a session of a pair of `once` resumes on the
next token that the node gave, and the one that it spent is refused after; a rotated stop token ends the
one before at the first use of the new one, also across a restart of the role with `--pairs`. Planted:
the role takes a spent token (`t615-leg-reused`), the replay test fails; the first use of the new stop
token ends nothing (`t615-stop-unrotated`), the rotation's test fails; the operator reads no seed
(`t615-seed-unread`), the resume's test fails; a spent token moves no window (`t615-window-unmoved`), the
test of the window fails. OpenSSH's `ssh` with `podssh operator` as its ProxyCommand through a node of
the role, which `relay_serve_node` runs, crosses the node's rotation at its start.

## Done

2026-11-04, drafted (`fe2bbaf`, the agent stopped at a limit of use and was resumed), merged and measured
by the main session the same day. At the merge: the roads of DERP and OpenTunnel, which came after the
draft's base, give their channel an empty table of leases, as each road of no pair does; `frame::verdict`,
read by the tests alone, is the tests'; a test's `matches!` borrows what it then prints; and the test of a
resume boxes the node, the layer's handshake, the session and its steps, as together they outgrew the
2 MiB stack of a test's thread in a build with no optimization (with a 16 MiB stack it passed as it was;
the binary's own futures are boxed where it runs them, and its suites passed).

- The seed and the tokens (`crates/podssh-relay/src/e2e/legs.rs`, its tests in
  `crates/podssh-relay/src/e2e/legs_tests.rs`): the node's `Leases`, the operator's `Taker` inside
  `legs::during`; the seed after the verdict's code (`crates/podssh-relay/src/e2e/frame.rs`,
  `crates/podssh-relay/src/e2e/channel.rs`, `Asked::admit_with` of
  `crates/podssh-relay/src/e2e/handshake.rs`); `ends::Node::leases`, a seed for each session let in, and
  the operator's taker given the seed (`crates/podssh-relay/src/e2e/ends.rs`).
- The node's socket: `Handler::attach`, `registers` and `spent` (`crates/podssh-relay/src/reverse/node.rs`),
  forwarded by `Layered` and taken by `E2e`, `Routed` and the CLI's `Piped`; the `token` frames through
  the writer, and the `spent` frame read (`crates/podssh-relay/src/reverse/serve.rs`,
  `crates/podssh-relay/src/reverse/control.rs`); the operator's leg by its token and the offer of the
  rotation heard (`crates/podssh-relay/src/reverse/legs.rs`).
- The role: `crates/podssh-relay/src/serve/reverse/legs.rs`, beside `pairs.rs`, the `hello` and
  `/v1/rotate/` of `crates/podssh-relay/src/serve/reverse/mod.rs`, the `token` frame of `node.rs`, the
  `spent` frame of `operator.rs`, and `/relays.json` (`crates/podssh-relay/src/serve/docs.rs`).
- The rotation: `crates/podssh-relay/src/pair/rotate.rs`, `crates/podssh-cli/src/node_rotate.rs`, and the
  renewal's stop token now (`crates/podssh-cli/src/node_expiry.rs`).
- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_once`: 6 passed, three runs (the
  2 of T-226, and 4 of T-615: the draft counted 5).
- `cargo test -p podssh-relay --features serve --lib serve::`: 73 passed (among them the two new tests of
  `pairs_tests.rs`, and the `hello` and `spent` of `serve::reverse::tests`).
- `cargo test -p podssh-relay --features pair --lib -- e2e:: reverse:: pair::rotate`: 20 passed (7 tests of
  `e2e::legs`, 1 of `e2e::frame`, 1 of `reverse::legs`, 1 of `pair::rotate`).
- The CLI's whole `--lib`: 848 passed (`node_expiry`, and `man::`: the notes' flags and
  variables, `man::notes_legs`).
- `cargo test -p podssh-cli --test relay_serve_node`: 6 passed (each node of the role rotates its stop
  token at its start; `relay revoke` after it reads the new one).
- The relay crate's whole suite with `pair,serve,plain-ws,grant,code,quick,piping`: 83 targets, each
  passed; the CLI's `exit` 7, `exit_routes` 3, `doctor_exit` 3, `node_cut` 3 and `relay_serve` 18 too.
- Planted (`sh scripts/plant-each.sh --here t615-leg-reused t615-stop-unrotated t615-seed-unread
  t615-window-unmoved`): 4 caught.
- `cargo clippy -p podssh-relay --features serve,plain-ws,quick,pair,grant,code --all-targets` and `-p
  podssh-cli --all-targets`, with `-D warnings`, and with no feature, with `serve,plain-ws,quick` and the
  CLI with `iroh`: clean; rustfmt: clean once it reflowed three files; the library crates on Rust
  1.89: clean. The rotation's task looks every 2 s, for the node's whole run, whether a socket heard
  the offer; on a relay of the contract that is one read of a flag each 2 s, kept as it is.

# T-620: The stop token's rotation and the renewal follow the node's next pair at expiry

**Source:** T-615's draft (2026-11-04), which left it: a node that moves to its next pair at the
pair's expiry (T-395) still rotates and renews the pair that it started with, as T-592's renewal does.
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A node of podssh's relay role rotates its pair's stop token each day (T-615) and renews the pair
before its end (T-592). At the pair's expiry a node moves to the next pair (T-395), and the task of
each still holds the first pair: it rotates a stop token that ended with it, or renews nothing, and
the new pair's stop token is never rotated.

## Premise

- Read: the rotation's task takes the pair held at the node's start
  (`crates/podssh-cli/src/node_rotate.rs`), and so does the renewal (`crates/podssh-cli/src/node_expiry.rs`).
- Read: a node goes on with the next pair at its pair's expiry (T-395, `node_expiry.rs`).

## Approach

1. The rotation and the renewal read the pair that the node holds now, through the same `Held`, which the
   move to the next pair replaces, so that each next turn is the new pair's.
2. The new pair's stop token is rotated at its first socket that hears the offer, as the first pair's.

## Decision

2026-11-04 (the drafting agent). The Premise holds at its files: `watch` makes the node's copy of its pair
once, at its start, and the hook of the expiry moves only the end that the lines read
(`crates/podssh-cli/src/node_expiry.rs`), so the renewal, where it is still on, asks for the first pair's
name with the next one's end (a `403`, then no renewal for good), and stays off where the first pair's
relay renewed none; and the rotation's task, which a flag of the process wakes
(`crates/podssh-relay/src/reverse/legs.rs`), sleeps a day after its last turn and then rotates the first
pair's token (a `403`, and the task ends), or, where the first pair's relay offered none, rotates the first
pair at the first pair's relay as soon as the next pair's socket set the flag (a `404`, and the task ends).
Two more facts of the same reading: the loop of the lines sleeps up to 10 min after the expiry before it
reads the next pair's end, and the flag cannot tell the next pair's first socket from the first pair's. No
row of `docs/decisions.md` settles these, and none changes one.

1. **One `Held` for the pair now, which the hook replaces** (Approach 1): `node_rotate::Held` keeps the
   pair with its stop token as rotated and its end as renewed, in the place of the `Arc<Mutex<Pair>>` of
   T-615 and of `node_expiry::Current`, so that the hook, the renewal, the lines and the rotation read one
   place, and an end and a pair never disagree. The hook says its line first, then moves, so that the next
   pair's lines come after it. Lost: `Current` kept beside it, two places that a move sets one after the
   other; each task reading the store, which holds the next pair from the first one's last day, before the
   first ended.
2. **A move wakes each task**, by a `tokio::sync::watch` of the count of moves: the next pair's end, its
   renewal and its rotation at once. Lost: the sleeps as they were, up to 10 min for the lines and the
   renewal, and a day or an hour for the rotation.
3. **The next pair's own first socket that heard the offer** (Approach 2): the relay crate counts the
   sockets of the process that heard a `hello` with `stopRotation` (`legs::offers`; `legs::rotates` stays,
   as `offers() > 0`), and the node takes the count when it begins with a pair and rotates once it grew. A
   node's sockets are of one pair at a time, and the hook runs between the last socket of one and the first
   of the next. Lost: the flag of T-615, set by the first pair's sockets, which would rotate the next pair
   at once, before its relay said that it rotates; the flag reset at the move, which a count needs no
   order for; the pair's name in what a socket heard, which `reverse::serve` does not know.
4. **A refusal or a relay that serves none is the pair's, not the task's**: a relay that renews none, or
   refuses the renewal, gives that pair the lines of T-395; a relay that rotates none, or refuses the stop
   token, ends that pair's rotation; the next pair's relay is asked again. Lost: the end of each task for
   good, as before, which leaves a next pair on podssh's role unrenewed and unrotated after a first pair on
   the default relay, the case of a node that moves to its own relay.
5. **Nothing of the first pair after the move**: a rotation or a renewal in flight at the move writes
   nothing into the pair now (`Held::restop` and `Held::renewed` check the name), nor its line, and the
   store's copy only under its own name, as before. Lost: the hook taking the turn of item 6, which would
   hold the node's repair while a request by the stop token waits for its answer.
6. **One request by the stop token at a time** (`Held::turn`), each with its write of the store. Before, a
   renewal could send the token that a rotation's first use had just ended (a `403`: "the relay refused the
   renewal"), and their two writes of the store could cross, one's end or token lost; at a node's start the
   rotation waits for its socket, so the two did not meet, but after a move both begin at once. Lost: the
   order that the timing gave.
7. **The Prove's test**, `a_node_that_goes_on_with_its_next_pair_renews_and_rotates_that_one`: the first
   pair is the stand-in relay's, whose mode `expirefirst` ends it while the node runs, and the next one is
   the role's, made by `relay pair` in the first one's last day, and in its own last day by its record. The
   role's pairs live 72 h, and the role has no shorter life to give; a restart of the role on the same port
   with an edited `--pairs` file needs a port that the sockets of its last run may still hold. It is also
   the case where the defect showed most, a first pair of the default relay and the next of podssh's role.
   The rotation's line names no pair, as podssh never shows a pair's random name: the test reads the next
   pair's name in the store, with its new stop token and its new end, and `relay revoke` stops the pair
   with that token; the stand-in says each `/v1/renew/` and `/v1/rotate/` that it was asked for, on its
   stderr, with the pair's name and never a token (`scripts/fake_reverse.py`), and none comes after the
   move. Lost: a variable of the role for a short life of its pairs, a setting that the product would
   carry for a test alone.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve_node
```

A node of the role whose pair ends while it runs moves to the next one, and its next rotation names
the new pair's name; the first pair's stop token is not used again. Planted: the task keeps the first
pair; the test fails.

## Done

2026-11-04, drafted (`cc54c09`, unbuilt), merged and measured by the main session the same day, onto
`b750af3`.

- The pair now (`crates/podssh-cli/src/node_rotate.rs`): `Held`, its move, its turn, and the rotation of
  each pair that the node holds (`run`, `after`, `offered`, `once`); its tests, with no network, in
  `crates/podssh-cli/src/node_rotate_tests.rs` (a move replaces the pair and wakes each task; a rotation
  or a renewal of the pair before a move changes nothing after it; one request by the stop token at a
  time; the next pair's rotation waits for a socket that heard the offer after the move).
- The expiry (`crates/podssh-cli/src/node_expiry.rs`): the hook moves `Held` to the next pair after its
  line; `warn` reads the end of `Held`, wakes at a move, keeps a refused or unserved renewal to its pair,
  and takes the turn; `Renewer::once` names the pair that it asked for, and `took` changes nothing after a
  move; `Current` is gone.
- The count of the sockets that heard the offer (`crates/podssh-relay/src/reverse/legs.rs`, `offers`).
- The stand-in's line of each renewal and rotation that its contract has not (`scripts/fake_reverse.py`,
  `unserved`).
- `crates/podssh-cli/tests/relay_serve_node.rs`: the test of item 7, and `both` through `each_of`.
- `docs/reverse.md` ("Tokens of one leg", item 5), `docs/relay.md`, `docs/cli.md` and the node's notes in
  the manual (`crates/podssh-cli/src/man/notes_legs.rs`), each with no line moved; `docs/STATUS.md`, in
  T-615's row, as a row of its own would move the lines that entries cite after it.
- `cargo test -p podssh-cli --test relay_serve_node`: 7 passed (the 6 of before, and the new one, a node
  through the stand-in's first pair and the role's next one).
- `cargo test -p podssh-cli --lib -- node_rotate node_expiry man::`: 49 passed (the 4 new tests of
  `node_rotate::tests` and the 5 of `node_expiry::tests` among them).
- `cargo test -p podssh-relay --features pair --lib -- reverse::legs`: 1 passed.
- `cargo test -p podssh-cli --test node_expiry`: 4 passed (T-395's, through the hook and the lines that
  this changed; the stand-in's new line too).
- The CLI's whole `--lib`: 867 passed; the node's suites through the stand-in (`node`, `node_moves`,
  `node_detach`, `node_copy`): 31 passed.
- Planted (`sh scripts/plant-each.sh --here t620-rotation-keeps-first t620-renewal-off-for-good
  t620-restop-after-move t620-offers-a-flag`): 4 caught.
- `cargo clippy -p podssh-cli --all-targets` and `-p podssh-relay --features pair` and `--features
  pair,serve,plain-ws`, `--all-targets`, with `-D warnings`: clean; rustfmt: clean once the merge
  formatted `crates/podssh-cli/tests/relay_serve_node.rs`.

# T-668: A node that keeps its sessions across its own upgrade: the new binary takes the sockets and the layer's state

**Source:** the study of osewa, 2026-11-04 (Q99; `docs/research/osewa.md`, `docs/research/osewa-code.md`, `docs/research/osewa-paper.md`).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

osewa's sessions outlive a restart of its server, as each session's holder is a process of its
own. A podssh node's sessions end with its process, so `podssh update` on a node ends each session
that it carries.

## Premise

- The resumable layer keeps each session's state in the node's process (`crates/podssh-relay/src/session/`).

## Approach

1. `podssh update` or a signal on a running node starts the new binary (rule 3: this binary started
   again at the user's request, Q61), which inherits the node's links and the sshd connections.
2. The layer's state (ids, secrets, offsets, replay buffers) passes over a pipe, and each session
   goes on in place; the sshd's TCP connection survives.
3. Windows needs `WSADuplicateSocket`: probed.

## Decision

2026-11-05 (the drafting agent of T-668), each call with what lost:

1. **The node becomes the new binary by `execve`, in its own process**, not a child that starts
   beside it while the old one serves (nginx's way with its master). The pid stays, so a supervisor
   of `--restart` (`crates/podssh-cli/src/detach/supervise.rs`), a unit of systemd whose main pid
   is the node, the scope of Q61 and the lock of a detached run see no end, and a node in the
   foreground of a terminal stays there. Lost: a child beside the old process, whose new pid each of
   them takes for the node's end, and which starts a second node of one pair (a `409`); a fork that
   writes the state, which leaves a writer process that the rule against helpers does not cover.
2. **SIGUSR2 is the request**, and `podssh update` sends it to each node of `--detach` of the user
   that takes it, once it replaced the binary, while the run's lock is held and its record names
   the pid (`detached/NAME.upgrade` says that the node takes it). Every `podssh node` ignores the
   signal from its start, so a stray one ends no node of a road that does not take it. Lost: a flag
   of `podssh update` to ask for it, two steps for the case of this entry's Problem; no signal from
   `update`, which leaves the Problem as it was; SIGHUP, which a detached run ignores (Q61).
3. **The binary is probed first**: the file at the node's path (`update::replace::running`, which
   reads past Linux's `(deleted)`) runs once as `podssh --version` with `PODSSH_HANDOVER=probe`, 10 s
   at most, and must add `podssh-handover 1`. A build of before, another program or another version
   of the handover leaves the node as it is. Lost: the version's number alone (a later build may
   drop a version of the handover); a hidden flag (each flag is in the manual, and a user never
   types this one).
4. **The relay's socket is not handed over; the sessions are.** The node's socket stops as a stop
   does, each session's `close` saying `the node is upgrading` (a client of the layer takes a node's
   `close` as a loss, `crates/podssh-relay/src/reverse/closes.rs`), and the new binary connects
   again; each client resumes on a new leg, which is what the layer is for. Lost: the node's socket
   across the exec (see the Correction).
5. **The state is the layer's as values, never its records**
   (`crates/podssh-relay/src/session/handover/mod.rs`): the offsets, the replay buffer, the bytes
   not yet written to the target, the flags; with the end-to-end channel above, its keys (snow's raw
   split, its feature `risky-raw-split`), its nonces, the bytes cut short each way and the seed of
   its tokens of one leg. A version byte guards each part, and the probe asks for it. The channel's
   transport comes back by a handshake of two keys of the new process whose cipher keys are then set
   to the session's (`rekey_manually`), as snow builds none from keys. Lost: a transport of podssh's
   own over chacha20poly1305, a second cipher that must match snow's to the byte.
6. **The state passes in anonymous memory**: `memfd_create` on Linux, a POSIX shared object
   unlinked at once on macOS, else a file of the cache's private directory unlinked at once; the
   variable names its descriptor and the node's pid, so a child of the new binary reads nothing.
   Lost: a pipe (see the Correction); a file by its path, which another process could open.
7. **A session that cannot move is kept as an ended one**, its resume answered with `CLOSE` and why
   (a UDP flow, a target inside the process, a channel that does not stop within 10 s); a session of
   `--plain` ends at the stop, as it has no layer. Lost: refusing the upgrade while one such session
   lives (a node of a long UDP flow would never upgrade); dropping it, which its client would learn
   as a forgotten session.
8. **A binary that does not start after its probe gives the sessions back**, read from the same
   bytes as the new binary would read them, and this binary serves again (`node_upgrade::AGAIN`).
   Lost: the node's exit with its sessions lost.
9. **Unix alone in this entry.** On Windows no signal asks, and a process that starts the new binary
   would change the node's pid (item 1), so the node takes a new binary at its next start, its
   sessions ending as before, and the manual says so. `WSADuplicateSocketW` passes a socket to a
   process of a known pid, which only a parent that stays can give; that is a design of its own,
   for an entry that the main session files from the report of this draft.
10. **The roads that take it**: the pair's road, with or without the transit road beside it, whose
    keeper is the upgrade's. The other roads (`--iroh`, `--derp`, `--quick-tunnel`, the Piping
    Server or OpenTunnel road alone, `--carrier`, `--temporary`) ignore the signal and go on with
    their binary, as before.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_handover
cargo test -p podssh-relay --lib -- session::handover e2e::hold e2e::channel
cargo test -p podssh-cli --lib -- node_upgrade
cargo test -p podssh-cli --test node_moves
sh scripts/plant-each.sh --here t668-replay-dropped t668-nonce-reset t668-no-socket
```

A new test: a session through a node goes on across the node's upgrade, its bytes whole.

## Correction

2026-11-05 (the drafting agent of T-668), read in the tree of this draft:

- The Problem's `podssh update` ends no session by itself: it renames the new file over the running
  one, and `crates/podssh-cli/src/update/replace.rs:5` says "running file, which keeps running from
  the old inode"; the manual says that an installed node "goes on with its own binary until it
  starts again" (`crates/podssh-cli/src/man/notes_update.rs:23`). The sessions end when the node
  starts again to take the new binary. The Premise holds: the sessions are in the process
  (`crates/podssh-relay/src/session/keep.rs:142` says "slots: Mutex<HashMap<SessionId, Slot<A>>>,").
- Approach item 1, "inherits the node's links": a link to the relay is a TLS session in rustls,
  often inside a proxy's CONNECT, whose secrets rustls exports for kernel TLS but builds no
  connection from; the new binary connects again, and the layer resumes each session on a new leg
  (Decision, item 4). The sshd's connections are inherited.
- Approach item 2, "over a pipe": with `execve` no writer is left to feed a pipe, and a pipe holds
  64 KiB on Linux by default, where the state holds up to 64 MiB of replay buffers. It passes in
  anonymous memory (Decision, item 6).
- Approach item 3: see Decision, item 9.
- The channel's state had to move too, which the Approach did not name: each session of a node runs
  the end-to-end channel above the layer by default, and its keys live in snow's transport
  (`crates/podssh-relay/src/e2e/channel.rs:39` says "state: StatelessTransportState,").
- A detached child closes each descriptor from 3 up at its start
  (`crates/podssh-cli/src/detach/child.rs:175`), which would close the sessions' sockets in the new
  binary: it no longer does when the variable of the handover names a descriptor.

## Done

2026-11-05, drafted (unbuilt, UNVERIFIED); the main session merges, builds and measures it.

- The layer's state as values and its bytes (`crates/podssh-relay/src/session/handover/mod.rs`,
  `crates/podssh-relay/src/session/handover/wire.rs`), with the parts of `Link`, of the replay
  buffer and of the carry (`crates/podssh-relay/src/session/link/parts.rs`,
  `crates/podssh-relay/src/session/pump/parts.rs`); `Keeper::hand_over` and `Keeper::take_over`
  (`crates/podssh-relay/src/session/keep/handover.rs`); a closed slot keeps the words of its
  `CLOSE`; the far end names the session's id around its target's opening (`handover::scope`).
- The channel held between two messages: its carry in a buffer of its own
  (`crates/podssh-relay/src/e2e/channel/carry.rs`), its keys from the handshake, the hold, its
  registry by the layer's id and the channel's state (`crates/podssh-relay/src/e2e/hold/mod.rs`,
  `crates/podssh-relay/src/e2e/hold/state.rs`, `crates/podssh-relay/src/e2e/hold/resume.rs`), the
  lease of its tokens of one leg handed over and restored (`crates/podssh-relay/src/e2e/legs.rs`).
- The node (`crates/podssh-cli/src/node_upgrade/mod.rs`, with `pass.rs`, `probe.rs`, `state.rs` and
  `mark.rs` beside it): the signal, the probe, the keepers, the handover, the exec, the bytes, the
  mark of a detached node; `node.rs` and `node_transit.rs` take its keepers and its stop;
  `--version` answers the probe; a detached child keeps the handed descriptors, and its ready leaves
  nothing again; `podssh update` asks each detached node.
- The manual (`crates/podssh-cli/src/man/notes_upgrade.rs`, `PODSSH_HANDOVER` in ENVIRONMENT),
  `docs/reverse.md` ("A node's upgrade in place"), `docs/design.md` (section 5), `docs/STATUS.md`.
- `cargo test -p podssh-relay --test session_handover`: UNVERIFIED (3 tests: over the target as it
  is, with the channel's keys and nonces, and a target that cannot move).
- `cargo test -p podssh-relay --lib -- session::handover e2e::hold e2e::channel`: UNVERIFIED.
- `cargo test -p podssh-cli --lib -- node_upgrade`: UNVERIFIED.
- `cargo test -p podssh-cli --test node_moves`: UNVERIFIED (the new test: 32 MiB down through the
  stand-in relay, SIGUSR2 at a quarter, the bytes whole, the same pid, no new connection to the
  test's server but the new binary's look at TARGET).
- The whole suites of the relay crate and of the CLI, as the channel's carry and the bounds of
  `serve_asked` changed: UNVERIFIED.
- Planted (`sh scripts/plant-each.sh --here t668-replay-dropped t668-nonce-reset t668-no-socket`):
  UNVERIFIED.
- clippy with `-D warnings` on Linux, macOS and Windows (the parts of Unix alone are behind `cfg`):
  UNVERIFIED.

# T-630: The relay role's table of 4096 pairs keeps no share for each key, so one key of a list can take each place

**Source:** GitHub #128 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A role that mints for a list of keys, or for the net's members, lends each of them a part of its
reverse road; but its table of pairs is one count for all. One key that pairs in a loop fills the 4096
places, each pair lives 72 h, and each other key is told that the relay is full.

## Premise

Read at `2042200`:

- `crates/podssh-relay/src/serve/reverse/pairs.rs:31` says "pub const MAX_PAIRS: usize = 4096;", and
  `crates/podssh-relay/src/serve/reverse/pairs.rs` said "if map.len() >= MAX_PAIRS {" at line 263 at
  `2042200`, whoever asks; `crates/podssh-relay/src/serve/reverse/pairs.rs:29` says
  "pub const LIFETIME_MS: u64 = 72 * 3600 * 1000;".
- A pair holds no maker (`crates/podssh-relay/src/serve/reverse/pairs.rs:78-98`), nor does its kept
  form (`crates/podssh-relay/src/serve/reverse/pairs.rs:397-402`).
- The key is known where a pair is made: `crates/podssh-relay/src/serve/mod.rs`, at lines 327-331 at
  `2042200`, took the key that proved itself, said its fingerprint in a line, and returned `Ok(())`,
  which `crates/podssh-relay/src/serve/reverse/mod.rs` called at line 186 at `2042200`, before the pair
  is made.
- The brake slows one address, not one key: `crates/podssh-relay/src/serve/brake.rs:22` says
  "pub const PER_MINUTE: usize = 120;", so one address fills the table in under 35 minutes, and several
  addresses sooner (arithmetic, not a measurement).
- The full table's answer is `429` with the table's size (`crates/podssh-relay/src/serve/reverse/mod.rs`,
  lines 198-200 at `2042200`), the same for a starved key as for a full relay.

## Approach

1. A pair keeps its maker's fingerprint (none for `--mint anyone`), in memory and in the kept file, a
   field with a default so that a file of before reads, its pairs counted against no key.
2. A reserve for each key: the table's places divided by the keys that the role mints for (the list's
   and the net's members at that moment), at least 1. A key may make a pair while the places left, after
   it, still hold each other key's unused reserve; past that, `429` that names the key's share and what
   it holds: `/v1/pair: this key holds N pairs, past its share of M while others wait`.
3. A pair that ends or expires gives its place back to its key; a renewal keeps its maker.
4. `docs/relay.md` ("The relay role's reverse road") says the share.

## Decision

2026-11-04 (the drafting agent of the triage). A reserve that a busy key may borrow past, not a ceiling:
a key alone on a role of many keys keeps the table, and each other key still finds its share. Lost: the
issue's ceiling for each key, which leaves one busy key among idle ones at 4096 divided by their
number; the same words as a full table, as a starved key could not tell its share from a full relay.

2026-11-04 (the drafting agent of T-630). The reserve is half the table in equal parts, `room / (2 *
keys)`, one place at least, and the whole table for a key alone (or for a role that counts no key); the
other half is the part that a busy key borrows, first come. With 4 keys of 4096 places, a busy key among
idle ones keeps 2560 and each other key 512. Lost: the Approach's reserve of `room / keys` for each key
(see the Correction); a reserve owed only to the keys that hold a pair (a key that comes after a greedy
one, the issue's case, would find nothing for 72 h); a share counted by the net's members that its
policy lets mint (the policy is the binary's, read for each key; each member counts, which makes each
reserve smaller and never lets one key take another's). A starved key's words: `/v1/pair: this key
holds N pairs, past its share of M while others wait`, with M the key's reserve, its own count, and no
other key's name or count; a full table keeps its words. podssh's client printed no word of a `429`
before, so it now says the relay's words after its own, as it does for a `503`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib serve::reverse::pairs
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib serve::keys
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_reverse
cargo test -p podssh-relay --features pair --test pair
cargo test -p podssh-cli --lib net::mint
sh scripts/plant-each.sh --here t630-reserve-a-ceiling
```

With a small table in the test: n-1 greedy keys leave each other key its reserve; one key alone takes
the whole table; an expired pair returns its place; a role for anyone counts no key; a kept file of
before reads, and the new field comes back from a restart; the refusal names the key's share. Planted:
the reserve read as a ceiling, and the test of a key alone fails.

## Correction

2026-11-04 (the drafting agent of T-630). The Approach's item 2 contradicts its Decision. A reserve of
`room / keys` for each key, held while the key is idle, leaves a busy key among idle ones the places of
its own part and the rest of the division alone, about 4096 divided by the number of keys: the ceiling
that the Decision lost. So the reserve is half that (the second paragraph of the Decision), and the
other half is borrowed. The Prove's "a key alone" is both cases: a busy key among idle ones goes past
its reserve (the planted ceiling fails that test), and a key that the role mints for alone takes the
whole table. The role's helpers that draw a pair's names and tokens, and compare its digests, left
`crates/podssh-relay/src/serve/reverse/pairs.rs` for `crates/podssh-relay/src/serve/reverse/draw.rs`, so
that it stays within 500 lines; the share is `crates/podssh-relay/src/serve/reverse/share.rs`.

## Done

2026-11-04, merged from its draft (`49ee0c1`).

- The relay role's table of pairs keeps a reserve for each key that may mint, half of the room over
  the keys (`room/(2·keys)`); the other half goes to whoever asks first, and a key alone takes the
  whole table. The role records which key made each pair, and a `429` names the asking key's count
  and its share alone (`crates/podssh-relay/src/serve/reverse/share.rs`, `draw.rs`, `pairs.rs`);
  `podssh relay pair` says the relay's words of a `429`.
- `cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib --
  serve::reverse serve::keys reverse::fair`: 35 passed; `--test relay_serve_reverse`: 6 passed;
  `cargo test -p podssh-relay --features pair --test pair`: 12 passed; `cargo test -p podssh-cli
  --lib net::mint`: 3 passed; the relay crate with those features: 825 passed, 0 failed. Plants
  `t630-reserve-a-ceiling` caught, and the three that the draft brought up to date
  (`t427-no-bound`, `t454-no-brake`, `t255-joins-during-stop`) caught. Clippy and rustfmt clean.

# T-633: No rule, written once, for a member of an answer that is absent where it carries a guarantee, and no helper that reads `None` and `false` alike

**Source:** GitHub #131 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

podssh reads optional members of a peer's answers in three ways: a hint whose absence keeps a floor of
its own, a feature's offer whose absence is no offer, and a guarantee that this end asked for, whose
absence must undo what was made. Each reader writes its own test, and no document states the classes,
so the next member's author copies a neighbour, and an `is_some()` reads a `false` as a yes.

## Premise

Read at `2042200`; each reader that exists is right:

- A guarantee asked for: `crates/podssh-relay/src/pair/once.rs:34-37` takes `"once": true` alone, and
  `crates/podssh-cli/src/relay_cmd.rs:274-275` stops the pair that a relay made with no such word
  before it refuses (`crates/podssh-cli/src/relay_cmd.rs:272` says "A relay that does not offer --once
  made a pair whose token takes each").
- A grant's markings: `crates/podssh-relay/src/grant/door.rs:94` says "it has no end, and a grant needs
  one", `crates/podssh-relay/src/grant/door.rs:118` says "it has no critical option", and
  `crates/podssh-relay/src/grant/door.rs:130` says "no such file, so no grant is let in".
- A hint: `crates/podssh-relay/src/reverse/control.rs:91` says "and 16 sessions, a small number that
  cannot exhaust a relay." for a `hello` with no `maxSessions`.
- Offers, each `true` alone: `crates/podssh-relay/src/e2e/legs.rs:79` says "and nothing else", and
  `crates/podssh-relay/src/reverse/legs.rs:50-52` the same for the stop token's rotation.
- So three readers write the same comparison apart, and no helper holds it; `docs/reverse.md` and
  `docs/relay.md` describe each member where it appears, and name no class (searched for "absent").
- The issue's claims of the three roads were not read by its author line by line; they hold, as above.

## Approach

1. A paragraph in `docs/reverse.md` (and a pointer from `docs/relay.md`, "The relay role's reverse
   road"): the three classes, and what absence means in each: a hint keeps a conservative floor and
   never refuses; an offer is no offer, said once at `-v`; a guarantee asked for is checked against the
   ask, and what was made is undone before the refusal is said, never retried.
2. A small module of `podssh-relay` with the one comparison (`Some(true)` alone confirms) and the
   check of a guarantee against the ask; the three readers above call it.
3. A test for each class, with a stand-in peer that leaves the member out, one that sends `false`, and
   one that sends another type.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib once
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib legs
cargo test -p podssh-cli --test relay
```

`None`, `false`, `"true"` and `1` are each no confirmation; an absent hint keeps the floor;
`relay pair --once` against a stand-in relay that answers with no `once` stops the pair before it exits, in that
order. Planted: the helper with `is_some()`, and the tests of `false` fail.

# T-643: Neither end of the reverse road compares the `version` of the role's `hello`, and an operator's offer of the net answered plainly says nothing

**Source:** GitHub #141 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A node reads the `version` of a relay's `hello` and drops it, so a node and a relay of two dialects get
as far as a frame that one of them does not read, and that frame is dropped with no word; the node
reconnects for ever. On the channel, an operator that offers the net's document and gets a plain proof
opens the session without the document, and neither end says so.

## Premise

Read at `2042200`:

- `crates/podssh-relay/src/reverse/control.rs:70` holds the version, and
  `crates/podssh-relay/src/reverse/control.rs:98-109` reads the two limits alone;
  `crates/podssh-relay/src/reverse/serve.rs:178` is its one call. The role sends `"version": 1`
  (`crates/podssh-relay/src/serve/reverse/mod.rs:339-347`), as the default relay does
  (`crates/podssh-relay/src/reverse/control.rs:62-63`). The issue's line numbers are of an older tree.
- `crates/podssh-relay/src/reverse/serve.rs:215` says "Ok(NodeInbound::Unknown) | Err(_) => {}".
- `crates/podssh-relay/src/reverse/node.rs:268` says "Next::Exit(_) => Next::Reconnect,", and
  `crates/podssh-relay/src/reverse/node.rs:118` says "A reconnection would" of `Exit::Unusable`.
- The channel: an operator offers only with a document (`crates/podssh-relay/src/e2e/handshake.rs:110`),
  a node answers in the net's form only when offered and when it holds one
  (`crates/podssh-relay/src/e2e/handshake.rs:208-209`), and the operator keeps no net then
  (`crates/podssh-relay/src/e2e/handshake.rs:123-126`). That is T-429's design, not a slip:
  `crates/podssh-relay/src/e2e/net.rs:8` says "An end of before must never meet a form that it does not
  read." A node outside the net, or of before, is let in by its own door and its key's proof; the
  document carries the net's newer state, not the session's admission. The issue reads it as a downgrade.
- The dialer's headers are fixed in `crates/podssh-ws/src/handshake.rs:37`.

## Approach

1. `PROTO` and `PROTO_MIN`, both 1, beside `Hello`; a `hello` with no `version` is 1.
2. The node compares the `hello`'s version: one it does not read ends the node as `Exit::Unusable` with
   one sentence that names both ranges and which side to update, handled in the run loop's arm, as
   `Next::Exit` carries a word alone; never a reconnection.
3. The role: a node's or operator's upgrade may carry `X-Podssh-Proto`; one that the role does not read
   gets `426` with the sentence and `X-Podssh-Proto: 1`, after the pair's token is checked, so that a
   peer with no token learns nothing; no header is version 1.
4. The channel: an operator that offered and got a plain proof says it once at `-v` ("the node holds no
   document of the net; the session goes on without it"), and `podssh status` of the session says it.
5. `docs/relay.md` and `docs/reverse.md` say the version's check and the header.

## Decision

2026-11-04 (the drafting agent of the triage). For the operator to confirm (Q86): a net offer answered
by a plain proof stays a session, said in a line, not refused as the issue asks. The document is the
net's state passed on between members, and its absence is a node outside the net or of before, which
T-429 lets in by its door; a refusal would cut each member off each node that is not one. Lost: the
refusal (that cost); silence (the defect the issue found). With `PROTO_MIN` equal to `PROTO` the
version's check refuses nothing until the first change of the dialect, as the issue says.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib reverse::control
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test reverse_node
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_contract
cargo test -p podssh-relay --test e2e_net
```

A `hello` of version 2 ends the node as unusable, with the sentence, and no second connection; a
`hello` with no version is 1; the role answers `426` with both numbers to an upgrade with
`X-Podssh-Proto: 2` and a good token, and `403` with a bad one; an operator with a document and a node with none open a
session, and the operator's `-v` says it once. Planted: the arm that reconnects on the new exit, and
the test of no second connection fails.

# T-647: A pair of the relay role is served or ended; no halt that keeps its name and its node's socket

**Source:** GitHub #145 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

An owner who wants a pair's operators kept out for a while has `stop`, which ends the pair, or a stop
of the role. Neither tells an operator why, and `relay status` cannot tell a pair kept out on purpose
from one that is down.

## Premise

Read at `2042200`:

- The reverse road's paths: `crates/podssh-relay/src/serve/reverse/mod.rs:74-78`, with `renew` and
  `rotate` beside the issue's list; each path but `node`, `connect` and `status` takes the stop token
  (`crates/podssh-relay/src/serve/reverse/mod.rs:104-108`).
- `status` answers `online`, `sessions` and `expires`
  (`crates/podssh-relay/src/serve/reverse/mod.rs:137`); `stop` ends the pair with
  `crates/podssh-relay/src/serve/reverse/mod.rs:150`, which says "operator stopped reverse relay", and
  the node exits on it (`crates/podssh-relay/src/reverse/node.rs:136`).
- A refusal with a cause before the upgrade exists for a planned stop alone: `503` with `Retry-After: 1`
  (`crates/podssh-relay/src/serve/reverse/mod.rs:160-163`). Since T-255 a planned stop sends `1012`,
  and the node joins the role that comes back, so a restart costs no 409's wait; the issue's waits
  (`crates/podssh-relay/src/reverse/serve.rs:70` and `crates/podssh-relay/src/session/resume.rs:44`)
  are for a node whose old socket the role still holds.
- A pair's state (`crates/podssh-relay/src/serve/reverse/pairs.rs:124-135`) has no halt, and the file is
  486 lines, so the state goes in a module beside it.
- The client: `crates/podssh-relay/src/pair/renew.rs:70-83` and the line and JSON of
  `crates/podssh-cli/src/relay_status.rs:50-67`; `relay` has no subcommand for it
  (`crates/podssh-cli/src/relay_cmd.rs:161-168`).
- A `503` is no refusal on the way (`crates/podssh-relay/src/piping/probe.rs:27-33`), so no other road
  starts on it.

## Approach

1. `POST /v1/halt/<name>` (an optional reason in the body, 200 bytes at most) and
   `POST /v1/resume/<name>`, each with the stop token; the halt is in memory alone, so a role that restarts
   serves again.
2. A halted pair: each session is closed once with `1011 the pair's owner halted it`; each operator's
   upgrade gets `503` with the reason and no `Retry-After`, checked before a once-pair's token is
   spent and before a token of one leg is taken; the node keeps its socket and hears
   `{"type":"halted"}` where the role's `hello` offered it, a podssh frame that a node of before skips.
3. `status` says `"halted": true` and the reason; `relay status` prints it and puts it in `--json`.
4. `podssh relay halt NAME [--reason TEXT]` and `podssh relay resume NAME`, with the pair's stored stop
   token, as `relay pair --renew` uses it; the manual and `docs/relay.md`.

## Decision

2026-11-04 (the drafting agent of T-647). No row of `docs/decisions.md` settles these, and none
changes one; none is a call of policy: each is podssh's role's own, beside the contract, and a node
or an operator of before works as before.

1. **The halt is a field of the pair's state, under its lock** (`State::halted`), and its code a module
   beside `pairs.rs` (`crates/podssh-relay/src/serve/reverse/halt.rs`), as `pairs.rs` is at its limit:
   the request's check refuses an operator before any token is spent, and an operator that passed it
   but registers its session after the halt gets `1011` with the halt's words, as the lock orders the
   two. Lost: a flag beside the lock (a halt between the check and the registration would let one
   session in).
2. **A second halt changes nothing**: the first's time and words stay, and the answer says
   `"already": true`; resume, then halt, for new words. Lost: a second halt that replaces the words
   (two halts of the owner's scripts would overwrite each other).
3. **The owner's words go into the `503`'s body and the status, never into a Close**, whose reason is
   always `the pair's owner halted it`: a Close's reason is cut at 123 bytes, and podssh's client
   reads it by its words. The words are optional, 200 bytes at most, one line (no control character,
   else `400`), trimmed; blank words are none.
4. **The node hears `{"type":"halted","since":MS,"reason":TEXT}` and `{"type":"resumed"}`**, the second
   beyond the Approach so that a node can tell the end of a halt, and a node that joins a halted pair
   hears `halted` after its `hello`, which offers `"halt": true` (not a carrier's). podssh's node of
   this build skips both, as each type that it does not know: its sessions and its socket go on, and
   `relay status` says the halt. Lost: a line of the node's (its socket's loop has no words for its
   user, a change of `crate::reverse::serve` beside this entry); a Close to the node (it would lose
   its name, the issue's case).
5. **The status says `"halted"` always, false too, and `halted_since` and `halt_reason` while a halt
   holds**: a check reads one field, and a client of the contract skips the fields that it does not
   know, as it skips `expires`. `/relays.json` offers `"reverse": {"halt": true}` beside the others.
   Lost: `halted` only while true.
6. **The halt's `503` is final for podssh's layered client** (`layered::is_final`, by the words
   `the pair's owner halted it` that `podssh_relay::pair::halt::HALTED` holds for both sides): an
   operator whose session the halt closed asks for a new leg, as after each `1011`, and ends at once
   with the owner's words, as the issue's "a close and not a pause" asks; a planned stop's `503`
   stays one to wait out. Lost: a pause (each such client would retry for its resume deadline,
   10 minutes, in silence, and resume after the owner's resume within it).
7. **`relay halt` and `resume` refuse `--relay-host` (64)**, as `pair --renew` does: they ask the relay
   that made the stored pair. `--reason` goes with `halt` alone (64). A relay that halts none (404 or
   405) is 69, with `relay revoke` as the way to end the pair; a refused stop token is 77.
8. **The role says a line for each halt and resume of an owner, and none for each operator that it
   refuses**: each try of an operator would be one. Nothing reaps a halt but a resume, a stop, the
   pair's end or a restart of the role, as the issue says.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_halt
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_reverse
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_once
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_contract
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib -- serve::reverse pair::
cargo test -p podssh-cli --lib -- relay_halt relay_status layered::tests
cargo test -p podssh-cli --test relay
cargo test -p podssh-cli --test relay_serve_node
cargo test -p podssh-cli --test man_flag_parity
sh scripts/plant-each.sh --here t647-halt-after-the-token t647-halt-ends-the-node t647-halt-not-final
```

A halted pair answers an operator `503` with its reason before the upgrade; the node's socket stays
across a halt and a resume, and a second node is still `409`; each session hears one `1011`; a resume
takes the next operator on the same socket; a once-pair's token is unspent after a refusal of a halt;
`relay status --json` reads `halted`. Planted: the halted check after the token is spent, and the
once-pair's test fails; the node's socket closed by the halt, and the test of the same socket fails;
a halt's `503` not final for the layered client, and its test fails.

## Correction

2026-11-04 (the drafting agent of T-647). Read in this tree before the draft (`df92546`):

- `crates/podssh-relay/tests/relay_serve_reverse.rs` is 459 lines, so the role's tests of a halt are
  a new target, `relay_serve_halt`, on raw sockets as `relay_serve_contract` speaks, and the Prove
  above names it; `relay_serve_reverse` and `relay_serve_once` stay in it, as the node's `hello` has
  a field more and the leg's path a check before it. The CLI's test against the role is in
  `relay_serve_node`, beside the renewal's, and `relay` keeps the stand-in's, which halts none.
- The Approach's `halted` frame has a second, `resumed`, and a status field more, `halted_since`, and
  the client's end of a leg reads a halt's `503` as final (the `## Decision`, items 4 to 6).

## Done

2026-11-04, merged from its draft (`3957215`).

- `POST /v1/halt/<name>` and `/v1/resume/<name>` in podssh's relay role, by the pair's stop token,
  and `podssh relay halt NAME [--reason TEXT]` and `podssh relay resume NAME`: a halted pair keeps
  its name, its node's socket and its budget of reconnects; each new session gets a `503` with the
  reason, checked under the pair's lock before any token is spent; a halt closes each session once,
  and a resume takes the next on the same socket; a node hears `halted` and `resumed`, which an
  older node ignores; `relay status` names `halted`; a layered client ends its session at a halt.
- `cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test
  relay_serve_halt --test relay_serve_reverse --test relay_serve_once`: 4, 6 and 6 passed; `--lib
  -- serve::reverse pair::`: 37; `cargo test -p podssh-cli --lib -- relay_halt relay_status
  layered::tests`: 10; `--test relay --test relay_serve_node --test man_flag_parity --test
  relay_serve`: 16, 8, 6 and 24. Plants `t647-halt-after-the-token`, `t647-halt-ends-the-node` and
  `t647-halt-not-final` caught. Clippy and rustfmt clean.

# T-648: A node's socket queues each session's bytes in one line of 256 places, so one session's backlog delays each other session's

**Source:** GitHub #146 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A node's socket carries up to 64 sessions, and their bytes wait in one queue, written in the order they
came. A bulk copy on a slow egress beside an interactive shell fills it, and each keystroke's echo waits
behind the copy's queue, not the network.

## Premise

Read at `2042200`:

- `crates/podssh-relay/src/reverse/serve.rs:104-110` keeps control apart from data, and a session's
  bytes in order with its close; `crates/podssh-relay/src/reverse/serve.rs` said
  "mpsc::channel(1024), mpsc::channel(256)" at line 145 at `2042200`: one queue of data for all the
  sessions of the socket.
- Each item is one read of up to `CHUNK_BYTES` (`crates/podssh-relay/src/reverse/serve.rs:349`), which
  `crates/podssh-relay/src/reverse/framing/legs.rs:51` says is 65504: up to 16 MiB of one session ahead
  of another's (arithmetic on the two constants, not a measurement).
- The writer is `biased`, control first (`crates/podssh-relay/src/reverse/serve.rs:388`), then the data
  queue in order, each item's frames awaited before the next
  (`crates/podssh-relay/src/reverse/serve.rs:411-418`); it chooses among no sessions.
- The relay role's own socket has one bound for each socket too
  (`crates/podssh-relay/src/serve/reverse/outbox.rs:27`), a change of its own (the issue says so).

## Approach

1. A fair queue in a module beside `crates/podssh-relay/src/reverse/serve.rs` (441 lines): a queue for
   each session, a turn each in a round, each with a room of 4 items and the socket's whole room of 256
   kept, so that the memory stays the same.
2. `Out::Data` and `Out::LocalEnd` go to it, the close after its session's bytes as now; the writer takes
   control first, then one turn; `Out::Closed` and `Out::Stalled` drop that session's queue; the end of
   the socket ends it as now.
3. The relay role's socket (`crates/podssh-relay/src/serve/reverse/outbox.rs`) takes the same queue,
   with its own test, in the same change, as both sides of a socket carry the same mix.

## Decision

2026-11-04 (the drafting agent of T-648). The queue is one module, `crates/podssh-relay/src/reverse/fair.rs`
(feature `pair`), generic over the key of a line and its pieces, with a room for each line and one for
the socket in the units of each piece's cost; both ends use it.

1. A line that holds nothing, queued or in flight, always takes one piece, past the socket's room: the
   session that writes little never waits for the room that the busy ones hold, which is the latency
   that the issue asks for; the socket's queue then holds its room and one piece of each other session
   at most. Lost: the socket's room as a hard bound, where an interactive session's read waits for a
   bulk one's room to come back, and a semaphore in the order of arrival, which is that same wait.
2. The node's line holds 4 reads and the socket 256, as the Approach says. The role's line holds the
   contract's bound, 1 MiB, in bytes, and the socket the same: one session to a slow node keeps the room
   that it had, and another session's empty line takes its frame. Lost: a quarter of the bound for each
   line, which halves what one bulk session to a node holds and changes no latency that the issue
   names.
3. The role's text frames to a node (`open`, `spent`) go before the sessions' bytes, as the node's own
   control does since T-410: an `open` that waited behind 1 MiB of another session's bytes could meet
   the role's own 15 s for a `ready`. A session's `close {id}` goes in its own line, after its last
   bytes, so that a node hears each byte of an operator who left; a session that the node closed or
   refused drops what waits for it. Lost: the role's one line in the order of arrival for text and data
   alike.
4. Turns, not bytes: a session of small pieces gets as many turns as one of 64 KiB pieces, which is the
   case of an interactive shell beside a copy. Lost: a deficit round robin by bytes, more code for a
   case that no report names.
5. The wire is the contract's, unchanged: no frame is new, and each session's frames keep their order;
   only the order among the frames of different sessions changes, which the contract leaves to the
   sender. A relay or a node of before reads each frame as it did.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib reverse::fair
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib serve::reverse
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test reverse_fair
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test reverse_node
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_reverse
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code
cargo test -p podssh-cli --test relay_serve_node
sh scripts/plant-each.sh --here t648-one-queue-node t648-one-queue-role
```

Against the scripted relay, a session that writes 4 bytes while another has 20 MiB queued gets them out
before the other's next 2 MiB; with both backed up, frames alternate by session; a session's close comes
after its last bytes; a closed session's queue is dropped. Planted: one queue again, and the test of the
4 bytes fails.

## Correction

2026-11-04 (the drafting agent of T-648). `crates/podssh-relay/tests/reverse_node.rs` is 395 lines and
other entries cite its lines, so the node's tests of this entry are a target of their own,
`crates/podssh-relay/tests/reverse_fair.rs`, with the same scripted relay; `reverse_node` stays in the
Prove, as each of its tests must still pass. The 20 MiB of the Prove is what one session wrote until
each queue on its way was full: the tests wait for that as a condition (a write that stays pending while
each other task of the test's one thread runs), not for a time, and one queue for all held 16 MiB there.
The role's test runs on a carrier's pipes (T-595), which carry the role's own code with no kernel's
buffer between the role and its node, so that the bound that it reads is the role's queue alone.

## Done

2026-11-04, merged from its draft (`f1f9449`).

- A node's socket and the role's writer to a node keep a line for each session and serve a turn
  each (`crates/podssh-relay/src/reverse/fair.rs`): a session waits for one piece of each other
  session at most, where one queue put it behind each byte queued before it; a line that holds
  nothing always takes one piece; the node keeps 4 reads a session and 256 a socket, the role 1 MiB
  a session and a socket; a session's `close` follows its own bytes. No frame of the wire changed.
- `cargo test -p podssh-relay --features pair --test reverse_fair`: 4 passed; `--lib
  reverse::fair` and `serve::reverse`: passed; the relay crate with each serve feature: 825
  passed; `cargo test -p podssh-cli --test relay_serve_node --test node_moves --test node_cut
  --test relay_serve`: 7, 2, 3 and 24 passed. Plants `t648-one-queue-node` and
  `t648-one-queue-role` caught. Clippy and rustfmt clean.
- At the merge, the test of both sessions backed up waited for 21 frames that the backlogs it left
  could not give (20 s, each run): its two sessions now keep writing while the relay reads, and it
  holds what the queue gives, never three frames of one session in a row and each a third of them
  at least, as a line whose writer is a moment behind is empty at its turn (one pair in 21, each
  run).

# T-650: Each operator's leg waits for its node's `ready` before its first byte: no session opened ahead for a node that asks for spares

**Source:** GitHub #148 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

A run of short connections to one node (a copy of many files, a loop of commands) pays, at each one, a
round trip of `open` and `ready` and the node's dial of its target before its first byte.

## Premise

Read at `2042200`:

- The role's leg: a new id (`crates/podssh-relay/src/serve/reverse/operator.rs:81`), room under
  `MAX_SESSIONS` (`crates/podssh-relay/src/serve/reverse/operator.rs:91`), `open` to the node
  (`crates/podssh-relay/src/serve/reverse/operator.rs:111`) and the wait for `ready` (`:120`), 15 s at
  most (`crates/podssh-relay/src/serve/reverse/mod.rs:64`); no node is `1011 node unavailable`
  (`crates/podssh-relay/src/serve/reverse/operator.rs:99`).
- A node readies a session only after its local side accepted:
  `crates/podssh-relay/src/reverse/control.rs:118` says "Only after the local side has accepted", so a
  spare is a live connection to the target with no one on it, and only a node that says it may make one
  gets one.
- The role's `hello` already carries offers that a node of before keeps and skips
  (`crates/podssh-relay/src/serve/reverse/mod.rs:339-347`, T-615); a node's word back is a podssh frame
  of its socket, as T-615's `token` frame is.
- `crates/podssh-relay/src/serve/reverse/pairs.rs` is 486 lines, so the spares go in a module beside it.
- With T-615 each leg takes a token of its own; a spare is a session, not a leg, so it changes no token.

## Approach

1. The role offers spares in its `hello` (`"spares": true`); a node started with `--spares N` (at most
   16) answers with `{"type":"spares","want":N}`; a node that says nothing gets none.
2. The role keeps up to the asked number of readied sessions for the node, inside `MAX_SESSIONS`; a leg
   takes a readied spare before it draws a new id, and else goes the way of today; a spare that a take
   used is replaced.
3. Each minute the role closes the spares that no leg took, down to the node's floor, and asks for more
   (up to its number) when a leg found none; a spare whose target closed is closed and not counted.
4. The node's line says each spare it holds; `docs/relay.md` says the frames.

## Decision

2026-11-04 (the drafting agent of the triage). Spares only when a node asks, by its own flag: a spare
is a connection to the target that no operator uses, which a node's owner chooses. Lost: spares by
default (that cost on each node); spares that the role opens with no `ready` (an operator then meets a
dead session, as `crates/podssh-relay/src/reverse/control.rs:119` says of an early `ready`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_reverse
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test reverse_node
```

With one spare readied, an operator's first byte reaches the node with no `open` for that leg; a node
whose `hello` answer has no word gets no spare and its leg works as before; a minute with no take leaves
the floor; two takes with no spare ask for more, never past `MAX_SESSIONS`. Planted: a spare handed out
before its `ready`, and the test of a dead session fails.
