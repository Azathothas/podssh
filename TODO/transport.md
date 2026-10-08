This file holds the open defects of `podssh-transport`, one entry for each row of the section
"podssh-transport" of the former defects page (`git show 3ee70dc:docs/defects.md`): T1, T2, T5,
T7, T8, T9 and T10. No command of the default build uses this crate; only examples do
(`crates/podssh-cli/examples/live_irc.rs:20-22`). The reverse runners of milestone M4 use it, so
T-071, T-072, T-073, T-075 and T-076 come first in M4 (`docs/ROADMAP.md:150-158`, and the work
order in `TODO/PROGRESS.md`). M4 starts after M3 is complete (`docs/ROADMAP.md:7-9`). T-082 moves
the repaired codecs into `podssh-relay` later in M4, and T-074 and T-077 can close in that commit.

# T-071: T1: `send_text` sends a binary frame, so the node leg cannot work

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row T1 (high).
Confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The node leg sends its control messages (`ready`, `reject`, `close`) as JSON, and the relay wants
them in text frames. podssh-transport puts each of them on the wire as a binary frame. The relay
reads a binary node frame as a 32-character session id and a payload. The first 32 bytes of
`{"type":"ready","id":...` are not hex, so the relay closes the node socket with
`1003 bad multiplex id`, and each session on that socket ends. No command uses the node leg yet.

## Premise

Read, at `692b3b0`: `WsSocket::send_text` calls `self.session.send(text)`
(`crates/podssh-transport/src/socket.rs` lines 114-118). The seam trait `WsSession` has `send`,
`send_pong` and `read`, and no text method (the same file, lines 74-81). The live adapter maps
`send` to `RelaySession::send_binary` (`crates/podssh-transport/src/adapt.rs` lines 37-39).
`Leg::send_control` reaches the wire only through `send_text` (`socket.rs` lines 247-263).
`podssh-ws` already has `RelaySession::send_text` (`crates/podssh-ws/src/session.rs:92-95`).

Read, at `692b3b0`: the test double records each `send` as `OPCODE_BINARY`
(`crates/podssh-transport/tests/socket.rs` lines 43-47). The one `send_text` test counts frames
and does not check the opcode (the same file, lines 121-122). `FrameQueue` keeps the frame type
(`crates/podssh-transport/src/socket.rs` lines 409-418), but it replaces `WsSocket`, so it cannot
show this defect.

Read: the contract sends control as text, and data as binary frames that start with 32 hex
characters (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:138-141`,
`docs/relay.md:206-211`). A prefix that is not hex closes the node with `1003 bad multiplex id`
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:176`).

## Approach

The lines below are those of `692b3b0`.

1. Add `async fn send_text(&mut self, text: &str) -> Result<(), String>` to `WsSession`
   (`crates/podssh-transport/src/socket.rs` lines 74-81). It takes `&str`, because RFC 6455
   allows only UTF-8 in a text frame.
2. Forward it to `RelaySession::send_text` in `crates/podssh-transport/src/adapt.rs` (lines
   36-50). Reuse that method; build no frame in this crate.
3. In `WsSocket::send_text` (`socket.rs` lines 114-118), convert with `std::str::from_utf8`, and
   refuse bytes that are not UTF-8 with a new `CodecError` variant. Check the 4 KiB control cap
   (`crates/podssh-transport/src/framing.rs` lines 58-62). Count the frame only after the send
   succeeds.
4. Make the double in `crates/podssh-transport/tests/socket.rs` (lines 25-60) record
   `(opcode, bytes)` for each of its methods. Keep one double; do not add a second one.
5. Pitfall: `Socket::send_text` takes `&[u8]` (`socket.rs` line 29). Keep that signature, so
   `FrameQueue` does not change, or change both in one commit.
6. In the same commit, update the `podssh-transport` row of `docs/STATUS.md`, and close this
   entry in place (`TODO/RULES.md:41-42`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-transport --test socket -- a_control_frame_leaves_as_text
cargo test -p podssh-transport --no-fail-fast
python scripts/check-repo.py
```

The new test `a_control_frame_leaves_as_text` in crates/podssh-transport/tests/socket.rs sends
`control::ready(&id)` through `Leg::send_control` over `WsSocket`. It asserts that the double
recorded `OPCODE_TEXT` with the exact JSON bytes, and that `send_data` recorded `OPCODE_BINARY`
with the 32-byte id first. Plant: make `WsSocket::send_text` call `session.send` again; the test
must fail on the opcode. No command uses this leg, so there is no check of the binary here; T-079
runs the node leg against the live relay.

## Done

2026-10-09, in the commit "The node leg's control leaves as a text frame".

- `WsSession` has `send_text(&mut self, text: &str)`, and the adapter forwards it to
  `RelaySession::send_text`; this crate builds no frame of its own.
- `WsSocket::send_text` keeps its `&[u8]` signature, so `FrameQueue` did not change. It refuses
  a control over the 4 KiB cap (`ControlFrameTooLong`) and bytes that are not UTF-8 (the new
  `CodecError::ControlNotUtf8`, which has no relay close code, because the frame never leaves
  this client; its row cites RFC 6455 section 8.1). It counts a frame only after the session
  took it.
- `Leg::socket()` gives a test the socket underneath, read-only.
- The one double in `crates/podssh-transport/tests/socket.rs` records the opcode of each write,
  and can fail the next write.
- Prove: `cargo test -p podssh-transport --test socket -- a_control_frame_leaves_as_text`: 1
  passed (`ready` leaves as `OPCODE_TEXT` with the exact JSON; `send_data` as `OPCODE_BINARY`
  with the 32-byte id first). New beside it: text that is not UTF-8 and a control of 4097 bytes
  never leave and are not counted, 4096 bytes leave; a write that the session failed is not
  counted. `cargo test -p podssh-transport --no-fail-fast`: 73 passed, 0 failed.
  `cargo test --no-fail-fast`: 773 passed, 0 failed, 7 ignored.
- Plant: `WsSocket::send_text` calls `session.send` again: 3 tests failed;
  `a_control_frame_leaves_as_text` on the opcode (`left: (2, ...)`, `right: (1, ...)`).

# T-072: T2: a received Close frame loses its code and reason

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row T2 (high).
Confirmed here on `3ee70dc` by reading the code; a related gap in `closes.rs` found while reading.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay ends a reverse socket with a WebSocket Close that carries a code and a reason, for
example `1001 pair expired` or `1001 operator stopped reverse relay`. podssh-transport turns that
Close into `Unexpected("opcode 0x8 is not a data frame")`. The code and the reason are lost, so
the close table never runs, and the two `1001` reasons, which need opposite actions, look the
same. The text of a read error is lost too.

## Premise

The lines of `crates/podssh-transport` below are those of `3d4785a`.

Read: `RelaySession::read_frame` echoes a Close and returns it to its caller
(`crates/podssh-ws/src/session.rs:195-203`). `WsSocket::recv` handles the opcodes of text, binary,
Ping and Pong, and maps each other opcode, Close included, to `TransportError::Unexpected`
(`crates/podssh-transport/src/socket.rs` lines 136-164). A read error becomes
`Aborted { clean: false }` and its text is dropped (the same file, lines 165-168). The adapter
states the gap (`crates/podssh-transport/src/adapt.rs` lines 25-29). `Unexpected` is
`Retry::Never`, and only `Closed` reaches `classify` (`crates/podssh-transport/src/error.rs` lines
225-234).

Read: the helper `closed(code, reason, clean)` exists and has no caller (`socket.rs` lines
478-481). `podssh-ws` parses a Close payload in `close_code_and_reason`
(`crates/podssh-ws/src/session.rs:298-306`), and `podssh proxy` uses it
(`crates/podssh-cli/src/proxy.rs:239-242`).

Read, a related gap that the former defects page did not list: `Classified::message` prints
"code withheld" and "reason withheld" for a close that matches no row, and the row's own words
for a matched row, never the received reason (`crates/podssh-transport/src/closes.rs` lines
119-150). The test that says the reason survives only checks that the message is not empty
(`crates/podssh-transport/tests/closes.rs` lines 255-258). The rules want the code and the reason
(`docs/relay.md:155-163`, `docs/reverse.md:42-44`).

## Approach

1. In `WsSocket::recv` (`crates/podssh-transport/src/socket.rs` lines 136-171 at `3d4785a`), add
   an arm for opcode 0x8. Parse the payload with `podssh_ws::session::close_code_and_reason` and return
   `closed(code, &reason, true)`. Reuse that parser; do not write a second one.
2. A Close with no status code gets code 1005, as RFC 6455 section 7.1.5 says. The parser already
   removes control characters from the reason.
3. Keep the text of a read error: give `Aborted` a detail field. Its retry stays `Reconnect`.
4. In `crates/podssh-transport/src/closes.rs` (lines 119-150 at `3d4785a`), print the received
   code and reason for each close, matched or not. Remove `reason_as_written` and `session_code`.
5. Pitfall: after a Close, a later `recv` must not read the socket again. Return the same error.
6. This entry also repairs the `closes.rs` gap; write no second entry for it. Close this entry
   in place in the same commit (`TODO/RULES.md:41-42`).

## Decision

2026-10-09: the parser of `podssh-ws` is reached through two lines in `adapt.rs`
(`close_code_and_reason`, and `one_line` for the message), and `socket.rs` and `closes.rs` call
those. The rule of `crates/podssh-transport/src/lib.rs` is that `adapt` is the only module that
names `podssh-ws`. Lost: a call to `podssh_ws` from `socket.rs` itself, which breaks that rule
for no gain; a second parser in this crate, which the Approach forbids.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-transport --test socket -- a_close_keeps_its_code_and_reason
cargo test -p podssh-transport --test closes -- the_message_names_the_code_and_the_reason
cargo test -p podssh-transport --no-fail-fast
```

The first test feeds the double a Close with code 1001 and `pair expired`. It asserts
`TransportError::Closed` with that code and reason, and `retry() == Retry::NewPair`; with
`operator stopped reverse relay` it asserts `Retry::Never`. Add one Close payload captured from
the live relay (for example `1000 target closed` through `podssh proxy`) as a fixture, so the
parser also meets bytes that podssh did not make (`docs/development.md:204-206`). The second test
asserts that an unmatched `4000 x` and a node's `1011 connection refused` both show their own code
and reason. Plant: delete the new 0x8 arm; the first test must fail with `Unexpected`.

## Done

2026-10-09, in the commit "A Close from the relay keeps its code and reason".

- `WsSocket::recv` reads a Close (opcode 0x8, the new `OPCODE_CLOSE`) with the parser of
  `podssh-ws` and returns `TransportError::Closed` with the code and the reason; a Close with no
  status code is 1005. A read error is `Aborted { clean: false, detail }` with its text, and its
  retry stays `Reconnect`. After either, each later read returns the same error and does not
  read the socket again.
- `Classified` carries the received `code` and `reason`; `message` names them for each close,
  matched or not, with the reason through `one_line` and the relay's cap (100 characters, 123
  bytes). `reason_as_written` and `session_code` are gone.
- `FrameQueue` moved, unchanged, to `crates/podssh-transport/src/queue.rs` (re-exported as
  `socket::FrameQueue`), to keep `socket.rs` under 500 lines (480 before, 429 now).
- The fixture: `scripts/capture-close.py` (new), a client of the Python standard library, captured
  the payload of the live relay's Close after github.com:22 closed: `03e874617267657420636c6f736564`,
  1000 `target closed`. `docs/development.md` names the script.
- Prove: `cargo test -p podssh-transport --test socket -- a_close_keeps_its_code_and_reason` and
  `cargo test -p podssh-transport --test closes -- the_message_names_the_code_and_the_reason`: 1
  passed each. Beside them: the captured Close, a Close with no code (1005), a reason with
  control characters, and a read error that keeps its text. `cargo test -p podssh-transport
  --no-fail-fast`: 78 passed, 0 failed. `cargo test --no-fail-fast`: 778 passed, 0
  failed, 7 ignored.
- Plants: the 0x8 arm deleted: 3 tests failed with `not a Close: Unexpected("opcode 0x8 is not a
  data frame")`. The message given `reason withheld` again: 2 tests of `closes` failed.

# T-073: T5: the `ready` gate is not enforced

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row T5 (high).
Confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

On the node leg, data for a session must not go out before the node sends `ready` for it. The
relay answers early data with `1003 data before ready`, which closes the node socket and ends each
session on it. podssh-transport has a `ready` flag that nothing checks, and the flag is one for
the leg, not one for each session. Its two read methods each discard a frame of the other type
with an error, so a caller cannot read the mixed control and data of a node socket.

## Premise

The lines of `crates/podssh-transport` below are those of `6d7737f`.

Read: `Leg` holds one `ready: bool` (`crates/podssh-transport/src/socket.rs` lines 222-232);
`set_ready` and `is_ready` write and read it (lines 244-253); `send_data` never reads it (lines
274-299). A test sends node data before `ready` and expects success
(`crates/podssh-transport/tests/plants.rs` lines 308-318).

Read: `recv_data` returns an error for a text frame (`socket.rs` lines 331-349) and
`recv_control` returns an error for a binary frame (lines 356-374). Both read the same socket, so
the frame of the other type is lost.

Read: the contract closes the node with `1003 data before ready` and the operator with
`1008 wait for ready`, and reaps an operator after 15 s with no `ready`
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:177`, `:180`, `:190`). The rules:
stop the writes of a session after its `close`; send `ready` only after the local service
accepts; route by id (`docs/reverse.md:12-18`).

## Approach

1. Replace `recv_data` and `recv_control` with one `recv` that returns `Data { id, payload }` or
   `Control(Control)` (`crates/podssh-transport/src/transport.rs` lines 37-49 at `6d7737f`). A
   text frame on the forward leg stays an error.
2. Keep the state of each session id on the node leg: opened, readied, closed. Use a map keyed by
   `SessionId` (`crates/podssh-transport/src/framing.rs:69-73`). The runner of T-079 uses this
   map; it keeps no second copy of the state.
3. `send_data` on the node leg refuses an id that is not readied, or that is closed, before a byte
   reaches the socket. The error names `1003 data before ready` or `1003 unknown session id`.
4. A `ready` sent through `send_control` marks its id readied only after the send succeeds. A
   received `close {id}` marks it closed (`docs/reverse.md:12-14`). Remove `set_ready`.
5. On the operator leg, data before the `ready` frame is refused here; T-080 owns the queue.
6. Change `crates/podssh-transport/tests/plants.rs` (lines 308-318 at `6d7737f`) to expect the
   refusal. Close this entry in place in the same commit (`TODO/RULES.md:41-42`).

## Decision

2026-10-09:

1. A closed session is forgotten: the map holds `Opened` and `Readied`, and `close` removes the
   id. The relay answers a stale id and an invented one the same way (`1003 unknown session id`,
   spec line 172), so the two need no separate state, and a node that runs for 72 hours must not
   keep each id that it ever saw. Lost: a `Closed` state for each id, which grows without bound.
2. A refusal is a typed `TransportError::Refused(Refusal)`, named by the close that the relay
   would answer with, and its `session_action` comes from the close table (`AnswerReadyFirst`,
   `WaitForReady`). The runners of T-079 and T-080 branch on it: queue before `ready`, drop after
   `close`. The two refusals that were text (a node frame with no id, `1009 bad multiplex
   frame`; a text frame on the operator leg, `1003 binary frames required`) use it too. Lost:
   text in `Unexpected`, which a runner could only match as a string.
3. `send_control` checks a node's frame as the relay checks it (JSON, a known type, an id of 32
   lowercase hex: spec lines 173-175), and refuses a `ready` for an id that is not open, because
   a `ready` for an old id closes the node socket with `1003` (`docs/reverse.md`, "Node", 2).
   This goes beyond steps 3 and 4, for the reason of this entry. Lost: a `send_control` that
   sends any text, which leaves the state of the session wrong when the relay refuses the frame.
4. On the operator leg, data after a `reject` or a `close` is refused as `Unexpected`: the relay
   closes the operator socket after them, and its table has no row for data after that.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-transport --test socket -- node_data_before_ready_is_refused_and_not_sent
cargo test -p podssh-transport --test socket -- mixed_control_and_data_all_arrive_in_order
cargo test -p podssh-transport --no-fail-fast
```

First test: over the frame double, `send_data` for an id with no `ready` returns an error and
`sent_frames()` does not change; after `ready` it sends; after a received `close {id}` it refuses
again. Second test: the double queues `open` (text), a binary frame for that id, and `close`
(text); one `recv` loop gets all three, in order. The JSON follows the contract
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:138-139`); replace it with frames
captured from the live relay when T-079 records them. Plant: remove the readied check; the first
test must fail because a frame was sent.

## Done

2026-10-09, in the commit "The node leg sends data only for a readied session".

- `Leg::recv` is the one reader: it returns `Inbound::Data { id, payload }` or
  `Inbound::Control(Control)` in the order of the socket, and moves the session of a control
  frame. `recv_data`, `recv_control` and `RecvFrame` are gone; `ForwardRunner::recv_bytes` uses
  `recv`.
- `crates/podssh-transport/src/sessions.rs` (new): `Sessions` (by id, `Opened` or `Readied`),
  `OperatorState` (`Waiting`, `Readied`, `Closed`), `Refusal` with the relay's rows that it
  names, and `check_outbound`. `Leg::sessions()` and `Leg::operator_state()` give the state to
  the runners; `set_ready` and `is_ready` are gone.
- `send_data` on the node leg refuses a session that is opened and not readied
  (`1003 data before ready`) and one that was never opened or is closed (`1003 unknown session
  id`); on the operator leg, data before `ready` (`1008 wait for ready`) and after a `reject` or
  a `close`. `send_control` refuses what the relay would close the node socket for, and moves the
  state only after the send succeeded.
- Prove: `cargo test -p podssh-transport --test socket -- node_data_before_ready_is_refused_and_not_sent`
  and `-- mixed_control_and_data_all_arrive_in_order`: 1 passed each. New beside them:
  `operator_data_waits_for_ready_and_stops_after_reject` and
  `a_control_frame_the_relay_would_refuse_never_leaves`; `plant_data_before_ready` expects the
  refusal; T-071's test opens its session first, as on the wire. `cargo test -p podssh-transport
  --no-fail-fast`: 82 passed, 0 failed. `cargo test --no-fail-fast`: 782 passed, 0
  failed, 7 ignored.
- Plants, each restored: the readied check removed: `node_data_before_ready_is_refused_and_not_sent`
  failed (data for an id that was never opened went out) and so did `plant_data_before_ready`;
  the operator's wait removed: `operator_data_waits_for_ready_and_stops_after_reject` failed; a
  frame that fails `check_outbound` sent anyway: `a_control_frame_the_relay_would_refuse_never_leaves`
  failed; the check of `ready` removed: the first test failed; a node leg whose `recv` refuses a
  text frame: 4 tests failed, `mixed_control_and_data_all_arrive_in_order` among them.

# T-074: T7: the backpressure module is not used

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row T7 (medium).
Confirmed here on `3ee70dc` by reading the code.
**Category:** chore
**Milestone:** M4
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`crates/podssh-transport/src/backpressure/mod.rs` and `ledger.rs` hold about 590 lines of pacing
code, with about 630 lines of tests. Nothing outside these tests uses them. The model is wrong for
the forward path, and the ledger has two defects, so a later caller would inherit them.

## Premise

Read: only the module line, a re-export and two test files reach the module
(`crates/podssh-transport/src/lib.rs:34`, `crates/podssh-transport/src/lib.rs:52`,
`crates/podssh-transport/tests/backpressure.rs`, `crates/podssh-transport/tests/backpressure_plants.rs`).

Read: the module says that the forward path drops a frame under backpressure, from the row
`1011 relay backpressure` (`crates/podssh-transport/src/backpressure/mod.rs:4-22`). That row is in
the table of the reverse path (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`).
On the forward path the relay closes with `1013` at 2 MiB and drops no frame
(`docs/relay.md:164-168`). The ledger counts the completion of local writes, which does not show
the relay's queue (`crates/podssh-transport/src/backpressure/ledger.rs:212-254`).

Read, the two ledger defects (the row does not name them; this is the reading here):
(a) a budget refusal in `begin` pops a parked write of another caller, because this write was
never pushed on that path (`crates/podssh-transport/src/backpressure/ledger.rs:181-187`, `:195-197`);
(b) `complete` sends parked writes and commits their bytes with no budget check
(`crates/podssh-transport/src/backpressure/ledger.rs:240-252`, compare `:193-204`), so a session
can pass the 32 MiB budget.

Read: the design removes the module (`docs/design.md:107-108`). The SSH window of 512 KiB is the
flow control that podssh uses (`docs/relay.md:165-166`).

## Approach

1. Delete `crates/podssh-transport/src/backpressure/mod.rs`, `ledger.rs`, both test files, and the
   lines `crates/podssh-transport/src/lib.rs:34` and `:52`.
2. Keep no part of it. The runners of T-079 and T-080 bound their queues with bounded channels
   and the relay's caps (`docs/reverse.md:30-35`), not with a ledger.
3. Check with `git grep` that no script or test still names the deleted files.
4. Update the line counts of the crate in `docs/STATUS.md:213`, and close this entry in place.
5. T-082 can do these steps in the move; then this entry closes with the commit of T-082.

## Decision

Recommendation: delete the module, because the design already says so (`docs/design.md:107-108`),
nothing uses it, and its premise contradicts the measured forward path. The alternative, repair
the two ledger defects and keep it for the reverse legs, lost: the ledger measures local write
completions, which do not show the relay's queue, so a repaired ledger still paces on the wrong
signal.

## Prove

```sh
export CARGO_BUILD_JOBS=4
git grep -n "backpressure::\|Ledger" -- crates scripts ; test $? -eq 1
cargo test -p podssh-transport --no-fail-fast
python scripts/check-repo.py
```

`git grep` exits 1 when no code or script names the module (exit 0 means that a caller is left).
The tests show that nothing else depended on it, and the repository check passes.

# T-075: T8: a 403 is not retried with a new token, and a 503 is retried

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row T8 (medium).
Confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

podssh-transport decides which HTTP answers to an upgrade it may retry. It never retries a `403`,
also when a new token repairs it, and it retries a `503`, which the contract says not to retry.
On the reverse legs, a wrong rule loops against a stopped pair, or gives up on a pair that only
expired.

## Premise

The lines of the files that this entry changed are those of `1a00ba2`.

Read: `HttpFailure::retry` maps `Forbidden` (403) to `Retry::Never` and `Unavailable` (503) to
`Retry::Reconnect` (`crates/podssh-transport/src/error.rs` lines 151-168). `HttpFailure` keeps
the status and not the body (the same file, lines 122-146 and 186-196), so it cannot tell
`missing or wrong token` from a policy refusal. A test asserts the current rule
(`crates/podssh-transport/tests/closes.rs` lines 129-149).

Read: the contract: `403 missing or wrong token` needs a new token; a `403` that names the target
is a policy refusal; `503` means that the relay does not issue or check tokens
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:97-103`, `docs/relay.md:104-107`). On
the reverse path each failed authentication is `403 reverse: forbidden` (`docs/relay.md:137-139`),
also after `POST /v1/stop` (`docs/reverse.md:51-53`). A `409` from `/v1/pair` means "pair again"
(`docs/relay.md:188-190`); a `409` on `/v1/node/<name>` means "exit" (`docs/reverse.md:19`).

Read: the forward path already follows the contract in `podssh-relay`. It mints once again after a
`403` for a cached token that is not a policy refusal (`crates/podssh-relay/src/open.rs` lines
236-244 and 113-117). It sends a `503` to the next host, never to the same one (the same file,
lines 53-76, and the test at line 300).

## Approach

1. Keep the body: build `HttpFailure` from `ConnectError::Refused { status, body }`
   (`crates/podssh-ws/src/client.rs` lines 117-120). Reuse `podssh_relay::open::is_policy_refusal`;
   do not parse the body a second way.
2. Make the rule depend on the leg (`crates/podssh-transport/src/transport.rs:117-127`):
   forward `403` that is not a policy refusal: a new `Retry::NewToken` (mint once, then stop);
   forward `403` policy: `Never`; reverse `403`: `ReverseForbidden`, and the runner of T-079 picks
   `NewPair` when the stored `expires` has passed (T-078), else `Never`; `503`: `Never` on this
   host, and failover stays the caller's rule.
3. Make `409` depend on the endpoint: `/v1/node/<name>` gives `Never`; `/v1/pair` pairs again once.
4. Update `crates/podssh-transport/tests/closes.rs` (lines 129-149) and the texts of
   `crates/podssh-transport/src/error.rs` (lines 170-184). Close this entry in place.
5. Pitfall: the body comes from the network. Keep it out of format strings and remove control
   characters before it reaches a terminal (`SECURITY.md:49-52`).

## Decision

2026-10-09: the one parser of a policy refusal moves to `podssh-ws`
(`podssh_ws::client::is_policy_refusal`, beside `ConnectError`); `podssh_relay::open` re-exports
it, so `podssh proxy` and the forward opener keep their name for it, and `podssh-transport`
reaches it through `adapt.rs`. Lost: a dependency of `podssh-transport` on `podssh-relay`, as step
1 says. It becomes a cycle when the runners of T-079 and T-080, in `podssh-relay`, use the codecs
of `podssh-transport` (T-082, step 1), and Cargo refuses a cycle.

Also: `HttpFailure::from_answer(status, body, Asked)` takes what was asked, `Asked::Upgrade(leg)`
or `Asked::Pair`, because a `409` and a `403` mean different things on each. A `403` on
`/v1/pair`, which takes no token, is `Other(403)` and `Never`. `Retry::ReverseForbidden` is not
`is_retryable`: only the runner knows `expires`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-transport --test closes -- http_answers_follow_the_contract
cargo test -p podssh-transport --no-fail-fast
cargo test -p podssh-relay --no-fail-fast
```

The new test gives the relay's own bodies (`missing or wrong token`,
`forward: github.com:25 not in the ALLOW list`, `reverse: forbidden`,
`forward relay authentication is not configured`) with `403` and `503` for each leg, and asserts
the action. The bodies come from the contract and from the tests of
`crates/podssh-relay/src/open.rs:281-299`. Plant: map `503` back to `Reconnect`; the test must
fail.

## Done

2026-10-09, in the commit "An HTTP answer to an upgrade keeps its body and follows the contract".

- `HttpFailure::from_answer` replaces `from_status`. A forward `403` is `TokenRefused`
  (`Retry::NewToken`, new: mint once, then stop) unless its body names the target
  (`PolicyRefused`, `Never`; a `400` with such a body too); a reverse `403` is
  `ReverseForbidden` (`Retry::ReverseForbidden`, new); a `503` is `Never` on this host; a `409`
  is `NameInUse` (`Never`) on an upgrade and `PairAgain` (`NewPair`) on `/v1/pair`.
- `TransportError::Http { failure, body }` keeps the body, through `one_line` and the cap of a
  close reason, and prints it after the explanation. `socket::http_failure(status, body, asked)`
  and `adapt::refused(&ConnectError, asked)` build it.
- `is_policy_refusal` is in `podssh-ws` now (see Decision); `podssh-relay` re-exports it.
- Prove: `cargo test -p podssh-transport --test closes -- http_answers_follow_the_contract`: 1
  passed (14 answers, the four bodies of the contract on each leg, `409` on a node and on
  `/v1/pair`, and a body with ESC printed with no control character). `cargo test -p
  podssh-transport --no-fail-fast`: 82 passed, 0 failed. `cargo test -p podssh-relay
  --no-fail-fast`: 26 passed, 0 failed, 2 ignored. `cargo test --no-fail-fast`: 782
  passed, 0 failed, 7 ignored.
- Plants, each restored: `503` mapped back to `Reconnect`: the test failed on the `503` row of the
  forward leg; the policy check removed: the test failed on the policy row.

# T-076: T9: host and node names are not validated or escaped

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row T9 (medium).
Confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

podssh-transport builds the relay path from a host name or a node name with `format!`. A name with
`/`, `?`, `#`, `..`, a space or a line break changes the request: another path, a query string, a
fragment, or a broken request line. Node names come from `/v1/pair`, from a file or from the user,
so each one is input.

## Premise

The lines of the files that this entry changed are those of `4b6e917`.

Read: `LegTarget::path` formats `/connect/{host}/{port}`, `/v1/node/{name}` and
`/v1/connect/{name}` with no check (`crates/podssh-transport/src/endpoint.rs` lines 34-43).
`endpoint` appends it to the origin as it is (the same file, lines 134-162). The tests use only
`github.com` and `podssh` (`crates/podssh-transport/tests/endpoints.rs` lines 70-85).

Read: `WsClientConfig::validate` refuses whitespace and a query string that is not a connect knob,
but not `#`, `/` or `..` in a segment (`crates/podssh-ws/src/client.rs:68-89`).

Read: the commands already check the forward path. `podssh_relay::relay::forward_path` calls
`check_host`: letters, digits, `.`, `-` and `_`, no leading `-` or `.`, at most 253 characters
(`crates/podssh-relay/src/relay.rs` lines 158-174), with a test of bad hosts (lines 218-226).
Nothing checks a node name.

Read in a local copy of podbox at `5bd8cb0` (`docs/design.md:66` names `452d792`): `validate_name`
accepts 1 to 128 characters of `[A-Za-z0-9._-]` and refuses anything else, with no encoding
(`Azathothas/podbox:crates/podbox-ssh/src/mux.rs`). The contract does not give the form of a pair
name (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:130-134`). To measure: the name
that one `POST /v1/pair` returns (T-078).

## Approach

The lines below are those of `4b6e917`.

1. Add `check_node_name` beside `check_host` in `crates/podssh-relay/src/relay.rs` (lines
   158-174): 1 to 128 bytes of `[A-Za-z0-9._-]`, not `.` or `..`, no leading `-` or `.`. Refuse;
   never percent-encode, because an encoded `/` hides a different path.
2. Make `LegTarget::path` return a `Result` and call `check_host` and `check_node_name`
   (`crates/podssh-transport/src/endpoint.rs` lines 34-43). Reuse the one `check_host`; do not
   copy it.
3. Refuse port 0, as `forward_path` does (`relay.rs` lines 125-127).
4. Check the name that `/v1/pair` returns with the same function, before podssh stores or uses it
   (T-078). A bad name from the relay gives a clear error and no request.
5. Close this entry in place in the same commit.
6. Pitfall: T-007 changes `check_host` for bracketed IPv6 literals. Keep one function, and keep the
   cases of both entries in its tests.

## Decision

2026-10-09:

1. `check_host`, `check_target` and the new `check_node_name` live in `podssh-ws`
   (`crates/podssh-ws/src/names.rs`), and `podssh_relay::relay` re-exports them, so each caller
   keeps its name for them; `podssh-transport` reaches them through `adapt.rs`. Lost: the check
   in `podssh-relay` with `podssh-transport` depending on it, which is a cycle once the runners
   of T-079 and T-080 in `podssh-relay` use `podssh-transport` (the reason of T-075's Decision).
2. The forward leg calls `check_target`, which also takes a bare IPv6 literal, as `forward_path`
   does since T-007: one rule for the forward path in both crates. Lost: `check_host` alone,
   which refuses an IPv6 target that the commands accept.
3. A refusal is `TransportError::BadTarget(why)`, never retried.
4. Step 4 belongs to T-078, which pairs: its Approach (step 2) checks the name "with T-076", with
   `podssh_relay::relay::check_node_name`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-transport --test endpoints -- names_cannot_bend_the_path
cargo test -p podssh-relay --lib -- node_names
cargo test -p podssh-transport --no-fail-fast
```

The new tests try `a/b`, `a?b`, `a#b`, `..`, `.`, `-x`, `a b`, a CR LF header, an empty name and
129 characters on each leg, and assert an error before a URL exists. The controls `podssh`,
`a.b_c-1` and `github.com` pass. Plant: remove the call to `check_node_name`; the node and the
operator cases must fail.

## Done

2026-10-09, in the commit "A host or a pair name cannot change the relay path".

- `crates/podssh-ws/src/names.rs` (new): `check_host` and `check_target`, moved unchanged from
  `podssh-relay`, and `check_node_name` (1 to 128 bytes of `[A-Za-z0-9._-]`, no leading `-` or
  `.`). `podssh_relay::relay` re-exports the three.
- `LegTarget::path` returns a `Result`: the forward leg checks its host with `check_target` and
  refuses port 0; the node and the operator legs check the name with `check_node_name`. `endpoint`
  and `socket::build` return a `Result`, so a refused target gives no URL. Nothing is encoded.
- Prove: `cargo test -p podssh-transport --test endpoints -- names_cannot_bend_the_path`: 1 passed
  (`a/b`, `a?b`, `a#b`, `..`, `.`, `-x`, `a b`, a CR LF header, an empty name and an overlong one
  on each leg; port 0; the controls, an IPv6 target among them). `cargo test -p podssh-relay --lib
  -- node_names`: 1 passed. `cargo test -p podssh-relay --lib`: 14 passed (the cases of
  T-007 and of `forward_paths_cannot_be_bent_by_the_target` kept). `cargo test -p podssh-transport
  --no-fail-fast`: 83 passed, 0 failed. `cargo test --no-fail-fast`: 784 passed, 0
  failed, 7 ignored.
- Plants, each restored: both calls to `check_node_name` removed: the test failed with `a/b` as
  `/v1/node/a/b`; the operator's call alone removed: it failed with `/v1/connect/a/b`.

# T-077: T10: the `Transport` trait has no implementation, and `Backoff` is used only by tests

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row T10 (low).
Confirmed here on `3ee70dc` by reading the code.
**Category:** chore
**Milestone:** M4
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

Two public items of podssh-transport describe code that does not exist. The `Transport` trait has
no implementation, and `Backoff` has no caller outside its tests. `Backoff` has no jitter, while
the reverse rules and `podssh-relay` use a jittered backoff. A runner that used either one would
follow a design that nothing else follows.

## Premise

Read: `Transport` (`crates/podssh-transport/src/transport.rs:15-35`) has no implementation in the
workspace (a search for `impl ... Transport for` finds none). It is exported at
`crates/podssh-transport/src/lib.rs:59`. `target_for` has no caller either
(`crates/podssh-transport/src/transport.rs:214-222`).

Read: `Backoff` doubles from 1 s to 30 s with no jitter (`crates/podssh-transport/src/backoff.rs:1-8`,
`:15-17`, `:51-55`). It is exported at `crates/podssh-transport/src/lib.rs:51` and used only by
`crates/podssh-transport/tests/closes.rs:354-391`.

Read: a node connects again "with a jittered backoff" (`docs/reverse.md:22-24`,
`docs/ROADMAP.md:150-158`). `podssh_relay::open::backoff` doubles from 1 s to 30 s and multiplies
by a random factor from 0.5 to 1.5 (`crates/podssh-relay/src/open.rs:261-275`); `podssh ssh` uses
it (`crates/podssh-cli/src/ssh/mod.rs:125-131`).

## Approach

1. Delete the `Transport` trait and `target_for`. Keep `Control`, `LegShape` and `Limits`, which
   `socket.rs` uses; T-082 moves them with the codecs.
2. Delete `crates/podssh-transport/src/backoff.rs`, its export, and its two tests
   (`crates/podssh-transport/tests/closes.rs:354-391`).
3. The node runner of T-079 uses `podssh_relay::open::backoff`. If a reset after a good connection
   is necessary, add it there, not as a second schedule.
4. Close this entry in place in the same commit.
5. T-082 can do these steps in the move; then this entry closes with the commit of T-082.

## Decision

Recommendation: delete both. A trait with no implementation is a guess at an API; the runners of
T-079 and T-080 are concrete types, and podbox reaches them through the facade of T-081. The
alternative, implement `Transport` for `Leg`, lost: its byte-only `send` hides the session id and
the per-session state (T-073) that the node leg needs.

## Prove

```sh
export CARGO_BUILD_JOBS=4
git grep -n "trait Transport\|struct Backoff\|fn target_for" -- crates ; test $? -eq 1
cargo test -p podssh-transport --no-fail-fast
cargo test -p podssh-relay --no-fail-fast
```

`git grep` exits 1 when the three items are gone. The tests show that nothing else used them.
