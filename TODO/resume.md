The resumable layer of milestone M6, with which a session between two podssh
ends survives a drop: the handshake and the offsets, the replay buffer, the
resume, the heartbeats, the move before the relay's limits, the exit
measurement and the throughput method. Then the session features that build
on the layer, which wait in the backlog.

# T-151: The resumable layer: its handshake and the byte offsets

**Source:** ROADMAP M6 (the resumable stream layer); `docs/design.md:570-587`
(layer 2, decided); GitHub #19 (Nemo-010, 2026-10-08: the quic-ssh, ssh-obi
and fux reports) and GitHub #20 (a handshake with a version and a role).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

A dropped link to the relay ends the session with exit 255, and a new client
address loses it (`docs/design.md:544-556`). The relay keeps nothing across a
new connection (`docs/design.md:558-561`).

## Premise

Read: the design is decided: offsets and acknowledgements in each direction,
a session id and a 256-bit resume secret, under SSH (`docs/design.md:570-587`),
in a `session` module of `podssh-relay` (`docs/design.md:473-482`), a crate
with no C. Measured: `grep -ril resum crates` finds only the IRC client.
Today russh's bytes go through a pipe to the relay session
(`crates/podssh-ssh/src/relay_stream.rs:169-279`). Frame boundaries mean nothing
on the relay (`docs/relay.md:120-123`), and the relay reads each record and can
drop or add frames (`SECURITY.md:33-36`).

## Approach

1. A sans-IO codec (`docs/architecture.md:112-116`) in a new module
   crates/podssh-relay/src/session/, with each file under 500 lines. A record
   is a type byte, a 32-bit length and a body of 64 KiB or less: `GREETING`
   and `ACCEPT` (far end), `OPEN` and `PROOF` (client), `REFUSE`, `DATA` (its
   first offset, then the bytes), `ACK`, `PING`, `PONG`, `CLOSE` (a reason).
2. Offsets are 64-bit, start at 0 in each direction, and never reset. A `DATA`
   record below the expected offset loses its overlap; one above it is a gap:
   drop the link and resume (T-153). Never deliver bytes after a gap.
3. Each first record carries a fresh nonce, and no side waits for the other's.
   On the reverse road the client waits for `GREETING`, because a node with no
   layer sends `SSH-2.0-`; the client then runs with no layer (one `-v`
   note). On the iroh road the ALPN names the layer (T-162).
4. A new session: X25519 keys of both sides, and HKDF-SHA256 over the shared
   value and both nonces, give the secret; `ACCEPT` gives a 128-bit id. A
   resume: `OPEN` names the session, and `PROOF` and `ACCEPT` carry an
   HMAC-SHA256 over both nonces and the sender's received offset.
5. Use `x25519-dalek`, `hkdf`, `hmac`, `sha2` and `zeroize` (`Cargo.toml`), and
   `rand` (`crates/podssh-relay/Cargo.toml:18`). Return an error when the
   system gives no random bytes (T-064). Keep the secret and the proofs out of
   output, logs and argv.
6. `GREETING` names its features (`replay.v1`, `heartbeat.v1`, `move.v1`); a
   side ignores a name that it does not know (ssh-obi's model, read in
   GitHub #19, not verified here).
7. On the client, the layer goes between the pipe and the link, and keeps
   `RelayStatus` (`crates/podssh-ssh/src/relay_stream.rs:69-163`). Docs: the
   records and the threat model in `docs/design.md` section 5,
   `docs/architecture.md`, the map of `AGENTS.md`, and `docs/STATUS.md`.

## Decision

Recommendation: an X25519 exchange gives the secret, and HMAC over fresh
nonces of both ends proves it. No secret and no reusable proof cross the
relay, so a passive reader of its logs cannot take the session; an active
relay can still break it, as today. The alternative, a secret sent in
`ACCEPT`, lost: the relay terminates TLS, so its logs would hold the secret.

Taken (2026-10-09): in this entry only the client of `podssh ssh node://`
runs the layer, and no far end runs it outside the tests. The alternatives
that lost: the node speaks the layer now, which gives each session the
layer's cost and none of its gain until T-152 and T-153, and shows a
`GREETING` to an SSH client with no layer behind `podssh operator` (T-153
decides that with the resume); the client waits for the first byte on the
forward road too, where a standard sshd never greets, so each session would
pay the wait for nothing.

Taken: the client waits 30 s at most for the far end's first byte, more
than the operator leg's 20 s wait for `ready`, after which the node's first
byte comes. 10 s lost: a slow `ready` would make the client choose no layer
before a `GREETING` came. Taken: the `ACCEPT` of a new session carries no
proof, since only an active relay could change the exchange, and it could
make the proof too.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_codec --test session_handshake
sh scripts/dev.sh check
```

The codec test decodes golden vectors written by hand from the table, not
made by the encoder; a planted decoder that delivers bytes after a gap fails
it. The handshake test refuses a wrong secret, a replayed `PROOF` and an
unknown session. The gate builds `podssh-relay` with `CC=/nonexistent`.

## Correction

Step 7 cites the pipe of the forward road
(`crates/podssh-ssh/src/relay_stream.rs:69-163`), whose far end is the
relay itself: it never speaks the layer, so that pipe keeps no layer and its
`RelayStatus` is unchanged. The client's pipe to a node is in
`crates/podssh-cli/src/ssh/node.rs`, between SSH and the operator's leg,
which has no `RelayStatus`; the layer goes there. The far end in
`podssh node` comes with T-153, which keeps a node's sessions across links.
By the operator's decision of 2026-10-09 (`docs/decisions.md`), the gate run
and the planted decoder wait for the checks of the release (T-251).

## Done

2026-10-09.

- `crates/podssh-relay/src/session/`: the records and their decoder
  (`record.rs`, `decode.rs`), the offsets (`offset.rs`), the id, the
  nonces, the secret and the proofs (`secret.rs`), the handshakes and the
  sessions that a far end keeps (`handshake.rs`), a link past its handshake
  (`link.rs`), and the two ends over tokio streams (`client.rs`, `far.rs`,
  `pump.rs`); each file under 500 lines, with `sha2`, `hmac`, `hkdf` and
  `x25519-dalek` of the workspace. The table, the derivation and what the
  layer defends against are in `docs/design.md`, section 5.
- `podssh ssh node://` runs the client's end (`crates/podssh-cli/src/ssh/node.rs`):
  it sends nothing until the node's first byte, takes a `GREETING` as the
  layer, and else passes the bytes as they are; `-v` says which (the
  manual's note of `node://`, `docs/cli.md`).
- In passing: x25519-dalek's `zeroize` feature is on in the workspace.
  podssh-ws's TLS key exchange wiped a copy of its X25519 scalar, not the
  scalar inside `StaticSecret`; it now wipes itself, and a function that
  does not compile without the feature guards that. And CI's lint failed at
  `9841fa5` on the form of the manual's scp note, now two paragraphs.
- Prove, native: `cargo test -p podssh-relay --test session_codec --test
  session_handshake --test session_link`: 31 passed (15, 12 and 4). The
  codec decodes 14 vectors written by hand, whole and one byte at a time,
  and refuses 11 bodies that are not their record; a link delivers nothing
  after a gap. The handshake gives the secret `8a41f649…` and the proofs
  `44f2167e…` and `3faedde0…`, computed apart with an X25519 written from
  the pseudo-code of RFC 7748 (checked against its section 6.1), and HKDF
  (checked against RFC 5869, A.1) and HMAC of Python's standard library. It
  refuses a wrong secret, a replayed `PROOF`, an unknown and a removed
  session, a reflected proof and a key of low order. The two ends carried
  1 MiB each way with equal SHA-256.
- Live, once: `cargo test -p podssh-cli --test node_live -- --ignored
  ssh_to_a_node` passed (`exit 3` through a node in front of railway.new,
  with `-v` showing "the far end offers no resumable layer"). Its first run
  failed: railway.new answered with 262 bytes on stdout and another exit
  status, after a login that worked (stderr held only the warning of the
  recorded host key); the next two runs gave 3.
- `cargo test --no-fail-fast`: 963 passed, 0 failed, 20 ignored (the live
  tests). `python scripts/check-repo.py`: ok.
  `cargo todo check`: the record agrees.
- Waits for T-251, by the decision of 2026-10-09: the gate
  (`sh scripts/dev.sh check`, with `CC=/nonexistent` and Rust 1.85), and the
  planted decoder: `Inbound::accept` that returns the bytes of a record past
  a gap must fail `a_gap_delivers_nothing_and_the_offset_stays`,
  `a_link_delivers_nothing_after_a_gap` and
  `a_gap_ends_the_link_and_nothing_after_it_is_delivered`.

# T-152: The replay buffer, limited, with backpressure

**Source:** ROADMAP M6 (a limited replay buffer with backpressure);
`docs/design.md:572-574`; GitHub #19 (Nemo-010, 2026-10-08: quic-ssh's bounded
buffer with a start offset; ssh-obi's duplicate recent bytes); GitHub #31.
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A resume can send again only the bytes that the sender still holds. A buffer
with no limit fills the memory of a small host when the peer is slow.

## Premise

Read: the sender keeps each byte that is not acknowledged, in 4 to 16 MiB,
"with backpressure when it is full" (`docs/design.md:573-574`). So no byte
that is not acknowledged is dropped, and a resume is byte-exact; the start in
an escape sequence of GitHub #31 needs dropped bytes (T-221). The reverse road
drops a frame and closes with `1011 relay backpressure` above 1 MiB queued
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`); the buffer
turns that close into a resume. The SSH window is 512 KiB for each channel
(`crates/podssh-ssh/src/run.rs:26-30`). Do not bring back the backpressure module of
`podssh-transport`, which T-074 removed (`docs/design.md:489-490`).

## Approach

1. In the session module of T-151, keep for each direction the bytes from the
   acknowledged offset to the sent offset, allocated as they arrive.
2. The capacity is 4 MiB, up to 16 MiB by a setting. Invariant: a session
   holds at most the capacity plus one record in each direction.
3. When the buffer is full, the writer returns `Poll::Pending` until an `ACK`
   frees space; russh then waits, and the far end's SSH window stops the
   server. Never drop a byte; never grow past the capacity.
4. The receiver sends `ACK` after each 64 KiB, after 200 ms with bytes not
   acknowledged, and in each `PONG` (T-154).
5. A resume sends again from the peer's received offset. An offset that the
   buffer does not keep gets `REFUSE` with both offsets, and the session ends
   with that reason: never a silent gap.
6. Pitfall: the SSH window limits one channel, so several channels can put
   more than 1 MiB in flight. T-157 tells whether a send window under 1 MiB
   for each link is worth its cost in throughput.
7. With `-v`, print the bytes that each resume sent again. Write the defaults
   in `docs/design.md` section 5, and the bound in T-201.

## Decision

Byte replay or screen state: byte replay is decided (`docs/design.md:570-571`,
the model of Eternal Terminal), and the layer sees only SSH ciphertext. Screen
state matters only when a new client attaches to a kept shell (T-161).

Recommendation: 4 MiB by default. The relay holds at most 1 MiB for a slow
receiver and the SSH window is 512 KiB, so 4 MiB keeps the bytes of a lost
link. A node with 16 sessions (crates/podssh-transport/src/control.rs lines 111-120 at `e8bbd4d`)
then holds 64 MiB at most. The alternative, 16 MiB, lost: four times the
memory in a cage, for no measured gain.

Taken (2026-10-09): the buffer and the `ACK`s run only when both sides
named `replay.v1` in their first records. A peer that never acknowledges
would fill the buffer, and the writer would then wait for ever: the
alternative, a buffer on each session, lost for that reason. Taken: the
writer reads from the application only what the buffer has room for, so the
buffer never holds more than its capacity (the bound of step 2 with no extra
record); a `DATA` record over the room is refused whole, never cut.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_replay
```

The test (crates/podssh-relay/tests/session_replay.rs) writes 32 MiB with no
`ACK`: the writer waits at 4 MiB, and an `ACK` frees space. A resume sends
exactly the missing bytes, also after a lost frame (an equal SHA-256). It
checks the invariant of GitHub #31: no byte that is not acknowledged is
dropped, and a resume at an offset that is not kept gets `REFUSE` with a
named reason, never a silent gap. A planted buffer with no capacity check
fails it, and so does one that drops its oldest bytes when it is full.

## Correction

The bound of the Decision counts 16 sessions on a node, but the node takes
the relay's limit from its `hello`: 64 sessions, measured 2026-10-09
(`docs/reverse.md:30-33`). With each session's 4 MiB kept, a node can hold
256 MiB; T-153, which makes the node a far end that keeps sessions, bounds
the whole node (its step 6). Step 7's `-v` line belongs to the resume loop
of T-153: no resume runs before it, and `Link::resume` gives the count of
the bytes sent again. By the operator's decision of 2026-10-09, the planted
buffers wait for the checks of the release (T-251).

## Done

2026-10-09.

- `crates/podssh-relay/src/session/replay.rs`: the bytes from the
  acknowledged offset to the sent offset, taken as they come and given back
  when the buffer empties; 4 MiB by default, up to 16 MiB with
  `PODSSH_REPLAY_BUFFER` (the manual's ENVIRONMENT); bytes past the room
  refused whole; a resume from an offset that it does not keep is `NotKept`,
  whose `REFUSE` (code 3) names the offset asked and the offsets kept.
- `link.rs`: the session's state now outlives a link (offsets, buffer, the
  last `ACK`), and `Link::resume` starts the next link with the bytes to send
  again; an `ACK` or a `PONG` frees the buffer. `pump.rs`: the writer reads
  only what the buffer has room for and waits for an `ACK` when it has none;
  the receiver acknowledges each 64 KiB at once and fewer bytes after 200 ms.
  The two ends turn the buffer on only when both named `replay.v1`
  (`Settings`, `session::FEATURES`); `podssh ssh node://` passes the
  setting. The defaults are in `docs/design.md` (section 5), the bound in
  T-201.
- Prove, native: `cargo test -p podssh-relay --test session_replay`:
  9 passed, three runs in a row with the link test. 32 MiB to a far end that
  does not acknowledge: exactly 4 MiB go out and nothing more for 500 ms; an
  `ACK` of 1 MiB lets exactly 1 MiB more through; then the whole 32 MiB with
  an equal SHA-256. A frame lost after 640 KiB of 2 MiB: the link ends with
  the bytes before the gap, the resume sends exactly the other 1,441,792,
  and the digests are equal. A model of 3 MiB of random sends and
  acknowledgements, old ones among them: the buffer holds exactly the bytes
  not acknowledged after each step. Resumes from below the acknowledged
  offset and past the bytes sent are refused with both offsets. A peer with
  no `replay.v1` gets 6 MiB with no buffer and no `ACK`.
- `cargo test --no-fail-fast`: 972 passed, 0 failed, 20 ignored (the live
  tests). `python scripts/check-repo.py`: ok.
  `cargo todo check`: the record agrees.
- Waits for T-251, by the decision of 2026-10-09: the two planted buffers
  (`Replay::keep` with no check of the room, which must fail
  `the_buffer_never_grows_past_its_capacity` and
  `a_full_buffer_makes_the_writer_wait_until_an_ack`; and one that drops its
  oldest bytes when full, which must fail
  `the_buffer_never_drops_a_byte_that_is_not_acknowledged` and
  `a_resume_sends_exactly_the_missing_bytes_after_a_lost_frame`).

# T-153: Resume through any road and relay host, with a session secret and a capped backoff

**Source:** ROADMAP M6 (reconnection through each relay host);
`docs/design.md:576-578`; GitHub #19 (Nemo-010, 2026-10-08: ssh-obi's policy,
talaria0101's drops); GitHub #17 and #25 (a retry by the close reason).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

After a loss, the client must find its session again through any road and
relay host. A retry that ignores the close reason is wrong: one of 180
sessions dropped with `1011`, and some drops repeat on one target, as
GitHub #19 reports. Some closes mean "do not come back".

## Premise

Read: the failover across relay hosts serves the first connection only
(`crates/podssh-relay/src/open.rs:188-247`). `classify` maps each reverse close
to a retry class (crates/podssh-transport/src/closes.rs lines 154-229 at `e8bbd4d`), with
`relay backpressure` as `Retry::Never`
(crates/podssh-transport/src/closes.rs line 202 at `e8bbd4d`); a received Close lost its code
until T-072 (repaired 2026-10-09). Read, not measured: `/v1/node` and `/v1/connect` are on the
control host only (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:23-24`).
A second node socket for one name gets `409`
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:152-153`), and
the node then exits (docs/reverse.md, line 19 at `fb228e9`).

## Approach

1. The client drives the resume. On a loss with no `CLOSE` record, it tries
   the roads of T-164 and each host of the `RelayList`
   (`crates/podssh-relay/src/relay.rs:64-78`), each within `HOST_DEADLINE`
   (`crates/podssh-relay/src/open.rs:32-34`), with `open::backoff` between
   rounds (`crates/podssh-relay/src/open.rs:349-363`). Do not fork it (T-077).
2. A `CLOSE` record never reconnects; each other loss reconnects first
   (ssh-obi's rule, read in GitHub #19, not verified here). Print one stderr
   line for each loss and each resume, and never a secret or a token.
3. Resume after `1011 socket error`, `node disconnected`, `node offline`,
   `relay backpressure`, `1013 node open timeout`, `1009 session byte cap`,
   and a loss with no Close. Stop with the reason on both `1001` rows and on
   the rows of a fault in podssh's own bytes (`1003`, `1008 wait for ready`).
4. The far end keeps a session with no link until the resume deadline, then
   closes the target connection. The client gives up at the same monotonic
   deadline, and exits 255 with the reason and the hop (T-024).
5. Measure first, with a live pair, whether a pool host serves
   `/v1/connect/<name>`. If none does, "each relay host" means each address of
   the control host (pins, resolver, DNS over HTTPS). Write it in
   `docs/relay.md`, with `docs/reverse.md` and the manual's relay section
   (`crates/podssh-cli/src/man/facts.rs:297-459`).
6. A node keeps the replay buffer of each session (T-152): with the relay's
   limit of 64 sessions and 4 MiB each, 256 MiB. Bound the node's whole
   replay memory (a session past the bound gets `REFUSE` busy, code 6), and
   write the bound in T-201.

## Decision

Recommendation: a resume deadline of 10 minutes at both ends: the M6 exit
asks for a stall of 3 minutes, and the backoff adds up to 45 s. The
alternative, no deadline, lost: a node in a cage would keep connections for
clients that never come back.

Recommendation: after a loss, a node retries `409` with the backoff until the
deadline, because the relay can still hold its old socket; a first
registration still exits on `409` (`docs/reverse.md:24`). The alternative, an
exit on each `409`, lost: a new node address would end each session. The
operator confirms this change of `docs/reverse.md`: T-261, to which the
operator agreed on 2026-10-09 (Q31).

Taken (2026-10-09): each session of `podssh node` runs the layer, and the
node has no flag for an operator with no layer. podssh replaces the other
operators of the reverse road, and both of its own (`podssh ssh node://`,
`podssh operator`) speak the layer; a flag would carry no resume, and it
can come when an operator needs it. Taken: the node keeps 64 MiB of replay
buffers at most, a whole buffer for each session that it keeps (16 at the
default of 4 MiB), so the bound of step 6 holds whatever the sessions do; a
new session past it ends at once with the reason. Taken: the line of each
resume gives the bytes sent again, so `-v` is not needed for them (T-152,
step 7).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_resume --test session_policy
```

The resume test cuts a scripted link at random points while 32 MiB go each
way, resumes through a second fake relay host, and compares SHA-256 digests;
after the deadline, `REFUSE` comes and the client exits 255. The policy test
maps each close row to resume or stop; a planted policy that resumes on
`1001 pair expired` fails it.

## Correction

The policy test needs the close table, which is in the feature `pair`: its
command is `cargo test -p podssh-relay --features pair --test
session_resume --test session_policy`. The Premise's `classify` gives
`relay backpressure` no retry, which stays true of a session with no layer;
with the layer, a dropped frame is a gap that a resume repairs, so the
layer's own policy (`podssh_relay::reverse::closes::resumes`) resumes it.
Step 5, measured 2026-10-09: two pool hosts answered an operator's
`/v1/connect/<name>` with `HTTP 503: reverse: unavailable`, and the control
host carried the session; a resume goes through the control host alone, by
each of its addresses (`docs/relay.md`). The `409` of the Decision is T-261.
By the operator's decision of 2026-10-09, the gate run and the planted
policy wait for the checks of the release (T-251).

## Done

2026-10-09.

- The client's session across links (`crates/podssh-relay/src/session/resume.rs`):
  after a loss, it asks its caller for a new link, proves the secret on it,
  and each side sends again from the other's offset; a `CLOSE`, a `REFUSE`,
  or a close that says not to come back ends it, and else it tries with the
  backoff of the forward opener until 10 minutes after the loss
  (`End::GaveUp` with the reason). The far end's sessions across links
  (`keep.rs`): a session's target and state wait after a loss until the
  deadline; a resume stops the old link when it still runs; the received
  offset of a resume's `ACCEPT` is read from the session's state at that
  moment (`sessions.rs`). One link (`pump.rs`) borrows the application and
  never shuts it on a loss, and the bytes received but not yet written stay
  with the session, so a link that ends in a write loses none.
- `crates/podssh-relay/src/reverse/layered.rs`: the node's far end, a handler
  over the TCP handler: `ready` at once, the handshake, then TARGET for a new
  session only, and the node's budget of 64 MiB. `reverse::closes::resumes`:
  the policy of step 3 over the table's rows.
- `crates/podssh-cli/src/layered.rs`: the client over the operator's legs,
  for `podssh ssh node://` and `podssh operator`; one line for each loss and
  each resume. `podssh node` runs the far end. The manual's notes of `ssh`,
  `node` and `operator`, `docs/cli.md`, `docs/reverse.md`, `docs/relay.md`
  and `docs/design.md` (section 5) say so.
- Prove, native: `cargo test -p podssh-relay --features pair --test
  session_resume --test session_policy`: 6 passed. Four cuts at random points
  in the middle of records, while 32 MiB go each way: four losses, four
  resumes through two stand-in hosts, and equal SHA-256 digests at both ends.
  A loss with no new link until the far end's deadline passed: the resume
  gets `REFUSE` (an unknown session), and the session ends with that reason;
  with no new link at all, the client stops at its own deadline. Each row of
  the close table resumes or stops as step 3 says. `--test reverse_layered`:
  3 passed: a session cut twice comes back whole with one connection to
  TARGET; an unreachable TARGET and a node past its budget end the session
  with the reason.
- Live, once (`cargo test -p podssh-cli --test node_live -- --ignored`):
  GitHub's banner came through a node with the layer, and `podssh operator`
  carried it with exit 0; `podssh ssh node://` logged in to railway.new
  through the layer (`-v`: "the far end (a podssh node) opened resumable
  session ef6f903b", features `replay.v1`), and railway.new then limited the
  anonymous visitor with its exit 13 in place of `exit 3`; the test now names
  that cause.
- `cargo test --no-fail-fast`: 981 passed, 0 failed, 20 ignored (the live
  tests). `python scripts/check-repo.py`: ok.
  `cargo todo check`: the record agrees.
- Waits for T-251, by the decision of 2026-10-09: the gate, and the planted
  policy that resumes on `1001 pair expired`, which must fail
  `an_expired_pair_and_a_stop_are_never_resumed` and
  `each_row_of_the_table_resumes_or_stops`.

# T-261: A node that lost its socket connects again on `409`, until the resume deadline

**Source:** T-153 (its Decision: "The operator confirms this change of
`docs/reverse.md`"); T-255 (the relay's side drops reverse sockets at
random, with no Close).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay's side drops a node's socket at random (T-255). A node that
connects again can get `409` while the relay still holds the old socket, and
the node then exits: each session that the resumable layer keeps on it ends,
and no client can resume it (T-153).

## Premise

Read, at `fb228e9`: rule 6 of docs/reverse.md (line 19) says "On `409` (a
second socket for the same name), exit. Do not retry." podssh's node does so
(crates/podssh-relay/src/reverse/node.rs, line 148), for a first registration
and after a loss alike. T-153's Decision recommends a retry after a loss and
leaves that change of `docs/reverse.md` to the operator.

## Approach

1. A node that held its socket and lost it takes `409` as a wait: it connects
   again with `open::backoff` until the resume deadline of T-153, then exits
   as now. A first registration still exits on `409`: another node has the
   name.
2. One stderr line for each `409` after a loss, with the time left.
3. Rule 6 of `docs/reverse.md` gives both cases, and the manual's section of
   `node` says so.

## Decision

Recommendation (T-153's): connect again after a loss. The alternative, an
exit on each `409`, lost: a node whose socket the relay dropped would end
each session that the layer keeps. The operator agreed on 2026-10-09 (Q31,
`docs/decisions.md`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_node -- conflict
```

A stand-in relay answers a node's next connection after a loss with `409`
twice, then accepts it: the node keeps its sessions. A first connection that
gets `409` exits as before. A planted node that exits on each `409` fails the
test.

## Correction

A test of a node that connects needs a stand-in relay over plain `ws://`:
the one of the blocking facade (`crates/podssh-relay/tests/stand_in/mod.rs`)
and the feature `plain-ws`. The tests are in
`crates/podssh-relay/tests/blocking_plain.rs`, which the gate's step `libs`
runs: `cargo test -p podssh-relay --features blocking,plain-ws --test
blocking_plain -- conflict`. The node keeps no session across its sockets
itself: the keeper of the resumable layer does, while the node runs, so the
test shows that the node runs on and serves on the new socket.

## Done

2026-10-09.

- `crates/podssh-relay/src/reverse/node.rs`: a node notes when it lost a
  socket that it held. A `409` within `Settings::rejoin` of that loss is a
  wait, with the jittered backoff, and a line for the user
  (`NodeConfig::say`) with the time left; a `409` at the first registration,
  or after the limit, ends the node as before (`Exit::NameInUse`).
  `Settings::rejoin` is the layer's resume deadline, 10 minutes.
- `podssh node` prints each such line on stderr, and its last line for
  `Exit::NameInUse` names both causes. Rule 6 of `docs/reverse.md` and the
  manual's note of `node` give both cases.
- Prove, native: `cargo test -p podssh-relay --features blocking,plain-ws
  --test blocking_plain -- conflict`: 3 passed. After a loss with no Close,
  two `409`s, then the node takes the new socket and serves a session on it;
  a `409` at the first registration ends the node at once; with a limit of
  2 s, `409`s after a loss end it, but only after the 2 s. Planted, a node
  that exits on each `409`: both tests after a loss failed, and the one of
  the first registration passed.
- `cargo test --no-fail-fast`: 994 passed, 0 failed, 22 ignored; with `-p podssh-relay --all-features`: 173 passed, 0 failed, 14 ignored.

# T-262: A session cut at random points can end before its bytes come through

**Source:** CI's gate at `7797b2a` (run 37945660729, step `libs`), and local
runs on 2026-10-09.
**Category:** defect
**Milestone:** M6
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

The test of T-153 that cuts a session's links at random points while 32 MiB
go each way, `a_session_survives_links_cut_at_random_points`, sometimes ends
the session before the bytes come through: the application's read fails.
The gate is red until it is repaired, and a user could lose a session that
the layer should carry over.

## Premise

Measured: the test failed in CI's gate at `7797b2a` (step `libs`, the
read at `crates/podssh-relay/tests/session_resume.rs:117` failed), and
locally in 2 of 3 runs on 2026-10-09; it passed in each run before that
day's last changes. The cause is not known: the resume driver
(`crates/podssh-relay/src/session/resume.rs`), the far end's keeper
(`crates/podssh-relay/src/session/keep.rs`), the pump
(`crates/podssh-relay/src/session/pump.rs`), or the test's stand-in relay.

## Approach

1. Run the test until it fails, with the driver's notes printed, and find
   which end gives up and why: a `GaveUp` reason, a `REFUSE`, a link that
   ends the session.
2. Repair the cause, with a test that fails on it alone.
3. The test passes 20 runs in a row, and the gate's step `libs` is green.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test session_resume
```

20 runs in a row pass, and so does CI's gate.

## Done

2026-10-09, with T-154's work and T-155's so far, which the session before
left in the same files. Here, before the repair, the test failed in 6 of 10
runs. A copy of it that printed each end's notes and each link's end found
four causes:

1. A failed write ended a link before its reader read what had come. The far
   end sent its last bytes and its `CLOSE`, and the stand-in relay then
   closed the link; the client's next `ACK` failed with a broken pipe, and the
   client took the link as lost with the `CLOSE` unread. Its resume found the
   session forgotten, and the application's read ended early: the failure of
   CI at `7797b2a`.
2. A stall: each end's reader waited for the link's write lock to send an
   `ACK` while its own writer held the lock, stalled on a full link. With
   both ends sending, no link moved again (a run that waited 120 s).
3. In the move of T-155, the new link's handshake took the offsets while the
   old link still carried acknowledgements: an offset fell below the other
   side's acknowledged one, and the far end refused it as not kept.
4. On the way: the bytes of a resume were written before the new link was
   read, at both ends; the far end left a session with no slot between
   taking it and starting the new link, so a resume that came then failed;
   an older resume could take a session back from a newer one; and a `CLOSE`
   that a lost link took with it was never sent again.

The repair, in `crates/podssh-relay/src/session/`:

- `pump.rs`, with `pump/outbox.rs` and `pump/down.rs`: one writer for each
  link. The reader and the heartbeat leave an `ACK`, a `PONG` or a `PING` in
  an outbox and never wait for the writer; the bytes of a resume go out
  through the writer while the link is read; a link whose writes fail is
  read for 5 s more.
- The end of a session: the peer answers a `CLOSE` with its own. A link that
  ends before the answer ends as `End::Closing`, and the resume sends the
  `CLOSE` again; a far end that forgot the session after this side's
  application ended had the `CLOSE` (`End::LocalEnd`); a resume that the far
  end accepted while the session ended on the old link gets a `CLOSE`.
- `resume.rs`: the move greets a new link while the old one runs, stops the
  old one with `RETIRE`, and only then takes the offsets; no move once this
  side's application ended.
- `keep.rs`: the new link takes the slot in the same lock that empties it,
  and the newest resume takes the session; an older one gives way.
- `docs/design.md` (section 5): a `CLOSE` answered, one writer for each
  link, the end of a session and the order of a move.

Prove, native, Windows, 2026-10-09:

- `cargo test -p podssh-relay --features pair --test session_resume`: the
  test binary, 20 runs in a row, each with its 3 tests passed.
- A test of each cause, which fails on the code before the repair and passes
  after it, 10 runs in a row (20 for the moves): `--test session_end`: a link
  whose writes fail still gives each of 1 MiB and the far end's `CLOSE`
  (before: 98,304 bytes); a `CLOSE` that its link lost goes again on the
  next link, from either side (before: the target waited past the test's
  20 s, and the client ended with a refusal). `--test session_link --
  both_ends_send_at_once_through_a_small_link`: 4 MiB each way through a link
  of 4 KiB (before: nothing moved for 20 s). `--test session_move --
  a_session_moves_while_both_ends_send_at_full_speed`: a move each 256 KiB
  with both ends at full speed, no loss and no failed move (before: the
  session ended with a refusal).
- `cargo test --no-fail-fast`: 991 passed, 0 failed, 21 ignored (the live tests). `cargo test -p podssh-relay
  --all-features --no-fail-fast`: 170 passed, 0 failed, 14 ignored. `cargo clippy -p podssh-relay
  -p podssh-cli --all-targets -- -D warnings`: no warning.
- Live, once: `cargo test -p podssh-cli --test node_live -- --ignored
  node_command_serves_a_tcp_target ssh_to_a_node`: GitHub's banner came
  through a node with the new pump, and `podssh ssh node://` logged in to
  railway.new through it; railway.new then limited the anonymous visitor
  (its exit 13) in place of running `exit 3`, as in the run of T-153.
- CI's gate passed at `a3b81d1`, the commit of this repair: each of its
  steps, `libs` included (run 37963246424).

# T-270: A resume whose far-end task starts late takes the session from a newer one

**Source:** the native run of `cargo test --workspace` on 2026-10-10,
during T-178: the test of moves at full speed lost a link once.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A session that moves twice in a row can lose its newest link: the client
sees the link end with no word from the far end, and resumes on another.
No byte is lost, but the test of T-155 at full speed fails, and a user
would see a loss that should not happen.

## Premise

- Measured: `a_session_moves_while_both_ends_send_at_full_speed`
  (`crates/podssh-relay/tests/session_move.rs:185-195`) failed once in the
  native run of the workspace on 2026-10-10, with `[Lost { why: "the link
  ended with no word from the far end" }]`. It then passed 30 runs alone,
  60 with four copies at once, 40 with the other test of its file, and 75
  with three copies at once.
- Read: the far end numbered each resume when its task reached
  `run_resumed`, after `far::accept` had sent the `ACCEPT`, and the newest
  number won (`Keeper::run_resumed`, `crates/podssh-relay/src/session/keep.rs`).
  At full speed the client moves again as soon as the new link carries
  256 KiB, so the far end can answer the handshake of a third link before
  the task of the second reaches `run_resumed`. That task then took a
  greater number, the third link's `take` gave way to it, and the far end
  dropped the third link after its handshake.

## Approach

1. Number a resume in `far::accept`'s handshake, under the sessions' lock,
   before the `ACCEPT` goes out (`Sessions::next_resume`), and carry the
   number in `Accepted`.
2. `run_resumed` takes that number, and only raises the newest: an older
   resume whose task starts late gives way.
3. A test that orders the tasks so: two resumes answered A then B, B's task
   first, then A's.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_newest
cargo test -p podssh-relay --all-features
```

A gives way at once with "a newer link resumed the session", and B still
carries the session. Plant: number by the order of the tasks again; the
test must fail.

## Done

2026-10-10. `Sessions::next_resume` numbers each resume in `far::accept`
before its `ACCEPT` goes out (`crates/podssh-relay/src/session/sessions.rs`,
`crates/podssh-relay/src/session/far.rs`); `Accepted` carries the number,
and `Keeper::run_resumed` only raises the newest
(`crates/podssh-relay/src/session/keep.rs`).
- `cargo test -p podssh-relay --test session_newest`: 1 passed. Planted,
  the number by the order of the tasks: the older resume took the session
  from the newer, and the test failed at its limit of 5 s.
- `cargo test -p podssh-relay --all-features`: 181 passed, 0 failed, 14
  ignored; clippy with no warning, also for `podssh-iroh`. The tests of
  moves (`--test session_move`) passed 40 runs in a row after the change.

# T-263: A node in plain mode, for a client with no resumable layer

**Source:** the operator's ruling of 2026-10-09 (Q34, `docs/decisions.md`),
after T-153.
**Category:** feature
**Milestone:** M6
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Since T-153, each session of `podssh node` greets with the resumable layer.
A client that does not speak the layer (a tool of another project, or a TCP
client through the operator's leg) reads the `GREETING` as the first bytes of
TARGET, and cannot use the node.

## Premise

Read: `podssh node` puts its TCP handler under the layer's far end
(`crates/podssh-cli/src/node.rs`, the handler `Layered`), which sends
`GREETING` before anything else (`crates/podssh-relay/src/reverse/layered.rs`).

## Approach

1. `podssh node NAME TARGET --plain`: each session dials TARGET at `open`
   and carries its bytes as they are, as before T-153, with no resume. The
   layer stays the default.
2. A row in the flag table of `node` (`crates/podssh-cli/src/flags.rs`), the
   help, the manual's note of `node`, `docs/reverse.md` and `docs/cli.md`.
3. The node's first line on stderr names the mode.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli -- plain
```

The argument test parses `--plain` for `node` and refuses it elsewhere. A
test of the handler shows that a plain node gives TARGET's first bytes with
no `GREETING`, and that the default node greets.

## Done

2026-10-10. `podssh node NAME TARGET --plain` carries each session's bytes
as they are, with no resumable layer: the node's handler is then the TCP
handler alone, which dials TARGET at `open`
(`crates/podssh-cli/src/node.rs`, lines 152-163 at `8e31960`). The node's first line names its
mode (`crates/podssh-cli/src/node.rs:302`). `--plain` with `--iroh` is
refused with 64 (`crates/podssh-cli/src/node.rs:62-65`): the iroh road
always runs the layer. The flag's row, the manual's note of `node`,
`docs/reverse.md` and `docs/cli.md`.
- Native: `cargo test -p podssh-cli -- plain`, 3 passed. The argument test:
  `--plain` with `--iroh` exits 64, `--plain` for `operator` and `ssh`
  exits 64, and a node with `--plain` gets to its pair (78, as none is
  stored). Through the stand-in relay's reverse road
  (`crates/podssh-cli/tests/node_plain.rs`), `podssh ssh -v node://` finds
  no layer at a plain node, the layer's features at the default node, and
  logs in and runs `greet` through each. Planted, a `--plain` that changes
  nothing fails the plain check, and the default check still passes.
- CI, the run of `c982d27` (38002695390): each job passed.

# T-154: Heartbeats that also prevent the relay's idle cut

**Source:** ROADMAP M6 (heartbeats); `docs/design.md:579-580`; GitHub #19
(Nemo-010, 2026-10-08: ssh-obi pings each 15 s and wants a pong in 45 s).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay cuts a connection after 180 s with no payload, and its empty
keepalive frames do not count (`docs/relay.md:127-128`, `docs/relay.md:185`). A
reverse socket gets no keepalive at all (`docs/reverse.md:34-42`). SSH's own
keepalives must not end a session that the layer would resume.

## Premise

Read: a read waits 90 s at most (`crates/podssh-ws/src/client.rs:23-25`, set at
`crates/podssh-relay/src/open.rs:315`), a limit that counts on the relay's
frame each 25 s. The ping watcher acts only after a first Pong
(`crates/podssh-ws/src/session.rs:203-240`); Pongs and the idle cut on reverse
sockets are not measured (T-061). russh sends a keepalive each 60 s and ends
the session after 3 with no answer (`crates/podssh-ssh/src/options.rs:354-394`).
Measured on `3ee70dc`, offline (`PODSSH_OFFLINE=1`, a `.invalid` host):
`-o ServerAliveInterval=0` prints the warning of
`crates/podssh-cli/src/ssh/resolve.rs:372-386` (the `warnings` of keepalives), and `podssh ssh` exits 255.

## Approach

1. Each end sends a `PING` record when it sent nothing for 10 s, and the peer
   answers `PONG`. A record is payload, so it resets the relay's idle cut on
   each road.
2. Any record counts as life, as for the ping watcher
   (`crates/podssh-ws/src/session.rs:203-212`). After 3 silent intervals the
   link is dead, and T-153 resumes: 30 to 40 s. Both ends send, so the read
   limit of 90 s also holds on reverse sockets.
3. Carry the `ACK` of T-152 in each `PONG`. The cost is about 20 bytes each
   way each 10 s: under 0.2 MiB in 12 h.
4. On the resumable road, do not print the warning of
   `crates/podssh-cli/src/ssh/resolve.rs:372-386` (the `warnings` of keepalives).
5. In the same commit: "Liveness" and "Idle limit" in the manual
   (`crates/podssh-cli/src/man/facts.rs:383-398`,
   `crates/podssh-cli/src/man/facts.rs:425-434`), the note at
   `crates/podssh-cli/src/man/notes_ssh.rs:263`, `docs/relay.md`, `README.md`.

## Decision

Recommendation: on the resumable road, turn russh's keepalives off unless the
user sets `ServerAliveInterval`. The heartbeat finds a dead link in 30 to
40 s, and the resume hides the outage from SSH; with 60 s and 3 missed
answers, russh would end a session in a stall of about 3 minutes (inferred),
the stall that M6 must survive. A keyword that the user sets stays, with one
warning. The alternative, the keepalives as now, lost for that reason.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_heartbeat
cargo test -p podssh-cli --test ssh_args -- resumable
cargo test -p podssh-relay --test live -- --ignored idle_reverse
```

On tokio's paused clock, each end sends a record each 10 s over 200 s of idle
time, and a link silent for 30 s is dead; a planted interval of 200 s fails.
The argument test shows no SSH keepalive and no warning on the resumable road
only. The live test keeps an idle reverse session for 10 minutes, and so
answers T-061.

## Correction

The resumable road is `node://` (T-153): only a podssh node runs the layer,
so the keepalives and the warnings follow the destination. A `ServerAliveInterval`
that the user sets there stays, with one warning that it can end a session
that the layer would carry over; `0` there is no warning, as the layer keeps
the idle cut away. The live test needs a node and the layer's client, which
are in podssh-cli: it is `cargo test -p podssh-cli --test node_live --
--ignored an_idle_session_through_a_node_lives_10_minutes`, with an echo
server on the loopback as the node's TARGET, since an SSH server ends a login
that waits 10 minutes. The paused clock needs tokio's `test-util` in the
dev-dependencies of `podssh-relay`.

## Done

2026-10-09, with T-262's repair and T-155's work so far, which the session
before left in the same files.

- `crates/podssh-relay/src/session/pump.rs`: with `heartbeat.v1` named by
  both sides (`session::FEATURES` now names it), each end sends `PING` when it
  sent nothing for 10 s, the far end answers `PONG` with its received offset,
  and a link with nothing from the far end for 30 s ends as a loss, which
  T-153 resumes. The writer notes when it last sent, and the reader when it
  last heard; since T-262, the heartbeat leaves its `PING` for the link's one
  writer, and never waits for it.
- `crates/podssh-cli/src/ssh/resolve.rs`: to `node://`, no SSH keepalive
  unless `ServerAliveInterval` is set, and then one warning; no warning of
  the idle cut there. The manual's "Liveness" and "Idle limit", the note of
  `ssh`, `docs/relay.md`, `docs/design.md` (section 5) and `README.md` say so.
- Prove, native: `cargo test -p podssh-relay --test session_heartbeat`: 3
  passed, on the paused clock, also in 10 runs in a row after the repair of
  T-262. Over 200 s of idle time, no gap of more than
  10 s between records either way, with 18 `PING`s and 18 `PONG`s at least;
  a far end that answers nothing: the link ends after 30 s with "nothing came
  from the far end for 30 s"; a far end that did not name `heartbeat.v1`
  gets no `PING` in 200 s. `cargo test -p podssh-cli --test ssh_args --
  resumable`: passed.
- Live, once, before the repair of T-262: `cargo test -p podssh-cli --test
  node_live -- --ignored an_idle_session_through_a_node_lives_10_minutes`
  passed in 608 s: a session through a node in front of an echo server on
  the loopback, idle for 600 s on the live relay, echoed after the wait; no
  link was lost in that run.
- `cargo test --no-fail-fast`: 991 passed, 0 failed, 21 ignored (the live tests), with T-262.
- Waits for T-251, by the decisions of 2026-10-09: the planted interval of
  200 s, which must fail `an_idle_session_carries_a_record_each_way_each_10_s`,
  and a run of the live test after T-262 (it takes more than 5 minutes).

# T-155: Move a session to a new relay connection before the relay's limits

**Source:** ROADMAP M6 (a new session before the relay's limits);
`docs/design.md:581-582`; the report of sandbox A, 2026-10-08 (the `1009`
close at the volume cap).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay ends a WebSocket session after 64 MiB, both directions together, or
after 12 h (`docs/relay.md:186-187`). A long or large session on the layer
meets these limits, and an end at a limit costs a resume and its delay.

## Premise

Read: the reverse road has the same cap, `1009 session byte cap`, "Open a new
session" (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:183`),
which `classify` maps to `Retry::NewSession`
(crates/podssh-transport/src/closes.rs lines 203-205 at `e8bbd4d`), and a session lives 720
minutes at most (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:233-235`).
Measured in sandbox A (T-001; `docs/STATUS.md`, "In the operator's real
sandboxes, measured"): 67,107,943 bytes, then `1009 session byte cap`. A pair
lives 72 h or less, and the operator gets its `connect_token` only from the
node's side (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:133-138`).

## Approach

1. Count each byte of a link in both directions, the records of the layer
   included.
2. At 48 MiB or at 11 h, open a second link through the usual roads and relay
   hosts, and run the resume of T-153 on it: no second connect path.
3. Move the writer to the new link at a record boundary. Then send `RETIRE` on
   the old link (a new record of T-151: it ends a link, not the session), and
   close it with 1000.
4. Invariants: at most two links for each session; no byte lost or given
   twice to SSH, because the offsets decide; the move never waits for the old
   link to drain.
5. A failed move is not a fault: at the cap the relay closes with `1009`, and
   T-153 resumes.
6. When the client knows the expiry of the pair (from the node's ticket,
   T-163), it warns 1 h before; at the expiry the session ends with the reason.
7. `-v` prints one line for each move. Docs: `docs/relay.md` ("Limits that
   users see") and the manual (`crates/podssh-cli/src/man/facts.rs:297-459`).

## Decision

Recommendation: move at 48 MiB (75 % of the cap) or at 11 h. The bytes in
flight at a move (a relay queue of 1 MiB, an SSH window of 512 KiB for each
channel) and a second try after a failed move fit in the 16 MiB that remain.
The alternative, a move at 60 MiB, lost: one failed move would leave too
little room for the next.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_move
cargo test -p podssh-relay --test live -- --ignored move_200mib
```

The move test gives a fake link a cap of 1 MiB, as a constructor argument:
8 MiB pass with an equal SHA-256 over more than 8 links, with no `1009`
close. A planted layer that never moves meets `1009` at the first cap, and
the test fails. The live test sends 200 MiB each way with equal digests.

## Correction

The live test needs a node and the layer's client, which are in
podssh-cli: it is `cargo test -p podssh-cli --test node_live -- --ignored
move_200mib`, with an echo server on the loopback as the node's TARGET.
Step 6 needs no ticket of T-163: the operator's part of a pair keeps its
expiry (`expires_ms`, `crates/podssh-relay/src/pair.rs:347`), and at the
expiry the relay ends each session of the pair with `1001 pair expired`
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:171`), which
the policy of T-153 does not resume. The repair of T-262 changed step 3:
the new link greets while the old one carries the session, but its
handshake takes the offsets only after the old one stopped.

## Done

2026-10-09.

- The record `RETIRE` (0x0b, no body: a link ends, the session goes on), in
  the codec, its vectors and `docs/design.md`; `Event::Retired` and
  `End::Retired`. `move.v1` in `session::FEATURES`, used only with
  `replay.v1`; `Settings::move_bytes` (48 MiB) and `move_age` (11 h).
- `pump::Watch`: the stop of a link, whether a stopped link sends `RETIRE`,
  the bytes of the link both ways (records included), and a notice when they
  pass the move's mark. `End::Moving`, which the driver gives its caller
  when it asks for a link to move to.
- The move in `resume::run`: at the mark or the age, a second link is asked
  for, and its far end greets while the old one still carries the session;
  then the old one stops at a record boundary and says `RETIRE`, and the new
  link's handshake takes the offsets, then sends again from the far end's
  offset (`Note::Moved`, `Note::MoveFailed`; the CLI prints them with `-v`,
  and its connect does not wait for a leg that still runs). A session whose
  application ended does not move.
- `podssh ssh node://` and `podssh operator` say, an hour before the pair
  expires, that the relay then ends the session (`EXPIRY_WARNING` and
  `expiry_wait` in `crates/podssh-cli/src/layered.rs`).
- `docs/relay.md` ("Limits that users see"), the manual's "Session limits",
  and `docs/design.md` (section 5) say so.
- Prove, native: `cargo test -p podssh-relay --test session_move`: 2 passed,
  in 20 runs in a row. Links capped at 1 MiB with a move at 768 KiB: 8 MiB
  each way with equal digests over more than 8 links, no cap met and no
  loss; a move each 256 KiB with both ends at full speed: no loss and no
  failed move. `cargo test -p podssh-cli --lib -- layered`: 3 passed (the
  wait before the warning: an hour before, at once with less left, none
  after the expiry). `cargo test -p podssh-cli --no-fail-fast`: 331 passed,
  0 failed, 8 ignored (the live tests). `cargo test --no-fail-fast`: 994
  passed, 0 failed, 22 ignored.
- Waits for T-251: the live test `move_200mib_each_way_through_a_node`
  (400 MiB through the relay: over 100 MiB, Q35), and the planted layer that
  never moves, which must meet the cap and fail the move test.

# T-156: M6 exit: a session survives a stopped relay host, a new address and a stall of 3 minutes

**Source:** ROADMAP M6, exit criteria; `docs/design.md:610-612` (the harness
must grow for layer 2).
**Category:** measurement
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

M6 is done when a session survives three faults, on the resumable layer and
on the iroh road: a stopped relay host, a change of the client's address, and
a stall of 3 minutes. Today each of these faults ends the session.

## Premise

Measured in the gate (`docs/STATUS.md`, "Faults between podssh and the relay,
measured"): a relay that stalls is declared dead at 50 s, and a relay host
killed in a session gives exit 255 (`scripts/interop-faults.sh:238-256`).
These checks stay, for the forward road, which has no resumption. Read: the
stand-in relay serves the forward path only (`scripts/fake-relay.py:114-132`),
and its `stall` mode never ends (`scripts/fake-relay.py:322-325`). The
harness cannot change an address or end a stall yet (T-203). The checks need
T-151 to T-155, the iroh road (T-162 to T-165), the reverse runners (T-079,
T-080) and a far end (`podssh serve`, T-107).

## Approach

1. With T-203, give the stand-in relay the reverse path: `/v1/pair`,
   `/v1/node/<name>`, `/v1/connect/<name>`, the text control frames and the
   32-character ids. One process serves two host names, so the reverse state
   survives when one listener stops.
2. Three faults: stop the relay host in use; make the client's link go silent
   with no RST, while new connections succeed from a second loopback address;
   stop each byte in both directions for 180 s, then let them pass again.
3. For each fault on each road (the layer over the reverse road; the iroh road
   with a local iroh relay or n0's relays): a `-tt` session that echoes lines,
   and a transfer of 20 MiB with SHA-256 compared at both ends. The fault
   comes in the middle.
4. Pass: exit 0, equal digests, each echoed line once, one stderr line for the
   loss and one for the resume.
5. A control: the same faults on the forward road end the session with exit
   255, so a check that passes for a wrong reason shows.
6. Then once live, from the Podman box through the live relay
   (`scripts/test_in_box.sh`), with the stall made at the box's proxy
   (`scripts/box/proxy.py`).
7. Record each result in `docs/STATUS.md` with the date and the command, and
   mark the M6 exit in `docs/ROADMAP.md`.

## Decision

2026-10-10, before the work:

- The faults go in the stand-in proxy, where each road meets them alike,
  the relay's protocols unread: `--stop-after SECONDS` (each open tunnel
  ends with RST, SECONDS after the first one, and new tunnels go on: the
  relay host in use stops, and the client and the node come back as through
  another address of the control host), `--move` (T-203) and `--pause
  AFTER:FOR`. Lost: the faults in the stand-in relay, which the iroh road's
  relay, iroh's own server, would then need again.
- The stand-in relay gains the reverse road (item 1) as the live relay
  showed it (`docs/relay.md`, the reverse path): `POST /v1/pair`,
  `/v1/node/<name>`, `/v1/connect/<name>`, `/v1/status/<name>`,
  `/v1/stop/<name>`, each token in `X-Relay-Token`, the text frames `hello`,
  `open`, `ready`, `reject` and `close`, and the 32 characters of each id.
- The iroh road's relay is iroh's relay server under a name that only the
  proxy resolves, with a certificate for that name, so its connections pass
  the faults of the proxy too.
- The same checks run natively in an ignored test, with the tests' SSH
  server for the transfer and the lines; the gate's run, with OpenSSH and a
  `-tt` shell, and the box's live run wait for T-251.

## Prove

```sh
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The fault step of the gate prints `ok` for six new checks (three faults on two
roads) and for the controls on the forward road; the controls show that the
checks fail for a session that does not resume. The run in the box shows a
live session that survives a stall of 3 minutes.

## Correction

The far end that the checks need is the layer's far end, which `podssh node`
is, in front of an SSH server; `podssh serve` (T-107, held by the operator)
is not needed for them.

- The new address and the stall are the client's, as the exit names them:
  the node has a proxy of its own, which makes a fault only when the relay
  host stops. A node whose own link goes silent comes back only when the
  relay lets its old socket go (`409`, T-261), and the stand-in relay, which
  sends nothing on an idle socket, never does.
- The gate runs the same checks in the build image (the step `m6`), with
  the tests' SSH server, and not OpenSSH with a `-tt` shell: the layer is
  below SSH, where a pty's bytes are bytes, and 20 MiB of `echo` checks each
  of them. The live run from the box, with a pty, comes with T-251.

## Done

2026-10-10. The exit of M6 is met on this machine's loopback: a session
survives a stopped relay host, a new address of its client and a stall of
3 minutes, on the resumable layer over the reverse road and on the iroh
road, and the same faults end a session of the forward road with 255
(`docs/STATUS.md`, "Faults between podssh and the relay, measured").
- The stand-ins: the reverse road in the stand-in relay
  (`scripts/fake_reverse.py`, on the WebSocket parts of
  `scripts/fake_ws.py`, which `scripts/fake-relay.py` imports);
  `--stop-after`, `--pause` and `--start-file` in `scripts/fake-proxy.py`;
  iroh's relay server under a name (`spawn_named` in
  `crates/podssh-iroh/src/test_relay.rs`); and `PODSSH_IROH_UDP=off`, which
  turns the iroh road's UDP off (`crates/podssh-iroh/src/endpoint.rs`, in
  the manual).
- The checks: 11 ignored tests in `crates/podssh-cli/tests/m6_exit.rs`, and
  the gate's step `m6` (`scripts/gate.sh`), which CI runs at each push.
  Native, Windows: 11 of 11 in 630 s, and the layer's check of a stopped
  relay host 10 times more.
- Found on the way: the stand-in relay gave the operator the node's first
  bytes before its `ready` when the two came in one read, which the live
  relay never does (repaired in the stand-in); and a session of the forward
  road could wait for ever after its relay host stopped (T-269, repaired).
- Waits for T-251: the live run from the box through the live relay, with
  the stall at the box's proxy ("a session that survives a killed relay
  connection").
- CI, the run of `94e3e6a` (38001904475): the gate's step `m6` in the build
  image, 11 of 11 in 692 s; each job passed.

# T-157: Throughput on each road and relay, by a committed method

**Source:** ROADMAP M6 (throughput on each road and relay, in and out of a
sandbox, before a default depends on it); `docs/design.md:1073-1093`; the two
sandbox reports of 2026-10-08; GitHub #18 (warren's method) and GitHub #23
(sshping: throughput up and down).
**Category:** measurement
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh has no committed method to measure throughput. The figures so far come
from testers' commands, and one target was out of the relay's reach. A
default road (T-164) and the iroh relays (T-165) need figures from one method.

## Premise

Measured by the operator's agents (T-001; `docs/STATUS.md`, "In the
operator's real sandboxes, measured"): 20 MiB down the forward road at 0.5 to
0.7 MB/s through a CONNECT proxy (2 runs), and at 1.8 to 6.9 MiB/s with no
proxy (4 runs). Read in the report, not verified here: the script's target
(thinkbroadband) gave `1011 write failed` and 0 bytes, and the relay's
`/trace` showed that the relay could not reach it.
Read: no iroh figure exists for a relay through a CONNECT proxy
(`docs/design.md:1073-1093`). A session carries 64 MiB at most, both directions
together (`docs/relay.md:187`).

## Approach

1. Write the method as an ignored test,
   crates/podssh-cli/tests/throughput_live.rs, in the form of
   `crates/podssh-cli/tests/proxy_live.rs`: it runs the built binary.
2. The cells: each road (forward, reverse with the layer, iroh through a
   relay, iroh direct where UDP works, direct); each relay (the default host,
   three pool hosts, n0's relays, the operator's iroh relay when it exists);
   two places (outside a sandbox; the Podman box or a real sandbox).
3. In each cell: 5 runs, each on a new connection, near in time to the other
   cells; 20 MiB up and 20 MiB down in separate sessions; 300 s at most each.
4. The targets: a far podssh node that sends and drains bytes. For the
   forward road, two public targets, each checked first with `/trace`, which
   needs a token (`docs/relay.md:237-238`; `docs/relay.md`, lines 296-302 at `24f3e2a`). Skip a
   target that fails the check, with its reason; never count it as 0.
5. A control: the same runs through the stand-in relay on loopback
   (`scripts/fake-relay.py`), which shows podssh's own limit.
6. Report the minimum, p50, p95 and maximum in MiB/s for each direction, and
   keep the line of each run. Write the table in `docs/STATUS.md` with the
   date, the place and the command. Test the statistics offline.

## Decision

Recommendation: an ignored Rust test that runs the binary. It needs no
`curl`, `wc` or shell on the host, and it runs on Windows too. The
alternative, a shell script around `curl`, lost: a sandbox may have no tools
(`docs/decisions.md`, 2026-10-05: never assume a tool).

2026-10-10, the far end and the cells:

- The far end is an SSH server, as a user's session has one: a russh server
  in the test, whose commands send N bytes (`source N`) or drain stdin and
  say the count (`sink`). Each run is `podssh ssh ... source N` or `podssh
  ssh ... sink` with N bytes on stdin, a new process and a new connection
  each time. What podssh carries for a user (SSH, `cp`) is what is measured.
  Lost: raw bytes through `podssh operator`, which has no form for the iroh
  road, and would leave SSH out of the figure.
- The cells that reach no target outside AGENTS.md's list run when nothing
  is set: the loopback (the test's own SSH server, `--direct`), the reverse
  road through the live relay (a pair, `podssh node` in front of the test's
  server, `podssh ssh node://`), and, with the feature `iroh-test`, the iroh
  road through iroh's relay server on the loopback. The others run only
  when a variable names their target: `PODSSH_THROUGHPUT_SSH` (a public SSH
  server, for the forward and the direct road) and
  `PODSSH_THROUGHPUT_IROH_RELAY` (n0's relays, or the operator's). Neither
  kind of target is on AGENTS.md's list of test targets: Q38.
- The control of the forward road, through `scripts/fake-relay.py` on the
  loopback, needs Python and a certificate; the test makes one with
  `openssl` when a probe finds it, and else says that it skipped the cell.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test throughput_live
cargo test -p podssh-cli --test throughput_live -- --ignored --nocapture
```

The first command runs the offline tests of the statistics; a planted p95
that takes the maximum fails them. The second makes the measurement and
prints the table, which goes into `docs/STATUS.md`, section "Throughput,
measured".

## Done

2026-10-10.

- `crates/podssh-cli/tests/throughput_live.rs`: the statistics (min, and
  p50, p95 by nearest rank, and max), tested offline with a planted p95
  that takes the maximum; one small run each way on the loopback, in each
  test run; and two ignored measurements: `throughput_on_the_loopback` (the
  cells that reach no network) and `throughput_on_each_road` (those and the
  live ones). Each cell's table keeps the line of each run, then the
  summary of each direction; a cell that cannot be set up, or a run that
  fails, says why and is never counted as 0.
- `tests/throughput_harness/`: the session (a scratch HOME, the test's SSH
  server, what the cells start, stopped at the end, a pair revoked), one run
  with its clock and its limit of 300 s (the process is killed), and the
  cells: the loopback with `--direct`; the forward road through
  `scripts/fake-relay.py`, with a test CA and certificate that `openssl`
  makes, when a probe finds Python and `openssl`; the reverse road through
  the live relay (a pair, `podssh node`); with `iroh-test`, the iroh road
  through iroh's relay server on the loopback; and, when a variable names
  their target (Q38), a public POSIX server (`PODSSH_THROUGHPUT_SSH`, by the
  live relay and directly, with `head` and `sh -c 'echo R; wc -c'`) and the
  iroh relays of `PODSSH_THROUGHPUT_IROH_RELAY`.
- `tests/ssh_harness/`: the test's SSH server (russh), shared with
  `tests/iroh_road.rs`: `greet`, `source N`, and `sink`, which says `R` as
  it starts to read and the count at the end.
- Prove, native, Windows: `cargo test -p podssh-cli --test throughput_live`:
  3 passed, 2 ignored (the statistics; the planted p95 fails the check; the
  method on the loopback). The loopback measurement, with `iroh-test`, 61 s:
  the table is in `docs/STATUS.md`, "Throughput, measured": `--direct` p50
  165.9 MiB/s up and 106.3 down; the stand-in relay 7.1 and 7.9, its own
  limit (Python's asyncio); the iroh road through iroh's relay server 34.6
  and 25.6. `cargo test --no-fail-fast`: 1006 passed, 0 failed, 24 ignored (the record's own test passed after its remaps). clippy in both builds and
  with `iroh-test`: no warning.
- Waits: the live run of `throughput_on_each_road` (the reverse road through
  the live relay, 200 MiB a cell, is more than 100 MiB) for T-251, and for
  Q38 the cells whose target is not on `AGENTS.md`'s list: a public SSH
  server for the forward and the direct road, and n0's relays. The run in a
  sandbox, or the Podman box, comes with T-251 too.

# T-158: Detach and attach again

**Source:** GitHub #19 (Nemo-010, 2026-10-08: rose's `~d` and `--session`,
ssh-obi's detach and list of sessions, and fux's refusal of a nested attach);
GitHub #18 (zuko: a detached pty with a lease).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A user cannot leave a shell running and come back to it later, from a new
podssh process or from another host. tmux does this on a server that has
tmux; a cage usually has none.

## Premise

Inferred from the design: the layer runs under SSH (`docs/design.md:570-571`),
so the keys and the sequence numbers of the SSH connection live in the client
process. A new process cannot continue that byte stream, so an attach is a
new SSH login to a far end that kept the shell (T-159). Read: podssh knows
the escapes `~.`, `~R`, `~?` and `~~`, and another character after `~` goes
to the server with the `~` (`crates/podssh-ssh/src/escape.rs:1-9`,
`crates/podssh-ssh/src/escape.rs:90-138`). The flag table has 469 lines, near
the limit of 500 (the table of `ssh`: `crates/podssh-cli/src/flags.rs:112-281`).

## Approach

1. Add the escape `~d` (detach), only when the far end offers kept shells (a
   feature name in the `GREETING` of T-151). Elsewhere `~d` goes to the server
   as now.
2. On `~d`, the client asks the far end to keep the shell, prints the name of
   the shell on stderr, and exits 0.
3. `podssh ssh --attach NAME DEST` logs in again and asks the far end to join
   the kept shell, with a channel request of podssh. With no NAME, it lists
   the user's kept shells and exits 0.
4. The far end decides when a shell is busy: one client at a time, unless the
   user asks to take it over (ssh-obi's rule, read in GitHub #19, not
   verified here). Refuse an attach from inside the same shell.
5. Put the new rows of the flag table in a new file, so that `flags.rs` stays
   under 500 lines. Add `~d` to the help of `~?`
   (`crates/podssh-ssh/src/escape.rs:137-145`) and to the manual.
6. Against a standard sshd, use `--persist` with tmux (T-178).

## Decision

Recommendation: the far end keeps the shell, and a new SSH login attaches to
it. This needs no listener on the client (`AGENTS.md`, section 5, rule 2),
survives a restart of the client host, and works from another host with the
same key. The alternative, a client in the background that keeps the SSH
connection and takes attaches over an AF_UNIX socket, lost: it needs a local
listener on the client, and it dies with the client host.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib escape
cargo test -p podssh-cli --test attach
```

The escape tests show `~d` as a detach only when the far end offers it, and
as two bytes otherwise. The attach test (crates/podssh-cli/tests/attach.rs)
runs `podssh serve` and the client: it sets a variable in the shell, detaches,
attaches by name, and reads the variable back. A planted far end that ends
the shell on a detach fails it.

## Correction

2026-10-12, read before the work:

- No far end keeps a shell yet: `podssh serve` (T-107 to T-110) waits for
  the operator (Q32), and the kept shells, their lease and their limits are
  T-159's, which waits on it. So the attach test cannot run `podssh serve`.
  It runs a stand-in of the far end in the test process
  (`crates/podssh-cli/tests/keep_harness/mod.rs`): the layer as `podssh
  serve` speaks it, with `keep.v1`, and a russh server whose shells outlive
  their client, behind a node in plain mode on the stand-in relay, as
  T-156 ran its far end.
- Step 3's channel request of podssh cannot reach a far end on russh: its
  server answers a channel request or a global request of a type that it
  does not know with FAILURE, and calls no handler (russh 0.64.1, the
  version of `Cargo.lock`: `Eugeny/russh:russh/src/server/encrypted.rs`,
  lines 1682-1686 and 1760-1763 at `b03c8d5`). The requests are therefore
  `env` requests of podssh's own names and a subsystem, which the handler
  sees (`crates/podssh-ssh/src/keep.rs`).
- An escape needs a pty and a terminal on stdin
  (`crates/podssh-ssh/src/session.rs:163`), so a test cannot type `~d`
  through a pipe: the attach test types it in a pseudo console on Windows
  (`crates/podssh-cli/tests/conpty_harness/mod.rs`) and in a pty on Linux
  (`crates/podssh-cli/tests/pty_harness/mod.rs`, new).
- The Premise's numbers moved: the escapes are `~.`, `~R`, `~#`, `~?` and
  `~~` since T-041, and the flag table had 464 lines before this entry. Its
  rows are one slice, which a second file cannot extend, so the two new
  rows are constants of a new file that `SSH_FLAGS` names.
- Step 4's refusal of an attach from inside the same shell: the client
  cannot tell which shell it runs in. The far end puts `PODSSH_SHELL_ID` in
  each shell that it starts, the client sends it, and the far end refuses.

## Done

2026-10-12.

- The layer: `keep.v1` (`KEEP`) and `SHELL_FEATURES` in
  `crates/podssh-relay/src/session/mod.rs`. `podssh ssh` names it
  (`layered::ssh_settings`), and the road of `node://NAME`, raced with
  `--iroh-ticket` too, reads the far end's answer before the SSH login
  (`layered::learn`, `layered::carry_keeping`;
  `crates/podssh-cli/src/ssh/node.rs`,
  `crates/podssh-cli/src/ssh/iroh/race.rs`). A node names FEATURES, never
  `keep.v1`.
- The client: `crates/podssh-ssh/src/keep.rs` (the offer, what the user
  asked, the name, the requests `detach@podssh`, `attach@podssh`,
  `take@podssh`, `from@podssh` and the subsystem `shells@podssh`, and the
  answer to `~d`). `~d` in the table of `crates/podssh-ssh/src/escape.rs`,
  an escape and a line of `~?` only with the offer. `session.rs` refuses an
  attach or a list with no offer (255), asks for the attach before `shell`,
  and gives `~d` its name; `io.rs` ends the session with `End::Detached`
  on SUCCESS and goes on after FAILURE, and `--result-file` says
  `detached`. `Termination` moved to
  `crates/podssh-ssh/src/terminal/termination.rs`, so that `io.rs` stays
  under 500 lines.
- The command line: `--attach NAME` and `--take`, in
  `crates/podssh-cli/src/flags/attach.rs`, which `SSH_FLAGS` names; the
  checks and what they ask in `crates/podssh-cli/src/ssh/attach.rs`.
  `--attach DEST` with no other word lists the kept shells. The manual's
  notes of `ssh` (`~d` in the terminal's note, a note of `--attach`,
  `detached` in the result file) and `PODSSH_SHELL_ID` in ENVIRONMENT;
  `docs/terminal.md` ("Detach and attach again"), `docs/cli.md`,
  `docs/design.md` (section 5), `docs/STATUS.md`.
- The calls made where the Approach left a choice. The client names the
  shell: 8 hexadecimal digits at the first detach, the attached name after
  an attach. SSH's SUCCESS carries no data, and only a global request's
  answer does, which russh's server never lets through; the far end
  refuses a name that another shell has. `~d` ends the input there, as
  `~.` does, and a refused detach leaves the session running. A value flag
  of the table needs its value, so `--attach WORD` with no destination
  makes WORD the destination, and lists. `--attach` is for `node://NAME`
  only (64 elsewhere), the one road that reads the offer: the iroh road
  alone (`iroh:TICKET`) carries the layer inside podssh-iroh's `carry`,
  which gives no handshake to read, so `~d` goes as two bytes there and
  `--attach` is refused; it comes with a far end that keeps shells on that
  road (T-159). A refusal of the far end is its words on stderr and its
  exit status, which podssh exits with. `--take` takes the shell, and the
  far end ends the other client's channel (255 there). A control master
  does not carry an attach: the run makes its own connection.
- Prove: `cargo test -p podssh-ssh --lib escape`: 9 passed here (among them
  `tilde_d_detaches_only_when_the_far_end_keeps_shells` and
  `the_help_names_tilde_d_only_where_it_detaches`).
  `cargo test -p podssh-cli --test attach`: 6 passed here, on Windows 11
  with Python and openssl, and in the build image with the pty of Linux
  (6 passed). Its tests:
  `a_shell_left_with_tilde_d_is_attached_again_by_name` (the variable, `~d`
  in a terminal, the list, `--attach NAME` from a new process, the
  variable read back); `a_far_end_that_ends_the_shell_on_a_detach_fails_the_check`
  (the planted far end of the Prove, run here as the control: the read
  fails with exit 1); `a_far_end_that_keeps_no_shells_refuses_attach_and_gets_tilde_d_as_bytes`;
  `the_far_end_refuses_a_nested_attach_and_a_second_client_unless_take`;
  `attach_refuses_what_it_cannot_serve_before_anything_connects`. The
  tests of `~d` run on Windows and Linux only; each test but the last says
  "did not run" with no Python or no openssl. The unit tests of
  `keep.rs` and `ssh/attach.rs`: 13 and 1 passed; the suites of
  `podssh-ssh` and `podssh-relay`, and those of `podssh-cli` that the change
  reaches (`ssh_args`, `node_plain`, the manual's and the flags'), passed,
  and so did a build with the feature `iroh`.
- Waits for T-251: the gate's run in the build image (the pty of Linux),
  and the planted client: an `Escapes` that takes `~d` with no offer must
  fail `tilde_d_detaches_only_when_the_far_end_keeps_shells` and
  `a_far_end_that_keeps_no_shells_refuses_attach_and_gets_tilde_d_as_bytes`.
  A run against `podssh serve`, and live through the relay, waits for
  T-159.

# T-159: Sessions on the far end that outlive the client

**Source:** GitHub #20 (Nemo-010, 2026-10-08: a session that the server owns
and that outlives the window, from fux); GitHub #19 (quic-ssh's registry of
persistent sessions; tty7's sessions after a reboot); GitHub #18 (zuko: a
detached pty kept for 5 minutes).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

When the client is away for longer than the resume deadline, the far end ends
the shell and its programs. A long job that runs in an interactive shell is
lost with the client's laptop or network.

## Premise

Read: no server exists yet; `podssh serve` is M5 (T-107, T-108, T-110). The
registry of the layer keeps a session only until the resume deadline
(T-153). Read in the reports, not verified here: zuko keeps a detached pty for
5 minutes, with no replay; quic-ssh keeps the output of a persistent session
in a bounded buffer with a start offset
(`VLOD-ZDOV/quic-ssh:src/server/persist.rs`); tty7 brings back the layout and
the screen after a reboot. A process does not survive a reboot, so only
metadata can.

## Approach

1. In `podssh serve`, a shell with a pty can outlive its SSH channel: keep the
   pty, the process group of the child, and a ring of its recent output. The
   ring drops its oldest bytes at a boundary of the terminal grammar (T-221),
   and T-161 decides what an attach shows.
2. Keep a shell only on request: the detach of T-158, or a keep request at the
   login. Give each kept shell a lease; it ends when the lease runs out or the
   shell exits.
3. Limits: a maximum count of kept shells for each user and in total, and a
   bounded ring for each. Hold the state in memory only.
4. At the end of a lease, send SIGHUP to the process group, then SIGKILL after
   10 s, with the stop rules of T-117.
5. A restart of `podssh serve` or of the host ends each kept shell. Write the
   names of the kept shells in a state file (mode 0600), so that the user
   learns what was lost. Say so in the manual.
6. Docs: the server side in `docs/terminal.md`, and the section of `serve` in
   the manual.

## Decision

Recommendation: keep a shell after the resume deadline only when the client
asked, with a lease that the user gives and a maximum that the server sets.
The alternative, keep each shell after each loss, lost: a cage would collect
programs that nobody comes back to.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test serve_keep
```

The test (crates/podssh-ssh/tests/serve_keep.rs) starts `sleep 600 &` in a
shell, detaches, and attaches again in the lease: the job still runs. With a
lease of 2 s, the process group is gone after the lease. A planted server that
keeps nothing fails the first check; a planted server with no lease fails the
second.

## Start condition

T-107, T-108, T-110 and T-117 are done: `podssh serve` exists, with a shell on
a real pty and a stop that signals each child's process group. The operator
holds them (Q32, `docs/decisions.md`), so this entry waits as they wait, as
T-114 does. Read at `b03c8d5` (2026-10-12): no source in `crates/` outside
the tests uses `russh::server`, and the verb table of
`crates/podssh-cli/src/flags.rs` has no `serve`. The far end of the resumable
layer keeps a stream to its target until the resume deadline, not a shell
(`crates/podssh-relay/src/session/keep.rs`), so a kept shell has no other
place to live. The parts that need no server (the lease, the limits, the stop
and the state file) wait too, as the TOTP code of T-115 waits: their shape
follows the server's pty and channels, which T-107 to T-110 decide. The
ring of step 1 exists: T-221's `Ring`
(`crates/podssh-terminal/src/grammar/ring.rs`), which drops its oldest
bytes only up to a boundary of the terminal's grammar.

# T-160: Local echo and prediction for high latency

**Source:** `docs/design.md:607-608`; GitHub #19 and GitHub #18 (Nemo-010,
2026-10-08: quic-ssh's prediction, `VLOD-ZDOV/quic-ssh:src/client/predict.rs`;
rose's prediction, GPL, of which only the specification may be read).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

Through the relay, each typed key shows only after a round trip: at 300 ms,
each key shows 300 ms late. Mosh shows a typed key at once, and corrects it
later.

## Premise

Read: an interactive echo for high latency is a later option on top of layer
2; it needs podssh at both ends, and it cannot use UDP here
(`docs/design.md:607-608`). podssh passes the bytes of a remote pty unchanged
and has no model of the remote screen (`docs/terminal.md:20-25`). A
prediction needs the place of the cursor, and needs to know when the far end
echoed a key. Only a podssh far end can tell when a key reached the pty and
whether the pty echoes. With no echo (a password prompt), a predicted key must
never show.

## Approach

1. A terminal model on the client: a pure-Rust parser of escape sequences and
   a screen grid, enough for the cursor, the line and the alternate screen.
   Accept a crate only with an MIT or Apache license and no C.
2. Predict printable characters, Backspace, and the left and right arrows, on
   the line of the cursor only. Show predictions only after the first
   confirmed key of an epoch (the rule of mosh, read in rose's specification,
   not verified here). Underline a prediction until the echo confirms it.
3. The far end (`podssh serve` with a pty, T-110) reports the input offset
   that reached the pty, and the ECHO flag of the pty. Invariant: no
   prediction shows while ECHO is off, so a password never shows.
4. A difference between a prediction and the screen clears each prediction,
   and starts a new epoch.
5. On only by request (`--predict`), with a pty, to a podssh far end, and
   above a measured round trip of 120 ms.
6. Test the model against the terminal oracle of T-200.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test predict
```

With 300 ms of latency from the fault harness (T-203), typed letters show
before the echo. With ECHO off at the far end, no typed letter shows before
the server writes it. A planted predictor that ignores the ECHO flag fails
the second check.

## Start condition

T-107 and T-110 are done: `podssh serve` exists and runs a shell on a real
pty. The operator holds them (Q32, `docs/decisions.md`), so this entry waits
as they wait, as T-159 does. Step 3 is the far end's: the offset of the input
that reached the pty and its ECHO flag come from `podssh serve`, and the
invariant of step 3 (no prediction while ECHO is off, so that a password never
shows) cannot hold without them; step 5 turns prediction on only to a podssh
far end. A model on the client alone would guess the ECHO flag, which the
invariant forbids. Read at `d56d316` (2026-10-12): the verb table of
`crates/podssh-cli/src/flags.rs` has no `serve`, and no source outside the
tests uses `russh::server`.

# T-161: Screen state and scrollback when a client attaches

**Source:** GitHub #19 (Nemo-010, 2026-10-08: ssh-obi replays the byte stream
and keeps the local scrollback; rose's State Synchronization Protocol and its
scrollback with stable row indices, GPL, specification only); GitHub #20
(fux: history that wraps again on a resize); GitHub #31 (the modes after a
replay that was cut).
**Category:** research
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

When a client attaches to a kept shell (T-158, T-159), its terminal is empty
and must show the current screen. A replay of the last bytes can start inside
a full-screen program that set its modes long before. A snapshot of the
screen needs a terminal model on the far end.

## Premise

Read: the resumable layer replays bytes, as decided (`docs/design.md:570-587`).
That serves the same client process, whose terminal still holds the screen
and its modes. A new process starts with an empty terminal. Read in the
reports, not verified here: ssh-obi replays the byte stream and accepts
duplicate recent bytes; rose sends the screen state and scrollback rows with
stable indices.

## Approach

Each step ends with a result in `docs/terminal.md`.

1. Byte replay from a safe point: replay the ring from a boundary (T-221),
   then send a window change to the pty, so that full-screen programs draw
   again (SIGWINCH). Measure with `vi`, `less`, `top` and a shell, through the
   oracle of T-200.
2. Send the terminal modes again after a replay that was cut (the alternate
   screen, application cursor keys, bracketed paste), as tty7 does
   (`l0ng-ai/tty7:crates/tty7-core/src/core/term_modes.rs`, read in the
   report of GitHub #31, not verified here); mind `?1049h` when the mode is
   on already.
3. A snapshot: the far end keeps a terminal model (the parser of T-160) and
   sends the visible screen and N lines of scrollback. Measure its memory for
   each session, wide characters and the alternate screen.
4. Compare the two: the screen after an attach, the local scrollback, the
   memory, and the size of the code.
5. Write the recommendation in `docs/design.md` section 5, for the operator.

## Decision

Recommendation, to confirm by the research: byte replay from a boundary, the
modes sent again, then a forced redraw. It needs no terminal model on the far
end, and it keeps the model of the layer. Use a snapshot only if the
measurement shows broken screens. The alternative, a snapshot first, puts a
terminal model into each `podssh serve`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test attach_screen
grep -n 'Screen on attach' docs/terminal.md
```

The test attaches to a kept shell that runs `vi`, and compares the client's
screen model with the far end's. A planted replay from a random offset fails
it, and so does a replay that leaves out the modes. The `grep` shows the
recorded result.

## Start condition

T-159 is done: a far end keeps a shell, its ring and its pty after the
client leaves. Each step measures what a client gets when it attaches to
such a shell (the ring replayed from a boundary and a window change sent to
the kept pty; the modes sent again; a snapshot kept by the far end), and no
far end keeps a shell yet: T-159 waits for `podssh serve`, which the
operator holds (Q32). T-158 made the client's side (`~d`, `--attach`,
61796d8), against a stand-in far end that keeps a shell but no screen. The
boundary of the replay is T-221's, done: its ring gives its bytes from a
boundary.

# T-221: Replayed output after dropped bytes starts at a boundary of the terminal grammar (GitHub #31)

**Source:** GitHub #31 (2026-10-08: a rule for where a kept window may start),
with the coordinator's reading of 2026-10-08, checked here against
`docs/design.md:572-578`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

An escape sequence of a terminal has several bytes. When a ring of output
drops its oldest bytes, the kept window can start inside a sequence or inside
a UTF-8 character. A client that attaches then gets the end of a sequence as
text: a full-screen program draws wrongly, or a part of a title sequence shows
on the command line.

## Premise

Read: the layer keeps each byte that is not acknowledged, "with backpressure
when it is full" (`docs/design.md:573-574`), and a resume sends again from the
other side's offset (`docs/design.md:576-578`). Thus a resume in the buffer
is byte-exact, and it cannot start in the middle of a sequence; T-152 tests
that invariant. Bytes are dropped only where a client attaches after output
that it never received: T-158, T-159 and T-161. The report puts the tracker
in `podssh-transport`; it cannot work there. The layer runs under SSH and
sees only ciphertext (`docs/design.md:570-571`), and the transport crates do
not know the protocol that they carry (`docs/architecture.md:117-119`). The
plaintext of a pty exists only on the far end that keeps the shell. Read in
the report, not verified here: tty7 drops bytes from its ring until a tracker
says that it is at a boundary
(`l0ng-ai/tty7:crates/tty7-core/src/daemon/pane.rs`).

## Approach

1. A sans-IO tracker in `podssh-terminal`, a crate with no C, in a new module
   beside the escape parser (`crates/podssh-terminal/src/escape.rs`). Bytes
   go in; it says whether the next byte is at a boundary. The caller gives
   the time with each chunk; the module reads no clock.
2. The states: plain, escape, CSI, OSC, DCS, and the other strings (SOS, PM,
   APC); a string ends with ST or, for OSC, with BEL; CAN and SUB end each
   sequence. Track UTF-8 too: a continuation byte is never a boundary.
3. Put the tracker beside the ring of a kept shell (T-159). The ring drops
   its oldest bytes only up to a boundary, so the first byte that it sends
   after dropped bytes is at a boundary.
4. The rule of the report for a long idle time: when the tracker stays in a
   sequence with no byte for 10 s, the grammar is broken. The next start is
   then the next newline or the next full repaint (`ESC [ 2 J`, or a switch to
   the alternate screen).
5. Test with bytes captured from real sessions (`vi`, `less`, `top`, a prompt
   that sets the title with OSC, UTF-8 text), not bytes that the test makes.
   The fixtures are bytes: give them a `-text` line in `.gitattributes`, as
   the IRC fixtures have.
6. Write the rule in `docs/terminal.md`, next to the ring of T-159.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-terminal --test grammar_boundary
```

The test reads the captured sessions from
crates/podssh-terminal/tests/fixtures/, cuts each at a table of offsets, and
asserts that the first byte kept after each cut is at a boundary, and that a
real terminal model (T-200) then shows no part of a sequence as text. A
planted tracker that ignores UTF-8 continuation fails it, and so does one
that ignores OSC strings. A case with a sequence cut by 10 s of silence
starts at the next newline.

## Correction

2026-10-12, read before the work:

- Step 3 puts the tracker beside the ring of a kept shell, and no far end
  keeps a shell: T-159 waits for `podssh serve`, which the operator holds
  (Q32). So the ring is made here, in `podssh-terminal`, with no shell
  around it (`crates/podssh-terminal/src/grammar/ring.rs`). T-159's step 1
  already puts a ring that drops its oldest bytes at a boundary into each
  kept shell; it takes this one.
- The Prove names the terminal model of T-200 (`vt100`) as the oracle. The
  oracle here is the parser under such a model: anstyle-parse 1.0.0, vte's
  state machine, which `Cargo.lock` has already (through clap's
  `anstream`), a dev-dependency of `podssh-terminal`, pure Rust, with no
  build script. A start is clean when the parser's actions from it are
  those of the whole capture, byte by byte; a model's screen shows only
  the cells that a sequence changed, so a part of a sequence shown as text
  can hide under a later repaint.
- Step 5's captures: this host is Windows, with no pty and no `top`, and
  `less` copies its file unchanged to a stream that is not a terminal. vim
  and bash of Git for Windows write their terminal's bytes to a file too,
  and were captured so; less and top need a pty of Linux
  (`scripts/capture-terminal.py`).

## Done

2026-10-13.

- `crates/podssh-terminal/src/grammar.rs`: `Tracker`, sans-IO. `feed`
  takes a chunk with the time it came and gives each `Boundary`: its
  offset, and whether it is the first after a broken sequence. The states
  of step 2 and UTF-8; `BROKEN_AFTER`, 10 s, after which the next start is
  the byte after a newline or the `ESC` of a repaint.
  `crates/podssh-terminal/src/grammar/ring.rs`: `Ring`, at most its
  capacity, which drops its oldest bytes up to a boundary and gives the
  bytes from it (`start`, `kept`).
- The calls made where the Approach left a choice. Where terminals differ,
  the tracker finds no boundary, since one too few costs the ring bytes
  and a wrong one shows garbage: after the byte that cuts a UTF-8
  character short (vte drops that byte), and at 0x9C, which vte takes as
  ST in a DCS and a UTF-8 terminal does not. The head of a DCS is part of
  its string. The repaints are step 4's two, and `ESC [ ? 1047 h`,
  `ESC [ ? 47 h` and the reset `ESC c`, which start a screen as surely. The
  ring keeps a boundary for each 1/256 of its capacity, the first after a
  broken sequence, and the newest, not one for each byte of text: a cut
  drops at most about 1/256 of the ring more than it must. With no
  boundary left it keeps its last bytes and gives none until one comes, so
  it never holds more than its capacity.
- The captures, with a `-text` line in `.gitattributes`:
  `crates/podssh-terminal/tests/fixtures/vi.bin`, vim 9.2 of MSYS2
  drawing 60 lines of UTF-8 text in 24 rows and 80 columns (10038 bytes:
  the alternate screen, titles by OSC 2, colours, a search, line numbers,
  a split, its exit); `crates/podssh-terminal/tests/fixtures/prompt.bin`,
  bash run interactive with a prompt that sets the title by OSC 0, then
  `ls --color=always` and UTF-8 text (560 bytes).
  `scripts/capture-terminal.py` captured busybox's less (8230 bytes), top
  (1361) and vi (5355) in a pty of Linux in the build image:
  `crates/podssh-terminal/tests/fixtures/less.bin`, `top.bin` and
  `vi-pty.bin`. The test reads each capture there is.
- `docs/terminal.md`, "Where kept output may start"; `docs/STATUS.md`, the
  row of `podssh-terminal`.
- Prove: `cargo test -p podssh-terminal --test grammar_boundary`: 5
  passed on Windows 11, and 5 in the build image with no C compiler, over
  the five captures (2026-10-13). Its tests: `each_boundary_in_each_capture_is_clean`;
  `a_ring_cut_at_each_offset_gives_its_bytes_from_a_clean_boundary` (each
  offset of `prompt.bin` and each third of `vi.bin`: the first byte kept is
  a boundary, a terminal that starts there does over 256 bytes what the
  terminal of the whole capture does, and a ring keeps nothing only where
  no boundary follows the cut);
  `the_oracle_finds_a_cut_inside_a_sequence_or_a_character` (the control: a
  cut inside a title, a CSI and a character of each capture fails the
  oracle; these are the cuts that the two planted trackers make);
  `a_capture_cut_by_10_s_of_silence_starts_at_the_next_newline`
  (`prompt.bin`, silent for 10 s inside its second title: the ring keeps
  from the text after the next newline; silent for 5 s: from the byte
  after the title's BEL); and
  `a_capture_cut_by_10_s_of_silence_starts_at_the_next_repaint`
  (`vi.bin`: from its `ESC [ 2 J`). `cargo test -p podssh-terminal --lib
  grammar`: 20 passed (each state, CAN and SUB, chunks cut anywhere, the
  rule of a broken sequence; the ring's capacity, a ring with no boundary
  left, a character cut by the capacity, a repaint after a broken
  sequence). Clippy 1.98 here and 1.99 in the build image: no warning,
  after a list of byte literals became a byte string.
- Planted, each restored: a tracker that takes a UTF-8 continuation byte
  as a boundary failed `each_boundary_in_each_capture_is_clean` and
  `a_ring_cut_at_each_offset_gives_its_bytes_from_a_clean_boundary`; one
  that ends an OSC at its `]` failed those two and
  `a_capture_cut_by_10_s_of_silence_starts_at_the_next_newline`.
- Waits: a ring in a kept shell is T-159's step 1, which waits for
  `podssh serve` (Q32), and T-161 replays it.

# T-302: A notice in the terminal while the far end is silent

**Source:** T-171 (`docs/design.md:634-648`): Mosh shows a line at the top of the screen after
6.5 s with no word from the server.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

When the link goes silent, an interactive session shows nothing until the limit of a dead link:
30 s on the layer, then a line on stderr; 30 to 40 s on the forward road, then the end of the
session. A user cannot tell a slow program from a dead link. And a line on stderr in the middle of
a full-screen program is written into its screen.

## Premise

- Read: the layer's lines, written always: a loss (`crates/podssh-cli/src/layered.rs:364`) and a
  resume (`crates/podssh-cli/src/layered.rs:375`). The heartbeat each 10 s, and a link dead after
  30 s with nothing from the far end (`crates/podssh-relay/src/session/pump.rs:57`,
  `crates/podssh-relay/src/session/pump.rs:60`). The forward road's checks
  (`docs/design.md:551`).
- Read in Mosh (`docs/design.md:634-648`): the notice comes after 6.5 s with no word from the
  server, or 10 s with no acknowledged state; Mosh draws it over its own model of the screen,
  and removes it when the server answers.
- Read: the client has no model of the screen yet; T-160 (item 1) makes one.
- Inferred: a line written at the cursor of a full-screen program stays in its screen until the
  program draws again.

## Approach

1. The client keeps the time of the last byte from the far end. After 5 s with no byte while keys
   wait for their answer, or after 10 s with no byte at all, the notice shows; it goes when a
   byte comes. This entry sets the times, after a measurement with the `pause` mode of T-203.
2. Where it shows, each after a probe of the terminal: (a) in the window's title, saved first
   with `CSI 22 t` and restored with `CSI 23 t`, where the terminal keeps a stack of titles; (b)
   on the top row, drawn and then repainted from T-160's model, once that model exists; (c) with
   no pty, a line on stderr, as now. Which terminals keep a stack of titles (xterm, VTE, Windows
   Terminal, the Windows console) is not verified: this entry measures them.
3. The text: the seconds since the last word, and the escape that ends the session (`~.`).
4. On a terminal only, never in a pipe; `-q` turns it off. The layer's lines stay when stderr is
   not the terminal.

## Decision

Taken (2026-10-13), the source of the silence: the resumable layer, not
SSH's bytes. The layer hears each byte of the far end, and knows which of
its own records the far end answers at once: `DATA` that it acknowledges
within 200 ms (both named `replay.v1`), a `PING`, and a resume after a loss
(`crates/podssh-relay/src/session/hearing.rs`). Any byte answers each
question. The alternative, the time since the SSH channel's last bytes,
lost: to a node, SSH sends no keepalive (`docs/design.md`, section 5), so
an idle shell would show the notice, and so would a password's prompt,
which echoes nothing.

Taken: the notice comes when a question has waited 5 s, and counts the
seconds since the far end's last byte. These values were provisional
until the measurement of the Prove, which gave the notice 5.0 s after the
pause began (2026-10-30, through the stand-ins): 5 s is the entry's own
value, a few round trips and the 200 ms of an `ACK`. The entry's "10 s with
no byte at all" lost as a rule of its own: the far end's records come each
10 s in an idle session (the heartbeat, `PING_EVERY`), so a fixed 10 s would
show the notice for a moment in each healthy idle session. The heartbeat's
own `PING`, after 10 s with nothing sent, is a question, so an idle link
that died shows the notice 15 s after the last word at most.

Taken: the title's sequences are XTWINOPS `CSI 22 ; 2 t` and `CSI 23 ; 2 t`
(the window's title alone) and OSC 2 ended by BEL; the text has no control
character and no `;`, at which a model terminal cuts a title. They are
written only where the session's output left the terminal's parser at its
ground state (`crates/podssh-ssh/src/notice/boundary.rs`), and the title
comes back before the far end's next bytes, so that a title that a program
sets then is kept. T-221's tracker of sequences, a draft, may replace that
small parser once it is merged.

Taken: the probe of the stack of titles is what is known of the terminal,
from its environment: xterm (`XTERM_VERSION`) and VTE (`VTE_VERSION`), not
inside tmux or screen, whose bytes go to the multiplexer; and
`PODSSH_TITLE_STACK=yes|no` for another terminal. A query lost: its answer
comes on stdin, which the session's input task reads already, so the
answer would go to the server as keys, or a key would be lost; and xterm
does not answer `CSI 21 t` by default. A title with no stack lost: the
user's title would stay lost. On a terminal not known to keep a stack there
is no notice, and the layer's lines stay as before. Windows Terminal and
the Windows console are not in the list until `scripts/title-stack.py`
measures them (UNVERIFIED); so are xterm and VTE, which the list names from
their documentation.

Taken: while the title shows the notice, the layer's lines of a loss and of
a resume are left out (`layered::folded`): they would be written into the
screen, and the title tells as much. The lines of `-v` stay. With no pty,
the notice is two lines, at its start and when the far end answers again;
a line for each second lost, as it would fill the terminal.

Taken: the roads of the layer: `ssh node://`, its race with
`--iroh-ticket`, `iroh:TICKET` (`podssh_iroh::client::carry_heard`), and
the session after `--upgrade`. `podssh operator` has no terminal of its
own: it is the ProxyCommand of OpenSSH, whose terminal it does not know,
and its lines stay. The forward road lost: there, nothing below SSH
answers a key, and the relay's Pong answers podssh's Ping each 10 s, so a
notice would come 15 s after the last word at the soonest; T-307 is that
road's notice. The top row of item 2 (b) waits for T-160's model of the
screen, which the operator holds behind T-110.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test silent_notice
```

Through the stand-in relay with `pause:AFTER:FOR`, the notice comes after its limit, counts up,
and goes when bytes come back. With the terminal oracle (T-200), the screen after the pause equals
the screen before it, and so does the title. A planted notice written at the cursor fails the
check of the screen.

The run through the stand-ins is ignored, on Linux only, as it needs a pty, Python and openssl
(`cargo test -p podssh-cli --test silent_notice -- --ignored --nocapture`); it uses the stand-in
proxy's `--pause 0:20`, the reverse road's pause, and prints when the notice came and went. The
same checks with no terminal and no stand-in, with a model of the stack of titles beside the
oracle: `cargo test -p podssh-ssh --test silent_notice`. The planted defect: `Facts::place`
that gives `Line` to a terminal in raw mode; in the model, the control
`a_notice_written_at_the_cursor_changes_the_screen` shows the same.

## Correction

The first item of the Premise cites the layer's lines at lines of `next_leg`, which opens a new
leg. The lines are in `line_of`: a loss (`crates/podssh-cli/src/layered.rs:407`) and a resume
(`crates/podssh-cli/src/layered.rs:418`). What the item says of them holds.

## Done

2026-10-13, a draft; merged on 2026-10-30, when the main session built it
and ran each check below.

- `crates/podssh-relay/src/session/hearing.rs`: the far end's last byte and
  the oldest question that waits, across the links of a session; the pump
  hears each read, and asks with each `PING` and each `DATA` that the peer
  acknowledges; a loss asks too. `Client::with_hearing`, and
  `podssh_iroh::client::carry_heard`.
- `crates/podssh-ssh/src/notice/`: the road's word (`Silence`, in
  `Options`), the place of the notice by the facts of the session, the
  title with its stack and the probe of the stack (`title.rs`), the parser's
  ground state (`boundary.rs`), and the notice itself, which the session's
  pump ticks each second and which takes the title back when it ends.
  `crates/podssh-ssh/src/io.rs` gives it the session's output.
- `crates/podssh-cli/src/layered.rs` (`Shell`, `heard`, `folded`), and the
  roads of `ssh`: `node://`, the race, `iroh:`, `--upgrade`.
- The manual (the note of `ssh`; `PODSSH_TITLE_STACK`, `XTERM_VERSION` and
  `VTE_VERSION` in ENVIRONMENT), `docs/terminal.md` (a section of its own),
  `docs/design.md`, `docs/STATUS.md`; `scripts/title-stack.py`, the
  measurement of a terminal's stack of titles. T-307, the forward road's
  notice, is a new entry.
- Prove: `cargo test -p podssh-ssh --test silent_notice`, 5 passed, and
  `cargo test -p podssh-ssh --lib -- notice`, 5 passed. `podssh-relay`'s
  lib, `hearing` among it, passed in its whole suite. In all, `podssh-ssh`,
  `podssh-relay`, `podssh-cli` and `podssh-iroh` passed 1575 of 1576; the
  one was the note of `ssh`, which wrote `PODSSH_TITLE_STACK=yes`, a word
  that the check of the notes reads as a keyword of `-o`; it says "set to
  yes" now, as the other notes say it, and the lib suite passed, 405.
- The run through the stand-ins on Linux (`cargo test -p podssh-cli --test
  silent_notice -- --ignored --nocapture`) failed as drafted: it pinned
  relay-a.test to the loopback, and since T-318 such a pin goes with no
  proxy, so the client went around the stand-in proxy and its pause, and
  no silence came. It pins no address now, and clears the machine's proxy
  variables, as `crates/podssh-cli/tests/m6_exit.rs` does since T-318.
  Then: the notice came 5.0 s after the pause began ("no word from
  node://lab for 6 s", then "for 7 s"), and the key's answer came after
  20.0 s; it passed. The ignored runs of `attach` and `m6_exit` run in the
  gate's step m6.
- The merge kept `main`'s pump of `crates/podssh-ssh/src/io.rs` (its stop
  of T-185 and its `~C` of T-291) and put the notice's arm into it, and
  `main`'s `Through` (its `command_line` and `expect`) with the field
  `notice`. clippy `-D warnings` on the four crates and rustfmt clean.
- The planted defect, `Facts::place` that gives `Line` to a terminal in
  raw mode: the unit test `a_notice_shows_on_a_terminal_and_nowhere_else`
  failed with it, and passed without it; `--test silent_notice` passed
  with it too, as it drives the model with a place that it chooses.
- The measurement of the terminals: `python3 scripts/title-stack.py` in
  xterm, in VTE, and under WSL in Windows Terminal and in the Windows
  console: UNVERIFIED; it waits for the operator's terminals.
- Waits for T-251: the run in the build image, and clippy at CI's Rust.

# T-303: The latest screen on request: frames that let Ctrl-C show within a round trip

**Source:** T-171 (`docs/design.md:634-648`): Mosh sends the difference of screens at most each
half round trip, so Ctrl-C stops a flood within a round trip (its paper, §2.3).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

Under heavy output (a `cat` of a large file, a loop that prints), each byte of the pty crosses the
link in order. Over a slow road, the bytes in buffers and in flight are shown before the output
that follows a Ctrl-C, so the user waits to see the prompt. Mosh sends only the latest screen,
so Ctrl-C shows within a round trip.

## Premise

- Read: the layer and SSH carry each byte in order, and only the end that runs the SSH server
  sees the bytes of the pty in clear (`docs/design.md:625-632`).
- Read: `podssh serve` with a pty is T-110, which the operator holds (Q32); a model of the far
  end's screen is item 3 of T-161, and the client's is item 1 of T-160.
- Read in Mosh's paper (§2, §2.3), as the section of T-171 gives it (`docs/design.md:634-648`):
  a frame at most each half round trip, from 20 to 250 ms, after 8 ms of collection; and frames
  lose the scrollback of the output that they skip (`docs/design.md:652-656`).
- Not measured: how long Ctrl-C takes to show through podssh at 300 ms of latency and a limited
  rate.

## Approach

1. Measure first, with T-203's harness: `-tt` to `podssh serve`, a delay of 300 ms and a rate of
   64 KiB/s, a flood of `yes`, then Ctrl-C: the time until the prompt shows. Write the result;
   build only if it is longer than three round trips.
2. On request only (this entry decides the spelling), with a pty, to `podssh serve`: the server
   keeps a model of the screen (T-161), and sends, in a channel request of podssh's own, the
   difference between the screen that the client last acknowledged and the current one: one
   frame at most each half round trip (20 to 250 ms), after 8 ms of collection.
3. The client applies each frame to its model (T-160), and draws the difference. Keys still go as
   bytes, each one.
4. A frame skips output, which the local scrollback then lacks: the manual says so, and the mode
   is off by default.
5. Mosh as a reference, never a road, where a test host of the operator's has it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test frame_rate
```

With a delay of 300 ms and 64 KiB/s, a flood, then Ctrl-C: the prompt shows within three round
trips, and at the end the client's model equals the server's. A planted server that sends each
byte fails the check of the time.

## Start condition

T-110 is done: `podssh serve` has a pty (the operator holds it, Q32); and T-161 has a model of the
far end's screen.

# T-304: Keys and screen frames as QUIC datagrams on the iroh road

**Source:** T-171 (`docs/design.md:634-648`): each datagram of Mosh is an idempotent difference
from a numbered state, so a lost one costs only itself (its paper, §2.2).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

On the iroh road with UDP, a session is one QUIC stream: a lost packet holds each later byte of
the stream until it comes again. With frames of the screen (T-303), a lost frame need not come
again: the next frame replaces it.

## Premise

- Read: a session on the iroh road is a bidirectional QUIC stream, after a UDP probe
  (`docs/design.md`, section 7; T-162).
- Not verified: whether iroh 1.3 lets its user send QUIC datagrams (RFC 9221).
- Read: the fault harness shapes the TCP stream of the stand-in relay (T-203), where a loss is
  only a delay; no stand-in drops datagrams.
- Read in Mosh's paper (§4), as the section of T-171 gives it (`docs/design.md:664-671`): with 29 %
  loss each way, a mean response of 0.329 s for Mosh and 16.8 s for SSH over TCP. QUIC recovers a
  loss in another way than TCP; not measured.

## Approach

1. A stand-in UDP forwarder on the loopback that drops a seeded share of datagrams (2 %, 10 % and
   29 %), between two iroh endpoints with direct UDP.
2. Measure first: `-tt` with the frames of T-303 over the QUIC stream, and the time from each key
   to its echo. Build only if the p95 at 2 % loss is longer than three round trips.
3. Each frame as one datagram: the numbers of its source and target screens, then the
   difference; the keys as the input since the last acknowledged key; an acknowledgement in each
   datagram. A lost or repeated datagram changes nothing.
4. A frame larger than a datagram goes on the stream, as each other byte of SSH does.
5. The datagrams are inside the iroh connection, whose keys both ends proved (T-163); whether they
   also go through the Noise channel of T-088, or carry a MAC of their own, this entry decides.
6. Only when both ends name it in the layer's features, after the UDP probe.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh --features test-relay --test datagram_frames
```

Through the lossy forwarder at 10 %, each key echoes, the last screens are equal, and the p95 of a
key's echo is below the stream's. A planted receiver that applies a difference to the wrong source
screen fails it.

## Start condition

T-303 is done: frames of the screen exist.

# T-305: Roam at once: a new link beside a silent one

**Source:** T-171 (`docs/design.md:634-648`): Mosh's server follows the newest authentic datagram,
and its client takes a new source port after 10 s with no round trip.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

When the client's address changes, its TCP link through the proxy and the relay often goes silent
with no error. The layer finds the link dead after 30 s with nothing from the far end, and only
then resumes over a new one. For those 30 s, an interactive session shows nothing.

## Premise

- Read: a link with nothing from the far end for 30 s is dead
  (`crates/podssh-relay/src/session/pump.rs:60`; `docs/design.md:762-770`).
- Read: a resume can come while the far end still runs the old link; the old link stops, and the
  new one goes on (`docs/design.md:776-778`). The far end lets the newest resume take a session
  (`docs/design.md:823-825`).
- Measured (T-156): a session on the layer and on the iroh road survives a new address of its
  client (`crates/podssh-cli/tests/m6_exit.rs:262`); the time that the resume took is not in the
  record.
- Read in Mosh (`docs/design.md:634-648`): its client tries a new source port after 10 s with no
  round trip, and its server follows each newer authentic datagram at once.

## Approach

1. Measure first: with the `--move` of the stand-in proxy, the time from the move to "the session
   resumed", on the layer over the reverse road and on the iroh road, 5 runs each.
2. A spare link: when a link has had nothing from the far end for 3 s while bytes wait for their
   acknowledgement, or for two heartbeats, the client opens a new link beside it. When the old
   link's bytes come first, the new link closes before its handshake ends; else the new link's
   resume takes the session, as now. One spare link at a time, and one each 10 s at most.
3. `-v` says each spare link, and which link went on.

## Decision

Taken (2026-10-13), what makes a link silent: the client's hearing of
T-302 (`crates/podssh-relay/src/session/hearing.rs`), across the session's
links. A question of the client, `DATA` that the far end acknowledges
within 200 ms or a `PING`, that waited 3 s with nothing from the far end;
or, where both ends run the heartbeat, nothing at all for 20 s, two of its
intervals. A link with no heartbeat that is idle stays as it is: its quiet
says nothing. The values (3 s, 20 s, one spare each 10 s) are the entry's;
the measurement of item 1 (`crates/podssh-cli/tests/roam_at_once.rs`, the
tests that measure) found a resume 3.0 to 3.2 s after a new address with
them, and they stand.

Taken: a spare link is a link beside the old one, as a move's is
(`crates/podssh-relay/src/session/beside.rs`): the caller gets
`End::Moving`, so it opens a new link with no wait for the old one's end;
the client reads the new link's `GREETING` and sends nothing. When the old
link's bytes come first, the new link closes, and its far end, which waits
for `OPEN`, dials no target. When the new link greets first, the old link
stops with no `RETIRE`, as it carries nothing, and the new link's resume
takes the offsets, as after a loss; the far end lets the newest resume win
(T-270). One watch beside each link serves the move and the spare, so one
new link at a time; a move that fails is not tried again on that link, but
the spare goes on, where the move's watch ended before.

Taken: a spare that takes the session says one line for the loss and one
for the resume, as a resume after a loss does ("the link said nothing for
N s, and a spare link answered; resuming the session"), so a user, and the
check of M6's exit, still see one of each for each loss. `-v` says each
spare link, and each that closes, with why. The alternative, a line of its
own for a spare that takes the session, lost: a loss would then say two
things by the road it took.

Taken: spare links are off in the library's default `Settings`, and on in
podssh's commands; `PODSSH_SPARE_LINKS=no` turns them off, for a link that
the user pays by the byte, for the measurement before the change, and for
the Prove's planted client. On in the library lost: the tests of the layer
count the links that they give, and a host under load can hold an `ACK`
3 s in a transfer of 32 MiB, which would open a spare and take a link of
theirs.

Taken, a limit: the caller of `podssh ssh node://` keeps the operator's leg
of the newest link, and a spare that closes leaves its own leg there, as a
move that fails does. At the next loss, the old leg's close is then not
read; a stopped or expired pair is found by the refusal of the next leg
(401 to 410), and the session still ends with its reason.

Taken at the merge (2026-10-30): the old link's reads wake the watch of a
spare at once (`Hearing::spoke_after`, a count of the reads and a `Notify`),
during the spare's connect too, and when both came the old link goes on.
The draft's look each 250 ms at the instant of the far end's last bytes
lost: a spare that greeted between two looks took a link that had spoken,
and on a paused clock two reads at one instant looked like none.

Taken at the merge, after item 1's measurement: no spare link on the iroh
road (`iroh_settings` of `crates/podssh-cli/src/layered.rs`, for `ssh`,
`pipe` and `chat` over iroh). With no spare link, its QUIC carried the
session across the move with no resume of the layer in 5 runs of 5; with
spare links, 3 runs of 5 resumed the layer, 15.8 to 20.2 s after the move,
as a spare there is a stream of the same connection and comes no sooner
than the old one. Spare links on each road lost: a resume that buys nothing
costs its handshake and the bytes sent again. The race of the two roads
(T-164) keeps them, as its spare races both roads again and the pair's road
can answer where the iroh road is silent; that is not measured.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test roam_at_once -- --ignored
```

After a `--move`, the session resumes within 10 s, where item 1 measured the time before the
change; and a link that stalls for 5 s and recovers keeps the session with no resume. A planted
client with no spare link takes 30 s, and fails.

The planted client is the test run with `PODSSH_SPARE_LINKS=no` in its environment. The same
checks in the library, on a paused clock, with the control of no spare link:
`cargo test -p podssh-relay --test session_spare`. Item 1's measurement:
`cargo test -p podssh-cli --test roam_at_once -- --ignored --test-threads 1 --nocapture measure`;
with `--features iroh-test`, the iroh road's check that a new address opens no spare link.

## Done

2026-10-13, a draft; merged on 2026-10-30, when the main session built it
and ran each check below.

- `crates/podssh-relay/src/session/beside.rs`: the watch beside a link,
  for a move and a spare; `resume.rs` runs it, says its steps as they come
  (`Note::Spare`, `Note::SpareClosed`), stops the old link of a spare with
  no `RETIRE`, and resumes on the spare. `Settings::spare_links`; the
  hearing's `quiet` and `heard_at`, and the mark of its reads with the wait
  for the next ones (`words`, `spoke_after`).
- `crates/podssh-cli/src/layered.rs`: spare links on, but with
  `PODSSH_SPARE_LINKS=no`, and off on the iroh road (`iroh_settings`, the
  Decision); the lines of `-v`. The manual (the note of
  `ssh`, ENVIRONMENT), `docs/design.md` (section 5, with the measurement),
  `docs/cli.md`, `docs/STATUS.md`.
- `crates/podssh-cli/tests/stand_harness/`: the stand-ins of `m6_exit.rs`
  as a harness, with the time of each line after the fault, which
  `tests/silent_notice.rs` of T-302 uses too.
- The merge repaired four things. The draft's spare looked each 250 ms
  whether the old link had spoken, by the instant of the far end's last
  bytes: `session_spare`'s test of a link that speaks again failed, as the
  session ended between two looks, and a spare that greeted between two
  looks would take a link that had spoken. Each read now wakes the wait, by
  a count of the reads that two reads at one instant of a paused clock
  still tell apart, while the spare connects too, and when both came the
  old link goes on (the Decision). The harness pinned relay-a.test to the
  loopback, a pin that since T-318 goes around the proxy and its fault: it
  pins nothing now, and clears the machine's proxy variables, as
  `m6_exit.rs` does. And T-302's run on the harness typed its key at once
  after the start file, which the stand-in proxy reads each 50 ms: once in
  its first two runs the key passed before the pause, and the notice timed
  a later heartbeat (it came at 16 s); `Stand::start_faults` now waits for
  each proxy's word that the clock of its faults runs. And a spare that
  greeted, then failed in its handshake after the old link had stopped,
  said the loss twice, and "the link goes on" of a link that had stopped:
  the next link is now tried at once, with no second loss (`after_stop` of
  `resume.rs`), which a fourth test of `session_spare` holds.
- Prove: `cargo test -p podssh-relay --test session_spare`, 4 passed on a
  paused clock, with the control of no spare link. `cargo test -p
  podssh-cli --test roam_at_once -- --ignored --test-threads 1`, 3 passed:
  the session resumed 3.1 s after the move, and the stall of 5 s kept it
  with no resume. The planted client, `PODSSH_SPARE_LINKS=no` in the run's
  environment: the first check failed, the session resumed 35.1 s after the
  move.
- Item 1, the time from the move to "the session resumed", 5 runs each: on
  the pair's road, with no spare link 35.1, 35.0, 35.1, 35.1 and 35.0 s,
  with one 3.2, 3.2, 3.2, 3.2 and 3.0 s. On the iroh road, with no spare
  link, no resume of the layer in 5 runs of 5, as QUIC carried the session
  across the move; with spare links, 20.2 s, 15.8 s, none, 20.2 s and
  none. So the iroh road opens no spare link (the Decision), and its test
  checks that: `cargo test -p podssh-cli --features iroh-test --test
  roam_at_once -- --ignored on_the_iroh_road`, 3 runs, passed, with no
  resume of the layer; planted, an iroh road with spare links failed it at
  its first run.
- The tests that the change touches: `podssh-relay`'s whole suite, 186
  passed, 0 failed, 2 ignored (`session_move`, `session_resume`,
  `session_end` and `session_newest` among them, and the lib's two of the
  hearing). `podssh-cli`'s whole suite, 990 passed, 0 failed, 39 ignored,
  once the note of `ssh` said "set to no": it wrote
  `PODSSH_SPARE_LINKS=no`, which the check of the notes reads as a keyword
  of `-o`, as at T-302. `cargo test -p podssh-cli --test m6_exit --
  --ignored --test-threads 1`: 7 passed, a new address in 19 s, a stall of
  3 minutes in 198 s and a stopped relay host in 21 s, each with exit 0,
  and the three controls of the forward road with 255. T-302's run on the
  harness, `--test silent_notice -- --ignored`, 3 of 3 passed: the notice
  came 5.9 s after the pause began, and the key's answer at 20.0 s. clippy
  `-D warnings` on `podssh-relay` and `podssh-cli`, and rustfmt, clean.
- Planted: a hearing whose reads wake no wait (`heard` with no
  `notify_waiters`) failed the lib's
  `a_wait_for_the_next_bytes_ends_when_they_come_at_the_same_instant`, and
  passed without it; the draft's look each 250 ms failed
  `a_link_that_speaks_again_first_keeps_the_session_and_the_spare_closes`;
  the draft's steps after a spare's failed handshake failed
  `a_spare_that_greets_and_fails_its_handshake_gives_way_and_the_loss_is_said_once`
  with two losses, and it passed without them.
- Waits for T-251: the run in the build image, and clippy at CI's Rust.

# T-306: A resume deadline that the user sets, for a host that sleeps

**Source:** T-171 (`docs/design.md:634-648`): Mosh's server keeps a session until its client comes
back, with no limit by default (`MOSH_SERVER_NETWORK_TMOUT`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A laptop that sleeps for a night loses each of its sessions on the layer: the far end forgets a
session 10 minutes after its link was lost. A session of Mosh waits.

## Premise

- Read: the deadline is 10 minutes at both ends (`crates/podssh-relay/src/session/resume.rs:44`;
  `docs/design.md:771-781`). T-153's Decision kept a deadline, as a node in a cage would keep
  connections for clients that never come back.
- Read: a node keeps 64 MiB of replay buffers at most, a whole buffer for each session that it
  keeps (`docs/design.md:856-858`); a pair expires after 72 h at most
  (`docs/design.md:825-827`).
- Read: the client measures the deadline with `Instant`
  (`crates/podssh-relay/src/session/resume.rs:329`). Not verified: whether `Instant` counts the
  time that the host slept, on Linux, macOS and Windows. If it does not, a client that wakes
  counts too little, and tries to resume a session that the far end forgot; it then gets
  `REFUSE` with the code 1.
- Read: the features of the layer are names only (`docs/design.md:687`, the section of T-151), so a
  limit needs a new feature or a new record.

## Approach

1. The far end's limit: a flag of `podssh node` (this entry decides the spelling), 10 minutes by
   default, the pair's expiry at most. The far end tells the client its limit, in a way that this
   entry decides; a side that does not know the way keeps 10 minutes.
2. The client asks for no more than the far end's limit; a flag of its own can only shorten it.
3. The node's bound on memory stays: a session kept longer keeps its buffer longer, and a session
   past the bound is refused, as now (`REFUSE` with the code 6).
4. After a `REFUSE` with the code 1, the client says that the far end forgot the session, and how
   long the client was away by the wall clock.

## Decision

Taken (2026-10-13), the way the far end tells its limit: one more feature
name in its `GREETING`, `deadline.SECONDS`, which only a far end gives. A
side ignores each name that it does not know, so an older client keeps 10
minutes, and an older far end names none, so a new client keeps 10 minutes
too. The alternatives lost: a new record after `ACCEPT`, which an older
client refuses at its type byte
(`crates/podssh-relay/src/session/decode.rs:85`), and which so needs a
feature to gate it as well; a field after the body of `ACCEPT`, which an
older decoder refuses as bytes after the end of a body
(`crates/podssh-relay/src/session/decode.rs:234-240`). A name for each value
is not a feature that both sides name, so `deadline::of` reads the far
end's own names, not the common ones.

Taken: the spelling `--resume-deadline TIME`, on `podssh node` for the far
end, and on `podssh ssh` and `podssh operator` for the client's own, which
only shortens the far end's. TIME is a whole number, then `s`, `m`, `h` or
`d` (none is seconds), from 1 minute (a silent link is found dead after
30 s) to 72 h, the longest life of a pair, at whose expiry the relay ends
each of its sessions; the iroh road, with no pair, has the same bound, for
the node's memory. `--keep-for` and `--linger` lost: they do not say what
is kept, nor that the client's flag is the same time. An `-o` keyword lost:
OpenSSH has none, and a node has no `-o`. A variable alone lost: the entry
asks for a flag. `--plain` and `--temporary` refuse it (64): a plain node
keeps no session, and the temporary node keeps the defaults of `ssh
--upgrade`.

Taken: the two deadlines are set for the process (`layered::settings`), as
the pins of `--relay-addr` and the rate of `cp --limit` are, since one
process runs one command. Passing them through each function that carries a
session lost: five signatures on two roads, each touched for one value.

Taken: the client counts its wait on the monotonic clock, as before, and
the wall clock only says how long it was away. Rust's `Instant` does not say
whether a sleep counts (`rust-lang/rust:library/std/src/time.rs`, lines
56-57 at the toolchain 1.98); it reads `CLOCK_MONOTONIC` on Linux and
`CLOCK_UPTIME_RAW` on macOS, which do not count a sleep, and
`QueryPerformanceCounter` on Windows (lines 114-119 there). The alternative,
to give up by the wall clock, lost: a wall clock set forward by NTP would
end a session that the far end still keeps; a resume after a sleep costs
one link, and its refusal now says why. Each far end names its deadline, 10
minutes too, so `-v` says it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_deadline
```

On a paused clock: with a limit of 3 h, a session resumes after 2 h, and is refused after 4 h with
the line of item 4. A planted far end that ignores its limit fails the first check.

The planted defects: `Keeper::idle` that keeps a lost session
`RESUME_DEADLINE` in place of its own deadline fails the first check (the
far end forgets the session at 10 minutes, and the resume after 2 h gets
`REFUSE`); `deadline::of` that reads no name fails it too (the client waits
10 minutes); a client that gives the far end's refusal alone, with no words
of item 4, fails the second.

## Correction

Item 3 of the Approach says that a session past the node's bound is refused
with `REFUSE` (6). Read: the far end accepts the handshake, then ends the
session with a `CLOSE` that gives the reason ("this node keeps as many
resumable sessions as its budget allows",
`crates/podssh-relay/src/session/far.rs:220-225`); code 6 is not sent. The
bound and its words stay as they are.

## Done

2026-10-13, a draft; merged on 2026-10-30, when the main session built it
and ran each check below.

- `crates/podssh-relay/src/session/deadline.rs`: the name
  `deadline.SECONDS`, its reading (72 h at most; a name that is not a number
  is ignored), the far end's names, the client's wait, and the words of item
  4. `Settings` has `client_deadline` and `wall_clock`; `Established` has
  `peer_deadline`; the far end's `GREETING` names its deadline; the client
  waits `client_wait`, and after `REFUSE` (1) says that the far end forgot
  the session, how long the far end keeps one, and how long this side was
  away by the wall clock. `Keeper::expire_at`, for a far end whose clock ran
  on.
- `podssh node --resume-deadline TIME`, and the client's own on `ssh` and
  `operator` (`crates/podssh-cli/src/node_flags.rs`, with the key flags
  moved there from `node.rs`, which had 500 lines; `layered.rs`). At the
  merge, `main` held the arguments of `node` in
  `crates/podssh-cli/src/node_args.rs` (T-121), so the field
  `resume_deadline` went there, read in `NodeArgs::from_matches`; and the
  check of the client's own deadline went before the snippets of `podssh
  ssh` (T-187). The
  node's first line says the time; `-v` of a client says the far end's.
- The manual (`notes_pair.rs`, `notes_ssh.rs`, the flag rows),
  `docs/cli.md`, `docs/design.md` (section 5), `docs/reverse.md`,
  `docs/STATUS.md`.
- Prove: `cargo test -p podssh-relay --test session_deadline`: 4 passed
  (3 on a paused clock). The tests that the change touches passed in whole
  suites: `podssh-relay` 181 passed, 0 failed, 2 ignored (`session_resume`,
  `session_move`, `session_handshake` and `session_heartbeat` among them),
  and `podssh-cli` 988 passed, 0 failed, 35 ignored (`node`, `node_plain`,
  `roost` and the lib's `layered` among them). clippy `-D warnings` and
  rustfmt clean.
- The planted defects, each run: `Keeper::idle` with `RESUME_DEADLINE` in
  place of its own failed `a_far_end_that_keeps_3_h_lets_its_client_resume_after_2_h`;
  `deadline::of` that reads no name failed it, and the three others; the
  refusal alone, with no words of item 4, failed
  `a_client_whose_clock_stood_still_is_refused_and_says_how_long_it_was_away`.
  Each passed again without its plant.
- Waits for T-251: the run in the build image, clippy at CI's Rust, and a
  node with `8h` on the live relay through a client whose host sleeps.

# T-307: A notice of silence on the forward road

**Source:** T-302's Decision: the notice of a silent far end runs on the roads of the resumable
layer only.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

On the forward road (`podssh ssh HOST` through the relay, or `--direct`), a link that goes silent
shows nothing until the WebSocket's checks find it dead, 30 to 40 s later, and the session ends.
A user cannot tell a slow program from a dead link there either, and the notice of T-302 does not
show on that road.

## Premise

- Read: the relay's session pings each 10 s, and a link with no frame for three intervals is dead
  (`crates/podssh-ws/src/client.rs:27-32`); the relay stream of the SSH client runs that check
  (`crates/podssh-ssh/src/relay_stream.rs:228`).
- Read: on that road nothing below SSH answers a key: the relay copies the bytes to the target's
  TCP connection. A Ping of podssh's, which the relay answers with a Pong, is the one question
  that the road asks.
- Read: the notice takes any road's word on the far end's silence (`Silence::attach`,
  `crates/podssh-ssh/src/notice/mod.rs`), and shows it in the window's title (T-302).
- Not measured: how soon the relay's Pong comes, and how often the relay's own keepalive comes
  (25 s, read in the relay's document).

## Approach

1. Measure first, with the stand-in relay's `pause:AFTER:FOR` on the forward road: the time from
   a pause to the WebSocket's end, with and without `ServerAliveInterval`.
2. The relay stream tells the silence: the time of the last frame from the relay, and a Ping of
   podssh's that waits for its Pong, as a question; with `ServerAliveInterval`, SSH's keepalive,
   which asks for a reply, as a question too. `--direct` has SSH's keepalive alone.
3. The forward road attaches it to the session's `Options::silence`; the notice and its places
   are T-302's.

## Decision

2026-10-30. The question on the forward road through the relay is a
WebSocket Ping of podssh's, sent after SSH's bytes up while no question
waits, so at most one waits at a time, each answered within a round trip;
any frame of the relay answers it, a Pong or the target's bytes, as the
layer counts any byte of the far end (T-302). The alternatives that lost:
SSH's bytes alone as the question, which a program that echoes nothing (a
password's prompt) leaves unanswered, and which the plant below shows as a
false notice; and the relay stream's own pings each 10 s, after which a key
could wait 10 s before its question is asked, past the notice's 5 s. The
`--direct` part of the Approach's item 2 goes to a new entry, T-332: there
the one question below SSH is SSH's own keepalive, which russh asks inside
the encrypted stream, and russh's `Handle::send_ping` (a keepalive that
waits for its reply) makes that one a change of podssh-ssh's session loop,
not of a road.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test silent_notice -- --ignored
```

Through the stand-in relay's forward road with `pause:0:20`, the notice comes, counts up and
goes before the key's answer, and the screen and the title are the ones before the pause. A
planted relay stream that tells no silence fails it.

## Correction

2026-10-30. The stand-in relay's `pause:AFTER:FOR` starts its clock at the
upgrade, before the session is ready, so a key cannot be sure to wait in
it. The test holds the bytes in the client's stand-in proxy instead
(`fake-proxy.py --pause 0:20`), whose clock starts when the test says so
(`--start-file`), as T-302's test does: the same stall that ends, both
ways, on the same link.

## Done

2026-10-30.

- `crates/podssh-ws/src/session.rs`: the session keeps when its last frame
  of any kind came (`last_heard`), beside the count of frames.
- `crates/podssh-ssh/src/relay_stream.rs`: the status asks with a Ping
  (`ASK`) after SSH's bytes up while no question waits, and tells the
  silence (`RelayStatus::silent`): once a question waited the wait, the
  time since the relay's last frame; any frame answers it.
- `crates/podssh-cli/src/ssh/transport.rs`: the forward road attaches it to
  the session's `Options::silence`, with the layer's wait of 5 s
  (`SILENCE_WAIT`); the notice and its places are T-302's.
- `cargo test -p podssh-ssh --lib relay_stream`: 5 passed, of them the
  relay's silence: a key and its Ping, no second Ping while one waits, the
  silence once the question waited 300 ms, counted from the last frame, a
  Pong that answers it, and the target's bytes that answer the next; and
  the burst of 1 MiB, its bytes in order with one Ping. Planted, no Ping:
  both failed; a question that no frame answers: the silence's test
  failed; each passed again without its plant.
- `cargo test -p podssh-cli --test silent_notice -- --ignored`, through the
  stand-in relay and a proxy that holds each byte both ways: on the
  forward road with a pause of 20 s, the notice came 6.0 s after the pause
  began, counted up, and went before the key's answer at 20.0 s, the
  screen and the title as before the pause (T-302's test, which shares its
  body, came at 5.9 s); with `sink`, which echoes nothing, a key each
  second for 12 s gave no notice; and the measure of item 1: a pause of
  90 s ended a forward session 40.0 s after it began (nothing from the
  relay for 30 s, the pings unanswered), and 12.0 s after with
  `ServerAliveInterval=4` and `ServerAliveCountMax=2` ("the server stopped
  answering keepalives"). Planted, a relay stream that tells no silence:
  the forward notice failed; no Ping with the keys: the test of `sink`
  failed with a notice; each passed again without its plant.
- `docs/terminal.md` ("A notice while the far end is silent"), the manual's
  note of the notice (`podssh man ssh`), `docs/STATUS.md`.
- The four ignored tests together: 4 passed (the notice 6.0 s after the
  pause on each road). `cargo test -p podssh-ws -p podssh-ssh`: 511 passed,
  0 failed, in 42 binaries; the manual's tests 28, and its lib tests 35;
  clippy `-D warnings` on podssh-ws, podssh-ssh and podssh-cli: clean.

# T-332: A notice of silence with `--direct`

**Source:** T-307's Decision (2026-10-30): the forward road's notice runs
through the relay only.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

With `--direct`, a link that goes silent shows nothing until SSH's
keepalives give up (3 times `ServerAliveInterval`, 180 s by default), or the
kernel's TCP gives up. The notice of T-302 and T-307 does not show there.

## Premise

- Read: on the direct road, nothing below SSH answers a key; the bytes are
  SSH's own, end to end, so the only question that the road can ask is one
  of SSH's.
- Read: russh's `Handle::send_ping` sends `keepalive@openssh.com` with a
  reply asked for, and waits for the reply (`vendor/russh/src/client/mod.rs`,
  "Send a keepalive/ping package to the remote peer, and wait for the
  reply/pong"); a server that does not know the request answers with a
  failure, which is a reply too (RFC 4254, section 4).
- Read: the notice takes any road's word on the far end's silence
  (`Silence::attach`, `crates/podssh-ssh/src/notice/mod.rs`).

## Approach

1. In podssh-ssh's session, with a key from the terminal while no question
   waits, a task calls `send_ping` and marks the question; its reply, or
   any byte of a channel, answers it. The silence counts from the server's
   last packet.
2. Attach it on the direct road, where no road below SSH tells the silence;
   through a `-J` hop, on the target's own session (the Decision).

## Decision

2026-10-30.

- **The question goes on the target's own session, through a `-J` hop.**
  The notice names the target, and the keys go to it: a hop that answers
  while the target is silent is still silence for the keys. The question
  on the first hop's connection lost: it would miss a silent target behind
  a live hop, and the target's keepalive goes through the hop anyway.
- **The question is in the session's own loop, not a task.** The pump
  holds `send_ping`'s future beside the channel's messages, so the question
  ends with the session; a task would need a handle of its own, and could
  outlive the session that it asks for.
- **A slot of the session's own, beside the road's** (`Silence::attach_own`).
  A road that tells the silence (the relay, the layer) keeps its word, and
  the session then asks nothing, as the road's question already goes with
  each key. One slot for both lost: the session's question would replace
  the road's word, which also hears the road's own frames.
- **Any reply answers.** A server that knows no `keepalive@openssh.com`
  answers with a failure, which russh resolves as it does a success; the
  server is there. Keys that nothing echoes are then no silence.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test silent_notice -- --ignored
```

With `--direct` through the stand-in proxy's `--pause 0:20`, the notice
comes, counts up and goes before the key's answer; with `sink`, keys that
nothing echoes give no notice. Planted, a key with no `send_ping`: the test
of `sink` fails.

## Done

2026-10-30.

- `crates/podssh-ssh/src/notice/asked.rs`: the server's last word and the
  question that waits (`Asked`): a key asks while none waits, a reply or a
  channel's message answers, and once a question waited 5 s (`WAIT`, the
  layer's and the relay's), the silence counts from the last word.
- `crates/podssh-ssh/src/notice/mod.rs`: the session's own slot
  (`attach_own`) beside the road's (`told_by_road`); the road's word comes
  first.
- `crates/podssh-ssh/src/io.rs` and `io/msg.rs` (the channel's messages,
  moved out to keep the file under 500 lines): with a key, while no
  question waits, `Handle::send_ping`; its reply, or any channel message,
  answers it. `crates/podssh-ssh/src/session.rs` attaches the question
  where no road told the silence.
- `cargo test -p podssh-ssh`: 298 passed, the new test of `Asked` among
  them (its wait, a second key while one waits, the silence from the last
  word, an answer and the next question).
- `cargo test -p podssh-cli --test silent_notice -- --ignored`: 6 passed.
  With `--direct` through a proxy that holds each byte both ways for 20 s
  (`fake-proxy.py --pause 0:20`, the harness's `direct()` to `target.test`),
  the notice came 6.0 s after the pause began ("no word from target.test
  for 8 s", then 9 s) and went before the key's answer at 20.1 s; with
  `sink`, a key each second for 12 s gave no notice. Planted, a key with
  no `send_ping`: the test of `sink` failed with a notice; a session that
  attaches no question of its own: the pause's test failed with none; each
  passed again without its plant.
- Against software that podssh did not write, on this host: OpenSSH 9.6p1
  and Dropbear 2022.83, each on 127.0.0.1 with a throwaway user and key,
  `podssh ssh --direct -t` in a pty. Keys to `stty -echo; cat >/dev/null`,
  one each second for 12 s: no notice from either. Through the stand-in
  proxy's pause of 20 s: the notice came 6.0 s into the pause and went
  before the echo, at 20.1 s (OpenSSH) and 20.0 s (Dropbear). The user,
  the keys and the servers were removed after.
- clippy `-D warnings` on podssh-ssh and podssh-cli, all targets: clean.
- `docs/terminal.md` ("A notice while the far end is silent"), the
  manual's note of the notice (`podssh man ssh`), `docs/STATUS.md`.
- A repair after the close, found in review (2026-10-30): a keepalive
  that still waited for its reply kept the next key from asking, so a
  link that died after the far end's bytes answered one question, and
  before the keepalive's reply, showed no notice again. Each key now marks
  its question, and a keepalive goes only when none waits; the waiting one
  asks the new question too (`Asked::key`). `cargo test -p podssh-ssh --lib
  notice::asked`: 2 passed; planted, the old order of the test, so that a
  waiting keepalive marks no question: the new test failed, and passed
  again without it. The two `--direct` tests of `silent_notice` passed
  again: the notice came 5.9 s into the pause and went before the key's
  answer at 20.1 s; keys that nothing echoes gave none.

# T-335: The iroh cells of the throughput run may not cross a relay

**Source:** the study of stand-ins for the live checks (2026-10-31): the
throughput harness never turns the iroh road's UDP off.
**Category:** defect
**Milestone:** M9
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The cells of the iroh road "through iroh's relay server" may measure a
direct path: with both ends on one host and UDP on, iroh can leave the
relay for a direct path, and the figure in `docs/STATUS.md` is then no
relay's figure.

## Premise

- Read: the iroh road turns UDP off with `PODSSH_IROH_UDP`
  (`crates/podssh-iroh/src/endpoint.rs:74`), and its probe only binds a
  socket (`crates/podssh-iroh/src/probe.rs:11-14`).
- Read: no file of `crates/podssh-cli/tests/throughput_harness/` sets
  `PODSSH_IROH_UDP`.
- Inferred: iroh moves a connection to a direct path when one works.

## Approach

1. The relay cells set `PODSSH_IROH_UDP=off` on both ends.
2. Each cell records the path that iroh used, and a relay cell that went
   direct fails.
3. Run the cells again, and correct the rows of `docs/STATUS.md` that the
   old figures hold.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --features iroh-test --test throughput_live -- --ignored --nocapture
```

Each relay cell reports the relay as its path. Planted: UDP on again in a
relay cell; that cell fails.

## Done

2026-10-31. The iroh cells of the throughput run measure the relay, and
say so:

- The iroh client watches the paths of each connection (iroh's
  `paths_stream`), and notes when a direct path is the one that carries the
  data (`crates/podssh-iroh/src/client.rs`); `Dialer::path` gives "the
  relay carried each byte of the session" or "a direct path carried the
  session", and nothing before a connection. `podssh ssh iroh:TICKET`, and
  the race of a pair's label with the iroh road, say it at the end of the
  session with `-v` (`crates/podssh-cli/src/ssh/iroh/dial.rs`,
  `crates/podssh-cli/src/ssh/iroh/race.rs`); the manual's entry of
  `PODSSH_IROH_UDP` says so too.
- The harness: a cell holds the variables of its runs and a line that each
  run must say (`crates/podssh-cli/tests/throughput_harness/cells.rs`,
  `mod.rs`). The iroh cells set `PODSSH_IROH_UDP=off` at the node and at
  each run, run with `-v`, and a run that does not say that the relay
  carried each byte gives no figure: the table gives the reason.
- Here, a Claude Code cloud container (Linux, the debug build): the
  loopback cells at 20 MiB a run (`cargo test -p podssh-cli --features
  iroh-test --test throughput_live -- --ignored --nocapture
  throughput_on_the_loopback`, 110 s): the iroh cell 4.2 MiB/s up and
  2.8 MiB/s down at the p50, each run said that the relay carried each
  byte; the table of `docs/STATUS.md` is replaced, and its old iroh row
  (34.6 MiB/s up) is named as most likely a direct path's. Planted: UDP on
  (`probe`) at both ends of the cell: its first run said "a direct path
  carried the session", and the cell gave no figure.
- Through n0's relay `use1-1` (`PODSSH_THROUGHPUT_IROH_RELAY=https://use1-1.relay.n0.iroh.link.`,
  the same command with `throughput_on_each_road`, 442 s with the other
  cells): 1.08 MiB/s up and 1.10 MiB/s down, alike in each run, and each
  run said that the relay carried each byte. Inferred: the flat figure is
  n0's limit for each connection (Read:
  <https://docs.iroh.computer/relays/rate-limiting>). The same run gave the
  reverse road through the live relay, with the layer, 2.37 MiB/s up and
  1.37 MiB/s down at the p50; both rows are in `docs/STATUS.md`.

# T-354: A session that closes while it moves can say a loss that was none

**Source:** CI's macOS job at `08275ee`, 2026-10-31 (run 41158346607):
`a_session_moves_while_both_ends_send_at_full_speed`
(`crates/podssh-relay/tests/session_move.rs:188-195`) failed once.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A session whose application ends while the layer moves it at full speed can
say a loss ("the link ended before the far end answered this side's CLOSE"),
then open a new link only to learn that the far end had ended the session.
The session ends well, but `-v` shows a loss that was none, the exit waits
for a new link, and the test that asks for no loss fails at random.

## Premise

- Measured: in the macOS job of CI at `08275ee` (run 41158346607), the
  test's notes held one loss, `Lost { why: "the link ended before the far end
  answered this side's CLOSE" }`, and no `Resumed`; the outcome and both
  digests held (`crates/podssh-relay/tests/session_move.rs:168-170`), and the
  assertion that failed is `:193`. The commit changed only `TODO/issues.md`.
- Not reproduced here: 40 runs of the test alone, and 80 runs eight at a
  time, passed (a Claude Code cloud container, 2026-10-31).
- Read: `End::Closing` comes from the pump's wait for the answer to its
  `CLOSE` (`crates/podssh-relay/src/session/pump.rs:292-299`): a reader that
  ended with anything but the peer's `CLOSE`, the 10 s of `LINGER` (not
  reached in a run of 2.9 s), or a stop. A loss with no `Resumed` after it is
  a resume that found the session forgotten while this side's application
  had ended (`crates/podssh-relay/src/session/resume.rs:359`): the far end
  had the `CLOSE` and ended the session, and this side's reader ended before
  its answer.
- Inferred: both ends closed at once (the test's target ends as the
  client's application does), and the far end's answer met a reader that
  had already ended, or the stop of a move.

## Approach

1. Reproduce: the test in a loop with the far end's answer delayed, or on
   paused time, to find which branch ends the wait.
2. Repair that branch: a reader that ended with the peer's own `CLOSE`
   before this side's (both closing at once) is the session's end, not a
   loss; a move does not cut a `CLOSE` in flight.
3. A test that closes both ends at once, with a move beside, many times.

## Decision

1. **A far end's last record on a link waits for the client**: `last_word`
   (`crates/podssh-relay/src/session/far.rs:156-173`) writes the record, then
   keeps the link, reading and dropping what the client sends, until the
   client ends it or 10 s pass (the wait of a `CLOSE` for its answer). It
   ends the four places: the `REFUSE` of the handshake, the `CLOSE` of a
   session that cannot start, the `CLOSE` of a resumed link whose session
   ended, and the `REFUSE` of an offset no longer kept. No shut of the write
   side first: a stand-in that ends at the first end of either way would
   then end before the client's next write, and the cut comes back. Lost:
   a shorter wait (1 s), which a slow path to the client could outlast; a
   wait in the relay's own close, which podssh cannot change.
2. **A loss after this side's `CLOSE` is said only when the resume goes
   on** (`crates/podssh-relay/src/session/resume.rs:271-277`, `:307-411`): the
   line "the link ended before the far end answered this side's CLOSE;
   resuming the session" waits, and comes before the next step said (a
   retry, the resume, the end that the resume gave up at), or once the
   resume takes longer than 3 s (`LOSS_GRACE`, the wait of a spare link). A
   far end that forgot the session had the `CLOSE`: nothing is said, and the
   session ends `LocalEnd`. Lost: saying it at once, as before, which is a
   line on each end whose answer a relay drops; never saying it, which hides
   a resume that waits.
3. **A handshake whose write fails reads what came before**
   (`crates/podssh-relay/src/session/client.rs:286-314`), 2 s at most, as the
   pump reads a link whose writes fail: a `REFUSE` there is the answer, else
   the write's failure is. Redundant with item 1 at podssh's own far end,
   and the answer from a far end or a relay that closes right after its
   last record.
4. Not done: the client's own `REFUSE` of a resume whose offset it no
   longer keeps (`resume.rs`, `resend`) is still sent and dropped; it ends a
   session that cannot go on, the far end's pump reads it after a failed
   write as each record, and the far end's deadline ends the rest.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_move
```

200 runs of `a_session_moves_while_both_ends_send_at_full_speed` with no loss
said; a planted race fails the new test.

## Correction

The reproduction found the cause on the far end's side, in three places of
one kind, and the client's word for it in a fourth. Debug lines in the close
paths, 40 runs of the test on one CPU (a Claude Code cloud container,
2026-10-31): in one run the far end accepted a resume on a move's new link,
then found the session ended on the old link (`NotTaken::Ended`,
`crates/podssh-relay/src/session/keep.rs:201-204`), wrote its `CLOSE` there and
dropped the link at once. The client's pump wrote on that link (the `DATA`
of a resume, its own `CLOSE`), and the stand-in relay, which ends both ways
when one way ends or fails as the relay ends a session, failed that write and
dropped the far end's `CLOSE` still on its way. The client then saw a link
end with no answer (`End::Closing`), said a loss, and learned on one more
link that the far end had ended the session. A new test of both ends closing
at once while the session moves each 16 KiB, 50 sessions a run, failed once
in 10 runs on one CPU on the code before, by the same kind of cut in the
handshake: the far end refused a resume at its `OPEN` and dropped the link
(`crates/podssh-relay/src/session/far.rs:135-139`) while the client wrote its
`PROOF`, so the client got a broken pipe in place of the refusal, said a
move's failure and a loss, and tried again. The same pattern is in
`Accepted::close`, whose reason the client would lose for "the far end did
not resume the session" (`crates/podssh-relay/src/session/far.rs:262-270`).
Approach item 2 is done as the Decision says.

## Done

2026-10-31. A session whose ends close at once while it moves says no loss:

- The far end's last record on a link waits for the client (Decision 1);
  the client says a loss after its `CLOSE` only when the resume goes on or
  waits (Decision 2); a handshake whose write fails reads the `REFUSE` before
  it (Decision 3). `docs/design.md` (the end of a session) says so.
- Tests, each against a stand-in relay that ends both ways when one fails:
  `crates/podssh-relay/tests/session_end.rs`,
  `a_close_whose_answer_its_link_lost_ends_with_no_loss_said` (the far end
  had the `CLOSE` and forgot the session; no note); the new
  `crates/podssh-relay/tests/session_last_word.rs`, 4 tests: a resumed
  link's `CLOSE` slower than the client's next write, the handshake's
  `REFUSE` at the `OPEN` while the `PROOF` is on its way, a `REFUSE` before a
  failed write read, and a new session's reason "no target here" while the
  client's application writes; `crates/podssh-relay/tests/session_move.rs`,
  `both_ends_close_at_once_while_the_session_moves` (50 sessions, both ends
  closing at once, a move each 16 KiB, no note but moves). `cargo test -p
  podssh-relay --test session_end --test session_last_word --test
  session_move`: 11 passed.
- Planted, each failed its test in 3 runs of 3: the loss said at once; the
  handshake's `REFUSE` sent and dropped; no read after a failed write; a new
  session's reason sent and dropped; a resumed link's `CLOSE` sent and
  dropped.
- The Prove: 200 runs of `a_session_moves_while_both_ends_send_at_full_speed`
  (100 on one CPU with `taskset -c 0`, 100 on four), none failed; 30 runs of
  the new test on one CPU, 1500 sessions, none failed, where the code before
  failed 1 run in 10. `cargo test -p podssh-relay`: 220 passed; with
  `--all-features`: 340 passed.
