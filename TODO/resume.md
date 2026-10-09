The resumable layer of milestone M6, with which a session between two podssh
ends survives a drop: the handshake and the offsets, the replay buffer, the
resume, the heartbeats, the move before the relay's limits, the exit
measurement and the throughput method. Then the session features that build
on the layer, which wait in the backlog.

# T-151: The resumable layer: its handshake and the byte offsets

**Source:** ROADMAP M6 (the resumable stream layer); `docs/design.md:220-237`
(layer 2, decided); GitHub #19 (Nemo-010, 2026-10-08: the quic-ssh, ssh-obi
and fux reports) and GitHub #20 (a handshake with a version and a role).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

A dropped link to the relay ends the session with exit 255, and a new client
address loses it (`docs/design.md:194-206`). The relay keeps nothing across a
new connection (`docs/design.md:208-211`).

## Premise

Read: the design is decided: offsets and acknowledgements in each direction,
a session id and a 256-bit resume secret, under SSH (`docs/design.md:220-237`),
in a `session` module of `podssh-relay` (`docs/design.md:123-132`), a crate
with no C. Measured: `grep -ril resum crates` finds only the IRC client.
Today russh's bytes go through a pipe to the relay session
(`crates/podssh-ssh/src/relay_stream.rs:102-181`). Frame boundaries mean nothing
on the relay (`docs/relay.md:65-68`), and the relay reads each record and can
drop or add frames (`SECURITY.md:33-36`).

## Approach

1. A sans-IO codec (`docs/architecture.md:94-98`) in a new module
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
   `RelayStatus` (`crates/podssh-ssh/src/relay_stream.rs:58-100`). Docs: the
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
(`crates/podssh-ssh/src/relay_stream.rs:58-100`), whose far end is the
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
`docs/design.md:222-224`; GitHub #19 (Nemo-010, 2026-10-08: quic-ssh's bounded
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
"with backpressure when it is full" (`docs/design.md:223-224`). So no byte
that is not acknowledged is dropped, and a resume is byte-exact; the start in
an escape sequence of GitHub #31 needs dropped bytes (T-221). The reverse road
drops a frame and closes with `1011 relay backpressure` above 1 MiB queued
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`); the buffer
turns that close into a resume. The SSH window is 512 KiB for each channel
(`crates/podssh-ssh/src/run.rs:25-29`). Do not bring back the backpressure module of
`podssh-transport`, which T-074 removed (`docs/design.md:139-140`).

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

Byte replay or screen state: byte replay is decided (`docs/design.md:220-221`,
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
(`docs/reverse.md:24-27`). With each session's 4 MiB kept, a node can hold
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
`docs/design.md:226-228`; GitHub #19 (Nemo-010, 2026-10-08: ssh-obi's policy,
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
(`crates/podssh-relay/src/open.rs:177-212`). `classify` maps each reverse close
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
   (`crates/podssh-relay/src/open.rs:27-29`), with `open::backoff` between
   rounds (`crates/podssh-relay/src/open.rs:262-276`). Do not fork it (T-077).
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
   (`crates/podssh-cli/src/man/facts.rs:152-272`).
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
registration still exits on `409` (`docs/reverse.md:19`). The alternative, an
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

# T-263: A node in plain mode, for a client with no resumable layer

**Source:** the operator's ruling of 2026-10-09 (Q34, `docs/decisions.md`),
after T-153.
**Category:** feature
**Milestone:** M6
**Priority:** P3
**Effort:** S
**Status:** open

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

# T-154: Heartbeats that also prevent the relay's idle cut

**Source:** ROADMAP M6 (heartbeats); `docs/design.md:229-230`; GitHub #19
(Nemo-010, 2026-10-08: ssh-obi pings each 15 s and wants a pong in 45 s).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay cuts a connection after 180 s with no payload, and its empty
keepalive frames do not count (`docs/relay.md:72-73`, `docs/relay.md:125`). A
reverse socket gets no keepalive at all (`docs/reverse.md:28-36`). SSH's own
keepalives must not end a session that the layer would resume.

## Premise

Read: a read waits 90 s at most (`crates/podssh-ws/src/client.rs:23-25`, set at
`crates/podssh-relay/src/open.rs:231`), a limit that counts on the relay's
frame each 25 s. The ping watcher acts only after a first Pong
(`crates/podssh-ws/src/session.rs:140-174`); Pongs and the idle cut on reverse
sockets are not measured (T-061). russh sends a keepalive each 60 s and ends
the session after 3 with no answer (`crates/podssh-ssh/src/options.rs:227-247`).
Measured on `3ee70dc`, offline (`PODSSH_OFFLINE=1`, a `.invalid` host):
`-o ServerAliveInterval=0` prints the warning of
`crates/podssh-cli/src/ssh/resolve.rs:306-320`, and `podssh ssh` exits 255.

## Approach

1. Each end sends a `PING` record when it sent nothing for 10 s, and the peer
   answers `PONG`. A record is payload, so it resets the relay's idle cut on
   each road.
2. Any record counts as life, as for the ping watcher
   (`crates/podssh-ws/src/session.rs:140-149`). After 3 silent intervals the
   link is dead, and T-153 resumes: 30 to 40 s. Both ends send, so the read
   limit of 90 s also holds on reverse sockets.
3. Carry the `ACK` of T-152 in each `PONG`. The cost is about 20 bytes each
   way each 10 s: under 0.2 MiB in 12 h.
4. On the resumable road, do not print the warning of
   `crates/podssh-cli/src/ssh/resolve.rs:306-320`.
5. In the same commit: "Liveness" and "Idle limit" in the manual
   (`crates/podssh-cli/src/man/facts.rs:199-214`,
   `crates/podssh-cli/src/man/facts.rs:238-247`), the note at
   `crates/podssh-cli/src/man/notes.rs:71`, `docs/relay.md`, `README.md`.

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
`docs/design.md:231-232`; the report of sandbox A, 2026-10-08 (the `1009`
close at the volume cap).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay ends a WebSocket session after 64 MiB, both directions together, or
after 12 h (`docs/relay.md:126-127`). A long or large session on the layer
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
   users see") and the manual (`crates/podssh-cli/src/man/facts.rs:152-272`).

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

**Source:** ROADMAP M6, exit criteria; `docs/design.md:253-255` (the harness
must grow for layer 2).
**Category:** measurement
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

M6 is done when a session survives three faults, on the resumable layer and
on the iroh road: a stopped relay host, a change of the client's address, and
a stall of 3 minutes. Today each of these faults ends the session.

## Premise

Measured in the gate (`docs/STATUS.md`, "Faults between podssh and the relay,
measured"): a relay that stalls is declared dead at 50 s, and a relay host
killed in a session gives exit 255 (`scripts/interop-faults.sh:150-168`).
These checks stay, for the forward road, which has no resumption. Read: the
stand-in relay serves the forward path only (`scripts/fake-relay.py:113-125`),
and its `stall` mode never ends (`scripts/fake-relay.py:265-268`). The
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

## Prove

```sh
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The fault step of the gate prints `ok` for six new checks (three faults on two
roads) and for the controls on the forward road; the controls show that the
checks fail for a session that does not resume. The run in the box shows a
live session that survives a stall of 3 minutes.

# T-157: Throughput on each road and relay, by a committed method

**Source:** ROADMAP M6 (throughput on each road and relay, in and out of a
sandbox, before a default depends on it); `docs/design.md:562-582`; the two
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
(`docs/design.md:562-582`). A session carries 64 MiB at most, both directions
together (`docs/relay.md:127`).

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
   needs a token (`docs/relay.md:177-178`, `docs/relay.md:286-292`). Skip a
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
**Status:** open

## Problem

A user cannot leave a shell running and come back to it later, from a new
podssh process or from another host. tmux does this on a server that has
tmux; a cage usually has none.

## Premise

Inferred from the design: the layer runs under SSH (`docs/design.md:220-221`),
so the keys and the sequence numbers of the SSH connection live in the client
process. A new process cannot continue that byte stream, so an attach is a
new SSH login to a far end that kept the shell (T-159). Read: podssh knows
the escapes `~.`, `~R`, `~?` and `~~`, and another character after `~` goes
to the server with the `~` (`crates/podssh-ssh/src/escape.rs:1-5`,
`crates/podssh-ssh/src/escape.rs:28-70`). The flag table has 469 lines, near
the limit of 500 (the table of `ssh`: `crates/podssh-cli/src/flags.rs:112-241`).

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
   (`crates/podssh-ssh/src/escape.rs:72-80`) and to the manual.
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

# T-160: Local echo and prediction for high latency

**Source:** `docs/design.md:250-251`; GitHub #19 and GitHub #18 (Nemo-010,
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
(`docs/design.md:250-251`). podssh passes the bytes of a remote pty unchanged
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

Read: the resumable layer replays bytes, as decided (`docs/design.md:220-237`).
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

# T-221: Replayed output after dropped bytes starts at a boundary of the terminal grammar (GitHub #31)

**Source:** GitHub #31 (2026-10-08: a rule for where a kept window may start),
with the coordinator's reading of 2026-10-08, checked here against
`docs/design.md:222-228`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

An escape sequence of a terminal has several bytes. When a ring of output
drops its oldest bytes, the kept window can start inside a sequence or inside
a UTF-8 character. A client that attaches then gets the end of a sequence as
text: a full-screen program draws wrongly, or a part of a title sequence shows
on the command line.

## Premise

Read: the layer keeps each byte that is not acknowledged, "with backpressure
when it is full" (`docs/design.md:223-224`), and a resume sends again from the
other side's offset (`docs/design.md:226-228`). Thus a resume in the buffer
is byte-exact, and it cannot start in the middle of a sequence; T-152 tests
that invariant. Bytes are dropped only where a client attaches after output
that it never received: T-158, T-159 and T-161. The report puts the tracker
in `podssh-transport`; it cannot work there. The layer runs under SSH and
sees only ciphertext (`docs/design.md:220-221`), and the transport crates do
not know the protocol that they carry (`docs/architecture.md:99-101`). The
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
