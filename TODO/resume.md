The resumable layer of milestone M6, with which a session between two podssh
ends survives a drop: the handshake and the offsets, the replay buffer, the
resume, the heartbeats, the move before the relay's limits, the exit
measurement and the throughput method. Then the session features that build
on the layer, which wait in the backlog.

# T-151: The resumable layer: its handshake and the byte offsets

**Source:** ROADMAP M6 (the resumable stream layer); `docs/design.md:203-220`
(layer 2, decided); GitHub #19 (Nemo-010, 2026-10-08: the quic-ssh, ssh-obi
and fux reports) and GitHub #20 (a handshake with a version and a role).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

A dropped link to the relay ends the session with exit 255, and a new client
address loses it (`docs/design.md:177-189`). The relay keeps nothing across a
new connection (`docs/design.md:191-194`).

## Premise

Read: the design is decided: offsets and acknowledgements in each direction,
a session id and a 256-bit resume secret, under SSH (`docs/design.md:203-220`),
in a `session` module of `podssh-relay` (`docs/design.md:106-115`), a crate
with no C. Measured: `grep -ril resum crates` finds only the IRC client.
Today russh's bytes go through a pipe to the relay session
(`crates/podssh-ssh/src/relay_stream.rs:73-150`). Frame boundaries mean nothing
on the relay (`docs/relay.md:58-61`), and the relay reads each record and can
drop or add frames (`SECURITY.md:23-26`).

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
   `RelayStatus` (`crates/podssh-ssh/src/relay_stream.rs:55-71`). Docs: the
   records and the threat model in `docs/design.md` section 5,
   `docs/architecture.md`, the map of `AGENTS.md`, and `docs/STATUS.md`.

## Decision

Recommendation: an X25519 exchange gives the secret, and HMAC over fresh
nonces of both ends proves it. No secret and no reusable proof cross the
relay, so a passive reader of its logs cannot take the session; an active
relay can still break it, as today. The alternative, a secret sent in
`ACCEPT`, lost: the relay terminates TLS, so its logs would hold the secret.

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

# T-152: The replay buffer, limited, with backpressure

**Source:** ROADMAP M6 (a limited replay buffer with backpressure);
`docs/design.md:205-207`; GitHub #19 (Nemo-010, 2026-10-08: quic-ssh's bounded
buffer with a start offset; ssh-obi's duplicate recent bytes); GitHub #31.
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A resume can send again only the bytes that the sender still holds. A buffer
with no limit fills the memory of a small host when the peer is slow.

## Premise

Read: the sender keeps each byte that is not acknowledged, in 4 to 16 MiB,
"with backpressure when it is full" (`docs/design.md:206-207`). So no byte
that is not acknowledged is dropped, and a resume is byte-exact; the start in
an escape sequence of GitHub #31 needs dropped bytes (T-221). The reverse road
drops a frame and closes with `1011 relay backpressure` above 1 MiB queued
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`); the buffer
turns that close into a resume. The SSH window is 512 KiB for each channel
(`crates/podssh-ssh/src/run.rs:25-29`). Do not reuse the backpressure module of
`podssh-transport`, which the design removes (T-074, `docs/design.md:122-123`).

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

Byte replay or screen state: byte replay is decided (`docs/design.md:203-204`,
the model of Eternal Terminal), and the layer sees only SSH ciphertext. Screen
state matters only when a new client attaches to a kept shell (T-161).

Recommendation: 4 MiB by default. The relay holds at most 1 MiB for a slow
receiver and the SSH window is 512 KiB, so 4 MiB keeps the bytes of a lost
link. A node with 16 sessions (`crates/podssh-transport/src/control.rs:111-120`)
then holds 64 MiB at most. The alternative, 16 MiB, lost: four times the
memory in a cage, for no measured gain.

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

# T-153: Resume through any road and relay host, with a session secret and a capped backoff

**Source:** ROADMAP M6 (reconnection through each relay host);
`docs/design.md:209-211`; GitHub #19 (Nemo-010, 2026-10-08: ssh-obi's policy,
talaria0101's drops); GitHub #17 and #25 (a retry by the close reason).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

After a loss, the client must find its session again through any road and
relay host. A retry that ignores the close reason is wrong: one of 180
sessions dropped with `1011`, and some drops repeat on one target, as
GitHub #19 reports. Some closes mean "do not come back".

## Premise

Read: the failover across relay hosts serves the first connection only
(`crates/podssh-relay/src/open.rs:172-211`). `classify` maps each reverse close
to a retry class (`crates/podssh-transport/src/closes.rs:154-229`), with
`relay backpressure` as `Retry::Never`
(`crates/podssh-transport/src/closes.rs:202`); a received Close lost its code
until T-072 (repaired 2026-10-09). Read, not measured: `/v1/node` and `/v1/connect` are on the
control host only (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:23-24`).
A second node socket for one name gets `409`
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:152-153`), and
the node then exits (`docs/reverse.md:19`).

## Approach

1. The client drives the resume. On a loss with no `CLOSE` record, it tries
   the roads of T-164 and each host of the `RelayList`
   (`crates/podssh-relay/src/relay.rs:36-50`), each within `HOST_DEADLINE`
   (`crates/podssh-relay/src/open.rs:27-29`), with `open::backoff` between
   rounds (`crates/podssh-relay/src/open.rs:261-275`). Do not fork it (T-077).
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
   (`crates/podssh-cli/src/man/facts.rs:102-192`).

## Decision

Recommendation: a resume deadline of 10 minutes at both ends: the M6 exit
asks for a stall of 3 minutes, and the backoff adds up to 45 s. The
alternative, no deadline, lost: a node in a cage would keep connections for
clients that never come back.

Recommendation: after a loss, a node retries `409` with the backoff until the
deadline, because the relay can still hold its old socket; a first
registration still exits on `409` (`docs/reverse.md:19`). The alternative, an
exit on each `409`, lost: a new node address would end each session. The
operator confirms this change of `docs/reverse.md`.

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

# T-154: Heartbeats that also prevent the relay's idle cut

**Source:** ROADMAP M6 (heartbeats); `docs/design.md:212-213`; GitHub #19
(Nemo-010, 2026-10-08: ssh-obi pings each 15 s and wants a pong in 45 s).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The relay cuts a connection after 180 s with no payload, and its empty
keepalive frames do not count (`docs/relay.md:65-66`, `docs/relay.md:118`). A
reverse socket gets no keepalive at all (`docs/reverse.md:24-29`). SSH's own
keepalives must not end a session that the layer would resume.

## Premise

Read: a read waits 90 s at most (`crates/podssh-ws/src/client.rs:23-25`, set at
`crates/podssh-relay/src/open.rs:230`), a limit that counts on the relay's
frame each 25 s. The ping watcher acts only after a first Pong
(`crates/podssh-ws/src/session.rs:146-180`); Pongs and the idle cut on reverse
sockets are not measured (T-061). russh sends a keepalive each 60 s and ends
the session after 3 with no answer (`crates/podssh-ssh/src/options.rs:220-240`).
Measured on `3ee70dc`, offline (`PODSSH_OFFLINE=1`, a `.invalid` host):
`-o ServerAliveInterval=0` prints the warning of
`crates/podssh-cli/src/ssh/resolve.rs:253-259`, and `podssh ssh` exits 255.

## Approach

1. Each end sends a `PING` record when it sent nothing for 10 s, and the peer
   answers `PONG`. A record is payload, so it resets the relay's idle cut on
   each road.
2. Any record counts as life, as for the ping watcher
   (`crates/podssh-ws/src/session.rs:146-155`). After 3 silent intervals the
   link is dead, and T-153 resumes: 30 to 40 s. Both ends send, so the read
   limit of 90 s also holds on reverse sockets.
3. Carry the `ACK` of T-152 in each `PONG`. The cost is about 20 bytes each
   way each 10 s: under 0.2 MiB in 12 h.
4. On the resumable road, do not print the warning of
   `crates/podssh-cli/src/ssh/resolve.rs:253-259`.
5. In the same commit: "Liveness" and "Idle limit" in the manual
   (`crates/podssh-cli/src/man/facts.rs:149-159`,
   `crates/podssh-cli/src/man/facts.rs:183-190`), the note at
   `crates/podssh-cli/src/man/notes.rs:46`, `docs/relay.md`, `README.md`.

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

# T-155: Move a session to a new relay connection before the relay's limits

**Source:** ROADMAP M6 (a new session before the relay's limits);
`docs/design.md:214-215`; the report of sandbox A, 2026-10-08 (the `1009`
close at the volume cap).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The relay ends a WebSocket session after 64 MiB, both directions together, or
after 12 h (`docs/relay.md:119-120`). A long or large session on the layer
meets these limits, and an end at a limit costs a resume and its delay.

## Premise

Read: the reverse road has the same cap, `1009 session byte cap`, "Open a new
session" (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:183`),
which `classify` maps to `Retry::NewSession`
(`crates/podssh-transport/src/closes.rs:203-205`), and a session lives 720
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
   users see") and the manual (`crates/podssh-cli/src/man/facts.rs:102-192`).

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

# T-156: M6 exit: a session survives a stopped relay host, a new address and a stall of 3 minutes

**Source:** ROADMAP M6, exit criteria; `docs/design.md:236-238` (the harness
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
killed in a session gives exit 255 (`scripts/interop-faults.sh:144-162`).
These checks stay, for the forward road, which has no resumption. Read: the
stand-in relay serves the forward path only (`scripts/fake-relay.py:98-110`),
and its `stall` mode never ends (`scripts/fake-relay.py:147-150`). The
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
sandbox, before a default depends on it); `docs/design.md:319-339`; the two
sandbox reports of 2026-10-08; GitHub #18 (warren's method) and GitHub #23
(sshping: throughput up and down).
**Category:** measurement
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

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
(`docs/design.md:319-339`). A session carries 64 MiB at most, both directions
together (`docs/relay.md:120`).

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
   needs a token (`docs/relay.md:145-146`, `docs/relay.md:234-240`). Skip a
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

Inferred from the design: the layer runs under SSH (`docs/design.md:203-204`),
so the keys and the sequence numbers of the SSH connection live in the client
process. A new process cannot continue that byte stream, so an attach is a
new SSH login to a far end that kept the shell (T-159). Read: podssh knows
the escapes `~.`, `~R`, `~?` and `~~`, and another character after `~` goes
to the server with the `~` (`crates/podssh-ssh/src/escape.rs:1-5`,
`crates/podssh-ssh/src/escape.rs:28-70`). The flag table has 469 lines, near
the limit of 500 (the table of `ssh`: `crates/podssh-cli/src/flags.rs:112-233`).

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

**Source:** `docs/design.md:233-234`; GitHub #19 and GitHub #18 (Nemo-010,
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
(`docs/design.md:233-234`). podssh passes the bytes of a remote pty unchanged
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

Read: the resumable layer replays bytes, as decided (`docs/design.md:203-220`).
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
`docs/design.md:205-211`.
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
when it is full" (`docs/design.md:206-207`), and a resume sends again from the
other side's offset (`docs/design.md:209-211`). Thus a resume in the buffer
is byte-exact, and it cannot start in the middle of a sequence; T-152 tests
that invariant. Bytes are dropped only where a client attaches after output
that it never received: T-158, T-159 and T-161. The report puts the tracker
in `podssh-transport`; it cannot work there. The layer runs under SSH and
sees only ciphertext (`docs/design.md:203-204`), and the transport crates do
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
