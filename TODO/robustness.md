The work that makes the tests of podssh find more defects: fuzzing of the
parsers, a scored interop harness, a terminal oracle, stated resource limits,
property tests, a fault-injection harness for M6, and expected exit codes
that come from stock OpenSSH. Each entry changes tests and harnesses, not
what a user sees. The main sources are GitHub #25 and GitHub #34.

# T-198: Fuzz each parser

**Source:** GitHub #25 (Nemo-010, 2026-10-08); the quic-ssh report in GitHub #18
(`VLOD-ZDOV/quic-ssh:fuzz/fuzz_targets/`) and the fux report in GitHub #19
(`gold-silver-copper/fux:diff/fuzz/`), read in the reports, not verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podssh parses bytes from a relay, a proxy, an SSH server, and files that
other programs wrote. Each parser has tests with inputs that a person chose.
No test gives a parser input that nobody chose, so a panic or a wrong
acceptance on rare input stays hidden. The release build aborts on a panic
(`panic = "abort"` in `Cargo.toml`), so such a panic stops the process.

## Premise

Read, the parsers that take input from a peer or a file: WebSocket frames
(`crates/podssh-ws/src/frame.rs:113`); HTTP heads and chunked bodies
(`crates/podssh-ws/src/http.rs:113`, line 179); the upgrade answer
(`crates/podssh-ws/src/handshake.rs:183`); proxy URLs, `NO_PROXY` and the
CONNECT status (`crates/podssh-ws/src/dial.rs:49`, lines 178 and 334); close
reasons (`crates/podssh-ws/src/session.rs:275`); PEM bundles
(`crates/podssh-ws/src/bundle.rs:80`); relay lists and the pool document
(`crates/podssh-relay/src/relay.rs:81`, `crates/podssh-relay/src/pool.rs:92`);
`known_hosts` lines, in a private function
(`crates/podssh-ssh/src/known_hosts.rs:123`); the escape filter
(`crates/podssh-ssh/src/escape.rs:30`); IRC lines and frames
(`crates/podssh-core/src/irc/encode.rs:17`,
`crates/podssh-core/src/irc/framing.rs:92`); the command line
(`crates/podssh-cli/src/tree.rs:110`). No fuzz target exists. libFuzzer is
C++, and the message of commit `a378863` says that `rust:1-alpine` has no C++
compiler.

## Approach

1. Add fuzz/ in the layout of cargo-fuzz, as its own workspace that the root
   workspace excludes (as it excludes `vendor/tailscale-rs`). It is not a
   library crate, so the no-C rule (`docs/decisions.md`) does not apply,
   and the library crates get no new dependency. Invariant: the gate builds
   nothing new.
2. One target for each parser. Each asserts more than "no panic": `decode`
   consumes at most its input, and a control frame has FIN and 125 bytes or
   fewer (fails until T-063); `forward_path` after `parse_relay_list` has the
   form `/connect/HOST/PORT`; `one_line` leaves no control character
   (`SECURITY.md:46-49`); `Reassembler::push` stays under a stated limit
   (fails until T-096); the command line target calls `parse`, never the
   dispatch, so no target reaches the network.
3. Reach a private parser through a wrapper under `#[cfg(fuzzing)]`, which
   cargo-fuzz sets, so the public API does not change.
4. Seeds from bytes that podssh did not make:
   `crates/podssh-core/tests/fixtures/grammar.txt`,
   `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`, and the
   frames of `crates/podssh-ws/tests/rfc6455.rs`.
5. A scheduled workflow (also by hand) runs each target for 120 s with a
   pinned nightly toolchain and `-rss_limit_mb=512`, and keeps a crash input
   as an artifact; it is not in the gate (nightly Rust and C++). Each crash
   becomes a unit test first, then a repair. docs/development.md and
   docs/STATUS.md name the targets and the last run.

## Decision

Recommendation: cargo-fuzz (libFuzzer) in its own workspace: its coverage
guidance reaches parser states that random input seldom reaches. Property
tests alone (T-202) lost: they explore the bytes blindly. Both stay: T-202 in
the gate on stable Rust, the fuzzer on a schedule.

## Prove

```sh
cargo +nightly fuzz list                                  # one target for each parser of the Premise
cargo +nightly fuzz run ws_frame -- -max_total_time=120 -rss_limit_mb=512
cargo +nightly fuzz run close_reason -- -max_total_time=120 -rss_limit_mb=512
sh scripts/dev.sh check                                   # the gate does not change
```

The list names each target, and each run ends with no crash (`ws_frame`
after T-063). Planted defect: remove the length guard of
`close_code_and_reason` (`crates/podssh-ws/src/session.rs:276-278`);
`close_reason` must crash within its 120 s.

# T-199: A scored interop harness

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for a scored
interop harness; `lablup/bssh:docs/openssh-regress.md` and
`lablup/bssh:tests/openssh-regress/baseline.json`, read in the report, not
verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The interop harnesses print `ok`, `FAIL` and `skip` lines, and the gate fails
only on `FAIL`. A check that becomes `skip` because the environment changed
passes with no word. A check that someone deletes lowers the total, and
nothing sees it. The totals in docs/STATUS.md ("62 of 62", "98 of 98") are
counted and typed by hand.

## Premise

Read: `scripts/interop.sh:22-24` defines `ok`, `bad` and `skipped`, and
`scripts/interop.sh:288-289` fails only when a check failed. With no
`sshd.pam` in the image, the PAM check becomes `skip` and the gate stays
green (`scripts/interop.sh:172-178`). A name carries values of the run (the
seconds at `scripts/interop.sh:237`, the tty at line 221), so it is not a
stable key. The formats differ: `ok` and four spaces in
`scripts/interop.sh:22` and `scripts/interop-pty.py:34`, three in
`scripts/interop-man.sh:23`. The gate shows the last 80 result lines only
(`scripts/gate.sh:129`). The totals are typed in `docs/STATUS.md:19`, line 57
and line 196.

## Approach

1. Give each check a stable id as its first word, in each harness
   (`scripts/interop*.sh`, `scripts/interop-pty.py`,
   `scripts/interop-conpty.py`), for example `ok    ssh.exit.dropbear.143 ...`.
   The text after the id can keep values of the run.
2. One line format for all: `VERDICT ID TEXT`, with the verdicts `ok`, `FAIL`,
   `skip` and `env`. `env` names a precondition of the host that is missing
   (the PAM case becomes `env`).
3. A committed baseline (proposed: scripts/interop-baseline.txt): one line for
   each id with the verdict that it must have (`pass`, or `env-allowed` with
   the reason), and a floor of passes for each harness.
4. A scorer reads the whole output of each harness. It fails when an id that
   must pass did not pass (also as `skip` or `env`), when an id is missing or
   unknown, or when a floor is not met. It prints one table: pass, fail, env
   and skip for each harness.
5. `scripts/gate.sh` runs the scorer after the interop and man steps, with
   `run` (`scripts/gate.sh:34-48`). docs/STATUS.md quotes its table, and
   docs/development.md says that the baseline changes with the check, in the
   same commit.

Pitfall: `scripts/interop-conpty.py` runs on Windows only
(`scripts/interop-conpty.py:27-28`); T-214 scores its part of the baseline.
T-225 is another question: where each expected exit code comes from.

## Decision

Recommendation: the scorer as a Rust integration test (proposed:
crates/podssh-cli/tests/interop_score.rs). With no log, it checks that the
scripts and the baseline have the same ids, so each `cargo test` (on Windows
too) sees a new or a deleted check; with the logs named by a variable, the
gate scores them. A Python scorer beside `scripts/check-repo.py` lost: its
static half would run only where the gate runs.

## Prove

```sh
cargo test -p podssh-cli --test interop_score    # the ids of the scripts equal the baseline
sh scripts/dev.sh check                           # the gate scores each harness against the baseline
```

The test passes with no log, and the gate prints the table and exits 0.
Planted defect 1: delete one `ok` call from `scripts/interop.sh`; the test
must fail and name the id. Planted defect 2: remove `/usr/sbin/sshd.pam` in
the container before the interop step; the PAM check becomes `env`, and the
scorer must fail.

# T-200: A terminal oracle

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for a real-terminal
oracle; the fux report in GitHub #19 and GitHub #20
(`gold-silver-copper/fux:diff/oracle/`), read in the report, not verified
here.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

podssh writes to a terminal in three places: its own messages in raw mode,
text from a peer after the sanitizer, and (in M5) the echo of its line
discipline. The tests compare these bytes with expected bytes. No test asks
what a terminal shows after the bytes: where the cursor is, and which rows
changed. A wrong cursor column, or lines that step down like stairs, passes a
byte test that a person wrote with the same mistake.

## Premise

Read:

- `crates/podssh-ssh/src/log.rs:70-83` turns LF into CR LF when the terminal
  is raw. The help of `~?` (`crates/podssh-ssh/src/escape.rs:73-80`) goes
  through it. The raw state is a global (`raw_active`), so a test cannot set
  it from outside.
- `crates/podssh-ws/src/text.rs:12-51` is the one sanitizer for text from a
  peer (`SECURITY.md:46-49`).
- docs/terminal.md gives the redraw sequence and the refusals of the line
  discipline (`docs/terminal.md:78-121`). T-127 (the cursor counts bytes) and
  T-129 (Home and End do not move the screen's cursor) are screen defects.
- Read in the message of commit `a378863`: `rio-vt` needs `simdutf`, a C++
  library, so it cannot be a dependency of a library crate.

## Approach

1. A model of a VT terminal for the tests: the `vt100` crate (pure Rust, over
   `vte`) as a dev-dependency. The gate's library test step runs under
   `CC=/nonexistent` and `CXX=/nonexistent` (`scripts/gate.sh:67-69`), so it
   shows that no C or C++ comes with it.
2. A helper: bytes in, screen out (rows, cursor, attributes). Each case
   compares screens, not bytes.
3. Cases for the default build first. (a) A message and the `~?` help in raw
   mode: each line starts at column 0. Make the newline rule a pure function
   first, so that the test does not touch the global state. (b) `one_line` of
   hostile text (ESC, CSI, BEL, CR, bidirectional controls): the screen shows
   the text on one row, and the cursor moved only by its width.
4. Cases for M5, with T-125 to T-129: after any sequence of keys, the screen
   shows the prompt and the buffer, and the cursor is at the buffer's cursor,
   also with UTF-8 text. These cases are the regression tests of T-127 and
   T-129.
5. Calibrate the model once: a fixed corpus of sequences goes through `tmux`
   in the gate's container (installed with apk, as `scripts/interop-man.sh:20`
   installs groff) and through `vt100`. The two must give the same screens
   before the model judges podssh.
6. docs/terminal.md, section "Tests" (`docs/terminal.md:129`), names the
   oracle.

## Decision

Recommendation: `vt100` in unit tests, calibrated against tmux. It is fast,
needs no process and no pty, and runs on Windows too. tmux alone lost: each
case would need a pty and a process. A model with C++ dependencies (`rio-vt`)
lost by the no-C rule.

## Prove

```sh
cargo test -p podssh-ssh --test terminal_oracle   # raw-mode messages and the ~? help, as screens
cargo test -p podssh-ws --test terminal_oracle    # sanitized peer text, as screens
sh scripts/dev.sh check                           # the model and tmux agree on the corpus
```

Each command exits 0. Planted defect: remove the CR LF conversion
(`crates/podssh-ssh/src/log.rs:81-83`); the help case must fail. After M5,
`cargo test -p podssh-terminal --test oracle` must fail while T-127 is open.

# T-201: Resource limits, stated and tested

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for explicit
resource bounds; the rose report in GitHub #18 (`nikhiljha/rose:doc/spec.md`,
line 125) and the MobaRust report in GitHub #21
(`OthmaneBlial/MobaRust:apps/desktop/src-tauri/src/ssh_backpressure_test.rs`),
read in the reports, not verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podssh keeps many bounds on memory and time, but no document lists them, and
few tests push a peer past one. A user cannot know how much memory a session
can use, or what happens at a limit. A change that removes a bound passes the
tests.

## Premise

Read, the bounds today:

- A frame: 262144 bytes (`crates/podssh-ws/src/frame.rs:30`, refused at lines
  180-194). A message in fragments: 16 MiB
  (`crates/podssh-ws/src/session.rs:28`, checked at lines 240-242).
- A response head: 16 KiB for HTTP (`crates/podssh-ws/src/http.rs:8`), for the
  proxy (`crates/podssh-ws/src/dial.rs:18`) and for the upgrade
  (`crates/podssh-ws/src/handshake.rs:132`).
- The pool document: 256 KiB (`crates/podssh-relay/src/pool.rs:33`). A cache
  file: 64 KiB (`crates/podssh-relay/src/cache.rs:19`).
- The SSH window: 512 KiB (`crates/podssh-ssh/src/run.rs:29`). The relay pipe:
  256 KiB each way, frames of 64 KiB
  (`crates/podssh-ssh/src/relay_stream.rs:22-25`). Pump buffers: 32 KiB
  (`crates/podssh-cli/src/proxy.rs:214`).
- Time: `crates/podssh-ws/src/client.rs:21-35`,
  `crates/podssh-relay/src/open.rs:25-29`, `crates/podssh-ssh/src/session.rs:21`.
- No limit: a `known_hosts` file is read whole
  (`crates/podssh-ssh/src/known_hosts.rs:104-109`); the IRC buffer (T-096).
- Two texts disagreed until T-024. The comment on the SSH window
  (`crates/podssh-ssh/src/run.rs` lines 25-28 at `80f20bf`) said that the
  relay drops a frame when more than 1 MiB waits (`1011 relay
  backpressure`): the row of the reverse path in the relay's document
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`). It
  now gives the forward path's rule (`crates/podssh-ssh/src/run.rs:25-28`):
  `docs/relay.md:164-168` says that backpressure closes with `1013` at
  2 MiB and drops no frame. T-062 measures whether that check operates.

## Approach

1. A section "Limits" in docs/architecture.md: one row for each bound, with
   its value, its file, and what podssh does at the bound (the error and its
   exit code). Name the two missing limits as missing.
2. The table states the forward path's bound, as the comment at
   `crates/podssh-ssh/src/run.rs:25-28` does since T-024, and the result of
   T-062 when it exists.
3. Tests in the process, with a peer over `tokio::io::duplex`, so no network
   (`docs/development.md:210-213`): a proxy head that never ends stops at
   16 KiB, and an upgrade head too; fragments past 16 MiB give the error, not
   more memory; a pool body over 256 KiB is refused; a cache file over 64 KiB
   is ignored.
4. A slow reader in the interop harness: `podssh ssh` whose stdout nobody
   reads for 30 s while the server writes 50 MB. First measure the peak memory
   (`VmHWM` in `/proc/PID/status`) with a fast reader. The bound is that value
   plus a margin; the check fails above it.
5. Give `known_hosts` a read limit (16 MiB, far above a real file) with a
   message that names the file, or state in the table that it has none.
6. In M6, the replay buffer (4 to 16 MiB, `docs/design.md:189-190`; T-152)
   joins the table.

## Prove

```sh
cargo test -p podssh-ws --test limits      # each head and message bound, against a peer that never stops
cargo test -p podssh-relay --test limits   # the pool body and the cache file
sh scripts/dev.sh check                    # interop: the slow reader stays under the stated peak memory
```

Each command exits 0. Planted defect: set `WINDOW`
(`crates/podssh-ssh/src/run.rs:29`) to 64 MiB; the slow-reader check must
fail. If it does not, the bound is somewhere else: find it before anybody
trusts the check. A second plant: remove the check at
`crates/podssh-ws/src/session.rs:240-242`; the fragment test must fail.

# T-202: Property tests for the state machines

**Source:** the MobaRust report in GitHub #21
(`OthmaneBlial/MobaRust:crates/mobarust-core/tests/property_invariants.rs`),
read in the report, not verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The state machines of podssh are tested with chosen examples. A property that
must hold for each input (a round trip, or the same result for each split of
a stream) is checked only for those examples. A defect that appears with one
split of the input only is not found.

## Premise

Read: the candidates, each a pure function or a state machine with no I/O.

- WebSocket frames: `encode` and `decode` (`crates/podssh-ws/src/frame.rs:67`,
  `crates/podssh-ws/src/frame.rs:113`).
- The joining of fragments (`crates/podssh-ws/src/session.rs:234-258`). It is
  private, but `RelaySession::new` (`crates/podssh-ws/src/session.rs:68`) takes
  any stream, so a test can drive it.
- Relay lists and paths (`crates/podssh-relay/src/relay.rs:81-147`, `crates/podssh-ws/src/names.rs:8-57`).
- `known_hosts` patterns (`crates/podssh-ssh/src/known_hosts.rs:148-204`).
- The escape filter, which keeps its state from one read to the next
  (`crates/podssh-ssh/src/escape.rs:30-70`).
- The sanitizer (`crates/podssh-ws/src/text.rs:12-57`).

Read: no crate uses a library for property tests. `proptest` is pure Rust;
the gate must show it.

## Approach

1. `proptest` as a dev-dependency of podssh-ws, podssh-relay and podssh-ssh.
   The gate's library test step runs under `CC=/nonexistent` and
   `CXX=/nonexistent` (`scripts/gate.sh:67-69`), so it shows that no C comes
   with it. Commit the regression files of proptest as seeds.
2. One test file for each crate (tests/properties.rs), with these properties:
   - frames: for each opcode, FIN, role, mask and payload up to 262144 bytes,
     `decode(encode(f))` gives `f` and uses each byte; each shorter prefix gives
     `Ok(None)`;
   - fragments: a message cut into any fragments arrives whole; a total over
     16 MiB gives the error;
   - relay lists: the order stays, duplicates go, each host passes
     `check_host`, and `forward_path` has the form `/connect/HOST/PORT`;
   - `known_hosts`: a negated pattern that matches always rejects; a hashed
     pattern made from a name matches that name; the case of the letters does
     not change a match;
   - escapes: the input cut at any point gives the same bytes and commands as
     the whole input;
   - the sanitizer: `one_line` leaves no control or bidirectional character
     and no double space, and a second pass changes nothing.
3. Later, with their entries: the IRC reassembler (T-096) and the line
   discipline (T-125 to T-129).
4. 256 cases for each property by default, so the time of the gate stays
   bounded.

## Prove

```sh
cargo test -p podssh-ws --test properties
cargo test -p podssh-relay --test properties
cargo test -p podssh-ssh --test properties
sh scripts/dev.sh check     # proptest builds under CC=/nonexistent and CXX=/nonexistent
```

Each command exits 0. Planted defect: in `encode`, mask with
`masking_key[(i + 1) % 4]` (`crates/podssh-ws/src/frame.rs:100`); the round
trip of frames must fail and print the smallest frame that fails.

# T-203: The fault-injection harness: latency, jitter, bandwidth, a new address

**Source:** `docs/design.md:219-221` (layers 2 and 3 need the harness
extended), and the exit criteria of M6 (`docs/ROADMAP.md`, M6; T-156).
**Category:** chore
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The fault harness tests the failures of one connection attempt: a relay host
that is down or silent, a 503, a proxy 502, a Close, a stall, a host that
stops. It cannot delay bytes, vary the delay, limit the bandwidth, or bring a
session back from a new address. The exit of M6 needs a session that
survives a stopped relay host, a new address of the client and a stall of 3
minutes, and no harness can test that yet.

## Premise

Read:

- The modes of the stand-in relay: `normal`, `refuse`, `blackhole`, `silent`,
  `stall` and `close` (`scripts/fake-relay.py:14-21`). The stand-in proxy maps
  names and answers a status (`scripts/fake-proxy.py:1-13`). Neither shapes
  the traffic.
- `scripts/interop-faults.sh:33-39` starts one stand-in for each fault; its
  checks are at lines 73-182 (`docs/STATUS.md:182-201`, 14 of 14 since T-236).
- The time limits that latency meets today: the SSH handshake, 60 s
  (`crates/podssh-ssh/src/options.rs:241`, enforced at
  `crates/podssh-ssh/src/run.rs:138-143`); a reply, 30 s
  (`crates/podssh-ssh/src/session.rs:21`); a write, 60 s, and liveness, three
  times 10 s (`crates/podssh-ws/src/client.rs:31-35`).
- The gate's container gets no added capability
  (`.github/workflows/build.yml:59-65`).

## Approach

1. New modes in `scripts/fake-relay.py`, applied in `pump` (lines 143-210), in
   each direction: `delay:MS`; `jitter:MIN:MAX:SEED`, from a seeded generator,
   so that a run repeats; `rate:BYTES_PER_SECOND`, a token bucket;
   `cut:BYTES`, the TCP connection closed with no Close frame.
2. A new address: an option of `scripts/fake-proxy.py` binds its upstream
   socket to another loopback address (127.0.0.2), so the stand-in relay sees
   the client come back from a new address. The harness binds; podssh does
   not.
3. Checks for layer 1 now, each with a time limit: with 2 s each way, a
   command and its exit status come back (the handshake takes about five
   round trips); with a jitter of 0 to 1.5 s, 5,000,000 bytes up and back keep
   their digest; at 64 KiB/s, 2 MB arrive within the computed time plus 50 %;
   with `cut`, exit 255 and the relay is named.
4. With T-151 to T-155: a stand-in relay host stopped during a session, the
   session back from 127.0.0.2, and a stall of 3 minutes, each with the digest
   of a running transfer intact. T-156 uses these checks as its measurement.
5. Update docs/development.md (item 8 of the gate,
   `docs/development.md:112-118`) and the faults table of docs/STATUS.md.

Pitfall: each check must show that its fault was injected (see Prove).

## Decision

Recommendation: shape the traffic in the stand-ins. They need no privilege,
and they run the same in the gate's container, in CI and on Windows. Linux
`tc netem` lost: it needs `CAP_NET_ADMIN`, which the gate's container does not
get, and it shapes all loopback traffic, the OpenSSH servers too.

## Prove

```sh
sh scripts/dev.sh check     # interop-faults: the delay, jitter, rate and cut checks pass
```

The faults section shows each new check as `ok`. Planted defect, built into
the harness as a control: the delay check of 2 s runs again with
`-o ConnectTimeout=5`, and it must fail with "did not finish within 5 s".
This shows that the delay was injected. After M6, the checks of T-156 must
fail when the resume layer is off.

# T-225: The interop gate takes each expected exit code from stock OpenSSH, beside the literal (GitHub #34)

**Source:** GitHub #34 (2026-10-08); the reporter read the workflow of
iroh-ssh (`rustonbsd/iroh-ssh:.github/workflows/build.yml`, lines 385-434),
read in the report, not verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

The interop harness writes each expected exit code as a literal. A literal
is a claim about a server and a client. When a server, its configuration or
a release of OpenSSH changes the right code, the gate keeps its pass, and
nobody measures again.

## Premise

Read, each claim of GitHub #34 at the lines as they are now:

- The matrix is at `scripts/interop.sh:113-122`. It expects 3, 0, 1, 127 and
  143, against OpenSSH (port 2201) and Dropbear (port 2203). `grep -c` gives
  13 lines with `expect_rc`: the comment, the definition
  (`scripts/interop.sh:25-28`) and 11 calls. `scripts/interop-keygen.sh` has 6
  more, for `podssh keygen`.
- `scripts/interop.sh` (lines 31-32 at `5c7a1ad`) installed `openssh-server`,
  `openssh-keygen` and others, but no client package. No harness ran the stock `ssh`; only
  `scripts/sandbox-check.sh:174-187` does, in a sandbox. Nobody knows whether
  the gate's image has `/usr/bin/ssh`.
- `crates/podssh-ssh/src/io.rs:115-120` maps an exit status that does not fit
  (the -1 of `railway.new`) to 255, and an exit signal to 128 plus its number
  (`docs/STATUS.md:63`, `docs/STATUS.md:65`).
- A correction to the framing of #34: for a signal, podssh differs from
  OpenSSH on purpose. `docs/cli.md:207-208` says 128 plus the signal's number,
  and that OpenSSH gives 255. `crates/podssh-ssh/src/lib.rs:16` says that the
  codes follow OpenSSH, with 128 plus a signal. The two texts disagree, and no
  record measures the code of OpenSSH.

## Approach

1. Settle the client first: in the gate's container, run `command -v ssh`
   before the package line. If it is missing, add the client package to
   `scripts/interop.sh:32`, and print its version (as line 96 does for the
   servers).
2. For each call of `podssh ssh` in the matrix and in the refusals (lines
   146-196), run the stock `ssh` first, with the same server, port, key,
   `known_hosts`, `BatchMode` and command, and a time limit. Record its exit
   code. Then run podssh and compare.
3. A table of the intended differences, each with its reason. Today one row:
   a signal (OpenSSH's code, against 128 plus the number;
   `docs/cli.md:207-208`). A difference that the table does not name fails,
   with both codes and the command.
4. Keep each literal as a second check with its own name, so that a change
   gives two named failures: "differs from OpenSSH" and "differs from the
   promise".
5. Refuse a reference of 0 for a case that must fail, so that a broken
   reference cannot pass.
6. Make `crates/podssh-ssh/src/lib.rs:16` and `docs/cli.md:207-208` agree with
   the measurement, and record the codes of OpenSSH in docs/STATUS.md.

Relation: T-199 (GitHub #25) scores the harness against a committed
baseline. This entry decides where each expected value comes from. With
T-199, each derived check gets its own id.

## Prove

```sh
sh scripts/dev.sh check     # interop: for each case, the code of OpenSSH, of podssh and the literal agree
```

The interop section shows, for each case, the reference code, podssh's code
and the literal, and the signal row as a named difference. Planted defect 1:
map an exit signal to 255 at `crates/podssh-ssh/src/io.rs:120`; the literal
check of 143 must fail, and the table must report its signal row as broken.
Planted defect 2: let the reference run `true` in place of `exit 3`; the
derived check must fail.
