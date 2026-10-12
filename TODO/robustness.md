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
**Status:** done

## Problem

podssh parses bytes from a relay, a proxy, an SSH server, and files that
other programs wrote. Each parser has tests with inputs that a person chose.
No test gives a parser input that nobody chose, so a panic or a wrong
acceptance on rare input stays hidden. The release build aborts on a panic
(`panic = "abort"` in `Cargo.toml`), so such a panic stops the process.

## Premise

Read, the parsers that take input from a peer or a file: WebSocket frames
(`crates/podssh-ws/src/frame.rs:113`); HTTP heads and chunked bodies
(`crates/podssh-ws/src/http.rs:110`, line 183 at `e892b0f`); the upgrade answer
(`crates/podssh-ws/src/handshake.rs:175`); proxy URLs
(`crates/podssh-ws/src/proxy.rs:82`), `NO_PROXY` and the CONNECT status
(`crates/podssh-ws/src/dial.rs`, lines 178 and 334 at `22c3b88`); since T-070 (2026-10-11), a
SOCKS5 proxy's answers (`crates/podssh-ws/src/socks5.rs:156`); close
reasons (`crates/podssh-ws/src/session.rs:371`); PEM bundles
(`crates/podssh-ws/src/bundle.rs:72`); relay lists and the pool document
(`crates/podssh-relay/src/relay.rs:107`, `crates/podssh-relay/src/pool.rs:95`);
`known_hosts` lines, in a private function
(`crates/podssh-ssh/src/known_hosts.rs:250`); the escape filter
(`crates/podssh-ssh/src/escape.rs:43`); IRC lines and frames
(`crates/podssh-core/src/irc/encode.rs:88`,
`crates/podssh-core/src/irc/framing.rs:110`); the command line
(`crates/podssh-cli/src/tree.rs:117`). No fuzz target exists. libFuzzer is
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
   (`SECURITY.md:79-82`); `Reassembler::push` stays under a stated limit
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

Decided in the work (2026-10-11):
- The targets run on Linux with glibc and the address sanitizer only. On
  Windows the link of libFuzzer's coverage needs MSVC's sanitizer runtime,
  which these build tools lack; on musl, the build image's C library, each
  target died of a signal within five inputs. This machine runs them in
  `docker.io/library/rust:1-trixie` through `scripts/dev.sh` and its
  `PODSSH_BUILD_IMAGE`, and CI on `ubuntu-24.04`. A target with no
  sanitizer on musl lost: its crashes were the C library's, not podssh's.
- The fuzz crate depends on `podssh-cli`, for the target of the command line,
  and so builds aws-lc: a second fuzz crate for one target lost, as cargo-fuzz
  builds the targets of one crate once.
- A private parser is reached through a function under `cfg(fuzzing)`, and
  its crate declares the cfg (`[lints.rust]`), so that clippy's
  `unexpected_cfgs` passes with `-D warnings`. Making the parsers public
  lost: the public API would grow for the fuzzer alone.
- An input that a target found is kept as a unit test in the crate of its
  parser (`crates/podssh-core/tests/fuzz_found.rs`, and next to the tests of
  each other parser), so the gate runs it on stable Rust at each push.

## Prove

```sh
cargo +nightly fuzz list                                  # one target for each parser of the Premise
cargo +nightly fuzz run ws_frame -- -max_total_time=120 -rss_limit_mb=512
cargo +nightly fuzz run close_reason -- -max_total_time=120 -rss_limit_mb=512
sh scripts/dev.sh check                                   # the gate does not change
```

The list names each target, and each run ends with no crash (`ws_frame`
after T-063). Planted defect: remove the length guard of
`close_code_and_reason` (`crates/podssh-ws/src/session.rs:372-374`);
`close_reason` must crash within its 120 s.

## Done

2026-10-11, in the commit that closes this entry.
- `fuzz/` (its own workspace; the root excludes it, so the gate builds none of it): 18 targets,
  one for each parser of the Premise, each with checks beyond the absence of a panic, written in
  its first lines; `fuzz/src/lib.rs` checks text that is safe on one line. `scripts/fuzz.sh` (a
  pinned nightly, cargo-fuzz 0.13.2, the address sanitizer, glibc only),
  `scripts/fuzz-seeds.py` (seeds from RFC 6455's frames, the IRC grammar fixture and the hosts
  of the relay's document), `.github/workflows/fuzz.yml` (each Monday and by hand), and the
  section "Fuzzing" of `docs/development.md`. `cargo +nightly fuzz list` names the 18.
- Each target ran 120 s on glibc with the address sanitizer
  (`PODSSH_BUILD_IMAGE=docker.io/library/rust:1-trixie sh scripts/dev.sh run -- 'sh
  /work/scripts/fuzz.sh 120'`), with no crash: ws_frame 53.0 M inputs, known_hosts_line 32.0 M,
  pem_bundle 29.0 M, connect_status 22.8 M, socks5_answer 22.3 M, one_line 19.2 M, proxy_url
  17.3 M, http_chunked 15.4 M, escape_filter 13.4 M, relay_pool 11.4 M, ws_upgrade 10.3 M,
  close_reason 10.0 M, http_head 6.2 M, relay_list 4.4 M, no_proxy 2.9 M, irc_message
  3.4 M, irc_framing 2.2 M, cli_args 0.5 M.
- Found, each repaired with a test first:
  - `irc_message`: a line `:prefix :text`, a trailing with no command, stopped the IRC parser
    with a panic, which the release build turns into an abort: one line of a server ended
    `podssh chat --irc`. `Message::parse` now refuses it, and `parse_command` no longer slices
    past a missing command (`crates/podssh-core/tests/fuzz_found.rs`; planted, the refusal
    removed, the test fails).
  - `irc_message`, again: `@ @ :` parsed as a command named `@`, which `to_wire` wrote as it
    was, and which a server reads back as tags. The encoder now takes a command of letters or
    three digits only (RFC 2812, section 2.3.1), and the test of the same file checks it.
  - `ws_upgrade`: a refused upgrade kept the peer's head whole, ESC included, in its message;
    it is now made safe for one line (`tests/rfc6455.rs`).
  - `proxy_url`: a host such as `]_::` parsed, and its URL did not parse back; a host with a
    bracket, `@`, `/`, `?`, `#`, a space or a control character is now refused (`tests/socks5.rs`).
  - Read for `http_chunked`: a chunk size near the largest number wrapped the sums of
    `decode_chunked`, a panic with overflow checks and, in the release build, a slice that ends
    before it starts (`tests/http.rs`; the old code fails the test).
  - Read for `pem_bundle`: an empty CERTIFICATE block passed as a certificate; it is refused by
    name (`tests/bundle.rs`).
- Three checks of the targets were wrong and were corrected: the escape filter holds an escape
  across reads, so its bound is for the stream; a Latin-1 line is two bytes of UTF-8 for each
  byte above 0x7f; the count of a lost IRC line depends on where the frames were cut. The IRC
  message target drops NUL first, as the byte layer does.
- Planted, in the build image's copy only: with the length guard of `close_code_and_reason`
  removed, `close_reason` crashed at its first input; with `decode_chunked` as it was,
  `http_chunked` crashed after 6.9 M inputs.
- Native, Windows: `cargo test -p podssh-core` and `-p podssh-ws`, each suite passed (185 in
  podssh-ws); `cargo clippy --all-targets -D warnings` for the five crates that changed.
- CI, `.github/workflows/fuzz.yml`, started by hand: the run of `5a88857` (38115715408) built
  the targets for musl, the default of cargo-fuzz's release binary, where the sanitizer does
  not work; `scripts/fuzz.sh` names the host's target since `6529789`, whose run (38115798595)
  passed: 18 targets, 120 s each, with the address sanitizer on glibc and no crash, from 0.5 M
  inputs (cli_args) to 50.6 M (ws_frame).

# T-199: A scored interop harness

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for a scored
interop harness; `lablup/bssh:docs/openssh-regress.md` and
`lablup/bssh:tests/openssh-regress/baseline.json`, read in the report, not
verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The interop harnesses print `ok`, `FAIL` and `skip` lines, and the gate fails
only on `FAIL`. A check that becomes `skip` because the environment changed
passes with no word. A check that someone deletes lowers the total, and
nothing sees it. The totals in docs/STATUS.md ("62 of 62", "98 of 98") are
counted and typed by hand.

## Premise

Read, at `b81480d`: `scripts/interop.sh` defines `ok`, `bad` and `skipped`
(lines 22-24), and fails only when a check failed (lines 445-446). With no
`sshd.pam` in the image, the PAM check becomes `skip` and the gate stays
green (lines 180-186). A name carries values of the run (the seconds at
line 350, the tty at line 391), so it is not a stable key. The formats
differ: `ok` and four spaces in `scripts/interop.sh` (line 22) and
`scripts/interop-pty.py` (line 34), three in `scripts/interop-man.sh` (line
23). The gate shows the last 80 result lines only (`scripts/gate.sh`, line
337). The totals are typed in `docs/STATUS.md` (line 21 at `b81480d`, line
57 at `3cbf215` and line 196 at `22c3b88`).

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
   `run` (`scripts/gate.sh:64-78`). docs/STATUS.md quotes its table, and
   docs/development.md says that the baseline changes with the check, in the
   same commit.

Pitfall: `scripts/interop-conpty.py` runs on Windows only
(`scripts/interop-conpty.py:27-28`). The job `windows` of CI runs it at each
push, through `scripts/interop-conpty-msys2.py` (T-214); this entry adds its
ids to the baseline, and scores that job's output.
T-225 is another question: where each expected exit code comes from.

## Decision

Recommendation: the scorer as a Rust integration test (proposed:
crates/podssh-cli/tests/interop_score.rs). With no log, it checks that the
scripts and the baseline have the same ids, so each `cargo test` (on Windows
too) sees a new or a deleted check; with the logs named by a variable, the
gate scores them. A Python scorer beside `scripts/check-repo.py` lost: its
static half would run only where the gate runs.

Taken otherwise, with these calls made in the work (2026-10-11). The scorer
is a command of the record's checker, `cargo todo interop`
(`crates/podssh-todo/src/interop/mod.rs`): with no log, it compares the ids
that the scripts can print with the baseline; with `--logs FILE...`, it
scores a run, each log by its name (`interop.log` is the run `interop`).
`crates/podssh-todo/tests/interop.rs` runs the check on this repository's
scripts, so each `cargo test` of the workspace sees a new or a deleted
check, on Windows too. A test of `podssh-cli` lost: the step `release` has
the logs and builds no test of the CLI, and the test would build the CLI
only to read text; `podssh-todo` already reads the repository's text, and
builds with no C compiler. An id is read as the scripts are written
(`crates/podssh-todo/src/interop/words.rs`): the first word after `ok`,
`bad`, `expect_rc`, `skipped`, `unmet` or `no_part`, quoted or not, outside
comments and heredocs, with `${VAR}` and `${VAR%%:*}` taken from the
nearest `for VAR in WORDS` above, whose words must be literal; in Python,
the literal first argument of `check(`. Each line that printed only on a
failure became a pair, so that each id prints one line in each run. The
PAM check is `pass` in the baseline, not `env-allowed`: `scripts/interop.sh`
installs `openssh-server-pam` itself, so a missing `sshd.pam` is the change
of the host that the scorer must catch.

## Prove

```sh
cargo test -p podssh-todo --test interop                     # the ids of the scripts equal the baseline
cargo todo interop                                           # the same check, by hand
sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh release'  # the step scores each harness against the baseline
```

The test passes with no log, and the step prints a row `score` for each
harness and exits 0. Planted defect 1: delete the check
`ssh.exit.signal_named` from `scripts/interop.sh`; `cargo todo interop` must
fail and name the id. Planted defect 2: the PAM check gives `env`, as with
no `/usr/sbin/sshd.pam` in the container; the scorer must fail.

## Correction

2026-10-11: the Premise named the tty at line 334 of `scripts/interop.sh`,
which at `b81480d` was a comment of the `-s sftp` check; the tty was at line
391. The Premise now reads at `b81480d`, the tree before this entry's work.

## Done

2026-10-11. Each check of the harnesses prints `VERDICT ID TEXT`
(`scripts/interop-lib.sh`, which `scripts/interop.sh` and
`scripts/interop-man.sh` source; `check()` in the two pty scripts), with an
id of the harness's prefix: 322 ids in 18 harnesses. A loop's label stands
in the id for a value (`ssh.exit.${srv%%:*}.${spec%%:*}`), and a check that
printed only on a failure is now a pair. The PAM case prints `env` when
`sshd.pam` is missing. `scripts/interop-baseline.txt` names each harness
with its run and floor, and each id with `pass`. `cargo todo interop`
(`crates/podssh-todo/src/interop/`) checks the scripts against it, and with
`--logs` scores a run; the step `release` of `scripts/gate.sh` shows every
result line and scores the logs of the interop and man runs; CI's job
`windows` scores the console checks (`--log` of
`scripts/interop-conpty-msys2.py`). `docs/development.md` says that the
baseline changes with its check.
- `cargo test -p podssh-todo`: each suite passed, `tests/interop.rs` 11 (the
  repository's own scripts against the baseline, and a planted case of each
  disagreement and of each way a run misses it). `cargo todo interop`: "322
  ids of 18 harnesses meet scripts/interop-baseline.txt".
- In the build image, `sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh
  release'` (11 min): interop 301 passed, 0 failed, 0 skipped, 0 env; the
  man page 7 of 7; each harness at its floor (ssh 71, status 6, keygen 28,
  agent 18, local 6, control 13, faults 27, ping 3, relay 4, socks 4, cp 68,
  mv 18, sftp 5, resume 9, pipe 9, pty 12, man 7); "gate green (release)".
- Planted defect 1: with `ssh.exit.signal_named` deleted from
  `scripts/interop.sh`, `cargo todo interop` exits 1: "ssh.exit.signal_named
  is printed by no line of scripts/interop.sh". Planted defect 2, on the
  lines of that run: with the PAM check as `env`, the scorer exits 1:
  "ssh.auth.kbdint_pam gave env, where ok is due", and ssh passed 70 checks,
  under its floor of 71.
- CI at `72ca309` (run 38118496778): every job passed; the step `release`
  scored interop 301 of 301 and the man page 7 of 7, and the job `windows`
  the console checks, conpty 14 of 14, each at its floor.

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
  is raw. The help of `~?` (`crates/podssh-ssh/src/escape.rs:82-91`) goes
  through it. The raw state is a global (`raw_active`), so a test cannot set
  it from outside.
- `crates/podssh-ws/src/text.rs:12-51` is the one sanitizer for text from a
  peer (`SECURITY.md:79-82`).
- docs/terminal.md gives the redraw sequence and the refusals of the line
  discipline (`docs/terminal.md:151-247`). T-127 (the cursor counts bytes) and
  T-129 (Home and End do not move the screen's cursor) are screen defects.
- Read in the message of commit `a378863`: `rio-vt` needs `simdutf`, a C++
  library, so it cannot be a dependency of a library crate.

## Approach

1. A model of a VT terminal for the tests: the `vt100` crate (pure Rust, over
   `vte`) as a dev-dependency. The gate's library test step runs under
   `CC=/nonexistent` and `CXX=/nonexistent` (`scripts/gate.sh:163-165`), so it
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
   in the gate's container (installed with apk, as `scripts/interop-man.sh:22`
   installs groff) and through `vt100`. The two must give the same screens
   before the model judges podssh.
6. docs/terminal.md, section "Tests" (`docs/terminal.md:280`), names the
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
**Status:** done

## Problem

podssh keeps many bounds on memory and time, but no document lists them, and
few tests push a peer past one. A user cannot know how much memory a session
can use, or what happens at a limit. A change that removes a bound passes the
tests.

## Premise

Read, the bounds today:

- A frame: 262144 bytes (`crates/podssh-ws/src/frame.rs:30`, refused at lines
  180-194). A message in fragments: 16 MiB
  (`crates/podssh-ws/src/session.rs:29`, checked at lines 240-242 at `23b5d82`).
- A response head: 16 KiB for HTTP (`crates/podssh-ws/src/http.rs:8`), for the
  proxy (`crates/podssh-ws/src/dial.rs:21`) and for the upgrade
  (`crates/podssh-ws/src/handshake.rs:124`).
- The pool document: 256 KiB (`crates/podssh-relay/src/pool.rs:36`). A cache
  file: 64 KiB (`crates/podssh-relay/src/cache.rs:33`).
- The SSH window: 512 KiB (`crates/podssh-ssh/src/run.rs:30`). The relay pipe:
  256 KiB each way, frames of 64 KiB
  (`crates/podssh-ssh/src/relay_stream.rs:30-33`). Pump buffers: 32 KiB
  (`crates/podssh-cli/src/pipe/pump.rs:22`).
- Time: `crates/podssh-ws/src/client.rs:21-35`,
  `crates/podssh-relay/src/open.rs:30-34`, `crates/podssh-ssh/src/session.rs:21`.
- No limit: a `known_hosts` file was read whole (`crates/podssh-ssh/src/known_hosts.rs`,
  lines 186-192 at `72ca309`); the IRC buffer (T-096).
- Two texts disagreed until T-024. The comment on the SSH window
  (`crates/podssh-ssh/src/run.rs` lines 25-28 at `80f20bf`) said that the
  relay drops a frame when more than 1 MiB waits (`1011 relay
  backpressure`): the row of the reverse path in the relay's document
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`). It
  now gives the forward path's rule (`crates/podssh-ssh/src/run.rs:26-29`):
  `docs/relay.md:236-240` says that backpressure closes with `1013` at
  2 MiB and drops no frame. T-062 measures whether that check operates.

## Approach

1. A section "Limits" in docs/architecture.md: one row for each bound, with
   its value, its file, and what podssh does at the bound (the error and its
   exit code). Name the two missing limits as missing.
2. The table states the forward path's bound, as the comment at
   `crates/podssh-ssh/src/run.rs:26-29` does since T-024, and the result of
   T-062 when it exists.
3. Tests in the process, with a peer over `tokio::io::duplex`, so no network
   (`docs/development.md:402-405`): a proxy head that never ends stops at
   16 KiB, and an upgrade head too; fragments past 16 MiB give the error, not
   more memory; a pool body over 256 KiB is refused; a cache file over 64 KiB
   is ignored.
4. A slow reader in the interop harness: `podssh ssh` whose stdout nobody
   reads for 30 s while the server writes 50 MB. First measure the peak memory
   (`VmHWM` in `/proc/PID/status`) with a fast reader. The bound is that value
   plus a margin; the check fails above it.
5. Give `known_hosts` a read limit (16 MiB, far above a real file) with a
   message that names the file, or state in the table that it has none.
6. In M6, the replay buffer joins the table (T-152, 2026-10-09): 4 MiB in
   each direction of each resumable session by default, 16 MiB at most with
   `PODSSH_REPLAY_BUFFER` (`crates/podssh-relay/src/session/replay.rs`); at
   the bound the writer waits for an `ACK`, and no byte is dropped. A node
   keeps 64 MiB of them at most, a whole buffer for each session that it
   keeps (`crates/podssh-relay/src/reverse/layered.rs`, T-153).

## Prove

```sh
cargo test -p podssh-ws --test limits      # each head and message bound, against a peer that never stops
cargo test -p podssh-relay --test limits   # the pool body and the cache file
sh scripts/dev.sh check                    # interop: the slow reader stays under the stated peak memory
```

Each command exits 0. Planted defect: set `WINDOW`
(`crates/podssh-ssh/src/run.rs:30`) to 64 MiB, and russh's queue of a
channel (`channel_buffer_size`, `crates/podssh-ssh/src/run.rs:439-448`) to
2^20 messages; the slow-reader check must fail. The window alone is not
enough: the queue is a second bound (Correction). A second plant: remove the
check at `crates/podssh-ws/src/session.rs:336-338`; the fragment test must
fail.

## Correction

2026-10-11, read against the Premise; each holds at the cited lines:

- The frame's bound refuses a 64-bit length (`crates/podssh-ws/src/frame.rs:171-173`). The check
  after it (`crates/podssh-ws/src/frame.rs:179-183`) cannot fire: a shorter length is at most 65535.
- The upgrade that podssh sends is `client::upgrade`, whose bound was a literal; it is
  `UPGRADE_HEAD` now (`crates/podssh-ws/src/client.rs:38`). `MAX_HANDSHAKE_RESPONSE`
  (`crates/podssh-ws/src/handshake.rs:124`) bounds `handshake::handshake`, which no command calls.
- The steps of the connection wait `CONNECT_TIMEOUT` each (`crates/podssh-relay/src/open.rs:30`).
  `DEFAULT_TIMEOUT` (`crates/podssh-ws/src/client.rs:21`) is a default for an embedder, which no
  command of podssh takes.
- The IRC buffer has a bound since T-096: 8192 bytes for a line
  (`crates/podssh-core/src/irc/framing.rs:52`).
- `known_hosts` was read whole a second time, under the lock of a record (`append`); the bound
  covers both reads.
- A pool body past its bound, and a file of the cache past its bound, are dropped with no word:
  the refresh's error goes nowhere (`crates/podssh-relay/src/open.rs:345`), and the cache reads a
  file that it cannot use as none (`crates/podssh-relay/src/cache.rs:299-301`). Each is made again,
  so the table says so, and nothing is added.
- `PODSSH_REPLAY_BUFFER` above 16 MiB gives 4 MiB, the default, not 16 MiB
  (`crates/podssh-relay/src/session/replay.rs:27-31`), as its comment says: another value is
  ignored. The table says so.
- The window is not the only bound of a reader that takes nothing: russh queues at most 100
  messages of a channel (`channel_buffer_size`, its default, which
  `crates/podssh-ssh/src/run.rs:439-448` leaves), each of 32 KiB at most, and its task then reads
  no more from the server. Measured in the build image on 2026-10-11, with the Prove's plant: the
  window at 64 MiB gave a peak of 8948 KiB, held by the queue; the queue at 2^20 messages as well
  gave 62708 KiB, and even a reader that took each byte held 62084 KiB, as the server outran the
  output.
  So the check compares no reader with another: its ceiling is half of what the server writes,
  and the plant is both bounds.

## Done

2026-10-11. `docs/architecture.md`, "Limits": each bound of memory and of time, with its value,
its constant and file, and what podssh does past it; the relay's forward path, russh's queue of
a channel and the replay buffers of M6 among them. The upgrade's bound has a name,
`UPGRADE_HEAD` (`crates/podssh-ws/src/client.rs:38`); `known_hosts` has a bound of 16 MiB, in
both of its reads (`crates/podssh-ssh/src/known_hosts.rs:25`); the pool's request takes a stream
(`pool::request`), so that a test can serve it. `scripts/interop-limits.sh` measures a session
whose output nobody reads; `scripts/interop-baseline.txt` has its two ids.
- `cargo test -p podssh-ws --test limits`: 6 passed. Against a peer that never stops, the heads
  of the upgrade, of HTTP and of a proxy's CONNECT stop at 16 KiB, and the peer wrote less than
  the bound and 8 KiB before podssh stopped reading; a body of each framing is read at its bound
  and refused one byte past it; a frame of 262144 bytes is read, and a header of one byte more
  ends the session with a Close 1002 before its payload; 16 MiB of fragments are read whole, and
  one byte more ends the session with a Close 1009.
- `cargo test -p podssh-relay --test limits`: 3 passed. A pool of 256 KiB is read and one byte
  more refused, an endless pool body stops past the bound, and a file of the cache of 64 KiB is
  read and one byte more ignored, the pool's and a token's.
- `cargo test -p podssh-ssh --test known_hosts`: 17 passed. A file of 16 MiB is read; one byte
  more is unreadable, with its reason, and a record into it is refused, the file unchanged.
- Planted, natively: without the check of fragments
  (`crates/podssh-ws/src/session.rs:336-338`), a message of 16777217 bytes came through, and the
  test failed; without the bound of `known_hosts`, the larger file was read, and the test failed.
- In the build image, `scripts/interop-limits.sh` alone with the Prove's plants: as the code is, a
  reader that took each byte peaked at 6884 KiB, and one that took nothing for 30 s at 7460 KiB,
  under the ceiling of 24414 KiB; with the window at 64 MiB, 9444 and 8948 KiB, held by russh's
  queue; with the queue at 2^20 messages as well, 62084 and 62708 KiB, and both checks failed. The
  step `release` (`sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh release'`): interop 303
  passed, 0 failed, the reader that took each byte at 6836 KiB and the other at 7160 KiB, each
  harness at its floor (limits 2), and "gate green (release)".

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
- The joining of fragments (`crates/podssh-ws/src/session.rs:330-354`). It is
  private, but `RelaySession::new` (`crates/podssh-ws/src/session.rs:82`) takes
  any stream, so a test can drive it.
- Relay lists and paths (`crates/podssh-relay/src/relay.rs:107-183`, `crates/podssh-ws/src/names.rs:8-57`).
- `known_hosts` patterns (`crates/podssh-ssh/src/known_hosts.rs:277-333`).
- The escape filter, which keeps its state from one read to the next
  (`crates/podssh-ssh/src/escape.rs:43-79`).
- The sanitizer (`crates/podssh-ws/src/text.rs:12-57`).

Read: no crate uses a library for property tests. `proptest` is pure Rust;
the gate must show it.

## Approach

1. `proptest` as a dev-dependency of podssh-ws, podssh-relay and podssh-ssh.
   The gate's library test step runs under `CC=/nonexistent` and
   `CXX=/nonexistent` (`scripts/gate.sh:163-165`), so it shows that no C comes
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

**Source:** `docs/design.md:267-269` (layers 2 and 3 need the harness
extended), and the exit criteria of M6 (`docs/ROADMAP.md`, M6; T-156).
**Category:** chore
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** done

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
  `stall` and `close` (`scripts/fake-relay.py:18-27`). The stand-in proxy maps
  names and answers a status (`scripts/fake-proxy.py:1-27`). Neither shapes
  the traffic.
- `scripts/interop-faults.sh:42-50` starts one stand-in for each fault; its
  checks are at lines 73-182 at `8d668b7` (`docs/STATUS.md:357-375`, 14 of 14 since T-236).
- The time limits that latency meets today: the SSH handshake, 60 s
  (`crates/podssh-ssh/src/options.rs:370`, enforced at
  `crates/podssh-ssh/src/run.rs:356-362`); a reply, 30 s
  (`crates/podssh-ssh/src/session.rs:21`); a write, 60 s, and liveness, three
  times 10 s (`crates/podssh-ws/src/client.rs:31-35`).
- The gate's container gets no added capability
  (`.github/workflows/build.yml:68-79`).

## Approach

1. New modes in `scripts/fake-relay.py`, applied in `pump` (lines 173-293 at `981b8fc`), in
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
5. Update docs/development.md (item 8 of the gate, item 9 since T-156,
   `docs/development.md:282-294`) and the faults table of docs/STATUS.md.

Pitfall: each check must show that its fault was injected (see Prove).

## Decision

Recommendation: shape the traffic in the stand-ins. They need no privilege,
and they run the same in the gate's container, in CI and on Windows. Linux
`tc netem` lost: it needs `CAP_NET_ADMIN`, which the gate's container does not
get, and it shapes all loopback traffic, the OpenSSH servers too.

2026-10-10, before the work:

- The new modes shape each direction in the stand-in relay's pump with a
  queue and a sender, so that order is kept: a jittered chunk waits for the
  one before it, as a TCP stream does. `rate` is a token bucket over each
  direction alone, as a link's capacity is.
- One more mode for T-156, which needs a stall that ends: `pause:AFTER:FOR`,
  each byte held both ways after AFTER seconds for FOR seconds, then let
  through. And the stand-in proxy's `--move SECONDS:ADDRESS`: SECONDS after
  the first tunnel, the open tunnels go silent with no RST, and each new
  tunnel leaves from ADDRESS (127.0.0.2), as a client whose address changed.
- The checks of item 3 also run natively, in an ignored Rust test that
  drives `podssh ssh` through the stand-in relay to the tests' SSH server
  (`crates/podssh-cli/tests/faults.rs`): a Windows run measures the modes now,
  where the gate's run waits for T-251.

## Prove

```sh
sh scripts/dev.sh check     # interop-faults: the delay, jitter, rate and cut checks pass
```

The faults section shows each new check as `ok`. Planted defect, built into
the harness as a control: the delay check of 2 s runs again with
`-o ConnectTimeout=5`, and it must fail with "did not finish within 5 s".
This shows that the delay was injected. After M6, the checks of T-156 must
fail when the resume layer is off.

## Correction

Item 4 needs the reverse road in the stand-in relay, which serves the
forward road only (`scripts/fake-relay.py:97-98`). T-156 builds it (its
item 1) and makes those checks its measurement (its items 2 to 5). T-203
gives T-156 the faults that those checks need: `pause:AFTER:FOR` for the
stall that ends, `cut` for a host stopped mid-session, and `--move` for the
new address.

## Done

2026-10-10.

- `scripts/fake-relay.py`: the modes `delay:MS`, `jitter:MIN:MAX:SEED`,
  `rate:BYTES`, `cut:BYTES` and `pause:AFTER:FOR`. Each direction has a
  shaper, a bounded queue in order: each frame to the client (data, Pongs,
  keepalives, Closes) and each chunk to the target goes through it, so a
  pause holds the Pongs too, and a Close waits for the bytes before it.
- `scripts/fake-proxy.py`: `--from ADDRESS` and `--move SECONDS:ADDRESS`;
  the log names the address of each tunnel.
- `scripts/interop-faults.sh`: four stand-ins more, and the checks of item
  3 with the planted control of the delay.
- `crates/podssh-cli/tests/faults.rs`, ignored: the same checks natively,
  through the tests' SSH server (which gained `echo`), and checks of `pause`
  and `--move`; the harness of T-157 starts a stand-in relay of any mode.
- Prove, native, Windows: `cargo test -p podssh-cli --test faults --
  --ignored --test-threads 1`: 6 passed, in about 3.5 minutes; the table is
  in `docs/STATUS.md`. `sh -n` and `scripts/check-scripts.py` (dash): the
  script parses. `cargo test --no-fail-fast`: 1014 passed, 0 failed, 30 ignored.
- Waits for T-251: `sh scripts/dev.sh check`, whose step of the faults runs
  the new checks with OpenSSH in the build image. The checks of item 4 are
  T-156's (the Correction).

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

- The matrix is at `scripts/interop.sh:114-124`. It expects 3, 0, 1, 127 and
  143, against OpenSSH (port 2201) and Dropbear (port 2203). `grep -c` gives
  17 lines with `expect_rc`, each a call; the helper is
  `scripts/interop-lib.sh:53-60` (T-199). `scripts/interop-keygen.sh` has 6
  more, for `podssh keygen`.
- `scripts/interop.sh` (lines 31-32 at `5c7a1ad`) installed `openssh-server`,
  `openssh-keygen` and others, but no client package. No harness ran the stock `ssh`; only
  `scripts/sandbox-check.sh:204-217` does, in a sandbox. Nobody knows whether
  the gate's image has `/usr/bin/ssh`.
- `crates/podssh-ssh/src/io.rs:309-316`, with `crates/podssh-ssh/src/io.rs:48-50`,
  maps an exit status that does not fit
  (the -1 of `railway.new`) to 255, and an exit signal to 128 plus its number
  (`docs/STATUS.md:71`, `docs/STATUS.md:75`).
- A correction to the framing of #34: for a signal, podssh differs from
  OpenSSH on purpose. `docs/cli.md:1270-1271` says 128 plus the signal's number,
  and that OpenSSH gives 255. `crates/podssh-ssh/src/lib.rs:16` says that the
  codes follow OpenSSH, with 128 plus a signal. The two texts disagree, and no
  record measures the code of OpenSSH.

## Approach

1. Settle the client first: in the gate's container, run `command -v ssh`
   before the package line. If it is missing, add the client package to
   `scripts/interop.sh:24`, and print its version (as `:95` does for the
   servers).
2. For each call of `podssh ssh` in the matrix and in the refusals (lines
   146-196), run the stock `ssh` first, with the same server, port, key,
   `known_hosts`, `BatchMode` and command, and a time limit. Record its exit
   code. Then run podssh and compare.
3. A table of the intended differences, each with its reason. Today one row:
   a signal (OpenSSH's code, against 128 plus the number;
   `docs/cli.md:1270-1271`). A difference that the table does not name fails,
   with both codes and the command.
4. Keep each literal as a second check with its own name, so that a change
   gives two named failures: "differs from OpenSSH" and "differs from the
   promise".
5. Refuse a reference of 0 for a case that must fail, so that a broken
   reference cannot pass.
6. Make `crates/podssh-ssh/src/lib.rs:16` and `docs/cli.md:1270-1271` agree with
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
map an exit signal to 255 at `crates/podssh-ssh/src/io.rs:316`; the literal
check of 143 must fail, and the table must report its signal row as broken.
Planted defect 2: let the reference run `true` in place of `exit 3`; the
derived check must fail.
