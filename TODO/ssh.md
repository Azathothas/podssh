The SSH client of `podssh ssh`: the messages of a refused login and of a
dropped session, exit codes, host keys and `known_hosts`, and client
features that need no local listener.

# T-023: With `PubkeyAuthentication=no`, the denial still says "no key was offered; use -i FILE" (GitHub #7)

**Source:** GitHub #7 (Nemo-010, 2026-10-08), measured by the reporter
through the relay with the static release binary, and again on `3a88e1d`.
Read here on `3ee70dc`; not measured here, because it needs a server.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

With `-o PubkeyAuthentication=no`, a refused login still ends with the note
"no key was offered: no agent answered and none of these could be used: ...;
use -i FILE". The user turned keys off, so the note names a wrong cause and a
wrong remedy. The same note comes when `PreferredAuthentications` leaves out
`publickey`, or when the server does not accept `publickey`.

## Premise

Read:

- `resolve` removes `publickey` from the methods when `PubkeyAuthentication`
  is `no` (`crates/podssh-cli/src/ssh/login.rs:59-67`). The chain then
  never offers a key (`crates/podssh-ssh/src/auth.rs:111-113`).
- The denial adds the notes of the keys with no condition
  (`crates/podssh-ssh/src/auth.rs` line 115 at `475aea9`). `PublicKeys::notes` writes "no key
  was offered" when nothing was offered (`crates/podssh-ssh/src/keys.rs:138-151`).
- The reporter's output (GitHub #7): the line
  `Permission denied (publickey,keyboard-interactive).`, the note about
  keyboard-interactive, then the wrong note.
- The gate's check "password with BatchMode" runs this case against OpenSSH
  (`scripts/interop.sh:183-186`). It only looks for the password note, so its
  output holds the wrong note today (inferred, not measured).

## Approach

1. In `authenticate`, add the notes of `PublicKeys` only when `publickey` is
   in `opts.methods` and in the server's first answer
   (`crates/podssh-ssh/src/auth.rs` lines 64-68 at `9fefff2`). Keep that first list: `allowed`
   changes in the loop.
2. When the user turned `publickey` off, write one true note instead:
   "publickey was not tried: -o PubkeyAuthentication=no", or
   "PreferredAuthentications does not list publickey". The module's rule is
   that a refusal says what was tried and what helps
   (`crates/podssh-ssh/src/auth.rs:8-9`).
3. When the server does not accept `publickey`, say nothing about keys:
   `-i FILE` cannot help.
4. Give the note about skipped encrypted keys
   (`crates/podssh-ssh/src/keys.rs:152-158`) the same condition as step 1.
5. Keep `PublicKeys::new` for each login (`crates/podssh-ssh/src/auth.rs:106`),
   so that only the notes change. No document changes: `docs/cli.md:2717-2772`
   already says that a refusal names the remedy.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- denial_notes
sh scripts/dev.sh check
```

The first runs a new unit test in `crates/podssh-ssh/src/auth.rs`. It tests
a pure function that builds the notes from the methods, the server's first
list and the keys offered: no key note when `publickey` is off or not
accepted, and the old note when keys were tried and failed. Planted defect:
put back the unconditional `notes.extend`, and the test fails. The second
runs the gate, where `scripts/interop.sh:183-186` also asserts that the
output has `publickey was not tried` and not `no key was offered`.

## Done

2026-10-08, in the commit "A refusal names keys only when keys were
tried".

- `auth::key_notes`, a pure function: the notes about keys only when
  `publickey` was among the methods and the server accepted it at first
  (the first list is kept, since `allowed` changes in the loop); else no key
  note. When the user turned `publickey` off, one note: "publickey was not
  tried: -o PubkeyAuthentication=no", or "... PreferredAuthentications does
  not list publickey". `Options` carries that reason (`publickey_off`), set
  where `resolve` removes the method. The note about skipped encrypted keys
  comes from the same key notes, so it has the same condition.
- `cargo test -p podssh-ssh -- denial_notes`: passes. Planted (the function
  returns the key notes with no condition): it fails.
- `scripts/interop.sh` asserts the note against OpenSSH. Planted, with the
  gate's binary of `3cd368b` (before this change), in the container: "FAIL
  keys turned off: the wrong note", with "no key was offered: no agent
  answered and none of these could be used: ...; use -i FILE"; interop 99
  passed and 1 failed. With this change, `sh scripts/dev.sh check`: green,
  interop 100 of 100.
- Found on the way: two scripts of T-057 built the new numbers of
  `docs/STATUS.md` (the faults, the gate, the man page, the binary size)
  and never wrote them. The numbers of this gate run are there now.

# T-024: The first line about a dropped session is generic; name the hop that broke (GitHub #17)

**Source:** GitHub #17 (talaria0101, 2026-10-08) and its comments; sandbox A
of T-001 (edge KTM), where `scripts/sandbox-check.sh` met the same drop. The
reporter used the static release binary. Read here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

When the relay drops a session, `podssh ssh` prints a generic line first,
then the relay's reason:

```text
podssh: railway.new: the connection closed unexpectedly
podssh: the relay closed the connection (code 1011): write failed: Network connection lost.
```

The first line does not say which hop broke: the link to the relay, the
relay's link to the target, or the SSH server. The reason that an SSH server
sends with its disconnect is not shown at all.

## Premise

Read:

- `describe` maps `Disconnect`, `HUP`, `RecvError`, `SendError` and an
  unexpected EOF to one sentence (`crates/podssh-ssh/src/run.rs:425-431`).
  `run` prints it first, and the relay's reason second
  (`crates/podssh-ssh/src/run.rs` lines 38-46 at `80f20bf`,
  `crates/podssh-ssh/src/relay_stream.rs:51-67`).
- The form `HOST: the connection closed unexpectedly` comes only from the
  handshake (`crates/podssh-ssh/src/run.rs` lines 108-122 at `80f20bf`).
  Thus both reported drops happened before the first key exchange ended.
- The handler keeps no SSH_MSG_DISCONNECT: it has no `disconnected` callback
  (`crates/podssh-ssh/src/handler.rs` lines 31-59 at `80f20bf`), and the
  default of russh 0.64.1 drops the reason.
- The relay's contract gives no close codes for the forward path;
  `docs/relay.md:244-256` lists them, read from the relay's source.
  `1011 write failed: ...` means that the relay could not write to the
  target. The KTM report saw it with 0 bytes, on a target that the relay
  could dial but not use (read in the report, not verified here).
- The reporter's second comment reads `1011` as "relay backpressure, over 1
  MiB queued". That row is in the contract's table of reverse close codes
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:160-166`, row
  `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`). On the
  forward path, backpressure closes with `1013` at 2 MiB (`docs/relay.md:255`,
  `docs/relay.md:266-278`). The comment on the SSH window
  (`crates/podssh-ssh/src/run.rs` lines 25-29 at `80f20bf`) also cites the
  reverse row.

## Approach

1. Classify a forward-path close in one place, next to
   `close_code_and_reason` (`crates/podssh-ws/src/close.rs:19-27`), which
   `podssh ssh` and `podssh proxy` both use. Map the code and the reason of
   `docs/relay.md:249-256` to a hop. Relay to target: `1011` with
   `connect failed`, `write failed`, `target closed before sending anything`
   or `wrong target banner`, and `1013 target write backlog`. Client to
   relay: `1011` with `client send failed` or `client error`,
   `1013 client receive backlog`, and no Close. A relay limit: `1001`,
   `1009`. A normal end: `1000`. Give an unknown code as it is.
2. Keep the server's SSH_MSG_DISCONNECT: implement `Handler::disconnected` in
   `crates/podssh-ssh/src/handler.rs`. Store the reason code and the text,
   made safe with `podssh_ws::text::one_line`, as the handler stores
   `refusal` (`crates/podssh-ssh/src/handler.rs:39-41`).
3. In `run` (`crates/podssh-ssh/src/run.rs` lines 34-48 at `80f20bf`), write one first line from
   three sources, in this order: a relay close other than 1000, the server's
   disconnect, then `describe`. Example: "railway.new: the relay lost its
   connection to railway.new:22 (relay close 1011: write failed: Network
   connection lost.)". Keep the code and the reason verbatim:
   `scripts/interop-faults.sh:240` looks for them.
4. Write a second line that says what to do. For the hop from the relay to
   the target: another relay host (`--relay-host`), and
   `podssh relay trace HOST:PORT` when T-058 exists.
5. Use the same classification in `podssh proxy`
   (`crates/podssh-cli/src/proxy.rs` lines 252-280 at `80f20bf`). Keep `CODE REASON` in its line:
   `scripts/interop-faults.sh:261` looks for `1009 session byte cap`.
6. Correct the comment on the window (`crates/podssh-ssh/src/run.rs` lines
   25-29 at `80f20bf`). The window of 512 KiB stays: it is below both limits.
7. Update `docs/relay.md` (lines 155-158 at `80f20bf`) and `docs/STATUS.md:536`. T-025 uses the
   classification for its retry rule. T-227 is a different path
   (`--direct`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws -- forward_close
cargo test -p podssh-ssh -- first_line
sh scripts/dev.sh check
```

The first test has one case for each row of `docs/relay.md:249-256`, and one
for an unknown code. The second builds the first line from each kind of
`RelayEnd`, from a server disconnect, and from a bare russh error. In the
gate, a new stand-in relay in `scripts/interop-faults.sh` (mode
`close:1:1011`, with its name added at `scripts/interop-faults.sh`, lines 11-12 at `981b8fc`) drops
the session during the handshake. The first line must name the relay's link
to the target and keep `write failed: fault injection`, and must not be the
generic sentence. Planted defect: return `describe` alone, and that check
fails.

## Done

2026-10-08, in the commit "A dropped session names the hop that broke".

- `forward_close` in `crates/podssh-ws/src/session.rs` maps each code and
  reason of the forward path to a part: the relay's link to the target, the
  link between podssh and the relay, a limit of the relay, a normal end, or
  an unknown code. Each part has a sentence and a remedy (`--relay-host`,
  `podssh doctor`, and the idle cut, the byte cap and the time cap).
- `podssh ssh`: `failure_lines` in `crates/podssh-ssh/src/run.rs` writes
  the first line from a relay close other than 1000 (or a link that broke
  with no Close), else from the server's disconnect, which the handler now
  keeps, else from `describe`. The code and the reason stay as the relay
  wrote them. `podssh proxy` uses the same parts.
- The comment on the SSH window cites the forward path: `1013` at 2 MiB.
- `docs/relay.md` (the close codes) says what podssh prints.
- Prove: `cargo test -p podssh-ws -- forward_close` (each row of the table
  and an unknown code) and `cargo test -p podssh-ssh -- first_line` passed.
  `sh scripts/dev.sh check`: green; interop 101 of 101, and the new check
  "closed with 1011 during the handshake: the first line names the relay's
  link to the target" passed.
- Plant: the gate's binary of `475aea9` (before this entry), run in the
  container with `scripts/interop.sh`. The new check failed, as it must:
  "first line: podssh: 127.0.0.1:2201: the connection closed unexpectedly".
- Left for T-058: the remedy names `podssh relay trace HOST:PORT` when that
  command exists.

# T-025: Try a dropped forward session again when it is safe, by the relay's close reason (GitHub #17)

**Source:** GitHub #17, and the comments of talaria0101 on #17, #19 and #25
(2026-10-08); GitHub #25 (the retry and backoff ask, from the
ImKKingshuk/USBoverSSH report). Measured by the reporter; read here on
`3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A relay drop ends `podssh ssh` with 255, also when nothing has run on the
server yet. One reporter saw 1 drop in 180 short sessions from one edge
(KTM), and one more in a run of `scripts/sandbox-check.sh`. A script cannot
retry safely: it cannot tell a drop before the command started from a drop
after it.

## Premise

Read:

- `podssh_relay::open` fails over and repeats rounds only until the
  WebSocket upgrade succeeds (`crates/podssh-relay/src/open.rs:200-277`).
  After the upgrade, a relay close ends the run
  (`crates/podssh-ssh/src/run.rs`, lines 38-47 at `981b8fc`).
- Both reported drops printed `HOST: the connection closed unexpectedly`,
  which only the SSH handshake prints (`crates/podssh-ssh/src/run.rs:368-390`).
  At that point no request has reached the server.
- The command starts with the exec, shell or subsystem request
  (`crates/podssh-ssh/src/session.rs:118-145`). `-W` reads stdin only after its
  channel opens (`crates/podssh-ssh/src/forward.rs:39-70`). `-N` never reads
  stdin (`crates/podssh-ssh/src/run.rs:208-250`).
- Measured by the reporter (read in the reports, not verified here): on one
  target the drop came back 3 times in 3, while other targets worked in the
  same minute, also with a client that shares no code with podssh. A blind
  retry can fail again.
- `podssh proxy` is a byte pipe and cannot know when a replay is safe. This
  entry is for `podssh ssh` only.

## Approach

1. Make `run_inner` (`crates/podssh-ssh/src/run.rs:180-264`) report the phase
   that a failure reached: the handshake, the authentication, the session
   request sent, or data moved. Keep the exit codes of OpenSSH.
2. In `connect_and_run` (`crates/podssh-cli/src/ssh/mod.rs`, lines 99-126 at `97146aa`, which
   reaches the relay through `crates/podssh-cli/src/ssh/transport.rs:167-208`), open a
   new relay session and run again only when the failure came before the
   session request, and before `-W` read a byte of stdin.
3. Decide by the close, with the classification of T-024. The link from the
   client to the relay, or no Close: go to the next relay host, as `open`
   does for a failed upgrade (`crates/podssh-relay/src/open.rs:60-84`). The
   link from the relay to the target: try once more, then stop. Never retry
   `1001`, `1009` or `1013`.
4. Wait with the jittered backoff that exists
   (`crates/podssh-relay/src/open.rs:379-393`). Bound the whole by the rounds
   of `ConnectionAttempts` (`crates/podssh-cli/src/ssh/resolve.rs:468`) and
   the deadline of each host.
5. Never prompt again without a person: under `BatchMode`, or with no
   terminal and no `SSH_ASKPASS`, a retry that needs a prompt stops. Keep a
   typed password in memory (zeroized) for the retry; do not ask twice.
6. Say each retry on stderr, with the hop and the reason. Document the rule
   in `docs/cli.md:2647-2715`, and add a row to `docs/STATUS.md`.

## Decision

Recommendation: retry inside podssh, and only before the session request.
Only podssh knows whether the request was sent, and `podssh ssh` keeps the
exit code 255 of OpenSSH (`docs/cli.md:2657-2660`). The alternative, a distinct
exit code for the caller to retry on, lost: it breaks scripts that expect
OpenSSH's codes, and a caller that retries each 255 runs a command twice.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- retry_phase
sh scripts/dev.sh check
```

The unit test checks the rule: which phases and which closes allow a retry.
In the gate, `scripts/fake-relay.py` gets a mode that drops only its first
session during the handshake, beside the modes at
`scripts/fake-relay.py:18-30`. Through it, `exit 5` still gives 5, with one
retry note. A second case drops after the exec request: exit 255, and a file
that the command appends to has one line. Planted defect: retry in each
phase, and that file has two lines.

## Done

2026-10-11. `podssh ssh` tries a session again when the relay dropped it
before any request reached the destination:

- `crates/podssh-ssh/src/retry.rs` keeps how far the run got (the
  handshake, the login, logged in, a request sent), and `retry_phase` is
  the rule: before the request only; the next relay host for a drop of the
  link to the relay or no Close; once more for the relay's link to the
  target; never 1001, 1009 or 1013, nor a frame that broke RFC 6455, nor
  a failure with no drop of the relay (a refusal, a host key, a login).
- The request is the command, the shell or the subsystem
  (`crates/podssh-ssh/src/session.rs`), the connection of `-W`, the
  forwards of `-R`, and the wait of `-N`.
- `run_outcome` gives the code, the rule's answer and the lines of the
  failure; `connect_and_run` tries again (`tries` in
  `crates/podssh-cli/src/ssh/mod.rs`) with the backoff of a failed upgrade,
  the relay hosts turned for the next host (`transport::reach_skipping`),
  at most `ConnectionAttempts` times the relay hosts, and says each try on
  stderr. A try after the first asks nothing: a key that a passphrase
  opened and a password that the server took are used again (as
  `--persist`), and a login that needs a prompt stops.
- `scripts/fake-relay.py` has `dropfirst:BYTES:CODE` and
  `dropfirstat:SECONDS:CODE`; the test's SSH server has `append PATH STATUS
  DELAY`. `docs/cli.md` and THE RELAY in the manual say the rule.

Prove, native, Windows: `cargo test -p podssh-ssh -- retry_phase`, 3
passed; `cargo test -p podssh-cli --test faults -- --ignored drop`, 2
passed: a drop during the handshake (the relay lost the target) is tried
once more, with one note, and the status 5 comes back, the command run
once; a drop 3 s after the command started gives 255, no try, and one run.
Planted (the Prove's plant): a retry in each phase failed the unit test,
and the second case's command ran again (exit 0 where 255 was due).

In the build image (`sh scripts/dev.sh run`, a debug build of the binary),
2026-10-11: `scripts/interop.sh` 239 passed, 0 failed, with the gate's two
cases against OpenSSH: a drop during the handshake is tried once more and
the command runs once (exit 5); a drop after the command started is not
tried again (exit 255, one run). The planted run in the build image waits
for T-251.

# T-026: A session that ends with no exit status never reads as a success

**Source:** GitHub #23 (the ask "Never report success when the session died
without an exit status"), and the sleepinginsummer/agent-ssh-cli report in
GitHub #21 (item 10). Read here on `3ee70dc`.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A script must not read exit 0 when the server gave no exit status. podssh
follows OpenSSH on its main path, but two paths still give 0 with no status:
`-N` ended by the server, and a closed stdout before the status came. The
exit codes of OpenSSH for these paths are not measured.

## Premise

Read:

- A channel that closes with no `exit-status` and no `exit-signal` gives 255
  (`crates/podssh-ssh/src/io.rs`, line 226 at `8cf2587`,
  `crates/podssh-ssh/src/session.rs:19-20`,
  `crates/podssh-ssh/src/session.rs:41`). A channel that ends with no Close
  is `Lost`: an error, and 255 (`crates/podssh-ssh/src/io.rs:273`,
  `crates/podssh-ssh/src/session.rs:42`).
- A closed stdout (EPIPE) gives the status so far, or 0 when none came
  (`crates/podssh-ssh/src/io.rs`, lines 200-204 at `8cf2587`).
- `-N` gives 0 when the connection ends with no error
  (`crates/podssh-ssh/src/run.rs`, lines 141-149 at `8cf2587`). russh 0.64.1 ends the session with
  no error when the server sends SSH_MSG_DISCONNECT.
- `-W` gives 0 when the far end closes and when stdout closes
  (`crates/podssh-ssh/src/forward.rs:78-82`), and 255 when the connection
  died (`crates/podssh-ssh/src/forward.rs:102-109`).
- An exit status above 255 gives 255 (`crates/podssh-ssh/src/io.rs`, lines
  209-211 at `8cf2587`).
  OpenSSH passes the value to `exit()`, so 256 reads as 0 there. podssh's
  rule is safer, and stays.
- `docs/cli.md`, line 610 at `8cf2587`, says only that a closed stdout ends
  the session cleanly.

## Approach

1. Measure first, in `scripts/interop.sh`, with the `ssh` of OpenSSH as the
   control: the client is in the image since T-238 (`openssh-client-default`,
   `scripts/interop.sh:24-25`). Compare the exit codes of both clients for:
   `-N` ended by the server (sshd with `UnusedConnectionTimeout 2`); `'yes'`
   into `head -c 1` (a closed stdout); `-W` when the far end closes; `-W`
   when stdout closes.
2. Where podssh gives 0 and OpenSSH does not, follow OpenSSH. For a closed
   stdout: stop writing, send EOF, wait at most 5 s for the status, then give
   it, or 255 with a note.
3. For `-N`, print the server's disconnect reason (T-024), and use the
   measured code.
4. Make the mapping from `io::End` to an exit code a pure function in
   `crates/podssh-ssh/src/session.rs`, with a test for each variant.
5. Write the measured rule in `docs/cli.md:2647-2715`, and the measurement in
   `docs/STATUS.md`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- exit_code_of_end
sh scripts/dev.sh check
```

The unit test covers each `End` variant, a status of 256, and a closed
stdout before and after the status. In the gate, `scripts/interop.sh` asserts
that podssh's code equals the code of OpenSSH for the four cases of step 1,
and that a case with no status never gives 0. Planted defect: make
`End::NoStatus` give 0, and the unit test fails.

## Correction

The title is a goal that podssh already meets on its main path: a Close or a
lost channel with no status gives 255. The open work is `-N`, a closed
stdout, and `-W`. Also, `docs/STATUS.md`, line 76 at `8cf2587`, says that
Tailscale SSH sends no status for a login shell, and that both clients exit
0. With no status, podssh gives 255
(`crates/podssh-ssh/src/session.rs:41`), so that server probably sends an
exit status of 0. Check it with `ssh -v` of OpenSSH, which
logs each `exit-status` request, and correct the row.

## Done

2026-10-11. `podssh ssh` never ends as a success with no exit status:

- A closed stdout: podssh stops writing, sends the end of input, and waits
  `io::STATUS_WAIT` (5 s) for the status. It gives that status, whether it
  came before or after the close, or 255 with a note
  (`crates/podssh-ssh/src/io.rs`: `Out`, `end_with`).
- `-N` that the server ends: 255, with the words of the server's
  SSH_MSG_DISCONNECT (`handler::take_last_disconnect`, read in
  `crates/podssh-ssh/src/run.rs`). A connection that broke was 255 already.
- `-W` keeps 0 when the far end closes and when stdout closes, and 255 when
  the connection died; the interop run compares it with OpenSSH.
- `io::status_code` maps an `exit-status` request: 255 above 255.
  `session::code` maps each `End`, with a test for each variant.
- `docs/cli.md` (the exit codes) and the manual's row of 255 say the rule.
  The Tailscale row of `docs/STATUS.md` is corrected as far as the record
  allows: podssh gave 255 then too for a Close with no status, so that 0
  was a status of 0 from the server.

Prove, native, Windows: `cargo test -p podssh-ssh -- exit_code_of_end`, 3
passed; `cargo test -p podssh-cli --test ssh_exit_status`, 3 passed, against
the test's SSH server, which gained `spew`, `spew-mute` and the user `kick`.
Planted, each restored: `End::NoStatus` as 0 failed two unit tests;
OpenSSH's `exit(256)` (the status masked to 8 bits) failed one; the old rule
of a closed stdout (the status so far, or 0) failed
`a_closed_stdout_with_no_status_is_never_a_success`; the old rule of `-N`
(0) failed `a_dash_n_session_that_the_server_ends_is_255_with_its_words`.

Waits for T-251, which names both: the run of `scripts/interop.sh` in the
build image, whose `scripts/interop-status.sh` compares the codes of OpenSSH's `ssh` and of podssh for
the four cases of step 1 and asserts that `-N` and `yes` never give 0; and
the check of the Tailscale row with `ssh -v`, as the two tailnet hosts were
offline on 2026-10-11.

2026-10-11, in the build image (`sh scripts/dev.sh run`, a debug build of the binary): `scripts/interop.sh` 237 passed, 0 failed, in 480 s: the four cases give OpenSSH's codes (255, 255, 0
and 0), and `-N` and `yes` never 0. Before it, CI's step `release` at
`bc59415` hung until its limit: the block's new sshd took port 2205, which
`scripts/interop-cp.sh` uses, and its clients had no time limit. Repaired:
port 2210, the sshd stopped after the block, and each client ended at 60 s.
The planted runs in the build image wait for T-251.

CI at `615c415` failed once in the gate's step `iroh`: `tests/ssh_exit_status.rs` read 64 KiB of
`spew-mute` before it closed stdout, but podssh had no stdin, so it sent the end of input at
once, and `spew-mute` stops at the end of input: under load, fewer than 64 KiB came
(`UnexpectedEof`). The test now holds stdin open, so that the remote writes until podssh itself
sends the end of input when its stdout closes, which is the case of step 1. 2026-10-11:
`cargo test -p podssh-cli --test ssh_exit_status` passed 20 runs in a row on Windows, and 20 in
the build image (`sh scripts/dev.sh run`).

# T-027: Host certificates and `@cert-authority` in `known_hosts` (GitHub #29)

**Source:** GitHub #29 (2026-10-08; read by the reporter, not measured); the
lablup/bssh report in GitHub #18, #20 and #22 (item 8, "`@cert-authority`
rejection"); the known gap in `docs/STATUS.md`, line 314 at `33c9a31`, and `SECURITY.md`,
lines 131-133 at `33c9a31`.
Each claim read again here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A host that the user trusts through a `@cert-authority` line, and through no
plain key line, cannot be reached. Under strict checking, or with no
terminal, podssh refuses it as unknown. With `accept-new`, podssh records the
host's plain key, and the trust in the CA is lost for that host: the user
ends up with pinned keys where the CA was the intent.

## Premise

Read:

- `known_hosts` parses the marker (`crates/podssh-ssh/src/known_hosts.rs:34-40`,
  `crates/podssh-ssh/src/known_hosts.rs:258`), and the lookup uses only lines
  with no marker, besides `@revoked`
  (`judge`, `crates/podssh-ssh/src/known_hosts.rs:112-129`). `CertAuthority` has two
  hits in `crates/` and `docs/`: the definition and the parse.
- The check takes the plain key of what russh gives
  (`crates/podssh-ssh/src/handler.rs`, line 99 at `33c9a31`). The comment at
  lines 96-98 there says that OpenSSH falls back the
  same way when no CA line matches; podssh never looks for a CA line.
- The refusal comes from the policy: `crates/podssh-ssh/src/hostkey.rs:189-193`
  (`yes`), `crates/podssh-ssh/src/hostkey.rs:199-203` (BatchMode),
  `crates/podssh-ssh/src/hostkey.rs:227-234` (no terminal). `accept-new`
  records the plain key (`crates/podssh-ssh/src/hostkey.rs:198`). GitHub #29
  cites line 91 at `22c3b88`, which builds the question about other key types.
- `ssh-key` 0.7.0-rc.11 is in the tree (`Cargo.lock:5484-5485`).
  `Certificate::validate_at` checks the signature, the SHA-256 fingerprint of
  the CA and the validity window. The caller must check the certificate type,
  the principals and the critical options (the crate's documentation).

## Approach

The order of GitHub #29: parse the certificate, look up a CA line, and fall
back to the plain key only when no CA line matches.

1. Ask for certificates: when a `@cert-authority` line matches the name of a
   hop, set `host_key_certificates` in `client_config`
   (`crates/podssh-ssh/src/run_config.rs:17-71`) to the algorithms of
   `preferred.key`. A host with no CA line keeps today's negotiation.
2. Add a lookup of CA keys in `crates/podssh-ssh/src/known_hosts.rs`, beside
   the `@revoked` arm (`crates/podssh-ssh/src/known_hosts.rs:113-115`). Match CA
   lines with the name `host` or `[host]:port`
   (`crates/podssh-ssh/src/known_hosts.rs:89-96`).
3. In `check_server_key` (`crates/podssh-ssh/src/handler.rs:124-146`), branch on
   `PublicKeyOrCertificate`. For a certificate: `validate_at` with the clock
   and the fingerprints of the matching CA keys; the type must be `host`; a
   principal must equal the host name or `HostKeyAlias`, with no port;
   refuse unknown critical options; refuse a `@revoked` CA key or host key.
   On success, accept and record nothing.
4. A certificate from a CA that matches no line: check its plain key as
   today, as OpenSSH does. A certificate from a matching CA that fails a
   check: refuse, and name the check (expired, principal, type). Each refusal
   prints the host key's fingerprint and the CA's fingerprint.
5. In an expiry refusal, name the clock: a sandbox clock can be wrong
   (`crates/podssh-cli/src/doctor/clock.rs`).
6. Keep the test `a_cert_authority_line_does_not_make_a_key_known`: a CA line
   never makes a plain key known. Correct `crates/podssh-ssh/src/handler.rs`, lines
   96-98 at `33c9a31`. When certificates work, change `docs/STATUS.md`, line 314 at
   `33c9a31`, and `SECURITY.md`, lines 131-133 at `33c9a31`.

GitHub #29 notes that the bssh report in #18, #20 and #22 asks podssh to
keep refusing a certificate that no trusted CA signed. Verification keeps
that refusal, so the two asks agree.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test known_hosts -- cert_authority
sh scripts/dev.sh check
```

The tests in `crates/podssh-ssh/tests/known_hosts.rs` make certificates with
`ssh-key`. A CA-signed host key is accepted under strict checking, and
nothing is recorded. A certificate whose CA is not in the file is refused,
and the message has both fingerprints. An expired certificate, a wrong
principal, a user certificate and a revoked CA are refused. In the gate,
`scripts/interop.sh` signs sshd's host key with
`ssh-keygen -s CA -h -n 127.0.0.1`, sets `HostCertificate`, and runs podssh
with a file that holds only a `@cert-authority` line: exit 0 under
`StrictHostKeyChecking=yes`.
Planted defect: accept each certificate, and the wrong-principal test fails.

## Correction

GitHub #29 says that podssh drops a certificate that russh gives. In fact no
certificate comes: russh 0.64.1 offers certificate algorithms only from
`Preferred::host_key_certificates`, which is empty by default, and
`client_config` does not set it (`crates/podssh-ssh/src/run_config.rs:17-71`). So
a server always presents its plain key. The words "checked as plain keys"
in `docs/STATUS.md` and `SECURITY.md` were not exact either: podssh never
asks for a certificate. They were corrected in the change that wrote this
entry. The effect that GitHub #29 gives is correct.

## Done

2026-10-11. podssh checks host certificates against the `@cert-authority`
lines, in the order of GitHub #29:

- `client_config` asks for certificates, of each algorithm of
  `preferred.key` but SHA-1 RSA, when a `@cert-authority` line names the
  hop (`hostcert::trusted_for`); a host with no CA line keeps today's
  negotiation.
- `crates/podssh-ssh/src/hostcert.rs`: a certificate's host key or CA
  marked `@revoked` is refused; a CA that no line names gives a check of the
  plain key, as OpenSSH falls back, and a refusal there names both
  fingerprints; from a CA of a line, the validity window (an expiry names
  this host's clock and `podssh doctor`), the signature
  (`Certificate::validate_at`), the type `host`, a principal equal to the
  host or `HostKeyAlias` with no port, and no critical option. Each refusal
  names the host key's and the CA's fingerprints.
- `Policy::check_offer` takes what the handler gives (`Offer`): a valid
  certificate is accepted with no record, and meets the run's pin; the
  fingerprints of `--host-key-fingerprint` decide alone, as for a plain key.
  The test `a_cert_authority_line_does_not_make_a_key_known` stays.
- podssh asks for a principal where OpenSSH takes a host certificate with
  none: a certificate with no principal is valid for no host here, which
  `docs/cli.md` says.
- `docs/cli.md`, the manual's note on host keys, `SECURITY.md` and the
  component row of `docs/STATUS.md` say it; the gap is gone from both.

Prove, native, Windows: `cargo test -p podssh-ssh --test known_hosts --
cert_authority`, 4 passed; `cargo test -p podssh-cli --test ssh_host_keys`,
7 passed: russh's server with a host certificate of a CA of the file, which
holds only that CA line, gives exit 0 under strict checking, and nothing is
recorded; one for another principal gives 255 and the check. Planted, each
restored: each certificate accepted (the Prove's plant) failed the test of
the checks; no CA looked up failed the accept and the checks.

In the build image (`sh scripts/dev.sh run`, a debug build of the binary),
2026-10-11: `scripts/interop.sh` 241 passed, 0 failed, with the gate's case:
OpenSSH's host key signed with `ssh-keygen -s` and `HostCertificate` on port
2211, and a `known_hosts` with only the CA line: exit 0 under
`StrictHostKeyChecking=yes`, and nothing recorded. The planted run in the
build image waits for T-251.

# T-028: `accept-new` when `known_hosts` cannot be written: verify, and say that the key was not recorded

**Source:** the lablup/bssh report in GitHub #18, #20 and #22 (item 8:
"`accept-new` must still verify when there is no home directory/unusable
file"; read in the report). Read here on `3ee70dc`.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

Under `accept-new`, a key that podssh cannot record is trusted again at each
run, with no check: the relay in the middle could present another key next
time. podssh says so in words that hide this. With no `HOME`, it blames a
missing configuration; after a failed write, it says that the key "will be
checked again next time". A `known_hosts` that exists but cannot be read
counts as empty, so `accept-new` accepts any key for that host.

## Premise

Read:

- With no `HOME`, the list of user files is empty
  (`crates/podssh-cli/src/ssh/login.rs:44-48`). `record` then says "no
  known_hosts file is configured" (`crates/podssh-ssh/src/hostkey.rs`, lines
  163-169 at `bc59415`).
- A failed write logs "it will be checked again next time", and the key is
  accepted (`crates/podssh-ssh/src/hostkey.rs`, lines 170-179 at `bc59415`).
- The lookup skips a file that it cannot open or read, as if it were missing
  (`crates/podssh-ssh/src/known_hosts.rs`, lines 100-105 at `bc59415`). A key recorded in an
  unreadable file never makes a key "changed".
- The lookup runs before `record`, so a changed or revoked key in a readable
  file is still refused (`crates/podssh-ssh/src/hostkey.rs:88-161`).
- `podssh doctor` fails when the default file cannot be written
  (`crates/podssh-cli/src/doctor/host.rs:27-54`).

Not measured here: each case needs a server.

## Approach

1. In `entries_for` (now `scan` and `read_file`,
   `crates/podssh-ssh/src/known_hosts.rs:149-205`), tell a
   missing file (NotFound) from a file that cannot be read (another error,
   or not a regular file). Give the unreadable files to the policy.
2. In `Policy::check` (`crates/podssh-ssh/src/hostkey.rs:88-161`), refuse an
   unknown key under `accept-new` and `no` when a user file exists and cannot
   be read: podssh cannot verify. Name the file, the error, and the remedy
   (`-o UserKnownHostsFile=FILE`, or the fingerprint of T-031).
3. Reword `record` (`crates/podssh-ssh/src/hostkey.rs`, lines 190-202 at
   `b657023`), at INFO: the
   key is accepted for this connection only; it was not recorded, and why
   (`HOME` is not set, `UserKnownHostsFile none`, or the write error); the
   next run cannot detect a changed key.
4. Check the file type before the open: a FIFO blocks an open for reading.
5. Update `docs/cli.md:2717-2772` (one line) and the manual's note on host keys
   (`crates/podssh-cli/src/man/notes.rs`, lines 60-66 at `33c9a31`).

## Decision

Recommendation: no other place for host keys; say clearly that the key was
not recorded. A fallback directory moves the trust without the user's
choice, and `docs/target-environment.md:101-103` forbids a silent fallback
that changes the behaviour. The alternative, the token cache's chain of
directories (`docs/target-environment.md`, lines 85-89 at `4dd52f8`), lost: a key recorded in
`$TMPDIR` or `/dev/shm` is invisible to the user and to OpenSSH, and it
outlives the user's intent.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test known_hosts -- unreadable
cargo test -p podssh-ssh -- not_recorded
sh scripts/dev.sh check
```

The first test makes the user file a directory, so a read fails also for
root. Under `accept-new`, an unknown key is refused, and the message names
the file. The second test checks the three messages of step 3. In the gate,
`scripts/interop.sh` runs `accept-new` with `UserKnownHostsFile` set to a
directory (exit 255, the file named), and with a file under `/proc` that
cannot be created (exit 0, and the note "not recorded"). Planted defect:
skip an unreadable file again, and the first test fails.

## Done

2026-10-11. Under `accept-new` and `no`, a key that podssh cannot verify is
refused, and a key that it cannot record is said to hold for this
connection only:

- `known_hosts::scan` reads each file's type before the open, and tells a
  missing file (NotFound, NotADirectory) from one that exists and cannot be
  read (another error, a directory, a FIFO or any file that is not
  regular). The null device reads as empty. `lookup_all` gives the
  unreadable files with the result; `lookup` and `entries_for` keep their
  form.
- `Policy::check` refuses an unknown key under `accept-new` and `no` when a
  user file cannot be read, with the file, its error and
  `-o UserKnownHostsFile=FILE`; under `yes`, `BatchMode` and the question,
  the same file is named in a note. An unreadable global file is said at
  VERBOSE only.
- `record` says, at INFO, that the key holds for this connection only, was
  not recorded, and why: `HOME` is not set (on Windows, neither `HOME` nor
  `USERPROFILE`), `UserKnownHostsFile` is none, or the write's error
  (`Options::no_user_known_hosts`, set in `crates/podssh-cli/src/ssh/resolve.rs`).
- `docs/cli.md` and the manual's note on host keys say the rule.

Prove, native, Windows: `cargo test -p podssh-ssh --test known_hosts --
unreadable`, 1 passed (the FIFO test runs on Unix); `cargo test -p
podssh-ssh -- not_recorded`, 1 passed; and `cargo test -p podssh-cli --test
ssh_host_keys`, 3 passed: the binary against the test's SSH server refuses
with 255 and names a directory as the user file, connects with 0 and the
note when the file cannot be written, and with no home says why. Planted,
each restored: an unreadable file skipped again (the Prove's plant) and a
policy that ignores the unreadable files each failed the first test; the
old words failed the second.

Waits for T-251: the two cases of `scripts/interop.sh` in the build image,
and the FIFO test, which CI's Linux steps run at each push.
2026-10-11, in the build image (`sh scripts/dev.sh run`, a debug build of the binary): `scripts/interop.sh` 237 passed, 0 failed, in 480 s: both cases pass (255 and the file named; 0 and
the note).

# T-029: Two processes that record the same new host key at the same time

**Source:** the lablup/bssh report in GitHub #18, #20 and #22 (item 8:
"first-use recording serialized across processes"; read in the report).
Read here on `3ee70dc`.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

Two runs of podssh that meet the same new host at the same moment both
record it. With the same key, the file gets a second line. With two
different keys (one from a man in the middle, on one of the paths), both are
recorded, and later each is accepted as known.

## Premise

Read: the check reads the files, then `record` appends; nothing between them
sees another process (`crates/podssh-ssh/src/hostkey.rs:88-161`,
`crates/podssh-ssh/src/hostkey.rs`, lines 190-202 at `b657023`). `append`
opens the file for appending and writes one line
(`crates/podssh-ssh/src/known_hosts.rs`, lines 281-314 at `b657023`),
so two lines do not mix, but nothing stops the second record. A lookup
accepts a key that any plain line of the host holds
(`crates/podssh-ssh/src/known_hosts.rs:116-119`), so two recorded keys of one
type are both "known". OpenSSH appends the same way (not measured here). Not
measured: a race needs two processes; the test below makes it certain.

## Approach

1. In `append` (`crates/podssh-ssh/src/known_hosts.rs:335-410`), lock the open
   file with `std::fs::File::try_lock`. It is stable since Rust 1.89, the
   minimum that `crates/podssh-ssh/Cargo.toml:8` declares, and it needs no new
   dependency (`flock` on Unix, `LockFileEx` on Windows). Try again for 5 s at
   most; never wait without a limit.
2. Under the lock, read the file again and look the name up. The same key:
   write nothing. Another key of the same type: return a new result, and let
   `record` refuse with the changed-key message
   (`crates/podssh-ssh/src/hostkey.rs:351-375`). Else append.
3. Hold the lock only for the read and the write, never across a prompt.
4. When the file system refuses locks, append as today, with a verbose note
   (a fallback that says so, `AGENTS.md:270`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test known_hosts -- recorded_meanwhile
cargo test -p podssh-ssh --test known_hosts -- concurrent_append
```

The first test calls the new append on a file that already holds a line for
the name, as another process leaves it after podssh's lookup. The same key
adds no line; a different key is refused. The second test starts 16 threads
that record one new key: the file has one line for it. Planted defect: drop
the second lookup, and the first test fails.

## Correction

`File::try_lock` on Windows takes `LockFileEx` over the file's bytes, a
mandatory lock: each other reader of the file fails meanwhile with os error
33, and since T-028 the lookup takes such a file as unreadable and refuses
an unknown key under `accept-new`. OpenSSH's reads would fail too. The lock
on Windows is one byte far past any end of the file, which no read meets;
on Unix `File::try_lock` is an advisory `flock`, which no reader sees.

## Done

2026-10-11. `known_hosts::append` locks the first user file for the read
and the write, waits 5 s at most for another writer, and reads the file
again under the lock (`crates/podssh-ssh/src/known_hosts/lock.rs`). The same
key recorded meanwhile adds nothing (`Recorded::Already`); another key of
the type is refused with the changed-key message, and a key revoked
meanwhile with the revoked one (`Recorded::Changed`, `Recorded::Revoked`).
A file system that takes no locks gets the line without one, said at
VERBOSE; a lock that another writer holds for 5 s makes the key one that
holds for this connection only (T-028). `docs/cli.md` says the rule.

Prove, native, Windows: `cargo test -p podssh-ssh --test known_hosts --
recorded_meanwhile`, 1 passed; `-- concurrent_append`, 2 passed (sixteen
threads write one line, and a lookup during writes reads the file each
time); the three tests 10 runs in a row. Planted, each restored: no second
lookup (the Prove's plant) failed the first test and the test of sixteen;
no lock failed the test of sixteen; a lock of the file's bytes failed the
readers' test with os error 33.

The Unix lock (`File::try_lock`, `flock`) runs in CI's Linux steps at each
push.

# T-030: Each hop of a `-J` chain checks its own host key

**Source:** the l0ng-ai/tty7 report in GitHub #20 ("Per-hop `known_hosts`",
`l0ng-ai/tty7:crates/tty7-core/src/daemon/ssh/connect.rs`, lines 396-398,
487 and 556; read in the report, not verified here). Read here on `3ee70dc`.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

In a chain `-J a,b c`, each hop is a different server. The key of one hop
must never be checked under the name of another hop, or a key can be
accepted for the wrong host.

## Premise

Read: each hop gets its own name for the check, its host and its port, as
`host` or `[host]:port` (`crates/podssh-ssh/src/run.rs`, lines 269-283 at `e85e6d2`;
`crates/podssh-ssh/src/known_hosts.rs:89-96`). `HostKeyAlias` applies to the
destination only (`crates/podssh-ssh/src/run.rs`, lines 270-273 at `e85e6d2`). The order of
host-key algorithms comes from the keys recorded for that hop
(`crates/podssh-ssh/src/run.rs:420-442`). The gate's check "-J through
OpenSSH to Dropbear" (`scripts/interop.sh:359-360`) passes only when this
holds: both hops are 127.0.0.1, both keys are Ed25519 and differ, and each
is recorded under its own port.

## Approach

The code is correct (see the Correction). The work is a direct regression
test, and a documented difference from OpenSSH.

1. Move the name of a hop (`crates/podssh-ssh/src/run.rs`, lines 269-275 at `e85e6d2`) into a
   function. Test it: a jump hop on port 22, a jump hop on port 2222, and the
   destination with and without `HostKeyAlias`.
2. In `scripts/interop.sh`, after the `-J` check, start from an empty file
   under `accept-new`. The file must then hold exactly `[127.0.0.1]:2201` and
   `[127.0.0.1]:2203`. Then change only the jump's line: the run must exit
   255, and the message must name `[127.0.0.1]:2201`.
3. Write in `docs/cli.md:63-106` that podssh applies the `-o` options to each
   hop, because it reads no `ssh_config`. The manual of OpenSSH says that
   command-line options apply to the destination only (ssh(1), option `-J`;
   confirm with `ssh -v` in the harness). T-043 brings settings for each
   host.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- hop_key_name
sh scripts/dev.sh check
```

The unit test fixes the name of each hop. In the gate, the two new checks of
step 2 pass. Planted defect: give each hop the destination's name, and both
the unit test and the changed-jump check fail.

## Correction

The premise that a hop can be checked under another hop's name is wrong for
`3ee70dc`: each hop is checked under its own name and port. The entry is
now a regression test and one line of documentation.

In the work (2026-10-11), a defect of the destination's name: under
`HostKeyAlias`, podssh filed the key as `[alias]:port` off port 22, where
OpenSSH files the alias as it is. Measured against GitHub's SSH on
`ssh.github.com` port 443, with no key offered: with `-o HostKeyAlias=ghalias`,
OpenSSH 10.3p1 filed `ghalias`, and podssh `[ghalias]:443`. The function of
step 1 gives the alias alone, and the gate checks it beside OpenSSH. The reason
of step 3 is out of date: podssh reads `ssh_config` since T-043, and applies the
destination's settings of the file to each hop, as it applies `-o`; a jump host
takes no block of its own name, as OpenSSH's does (T-290).

## Done

2026-10-11. The name of each hop's key is `hop_key_name`
(`crates/podssh-ssh/src/run.rs:319-329`), which each hop's check takes
(`crates/podssh-ssh/src/run.rs:343-344`); the destination's `HostKeyAlias` is
filed as it is, with no port, as OpenSSH files it (the Correction).
- `cargo test -p podssh-ssh --lib -- hop_key_name`: 1 passed: a jump hop on
  port 22 and on port 2222, with and without the alias set, and the destination
  with and without `HostKeyAlias`. Planted, each hop named as the destination
  (the Prove's plant): the test failed; restored.
- Against GitHub's SSH on `ssh.github.com` port 443, with no key offered and
  `-o HostKeyAlias=ghalias`: after the change podssh filed `ghalias`, as OpenSSH
  10.3p1 did, and under `StrictHostKeyChecking=yes` each tool took the key that
  the other had filed and went on to the login.
- A new harness, `scripts/interop-hostkeys.sh:1-58`, sourced after the check of
  `-J` (`scripts/interop.sh:361-362`), has four checks (its floor is 4):
  `hostkeys.jump_names`, from an empty file under accept-new, `-J` through
  OpenSSH to Dropbear files `[127.0.0.1]:2201` and `[127.0.0.1]:2203`;
  `hostkeys.jump_changed`, with the jump's key changed, exits 255 with a
  message that names `[127.0.0.1]:2201`; `hostkeys.alias_no_port` and
  `hostkeys.alias_read`, with `HostKeyAlias` and `-p 2201`, both tools file
  `alias-t030` and each reads the other's file. The gate runs them at this push;
  a run in the build image stalled on the download of the crates, and the
  checks' plant waits for T-251.
- `docs/cli.md:84-93` and the manual's note of host keys
  (`crates/podssh-cli/src/man/notes_ssh.rs:98-109`) say how each hop is checked,
  and which settings hold for each hop.
- `cargo test -p podssh-ssh`: 141 passed; `cargo test -p podssh-cli`:
  563 passed, 0 failed, 31 ignored; clippy; rustfmt.

# T-031: Accept only the host key that a fingerprint names, for scripts with no `known_hosts`

**Source:** the sleepinginsummer/agent-ssh-cli report in GitHub #21 (item 6,
`trust-host --fingerprint`); the willykeenan/warren report in GitHub #18
(item 4, `trust NAME --expect FINGERPRINT`). Read in the reports. Read and
measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

An agent in a new sandbox has no `known_hosts`, but often gets the
fingerprint of the server from its operator. Today it must choose between
`accept-new` (trust on first use, with the relay in the middle) and the
refusal of an unknown host. podssh has no flag that says: accept this key,
and no other.

## Premise

- Read: the host-key question accepts a typed fingerprint
  (`crates/podssh-ssh/src/hostkey.rs:223-240`), and an `SSH_ASKPASS` program
  can answer it (`crates/podssh-ssh/src/prompt.rs:47-70`). A script then
  needs an askpass program that it can run, which a noexec sandbox can
  refuse.
- Read: OpenSSH has no keyword for this. podssh refuses
  `KnownHostsCommand` (`crates/podssh-cli/src/ssh/options.rs:248-252`,
  `crates/podssh-cli/src/ssh/keywords.rs:109`).
- Measured, offline (`PODSSH_OFFLINE=1`):
  `podssh ssh --host-key-fingerprint SHA256:abc example.invalid true` gives
  `unknown flag '--host-key-fingerprint'`, exit 64.

## Approach

1. Add the long flag `--host-key-fingerprint SHA256:B64[,SHA256:B64...]` to
   `SSH_FLAGS` (`crates/podssh-cli/src/flags.rs:112-282`), and to `ONCE`
   (`crates/podssh-cli/src/ssh/args.rs:130-151`). Refuse a malformed value with
   exit 64 before anything connects.
2. Carry it in `Options` (`crates/podssh-ssh/src/options.rs:192-315`) and
   `Policy` (`crates/podssh-ssh/src/hostkey.rs:19-39`), for the destination
   only, as `HostKeyAlias` (`crates/podssh-ssh/src/run.rs:324-329`).
3. In `Policy::check`, refuse a revoked key and a changed key first, as today
   (`crates/podssh-ssh/src/hostkey.rs:147-150`). Then accept a key whose SHA-256
   fingerprint (`crates/podssh-ssh/src/known_hosts.rs:426-429`) is in the
   list, and record nothing. Refuse any other key, also under `accept-new`
   and `no`, with the fingerprint seen and the ones expected.
4. Jump hops keep the normal policy; say so in the help.
5. Name the flag in the refusal of an unknown key when a user
   `known_hosts` cannot be read (`unverifiable` in
   `crates/podssh-ssh/src/hostkey.rs`, T-028), next to
   `-o UserKnownHostsFile=FILE`.
6. The flag's row gives the help and the manual. Update `docs/cli.md:48-478`,
   and add an example to `crates/podssh-cli/src/man/examples.rs`.

## Decision

Recommendation: a podssh flag. OpenSSH has no `-o` keyword for it, and a
podssh `-o` keyword would break a configuration file that OpenSSH also
reads. The alternative, an askpass program that answers with the
fingerprint, lost: it needs a file that can run, and it parses a prompt.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- host_key_fingerprint
cargo test -p podssh-ssh -- pinned_fingerprint
sh scripts/dev.sh check
```

The first test parses one and two fingerprints, and refuses a malformed value
and a second flag with exit 64. The second checks the policy: the pinned key
is accepted and not recorded; another key is refused under `accept-new`; a
revoked or changed key is refused, also when pinned. In the gate,
`scripts/interop.sh` connects with an empty `known_hosts` and the fingerprint
of `$W/host_ed25519.pub`: exit 0, and the file stays empty. A wrong
fingerprint gives 255. Planted defect: fall back to `accept-new` when the pin
does not match, and the second test fails.

## Done

2026-10-11. `--host-key-fingerprint SHA256:B64[,...]` (`SSH_FLAGS`, `ONCE`)
names the only keys that the destination may present:

- `hostkey::parse_fingerprints` takes the form that `ssh-keygen -l` prints,
  and refuses a value that is not `SHA256:` and the base64 of 32 bytes
  (padding is dropped), before anything connects (64).
- `Policy::fingerprints`, set for the destination only (`run.rs`, as
  `HostKeyAlias`): after a revoked and a changed key, which are refused
  first, the named keys decide alone, also for a key that `known_hosts`
  holds, under each `StrictHostKeyChecking`; the named key is recorded
  nowhere, and another is refused with both fingerprints.
- The refusal of T-028 for a user file that cannot be read names the flag
  as a remedy. `docs/cli.md`, the flag's row (the help and the manual) and
  an example of the manual say the rule.

Prove, native, Windows: `cargo test -p podssh-cli --test ssh_args --
host_key_fingerprint`, 1 passed; `cargo test -p podssh-ssh --
pinned_fingerprint`, 2 passed; and `cargo test -p podssh-cli --test
ssh_host_keys`, 5 passed, the binary against the test's SSH server: the
server's fingerprint gives 0 and no `known_hosts`, another gives 255 and
both fingerprints. Planted, each restored: a fallback to `accept-new` when
no fingerprint matches (the Prove's plant), and the check after the arm of
a known key, each failed the policy's test.

Waits for T-251: the two cases of `scripts/interop.sh` in the build image.
2026-10-11, in the build image (`sh scripts/dev.sh run`, a debug build of the binary): `scripts/interop.sh` 237 passed, 0 failed, in 480 s: both cases pass (0 and nothing recorded; 255).

# T-032: Run a remote command under `sudo` or `su`, with the password from `SSH_ASKPASS`

**Source:** the sleepinginsummer/agent-ssh-cli report in GitHub #21 (item 7,
`--sudo` and `--su`, `sleepinginsummer/agent-ssh-cli:native/src/privilege.rs`);
the totoshko88/RustConn report in GitHub #24 (item 8, sudo and su
injection). Read in the reports. Read and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

An agent with no terminal cannot run `sudo` on the server when `sudo` asks
for a password: the prompt goes to a remote pty that nobody types into, or
`sudo` refuses with no tty. A password on the command line is not
acceptable.

## Premise

- Read: podssh asks for passwords on the terminal or through `SSH_ASKPASS`
  (`crates/podssh-ssh/src/prompt.rs:47-70`), and refuses when nobody can
  answer (`crates/podssh-ssh/src/prompt.rs:80-90`). A remote command is one
  string for the remote shell (`crates/podssh-ssh/src/session.rs:123-136`).
  Local stdin goes to the channel only after the exec request
  (`crates/podssh-ssh/src/io.rs`, lines 148-157 at `3e42773`).
- Measured, offline: `podssh ssh --sudo example.invalid id` gives
  `unknown flag '--sudo'`, exit 64.

## Approach

1. `--sudo`: send `sudo -S -k -p M1 -- sh -c 'printf %s M2 >&2; CMD'`, with
   CMD quoted for the shell. M1 and M2 are random markers of this run.
2. Hold local stdin until M2 comes. When M1 comes on stderr (or in the pty's
   output), ask with `prompt::ask`, send the password and a newline once, and
   remove M1 from the output. When M2 comes, remove it and start to copy
   stdin. A second M1 (a wrong password) ends the session with a clear
   message.
3. When neither marker comes within 30 s (as `REPLY_WAIT`,
   `crates/podssh-ssh/src/session.rs:21-22`), stop with 255 and say why.
4. `--su`, a second step: `su` reads only a terminal, so it needs `-tt`. Send
   the password only for a prompt that ends the output with no newline after
   it, before M2, and once.
5. Put the filter in a new module, crates/podssh-ssh/src/elevate.rs. Hook it
   into `handle_msg` (`crates/podssh-ssh/src/io/msg.rs:11-75`) and the stdin
   branch (`crates/podssh-ssh/src/io.rs:190-257`), and keep `io.rs` under 500
   lines.
6. Pitfalls: with a NOPASSWD rule, M1 never comes, so no password is sent;
   `-k` makes `sudo` ask also with cached credentials; the remote login shell
   must read POSIX quoting (say so in the help).
7. Add the rows of `--sudo` and `--su` to `crates/podssh-cli/src/flags.rs`,
   and a paragraph to `docs/cli.md`.

## Decision

Recommendation: `sudo -S` with markers that podssh chooses, on stderr, with
no pty. podssh then knows the exact prompt, and never types a password into
an unknown program. The alternative, to match a prompt text such as
"Password:" in a pty, lost: the text depends on the language, and a wrong
match sends the password as input.

Taken, with these calls made in the work (2026-10-11). The markers are
`podssh-ID-password` and `podssh-ID-started`, ID 64 random bits in hex:
letters, digits and `-`, as a `[` would make a glob of the word in the
remote shell. `--sudo` refuses `-t`, as `sudo -S` on a pty would have the
password echoed, and asks for no pty; `--su` refuses `-T`, and asks for one.
On a second prompt podssh ends the input, and sudo exits with its refusal,
rather than asking again. A run with either flag makes a connection of its
own, with no `ControlPath`: a master's session would run the command with
no filter. With `BatchMode`, a prompt ends the input. su's own output is
shown only when the command never starts.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- elevate
sh scripts/dev.sh check
```

The unit test checks the quoting of the command, the removal of both
markers, one password for each M1, and a marker split across two reads. In
the gate, `scripts/interop.sh` installs `sudo`, gives `podtest` a rule with a
password, and runs `--sudo ... 'id -u'` with `SSH_ASKPASS`: the output is
`0`, exit 0. With a NOPASSWD rule, the askpass program never runs (it writes
a log file when it runs). Planted defect: send the password at once, without
M1, and the NOPASSWD check fails.

## Done

2026-10-11. The markers, the command and the filter in
`crates/podssh-ssh/src/elevate.rs:1-290`. The session wraps the command
(`crates/podssh-ssh/src/session.rs:123-136`, the question at
`crates/podssh-ssh/src/session.rs:218-227`), and the pump filters the output,
asks, and holds its input until the start (`crates/podssh-ssh/src/io.rs:158-172`,
`crates/podssh-ssh/src/io.rs:386-393`). The flags at
`crates/podssh-cli/src/flags.rs:212-217`, and their check in
`crates/podssh-cli/src/ssh/elevate.rs:1-43`.
- `cargo test -p podssh-ssh -- elevate`: 5 passed: the quoting of the
  command, both markers removed, one password for each prompt, a marker split
  across two reads, and su's prompt and own output.
- `cargo test -p podssh-cli --test ssh_sudo`: 5 passed, against the test
  server's sudo and su (`crates/podssh-cli/tests/ssh_harness/mod.rs`): one
  question through `SSH_ASKPASS`, and the input after the password, never
  with it; a wrong password ends with sudo's refusal; a NOPASSWD rule asks
  nothing; su's prompt is answered, and its refusal shown; the usage errors.
  Planted, each restored: the password asked at once (the Prove's plant)
  failed three tests, the NOPASSWD one among them; the input not held failed
  three; the markers left in the output failed two.
- `scripts/interop-sudo.sh:1-48`, a new harness of three checks against
  OpenSSH's sshd and Alpine's sudo in the box: `sudo.password`, `sudo.wrong`
  and `sudo.nopass`. The gate runs them at this push; their plant in the box
  waits for T-251.
- `docs/cli.md:356-371` and a note of the manual say what the flags do.
- `cargo test -p podssh-ssh`: 147 passed; `cargo test -p podssh-cli`:
  570 passed, 0 failed, 31 ignored; clippy; rustfmt.

# T-033: Record a session as asciicast v2, and play it again

**Source:** the rssh-org/rssh report in GitHub #24 (item 2, "Session
recording in asciicast v2"); the Petyok/SSHub report in GitHub #22 (item 8,
session logging and a log browser). Read in the reports. Read and measured
here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A user or an agent cannot keep a record of what a session showed, with its
timing, for an audit or to show a problem again. podssh has no recording
and no player.

## Premise

- Read: each output of a session passes `handle_msg`
  (`crates/podssh-ssh/src/io/msg.rs:11-34`), and each window change passes the
  resize branch (`crates/podssh-ssh/src/io.rs:295-300`). The size at the start
  is `terminal::size` (`crates/podssh-ssh/src/terminal/mod.rs:78`).
  `podssh-ssh` has no JSON dependency
  (`crates/podssh-ssh/Cargo.toml:17-33`).
- Measured, offline: `podssh ssh --record /tmp/s.cast example.invalid` gives
  `unknown flag '--record'`, exit 64. `podssh replay /tmp/s.cast` gives
  `unknown subcommand 'replay'`, suggests `podssh relay`, and exits 64.

## Approach

1. `podssh ssh --record FILE`: create FILE with mode 0600, never over a file
   that exists. Write the asciicast v2 header (`version` 2, `width`,
   `height`, `timestamp`, `env.TERM`). Then write one line for each event:
   `[seconds, "o", data]`, and `[seconds, "r", "COLSxROWS"]` for a resize.
2. Put the writer in a new module, crates/podssh-ssh/src/record.rs: JSON
   string escapes by hand (no new dependency), and a UTF-8 decoder that
   keeps a split character for the next read.
3. Never record input. Do not write the command line in the header: it can
   hold a secret.
4. Playback: a new verb `podssh play FILE`, with `--speed` and
   `--idle-limit`. Not `replay`: it is one edit from `relay`, and the
   suggestion step would mix them (`docs/cli.md:1051-1060`). Add it to `VERBS`
   (`crates/podssh-cli/src/flags.rs:353-412`), to
   `crates/podssh-cli/src/positionals.rs`, to dispatch, and to `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:110-140`).
5. Refuse a file whose header is not version 2. Skip unknown event types.
6. Write the risks in the manual: the output can hold secrets (a printed
   key, a password that a remote program echoes); a recording sends control
   sequences to your terminal again, so play only files that you trust.

## Decision

Taken, with these calls made in the work (2026-10-11). The file is made as
the run starts, not as the command line is read, so `-G` makes none; one that
exists is refused with 255, before anything connects. The output of stdout
and of stderr is recorded, as the terminal shows both, after the filter of
`--sudo` (T-032), so no marker is kept. `-N` and `-W`, which open no session,
and `--persist`, whose sessions follow one another, are refused with 64, and
a recorded run makes a connection of its own, with no `ControlPath`. `podssh
play` takes the file's `idle_time_limit` when `--idle-limit` is not given,
refuses a bad file with 1 and a bad flag with 64, and is the one verb of a new
group of `--help`, "Recordings".

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- asciicast
sh scripts/dev.sh check
```

The unit test checks the header, the escapes of control bytes and quotes, a
UTF-8 character split across two reads, and the resize event. In the gate,
`scripts/interop.sh` records `-tt ... 'printf hi; exit 3'`: exit 3; Python's
`json.loads` reads each line; the mode is 0600; a second run onto the same
file is refused; `podssh play` prints `hi`. Planted defect: cut the data at a
byte boundary, and the UTF-8 test fails.

## Done

2026-10-11. The recorder in `crates/podssh-ssh/src/record.rs:1-153`, which a
session starts with the size of its start
(`crates/podssh-ssh/src/session.rs:169-176`) and its output passes through
(`crates/podssh-ssh/src/io.rs:93-148`). The flag at
`crates/podssh-cli/src/flags.rs:214-215`, its check and its file in
`crates/podssh-cli/src/ssh/recording.rs:1-42`; the verb in
`crates/podssh-cli/src/play.rs:1-86`, its flags in
`crates/podssh-cli/src/flags/play.rs:1-14`.
- `cargo test -p podssh-ssh -- asciicast`: 4 passed: the header and both
  events, the escapes of quotes and control bytes, a character split across
  two reads, and a file for the first session alone.
- `cargo test -p podssh-cli --test ssh_record`: 4 passed: against the test's
  server, a session recorded and played again, the file of mode 0600 on Unix
  and never written over (255, the file as it was); `-N`, `-W` and
  `--persist` refused with no file made; `podssh play` with its timing,
  `--speed` and `--idle-limit`, events of other kinds passed over, and its
  refusals. Planted, each restored: the data cut at a byte boundary (the
  Prove's plant) failed the UTF-8 test; a quote left unescaped failed the
  test of the escapes; a file written over failed the session's test.
- `scripts/interop-recording.sh:1-39`, a new harness of three checks against
  OpenSSH's sshd in the box: `recording.session` (exit 3, Python's
  `json.loads` reads each line, mode 600), `recording.no_overwrite` and
  `recording.play`. The gate runs them at this push.
- At `e58ebcd` the gate's step release failed: the three checks ran `podssh
  ping` (`podssh: unknown flag '-t'`, 64), as `scripts/interop-ping.sh`,
  sourced by the faults harness before them, had put its own helper `p` in
  place of the one of `scripts/interop.sh`. The next commit names that helper
  `ping_via` (`scripts/interop-ping.sh:10-16`), so that each later harness
  gets `podssh ssh`.
- `docs/cli.md:372-383` and `docs/cli.md:2246-2258`, the manual's notes and an
  example, say what the flag and the verb do, and their risks.
- `cargo test -p podssh-ssh`: 151 passed; `cargo test -p podssh-cli`:
  574 passed, 0 failed, 31 ignored; clippy; rustfmt.

# T-034: `podssh agent`: an SSH agent inside podssh, with no separate binary

**Source:** the operator's ruling of 2026-10-08 on Q5: the agent and the
credential helper are parts of podssh (`docs/decisions.md`). The key stores
that the reports in GitHub #21, #22 and #24 ask for (read in the reports).
Read and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

On a host with no `ssh-agent`, a user with an encrypted key types its
passphrase at each run, and a script must answer it through `SSH_ASKPASS`
each time. The hosts that podssh is for often have no OpenSSH program that
runs: with no user database entry, OpenSSH's programs stop at once
(`docs/target-environment.md:37-44`). podssh has no agent of its own.

## Premise

- Read: podssh uses an agent that `SSH_AUTH_SOCK` names, today. On Unix it
  connects to that socket, or to `IdentityAgent PATH`; on Windows it tries
  the named pipe of `SSH_AUTH_SOCK`, then the pipe of the OpenSSH agent, then
  Pageant (`crates/podssh-ssh/src/keys.rs:392-429`, `connect_agent`). It offers the agent's
  keys first (`crates/podssh-ssh/src/keys.rs:200-265`), and skips the agent's
  certificates (`crates/podssh-ssh/src/keys.rs:208-211`).
- Read: russh 0.64.1, which the binary links, has an agent server
  (`russh::keys::agent::server::serve`): identities, signatures, add and
  remove, lock, and the lifetime and confirm constraints. It has no handler
  for the extension message (27).
- Read: an agent listens. The operator's ruling on Q1 (2026-10-08) allows a
  local listener when the user asks for it and a probe at run time allows
  the bind; AF_UNIX by default. Sandbox A allowed a bind for AF_UNIX (T-001);
  the Podman box refuses each `bind` (`scripts/box/seccomp.json:5-10`).
- Measured, offline: `podssh agent` gives `unknown subcommand 'agent'`, exit
  64.

## Approach

1. A verb `podssh agent` in the same binary. It probes, then listens on an
   AF_UNIX socket of mode 0600, in a directory of mode 0700 that it makes,
   with the owner checks of the token cache
   (`crates/podssh-relay/src/cache.rs:1-12`). On Windows: a named pipe that
   only the user can open. It prints the line
   `SSH_AUTH_SOCK=PATH; export SSH_AUTH_SOCK;` on stdout, as `ssh-agent -s`
   does.
2. Serve the agent protocol with russh's server, so that OpenSSH's `ssh` and
   `ssh-add` and podssh's own client (unchanged) use it.
3. `podssh agent add FILE`, as `ssh-add FILE`: ask the passphrase once (the
   terminal, `SSH_ASKPASS`, or T-228), and send the decrypted key;
   `-t SECONDS` gives a lifetime. Also `list`, `remove` and `lock`. Keys stay
   in memory only, zeroized at removal and at exit.
4. On Linux, check the peer of each connection (`SO_PEERCRED`): refuse
   another uid.
5. Remove the socket and its directory at exit (SIGTERM, SIGINT, SIGHUP).
6. When the probe fails, refuse with the reason and the other ways: key
   files with `-i`, and the helper of T-228.
7. In the same commit: the verb in `VERBS`
   (`crates/podssh-cli/src/flags.rs:353-412`), in
   `crates/podssh-cli/src/positionals.rs` and in `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:110-140`); `docs/cli.md`;
   "Nothing listens" in `SECURITY.md:129-156`; `docs/STATUS.md`.

## Decision

Recommendation: the agent stays in the foreground, and the user starts it
with `&`. podssh refuses to go to the background (`-f`,
`crates/podssh-cli/src/flags.rs:257-258`), and one life cycle is easier to
test. The alternative, the fork of `ssh-agent`, lost: it works on Unix only,
and it hides a failure that comes after the fork.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli -- agent_socket
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The unit test checks the socket: mode 0600 in a directory of mode 0700,
removed at exit. In the gate, `scripts/interop.sh` starts `podssh agent`
with `&`, adds `$W/id_enc` with its passphrase from `SSH_ASKPASS`, then
OpenSSH's `ssh-add -l` lists the key, and `podssh ssh -o BatchMode=yes`
logs in with no `-i`. After a kill, the socket is gone. In the box, where
each bind is refused, `podssh agent` refuses with the probe's reason.
Planted defect: make the socket with the default umask, and the mode test
fails.

## Done

2026-10-11. `podssh agent` is a verb of the same binary
(`crates/podssh-cli/src/agent/`):

- With no subcommand it serves russh's agent server, in the foreground, on
  `agent.sock` in a new directory of mode 0700 in `XDG_RUNTIME_DIR` or the
  temporary directory (`--socket PATH` names another; on Windows the named
  pipe `\\.\pipe\podssh-agent-USER-PID`). It binds through `podssh pipe`'s
  listener: `PODSSH_LISTEN=no` refuses it with 78, the socket is made under
  umask 0177 (mode 0600), a peer of another uid is closed (`SO_PEERCRED`,
  as `tokio`'s `peer_cred` reads it), and on Windows a client must run as
  this user. It prints `SSH_AUTH_SOCK=PATH; export SSH_AUTH_SOCK;` and
  `echo Agent pid N;`, and removes the socket and its directory at SIGINT,
  SIGTERM and SIGHUP (129, 130, 143). A refused bind names the reason and
  the ways with no agent.
- `add FILE...` (`-t`, `--lifetime SECONDS`), `list` (1 with no key, as
  `ssh-add -l`), `remove FILE...` or `remove --all`, `lock` (the password
  asked twice) and `unlock` talk to the agent of `SSH_AUTH_SOCK`, podssh's
  or OpenSSH's; a passphrase is asked on the terminal or through
  `SSH_ASKPASS`.
- A key added for a confirmation of each use is never used: nobody can
  confirm one. russh's agent keeps no comment (its client sends none, its
  server drops one), so `list` shows the size, the fingerprint and the
  type. russh 0.64.1's client sends its request to remove all keys with no
  length, which no agent understands; `remove --all` removes each key in
  turn.
- `pub use russh;` in `podssh-ssh` names the one russh that the binary
  links; `futures-util`, which russh pulls in, gives the stream of clients.
  The verb is in `VERBS`, the positionals, `DISPATCHED`, the manual's notes,
  `docs/cli.md` and "Nothing listens" of `SECURITY.md`; the listener scan
  of `scripts/check-repo.py` allows its bind.

Prove, native, Windows: `cargo test -p podssh-cli -- agent_socket` (the
named pipe of this user and process) and the usage test, 2 passed;
`cargo test -p podssh-cli --test agent_cli`, 3 passed: the agent on its
named pipe, `list` 1 when empty, `add`, `list` with the key's fingerprint,
`podssh ssh` in with the agent's key and no `-i` to a server that needs a
key, out with 255 after `remove --all`, and 78 with `PODSSH_LISTEN=no`.

In the build image (`sh scripts/dev.sh run`, a debug build), 2026-10-11:
the test of Unix (mode 0600 in a directory of mode 0700, both gone at the
end) passed, and with the default umask planted (the Prove's plant) it
failed, 0755 where 0600 was due; `scripts/interop.sh` 249 passed, 0
failed, with `scripts/interop-agent.sh`: OpenSSH's `ssh-add -l` lists the
key that `podssh agent add` took with its passphrase from `SSH_ASKPASS`,
`podssh ssh -o BatchMode=yes` logs in through it with no `-i`, and after a
kill the socket and its directory are gone.

Waits for T-251: the box (`scripts/test_in_box.sh`), where each bind is
refused and `podssh agent` must refuse with the probe's reason.

CI at `f7d5640` failed in each Linux step of the gate: `tests/agent_cli.rs`
ended the agent through its guard, whose kill is SIGKILL, so the agent
could not remove its socket, and the test's check of the socket failed and
`/tmp/podssh-agent-PID` stayed (the check of T-272). The test now sends
SIGTERM, as a user does, waits for exit 143, checks that the socket and
its directory are gone, and gives the agent `TMPDIR` in its scratch
directory, so a failure leaves nothing outside it. In the build image,
2026-10-11: 3 passed, and nothing was left in `/tmp`.

2026-10-30, later: on macOS (T-218's trial, run 41074530703, both Macs) the
agent of two tests ended before its first line: its socket's path, under a
`TMPDIR` that is long on macOS (`/var/folders/...`) and longer with a test's
scratch directory, passed the bytes of `sun_path`, and the bind failed. The
agent's directory now goes under `/tmp` when its socket's path would not fit
in `sun_path` with its NUL, by the size of libc's `sockaddr_un` (104 bytes
on macOS and the BSDs, 108 on Linux). A first repair took `doctor`'s bound
of 100 bytes, and the next run on the arm64 Mac moved a path of 100 to 103
bytes, which fits, out of the test's directory. Linux: `agent::serve` 2
passed (a path that fits by a byte stays, one byte more goes under `/tmp`),
`agent_cli` 6, `agent_sk` 1; planted, a limit that never falls back, one
that forgets the NUL, and the bound of 100: the new test failed each time.

# T-227: `--direct` has no limit on a stuck write, but the relay leg fails after 60 s (GitHub #36)

**Source:** GitHub #36 (2026-10-08): read by the reporter and marked
plausible; the hang was not observed. Each link read again here on
`3ee70dc`.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

On the relay road, a write that makes no progress for 60 s ends the session.
On the direct road (`--direct`), nothing limits a write. If the peer stops
reading below SSH (a TCP zero window that never opens, or a path that drops
each packet after the connection is up), `podssh ssh --direct` can wait for
ever. `docs/design.md`, line 202 at `cafcdb4`, says "A stuck write | Fails
after 60 s" and names no road.

## Premise

Read:

- `client_config` sets `inactivity_timeout: None`
  (`crates/podssh-ssh/src/run_config.rs:65`). russh 0.64.1 races each write against
  that timer in `flush_or_timeout`; with `None`, the timer never fires, so
  only the write can end the wait.
- The relay leg limits each write: `WRITE_TIMEOUT` is 60 s
  (`crates/podssh-ws/src/client.rs:34-35`, given to the session at
  `crates/podssh-ws/src/client.rs:181`), and `write` applies it
  (`crates/podssh-ws/src/session.rs:370-377`). Then the copy task stops
  (`crates/podssh-ssh/src/relay_stream.rs:203-219`), the next ping meets the
  same limit and ends the read task (`crates/podssh-ws/src/session.rs:280-283`,
  `crates/podssh-ssh/src/relay_stream.rs:225-236`), and russh's next write
  fails. So the relay road ends a stuck write in about 60 to 130 s.
- The direct road gives russh the TCP stream with only `nodelay` set
  (`crates/podssh-cli/src/ssh/transport.rs`, lines 99-101 at `cafcdb4`,
  `crates/podssh-ws/src/dial.rs:241-243`).
- russh takes SSH window credit before it writes, so a remote program that
  stops reading makes the session idle, not stuck (GitHub #36). Only a stall
  below SSH causes the hang.
- The stand-in relay's `stall:` mode reads the client's frames and drops them
  (`scripts/fake-relay.py:339-343`), so no fault tests a stuck write today.
  GitHub #36 cites it as scripts/box/fake-relay.py, which does not exist.
- The reporter measured a zero-window stall outside podssh: after 2.0 MiB,
  the write stayed blocked (read in the issue, not verified here).

## Approach

1. Measure first, on an unchanged tree. Add a plain TCP forwarder to the
   fault harness (a new mode of `scripts/fake-proxy.py`, or a new script)
   between podssh and OpenSSH on port 2201. It passes the handshake and the
   session request, then stops reading from podssh, with a small receive
   buffer. Run `timeout 300 podssh ssh --direct ... 'cat >/dev/null'` with
   20 MB on stdin. Exit 255 with a message: correct the document only. Exit
   124 (the time limit): change the code, as below.
2. Preferred change: wrap the direct stream in a writer that fails a write
   that makes no progress for 60 s, with the constant of the relay leg
   (`crates/podssh-ws/src/client.rs:34-35`). Only
   `crates/podssh-cli/src/ssh/transport.rs:221-265` changes, and both roads behave
   the same.
3. The other change: set `inactivity_timeout` at
   `crates/podssh-ssh/src/run_config.rs:65`. russh resets that timer only in a loop
   round that sent no keepalive, podssh's keepalive interval is also 60 s
   (`crates/podssh-ssh/src/options.rs:371`), and the timer also ends a
   session that is only idle. Measure an idle session with
   `ServerAliveInterval=0` before this choice.
4. Keep the forwarder as a fault in `scripts/interop-faults.sh`, with the
   exit code and the time as its check.
5. Name both roads in the row of a stuck write (`docs/design.md:575`), and add the fault to
   `docs/STATUS.md`. This is not the path of GitHub #17 (T-024, T-025): there
   the relay closes the session.

## Decision

Recommendation: the writer with the limit of 60 s. It gives `--direct` the
rule of the relay leg, and it does not change how russh times an idle
session. The alternative, `inactivity_timeout`, is one line, but it
interacts with the keepalives and can end a healthy idle session.

## Prove

```sh
export CARGO_BUILD_JOBS=4
sh scripts/dev.sh check
cargo test -p podssh-cli -- direct_write_limit
```

In the gate, the new fault exits 255 within 90 s, with a message that names
a stuck write; on the unchanged tree it reaches the time limit of 300 s
(exit 124). The unit test drives the wrapper with a writer that never
completes, under tokio's paused clock: the write fails at 60 s. Planted
defect: remove the wrapper, and the fault reaches the time limit.

## Done

2026-10-11. The Decision's writer: `podssh_ws::write_limit::WriteLimit`
wraps the direct TCP stream (`crates/podssh-cli/src/ssh/transport.rs`), and
fails a write, a flush or a shutdown that makes no progress for
`podssh_ws::client::WRITE_TIMEOUT` (60 s), the relay leg's limit. Each byte
that goes resets the count, and each wait counts on its own; reads pass
with no limit. A lost session, `-N` and `-W` now say the cause that russh
gives only to the handler (`handler::take_last_error`), where they said
that the connection was lost. `docs/design.md` names both roads.

Prove, native, Windows: `cargo test -p podssh-cli -- direct_write_limit`,
4 passed under tokio's paused clock: a writer that never completes fails at
60 s, and so does its flush after it; a real socket of the loopback whose
peer reads nothing fails at 60 s; a peer that reads takes 16 MiB; a quiet
peer passes ten minutes. The ignored test, run with `--include-ignored`:
the binary with 20 MB on stdin, through a forwarder that passed 64 KiB and
then read nothing, ended with 255 after 60.1 s and named the stuck write.
Planted: with no writer (the Prove's plant), the binary still waited at the
test's limit of 300 s. The test of the writer that never completes found a
defect first: the timer stayed armed after it fired, and the next wait
failed at once; it is repaired.

Waits for T-251: step 1's measurement and step 4's fault in the gate,
`scripts/stall-forward.py` between podssh and OpenSSH in
`scripts/interop-faults.sh` (255 within 90 s, the stuck write named).
2026-10-11, in the build image (`sh scripts/dev.sh run`, a debug build of the binary): `scripts/interop.sh` 237 passed, 0 failed, in 480 s: the fault ends with 255 in 60 s, and names the
stuck write. The run on an unchanged tree waits for T-251.

# T-228: A credential helper inside podssh, for passphrases and passwords

**Source:** the operator's ruling of 2026-10-08 on Q5 (`docs/decisions.md`);
the reports in GitHub #21 (yituorou/meatshell: encrypted passwords;
sleepinginsummer/agent-ssh-cli: an encrypted `secrets.json`), GitHub #24
(rssh-org/rssh: secrets at rest; totoshko88/RustConn: key stores and a
script) and GitHub #22 (Petyok/SSHub: KeePassXC). Read in the reports. Read
here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh asks for a key passphrase or a server password at each run, on the
terminal or through `SSH_ASKPASS`. A script must keep an askpass program
that it can run, and a sandbox can refuse to run a file from each directory
that it can write (sandbox A: `/tmp`, `/dev/shm` and `$HOME`, T-001). Other
clients store credentials; podssh stores none.

## Premise

Read, at `4cfbd5f`:
- A prompt goes to `SSH_ASKPASS` or to the terminal; with neither, podssh
  refuses and names the remedy (`crates/podssh-ssh/src/prompt.rs:47-90`).
  The askpass program's answer is zeroized
  (`crates/podssh-ssh/src/prompt.rs:102-119`).
- The prompts for a credential: the passphrase of a key file
  (`crates/podssh-ssh/src/keys.rs`, lines 211-236), the password
  (`crates/podssh-ssh/src/auth.rs`, lines 231-274), and the answers of
  keyboard-interactive (the same file, lines 176-229).
- podssh stores no credential but the relay token cache, readable by the
  owner only (`crates/podssh-relay/src/cache.rs:1-12`).
- russh's agent server has no handler for the extension message (27), so a
  store in `podssh agent` (T-034) needs a handler of podssh's own.

## Approach

1. The store lives in `podssh agent` (T-034), behind an extension message of
   the agent protocol (names such as `store@podssh` and `lookup@podssh`, to
   fix in `docs/cli.md`). Only a connection from the same uid can use it
   (T-034, step 4).
2. `podssh agent add-password [USER@]HOST[:PORT]` reads the password from
   the terminal, `SSH_ASKPASS` or stdin, never from argv. A passphrase is
   stored for a key file that the agent does not hold; `podssh agent add`
   (T-034) holds the decrypted key instead.
3. Before each prompt of the Premise, `podssh ssh` asks the agent that
   `SSH_AUTH_SOCK` names. When it has nothing, the prompt goes on as today.
   A credential that the server refuses is removed, and never tried twice.
4. Keep each credential zeroized in memory, for the agent's life or a `-t`
   lifetime. Never put it in a log, a URL or argv; `-v` names the source
   ("from podssh agent"), never the value.
5. `BatchMode` forbids prompts, not a lookup in the store.
6. `podssh doctor` says whether the store answers and how many entries it
   holds, never which. The host-key question is not a credential: the helper
   never answers it (T-031 pins a key).

## Decision

Recommendation: a credential lives in the memory of `podssh agent`, for its
life, and nowhere on disk. A file is a new target, and its passphrase must
come from a prompt at each start, which is the problem again. The
alternative, a file encrypted with a passphrase, lost for now: it adds a
format, a key derivation and the case of a lost passphrase. It can be a
later step if a credential must outlive a restart of the agent.

Taken, with these calls made in the work (2026-10-11). The store is
`crates/podssh-ssh/src/credential_store.rs`, a layer in front of russh's agent server: it reads
each message of a client, answers the four requests of the store itself, and passes each other
message to russh's server, and its answer back. It reads the answers to a lock and an unlock
(22 and 23), and while the agent is locked the store answers FAILURE. A frame over 256 KiB ends
the connection, as OpenSSH's agent bounds its own. A password's name is `USER@HOST:PORT`, the
host in lower case and an IPv6 address in brackets; a passphrase's is the key file's absolute
path. `add-password` names the user, the host and the port as `podssh ssh` would log in, its
ssh_config read; `add-passphrase` keeps only a passphrase that opens its file, and refuses a
file that needs none, with 65. keyboard-interactive takes a kept password only for a round of
one prompt with no echo whose text holds "password", in any case; a round of other prompts goes
to the terminal as before. The same prompt asked again, or a failure, is a refusal, and the
agent forgets the password. `IdentityAgent none` asks no agent, so no store either. A question
to the store has 5 s, its connection included. An agent that answers FAILURE or
EXTENSION_FAILURE (28), or closes the connection at the question, has no store, and the prompt
goes on.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- credential_store
sh scripts/dev.sh check
```

The unit test stores and looks up a password and a passphrase over a socket
pair, refuses a lookup for another host, and removes a refused password. In
the gate, `scripts/interop.sh` starts `podssh agent`, stores the password of
podtest from stdin, and runs `podssh ssh` to port 2201 with
`-o PubkeyAuthentication=no -o BatchMode=yes` and no `SSH_ASKPASS`: exit 0.
During the run,
`ps -ef` shows the password in no argv, and the output of `-vvv` does not
hold it. Planted defect: log the value at `-vvv`, and that check fails.

## Done

2026-10-11. `podssh agent add-password [USER@]HOST[:PORT]` and `add-passphrase FILE` keep a
server's password and a key file's passphrase in the memory of `podssh agent`, for its life or
`-t SECONDS`. `podssh ssh` asks the agent of `SSH_AUTH_SOCK` before the prompt of a key file's
passphrase, of a password, and of the one password prompt of keyboard-interactive, also under
`BatchMode`, and the agent forgets what a server or a key file refuses. `podssh doctor` has a line
`agent`: none runs, the count that `podssh agent` keeps, or an agent with no store. `docs/cli.md`
gives the extension messages and the exit codes; the manual's EXIT STATUS has 65 and the 69 of
`podssh agent`.
- `cargo test -p podssh-ssh --lib -- credential_store`: 6 passed, on Windows and in the build
  image: a password and a passphrase kept and found under their names, and none for another host,
  port, user or kind; a refused password forgotten; a locked agent silent until the unlock, with
  the agent's own messages passed to its server; an agent with no store, which answers FAILURE or
  28, or closes the connection; a lifetime; a frame over the bound.
- `cargo test -p podssh-cli --test agent_store`: 4 passed, on Windows and in the build image,
  against russh's server on the loopback, which takes only a password or only
  keyboard-interactive. `add-password` took the password on stdin, and `podssh ssh -o
  BatchMode=yes -o PubkeyAuthentication=no`, with no `SSH_ASKPASS`, logged in by each method;
  `-vvv` named the agent as the source of the password, never the value. A refused password was
  forgotten: in two runs the server saw it once. `podssh doctor` said that the agent keeps 1, and
  named no user, host or secret. Planted: the value in a debug line beside the line that names the
  source; the tests of the password and of keyboard-interactive failed.
- The doctor's tests failed in their first run on this host, where no agent runs: russh's stream
  to Pageant opens when no Pageant runs, and closes at the first request, so the line said FAIL.
  podssh now asks for Pageant's window first (`crates/podssh-ssh/src/keys.rs:414-418`), which also
  spares `podssh ssh` that stream, and reads an agent that closes the connection at the store's
  question as one with no store (`crates/podssh-ssh/src/credential_store.rs:354-361`). The
  doctor's tests: 10 passed, on Windows and in the build image.
- `cargo test -p podssh-ssh -p podssh-cli`: 630 passed, 0 failed, 31 ignored, on Windows; clippy
  with all features.
- In the build image, the step `release` (a static build): interop 312 passed, 0 failed, and the
  agent harness 22 of 22, at its floor (`scripts/interop-baseline.txt`, 333 ids). podtest's
  password, from stdin, logged in to OpenSSH's sshd on port 2201 under `BatchMode`, with no
  `SSH_ASKPASS` and no keys; `ps -ef` showed it in no argv during the run, and `-vvv` said "the
  password for podtest@127.0.0.1:2201 from podssh agent", never the value. After `remove --all`,
  the kept passphrase of `id_enc` opened it under `BatchMode`. That run's tree lacked what came
  after it: the Pageant check, the closed connection and 28 as no store, the doctor's test, the
  name of 65, and texts. The plant in the gate waits for T-251.

# T-229: Hardware keys (FIDO2 `sk-` keys) in `podssh keygen`, the client and `podssh agent`

**Source:** the operator's ruling of 2026-10-08 on Q5 (`docs/decisions.md`);
the totoshko88/RustConn report in GitHub #24 (item 6: FIDO2 and PKCS#11;
read in the report). Read and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** done

## Problem

A FIDO2 security key keeps the private key in the device, and each login
needs a touch. OpenSSH supports such keys (`sk-ssh-ed25519@openssh.com`,
`sk-ecdsa-sha2-nistp256@openssh.com`). podssh cannot make one, cannot sign
with the key file of one, and has no agent to hold one.

## Premise

- Measured, offline: `podssh keygen -t ed25519-sk -f FILE` gives
  `unknown key type "ed25519-sk": ed25519 (the default), ecdsa or rsa`,
  exit 64, and writes nothing.
- Read: the default key files leave out the types of security keys
  (`crates/podssh-ssh/src/options.rs`, lines 392-399 at `c7c5aa6`). `known_hosts::key_type` names
  them (`crates/podssh-ssh/src/known_hosts.rs:416-417`), and `ssh-key`
  0.7.0-rc.11 has their algorithms.
- Read: podssh offers each key that an agent lists
  (`crates/podssh-ssh/src/keys.rs:200-265`), so an `sk-` key in OpenSSH's
  `ssh-agent`, with its device present, can work today. Not measured.
- Read: `-I` (PKCS#11) is refused by name
  (`crates/podssh-cli/src/flags.rs:260-261`).
- A device needs USB access (`/dev/hidraw*` on Linux) or the WebAuthn API of
  Windows. A sandbox has neither, so each use needs a probe.

## Approach

1. Measure first, on the operator's Windows machine with a real key:
   `ssh-keygen -t ed25519-sk` and `ssh-add` of OpenSSH 10.3p1, then
   `podssh ssh` through that agent. The result tells whether step 2 starts
   with a test or with a change.
2. The client with a key file: sign through the device. On Windows, the
   WebAuthn API of the system through `windows-sys` (no C to compile). On
   Linux, CTAP2 over `/dev/hidraw*` in Rust, after a probe of access. Ask for
   the touch on stderr, and limit the wait to 30 s. With no person, nobody
   touches the key: say so, also under `BatchMode`.
3. `podssh keygen -t ed25519-sk` and `-t ecdsa-sk`, with `-O resident` and
   `-O application=`, write the key handle file of OpenSSH. The `ssh-keygen`
   of OpenSSH must read it (a check in `scripts/interop-keygen.sh`).
4. `podssh agent` (T-034) holds key handles, and signs through the device.
5. Probe each step; with no device, refuse with the reason before anything
   is written. Never assume a device.

## Decision

The calls of the draft of 2026-10-13:

- **The run with a device waits for the operator; the entry closes on its
  native Prove.** Step 1 measures with a real key on the operator's
  machine, and no session has a key. The Prove names the run with a real
  key as a measurement of the operator, apart from its unit test and the
  gate's checks, which need no device; T-181 closed in the same way, its
  serial device waiting for hardware. Where no device is, podssh refuses
  with the reason, so a defect of the device layer cannot pass as a
  success. The alternative, `blocked` with a `## Blocker` on the operator
  until the run, lost: the code and each test that needs no device would
  wait with it. Step 2 starts with the change: the agent's road of step 1
  needs no change of the login (the agent signs), and podssh now says the
  touch for it.
- **Linux: CTAP2 over `/dev/hidraw*` in podssh's own Rust**
  (`crates/podssh-ssh/src/sk/`): the framing of CTAPHID, the part of CBOR
  that CTAP2 uses, and the PIN protocol one, with aws-lc-rs, which the
  binary links already, for its ECDH, AES-256-CBC and HMAC. The probe
  lists the `hidraw` devices, keeps those whose report descriptor has
  FIDO's usage page 0xF1D0 (in sysfs, else by `HIDIOCGRDESC`), and opens
  each; most systems give that access through a udev rule. Lost: libfido2
  (C, with libcbor, libcrypto and libudev to link into a static binary),
  and the crates `ctap-hid-fido2` and `authenticator` (new trees of
  dependencies, with hidapi or udev). A device of U2F only (CTAP1) is
  refused by name: Ed25519 needs CTAP2, and the devices sold since 2018
  speak it. With several devices, `keygen` asks the user to name one, and a
  signature goes to the device that answers a silent request (no touch)
  for the key, as OpenSSH's `sk_select_by_cred` does; a touch to choose a
  device (OpenSSH's `sk_select_by_touch`) lost, as it asks each device for
  a touch.
- **Windows: the WebAuthn API of the system, loaded at run time.**
  windows-sys gives the types of `webauthn.h`, and podssh loads
  `webauthn.dll` with `LoadLibraryExW` (System32 only) and
  `GetProcAddress`. windows-sys's own functions of the library link it at
  load time, so podssh would not start on a Windows without it (Windows 10
  before 1903, Windows Server 2016); the load is the probe. The raw HID of
  a FIDO device lost: since Windows 10 1903 only an administrator opens
  it. The client data that Windows hashes is podssh's data itself, as
  libfido2 gives it to Windows for OpenSSH, so the device signs SHA-256 of
  the data, as PROTOCOL.u2f wants. Windows' own dialog asks for the touch
  and the PIN; its owner is the window in front, else the console's, and a
  session with neither is refused. Windows tests the user's presence each
  time, so a key made with `no-touch-required` asks for a touch there.
- **macOS and each other system: no way to a device, said by the probe.**
  macOS gives a FIDO device through IOKit only, an API of frameworks with
  a run loop of its own, and no macOS host is here to test it. A key that
  an agent holds (OpenSSH's `ssh-agent` with its helper) still signs
  through the agent, and podssh says the touch. IOKit through FFI, with no
  test, lost for now.
- **30 s for each operation of a device, the touch included**
  (`TOUCH_LIMIT`): podssh's own timer and CTAPHID's CANCEL on Linux,
  `dwTimeoutMilliseconds` on Windows. The time does not count against
  `ConnectTimeout`, as an agent's does not (`answer::within_signing`). The
  server is asked first whether it takes the key (russh's query), so a key
  that it refuses asks for no touch. Lost: no limit, as libfido2 waits,
  which can hold a script for ever; and `ConnectTimeout`, which a person
  needs for the touch.
- **`BatchMode` does not stop the touch.** The touch is no question: its
  line goes to stderr, and the wait has its 30 s, also under `BatchMode`;
  when nobody touches the key, podssh says so and goes on to the next key.
  `BatchMode` forbids only the PIN of a key made with `verify-required`.
  OpenSSH does the same. Lost: skip each security key under `BatchMode`,
  which loses a key that a script with a person at it, or a key with
  `no-touch-required`, can use.
- **The probe of a login comes before the key goes to the server.** With
  no device, the key file is skipped, `-v` says why, and so does the
  message of a login that fails. Lost: the probe after the server took the
  key, which needs a signature that cannot verify to go on.
- **`keygen` asks for the passphrase before the touch**, after the probe:
  a run with nobody to ask stops before the device makes a key, which
  stays in the device when it is resident. OpenSSH asks after the touch. A
  refusal exits 1, as `ssh-keygen` and podssh's other failures of `keygen`
  do.
- **`podssh agent` keeps a security key in its front**, beside the store of
  T-228, as russh's agent server cannot sign with one: it takes `ssh-add`'s
  request with the constraint `sk-provider@openssh.com` (whatever it
  names), lists the keys after russh's, signs in the device, and asks for a
  PIN only through `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force`, as the
  agent runs in the background, where a read of the terminal stops it. A
  PIN on the agent's terminal lost.
- **`PODSSH_SK_DEVICE`**: a path of `/dev/hidraw*` (Linux), or `none`,
  which turns security keys off. The client and the agent take no
  `-O device=`, and a test on a host with a device needs a way to have
  none. `-O device=` alone lost.
- **The default identity files take `id_ecdsa_sk` and `id_ed25519_sk`**, in
  OpenSSH's order, so `-G` prints OpenSSH's lines.
- **The tests of the format use bytes that OpenSSH wrote**, published as
  the test vectors of ssh-key 0.7.0-rc.11 (see the Correction). A device in
  software (aws-lc-rs) speaks CTAPHID and CTAP2 in the tests of the flows,
  and ssh-key, which podssh does not use to sign, verifies each signature.
- **`-O challenge=` and `-O write-attestation=` are refused**: podssh keeps
  no attestation of a device.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- sk_signature
sh scripts/dev.sh check
```

The unit test checks the format of an `sk-` signature against bytes captured
once from OpenSSH and a real key. In the gate, with no device,
`podssh keygen -t ed25519-sk` and a login with an `sk-` key file refuse with
the reason, and no file is written. The run with a real key is a measurement
of the operator, recorded in `docs/STATUS.md`. Planted defect: skip the
probe, and the refusal check fails with an error of the device layer.

## Correction

- The Prove's unit test was to check the format "against bytes captured
  once from OpenSSH and a real key". No session has a key, and none
  captured bytes. `sk_signature` checks podssh's signature against bytes
  that OpenSSH wrote, the test vectors of ssh-key 0.7.0-rc.11: an SSH
  signature of `ssh-keygen -Y sign` with the key `id_sk_ed25519_2.pub`
  (counter 9), and an agent's signature with `id_sk_ecdsa_p256_2.pub`
  (counter 236), each of "testing". Their source does not name the device
  that made them, so "a real key" is not shown; the operator's run with a
  device captures one.
- Step 3's check, that OpenSSH's `ssh-keygen` reads a key file of
  `podssh keygen -t ed25519-sk`, needs a device, which the build image has
  not. `scripts/interop-keygen.sh` reads instead a file that podssh's
  writer made (`keygen -c` of a file built as `ssh-keygen` writes one); a
  file of `podssh keygen` with a device waits for the operator's run.
- Step 2 names "`windows-sys` (no C to compile)": windows-sys's functions
  of webauthn.dll link the library at load time, so podssh loads it at run
  time, with windows-sys's types (the Decision).

## Done

2026-10-13.

- `crates/podssh-ssh/src/sk/` (new): the probe and the way to a device
  (`linux.rs`: `/dev/hidraw*`, the report descriptor, `flock`;
  `windows.rs`: webauthn.dll at run time; `other.rs`: the refusal),
  CTAPHID (`hid.rs`), CBOR (`cbor.rs`), the commands of CTAP2 (`ctap.rs`),
  the PIN protocol one (`pin.rs`), the flows over a channel (`flow.rs`),
  the formats of PROTOCOL.u2f and of a device's answers (`format.rs`), the
  keys of `podssh agent` (`agent.rs`) and the signers of a login
  (`signer.rs`). Each refusal of the probe starts "no security key: ".
- `podssh keygen -t ed25519-sk` and `-t ecdsa-sk`
  (`crates/podssh-cli/src/keygen_sk.rs`), with `-O resident`,
  `verify-required`, `no-touch-required`, `application=`, `user=` and
  `device=`; `KeyKind::Sk` in `crates/podssh-ssh/src/keygen.rs`.
- The login: a key file of a security key signs in its device after the
  probe, with the line of the touch and 30 s
  (`crates/podssh-ssh/src/keys.rs`); an agent's key says the touch; the
  signature that stands in for a device that did not sign carries the
  flags and the counter (`crates/podssh-ssh/src/answer.rs`); `-Y sign` with
  a key file of one (`crates/podssh-ssh/src/sshsig.rs`); the default `_sk`
  identity files.
- `podssh agent`: the front keeps, lists, signs with and removes security
  keys (`crates/podssh-ssh/src/credential_store.rs`); `podssh agent add`
  sends one as `ssh-add` does, with `sk-provider@openssh.com`.
- The manual: `PODSSH_SK_DEVICE`, the notes of `keygen`, `ssh` and
  `agent`, the rows of `-t` and `-O`; `docs/cli.md` ("Security keys") and
  README.
- Tests: `cargo test -p podssh-ssh --lib -- sk::` (CBOR, CTAPHID, CTAP2,
  the PIN protocol, the flows against a device in software, the formats,
  the agent's keys, the probe of Linux), with the three `sk_signature`
  tests: 25 passed on Windows 11, 35 on Linux in the build image (the
  probe of Linux among them). `cargo test -p podssh-cli --test keygen_sk
  --test agent_sk --test ssh_config --test ssh_args`: passed;
  podssh-ssh and podssh-cli together, 1031 passed, 0 failed.
- The merge found three defects of the draft. Clippy refused seven lines
  (keys passed by reference to `agreement::agree`, a `drop` of a value with
  no `Drop`, a loop on a condition that the loop does not change). The
  manual's scan of the variables reads each file up to its first item of
  the tests, and `sk/mod.rs` declared its device in software first, so
  `PODSSH_SK_DEVICE` read as unread: that module is last now. And the fake
  device of `flow_tests.rs` checked the PIN's hash and its proof with
  `pin::pin_hash` and `pin::auth`, the code under test, so the plant of the
  PIN's whole hash passed: the fake makes both by CTAP2 now, and
  `the_cipher_is_aes_256_cbc_with_an_iv_of_zeros` checks the cipher of the
  PIN protocol against NIST SP 800-38A's vector.
- Planted, each restored: the counter little-endian in
  `format::signature_blob` failed the two tests of OpenSSH's bytes and
  two more; the PIN's whole hash in `pin::pin_hash` failed
  `a_pin_goes_through_the_pin_protocol`; the whole HMAC in `pin::auth`
  failed it and `a_pin_is_checked_and_proved`; no CANCEL in
  `hid::Channel::cbor` failed `no_answer_cancels_and_says_why` and
  `nobody_touches_the_device`.
- In the build image (the steps `lint` and `release`, 2026-10-13): green,
  clippy 1.99 clean; interop 526 passed, 0 failed; `keygen` 92 of 92 with
  the 5 checks `keygen.sk.*` (with no device, the probe's reason and no
  file; OpenSSH's `ssh-keygen -y` of podssh's rewrite of a key file; a
  login that says the reason), and `agent` 30 of 30 with the 4 checks
  `agent.sk.*` (OpenSSH's `ssh-add` gives `podssh agent` a key of a
  security key, `ssh-add -l` lists it, a login through it with no device
  gives 255, `ssh-add -d` takes it back). The Prove's plant, the probe of
  Linux skipped so that the device layer meets `/dev/hidraw0` unchecked,
  in the image: `keygen.sk.nothing_written` and `keygen.sk.login_no_device`
  failed, each with the device layer's error in place of the probe's
  reason; `keygen.sk.no_device`, which reads the exit code alone, passed.
- Waits for the operator: the run with a real key on Linux and on Windows
  (step 1): `podssh keygen -t ed25519-sk` and `-t ecdsa-sk` (also with
  `-O resident` and `-O verify-required`), OpenSSH's `ssh-keygen -y` of the
  file, a login with `podssh ssh -i` to sshd, `podssh agent add` and a
  login through it, and a capture of a signature for `sk_signature`;
  recorded in `docs/STATUS.md`. Until then the code that speaks to a
  device is tested against a device in software only.

# T-236: Authentication has no time limit, but the comment of `connect_timeout` says that it has

**Source:** the writer of `TODO/copy.md` (2026-10-08). Read again here on
`3ee70dc`, and in russh 0.64.1 in the local cargo registry.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`ConnectTimeout` (60 s by default) limits the SSH handshake only. During the
authentication, podssh waits for each answer of the server with no limit. A
server that stalls after the key exchange holds `podssh ssh --direct` for
ever, and a run through the relay until the relay's idle cut (180 s). The
comment of the field says that the limit covers the authentication too.

## Premise

Read, at `9fefff2`:

- The comment says "Bound on the SSH handshake and authentication"
  (`crates/podssh-ssh/src/options.rs` lines 202-203 at `8d668b7`). The manual says "the
  SSH handshake" only (`crates/podssh-cli/src/ssh/keywords.rs` line 28 at `8d668b7`,
  `crates/podssh-cli/src/flags.rs` lines 167-168 at `8d668b7`).
- `connect` limits `connect_stream` only
  (`crates/podssh-ssh/src/run.rs` lines 137-159 at `8d668b7`); `auth::authenticate` runs
  with no limit (line 160 at `8d668b7` there).
- In russh 0.64.1, an authentication request waits for its reply with no
  limit (`wait_recv_reply`), and keepalives start only after the
  authentication succeeds. So nothing ends the wait on the direct road.
- On the relay road, nothing moves while podssh waits, so the relay closes
  the session after 180 s with no payload (`docs/relay.md:190`). The relay's
  own keepalive frames keep the ping watcher content meanwhile.
- A prompt has its own limit when nobody watches the terminal (60 s, T-005;
  `docs/cli.md:2740-2743`). A person who types slowly must not meet a limit
  of the server.

Not measured: it needs a server that stalls.

## Approach

1. Measure first, with the forwarder of T-227 in the fault harness, set to
   pass the key exchange, then to hold the server's replies. Run
   `timeout 300 podssh ssh --direct ... true`: the reading predicts the time
   limit (exit 124).
2. Limit each wait for an answer of the server with `ConnectTimeout`, at
   `9fefff2`: the `none` request (`crates/podssh-ssh/src/auth.rs` lines
   64-68), a key (`crates/podssh-ssh/src/keys.rs` lines 73-76 at `8d668b7`), an agent key
   (line 148 at `8d668b7` there), keyboard-interactive (`crates/podssh-ssh/src/auth.rs`
   lines 162-165 and 194 at `8d668b7`) and the password (lines 214-218 at `8d668b7` there).
3. Do not count a local prompt: each prompt runs before its request
   (`crates/podssh-ssh/src/auth.rs:173-178`). Pitfall: an agent that asks its
   user to confirm a signature (`ssh-add -c`) runs inside the agent request.
4. On expiry, end with 255, and name the step, as "HOST did not answer the
   publickey request within 60 s".
5. Make the comment and the manual (`crates/podssh-cli/src/ssh/keywords.rs:36-37`,
   `crates/podssh-cli/src/flags.rs:169-170`) say the same: the handshake, and
   each answer during the authentication.
   `docs/cli.md:2770-2772` asks for a limit on the whole operation.

## Decision

Recommendation: a limit on each answer of the server, not one limit on the
whole authentication. A person at a prompt can take minutes, and one total
limit would cut a slow typist off. The alternative, russh's
`inactivity_timeout`, lost: it also acts after the login, and it interacts
with the keepalives (T-227).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- auth_answer_limit
sh scripts/dev.sh check
```

The unit test runs a russh server in the process (`russh::server` is built
for each target that podssh has), which completes the key exchange and never
answers a request to log in. With a limit of 2 s, under tokio's paused clock,
podssh ends with the new message. In the gate, the fault of step 1 exits 255
within 90 s. Planted defect: remove the limit around the publickey request,
and the unit test reaches its own time limit.

## Done

2026-10-08, in the commit "Each answer of the server while logging in has a
time limit".

- `crates/podssh-ssh/src/answer.rs` (new): `within` limits one wait for the
  server with `ConnectTimeout`, and names the request: "HOST did not answer
  the first request to log in within 60 s". `within_signing` does the same
  for an agent key, but leaves out the time that the agent spends signing
  (`Timed` wraps the agent and records it), and never ends a wait while the
  agent signs.
- The limit is on the `none` request, each key, each agent key, the
  keyboard-interactive request and its answers, and the password. Each
  prompt runs before its request, so a person who types slowly never meets
  it. The comment of `connect_timeout`, the manual (`-o ConnectTimeout` and
  `--ConnectTimeout`) and `docs/cli.md` say the same.
- Step 1 was measured in the gate rather than first: `scripts/fake-stall.py`
  (new) forwards to OpenSSH and drops the server's bytes after its
  NEWKEYS, so the client waits for the answer to its first request to log
  in. T-227 has no forwarder yet.
- Prove: `cargo test -p podssh-ssh -- auth_answer_limit`: 3 passed. A russh
  server in the process stops answering the first request, then (in the
  second test) the publickey request: each ends with the message, at 2 s.
  The third shows that 3 s in the agent do not count against 2 s, and its
  control ends at the limit. `sh scripts/dev.sh check`: green; interop 102 of
  102; the new fault exits 255 after 10 s with `-o ConnectTimeout=10`.
- Plant: no limit around the publickey request; the unit test reached its
  own limit ("nothing ended the wait within 30 s"). The gate's binary of
  `02e4e1f`, before this entry, in the container: the new fault check
  failed, "exit 143 after 90s" (`timeout 90` ended it).

# T-237: The client accepts each channel that the server opens; OpenSSH refuses a channel that it did not ask for

**Source:** found while writing T-035, T-036 and T-037 (2026-10-08). Read
here on `3ee70dc`, and in russh 0.64.1 in the local cargo registry.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A server can open channels toward the client: `forwarded-tcpip` (for `-R`),
`auth-agent@openssh.com` (for `-A`), `x11`, `session`, `direct-tcpip`, and
the two streamlocal kinds. podssh asks for none of them, but it accepts each
one. OpenSSH refuses a channel that it did not ask for, and warns about an
agent or X11 channel. A server can thus make podssh read and discard data
with no end.

## Premise

Read:

- podssh's handler implements `check_server_key`, `auth_banner` and (since
  T-024) `disconnected`, and no callback for a channel
  (`crates/podssh-ssh/src/handler.rs` lines 44-88 at `8d668b7`).
- In russh 0.64.1, the default callbacks for the seven kinds above accept
  the channel. A channel of an unknown kind is refused
  (`should_accept_unknown_server_channel` returns false by default).
- russh reopens the window of a channel when data arrives
  (`adjust_window_size`, on each `CHANNEL_DATA`), whether or not the program
  reads it. Then it queues the data and ignores a failed send. The default
  callback drops its `Channel`, so such data is read and thrown away, and the
  window never closes. Each byte crosses the relay and counts toward its
  64 MiB (`docs/relay.md:192`).
- A channel that podssh keeps and does not read is worse: its queue fills
  (`channel_buffer_size`), and then the whole session stops reading.
- Nothing connects such a channel to a local service today, so no data
  leaks.

Not measured: OpenSSH's server opens no such channel unasked, so the
measurement needs a test server.

## Approach

1. In `crates/podssh-ssh/src/handler.rs`, implement the seven callbacks:
   reject with `AdministrativelyProhibited` (to drop the `reply` does it),
   and drop the channel.
2. For `auth-agent@openssh.com` and `x11`, log a warning at INFO, as OpenSSH
   does: the server tried agent (or X11) forwarding that podssh did not ask
   for.
3. Keep one place that knows what podssh asked for; nothing today. T-035,
   T-036 and T-037 each turn on one kind, only for their own requests.
4. The rule for those entries: read an accepted channel at once, or close
   it; never keep one unread.
5. Add the rule to `SECURITY.md` (section "Design rules").

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- unrequested_channels
```

The test runs a russh server in the process over a pipe. After the login,
the server opens each of the seven kinds (russh's server `Handle` has a call
for each): each open fails with `AdministrativelyProhibited`, and an exec on
a session channel still returns its exit status. For the agent and X11
kinds, the log has the warning. Planted defect: remove the callback for
`forwarded-tcpip`, and its open succeeds, so the test fails.

## Done

2026-10-08, in the commit "A channel that podssh did not ask for is
refused".

- `crates/podssh-ssh/src/handler.rs`: the seven callbacks for a channel
  that the server opens (`forwarded-tcpip`, `forwarded-streamlocal`, the
  agent, `session`, `direct-tcpip`, `direct-streamlocal`, X11) go to one
  method, `unasked`, the one place that decides. It refuses with
  "administratively prohibited", and warns at INFO for an agent or X11
  channel, as OpenSSH does. Its comment gives the rule for T-035, T-036 and
  T-037: accept only the kind asked for, and read an accepted channel at
  once or close it.
- `SECURITY.md` (section "Design rules") has the rule.
- Prove: `cargo test -p podssh-ssh -- unrequested_channels` passed. A russh
  server in the process, after the login, opens each of the seven kinds
  through its `Handle`: each open fails with `AdministrativelyProhibited`,
  an exec on a session channel that podssh opens still returns exit status
  0, and the log has both warnings.
- Plant: the callback for `forwarded-tcpip` removed. The test failed:
  "forwarded-tcpip: the client accepted a channel that it did not ask for".

# T-238: `%` tokens differ from OpenSSH: some stay literal, `%u` gives the remote user, and an unknown token is kept

**Source:** the writer of `TODO/config.md` (2026-10-08; T-043 names it).
Measured here on `3ee70dc`, and against OpenSSH 10.3p1 with `ssh -G`, which
does not connect.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

OpenSSH expands `%` tokens in `IdentityFile`, `UserKnownHostsFile`,
`IdentityAgent` and other paths. podssh expands only `%d`, `%h`, `%r`, `%u`
and `%%`, and keeps each other token as text. So `-o IdentityFile=~/.ssh/id_%p`
names another file in podssh than in OpenSSH, with no message. `%u` is
worse: podssh gives the remote user, and OpenSSH the local user.

## Premise

Measured, offline, with `MSYS_NO_PATHCONV=1` and `PODSSH_OFFLINE=1`. podssh
expands the `-E` path before it connects, so the name of the log file shows
the result:

- `podssh ssh -E DIR/p%p-u%u-r%r-h%h-n%n-L%L-l%l-i%i-C%C-pct%%.log -l remoteuser -p 2222 example.invalid true`
  made the file `p%p-uremoteuser-rremoteuser-hexample.invalid-n%n-L%L-l%l-i%i-C%C-pct%.log`.
- OpenSSH, `ssh -F /dev/null -G -l remoteuser -p 2222 example.invalid` with
  `-o ControlPath=/x/p%p-u%u-r%r-h%h-n%n-L%L-l%l-i%i-pct%%`, exit 0, prints
  `/x/p2222-uLOCALUSER-rremoteuser-hexample.invalid-nexample.invalid-LLOCALHOST-lLOCALHOST-iUID-pct%`.
  `UserKnownHostsFile` is expanded the same way. `LOCALUSER`, `LOCALHOST` and
  `UID` stand for the local user, host name and user id. `%C` gives 40 hexadecimal digits, `%k` the
  `HostKeyAlias`, and `%j` is empty with no `ProxyJump`.
- OpenSSH refuses an unknown token: `-o ControlPath=/x/%Q` gives
  `unknown key %Q`, exit 255. podssh accepts `-o IdentityFile=/x/%Q`.
- OpenSSH opens `-E FILE` with the name as typed (`-E DIR/ossh-p%p-h%h.log`
  made `ossh-p%p-h%h.log`); podssh expands it.

Read, at `5c7a1ad`: `expand_path` knows `%d`, `%h`, `%r`, `%u` and `%%`,
maps `%u` to the remote user, and keeps other tokens as typed
(`crates/podssh-cli/src/ssh/resolve.rs` lines 328-355). It serves the key
files, the `known_hosts` files, `IdentityAgent` and `-E` (lines 118-130,
200-204 and 223 there).

## Approach

1. Expand the tokens of ssh_config(5) for these paths: `%%`, `%C`, `%d`,
   `%h`, `%i`, `%j`, `%k`, `%L`, `%l`, `%n`, `%p`, `%r` and `%u`. `%u` is the
   local user, `%r` the remote user, `%n` the destination as typed, `%k` the
   `HostKeyAlias` or the host.
2. Take the local user from `USER`, `LOGNAME` or `USERNAME`, as `Env` does
   (`crates/podssh-cli/src/ssh/resolve.rs:111-127`), and the host name from the
   system; never `getpwuid` (`crates/podssh-cli/src/ssh/resolve.rs:136-148`).
3. Compute `%C` as OpenSSH does, and check it against `ssh -G` (step 6).
4. Refuse an unknown token with exit 64, before anything connects, and name
   it.
5. Do not expand `-E`, as OpenSSH does not.
6. T-043 uses the same function for `ssh_config`. Name the tokens in the
   manual's notes and in `docs/cli.md:48-478`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- percent_tokens
sh scripts/dev.sh check
```

The test expands each token for a fixed user, host and port, and refuses
`%Q` with exit 64. In the gate, `scripts/interop.sh` compares podssh's
expansion of `%C`, `%L`, `%l`, `%i` and `%u` with the `ControlPath` that
`ssh -G` prints in the same container; add `openssh-client` to the packages
(`scripts/interop.sh:24-25`) when T-026 has not. Planted defect: map `%u` to
the remote user again, and both checks fail.

## Done

2026-10-08, in the commit "The % tokens are OpenSSH's".

- `crates/podssh-cli/src/ssh/tokens.rs` (new) expands the 13 tokens with
  the values of OpenSSH 10.3p1, read in its source (`sshconnect.h`,
  `DEFAULT_CLIENT_PERCENT_EXPAND_ARGS`; `ssh.c`; `ssh_connection_hash` in
  `readconf.c`): `%u` is the local user, `%r` the remote one, `%h` the host
  lowercased unless it is an address, `%n` the host as typed, `%k` the
  alias (lowercased) or `%n`, `%j` the host of the last jump hop, `%L` the
  first label of the local host name, `%C` the SHA-1 of `%l%h%p%r%j`. The
  local host name and user id come from the system (`gethostname`,
  `getuid`; `COMPUTERNAME` on Windows, which has no user id), never from
  the user database. An unknown token, a `%` at the end, or a token whose
  value is unknown is refused with exit 64, before anything connects.
- `-i`, `IdentityFile`, `UserKnownHostsFile`, `GlobalKnownHostsFile` and
  `IdentityAgent` use it. `-E FILE` is opened as typed, as OpenSSH opens
  it. `keygen` takes the host name from the same function.
- Prove: `cargo test -p podssh-cli --test ssh_args -- percent_tokens`
  passed: each token for a fixed user, host and port (`%C` computed apart,
  with Python's hashlib), `%Q` refused with exit 64, `%u` with no local user
  refused, `-E` as typed. `sh scripts/dev.sh check`: interop 103 of 103; the
  new check "% tokens: podssh expands %C %L %l %i %u %r %h %p %n %j %k as
  ssh -G does" passed (the container's package `openssh-client-default` is
  `ssh`). In that run, the record step failed only because the citations of
  this change were not yet moved (`keygen.rs` got shorter); after the remap,
  `cargo todo check` agrees.
- Plant: `%u` as the remote user again; the unit test failed (`...-remoteuser`
  for `...-envuser`). The gate's binary of `8d668b7`, before this entry:
  the new check failed, "podssh wrote .../%C-%L-%l-%i-podtest-podtest-
  127.0.0.1-%p-%n-%j-%k; ssh -G gives .../185b8d38...-0-root-podtest-...".

# T-257: An RSA user key signs through the `rsa` crate, which is open to a timing attack

**Source:** the first run of `.github/workflows/deny.yml` on 2026-10-09
(T-216): advisory RUSTSEC-2023-0071 for `rsa` 0.9.10 and 0.10.0-rc.18.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The private-key operations of the `rsa` crate are not constant-time (the
Marvin attack), and no fixed version exists. `podssh ssh` signs with an RSA
user key through russh and ssh-key, which use that crate, so each login with
such a key shows a server the timing of one signature. `podssh keygen -t rsa`
makes its keys with the same crate.

## Premise

Read: `rsa` 0.10.0-rc.18 comes into `podssh-ssh` through russh 0.64.1 and
ssh-key 0.7.0-rc.11 (`cargo tree -i rsa@0.10.0-rc.18`); `podssh keygen` makes
an RSA key with `RsaKeypair::random` (`crates/podssh-ssh/src/keygen.rs`, line 67 at `ff75425`),
and its default is Ed25519 (`crates/podssh-ssh/src/keygen.rs:35`). `rsa`
0.9.10 comes into `podssh-ws`, which only verifies signatures with public keys
(`crates/podssh-ws/src/crypto/rsa_sig.rs:10-12`): the attack needs the private
key. The binary already links aws-lc-rs, whose RSA is constant-time, for the
ciphers of russh (`docs/decisions.md`, the SSH client).

## Approach

1. Sign with an RSA user key through aws-lc-rs: russh can authenticate with a
   signer of the caller's (the path that an agent takes), so the key is read
   once into an aws-lc-rs key pair, and only the signature leaves it.
2. Make RSA keys in `podssh keygen` with aws-lc-rs too, and write them in
   OpenSSH's format as now.
3. Test against OpenSSH: a login with an RSA key to the gate's sshd, and
   `ssh-keygen -Y verify` on a signature; a plant that signs with the old path
   is found by a source sweep that names `rsa::` outside verification.
4. Keep the ignore of RUSTSEC-2023-0071 in `deny.toml` while `rsa` stays in
   the graph for verification, with its reason changed to say that no
   private-key operation uses it; remove the gap from `SECURITY.md`.

## Decision

Taken, with these calls made in the work (2026-10-11). A key file's RSA key is read into an
aws-lc-rs key pair (`crates/podssh-ssh/src/rsa_key.rs`): its PKCS#1 form is built from the OpenSSH
key, whose mpints are the contents of DER integers, with d mod (p - 1) and d mod (q - 1) computed
in constant time by crypto-bigint, and aws-lc-rs checks the key as it parses it. It signs each
login on the path that an agent takes, and puts the signature after the data as an agent does.
aws-lc-rs signs no SHA-1 and takes keys of 2048 to 8192 bits, so a key file is offered to no
server that lists only `ssh-rsa`, and at no other size; each refusal comes before the request, as
russh waits for the signature of a key that the server took and drops each other message.
`podssh keygen -t rsa` makes 2048, 3072, 4096 or 8192 bits, the sizes that aws-lc-rs makes, and
reads its PKCS#8 back into ssh-key's types. The one way to russh's own signing is `russh_key`,
which hands it a key that is not RSA. Beyond the Approach: russh's agent server signs a key that
it holds through `rsa`, and with SHA-1, so the front of `podssh agent` answers FAILURE to a
request to add an RSA key, and `podssh agent add` names the reason. The `ssh-keygen -Y verify` of
step 3 needs a signature in SSHSIG form, which podssh does not make (T-020): russh's server in the
tests, and OpenSSH's sshd in the gate, verify the signatures of the logins instead. The sweep
cannot see a `russh_key` that lets an RSA key through; the login with a key of 1024 bits, which
aws-lc-rs refuses and the `rsa` crate would sign, finds that plant.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --no-fail-fast
sh scripts/dev.sh check     # the interop logins, an RSA key among them
```

Both pass, and no private-key operation of the `rsa` crate is left in the
source. Planted defect: sign with `RsaKeypair` again; the sweep must fail.

## Done

2026-10-11. An RSA user key signs through aws-lc-rs, `podssh keygen -t rsa` makes its key there,
and `podssh agent` keeps no RSA key; `deny.toml` gives the new reason for RUSTSEC-2023-0071, and
`SECURITY.md` has the rule in place of the gap.
- `cargo test -p podssh-ssh --lib -- rsa_key credential_store keygen`: 18 passed, on Windows. A
  key that aws-lc-rs made, through OpenSSH's format and back, signs with SHA-512 and SHA-256, and
  aws-lc-rs's verifier takes each signature; its CRT exponents are those that aws-lc-rs wrote; a
  key whose d does not match its primes is refused; SHA-1 is never signed; a key of 1024 bits, and
  each size that aws-lc-rs does not make, is refused. Against russh's server in the process, which
  checks that a signature has the algorithm of its request and verifies it, the key logged in with
  SHA-512 and with SHA-256, and was offered to no server that lists only `ssh-rsa`, nor at 1024
  bits, the reason in the log. The agent's front answered FAILURE to three requests to add an RSA
  key, and russh's server saw only the Ed25519 key.
- `cargo test -p podssh-ssh --test no_rsa_private_op`: 2 passed: no private-key operation of `rsa`
  in the source, and each of eight planted lines found.
- Planted: russh's own signing for each key in `keys.rs`, as before T-257: the sweep named
  `keys.rs:86`, and the login at 1024 bits failed. A `russh_key` that lets an RSA key through: the
  login at 1024 bits failed.
- `cargo test -p podssh-ssh -p podssh-cli`: 640 passed, 0 failed, 31 ignored, on Windows; clippy
  with all features. The logins of the gate with an RSA key (`ssh.auth.key.rsa`, OpenSSH's sshd)
  run in CI at this push.

# T-269: A session can wait for ever when its link ends while it sends

**Source:** T-156's controls (2026-10-10): a session of the forward road
whose relay host stopped in the middle of 20 MiB up and back did not end in
7 of 54 runs, and said nothing after its login.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A session of `podssh ssh` whose link ends while it sends can wait for ever,
with no exit and no word, where it should end with 255 and the reason. A
user sees a session that hangs.

## Premise

Measured: a hung run of the control held no TCP connection (the relay
host's reset had come through), and `-vv` printed nothing after the login.
Read at `b62d657`: the session's loop awaited each send of stdin's bytes on
the channel inside its `select!` (now `crates/podssh-ssh/src/io.rs:209-221`),
and a send waits for the channel's window; while it waited, the loop read
none of the channel's messages, which carry the end. And in the relay
stream, the task that sends stopped reading the pipe when a send failed,
while the task that receives could wait for russh to read (now
`crates/podssh-ssh/src/relay_stream.rs:182-276`): russh, which waited on a
write into the pipe, read nothing, so neither task ended.

## Approach

1. While a send waits, the loop reads the channel's messages, and their
   end ends the session.
2. In the relay stream, each task's end with the link stops the other: the
   pipe closes, and a write of russh's that waits on it fails.
3. Tests: the relay stream's deadlock (the link breaks while russh writes
   and does not read; russh's write must fail); a command that exits, and a
   connection that ends, while the window is spent
   (`crates/podssh-cli/tests/window_lost.rs`, with `hold` and `quit` of the
   tests' server); and T-156's control of a stopped relay host, run many
   times.

## Prove

```sh
cargo test -p podssh-ssh --lib relay_stream
cargo test -p podssh-cli --test window_lost
```

With T-156's checks: its control of a stopped relay host, 40 runs and no
hang. Plant: the relay stream's receiving task with no stop fails its test.

## Done

2026-10-10. The session's loop reads the channel's messages while a send
waits for the window (`crates/podssh-ssh/src/io.rs:209-221`), and in the
relay stream each task's end with the link stops the other
(`crates/podssh-ssh/src/relay_stream.rs:182-276`).
- T-156's control of a stopped relay host (the forward road, 20 MiB up and
  back, the relay host's connections end with RST at 8 MiB; a limit of 60 s
  for each run): before, 7 of 54 runs never ended; with the loop's change
  alone, 0 of 40; with both changes, 0 of 70 (30 of them with lines of
  debugging). Each other run ended with 255 in about 4 s.
- Native: the relay stream's new test passes, and fails on the planted
  deadlock (the receiving task with no stop: russh's write did not end
  within 10 s). `crates/podssh-cli/tests/window_lost.rs`: a command that
  exits (3) and a connection that ends (255) while the window is spent, 2
  passed; they pass on the old loop too, as russh wakes a send that waits
  when a channel or a direct connection ends. `cargo test --workspace`:
  1069 passed, 0 failed, 30 ignored.
- CI, the run of `3022d13` (37999580675): each job passed.

# T-284: `podssh agent` signs with a key added for a confirmation of each use

**Source:** the planning of T-257 (2026-10-11): a read of russh's agent server.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`ssh-add -c` adds a key that an agent may use only after the user confirms each use. `docs/cli.md`
says that `podssh agent` never uses such a key, as nobody can confirm one; it signs with it,
unasked. Each process that reaches the agent, a server through `-A` among them, signs with a key
that the user meant to guard.

## Premise

Read in russh 0.64.1's `src/keys/agent/server.rs` (the local cargo registry): the server keeps the
constraint of a key (lines 296-297), and when a request to sign names such a key, it takes a future
that is always ready with `true`; it never calls the agent's `confirm` (lines 348-356).

Read: podssh's `confirm` refuses (`crates/podssh-cli/src/agent/serve.rs:173-176`), and is never
called. `docs/cli.md:2155-2156` says that the key "is never used".

## Approach

1. The front of `podssh agent` (`serve_client`, beside the refusal of an RSA key of T-257) reads a
   request to add a key with constraints (25) as russh's server reads it: the key, the comment,
   then each constraint. It answers FAILURE to one that asks for a confirmation (2), so that the
   agent holds no key that could sign unasked; `ssh-add -c` fails, as with an agent that cannot
   confirm. A request that does not parse goes on to russh's server, which refuses it.
2. `docs/cli.md`: such a key is refused when it is added.
3. In the gate, OpenSSH's `ssh-add -c` to `podssh agent` fails, and `ssh-add -l` lists nothing.

## Prove

```sh
cargo test -p podssh-ssh --lib -- credential_store
```

A request to add an Ed25519 key with the confirm constraint gets FAILURE, and russh's server never
sees it; one with the lifetime constraint alone goes on. Planted: the front passes the confirm
constraint on; the test fails.

## Done

2026-10-11. The front of `podssh agent` reads a request to add a key with constraints as russh's
server reads it, and answers FAILURE to one with the confirm constraint
(`crates/podssh-ssh/src/credential_store.rs:247-263`); `docs/cli.md` says that such a key is
refused as it is added.
- `cargo test -p podssh-ssh --lib -- credential_store`: 8 passed, on Windows. Requests to add an
  Ed25519 key with the confirm constraint, alone and after a lifetime, got FAILURE, and russh's
  server saw neither; with a lifetime alone, and with none, the key went on. Planted: the front
  passes the confirm constraint on; the test failed.
- `scripts/interop-agent.sh` has the check `agent.confirm_refused`: OpenSSH's `ssh-add -c` to
  `podssh agent` fails, and `ssh-add -l` lists no key (the baseline: 334 ids, the agent's floor
  23). It runs in CI's gate at this push.

# T-285: A login waits out its limit after the agent fails to sign

**Source:** the planning of T-257 (2026-10-11): a read of russh's client.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

When the server takes the offer of an agent's key and the agent then fails to sign (it refuses,
its key is gone, or it closes), podssh logs "the agent could not sign" and offers the next key.
russh drops that request, as it still waits for the first signature: the login waits until
`ConnectTimeout` and fails, where it could go on with the next key or method.

## Premise

Read in russh 0.64.1's `src/client/encrypted.rs` (the local cargo registry): after the client asks
its caller for a signature, it takes the caller's messages until one is a signature, and drops each
other (lines 287-299).

Read: podssh offers the next key after a signature that failed
(`crates/podssh-ssh/src/keys.rs:262`).

## Approach

1. When the agent fails to sign, give russh a signature that cannot verify (the algorithm's name
   and no bytes), so that russh sends the request and the server refuses it; then go on with the
   next key, as after any refusal. `-v` says "the agent could not sign", as now.
2. A test with russh's server in the process and an agent that refuses to sign: the login goes on
   with the next key, a key file, at once, under a limit of 10 s.

## Prove

```sh
cargo test -p podssh-ssh --lib -- agent_sign
```

Before the repair the test runs into its limit; after it, the key file logs in. Planted: give russh
the agent's error, as now; the test fails.

## Done

2026-10-11. When the agent fails to sign, the signer keeps the reason and gives russh a signature
that each server decodes and none verifies, of the key's own kind: Ed25519 64 bytes of zero, RSA
zeros of the modulus's length, ECDSA r and s of 1 (`crates/podssh-ssh/src/answer.rs:48-106`); an
empty one, the first try, made russh's server close the session, as it cannot decode it. The login
says why at `-v` and goes on with the next key (`crates/podssh-ssh/src/keys.rs:254`).
- `cargo test -p podssh-ssh --lib -- agent_sign`: 1 passed, on Windows: for an Ed25519, an ECDSA
  and an RSA key whose agent refuses to sign, russh's server in the process refused the signature
  that stood in, and a key file logged in at once on the same connection. Planted: the agent's
  error given to russh, as before; the request of the key file got no answer within the limit of
  10 s, and the test failed.
- `cargo test -p podssh-ssh`: 111 passed, 0 failed; clippy with all features.

# T-287: An encrypted key of PKCS#8 or of PuTTY is never asked for, and an encrypted ECDSA key in PEM is refused with its passphrase

**Source:** the work of T-018 (2026-10-11): `podssh keygen -p` on keys that OpenSSH's
`ssh-keygen -m` made, and on the PuTTY keys of ssh-key's tests.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh ssh -i FILE` asks for the passphrase of a key only when russh says that it is encrypted
(`crates/podssh-ssh/src/keys.rs:292-293`). russh says so for a key of OpenSSH and for an RSA key
in PEM, but not for three others. An encrypted key of PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) is
read as a plain one, and fails on its DER. An encrypted key of PuTTY fails with ssh-key's "private
key is encrypted". A key in PEM encrypted with another cipher than AES-128-CBC is read as a plain
one. For each, podssh logs that it could not use the key file, and offers the next key: the user is
never asked. An encrypted ECDSA key in PEM is asked for, and then refused with its own passphrase,
as russh reads a decrypted PEM key only as RSA. `podssh keygen -p` and `-c` (T-018) read keys the
same way.

## Premise

Measured on Windows with `podssh keygen -p` (2026-10-11), on keys that the `ssh-keygen` of
OpenSSH for Windows 10.0p2 made with `-m PKCS8` and a passphrase (RSA and ECDSA): "not a private
key that podssh reads: Der: unexpected ASN.1 DER tag: expected INTEGER, got SEQUENCE", before any
question. On the encrypted PuTTY keys of ssh-key 0.7.0-rc.11's tests (`tests/examples`, Ed25519,
ECDSA and RSA, versions 2 and 3): "SshKey: PPK parsing error: private key is encrypted". On an
ECDSA key made with `-m PEM` and a passphrase: "incorrect passphrase" with the right one.

Read in russh 0.64.1 (the local cargo registry): `decode_secret_key` takes a PEM key as encrypted
only with the line `DEK-Info: AES-128-CBC,` (`src/keys/format/mod.rs`, lines 59-68), and
`decode_pkcs5` decodes the decrypted bytes only as an RSA key of PKCS#1 (`src/keys/format/pkcs5.rs`,
lines 31-35). Without a passphrase, `decode_pkcs8` decodes an encrypted document as a plain one
(`src/keys/format/pkcs8.rs`, lines 19-25). ssh-key 0.7.0-rc.11 refuses an encrypted PuTTY key with
no passphrase (`src/ppk.rs`, lines 350-353), and russh passes that on as `Error::SshKey`.

## Approach

1. One reader of a key file's text in podssh-ssh, for `podssh ssh -i`, `podssh agent`'s files and
   `podssh keygen -p` and `-c`: before russh, it finds an encrypted key by its text (a PEM key
   with `Proc-Type: 4,ENCRYPTED`, `BEGIN ENCRYPTED PRIVATE KEY`, a PuTTY key whose `Encryption`
   is not `none`), and with no passphrase answers "encrypted", so that podssh asks.
2. With the passphrase: PKCS#8 and PuTTY go to russh, which opens them. A PEM key encrypted with
   AES-128-CBC, AES-192-CBC or AES-256-CBC, of any kind, is decrypted here as OpenSSL wrote it
   (the key from MD5 of the passphrase and the salt, as `EVP_BytesToKey` makes it), and its DER
   goes to russh as a plain key. Another cipher (DES-EDE3-CBC) is refused by name.
3. Tests with the keys that OpenSSH's `ssh-keygen -m PEM` and `-m PKCS8` make, and with PuTTY
   keys: each is asked for, and opens with its passphrase; a wrong passphrase is refused.

## Prove

```sh
cargo test -p podssh-ssh --lib -- key_file
cargo test -p podssh-cli --test keygen -- formats
```

Plant: answer as russh does, with no look at the text; the tests of the question fail.

## Done

2026-10-11. `podssh_ssh::key_file` (`crates/podssh-ssh/src/key_file.rs:25-42`) reads each key
file: `podssh ssh -i` (`crates/podssh-ssh/src/keys.rs:289-334`), `podssh agent add` and
`add-passphrase`, and `podssh keygen -p` and `-c`. It finds an encrypted key by its text (a PEM key
with `Proc-Type: 4,ENCRYPTED`, `BEGIN ENCRYPTED PRIVATE KEY`, a PuTTY key whose `Encryption` is
not `none`) and answers "encrypted" with no passphrase. It decrypts a PEM key of AES-128-CBC,
AES-192-CBC, AES-256-CBC or DES-EDE3-CBC, its key made as OpenSSL's `EVP_BytesToKey` makes it, and
gives russh the plain key of the same label. A PKCS#8 key goes to russh, whose `pkcs5` now has the
schemes of OpenSSH's `ssh-keygen -m PKCS8` (PBKDF2 with HMAC-SHA1: its feature `sha1-insecure`)
and of OpenSSL's `-v2 des3` (its feature `3des`), turned on in `crates/podssh-ssh/Cargo.toml`
with no new crate; one of PBES1 or of a scheme of PKCS#12, a DSA key and a PEM key of another
cipher are refused by name before the question.
- `cargo test -p podssh-ssh --lib -- key_file`: 8 passed: the key of a passphrase equals OpenSSL
  3.5.7's for 16, 24 and 32 bytes; ECDSA keys in PEM of each of the four ciphers, an RSA key of
  AES-128-CBC and of DES-EDE3-CBC, a PKCS#8 key of russh's, of OpenSSH's scheme and of OpenSSL's
  `-v2 des3` are each asked for, open with their passphrase and refuse another; a PuTTY key is
  asked for by its `Encryption` line; DES-CBC, DSA and a scheme of PKCS#12 are refused by name.
  `cargo test -p podssh-cli --test keygen -- formats`: 1 passed. Planted, each restored: russh's
  answer with no look at the text (the Prove's plant) failed 7 of the 8 tests and the test of the
  CLI ("Der: unexpected ASN.1 DER tag"); `pkcs5` without `sha1-insecure` failed the test of
  OpenSSH's scheme.
- Against files on Windows (2026-10-11): `podssh keygen -p` wrote, from each key that OpenSSL
  3.5.7 encrypted in PEM (AES-128-CBC, AES-192-CBC, AES-256-CBC, DES-EDE3-CBC; ECDSA and RSA) and
  in PKCS#8 (PBES2 with AES-128-CBC, AES-256-CBC or Triple DES, and scrypt), and from those that
  the `ssh-keygen` of OpenSSH for Windows 10.0p2 encrypted with `-m PEM` and `-m PKCS8`, the key
  that this `ssh-keygen` reads from the original; the scrypt key, which this `ssh-keygen` does not
  read, was written too. The encrypted PuTTY keys of ssh-key 0.7.0-rc.11's tests (Ed25519, ECDSA
  and RSA, versions 2 and 3) became keys that OpenSSH reads. OpenSSL's `-v1 PBE-SHA1-3DES` was
  refused at once: "a scheme of PKCS#12 (1.2.840.113549.1.12.1.3)".
- `scripts/interop-keygen.sh` has six new checks, `keygen.formats.*` (the floor of keygen is 41):
  an ECDSA key that OpenSSH's `ssh-keygen` encrypted in PEM and in PKCS#8 logs in to sshd, its
  passphrase asked through `SSH_ASKPASS`, and `-p` writes the same key in the format of OpenSSH.
  The gate runs them at this push.
- `cargo test -p podssh-ssh`: 120 passed; `cargo test -p podssh-cli`: 544 passed, 0 failed, 31
  ignored; clippy. In the build image: the tests of `key_file` and `keygen`, and of `podssh
  agent`, passed.
- At `fbb9b94` the gate's step lint failed in CI on the format of
  `crates/podssh-ssh/src/key_file_tests.rs` and of `crates/podssh-cli/tests/keygen.rs`, which
  rustfmt had not been run on. `f6b7676` formats the first; its check of the format had run on the
  working tree, where the second was formatted and not committed, and the gate failed again on it.
  `63cad33` (T-019) formats the second: `cargo fmt` of the gate's packages, in a clean tree of
  `63cad33`, finds nothing.

# T-356: russh 0.65.0 fixes six advisories, three of them in the client, and gives the session binding

**Source:** T-341's first reading of the vendored crates' upstreams, 2026-10-31: crates.io's
newest russh is 0.65.0, of 2026-10-25, where vendor/russh holds 0.64.1.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

podssh's SSH client is russh 0.64.1, vendored with one patch. A server that podssh reaches, or
anything in its path before the host key is checked, can make it grow its memory with no bound,
stall a channel's writes for ever, or end it with a stack overflow; russh 0.65.0 fixes the
three. cargo-deny will not say so when RustSec publishes them, as it passes over a path
package (T-341).

## Premise

- Read, the release notes of russh v0.65.0, through forge.web.pkgforge.dev on 2026-10-31
  (https://github.com/warp-tech/russh/releases/tag/v0.65.0): six security fixes.
  GHSA-4p9f-7p9m-5vfg, the client takes any number of EXT_INFO messages (commit `b33e93b`, in
  `russh/src/client/encrypted.rs` and `client/mod.rs`); GHSA-fw5c-8223-6h42, a peer's maximum
  packet size of zero stalls a channel's writes (`39cb9db`, in `client/encrypted.rs` and
  `parsing.rs`); GHSA-3hm4-p7h4-rvwp, nested OpenSSH certificates exhaust the stack (`730d663`,
  in `client/kex.rs`, `keys/agent/client.rs` and `keys/key.rs`); and three of the agent and
  pageant: GHSA-9wfm-jcj8-jfv9 and GHSA-662x-8wvj-2276, allocations that an agent's client sets,
  and GHSA-vp5q-ff62-jwqv, an agent server that never calls `Agent::confirm`.
- Read: podssh runs russh's client and its agent server (`crates/podssh-cli/src/agent/serve.rs:14`),
  and russh's SSH server only in tests; the agent refuses a key added for confirmation as it is
  added (`crates/podssh-cli/src/agent/serve.rs:166-170`, T-284), and its front bounds each frame
  (`crates/podssh-cli/src/agent/serve.rs:182-190`).
- Read, through forge.web.pkgforge.dev on 2026-10-31: advisory-db's directory of russh holds
  RUSTSEC-2026-0154 alone; none of the six is there yet.
- Read: the same release adds `AgentSessionBinding` to the client (#794): "Exposes the verified
  initial key-exchange data", for `session-bind@openssh.com`. `vendor/README.md` lines 108-119 at `80e26fc` said the
  patch and the tree go when a release of russh gives a client the binding.
- Read: the breaking changes of 0.65.0 are in the server's `Handler` (`auth_publickey_offered`,
  `auth_publickey`) and the removal of the feature `async-trait`.

## Approach

1. Read `AgentSessionBinding` of 0.65.0 against what podssh's patch keeps: the server's host
   key, the session identifier of the first key exchange and the server's signature of it. If it
   holds them, podssh-ssh takes it; `[patch.crates-io]`, vendor/russh and
   vendor/patches/russh go, and the lock names crates.io's russh 0.65.0 with its checksum, which
   cargo-deny checks again. Else vendor/russh becomes 0.65.0 with the patch moved onto it.
2. The breaking changes, in podssh's code and in the servers of its tests.
3. Tests of the three fixes of the client, through a stand-in server of the tests: a flood of
   EXT_INFO ends with an error and bounded memory; a channel whose peer gives a maximum packet
   size of zero is refused; a host key that nests certificates gives an error, not an abort.
   Each runs against 0.64.1 first, where it must fail.
4. `vendor/README.md`, `docs/development.md` (the vendored crates), STATUS.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test --workspace
cargo deny --locked check advisories licenses bans sources
```

The three tests of the client fail on 0.64.1 and pass on 0.65.0; the agent's session binding
(T-279) passes with the same bytes; the gate's interop suites pass in CI.

## Correction

Approach item 1 holds: 0.65.0's `AgentSessionBinding` keeps the server's host key, the exchange
hash of the first key exchange and the server's signature of it, as the server sent them, and
none for a re-key. It reaches the client's `Handle` (`agent_session_binding`) once `connect` has
seen the first key exchange, not the handler's `kex_done`, so podssh takes it there, before the
server can ask for the agent. Approach item 3: the test of a maximum packet size of zero runs
through podssh's client, against a russh server that gives one; a flood of EXT_INFO and nested
certificates need a server that writes SSH by hand, which podssh's tests do not have, and russh's
commits carry their own tests (`b33e93b`, `730d663`, and `39cb9db`'s of the parser). No test runs
against 0.64.1 first: podssh's code now takes 0.65.0's type. The test's assertion names what
0.64.1 did, a write that waits for ever, and its control is the same server with packets of
32 KiB.

## Done

2026-10-31: done. CI at `1a9aefe` (build run 41177809365, which carries the change of `3504c1a`):
each step of the gate passed, among them `ssh` with the interop suites against OpenSSH and Dropbear,
`m6`, `release` and `lint`; the job `windows` passed, its console checks against MSYS2's sshd
among them; the job `macos` passed its default tests (its other step, T-340's trust settings,
failed on the runner's authorization, which this entry does not touch).

- podssh-ssh, podssh-cli's tests and the fuzz workspace take crates.io's russh 0.65.0 with its
  checksum; `[patch.crates-io]` keeps iroh-relay alone, and vendor/russh with its patch is gone
  (and the map of `AGENTS.md`, the section of `vendor/README.md`). cargo-deny checks russh again: `cargo deny --locked check advisories
  licenses bans sources`, exit 0, and with each feature; `scripts/check-vendored-advisories.py`
  now reads 32 path packages, exit 0.
- The binding: podssh-ssh's own `SessionBinding`, from russh's `AgentSessionBinding`;
  `run::connect` hands it from the client's handle to the agent's forward, whose clones share
  it (`agent_forward::Forward::set_binding`). T-279's tests pass with it: the bind before the
  server's first byte, checked as OpenSSH's agent checks it against the server's host key.
- The breaking change: the stand-in servers of the tests take `PublicKeyOffer` and
  `VerifiedPublicKey`, and accept a channel through its `ChannelOpenHandle`.
- `answer::tests::a_server_whose_packets_hold_no_byte_is_refused_not_waited_for`: a russh server
  with a maximum packet size of zero; podssh's client ends at once with "Disconnected", where
  0.64.1 waited on the write for ever; its control, packets of 32 KiB, takes the write. Planted, a
  control of zero: failed.
- The agent: russh 0.65.0's server asks `Agent::confirm`, which podssh's agent answers with a
  refusal (the front still refuses such a key as it is added); russh's request to remove each
  key still has no length in 0.65.0, so podssh removes them in turn, as before.
- Tests: `cargo test -p podssh-cli`, 1005 passed, 0 failed, 47 ignored (117 binaries);
  `cargo test --workspace --exclude podssh-cli`, 1247 passed and the record's test, which passed
  once the record's citations moved; podssh-ssh 300 passed; clippy `-D warnings` clean for
  podssh-ssh and podssh-cli.
- T-341's watch: its plant set only the line "Upstream read" to 0.0.0, which failed while
  russh's copy was older than its release; with russh gone, the first crate's copy is its newest
  release and the plant passed. The plant now takes the copy as 0.0.0 too, and fails again.
- The TruffleHog allowlist: the push removed the 13 lines of russh's test keys with the copy, and
  the job `secrets` failed from 27b8d8f on (run 41175920199: two of them unknown, keys of
  russh's keys tests in the copy, added in 922f1aa2cde7), as the scan reads each
  commit of the history, which keeps the copy. The 13 lines are back, with that reason. Measured:
  `scripts/secrets-report.py` over those findings, exit 1 without the lines and 0 with them.

