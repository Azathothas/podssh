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
  never offers a key (`crates/podssh-ssh/src/auth.rs:124-126`).
- The denial adds the notes of the keys with no condition
  (`crates/podssh-ssh/src/auth.rs` line 115 at `475aea9`). `PublicKeys::notes` writes "no key
  was offered" when nothing was offered (`crates/podssh-ssh/src/keys.rs:150-163`).
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
   (`crates/podssh-ssh/src/auth.rs:10-11`).
3. When the server does not accept `publickey`, say nothing about keys:
   `-i FILE` cannot help.
4. Give the note about skipped encrypted keys
   (`crates/podssh-ssh/src/keys.rs:164-170`) the same condition as step 1.
5. Keep `PublicKeys::new` for each login (`crates/podssh-ssh/src/auth.rs:107`),
   so that only the notes change. No document changes: `docs/cli.md:5277-5335`
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
  unexpected EOF to one sentence (`crates/podssh-ssh/src/run.rs:458-464`).
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
  `docs/relay.md:511-523` lists them, read from the relay's source.
  `1011 write failed: ...` means that the relay could not write to the
  target. The KTM report saw it with 0 bytes, on a target that the relay
  could dial but not use (read in the report, not verified here).
- The reporter's second comment reads `1011` as "relay backpressure, over 1
  MiB queued". That row is in the contract's table of reverse close codes
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:160-166`, row
  `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`). On the
  forward path, backpressure closes with `1013` at 2 MiB (`docs/relay.md:522`,
  `docs/relay.md:533-545`). The comment on the SSH window
  (`crates/podssh-ssh/src/run.rs` lines 25-29 at `80f20bf`) also cites the
  reverse row.

## Approach

1. Classify a forward-path close in one place, next to
   `close_code_and_reason` (`crates/podssh-ws/src/close.rs:19-27`), which
   `podssh ssh` and `podssh proxy` both use. Map the code and the reason of
   `docs/relay.md:516-523` to a hop. Relay to target: `1011` with
   `connect failed`, `write failed`, `target closed before sending anything`
   or `wrong target banner`, and `1013 target write backlog`. Client to
   relay: `1011` with `client send failed` or `client error`,
   `1013 client receive backlog`, and no Close. A relay limit: `1001`,
   `1009`. A normal end: `1000`. Give an unknown code as it is.
2. Keep the server's SSH_MSG_DISCONNECT: implement `Handler::disconnected` in
   `crates/podssh-ssh/src/handler.rs`. Store the reason code and the text,
   made safe with `podssh_ws::text::one_line`, as the handler stores
   `refusal` (`crates/podssh-ssh/src/handler.rs:46-48`).
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
7. Update `docs/relay.md` (lines 155-158 at `80f20bf`) and `docs/STATUS.md:719`. T-025 uses the
   classification for its retry rule. T-227 is a different path
   (`--direct`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws -- forward_close
cargo test -p podssh-ssh -- first_line
sh scripts/dev.sh check
```

The first test has one case for each row of `docs/relay.md:516-523`, and one
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
  WebSocket upgrade succeeds (`crates/podssh-relay/src/open.rs:203-285`).
  After the upgrade, a relay close ends the run
  (`crates/podssh-ssh/src/run.rs`, lines 38-47 at `981b8fc`).
- Both reported drops printed `HOST: the connection closed unexpectedly`,
  which only the SSH handshake prints (`crates/podssh-ssh/src/run.rs:403-420`).
  At that point no request has reached the server.
- The command starts with the exec, shell or subsystem request
  (`crates/podssh-ssh/src/session.rs:127-160`). `-W` reads stdin only after its
  channel opens (`crates/podssh-ssh/src/forward.rs:39-70`). `-N` never reads
  stdin (`crates/podssh-ssh/src/run.rs:213-255`).
- Measured by the reporter (read in the reports, not verified here): on one
  target the drop came back 3 times in 3, while other targets worked in the
  same minute, also with a client that shares no code with podssh. A blind
  retry can fail again.
- `podssh proxy` is a byte pipe and cannot know when a replay is safe. This
  entry is for `podssh ssh` only.

## Approach

1. Make `run_inner` (`crates/podssh-ssh/src/run.rs:185-269`) report the phase
   that a failure reached: the handshake, the authentication, the session
   request sent, or data moved. Keep the exit codes of OpenSSH.
2. In `connect_and_run` (`crates/podssh-cli/src/ssh/mod.rs`, lines 99-126 at `97146aa`, which
   reaches the relay through `crates/podssh-cli/src/ssh/transport.rs:178-232`), open a
   new relay session and run again only when the failure came before the
   session request, and before `-W` read a byte of stdin.
3. Decide by the close, with the classification of T-024. The link from the
   client to the relay, or no Close: go to the next relay host, as `open`
   does for a failed upgrade (`crates/podssh-relay/src/open.rs:61-85`). The
   link from the relay to the target: try once more, then stop. Never retry
   `1001`, `1009` or `1013`.
4. Wait with the jittered backoff that exists
   (`crates/podssh-relay/src/open.rs:404-418`). Bound the whole by the rounds
   of `ConnectionAttempts` (`crates/podssh-cli/src/ssh/resolve.rs:469`) and
   the deadline of each host.
5. Never prompt again without a person: under `BatchMode`, or with no
   terminal and no `SSH_ASKPASS`, a retry that needs a prompt stops. Keep a
   typed password in memory (zeroized) for the retry; do not ask twice.
6. Say each retry on stderr, with the hop and the reason. Document the rule
   in `docs/cli.md:5151-5251`, and add a row to `docs/STATUS.md`.

## Decision

Recommendation: retry inside podssh, and only before the session request.
Only podssh knows whether the request was sent, and `podssh ssh` keeps the
exit code 255 of OpenSSH (`docs/cli.md:5161-5164`). The alternative, a distinct
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
`scripts/fake-relay.py:18-34`. Through it, `exit 5` still gives 5, with one
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
  is `Lost`: an error, and 255 (`crates/podssh-ssh/src/io.rs:293`,
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
5. Write the measured rule in `docs/cli.md:5151-5251`, and the measurement in
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
  `crates/podssh-ssh/src/hostkey.rs:228-235` (no terminal). `accept-new`
  records the plain key (`crates/podssh-ssh/src/hostkey.rs:198`). GitHub #29
  cites line 91 at `22c3b88`, which builds the question about other key types.
- `ssh-key` 0.7.0-rc.11 is in the tree (`Cargo.lock:5520-5521`).
  `Certificate::validate_at` checks the signature, the SHA-256 fingerprint of
  the CA and the validity window. The caller must check the certificate type,
  the principals and the critical options (the crate's documentation).

## Approach

The order of GitHub #29: parse the certificate, look up a CA line, and fall
back to the plain key only when no CA line matches.

1. Ask for certificates: when a `@cert-authority` line matches the name of a
   hop, set `host_key_certificates` in `client_config`
   (`crates/podssh-ssh/src/run_config.rs:17-82`) to the algorithms of
   `preferred.key`. A host with no CA line keeps today's negotiation.
2. Add a lookup of CA keys in `crates/podssh-ssh/src/known_hosts.rs`, beside
   the `@revoked` arm (`crates/podssh-ssh/src/known_hosts.rs:113-115`). Match CA
   lines with the name `host` or `[host]:port`
   (`crates/podssh-ssh/src/known_hosts.rs:89-96`).
3. In `check_server_key` (`crates/podssh-ssh/src/handler.rs:155-185`), branch on
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
`client_config` does not set it (`crates/podssh-ssh/src/run_config.rs:17-82`). So
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
  (`crates/podssh-cli/src/doctor/host.rs:30-57`).

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
5. Update `docs/cli.md:5277-5335` (one line) and the manual's note on host keys
   (`crates/podssh-cli/src/man/notes.rs`, lines 60-66 at `33c9a31`).

## Decision

Recommendation: no other place for host keys; say clearly that the key was
not recorded. A fallback directory moves the trust without the user's
choice, and `docs/target-environment.md:116-118` forbids a silent fallback
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
   (`crates/podssh-ssh/src/hostkey.rs:352-376`). Else append.
3. Hold the lock only for the read and the write, never across a prompt.
4. When the file system refuses locks, append as today, with a verbose note
   (a fallback that says so, `AGENTS.md:314`).

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
(`crates/podssh-ssh/src/run.rs:453-475`). The gate's check "-J through
OpenSSH to Dropbear" (`scripts/interop.sh:361-362`) passes only when this
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
3. Write in `docs/cli.md:110-168` that podssh applies the `-o` options to each
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
(`crates/podssh-ssh/src/run.rs:324-334`), which each hop's check takes
(`crates/podssh-ssh/src/run.rs:371-372`); the destination's `HostKeyAlias` is
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
  `-J` (`scripts/interop.sh:363-364`), has four checks (its floor is 4):
  `hostkeys.jump_names`, from an empty file under accept-new, `-J` through
  OpenSSH to Dropbear files `[127.0.0.1]:2201` and `[127.0.0.1]:2203`;
  `hostkeys.jump_changed`, with the jump's key changed, exits 255 with a
  message that names `[127.0.0.1]:2201`; `hostkeys.alias_no_port` and
  `hostkeys.alias_read`, with `HostKeyAlias` and `-p 2201`, both tools file
  `alias-t030` and each reads the other's file. The gate runs them at this push;
  a run in the build image stalled on the download of the crates, and the
  checks' plant waits for T-251.
- `docs/cli.md:137-146` and the manual's note of host keys
  (`crates/podssh-cli/src/man/notes_ssh.rs:323-334`) say how each hop is checked,
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
  (`crates/podssh-ssh/src/hostkey.rs:223-241`), and an `SSH_ASKPASS` program
  can answer it (`crates/podssh-ssh/src/prompt.rs:50-73`). A script then
  needs an askpass program that it can run, which a noexec sandbox can
  refuse.
- Read: OpenSSH has no keyword for this. podssh refuses
  `KnownHostsCommand` (`crates/podssh-cli/src/ssh/options.rs:273-277`,
  `crates/podssh-cli/src/ssh/keywords.rs:139`).
- Measured, offline (`PODSSH_OFFLINE=1`):
  `podssh ssh --host-key-fingerprint SHA256:abc example.invalid true` gives
  `unknown flag '--host-key-fingerprint'`, exit 64.

## Approach

1. Add the long flag `--host-key-fingerprint SHA256:B64[,SHA256:B64...]` to
   `SSH_FLAGS` (`crates/podssh-cli/src/flags.rs:116-291`), and to `ONCE`
   (`crates/podssh-cli/src/ssh/args.rs:183-222`). Refuse a malformed value with
   exit 64 before anything connects.
2. Carry it in `Options` (`crates/podssh-ssh/src/options.rs:195-332`) and
   `Policy` (`crates/podssh-ssh/src/hostkey.rs:19-39`), for the destination
   only, as `HostKeyAlias` (`crates/podssh-ssh/src/run.rs:329-334`).
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
6. The flag's row gives the help and the manual. Update `docs/cli.md:48-895`,
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
  (`crates/podssh-ssh/src/prompt.rs:50-73`), and refuses when nobody can
  answer (`crates/podssh-ssh/src/prompt.rs:83-93`). A remote command is one
  string for the remote shell (`crates/podssh-ssh/src/session.rs:132-147`).
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
   into `handle_msg` (`crates/podssh-ssh/src/io/msg.rs:11-76`) and the stdin
   branch (`crates/podssh-ssh/src/io.rs:210-277`), and keep `io.rs` under 500
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
`crates/podssh-ssh/src/elevate.rs:1-395`. The session wraps the command
(`crates/podssh-ssh/src/session.rs:132-147`, the question at
`crates/podssh-ssh/src/session.rs:268-277`), and the pump filters the output,
asks, and holds its input until the start (`crates/podssh-ssh/src/io.rs:178-192`,
`crates/podssh-ssh/src/io.rs:405-412`). The flags at
`crates/podssh-cli/src/flags.rs:221-226`, and their check in
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
- `scripts/interop-sudo.sh:1-50`, a new harness of three checks against
  OpenSSH's sshd and Alpine's sudo in the box: `sudo.password`, `sudo.wrong`
  and `sudo.nopass`. The gate runs them at this push; their plant in the box
  waits for T-251.
- `docs/cli.md:764-787` and a note of the manual say what the flags do.
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
  resize branch (`crates/podssh-ssh/src/io.rs:314-319`). The size at the start
  is `terminal::size` (`crates/podssh-ssh/src/terminal/mod.rs:80`).
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
   suggestion step would mix them (`docs/cli.md:2002-2011`). Add it to `VERBS`
   (`crates/podssh-cli/src/flags.rs:372-436`), to
   `crates/podssh-cli/src/positionals.rs`, to dispatch, and to `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:110-143`).
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
(`crates/podssh-ssh/src/session.rs:184-191`) and its output passes through
(`crates/podssh-ssh/src/io.rs:113-168`). The flag at
`crates/podssh-cli/src/flags.rs:223-224`, its check and its file in
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
- `docs/cli.md:788-799` and `docs/cli.md:4644-4656`, the manual's notes and an
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
(`docs/target-environment.md:37-48`). podssh has no agent of its own.

## Premise

- Read: podssh uses an agent that `SSH_AUTH_SOCK` names, today. On Unix it
  connects to that socket, or to `IdentityAgent PATH`; on Windows it tries
  the named pipe of `SSH_AUTH_SOCK`, then the pipe of the OpenSSH agent, then
  Pageant (`crates/podssh-ssh/src/keys.rs:410-447`, `connect_agent`). It offers the agent's
  keys first (`crates/podssh-ssh/src/keys.rs:212-281`), and skips the agent's
  certificates (`crates/podssh-ssh/src/keys.rs:220-223`).
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
   (`crates/podssh-cli/src/flags.rs:372-436`), in
   `crates/podssh-cli/src/positionals.rs` and in `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:110-143`); `docs/cli.md`;
   "Nothing listens" in `SECURITY.md:233-260`; `docs/STATUS.md`.

## Decision

Recommendation: the agent stays in the foreground, and the user starts it
with `&`. podssh refuses to go to the background (`-f`,
`crates/podssh-cli/src/flags.rs:265-266`), and one life cycle is easier to
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
  (`crates/podssh-ssh/src/run_config.rs:73`). russh 0.64.1 races each write against
  that timer in `flush_or_timeout`; with `None`, the timer never fires, so
  only the write can end the wait.
- The relay leg limits each write: `WRITE_TIMEOUT` is 60 s
  (`crates/podssh-ws/src/client.rs:34-35`, given to the session at
  `crates/podssh-ws/src/client.rs:182`), and `write` applies it
  (`crates/podssh-ws/src/session.rs:417-424`). Then the copy task stops
  (`crates/podssh-ssh/src/relay_stream.rs:216-232`), the next ping meets the
  same limit and ends the read task (`crates/podssh-ws/src/session.rs:326-329`,
  `crates/podssh-ssh/src/relay_stream.rs:240-251`), and russh's next write
  fails. So the relay road ends a stuck write in about 60 to 130 s.
- The direct road gives russh the TCP stream with only `nodelay` set
  (`crates/podssh-cli/src/ssh/transport.rs`, lines 99-101 at `cafcdb4`,
  `crates/podssh-ws/src/dial.rs:241-243`).
- russh takes SSH window credit before it writes, so a remote program that
  stops reading makes the session idle, not stuck (GitHub #36). Only a stall
  below SSH causes the hang.
- The stand-in relay's `stall:` mode reads the client's frames and drops them
  (`scripts/fake-relay.py:384-388`), so no fault tests a stuck write today.
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
   `crates/podssh-cli/src/ssh/transport.rs:303-347` changes, and both roads behave
   the same.
3. The other change: set `inactivity_timeout` at
   `crates/podssh-ssh/src/run_config.rs:73`. russh resets that timer only in a loop
   round that sent no keepalive, podssh's keepalive interval is also 60 s
   (`crates/podssh-ssh/src/options.rs:388`), and the timer also ends a
   session that is only idle. Measure an idle session with
   `ServerAliveInterval=0` before this choice.
4. Keep the forwarder as a fault in `scripts/interop-faults.sh`, with the
   exit code and the time as its check.
5. Name both roads in the row of a stuck write (`docs/design.md:653`), and add the fault to
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

2026-11-03, on a cloud container's host: `faults.stuck_write` gave 255 after 240 s on the
keepalives, not the stuck write; the gate's runners pass it within 60 s. A larger file did not
change it, so the cause is not the host's TCP buffers: T-598.

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
  refuses and names the remedy (`crates/podssh-ssh/src/prompt.rs:50-93`).
  The askpass program's answer is zeroized
  (`crates/podssh-ssh/src/prompt.rs:105-122`).
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
  podssh now asks for Pageant's window first (`crates/podssh-ssh/src/keys.rs:432-436`), which also
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
  (`crates/podssh-ssh/src/keys.rs:212-281`), so an `sk-` key in OpenSSH's
  `ssh-agent`, with its device present, can work today. Not measured.
- Read: `-I` (PKCS#11) is refused by name
  (`crates/podssh-cli/src/flags.rs:269-270`).
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
  the session after 180 s with no payload (`docs/relay.md:452`). The relay's
  own keepalive frames keep the ping watcher content meanwhile.
- A prompt has its own limit when nobody watches the terminal (60 s, T-005;
  `docs/cli.md:5300-5303`). A person who types slowly must not meet a limit
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
   (`crates/podssh-ssh/src/auth.rs:235-240`). Pitfall: an agent that asks its
   user to confirm a signature (`ssh-add -c`) runs inside the agent request.
4. On expiry, end with 255, and name the step, as "HOST did not answer the
   publickey request within 60 s".
5. Make the comment and the manual (`crates/podssh-cli/src/ssh/keywords.rs:39-40`,
   `crates/podssh-cli/src/flags.rs:173-174`) say the same: the handshake, and
   each answer during the authentication.
   `docs/cli.md:5333-5335` asks for a limit on the whole operation.

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
  64 MiB (`docs/relay.md:454`).
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
   (`crates/podssh-cli/src/ssh/resolve.rs:139-155`), and the host name from the
   system; never `getpwuid` (`crates/podssh-cli/src/ssh/resolve.rs:164-179`).
3. Compute `%C` as OpenSSH does, and check it against `ssh -G` (step 6).
4. Refuse an unknown token with exit 64, before anything connects, and name
   it.
5. Do not expand `-E`, as OpenSSH does not.
6. T-043 uses the same function for `ssh_config`. Name the tokens in the
   manual's notes and in `docs/cli.md:48-895`.

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
the channel inside its `select!` (now `crates/podssh-ssh/src/io.rs:229-241`),
and a send waits for the channel's window; while it waited, the loop read
none of the channel's messages, which carry the end. And in the relay
stream, the task that sends stopped reading the pipe when a send failed,
while the task that receives could wait for russh to read (now
`crates/podssh-ssh/src/relay_stream.rs:195-292`): russh, which waited on a
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
waits for the window (`crates/podssh-ssh/src/io.rs:229-241`), and in the
relay stream each task's end with the link stops the other
(`crates/podssh-ssh/src/relay_stream.rs:195-292`).
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
called. `docs/cli.md:4542-4543` says that the key "is never used".

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
(`crates/podssh-ssh/src/keys.rs:278`).

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
says why at `-v` and goes on with the next key (`crates/podssh-ssh/src/keys.rs:270`).
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
(`crates/podssh-ssh/src/keys.rs:310-311`). russh says so for a key of OpenSSH and for an RSA key
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
file: `podssh ssh -i` (`crates/podssh-ssh/src/keys.rs:307-352`), `podssh agent add` and
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
  (`crates/podssh-cli/src/agent/serve.rs:184-192`).
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


# T-391: `--persist` that never gives up, for a tunnel of `-N`

**Source:** the operator, 2026-11-01: the study of Nemo-010/d-mon (T-389's Source); its third
finding.
**Category:** feature
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`podssh ssh --persist -N -R ...` keeps a reverse tunnel across lost links, but gives up after 10
attempts within 300 s of a loss: an outage of the relay or of the server's network of more than 5
minutes ends the tunnel for good, and the server is locked out.

## Premise

- Read: `ATTEMPTS` is 10 and `WITHIN` 300 s (`crates/podssh-cli/src/ssh/persist.rs:25`), and a
  connection of less than 30 s counts in the round of the loss before it.

## Approach

`--persist=always` (and `-o Persist=always`): no limit of attempts, with the backoff of the relay
(1 to 30 s with jitter, at most 5 minutes apart after an hour of failures), and a line for each
attempt, then one each 10 attempts. A refusal that cannot change (an unknown host key, a refused
authentication: 255 with its cause) still ends the run. The default stays as it is.

## Decision

A flag of its own, `--persist-forever`, in place of `--persist=always`: `--persist` takes no value
today, and a value of its own would change how `--persist DEST` is read. `--persist` has no form of
`-o`, so neither has this. The wait is the relay's backoff, as a node's (1 s doubling to 30 s, with
a jitter of half either way), with no longer pause after an hour: an attempt is one connection,
and a server waits for its tunnel no longer than it must. Lost: a growing pause, which a relay with
many such clients would want; it can come with a ruling of the relay's operator. The first
connection that fails is a loss too, so that a unit that starts the tunnel before the network
is up keeps trying; its prompts may still ask, as no session owns the input before a login.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib ssh::persist
cargo test -p podssh-cli --test persist persist_forever
```

## Done

2026-11-01: `podssh ssh --persist --persist-forever` never gives up.

- `crates/podssh-cli/src/ssh/persist.rs`: `next_wait` (no limit with `forever`) and
  `attempt_words` (the first 10 attempts said, then one in 10); a reach or a login that failed
  before the first attach is a loss with `forever`, after its lines; batch mode only after a
  login. `--persist-forever` without `--persist` is refused (64). The manual's paragraph of
  `--persist` and `docs/cli.md` say it.
- Tests: `cargo test -p podssh-cli --lib ssh::persist`, 3 passed (the limit of 10 attempts and 5
  minutes; `forever` outlasts both, its wait at most the backoff's 45 s; the attempts said);
  `cargo test -p podssh-cli --test persist`, 7 passed, two new:
  `persist_forever_keeps_trying_a_server_that_is_not_there` (`--persist` alone ends with 255 at the
  first failure; with `--persist-forever` the third attempt comes and the run goes on) and
  `persist_forever_without_persist_is_a_usage_error`. Planted, a first failure final again with
  `forever`: the first test failed. The manual's tests (`man_flag_parity`, `flag_table`,
  `man_page`, `man_json`) passed; clippy `-D warnings`: clean.
- The entry's Prove named a test of ten failed attempts after a loss; the unit test shows the
  limit lifted, and the integration test the attempts going on, in 5 s in place of the 5 minutes
  that ten real attempts take.

# T-460: A reply to a global request that carries data ends the connection: a quiet minute with keepalives, and a refused `-R`

**Source:** GitHub #83 (Nemo-010, 2026-11-02): against a Go SSH server (`SSH-2.0-Go`, behind a
gateway), `podssh ssh HOST 'sleep 100; echo alive'` ends after 62 s with "SshEncoding: unexpected
trailing data at end of message (15 bytes)" and 255; `-o ServerAliveInterval=20` ends it at 21 s,
`=0` keeps it, and a command that prints each second lives; its comment: on that server no
interval holds a quiet session past the relay's idle cut. GitHub #85 (the same day):
`-N -R 12345:127.0.0.1:9` against a Go server ends 0.7 s after the login with "the connection was
lost while the forwards were asked for". Read at `f8d15bf`.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

A server built on Go's x/crypto/ssh may answer a global request with data after the reply's type.
russh, podssh's SSH client, ends the whole connection on such a reply: on a failure of any
request, and on a success of a keepalive or a ping. podssh's keepalives are on by default, each
60 s, so on such a server each session that goes quiet for a minute dies, and the only way out,
`ServerAliveInterval=0`, gives the session to the relay's idle cut at 180 s. `-R`, whose
`tcpip-forward` such a server refuses, ends the run as a lost connection, where podssh should warn
and go on. OpenSSH's client reads no data of either reply, and keeps the session.

## Premise

Read in russh 0.65.0, the version of the lock (cargo's registry), its `src/client/encrypted.rs`: a
REQUEST_SUCCESS that answers a keepalive or a ping must end where its type ends (`ensure_end`,
lines 971-976), and so must each REQUEST_FAILURE, before russh looks at which request it answers
(lines 1041-1043); the `?` of each ends the session's task. `ensure_end` gives ssh-encoding's
`TrailingData` (russh's `src/parsing.rs`, lines 13-22), whose words are those of #83. The
generic `Handle::send_global_request` keeps a success's data (`GlobalRequestResponse::Other`,
lines 1032-1033), but not a failure's. russh's API sends no channel request of a free name (its
`src/channels/mod.rs`), and no SSH_MSG_IGNORE.

Read, through fetch.web.pkgforge.dev on 2026-11-02: Go's x/crypto/ssh gives each reply of a global
request a field for the rest of the message (`golang/crypto:ssh/messages.go`,
`globalRequestSuccessMsg` and `globalRequestFailureMsg`), and `Request.Reply(ok, payload)` sends
that payload in a failure too (`golang/crypto:ssh/channel.go`, `Reply`; `golang/crypto:ssh/mux.go`,
`ackRequest`); the reply to a channel's request carries none. OpenSSH's client reads no data of
either reply: `client_global_request_reply` calls the callback of the request, and its keepalive
registers none (`openssh/openssh-portable:clientloop.c`, `client_global_request_reply` and
`server_alive_check`).

- Read: keepalives are on by default, each 60 s (`crates/podssh-ssh/src/options.rs:388`), as
  russh's own (`crates/podssh-ssh/src/run_config.rs:71-72`), so that the relay's idle cut never
  meets a quiet session; `-o ServerAliveInterval=0` turns them off, with the warning of the cut
  (`crates/podssh-cli/src/ssh/resolve.rs:400-403`) that #83's comment reads. T-332's question on
  `--direct` sends russh's ping (`crates/podssh-ssh/src/io.rs:239`), which the same reply ends.
- Read: the handler keeps russh's error in podssh's words, and a lost session names it
  (`crates/podssh-ssh/src/handler.rs:206`, `crates/podssh-ssh/src/session.rs:30-33`); a decode
  error has no words of podssh's (`crates/podssh-ssh/src/run.rs:478`), so #83 read russh's.
- Read: a forward that the server refuses is a warning, and the run goes on
  (`crates/podssh-ssh/src/remote.rs:90-95`); a refusal with the connection gone ends the run as
  lost, with no cause (`crates/podssh-ssh/src/remote.rs:87-88`). `tcpip_forward` gives the same
  `None` for an error and a refusal (`crates/podssh-ssh/src/remote.rs:127`).
- Inferred: #85's server sent a failure with data. A failure with none, or a success with data
  (which russh reads as a refusal when more than a port came), leaves the connection up, and
  podssh would have warned (`crates/podssh-ssh/src/remote.rs:94`); the connection was gone 0.7 s
  after the login, as the failure's decode ends it. #83's 15 bytes are a failure's too, then: a
  Go server that knows no `keepalive@openssh.com` refuses it.
- Read: the project carries a patched crate in `vendor/` through `[patch.crates-io]`, iroh-relay's
  (`vendor/README.md:154-173`, `Cargo.toml:244-246`), and watches its upstream (T-341); russh's
  copy went with T-356, as 0.65.0 gave what its patch had added.

## Approach

1. A stand-in of the report's server first: a Go server on x/crypto/ssh, the library under
   gliderlabs/ssh, of a few lines in scripts/interop-go-ssh/ (new), which runs a command, refuses
   `tcpip-forward`, and answers each other global request with `Reply(false, payload)` of 15
   bytes; a second mode answers with `Reply(true, payload)`. Its harness, scripts/interop-go-ssh.sh
   (new, its checks in `scripts/interop-baseline.txt`), runs in a workflow of its own with Go on
   the runner, as `.github/workflows/build.yml` sets Go up for T-385's transports. Run first on
   the code of now: a quiet session ends with 255 at about 60 s, and `-R` as lost, #83 and #85
   reproduced.
2. russh 0.65.0 into vendor/russh from cargo's copy, with one patch
   (vendor/patches/russh/0001-reply-data.patch): a reply's data after its type is read as RFC
   4254, section 4, leaves it ("response specific data"), and dropped where podssh needs none: a
   success that answers a keepalive, a ping, `no-more-sessions@openssh.com` or a cancel, and a
   failure that answers any request. A success of `tcpip-forward` for port 0 reads its port and
   drops the rest. Each drop is a debug line, never an end. The patch's tests, in russh's own way
   of crafted messages (as its `third_ext_info_is_rejected`): a failure with 15 bytes after a
   keepalive, a success with data after a ping, and a failure with data after `tcpip-forward`,
   each leave the session up and give the caller its answer.
3. `[patch.crates-io]` takes it, as iroh-relay's; `vendor/README.md` gets its section (the
   upstream, the patch and why, how to carry it to another version); T-341's watch reads it, and
   cargo-deny and `scripts/check-vendored-advisories.py` read it as a path package.
4. The words where a message still does not decode: `describe` names a message of the server
   that podssh could not read, then russh's words; a connection lost while the forwards were asked
   for names russh's cause, as a lost session does (the reading of T-464).
5. The patch offered to russh upstream. That is the operator's to send, as no session changes
   another repository (`docs/decisions.md:74` says "no session changes another repository"); the
   copy goes once a release of russh reads such replies.
6. `docs/cli.md` (the keepalive, and `-R`'s refusal), `docs/STATUS.md`.

## Decision

- A copy of russh with a patch, as iroh-relay's: it repairs both reports, and each request whose
  reply a Go server fills. Lost: podssh's own keepalive through `send_global_request`, which
  keeps a success's data but still ends on a failure's, the reply that Go gives to a request that
  it does not know (Premise); a keepalive that asks for no reply, which keeps the idle cut away
  but finds no dead far end for ServerAliveCountMax, and leaves `-R` broken (and russh's
  `send_keepalive(false)` queues a reply that never comes; `send_global_request` with no reply
  does not); a keepalive as a request on the session's channel, which Go answers with no data
  (#83's third ask): russh's API sends none of a free name; and a wait for a release of russh, as
  no entry waits for another party.
- #83's second ask, a failure that names the keepalive and its workaround: with the patch the
  session lives, so no workaround is said; a message that still does not decode names itself
  (Approach item 4).
- The stand-in is built in the Go of `images/derper/Dockerfile`, pinned to a digest, against
  x/crypto v0.58.0 checked by Go's checksum database, and runs on the Alpine of
  `images/box/Dockerfile`: the harness then runs the same on a runner and on any host with a
  container engine, as `scripts/interop-wstunnel.sh` does, and `scripts/check-repo.py` keeps
  each image in one place. Lost: `actions/setup-go` on the runner (Approach item 1), which ties
  the harness to GitHub's runners and to a Go that no file of the repository pins.
- The plants run on the runner (the group `host-gossh` of `plants.yml`), as the harness starts
  containers of its own. The Prove's plant of the copy with no patch is the failure's reading
  put back (`t460-failure-data-ends`), the reply of #83; the others would fail the same tests.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test --manifest-path vendor/russh/Cargo.toml --target-dir .work/russh-target --lib client::reply_data
cargo test -p podssh-ssh --lib -- run::tests
sh scripts/interop-go-ssh.sh
```

Against Go's x/crypto/ssh, in the harness's workflow: `sleep 100; echo alive` with the default
keepalive exits 0 and prints `alive`, and with `-o ServerAliveInterval=20` too, in both modes;
`-N -R 12345:127.0.0.1:9` warns "remote port forwarding failed for listen port 12345" and waits,
and with `-o ExitOnForwardFailure=yes` exits 255 with that error. Planted: the published russh
(the patch's line of `[patch.crates-io]` gone): the quiet session ends with 255 at about 60 s, and
the harness fails; the patch's tests fail on the copy with no patch.

## Done

Drafted 2026-11-02 by an agent, which built nothing; merged and measured by the main session the
same day. The WIP `818f7fe` (branch `worktree-agent-t460-ssh`) is carried onto
`main` here, with what it left.

- `vendor/russh`: crates.io's russh 0.65.0, the crate that cargo unpacked of that release file
  for file (`diff -r`, 2026-11-02, but `.cargo-ok`), and the same tree with
  `vendor/patches/russh/0001-reply-data.patch` applied: the patch is the whole difference. In
  `src/client/encrypted.rs`, `drop_reply_data` (a debug line) in place of `ensure_end` for each
  failure, before russh looks at which request it answers, and for the success of a keepalive,
  a ping, `no-more-sessions@openssh.com`, a cancel and `streamlocal-forward`; a success of
  `tcpip-forward` gives its port, then drops the rest. Its 5 tests in `src/client/reply_data.rs`
  (crafted packets through `process_packet`, as `third_ext_info_is_rejected`): a failure with
  15 bytes after a keepalive, then a ping answered; a success with data after a keepalive and a
  ping; a failure with gliderlabs/ssh's words after `tcpip-forward` (a refusal), then a cancel
  taken; a success of port 0 with data (its port); and replies with no data, as before.
  `cargo test --manifest-path vendor/russh/Cargo.toml --target-dir .work/russh-target --lib
  client::reply_data`: 5 passed. `diff -r` of `vendor/russh` against cargo's own copy of
  russh 0.65.0 with the patch applied: no difference (but `.cargo-ok` and
  `.cargo_vcs_info.json`).
- `Cargo.toml`: `[patch.crates-io]` takes `vendor/russh`, and `exclude` keeps it out of the
  workspace; `fuzz/Cargo.toml` the same; both locks' `russh` with no source and no checksum.
  `vendor/README.md`'s section (the upstream, the release read, the patch and why, how to carry
  it). `AGENTS.md`'s map, Dependabot's comment, `docs/development.md` (check 10, the watch).
  `scripts/check-vendored.py` watches russh again; `scripts/check-vendored-advisories.py` reads
  it as each path package, unchanged.
- `scripts/check-repo.py`, check 10 (`scripts/repo_scans.py`, `patch_misses`): each package of
  a `[patch.crates-io]` must come from its path in its lock, with no `[[patch.unused]]`; two
  planted locks (the release, an unused patch) must be found, and a lock of the path not.
  `python scripts/check-repo.py`: each check passed, check 10 with its "2 planted locks found".
- `describe` names a message of the server that does not decode, then russh's words
  (`a_message_that_does_not_decode_names_the_server`); a connection lost while `-R`'s forwards
  were asked for names the server's words of a DISCONNECT, else russh's error
  (`crates/podssh-ssh/src/remote.rs`, `lost_while_asked`). `cargo test -p podssh-ssh`: 309
  passed, none failed (1 ignored).
- `scripts/interop-go-ssh.sh` with its stand-in `scripts/interop-go-ssh/main.go` (Go's
  x/crypto/ssh v0.58.0; a failure, or a success, with 15 bytes for each global request but
  `tcpip-forward`, which it refuses with 27): 8 checks, `go-ssh.*` in
  `scripts/interop-baseline.txt` (floor 8); `.github/workflows/go-ssh-interop.yml` runs it;
  the release check's row `actions.gossh` (`scripts/release-check-catalog.sh`). UNVERIFIED:
  `gh workflow run go-ssh-interop.yml --ref main`, 8 of 8, and first on the code before the
  patch (the plant below): #83 and #85 reproduced.
- Plants: `t460-published-russh` (the patch's line of `[patch.crates-io]` gone, the lock on
  crates.io's russh: `go-ssh.quiet.failure.default` must fail) and `t460-failure-data-ends` (a
  failure read with `ensure_end` again: the patch's first test must fail), group `host-gossh`.
  UNVERIFIED: `gh workflow run plants.yml --ref main -f group=host-gossh`, or on a host with
  Docker, `sh scripts/plant-each.sh --here t460-published-russh t460-failure-data-ends`.
- `docs/cli.md` (a refused `-R` and the keepalive against Go's servers).
- The merge: `cargo build`; clippy of `podssh-ssh` with `-D warnings`, all targets: clean; `cargo
  deny check`: advisories, bans, licenses and sources ok, russh a path package. In GitHub Actions at
  `7f31fef` (2026-11-02): `go-ssh-interop.yml` (run 41496677959), `interop-go-ssh: 8 passed, 0
  failed`, each quiet session alive after 100 s and `-R`'s refusal a warning (or 255 with
  `ExitOnForwardFailure=yes`); the plants of `host-gossh` (run 41496696749), 2 caught:
  `t460-failure-data-ends` (the patch's test of a failure with data failed) and
  `t460-published-russh` (3 passed, 5 failed, "unexpected trailing data at end of message (15
  bytes)"). The rest the draft named for the main
  session: `cargo todo interop`; `cargo todo remap` of
  `Cargo.toml`, `docs/development.md`, `vendor/README.md`, `AGENTS.md`, `docs/cli.md` and
  `docs/STATUS.md` (the draft moved their citations by hand, `Cargo.toml:219` among them);
  and TruffleHog: the test keys of russh 0.65.0 are where 0.64.1 held them, so after the commit
  on `main` add to `.github/secrets-allow.txt`, with that commit's first 12 digits for COMMIT
  (and the draft branch's commit, if it is pushed):

```text
PrivateKey vendor/russh/src/keys/mod.rs:279 COMMIT  # ED25519_KEY of russh's keys tests
PrivateKey vendor/russh/src/keys/mod.rs:289 COMMIT  # ED25519_AESCTR_KEY of russh's keys tests, password test
PrivateKey vendor/russh/src/keys/mod.rs:385 COMMIT  # a test key of russh's keys tests
PrivateKey vendor/russh/src/keys/mod.rs:406 COMMIT  # a test key of russh's keys tests
PrivateKey vendor/russh/src/keys/mod.rs:428 COMMIT  # a test key of russh's keys tests
PrivateKey vendor/russh/src/keys/mod.rs:547 COMMIT  # a test key of russh's keys tests
PrivateKey vendor/russh/src/keys/mod.rs:583 COMMIT  # a test key of russh's keys tests
PrivateKey vendor/russh/src/keys/mod.rs:601 COMMIT  # a test key of russh's keys tests
PrivateKey vendor/russh/src/keys/mod.rs:620 COMMIT  # a test key of russh's keys tests
PrivateKey vendor/russh/src/keys/mod.rs:658 COMMIT  # a test key of russh's keys tests
PrivateKey vendor/russh/src/keys/mod.rs:693 COMMIT  # a test key of russh's keys tests
PrivateKey vendor/russh/src/keys/format/tests.rs:9 COMMIT  # a test key of russh's format tests
PrivateKey vendor/russh/src/helpers.rs:286 COMMIT  # a test key of russh's helpers tests
```

  The scan's own findings are the list to trust: a key that it finds elsewhere goes in too.
- The patch for russh upstream (Approach item 5) is the operator's to send.

# T-461: A link that ends after the exit status and before the output's end gives that status: output cut at the relay's 64 MiB exits 0

**Source:** GitHub #84 (Nemo-010, 2026-11-02):
`podssh ssh --result-file r.json HOST 'head -c 70000000 /dev/zero' > out.bin` exits 0, stderr
empty, with 67010560 bytes of 70000000; the file holds `"exit":0` beside the relay's close 1009
`session byte cap`, in three runs and in a second sandbox; with 100000000 bytes the run exits 255
with the cap's words. Read at `f8d15bf`.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The relay ends a session at 64 MiB, both ways together. When the server's exit status came before
the last of the output, and the relay then cut the session, `podssh ssh` exits with that status,
0 here, and says nothing, also at `-v`; the bytes after the cut are lost. A script reads a success
and a cut file. The relay's close is in `--result-file` alone.

## Premise

- Read: when the channel ends with the connection, the session gives the status if one came, and
  is lost only with none:
  `crates/podssh-ssh/src/io.rs` line 273 at `582b1bf` said "None => return status.map(End::Status)", and so does
  the wait of a send (`crates/podssh-ssh/src/io.rs`, line 356 at `582b1bf`). The channel's EOF
  is not kept: it falls through (`crates/podssh-ssh/src/io/msg.rs`, lines 70-72 at `582b1bf`). So
  a status, then a lost link, reads as the command's end.
- Read: a run that ends with a code prints no line, whatever the relay's close
  (`crates/podssh-ssh/src/run.rs:63`); the lines of a close, with "a session carries 64 MiB at
  most" (`crates/podssh-ws/src/close.rs:91-93`), come for a run that failed alone
  (`crates/podssh-ssh/src/run.rs:87-107`).
- Read: the exec of the copy and the probes takes the same rule: a status, then a lost channel, is
  its end (`crates/podssh-ssh/src/exec.rs`, line 109 at `582b1bf`).
- Read: the relay stream counts the payload both ways, as the relay counts its cap
  (`crates/podssh-ssh/src/relay_stream.rs:133-137`), and `podssh cp` opens a new relay session
  before the cap with that count (T-137; the cap and the budget,
  `crates/podssh-relay/src/relay.rs:25` and `crates/podssh-relay/src/relay.rs:34`). A session of
  `podssh ssh` cannot go on in a new relay session: its SSH connection is one, and a plain sshd
  keeps nothing to resume; a node's layer moves its session before the cap (T-155).
- Read, through fetch.web.pkgforge.dev on 2026-11-02: OpenSSH's client ends its loop on a closed
  or failed read with a message, and returns the status that came
  (`openssh/openssh-portable:clientloop.c`, `client_process_net_input` and the end of
  `client_loop`), so it exits with the status in #84's case too.
- Inferred: a server sends the status when the command exits, while the command's last output can
  still wait for the client's window, in the server's buffers or a gateway's (RFC 4254 orders
  them in no way). The cut can then come between them, as in #84; with 100000000 bytes the command
  was still writing at the cut, and no status had come.

## Approach

1. The end of the output is the channel's EOF or its Close. The loop keeps the EOF; a link that
   ends after a status and before either is a cut: the run fails with 255, its line "the
   connection to HOST was lost before the output ended (the remote command had exited with N)",
   then the relay's lines (its close, and the remedy of the cap), as for a lost session. A status
   and an EOF, then a lost link, keep the status, as now.
2. `--result-file`: `"end": "lost"`, `"exit": 255`, and the remote `"status"` kept, so that a reader
   sees both; the class of the failure is `relay` when the relay closed abnormally, as now.
3. The same rule in the exec's finish (`exec.rs`), for the copy by exec and the probes.
4. Near the cap, a line on stderr once the payload passes the budget of the relay's limits (60
   MiB): "this relay session has carried 60 MiB, and the relay ends it at 64 MiB; podssh cp
   copies more on new sessions", not with `-q`.
5. `docs/cli.md` (the exit codes, the relay's cap), the manual's note, `docs/STATUS.md`.
6. Tests: the tests' SSH server (`crates/podssh-cli/tests/ssh_harness/mod.rs`) gets a command
   `cut N`: the exit status 0, then N bytes, then the end of the connection with no EOF and no
   Close; and `cut-eof N`, with the EOF before the end.
   `podssh ssh --direct` on `cut 1000000` exits 255 with the line, and on `cut-eof 1000000` exits
   0; the result file holds each.

## Decision

- A status that came before the output's end, then a cut link, is no success: 255, as a lost
  session. Lost: OpenSSH's reading, which exits with the status (Premise): podssh cannot tell a
  clean close of the target from the relay's cut on every road, and a success that lost bytes is
  the worse error. Lost: the status with a warning: a script reads the code, not the line. Lost:
  the rule on an abnormal close of the relay alone, as a reset on `--direct` loses bytes the same
  way.
- No rotation for `podssh ssh`, which #84 names as the ideal: the far end of a plain sshd keeps
  nothing to go on with (Premise); a node's layer does it already (T-155). No refusal up front: the
  size of a command's output is not known before it runs.
- The same rule in a session through a control master, which then tells its client no status
  (so it exits 255, as with none), and in `--persist`, which then ends with the lines of the cut and
  attaches nothing again: the shell had ended. Lost: the rule in the exec alone (Approach item 3),
  which leaves the same success with lost bytes on those two roads.
- The tests' server cuts a connection through a stream of its own that the command breaks (its
  reads end, its writes fail), 2 s after its last message is queued, so russh drops it with no
  DISCONNECT, as the relay's cap leaves the SSH inside it. Lost: a DISCONNECT, which is a word of
  the server and no cut; and a handler's error, which ends the session before the queued bytes and
  the EOF go out, so `cut-eof` could not be told from `cut`.
- The warning near the cap lives in `podssh ssh`'s run on the relay's road (`ssh/near_cap.rs`),
  which knows the relay's limits and `PODSSH_SESSION_BUDGET` as `podssh cp` reads them, and reads
  the count each 250 ms. Lost: the relay stream of `podssh-ssh`, which knows no limits of a relay.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib -- exit_code_of_end
cargo test -p podssh-cli --test ssh_exit_status -- cut
cargo test -p podssh-cli --test ssh_result -- cut
```

Planted: a cut read as its status: the tests of `cut` fail. Live, through the live relay to
railway.new's sshd: `head -c 70000000 /dev/zero` never exits 0 with fewer bytes than asked, in 5
runs; `head -c 50000000 /dev/zero` exits 0 with each byte. The gate's interop against OpenSSH and
Dropbear (`scripts/interop.sh`, T-026's codes) keeps each status, and waits for the release's
checks.

## Done

Drafted 2026-11-02 by an agent, which built nothing; merged and measured by the main session the
same day.

- `crates/podssh-ssh/src/io.rs`: `End::Cut(status)`, and `link_ended(status, eof)`: a status with
  the output's end (the channel's EOF, kept in `Out`, before or after it) is the command's end; a
  status alone, then a lost link, is a cut; none is a loss. Both waits of the channel (the loop and
  a send) read it. `io/msg.rs` keeps the EOF. `outcome.rs` gives `lost` for a cut, and the status
  stays in the record. `session.rs`: `cut(host, status)`, the words "the connection to HOST was
  lost before the output ended (the remote command had exited with N)", which `code` gives as the
  failure; the run's failure lines then add russh's cause and the relay's close with its remedy,
  as for a lost session, and the class is `relay` after the relay's abnormal close, else `session`.
  `cargo test -p podssh-ssh --lib -- exit_code_of_end`: 5 passed, the new
  `exit_code_of_end_when_the_link_ends_after_the_status` among them.
- The same rule in `exec.rs`'s finish (the copy by exec, the probes): a status, then a lost link,
  with no EOF and no Close, is `ExecError::Lost`; in `mux/msession.rs` (a session through a control
  master gives no status); and in `persist.rs` (the lines of the cut, and no attach again).
- `crates/podssh-cli/src/ssh/near_cap.rs`: one line at INFO (so none with `-q`) once a relay session
  has carried the budget of the relay's limits, 60 MiB, or `PODSSH_SESSION_BUDGET`'s less: "this
  relay session has carried 60 MiB, and the relay ends it at 64 MiB; podssh cp copies more on new
  sessions"; `podssh ssh` runs it beside each try on the relay's road. Its 3 tests, on tokio's
  paused clock: `cargo test -p podssh-cli --lib -- ssh::near_cap`, 3 passed.
- The tests' server: each connection on a stream that a command can cut with no word
  (`crates/podssh-cli/tests/ssh_harness/cut.rs`); `cut N` (the status 0, N bytes, the cut) and
  `cut-eof N` (the EOF before the cut). `channel_eof`'s body moved to `ssh_harness/eof.rs`, as
  `mod.rs` was at 499 lines. Tests: `ssh_exit_status` (`cut 1000000`: 255 with the line within
  10 s; `cut-eof 1000000`: 0 and each byte) and `ssh_result` (`lost`, 255 and `status` 0 beside
  them; then `status` and 0): `cargo test -p podssh-cli --test ssh_exit_status --test ssh_result
  -- cut`, 2 and 1 passed; and each other test of the server's users, as each connection now runs
  on the cuttable stream: 1366 passed, 0 failed, 52 ignored (Unix, 2026-11-02, at the merge of T-460 to T-464, run in chunks of 15 targets, each chunk's binaries deleted after it, as the disk holds no more).
- The plant `t461-cut-is-status` (a cut read as its status; group `cli-tests`), `sh
  scripts/plant-each.sh --here t461-cut-is-status`: caught, the test of a cut after the status
  failed.
- The manual: the row of 255, the note of `--result-file`, the note of the keepalives (the line
  near the cap), and the session limits of the variables; `docs/cli.md` (the result file, and a
  bullet on the cut beside T-026's).
- The merge: clippy of `podssh-ssh` and `podssh-cli` with `-D warnings`, all targets: clean;
  `cargo fmt -p` of both. Waits for the checks of the release: the live run of the Prove through
  the live relay to railway.new (`head -c 70000000 /dev/zero` in 5 runs never 0 with fewer bytes,
  and `head -c 50000000 /dev/zero` 0 with each byte), 350 MB, more than a live test with its entry
  carries (AGENTS.md, section 6), and railway.new refused each login on 2026-11-02 (the bundle's
  L-02), so a target with a shell behind the relay is the release check's to name; the interop of the gate against OpenSSH and Dropbear (`scripts/interop.sh`, T-026's
  codes), which waits for the release's checks; and `cargo todo remap` of each file that the
  draft changed and an entry cites (`docs/cli.md`, `docs/STATUS.md`,
  `crates/podssh-ssh/src/io.rs`, `crates/podssh-ssh/src/io/msg.rs`,
  `crates/podssh-ssh/src/session.rs`, `crates/podssh-ssh/src/exec.rs`,
  `crates/podssh-ssh/src/persist.rs`, `crates/podssh-ssh/src/mux/msession.rs`,
  `crates/podssh-cli/src/man/notes_ssh_more.rs`, `crates/podssh-cli/src/man/facts.rs`,
  `crates/podssh-cli/src/ssh/mod.rs`, `crates/podssh-cli/tests/ssh_harness/mod.rs`): the draft
  moved their citations by hand.
- The Premise's quote of `crates/podssh-ssh/src/io.rs` reads at `582b1bf` now, the tree before
  the repair, as its line is gone.

# T-462: A `-J` hop whose channel opens and then carries nothing ends in a bare handshake timeout, and the open has no limit

**Source:** GitHub #86 (Nemo-010, 2026-11-02):
`podssh ssh -v -J USER@HOST USER@HOST 'echo via-jump'` against a Go SSH server logs in to the hop,
says "SSH handshake with HOST", and 60 s later "HOST: the SSH handshake did not finish within
60 s", 255; the issue reads it as a hop with no `direct-tcpip`. Read at `f8d15bf`.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A hop that takes the channel to the next hop and then carries nothing gives, after 60 s, a line
that names a handshake, and never the hop or its channel; with no `-v` nothing is said in the
60 s. A user debugs the destination, or the network. And the open of the channel waits for the
hop's answer with no limit.

## Premise

- Read: each later hop is reached on a `direct-tcpip` channel of the one before
  (`crates/podssh-ssh/src/run.rs`, lines 165-168 at `582b1bf`); the open waits for the hop's
  answer with no limit, and
  a refusal is named at once in the hop's words (`crates/podssh-ssh/src/forward.rs:19-21`), which
  `crates/podssh-cli/tests/jump_hop.rs:180` tests ("administratively prohibited").
- Read: "SSH handshake with" is said once the channel opened (`crates/podssh-ssh/src/run.rs:399`),
  and its limit, ConnectTimeout (60 s by default, `crates/podssh-ssh/src/options.rs:390`), gives a
  line with the next hop's label alone (`crates/podssh-ssh/src/run.rs:404-405`).
- Inferred, against the issue's reading: #86's hop opened the channel, as the handshake's line
  came, and nothing of an SSH server answered on it within 60 s. A hop with no `direct-tcpip`
  refuses the open, and podssh names that at once.
- Read: `--direct` marks the first byte that comes through a proxy, and a failure with none heard
  names the proxy (`crates/podssh-cli/src/ssh/transport.rs:104-130`, T-317); a hop's channel has no
  such mark.

## Approach

1. The open of a hop's channel has ConnectTimeout's limit, and its line names the hop and the
   target: "the hop HOP did not answer the open of a channel to DEST:PORT within 60 s".
2. `-v`: "the hop HOP opened a channel to DEST:PORT" once it opened.
3. The channel's stream marks its first byte, as `--direct`'s does. A handshake that runs out with
   nothing heard says "the hop HOP opened its channel to DEST:PORT, and no byte came on it within
   60 s: no SSH server answered behind the hop"; with a byte heard, the line of now.
4. `-v` says the wait: a line after 10 s with nothing from DEST through HOP, and each 10 s after.
5. Tests, in `crates/podssh-cli/tests/jump_hop.rs`: the harness's `direct-tcpip` to a listener of
   the test that reads and never writes, with `-o ConnectTimeout=3`, ends with 255 within 10 s and
   names the hop and its channel; a hop that never answers the open (a user of the harness whose
   server never answers `direct-tcpip`) gives the open's line after 3 s; the refused hop's test
   stays.

## Decision

The open's limit is ConnectTimeout, as for the handshake that follows it: one setting for the
whole reach of a hop. Lost: a limit of its own, which nobody set. The lines of the wait are for
`-v` alone, as each other line of the reach is: without `-v` podssh says nothing until it fails,
as OpenSSH does. Lost: a line at 10 s for each run, which a script's stderr would get in each slow
login.

- A channel that closes before any byte came names the hop too ("and it closed before any byte
  came"), as no SSH server answered behind it either: a login that heard nothing and failed before
  the limit is that case, and one that failed at the limit is #86's. The line of the login goes to
  `-v`. Lost: that line alone for a closed channel, "HOST: the connection closed unexpectedly",
  which names the destination as #86's line did.
- The reach lives in a module of its own, `crates/podssh-ssh/src/hop.rs`, beside `run.rs`, which
  stays under 500 lines; its stream marks the first byte as `--direct`'s mark of its proxy does,
  a copy of a few lines, as `podssh-ssh` cannot reach `podssh-cli`'s. Lost: a new class of
  `HopError` for a silent hop, which `cp`, `pipe` and `--persist` read: a silent hop is unreachable
  to them, as before.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib -- hop::tests
cargo test -p podssh-cli --test jump_hop
```

Planted: the first byte always marked as heard: the test of the silent channel fails, with the old
words.

## Done

Drafted 2026-11-02 by an agent, which built nothing; merged and measured by the main session the
same day.

- `crates/podssh-ssh/src/hop.rs`: `Reach`, the reach of each later hop: the open of its
  `direct-tcpip` channel within the hop's ConnectTimeout ("the hop HOP did not answer the open of a
  channel to DEST:PORT within N s"), `-v`'s "the hop HOP opened a channel to DEST:PORT", and the
  login on `Heard`, a stream that marks its first byte; while nothing came, `-v` says "nothing yet
  from DEST:PORT through the hop HOP, after N s" each 10 s; a failure to reach with nothing heard
  says "the hop HOP opened its channel to DEST:PORT, and no byte came on it within N s: no SSH
  server answered behind the hop" at the limit, else "and it closed before any byte came", and the
  login's own line goes to `-v`. `run.rs`'s `connect_hops` takes it for each hop after the first.
  Its 5 tests in `crates/podssh-ssh/src/hop_tests.rs` (the mark, a stream with nothing, the wait's
  lines on tokio's paused clock, the words of each failure, the open's line); `test-util` of tokio
  for `podssh-ssh`'s tests. `cargo test -p podssh-ssh --lib -- hop::tests`: 5 passed.
- The tests' server: a user `pass-mute-...` whose server never answers a `direct-tcpip` open
  (`ssh_harness/pass.rs`, `ssh_harness/forward.rs`'s `never`). Three tests in
  `crates/podssh-cli/tests/jump_hop.rs`, each with `-o ConnectTimeout=3`: a target behind the hop
  that reads and never writes (255 within 10 s, the line, and `-v`'s open), one that closes at once
  (the closed line), and the mute hop (the open's line after 3 s and before 10 s); the refused
  hop's test stays. `cargo test -p podssh-cli --test jump_hop` (Unix): 6 passed.
- The plant `t462-always-heard` (the mark set at the start; group `cli-tests`), `sh
  scripts/plant-each.sh --here t462-always-heard`: caught, the silent channel's test failed.
- The manual's note of `-J` (`notes_ssh_more.rs`), `docs/cli.md` (the destination's bullet),
  `docs/STATUS.md`.
- The merge: clippy of `podssh-ssh` and `podssh-cli` with `-D warnings`, all targets: clean; the
  whole suite of `podssh-cli`: 1366 passed, 0 failed, 52 ignored (Unix, 2026-11-02, at the merge of T-460 to T-464, run in chunks of 15 targets, each chunk's binaries deleted after it, as the disk holds no more). Waits: a live run against a Go server as
  #86's, which the tests' russh server stands in for, waits for T-460's harness of Go's x/crypto/ssh
  (`scripts/interop-go-ssh.sh`), whose server could take a mode with a hop's silent channel; and
  `cargo todo remap` of each file that the draft changed and an entry cites
  (`crates/podssh-ssh/src/run.rs`, `crates/podssh-cli/src/man/notes_ssh_more.rs`,
  `crates/podssh-cli/tests/ssh_harness/mod.rs`, `docs/cli.md`, `docs/STATUS.md`): the draft moved
  their citations by hand, and `crates/podssh-ssh/src/run.rs:161-173` in T-347's Premise
  (`TODO/roads.md`) by reading.

# T-463: A warning before the relay's idle cut, while the user can still act

**Source:** GitHub #98 (Nemo-010, 2026-11-02, a request): the relay ends a session after 180 s
with no payload; podssh says so once at the connect when keepalives are off, and after the cut;
`sleep 175` with `-o ServerAliveInterval=0` printed nothing between. It asks for a line at about
150 s of silence, the terminal's title with a pty, `--idle-warn SECONDS`, and `-q` to silence it.
Read at `f8d15bf`.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A session that crosses the relay with keepalives off, or slower than the idle cut, gets no word
before the cut: a shell left idle, or a script that waits on a lock, is gone at 180 s, and the
first word is the cut's. A warning 30 s before would let the user press a key, or know why.

## Premise

- Read: the warning at the connect, on the relay's road when ServerAliveInterval is off or at least
  the cut (`crates/podssh-cli/src/ssh/resolve.rs:400-403`); after the cut, the relay's close with
  its remedy (`crates/podssh-ws/src/close.rs:88-90`). The cut is the relay's, from its limits
  (`crates/podssh-relay/src/relay.rs:70-73`), counted on payload alone (`docs/relay.md:452`).
- Read: the relay stream counts the payload both ways
  (`crates/podssh-ssh/src/relay_stream.rs:133-137`), and keeps the time of the relay's last frame
  of any kind, keepalives among them (`crates/podssh-ws/src/session.rs:288-291`,
  `crates/podssh-ssh/src/relay_stream.rs:192`); it kept no time of the last payload before this
  entry's draft (read at `582b1bf`). So #98's
  reading that the client already knows the time of the last byte holds for no clock that the cut
  counts: russh's keepalive counts SSH's packets in.
- Read: the notice of a silent far end (T-302) has the places that this needs: the window's title
  with a pty on a terminal that keeps the stack of titles, taken back before the far end's next
  bytes, and none with `-q` or for output that goes elsewhere
  (`crates/podssh-ssh/src/notice/mod.rs:229-244`, `crates/podssh-ssh/src/notice/title.rs`).
- Read: with T-460, the default keepalives hold a quiet session on the servers of #83 too; the
  warning is for `ServerAliveInterval=0`, an interval at or above the cut, and `podssh proxy`
  under a client with none.

## Approach

1. The relay stream keeps the time of the last payload, either way, beside its count.
2. A watch of each session on the relay's road (`podssh ssh`, and `podssh proxy`, whose stderr its
   client shows): when the payload's age reaches the cut less the lead (30 s: at 150 s of 180),
   one warning, and none again until a payload crossed. With a pty on a terminal that keeps the
   title stack, in the title, as T-302's notice, taken back at the next payload; else one line on
   stderr: "the relay ends this session in 30 s, as nothing crossed it for 150 s: a key, or -o
   ServerAliveInterval below 180, keeps it".
3. `--idle-warn SECONDS`, the lead; 0 turns it off, and so does `-q`. The manual, the table of
   `podssh man --json`, `docs/cli.md`.
4. On a road with the relay's cut alone: not on `node://` (the layer's heartbeat), `--direct`, the
   iroh road or DERP.
5. Tests, on tokio's paused clock: no payload for 150 s gives the warning once; a payload at 140 s
   moves it; the title with a pty, and its return at the next byte; none with `-q`, none with 0.

## Decision

- A line on stderr also where stderr is no terminal: the agents and scripts that #98 names read
  stderr from a pipe, and a cut session is theirs too. T-302's notice stays out of a pipe, as it
  counts its seconds up; this one is a single line. Lost: a terminal alone.
- `--idle-warn SECONDS`, as #98 asks, with no `-o` keyword, as OpenSSH has none of it.
- The lead is 30 s, or a sixth of a shorter cut, which a relay's limits may give (T-342).
- The warning keeps nothing alive: podssh sends nothing that the user turned off. Lost: an
  SSH_MSG_IGNORE as the cut nears, which needs no reply and which each server ignores (RFC 4253,
  section 11.2): it would undo the `ServerAliveInterval=0` that the user set, and russh 0.65.0 has
  no call that sends one.
- The work goes by Q85 (2026-11-02: the testers' features go too), in the order of the work order.
- The title is T-302's: the warning goes there through the session's `Silence`, which the notice
  reads at its tick, where the session shows that notice in the title (`Silence::titled`); the
  notice of a silent far end takes the title's place when both stand, and the far end's next bytes,
  or a payload that the watch sees, take it down. Lost: a title of the watch's own, which would
  push the terminal's stack a second time beside the notice's, and write at no boundary of the
  output.
- The watch lives beside the run, as the line near the cap (T-461): a task of `podssh ssh` on the
  relay's road alone (no layer), and one of `podssh proxy` on the relay's end of its pipe, which
  keeps the same clock (`notice::idle::Crossed`). Not with `--persist` or `--upgrade` in this
  draft: the first attaches its shell again after the cut, and both reach the relay through runs of
  their own; a later entry may give them the watch. Lost: the watch inside the session's pump,
  which `podssh proxy` has none of.
- `--idle-warn` is parsed after the resolve, in `podssh ssh`'s run, as
  `crates/podssh-cli/src/ssh/resolve.rs` is at 500 lines; its value goes in
  `podssh_ssh::Options::idle_lead`. A value that is not a whole number of seconds is refused with
  64 before anything connects. Lost: a time with a unit (`30s`), as the flag's name says seconds,
  as `ConnectTimeout` does.
- For the operator to confirm (Q86): the live run goes to the operator's server of
  `PODSSH_THROUGHPUT_SSH`, which Q38 names for the throughput run, for 3 minutes with nothing
  sent: no test target of `AGENTS.md` gives a shell behind the relay's forward road (railway.new's
  service runs no command, GitHub's endpoint gives no session, a node has no idle cut). Lost: no
  live run, which leaves the Prove's line unchecked; and the loop of the live relay to a node of
  the session's own (T-157's cell), whose node:// leg has no idle cut, though its forward session
  has, and which a session could build later.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib -- notice::idle
cargo test -p podssh-cli --lib -- ssh::idle_warn
cargo test -p podssh-cli --test ssh_args -- idle_warn
cargo test -p podssh-cli --test proxy -- idle_warn
cargo test -p podssh-cli --test relay_live -- --ignored idle_warn
```

The live test, through the live relay with `-o ServerAliveInterval=0` and `sleep 200`, to the server
of `PODSSH_THROUGHPUT_SSH`: the line at about 150 s, then the cut's at 180 s, each once (`sleep 175`,
#98's, ends before the cut). Planted: the payload's time never moved: the test of a payload at 140 s
fails.

## Done

Drafted 2026-11-02 by an agent, which built nothing; merged and measured by the main session the
same day.

- `crates/podssh-ssh/src/notice/idle.rs`: `Crossed`, the time of the last payload (a count of
  milliseconds after its start, which clones share); `lead` (30 s, or a sixth of a shorter cut, or
  the one asked; none for 0; never at the cut); `Idle`, whose `at` waits until the cut less the
  lead, then warns once, and gives `Crossed` at the next payload; the words of the line and of the
  title; `watch`, the loop. Its 8 tests in `notice/idle_tests.rs`, on tokio's paused clock: the
  warning once at 150 s, a payload at 140 s moves it, a payload after it ends it, the watch ends
  with its session, the lead, the words, and the title up and down through a `Notice`.
  `cargo test -p podssh-ssh --lib -- notice::idle`: 8 passed.
- `crates/podssh-ssh/src/notice/mod.rs`: `Silence::set_idle` and `idle`; the notice puts the
  warning in the title at its tick where no notice of silence shows, takes it down with the far
  end's next bytes (which also end the warning) or once the watch says a payload crossed, gives the
  title's place to the notice of silence, and takes it back at its drop. The notice's other tests
  hold as before: `cargo test -p podssh-ssh --lib -- notice`, 15 passed, and
  `cargo test -p podssh-ssh --test silent_notice`, 5 passed.
- `crates/podssh-ssh/src/relay_stream.rs`: `RelayStatus::last_payload`, marked by each count of
  payload (a keepalive of the relay carries none). `podssh_ssh::Options::idle_lead`.
- `crates/podssh-cli/src/ssh/idle_warn.rs`: `lead_of` (whole seconds, 0 for none, else the refusal
  with its remedy), `spawn` for `podssh ssh` (none with `-q` or 0; the title through `Silence`
  where the session shows it there, else a line at INFO; aborted at the run's end, beside T-461's
  line near the cap) and `spawn_proxy` (a line on stderr). Its 2 tests. `cargo test -p
  podssh-cli --lib -- ssh::idle_warn`: 2 passed.
- The flag `--idle-warn SECONDS` on `ssh` (`flags/idle.rs`, `SshArgs::idle_warn`, once) and on
  `proxy` (`PROXY_FLAGS`, `Parsed::Proxy`, `ProxyArgs`); `podssh proxy` keeps the clock in the
  relay's end of its pipe (`pipe/relay.rs`, `carry_watched`). Tests: `tests/ssh_idle/mod.rs`, a
  module of `ssh_args.rs` (3: as typed, whole seconds, once) and `tests/proxy.rs` (1: it reaches
  the verb, and a bad value is 64). `cargo test -p podssh-cli --test ssh_args` (29 passed) and
  `cargo test -p podssh-cli --test proxy` (10 passed).
- The live test in `crates/podssh-cli/tests/relay_live.rs` (`--ignored`), which fails with no
  server named. Measured in its place, 2026-11-02, on this host: podssh's relay role (`podssh relay
  serve`, whose cut is the contract's 180 s with no payload) on the loopback in front of OpenSSH's
  sshd, and `podssh ssh -o ServerAliveInterval=0 HOST 'sleep 200; echo alive'` through it (a
  scratch script with throwaway keys, removed after): one line "the relay ends this session in
  29 s, as nothing crossed it for 150 s: a key, or -o ServerAliveInterval below 180, keeps it",
  then the role's close 1001 ("idle timeout") with its remedy, 255 after 180 s, and no "alive".
- The plant `t463-payload-never-moves` (group `resume`). `sh scripts/plant-each.sh --here
  t463-payload-never-moves`: caught, `a_payload_at_140_s_moves_the_warning` failed.
- The manual's notes of `ssh` (the keepalives) and `proxy`, the help of each row (and so `podssh
  man --json`), `docs/cli.md` (a bullet beside `--result-file`), `docs/STATUS.md`.
- The merge: rustfmt of `podssh-cli` (one call of `ssh/mod.rs` wrapped) and clippy of
  `podssh-ssh` and `podssh-cli` with `-D warnings`, all targets: clean after one repair (a slice
  of one clone in `idle_tests.rs`, `std::slice::from_ref`); the whole suite of `podssh-ssh`: 326
  passed, 0 failed, 1 ignored; the whole suite of `podssh-cli`: 1366 passed, 0 failed, 52 ignored (Unix, 2026-11-02, at the merge of T-460 to T-464, run in chunks of 15 targets, each chunk's binaries deleted after it, as the disk holds no more); `cargo todo remap` from the tree before the draft of each file that it changed.
  Waits: the live test through the live relay, to the server of `PODSSH_THROUGHPUT_SSH`, which this
  session has not (its target is a call for the operator to confirm, Q86); and the watch for
  `--persist` and `--upgrade` (Decision), for a later entry.

# T-464: A connection that ends right after the login reads as a refused session, or as a loss with no cause

**Source:** GitHub #104 (Nemo-010, 2026-11-02): against a stopped sandbox whose gateway
(`SSH-2.0-Go`) still logs in, `podssh ssh -v HOST 'echo hi'` says "the server refused to open a
session: Disconnected", on another run "...: Channel send error", then "the relay closed the
connection (code 1000): target closed", 255; four times in an afternoon, each time read as a fault
of the relay. GitHub #85 (the same day): the lost connection while `-R`'s forwards were asked for
names no cause. Read at `f8d15bf`.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

When the server ends the connection between the login and the first channel, podssh says that the
server refused a session, with russh's words; the server refused nothing. A refusal and a lost
connection read alike, so a user cannot tell a far host that has stopped from a server that
refuses a session, and debugs the relay.

## Premise

Read in russh 0.65.0, the version of the lock (cargo's registry), its `src/client/mod.rs`:
`channel_open_session` gives `SendError` when the connection's task went before the request
(lines 849-852), `Disconnect` when it went before the answer (lines 768-771), and
`ChannelOpenFailure` for the server's refusal alone (lines 765-766). So the words that #104 reads
as the server's are russh's.

- Read: each error of the session's open gives "the server refused to open a session", with
  russh's words after (`crates/podssh-ssh/src/session.rs`, lines 62-63 at `582b1bf`), and that
  open has no limit, where the exec's and SFTP's have one (`crates/podssh-ssh/src/exec.rs:83`,
  `crates/podssh-ssh/src/sftp/mod.rs:174`). `describe` reads `Disconnect` and `SendError` as a
  connection that closed (`crates/podssh-ssh/src/run.rs:461-463`); the session's open does not
  call it. The other opens give one line for each error alike (read at `582b1bf`:
  `crates/podssh-ssh/src/exec.rs` line 84, `crates/podssh-ssh/src/mux/msession.rs` line 65,
  `crates/podssh-ssh/src/sftp/mod.rs` line 170, `crates/podssh-cli/src/ping/far.rs` line 51).
- Read: the handler keeps the server's DISCONNECT in words, and russh's error
  (`crates/podssh-ssh/src/handler.rs:201`, `crates/podssh-ssh/src/handler.rs:206`); the open reads
  neither. The relay's close with 1000 comes as a line after the message
  (`crates/podssh-ssh/src/run.rs:94-97`).
- Read: the lost connection of `-R`'s requests names no cause
  (`crates/podssh-ssh/src/remote.rs`, lines 87-88 at `582b1bf`), where a lost session names
  russh's (`crates/podssh-ssh/src/session.rs:30-33`).

## Approach

1. One reading of an open's error, for each place that opens a channel after the login (the
   session, `-R`'s requests, the exec, SFTP, a control master's session, `ping`):
   `ChannelOpenFailure` is a refusal, in OpenSSH's words of its reason ("open failed:
   administratively prohibited"); `Disconnect`, `SendError` or a closed handle is a connection
   that ended: "the server ended the connection right after the login, before a session opened",
   with the server's own words when it sent a DISCONNECT, else russh's cause from the handler;
   then one line of what it may mean: "the far host may be stopped, the login may no longer be
   valid, or the server takes no more sessions".
2. The session's open within ConnectTimeout, as the exec's and SFTP's opens have their limits.
3. Tests: the tests' SSH server (`crates/podssh-cli/tests/ssh_harness/mod.rs`) gets a user whose
   server ends the connection when a session channel is asked for, and one whose server refuses
   it (administratively prohibited);
   `podssh ssh --direct` exits 255 with the line of each; and `-R` to a server that ends the
   connection at `tcpip-forward` names the cause.

## Decision

The words name what podssh knows, the order of the events, and then say what it may mean, with no
product's name: a sandbox is #104's case, not each server's. Lost: #104's own sentence ("the
sandbox may be stopped, the token expired"). The cause comes first and the reading second, so a
script that reads the first line gets the fact.

- The line of what it may mean is the message's second line, indented by two spaces, as the
  lines of a host key's refusal follow their first: one message, so the relay's close and the
  result file's class come after it as for each failure. Lost: a line of its own at INFO, which
  `-q` would hide while the error stays, and which would come before the cause.
- A refusal's words are OpenSSH's `reason2txt` (`openssh/openssh-portable:channels.c`, read
  through fetch.web.pkgforge.dev on 2026-11-02: "administratively prohibited", "connect failed",
  "unknown channel type", "resource shortage", else "unknown reason") after "open failed: ", as
  its client says "channel N: open failed: REASON"; a reason that russh does not know gives the
  server's words, made safe. A control master keeps its "Session open refused by peer" for a
  refusal, OpenSSH's words of a master.
- An exec whose connection ended is `ExecError::Lost`, no longer `Refused`: `podssh job` read a
  refusal as "runs no command for podssh job: it needs a shell", and `cp` as an answer of the
  server, where a link that broke is the fault (`crates/podssh-cli/src/job/far.rs:190`,
  `crates/podssh-cli/src/cp/byexec.rs:67-68`); `--persist`'s probe then connects again.
- The tests' server ends the connection in two ways: a DISCONNECT with words (`gone-said-...`,
  #104's gateway as a server that says why) and a cut with no word (`gone-...`, through T-461's
  stream), each at the open, whose reply it holds unanswered, as a drop of it would refuse.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib -- unopened::tests
cargo test -p podssh-cli --test ssh_exit_status -- after_login
```

Planted: the refusal's words for each error, as now: the test of the user whose server ends the
connection fails.

## Correction

Read with T-460's draft in the tree, 2026-11-02:

- The lost connection of `-R`'s requests names its cause there already: the server's words of a
  DISCONNECT, else russh's error (`lost_while_asked`, `crates/podssh-ssh/src/remote.rs:99-109`),
  as T-460's Approach item 4 took this entry's reading. Here `-R` keeps that line, and gets the
  test of Approach item 3.
- The lock's russh is `vendor/russh` there, crates.io's 0.65.0 with T-460's patch, which adds 5
  lines to `src/client/mod.rs` above that code: the code that the Premise reads in cargo's copy is
  at `vendor/russh/src/client/mod.rs:875-878` (`SendError`), `vendor/russh/src/client/mod.rs:794-797`
  (`Disconnect`) and `vendor/russh/src/client/mod.rs:791-792` (`ChannelOpenFailure`).
- russh closes the queue of the connection's requests before it calls the handler's
  `disconnected` (`vendor/russh/src/client/mod.rs:1385-1392`): an open that fails with
  `SendError` can come before the handler kept the cause. The reading waits for the cause, half a
  second at most.
- `ChannelOpenFailure::Other` keeps the server's words of a reason that russh does not know
  (`vendor/russh/src/lib_inner.rs:416`); the known ones keep none.

## Done

Drafted 2026-11-02 by an agent, which built nothing; merged and measured by the main session the
same day.

- `crates/podssh-ssh/src/unopened.rs`: `read` gives `Refused` (russh's `ChannelOpenFailure`, in
  OpenSSH's words of its reason), `Ended` (`Disconnect`, `SendError`, `HUP`, `RecvError`, an
  unexpected EOF, or a closed handle; with the server's words of its DISCONNECT, else russh's
  cause, after a wait of 500 ms at most for the handler to keep one, `handler::cause_kept`) or
  `Other`; `words` says "the server refused to open WHAT: open failed: REASON", or "the server
  ended the connection right after the login, before WHAT opened: CAUSE", then "  the far host
  may be stopped, the login may no longer be valid, or the server takes no more sessions". Its 3
  tests. `cargo test -p podssh-ssh --lib -- unopened::tests`: 3 passed.
- The session's open (`session.rs`, `open_session`) within ConnectTimeout, with those words; the
  exec's (`exec.rs`: a refusal stays `Refused`, an ended connection is `Lost`), SFTP's
  (`sftp/mod.rs`), a control master's session (`mux/msession.rs`) and `podssh ping`'s
  (`crates/podssh-cli/src/ping/far.rs`) read the same way. `-R` keeps T-460's line.
- The tests' server (`crates/podssh-cli/tests/ssh_harness/gone.rs`): `gone-said-...` (a
  DISCONNECT at the session's open), `gone-...` (a cut at it, with no word), `gone-fwd-...` (a
  DISCONNECT at `tcpip-forward`) and `nosession-...` (administratively prohibited); each other
  user's session opens, and its `tcpip-forward` is refused, as before. Four tests in
  `crates/podssh-cli/tests/ssh_exit_status.rs` (`..._after_login_...`): 255 and the order of the
  events with no "refused"; 255 with no words; the refusal's reason, with no line of what it may
  mean; and `-N -R` with the server's words. `cargo test -p podssh-cli --test ssh_exit_status`
  (Unix): 9 passed, the four among them; each test of the server's other users, as each session's
  open and each `tcpip-forward` now pass `gone.rs`: the whole suite below.
- The plant `t464-ended-is-refused` (the session's open says the refusal's words for each error
  again; group `cli-tests`). `sh scripts/plant-each.sh --here t464-ended-is-refused`: caught, 3 of the 4 tests failed.
- The manual's row of 255, `docs/cli.md` (a bullet beside T-461's), `docs/STATUS.md`.
- The merge: rustfmt and clippy of `podssh-ssh` and `podssh-cli` with `-D warnings`, all targets:
  clean; the tests of `cp`, `job` and `--persist` whose server ends a connection at an exec, which
  now read `Lost` where they read `Refused`, and the whole suite of `podssh-cli`: 1366 passed, 0 failed, 52 ignored (Unix, 2026-11-02, at the merge of T-460 to T-464, run in chunks of 15 targets, each chunk's binaries deleted after it, as the disk holds no more);
  `cargo todo remap` from the tree before the draft of each file that it changed and an entry
  cites, in place of the draft's moves by hand. Waits: a live run against a far host that stops
  behind a gateway, as #104's, which no test target gives.

# T-500: A destination with no user name is refused when `USER`, `LOGNAME` and `USERNAME` are unset, where OpenSSH reads the user database

**Source:** the report of the operator's testing agents, a black-box test of `v1.0.0` (`35a0d19`)
on a Debian 13 guest with a curated environment, 2026-11-02: its issue 01 (`01-no-user-name.md`)
and its ledger's L-01. `env -u USER -u LOGNAME -u USERNAME podssh ssh --direct 127.0.0.1 'id -un'`
exits 64 with "no user name: give one with user@host or -l USER", and so do `cp`, `mv`, `scp`,
`sftp`, `health`, `ping`, `run`, `each`, `containers` and `job`; OpenSSH 10.0p2 on the same host
logs in as the uid's entry of `/etc/passwd`, and podssh with `-l agent` does too. Read at
`01e371e`.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

An agent's harness, `env -i`, `docker exec` with an environment of its own and many runners start
podssh with none of the three variables, and the process still runs as a uid with an entry in
`/etc/passwd`. Each command that logs in then refuses a destination with no user name (64), the
one that a hosted service prints (`ssh railway.new`) among them, and the user does not know which
name to give. OpenSSH on the same host connects.

## Premise

- Read: the local user is `USER`, else `LOGNAME`, else `USERNAME`, else `root` for uid 0 alone
  (`crates/podssh-cli/src/ssh/resolve_env.rs:40`, `crates/podssh-cli/src/ssh/resolve_env.rs:63-70`);
  with none, a destination with no user, no `-l` and no `User` is refused
  (`crates/podssh-cli/src/ssh/resolve.rs:273`), and so is a jump host
  (`crates/podssh-cli/src/ssh/jump.rs:235-236`). Each verb of the report resolves its destination
  there, so one change serves all eleven.
- Read: the manual says that podssh never reads the user database
  (`crates/podssh-cli/src/man/facts.rs:201-204`); the reason is in
  `docs/target-environment.md:37-44`: on hosts with no passwd entry, OpenSSH's tools exit 255 ("No
  user exists for uid 0"), so podssh takes the name from the environment. The rule is no row of
  `docs/decisions.md`; T-222 (on hold) says the same of the shell of `podssh serve`.
- Read: the same name is `%u`, `Match localuser` (`crates/podssh-cli/src/ssh/config/matching.rs:110`),
  the nick of `chat`, and the default comment of `keygen`, "never from the user database"
  (`crates/podssh-cli/src/man/notes_keygen.rs:48-49`).
- Read, against the report: the README of this repository holds no prompt with `ssh railway.new`
  (no line of `README.md` names Railway, at `01e371e` and at `35a0d19`); that one-liner is
  Railway's own page. Its L-02, Railway's refusal of each login of the day, is the service's state,
  as `docs/STATUS.md` records in the row of `podssh ssh node://`, and no defect of podssh.

## Approach

1. `PODSSH_USER` first, then the three variables (Q68), then the name of the effective uid's entry, when the host has one: on
   Linux and the BSDs the first line of `/etc/passwd` whose uid field is the euid, read as a file
   (no NSS, which a static binary lacks); on macOS `getpwuid_r`. A file that is missing or
   unreadable, or that has no such line, gives no name and no error, so a host with no entry is as
   now. uid 0 with no entry stays `root`. A variable that is set still wins.
2. With no name from any of them, the refusal says what was read and what to do: "no user name:
   PODSSH_USER, USER, LOGNAME and USERNAME are not set, and uid 1000 has no entry in
   /etc/passwd: give user@host, -l USER, PODSSH_USER, or User in ssh_config".
3. `-v` says once where the name came from: "the user name agent is uid 1000's entry in
   /etc/passwd, as USER, LOGNAME and USERNAME are not set".
4. One function gives the name to each user of it: the login, the tokens, `Match localuser`, the
   nick of `chat` and the comment of `keygen`. The manual's VARIABLES (`USER`), the notes of
   `keygen` and `docs/target-environment.md` say the new order.
5. Tests: the function over the text of a passwd file and a uid: the entry's name; no line for
   the uid, a line with too few fields, an empty file: none, and the refusal's words; uid 0 with no
   entry: `root`. In `crates/podssh-cli/tests/ssh_args.rs`, `podssh ssh -G` with the three
   variables removed gives the entry's name as its `user` line, on a Unix host that has one.

## Decision

Recommendation, for the operator to rule, as the manual and `docs/target-environment.md:42-44`
state "never the user database" as a rule: read the entry last, after the variables, and go on without
it. The rule's reason holds: a host with no entry gives the refusal of now, and nothing fails where
an entry is missing, which is where OpenSSH fails. Lost: a new variable, `PODSSH_USER` (the report's
third way): `USER` is the variable that each tool reads, and `PODSSH_SSH_CONFIG` with `Host *` and
`User NAME` already sets a name once for a harness. Lost: the refusal alone with better words (its
second way): the name that it would print is the entry's, which it would read anyway.

**Ruled, Q68 (2026-11-02):** the entry last, and `PODSSH_USER` too, against the loss above: `PODSSH_USER` names the login first, then `USER`, `LOGNAME` and `USERNAME`, then the entry. The Approach says it.

The draft's calls (2026-11-02), where the ruling left a choice:
- The effective uid, as Q68 says. Lost: the real uid, which OpenSSH's `ssh` reads: the two differ
  in a setuid run alone, and podssh is never one.
- On macOS `getpwuid_r` first, then `/etc/passwd` as a file, which holds the system's own accounts
  (rule 7, a fallback). Lost: `getpwuid_r` alone. On Linux and the BSDs the file alone, as Q68
  says: a static binary has no NSS.
- The file's lines as the C library reads them: a comment, a line of NIS (`+`, `-`), a line of
  fewer than 7 fields and a name with a blank or a control character are passed over, and the
  first entry of the uid wins; at most 16 MiB is read. A file that is missing or unreadable gives
  no name and no error.
- The refusal names `USER` as a variable, as Q68 says it names `-l`, `PODSSH_USER` and `USER`: "no
  user name: PODSSH_USER, USER, LOGNAME and USERNAME are not set, and uid 1000 has no entry in
  /etc/passwd: give user@host or -l USER, set PODSSH_USER or USER, or set User in ssh_config". Lost:
  the Approach's "give user@host, -l USER, PODSSH_USER, or User in ssh_config", where `USER` reads
  as `-l`'s placeholder alone. A jump host's refusal has the same facts and no `-l`, which is the
  destination's in OpenSSH.
- The line of `-v` names the local user name ("the local user name agent is uid 1000's entry in
  /etc/passwd, as PODSSH_USER, USER, LOGNAME and USERNAME are not set"), whether the login or only
  `%u` takes it. Lost: the Approach's "the user name", which reads as the login's when `-l` gives
  another.
- The nick of `chat` and of `chat --irc` takes the one function, so uid 0 with no variable is
  `root` there too, where it was `podssh`. Lost: `podssh` for chat alone, two rules for one name.
  `doctor`'s line of the user database reads the four variables and names `PODSSH_USER` and `USER`.
- `resolve.rs` was at 500 lines: the relay road's CA trust is `tls_trust`, the same code, which made
  the room for the line of `-v`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib ssh::resolve_env
cargo test -p podssh-cli --test ssh_args -- user_database
```

Planted: the entry never read: the test of a host with no variables fails with the old refusal.

## Done

Drafted on 2026-11-02 by a drafting agent, which built nothing; merged and measured by the main
session on 2026-11-03. The Premise and the Decision read the tree at
`582b1bf`; their citations name the lines that this change rewrote.

- `crates/podssh-cli/src/ssh/resolve_env.rs`: `local_user()`, the one function of the local user's
  name (`PODSSH_USER`, `USER`, `LOGNAME`, `USERNAME`, then the euid's entry, then `root` for uid 0),
  with `UserFrom` (where it came from), `Env::login_user` (the name or the refusal) and
  `Env::user_note` (the line of `-v`). `Env` gains `user_from`. Its tests are
  `crates/podssh-cli/src/ssh/resolve_env_tests.rs`: the passwd text and a uid, the variables' order,
  the fallbacks, the refusal's and the note's words. `cargo test -p podssh-cli --lib ssh::resolve_env`: 6
  passed.
- `crates/podssh-cli/src/ssh/resolve.rs` and `crates/podssh-cli/src/ssh/jump.rs` refuse through
  `login_user`; the note joins the notes of `-v`. `crates/podssh-cli/src/ssh/tokens.rs` (`%u`),
  `crates/podssh-cli/src/chat/args.rs`, `crates/podssh-cli/src/chat/irc/plan.rs`,
  `crates/podssh-cli/src/keygen.rs` (its comment, through `Env::from_process`) and
  `crates/podssh-cli/src/doctor/unix.rs` take the same name. `Match localuser` takes it through
  `Env::user`, as before.
- `crates/podssh-cli/tests/ssh_user/mod.rs`, a module of `tests/ssh_args.rs`: resolved, the entry is
  the login with its line of `-v`, and a host with none refuses the destination and a jump host
  with 64; against the binary on Unix, `podssh ssh -G` with the four variables removed prints the
  euid's entry as its `user` line (as root it runs the binary as another uid of `/etc/passwd`, as
  uid 0 falls back to `root` anyway), and `PODSSH_USER` beats `USER`. `cargo test -p podssh-cli
  --test ssh_args -- user_database`: 3 passed, on Linux as root (uid 0), so the binary ran as
  another uid of `/etc/passwd` from `target/`; the whole `ssh_args`, 32 passed. macOS and Windows:
  CI's build at the push.
- The manual: `PODSSH_USER` joins the row of `USER`, `LOGNAME` and `USERNAME` in ENVIRONMENT
  (`crates/podssh-cli/src/man/facts.rs`), with the order, the refusal and `-v`; the notes of
  `keygen` (`crates/podssh-cli/src/man/notes_keygen.rs`). `cargo test -p podssh-cli --lib
  man::`, 37 passed, and `cargo test -p podssh-cli --test man_page`, 10 passed.
- `docs/target-environment.md` ("No user database"): the user database last, nothing fails with no
  entry; `docs/cli.md` (`%u`, and the comment of `keygen`).
- Planted: `scripts/plants/t500-entry-never-read.plant`, the file of the user database renamed to
  one that does not exist. `sh scripts/plant-each.sh --here t500-entry-never-read`: caught, the test of
  the binary failed.
- The merge: `cargo todo remap` from the tree before the draft of each file that it changed, in
  place of its text diff; rustfmt of `podssh-cli` (`%u` of `tokens.rs`) and clippy of `podssh-cli`
  with `-D warnings`, all targets, on Linux: clean; macOS and Windows: CI's build at the push.
# T-501: `--su` waits for ever when its password cannot be given: a cancelled `SSH_ASKPASS` leaves su waiting, and podssh with it

**Source:** the report of 2026-11-02 (T-500's Source): its issue 02 (`02-su-hang.md`) and its
ledger's L-03, L-05 and L-11. With an `SSH_ASKPASS` that exits 1 and `SSH_ASKPASS_REQUIRE=force`,
`podssh ssh --direct --su agent@127.0.0.1 'id -un'` prints "the password for the remote command:
cancelled" and runs on: killed at 30, 45, 150 and 180 s, with the far `su -c` still waiting for its
password; `--sudo` with the same helper ends with 1 in 1 s, and so does OpenSSH with `su -c`. With
no helper and no terminal, `--su` says at once that podssh may ask none, and ends 30 s later with
255 (L-05). Read at `01e371e`.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

An agent whose askpass helper fails (a call of `pass`, `gpg` or a keychain, a helper that cannot
run) gets a run that never ends, after a line that reads like an end. That breaks the README's
promise for a host with no terminal: podssh never waits for input that cannot come. With no helper
the run ends, but 30 s after the line that gave the reason, with a line that says the command never
asked.

## Premise

- Read: `su` reads a terminal alone, so `--su` asks for a pty, and `--sudo` for none
  (`crates/podssh-cli/src/ssh/elevate.rs:32-36`); `sudo -S` reads the channel
  (`crates/podssh-ssh/src/elevate.rs:1-10`).
- Read: at su's prompt, podssh drops the deadline of the start and asks on a thread
  (`crates/podssh-ssh/src/elevate.rs:333-337`). A cancelled answer (a helper that exits not 0 is
  `Cancelled`, `crates/podssh-ssh/src/prompt.rs:27-31`), and each other failure of the question,
  give a line and the end of the channel's input, and no new deadline
  (`crates/podssh-ssh/src/elevate.rs:378-384`); with no deadline the wait has no end
  (`crates/podssh-ssh/src/elevate.rs:222-227`, `crates/podssh-ssh/src/elevate.rs:355-361`).
- Inferred, from the report's controls: the end of the input stops `sudo -S`, whose stdin is the
  channel, and does not reach `su`, which reads the pty: OpenSSH's server takes the EOF of a pty's
  channel and keeps the pty open, so su waits, and podssh with it.
- Read: with no way to ask, podssh says so, ends the input and keeps the deadline
  (`crates/podssh-ssh/src/elevate.rs:325-332`); at 30 s its line says that the command "neither
  asked for a password nor started" (`crates/podssh-ssh/src/io.rs:308-312`), though it asked.
- Read: the tests run `--su` with a right and a wrong password, and with no helper that fails
  (`crates/podssh-cli/tests/ssh_sudo.rs:202-264`).
- Read (L-11): `--sudo` under a `NOPASSWD` rule sends no password, by design
  (`crates/podssh-ssh/src/elevate.rs:6-7`); no change.

## Approach

1. One end for each answer that cannot be sent (a cancelled question, a helper that failed or did
   not run, a thread that ended, and no way to ask): with `--su`, the pty's own end of the line
   that su reads, Ctrl-U then Ctrl-D, so that su's read ends and su refuses with its own words and
   status, as `sudo -S` does at the end of its stdin; then the channel's EOF, as now.
2. After that end, the deadline of 30 s again: a su that does not end gives 255 within it, with a
   line that says what podssh did ("su did not end within 30 s after podssh sent it no password:
   the helper was cancelled"), and podssh closes the channel, so that the far su gets its hangup.
3. The line of a failed helper names the cause: "the password for the remote command: SSH_ASKPASS
   exited 1, so podssh sends su no password"; the line of the 30 s says that the command asked,
   when it did.
4. With no way to ask (BatchMode, or no terminal and no helper), the same end at once: su's
   refusal, not a wait of 30 s.
5. Tests in `crates/podssh-cli/tests/ssh_sudo.rs`, against the harness's su: a helper that exits 1
   ends `--su` within 10 s with not 0 and the new line; no helper and no terminal ends within 10 s;
   `--sudo` with the same helper keeps its 1; a su of the harness that ignores Ctrl-D gives 255
   within the 30 s, with the line of step 2. In `scripts/interop-sudo.sh`, `--su` with a failing
   helper against OpenSSH's server ends with not 0, and no `su` of the test runs after it.

## Decision

- su's own refusal and status, as `--sudo` gives sudo's. Lost: 255 at once (the report's second
  reading), which hides whether su refused; 255 stays for a su that does not end.
- A cancelled helper sends no password: its output is no answer, as OpenSSH reads it. Lost: send
  what the helper wrote (the report's first reading).

The draft's calls (2026-11-02), where the Approach left a choice:
- su's two keys are the ones of the modes that podssh asked for the pty with (`VKILL`, `VEOF`),
  else the pty's defaults, Ctrl-U and Ctrl-D; a key that the modes turned off is not sent, and a
  session whose pty was not granted gets none, as the channel's EOF reaches su's stdin there. Lost:
  Ctrl-U and Ctrl-D always: a local terminal with other keys gives the far pty those, and su would
  read the two bytes as a password, a failed login in the far host's log.
- The line of a helper that failed names how it ended: `PromptError` gains `Exited` ("SSH_ASKPASS
  exited 1"), where it was `Cancelled` ("cancelled"). The other questions of podssh (password
  authentication, keyboard-interactive, the host key, `keygen`) say the same words now. Lost: the
  variant `Cancelled` with a new text alone, which could not say "exited 1" or a signal.
- sudo's second prompt (a refused password) gets the same time to end as a password that was not
  sent, with a line of its own ("sudo refused the password, and did not end within 30 s after podssh
  ended its input"), where it kept the time of the check of its password. Lost: no change there,
  whose line said that sudo had not asked again, after it had.
- At the time that ran out podssh closes the channel before it ends with 255, so that OpenSSH's
  server hangs up the far su's pty. Lost: the end of the connection alone, which does the same a
  moment later, with nothing said to the server.
- The interop check installs util-linux's su (`util-linux-login`) in the build image and gives root
  a password of the run, so that su asks podtest for one; with no su that asks, the check says
  `env`. Lost: busybox's su, which runs only where it is setuid, and the image does not say.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib elevate
cargo test -p podssh-cli --test ssh_sudo
```

Planted: no deadline after the end, as now: the test of the su that ignores Ctrl-D runs past its
limit and fails.

## Done

Drafted on 2026-11-02 by a drafting agent, which built nothing; merged and measured by the main
session on 2026-11-03. The Premise read the tree at `582b1bf` with the draft
of T-500, which none of its files changed; its citations name the lines that this change rewrote.
The harness's su took the channel's EOF as a refusal, which OpenSSH's server never gives su, so the
tests could not see the wait; it now reads its pty's keys and waits on at the EOF.

- `crates/podssh-ssh/src/elevate.rs`: `end_keys` (the two keys of su's pty, from the modes that
  podssh asked for); `Elevated` keeps them and a `Phase`, and one `end` sends them, then the EOF,
  then gives the command `WAIT` to end: for a question that failed, a helper that exited not 0 or
  could not run, a thread that ended, no way to ask (at once), and sudo's second prompt. The line
  of a time that ran out says what podssh did (`expired_line`). `crates/podssh-ssh/src/session.rs`
  passes the pty's modes and whether it was granted. `crates/podssh-ssh/src/io.rs` closes the
  channel when the time ran out. `crates/podssh-ssh/src/prompt.rs`: `PromptError::Exited`, how the
  helper ended. Tests in `crates/podssh-ssh/src/elevate_tests.rs`: the keys of su's pty, and the
  lines. `cargo test -p podssh-ssh --lib elevate`: 7 passed.
- The harness (`crates/podssh-cli/tests/ssh_harness/sudo.rs`, `mod.rs`, `far.rs`): su reads Ctrl-U
  and Ctrl-D as a pty in canonical mode, and refuses at its end of file; the channel's EOF leaves it
  waiting, as OpenSSH's server does; the su of a user `su-deaf-...` ignores both. Tests in
  `crates/podssh-cli/tests/ssh_sudo.rs`, each run within a limit: a helper that exits 1 ends `--su`
  within 10 s with su's refusal (1) and the new line; BatchMode with no helper ends within 10 s, and
  no line says that the command asked nothing; `--sudo` with that helper keeps its 1; the deaf su
  gives 255 within 45 s with "su did not end within 30 s after podssh sent it no password: SSH_ASKPASS
  exited 1". `cargo test -p podssh-cli --test ssh_sudo`: 9 passed on Linux; macOS and Windows (the
  helper a `.cmd` there): CI's build at the push.
- `scripts/interop-sudo.sh`, `sudo.su_cancelled` (`env-allowed` in `scripts/interop-baseline.txt`):
  `--su` with a helper that exits 1 against OpenSSH's sshd and util-linux's su: not 0 within 25 s,
  one question, the line of the helper, and no `su -c` of the run left in `/proc`. Waits for the build image, which this
  host's Docker did not run: the gate's step `release` at the push, which runs
  `scripts/interop.sh` and `cargo todo interop`, and says whether Alpine's `util-linux-login` gives
  a su that asks.
- Planted: `scripts/plants/t501-no-deadline-after-end.plant` (the Prove's: no time to end, the deaf
  su's test fails at its limit), `scripts/plants/t501-no-end-keys.plant` (no keys: the helper's test
  fails, 255 after 30 s) and `scripts/plants/t501-su-interop-no-end-keys.plant` (the same, against
  sshd: `sudo.su_cancelled` fails). `scripts/plants/t032-sudo-at-once.patch` moved with
  `Elevated::new`. `sh scripts/plant-each.sh --here t501-no-deadline-after-end t501-no-end-keys`:
  both caught (the deaf su's test and the helper's test failed). `t501-su-interop-no-end-keys` and
  `t032-sudo-at-once` (group `ssh-pty`, the static build of the image): `plants.yml` run 41560470075
  at a003af3, "plant-each: 5 caught, 0 missed, 0 stale"; `t501-su-interop-no-end-keys` failed
  `sudo.su_cancelled` (exit 255 in 30 s) and `t032-sudo-at-once` failed `sudo.nopass`.
- The manual (`crates/podssh-cli/src/man/notes_ssh.rs`, the note of `--sudo` and `--su`) and
  `docs/cli.md` say what a password that cannot be given does. `cargo test -p podssh-cli --test
  man_page`: 10 passed.
- The merge: the harness's end of input had moved to `ssh_harness/eof.rs` (T-461), so the draft's
  change of `mod.rs` went there. `cargo todo remap` from the tree before the draft, in place of its
  text diff; rustfmt and clippy of `podssh-ssh` and `podssh-cli` with `-D warnings`, all targets,
  on Linux: clean; macOS and Windows: CI's build at the push.
# T-503: The direct road dials a host name that the relay road refuses, and refuses a blank only at the dial, with 255

**Source:** the report of 2026-11-02 (T-500's Source): its issue 04 (`04-each-whitespace.md`), the
first part, and its ledger's L-19. `a$b`, `a!b` and `a/b` are refused with 64 through the relay
("\"a$b\" is not a host name ('$' is not allowed)"), and end with 255 with `--direct`, where `a$b`
reached the proxy as `CONNECT a$b:22`. The road decides which names are legal, and the direct road
is the one that a user falls back to when the relay is down. Read at `01e371e`.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

On the direct road (`--direct`, and the fallback once the relay hosts failed), podssh passes `$`
and `!` to the proxy or the resolver, and refuses a blank or a `/` only when it dials, with 255,
the code of a network failure. A script that assembles a name badly gets a dial, where the relay
road gives 64 before anything connects.

## Premise

- Read, against the report: the check of the relay road is podssh's own, before anything connects
  (`crates/podssh-cli/src/ssh/resolve.rs:354`, with `crates/podssh-ws/src/names.rs:10-32` and
  `crates/podssh-ws/src/names.rs:37-45`: letters, digits, `.`, `-` and `_`, or an IPv6 literal),
  not the relay's.
- Read: on the direct road, the destination is checked for an empty name and a first `-` alone
  (`crates/podssh-cli/src/ssh/hop.rs:79-87`), then at the dial for a blank, a control character,
  `/`, `?`, `#` and `@` (`crates/podssh-ws/src/dial.rs:346-354`, from
  `crates/podssh-ws/src/dial.rs:225`), which ends with "invalid destination" and 255. Inferred: the
  report's `a/b` with `--direct` is that refusal, which its table counts as a dial; `a$b` and `a!b`
  reach the proxy.
- Read: OpenSSH 10.0p2 refuses a destination that holds one of the characters of its
  `valid_hostname` (quotes, a backquote, `$`, `\`, `;`, `&`, `<`, `>`, `|`, parentheses, braces and
  a comma), a blank or a control character, with 255 before it connects
  (`openssh/openssh-portable:ssh.c`, at its tag `V_10_0_P2`); it takes `!`, `/` and each byte above
  127.
- Read: the relay road's check reads the host that is dialed, after `HostName`
  (`crates/podssh-cli/src/ssh/resolve.rs:354`).

## Approach

1. One check at the resolve, for each road, of the host that is dialed and of the first hop of
   `-J`: what `check_target` takes, and on the direct road also an IPv6 literal with a zone
   (`fe80::1%eth0`), which only a dial from this host can use; else 64 before anything connects,
   in the relay road's words. A name with a byte above 127 is refused with the advice of its ASCII
   form (`xn--`).
2. The check at the dial stays, the second line of defence for each other caller of
   `podssh_ws::dial`.
3. Each verb that resolves a destination gets it (`ssh`, `cp`, `mv`, `scp`, `sftp`, `run`, `each`,
   `job`, `health`, `ping`, `containers`, `edit`, `session start`); `pipe`'s `tcp:` and `ssh:` take
   their hosts through the same function.
4. Tests in `crates/podssh-cli/tests/ssh_args.rs`: `a$b`, `a!b`, `a/b` and a blank, with
   `--direct` and without: 64, and no dial (with `PODSSH_OFFLINE` set, a dial would say so);
   `fe80::1%eth0` with `--direct` passes the check, and through the relay it is refused, as now.

## Decision

The relay road's rule on each road, as the report asks, with the zone of a link-local address on
the direct road. Lost: OpenSSH's shorter list, which lets `!` and `/` go to the resolver or the
proxy, which refuse them later with 255; no name of DNS holds them. Lost: a name in Unicode on the
direct road: a proxy takes a CONNECT in ASCII, and podssh has no IDNA of its own; the line names
the `xn--` form.

The draft's calls (2026-11-02), where the Approach left a choice:
- For the operator to confirm (Q86): each host after the first, a later hop of `-J` and the
  destination behind it, is checked too, on each road, by the direct road's rule, as the hop
  before it dials it (so a zone there is that hop's). The relay road checked the first hop alone,
  so `-J bastion 'a$b'` reached the jump host, whose refusal ended the run with 255. OpenSSH
  applies its list to the destination of its command line whatever `-J` gives, and its jump
  process is an `ssh` of its own for each hop (not measured here). Lost: the first hop alone,
  which the Approach's words allow, and which leaves a `$` behind a jump host to the far server.
- The zone of an IPv6 literal is letters, digits, `.`, `-` and `_`, at most 64 characters, on any
  IPv6 literal, as the system's resolver takes it. Lost: a zone on a link-local address alone: a
  multicast address takes a zone too, and the resolver is the judge of the rest. Through
  `HTTPS_PROXY` the zone goes in the `CONNECT` as before, for the proxy to refuse.
- `pipe`'s `tcp:` and the target of `ssh:` keep the relay's rule of their parser
  (`crates/podssh-cli/src/proxy.rs:362`, before anything starts), so `tcp:` takes no zone; the hops
  of `ssh:` get the new check, through the resolve of `podssh ssh`. Lost: a zone for `tcp:` too:
  that parser is `podssh proxy`'s as well, whose target the relay dials.
- A host in a refusal is shown as it is typed when each of its characters prints as itself, else
  in quotes with its escapes, so that a blank or a control character is seen. `-4` and `-6` with
  `--direct` are refused in the same new file, with the same words, which made the room in
  `resolve.rs`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --lib names
cargo test -p podssh-cli --test ssh_args -- host_name
```

Planted: the direct road's check removed: `a$b` with `--direct` reaches the dial, and the test
fails.

## Done

Drafted on 2026-11-02 by a drafting agent, which built nothing; merged and measured by the main
session on 2026-11-03. The Premise read the tree at `582b1bf` with the drafts
of T-500 and T-501; its citations name the lines that this change rewrote. Found while drafting:
with `-J`, the relay road checked the first hop alone, and no road checked a later hop or the
destination behind it.

- `crates/podssh-ws/src/names.rs`: `check_direct_target` (what `check_target` takes, or an IPv6
  literal with a zone), and `check_host` names the ASCII form (`xn--`) for a character beyond
  ASCII; tests of both roads' names in the file. `cargo test -p podssh-ws --lib names`: 20 passed.
- `crates/podssh-cli/src/ssh/dialed.rs`, new: the first hop by its road's rule (the relay's, the
  direct road's, or none for a tunnel), each host after it by the direct road's, with the refusals
  in the relay road's words ("cannot reach a$b directly: ..."); `direct` also refuses `-4` and `-6`,
  moved from `resolve.rs`. `crates/podssh-cli/src/ssh/resolve.rs` calls it on the relay road, the
  direct road and behind a tunnel's first hop, before anything connects; each verb that resolves a
  destination gets it there. The check of `podssh_ws::dial` stays. Tests in the file.
  `cargo test -p podssh-cli --lib ssh::dialed`: 1 passed; `--lib ssh::`, 89 passed.
- `crates/podssh-cli/tests/ssh_hostname/mod.rs`, a module of `tests/ssh_args.rs`: `a$b`, `a!b`,
  `a/b`, a blank, a tab and a name beyond ASCII give 64 with `--direct` and without, and a
  `HostName` is checked as the host; `fe80::1%eth0` passes with `--direct` and behind a jump host,
  and through the relay it is refused; a host behind a jump host, and a later hop, are refused in
  the jump host's words; against the binary, `--direct` with `PODSSH_OFFLINE` set refuses
  `tester@a$b` with 64 and no line of `PODSSH_OFFLINE`, as nothing dials. `cargo test -p
  podssh-cli --test ssh_args -- host_name`: 5 passed on Linux, the whole `ssh_args` 36; macOS and
  Windows: CI's build at the push; the other tests that resolve a host, for a name that the rule
  now refuses: the whole suite of `podssh-cli` at the merge of T-500 to T-509 (2026-11-03, in chunks): 1448 passed, 0 failed, 52 ignored.
- The manual (`crates/podssh-cli/src/man/notes_ssh.rs`, a note of `podssh ssh`) and `docs/cli.md`
  give the rule. `cargo test -p podssh-cli --test man_page`: 10 passed.
- Planted: `scripts/plants/t503-direct-unchecked.plant`, the direct road's check removed: the test
  of each road fails. `sh scripts/plant-each.sh --here t503-direct-unchecked`: caught, the test of
  each road failed.
- The merge: the note of `podssh ssh` named the underscore as `_`, a word that the manual's test
  of names (`man::notes::tests::each_name_in_a_note_exists`) reads as a variable; it says
  "underscores" since T-509's merge, where `cargo test -p podssh-cli --lib man` found it.
  `cargo todo remap` from the tree before the draft, in place of its text diff;
  rustfmt of `podssh-cli` (one refusal of `dialed.rs`) and clippy of `podssh-ws` and `podssh-cli`
  with `-D warnings`, all targets: clean.

# T-583: The warning before the relay's idle cut with `--persist` and `--upgrade`

**Source:** the merge of T-463 (2026-11-02): its Decision leaves out `--persist` and `--upgrade`,
which reach the relay through runs of their own.
**Category:** feature
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`podssh ssh` warns 30 s before the relay's idle cut (T-463), but not with `--persist` or
`--upgrade`: a session of either that crosses the relay with keepalives off gets no word before
the cut. `--persist` attaches its shell again after the cut, so the loss is a pause; the line
would still say why the pause comes.

## Premise

- `crates/podssh-cli/src/ssh/mod.rs:351-353` says "if let Some(kept) = resolved.persist.clone() {",
  and returns from `persist::run` before the watch of the relay's road starts.
- `crates/podssh-cli/src/ssh/mod.rs:357-358` says "if let Some(upgrade) = resolved.upgrade.clone() {",
  and so does `upgrade::run`.
- `docs/cli.md:762` says "`--direct`; with `--persist`, which attaches again after the cut, and",
  and the next line "`--upgrade`, not before T-583."

## Approach

1. `persist::run` and `upgrade::run` start the watch of `crates/podssh-cli/src/ssh/idle_warn.rs` on
   each run that crosses the relay with no layer, as `podssh ssh` does, and abort it at that run's
   end.
2. With `--persist`, the line names the next attach: "the relay ends this session in 30 s, ...;
   --persist attaches again after it".
3. The manual's note of the keepalives and `docs/cli.md` drop the exception.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib -- ssh::idle_warn
```

A test of the line's words with `--persist`; and, against podssh's relay role in front of
OpenSSH's sshd, `--persist` with `ServerAliveInterval=0` warns once before the cut and attaches
again after it. Planted: the watch not started for `--persist`: the run against the role gives no
line, and the test fails.

# T-588: `ssh node://` waits ConnectTimeout for an SSH handshake that OpenSSH through `operator` finishes on the same node, and says nothing of what came

**Source:** GitHub #114 (a tester's agent, 2026-11-02), with `podssh 1.0.0 (35a0d19)`, the client
on Windows and the node on a gVisor sandbox in front of OpenSSH 10.0p2:
`ssh --pair-file F -l root --ConnectTimeout 25 node://NAME 'echo A'` said that the node opened a
resumable session, its features and its deadline, then "the SSH handshake did not finish within
25 s" (and the same at 120 s); at the same time `podssh operator --pair-file F NAME` read sshd's
version line in 3 s, and OpenSSH's client through it logged in in 4.4 s. Read at `3bb42ea`.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

On one node, at one time, `podssh ssh node://` cannot log in where `podssh operator` carries
OpenSSH's login: the fault is in podssh's client, between the layer and SSH. Its line says only
that the handshake did not finish, so a user cannot tell a node that sent nothing from a version
line that came and a key exchange that stopped; a longer ConnectTimeout gives the same line later.
A defect: `ssh node://` is the documented way to log in to a node.

## Premise

- Read: the handshake is one wait of ConnectTimeout around russh's `connect_stream`, and its line
  names no byte, no version line and no step (`crates/podssh-ssh/src/run.rs`, lines 395-403 at
  `3bb42ea`).
- Read: `ssh node://` carries SSH with `carry_keeping`: the layer's settings of `ssh`, which name
  `keep.v1` (`crates/podssh-cli/src/layered.rs:222`), the far end's shells learned and its
  silence watched (`:256-262`), and the SSH client and the carriage joined in one task
  (`crates/podssh-cli/src/ssh/node.rs:293-296`); `operator` carries with `carry_through`, with
  none of these (`crates/podssh-cli/src/operator.rs:164-165`). These are the client's differences
  between the run that stopped and the one that worked; which one stopped it is not known.
- Read: the tester's lines show the layer's session open and its features (`replay.v1`,
  `heartbeat.v1`, `move.v1`), so the relay, the pair and the layer's handshake worked; a roost
  checks sshd's version line on each session's connection
  (`crates/podssh-cli/src/man/notes_pair.rs:39-41`), so the node had sshd's line.
- Read: no test runs `ssh node://` with a client on Windows: `relay-live.yml` runs `node_live` on
  Linux alone (`.github/workflows/relay-live.yml:37`), and `node_live`'s `ssh_to_a_node`
  (`crates/podssh-cli/tests/node_live.rs:141-142`) serves railway.new:22 where no sshd runs, so a
  Windows runner can run it.
- Read: since `35a0d19`, T-460, T-462 and T-505 changed `crates/podssh-ssh/src/run.rs`, none for
  this case; not reproduced on `main`.

## Approach

1. Reproduce on Windows: `node_live`'s `ssh_to_a_node` in `relay-live.yml` on `windows-2025` too
   (a live test of the relay, which runs with its entry), with the node's lines and the client's
   `-vvv`. If it passes there, the tester's pairing is the variable: the node on a Linux runner and
   the client on a Windows one, meeting through the live relay, in one workflow.
2. Find where it stops, with the record of item 3, and repair it; the record names the place
   before the repair.
3. A record of the handshake: the bytes that came from the far end, whether they held a version
   line (its text, on one line), and the last message of the key exchange sent and received; and,
   on a node's road, the bytes through the layer and through the end-to-end channel each way. The
   line of a timeout says them: "node://NAME: the SSH handshake did not finish within 25 s: no byte
   came from the node's TARGET after the layer opened (0 bytes through the channel)", or "...:
   SSH-2.0-OpenSSH_10.0p2 came, then nothing after this side's KEXINIT", one form for each case.
4. A first word inside ConnectTimeout: when no byte came 10 s after the layer opened, one line says
   so at once, and the wait goes on to ConnectTimeout; so a long ConnectTimeout is not one silence.
5. The manual's note of ConnectTimeout, `docs/STATUS.md`.

## Decision

The 10 s of item 4 are the node's own bound on its TARGET's answer
(`crates/podssh-relay/src/session/far.rs:42`): a sshd that the node reached has answered by then.
Lost: a retry of the handshake (the issue's third ask), which sends a second login while the
first may be on its way; the line of item 4 is the shorter first bound that it asks for.

The calls of the draft (2026-11-03), after the cause that the Correction names:

- The question of a new host key runs inside the handshake (`crates/podssh-ssh/src/handler.rs:175`),
  and its time does not count against ConnectTimeout, as a prompt of the login, the agent's
  signing and a security key's touch do not (`docs/cli.md`, the note of `ConnectTimeout`). The
  question keeps its own bound: 60 s when none of stdin, stdout and stderr is a terminal
  (`crates/podssh-ssh/src/terminal/mod.rs:92`), now on Windows' console too. Lost: the question
  inside the limit, which cuts a person who reads a fingerprint, and on a console that nobody sees
  lets the limit decide with words of no question; a cap on the time left out, which a person at
  the terminal would meet as a cut while reading.
- The first word says each state at 10 s, not only that no byte came: a key exchange that stops
  after the version line is as silent until ConnectTimeout. While the question waits, it speaks
  only when nobody can see the question, as a line would write into a person's question on the
  same terminal. Lost: a line for no byte alone, item 4's words.
- The 10 s run from the layer's open on a node's road (its first read or write of the stream that
  it carries, after its own handshake), else from the handshake's start; a layer that has not
  opened 10 s after the start is said so. Lost: the handshake's start on each road, which on a
  node's road counts the layer's own handshake.
- On Windows a key on the console ends the question's wait for input, and each other event (a
  focus, a mouse, a size) is taken from the console's buffer: it is nobody's answer, and a read
  after it would wait with no bound. Lost: `WaitForSingleObject` on the console's handle, another
  feature of windows-sys, which wakes for those events too.
- The record reads each direction up to NEWKEYS, then counts alone, and stops at the handshake's
  end: each later read and write of the session costs one atomic load. Lost: a record of the whole
  session, which no line reads.
- On each other road the far end is "the server"; on a node's road "the node's TARGET after the
  layer opened", with what the layer and the channel carried.
- Item 1's second half (the node on a Linux runner and the client on a Windows one) waits for the
  run of its first: the cause read is the client's question, which a runner of Windows meets with
  the node on the same runner.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib run::
cargo test -p podssh-ssh --lib handshake
cargo test -p podssh-cli --test node_live -- --ignored ssh_to_a_node
```

New tests in `podssh-ssh`: `a_silent_far_end_s_timeout_says_no_byte_came`, and
`a_far_end_that_stops_after_its_version_line_is_named` (a stream that sends OpenSSH 10.0p2's
version line, captured, then nothing; ConnectTimeout 3: the line names the version line and the
step, within 5 s). In Actions, `relay-live.yml`'s `node_live` on `windows-2025`
(`test=node_live_windows`) passes after the repair, and the Done names the cause. Planted:
`t588-handshake-unrecorded` (the record not read, the line as before): both new tests fail.

## Correction

Read on 2026-11-03 by the drafting agent, at `e176606` (the tree of `3bb42ea` with the triage):

- The Premise's list of the client's differences misses the one that reading finds to be the
  cause. `podssh ssh` checks the node's host key against its own known_hosts under `node://NAME`,
  inside the handshake (`crates/podssh-ssh/src/handler.rs:175`, the check that russh awaits within
  `connect_stream`), so the question of a new key runs within ConnectTimeout. On Windows the
  question went to `CONOUT$`, not to stderr, and read `CONIN$` with no bound
  (`crates/podssh-ssh/src/terminal/windows.rs`, lines 158-199 at `3bb42ea`), where Unix bounds it to
  60 s when stdin, stdout and stderr are all redirected (`crates/podssh-ssh/src/terminal/unix.rs:188`),
  as `docs/cli.md` promised for each system. A console with no window, as an agent's process and a
  step of a runner have, opens: the question waited unseen for the whole ConnectTimeout, and the
  line said only that the handshake did not finish. That is the line of #114, and the same at
  120 s, as no bound of 60 s came first. The tester's command named no `StrictHostKeyChecking` and
  no `BatchMode`; OpenSSH through `operator` asks under its own known_hosts, which knew the node or
  was told not to ask (the issue does not say which). `node_live`'s `ssh_to_a_node` passes
  `StrictHostKeyChecking=accept-new` and `BatchMode=yes`
  (`crates/podssh-cli/tests/node_live.rs:188-192`), so no test met the question. Not reproduced
  here: the run of item 1 confirms it.
- On `main`, `ssh node://NAME` with a good pair goes through the race of the roads
  (`crates/podssh-cli/src/ssh/node_roads.rs:117-123`, moved from `ssh/mod.rs` by T-531 and to `node_roads.rs` by T-551), not through `node::connect`, as the transit road is
  on by default (`crates/podssh-relay/src/transit/mod.rs:59`) since T-436; at `35a0d19`, the
  tester's build, it went through `node::connect`. The record is in the login of `podssh-ssh`,
  which both roads share, and both count what their layer carries.

## Done

2026-11-03, drafted by an agent and merged here, after T-586.

- `crates/podssh-ssh/src/handshake.rs`, new, with `handshake_side.rs` (one direction read: the
  lines before the version line, the version line, each packet's header up to NEWKEYS) and
  `handshake_flow.rs` (what a layer carried, `Flow` and `Counted`, and the `Road`): the record of
  a handshake on the stream between russh and the road, the line of a timeout in one form for each
  case, the first word 10 s in, and the wait that leaves the question's time out.
  `crates/podssh-ssh/src/run.rs` waits with it; `handler.rs` and `hostkey.rs` mark the question;
  `options.rs` has the `road`. `cargo test -p podssh-ssh --lib -- run:: handshake`: 21 passed (the parse
  each way and byte by byte, another service's line, a length that is no packet, the words of each
  case, a node's layer and channel, the counted stream, the question's time left out on a paused
  clock, the mark of the question, the first word of a question, and the first word at 14 s after
  a layer that opened at 4 s).
- The two new tests in `run_tests.rs`, among those 21, against
  russh's client over a stream: a far end that sends nothing gives "dest.example: the SSH
  handshake did not finish within 3 s: no byte came from the server", and one that sends OpenSSH
  10.0p2's version line "...: SSH-2.0-OpenSSH_10.0p2 came, then nothing after this side's
  KEXINIT", each within 5 s on a paused clock. The version line is written as sshd forms it, not
  captured; a capture of OpenSSH 10.0p2's waits (Q88). `cargo test -p podssh-ssh`: 354 passed.
- `crates/podssh-ssh/src/terminal/windows.rs`: the question on the console has the bound of Unix
  when nobody watches, a key ends the wait, and each other event is taken. Built and tested on
  Windows: the gate's job `windows` at the push.
- The CLI: `crates/podssh-cli/src/layered.rs` counts the layer's stream into the `Flow` of
  `Shell`; `crates/podssh-cli/src/ssh/node.rs` and `roads.rs` name the node's road in the
  options, so the line of each road through a node names the layer and the channel. Built; the
  CLI's `node_plain`, `roost`, `operator`, `ssh_args`, `ssh_exit_status` and `node_routes`: 3, 9,
  7, 36, 9 and 2 passed.
- `crates/podssh-cli/tests/live_harness/question.rs`, new, run from `ssh_to_a_node`: the run of
  #114, with ConnectTimeout 25 and no answer to the question, gives 255 with the key's refusal and
  its remedy, never "did not finish within 25 s", and records no key. `cargo test -p podssh-cli
  --test node_live -- --ignored ssh_to_a_node` on Linux, through the live relay: passed, "255 after
  1 s; no terminal to ask on: refused at once". `relay-live.yml` with `test=node_live_windows`, the
  new job on `windows-2025`, waits (Q88: a live run of about 14 min), and with it the cause's proof (the
  question waits 60 s on a console with no window, says so 10 s in, then the refusal; before the
  repair, the line of #114). The pairing of a Linux node and a Windows client: not drafted, by the
  Decision.
- The manual (`crates/podssh-cli/src/man/notes_ssh_more.rs`, a note of `podssh ssh`; the
  keyword's line in `crates/podssh-cli/src/ssh/keywords.rs`), `docs/cli.md` and
  `docs/architecture.md`. `cargo test -p podssh-cli --lib`: 657 passed; `--test man_page`: 10
  passed. The manual's reader of variables took the names of the transport's messages for
  variables: they are one string now, and the reader skips files of tests, as it skips tests in a
  file.
- Planted: `scripts/plants/t588-handshake-unrecorded.plant` (group `resume`), the old line again:
  `sh scripts/plant-each.sh --here t588-handshake-unrecorded`: caught
  (`a_far_end_that_stops_after_its_version_line_is_named` failed).
- `cargo todo remap` of each changed file: run from the draft's tree with the binary of the main
  checkout; four citations moved by hand (`TODO/robustness.md`, `TODO/ssh.md`). rustfmt
  `--check`: clean; clippy of `podssh-ssh` and `podssh-cli`, all targets, `-D warnings`: clean;
  the merge joined T-586's signals and this entry's record in `ssh/node.rs`; `ssh/roads.rs` grew to 502
  lines with both, so its `Kind` went to `ssh/road_link.rs`.

# T-598: On a cloud container's host, a peer that stops reading below SSH with `--direct` ends the session after 240 s on the keepalives, not after 60 s on the stuck write

**Source:** the session of 2026-11-03: `scripts/interop-faults.sh`'s `faults.stuck_write` in the
build image on a Claude Code cloud container's host (Linux 6.18, a VM), twice, with the dry run's
static binary of `3bb42ea`, `INTEROP_ONLY=faults sh scripts/interop.sh BIN`: 255 after 240 s, "the
server stopped answering keepalives", where the gate's runners give 255 within 60 s and "no
progress" (the gate's step `release` at `3bb42ea`, run 41563940463).
**Category:** defect
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

On this host the write limit of T-227 never ends the session: the peer that reads nothing is
found by the keepalives after 240 s, four times the 60 s that the manual says for a stuck write.
The session still ends with 255 and a named cause, so the defect is the time and the words, on a
kind of host that podssh is for.

## Premise

- `crates/podssh-ws/src/write_limit.rs:37` arms the limit only when a write of the inner stream
  waits (`Poll::Pending`); a write that SSH never makes arms nothing.
- `scripts/stall-forward.py` stops reading from the client after 65536 bytes, with a small
  receive buffer, and passes the server's bytes back.
- A first guess, that this host's TCP buffers (to 32 MiB to read, 4 MiB to write) took all of the
  test's 20 MB, is wrong: a file of the two ceilings and 16 MiB more failed the same way, 240 s
  on the keepalives. So the writes most likely stop above the socket, at the SSH channel's
  window, which the far end never opens again, and no write of the socket waits.

## Approach

1. Measure where the writes stop on this host: the bytes that the socket took, the channel's
   window left, and whether a write of the socket waited, with `-v` and the forwarder's count.
2. If the window is where they stop: a stall of the channel's window with bytes waiting to go
   for the write limit's 60 s ends the session with the same words, on each road; else the
   socket's case, with what the measurement shows.
3. The test asserts the 60 s on such a host too.

## Prove

```sh
sh scripts/dev.sh run -- 'INTEROP_ONLY=faults sh /work/scripts/interop.sh BIN'
```

On this cloud container's host, `faults.stuck_write` ends with 255 within 90 s and "no
progress", as on the gate's runners. Planted: the new limit removed: it fails at 240 s again.

# T-609: An ECDSA key of P-256 whose scalar OpenSSH writes in 31 bytes is refused: "SshKey: length invalid"

**Source:** the gate at `b02d8c4` (run 41647533798, its job `gate (release)`, 2026-11-03):
`ssh.auth.key.ecdsa` and `ref.auth.key.ecdsa` failed, "podssh: could not use the key file
/tmp/podssh-interop/id_ecdsa: SshKey: length invalid", where OpenSSH's client logged in with the
same key; the interop test makes that key anew with `ssh-keygen -t ecdsa` each run, and passed at
the gates before.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

podssh cannot use some valid ECDSA keys of OpenSSH: about one P-256 key of 512 that
`ssh-keygen -t ecdsa` makes is refused at its reading, on each road and by each verb, and the
gate's interop test fails at random with it.

## Premise

- Read: ssh-key 0.7.0-rc.11, `src/private/ecdsa.rs`, `EcdsaPrivateKey::decode`, refuses a scalar
  under 32 bytes (`MIN_SIZE`); an `mpint` (RFC 4251, section 5) has no leading zero bytes, so
  OpenSSH writes a scalar whose first byte is zero, and whose second byte has no high bit, in 31
  bytes or fewer. russh's `decode_secret_key`, which `crates/podssh-ssh/src/key_file.rs:35` calls,
  reads every key through it.
- Read: crates.io's newest ssh-key is 0.7.0-rc.11 (2026-11-03): no release reads such a key.

## Approach

1. Carry ssh-key 0.7.0-rc.11 as T-460 carries russh: the published crate in `vendor/ssh-key`, one
   patch that takes a scalar of any length up to the field's, `[patch.crates-io]` in the root and
   in `fuzz/`, the section of `vendor/README.md` and the watch of `scripts/check-vendored.py`.
2. A test that builds a key as OpenSSH writes one, its scalar 31 bytes, and reads it.

## Decision

- A copy with a patch, not a repair inside podssh: russh reads OpenSSH's keys, encrypted ones and
  PuTTY's through this one decoder, and a repair of the key's bytes before it would reach the
  plain format alone. Lost: a pass over the plain format in `key_file.rs`, which leaves the
  encrypted keys refused.
- The patch takes any length from 1 to the field's size: each is a scalar that OpenSSH may write.
  Lost: 31 bytes and up, which leaves the keys of 30 bytes (one of 131,072).

## Prove

```sh
cargo test -p podssh-ssh --lib key_file
```

The key of 31 bytes is read and gives its own public key; planted, the release's decoder in the
copy: the test fails. A key of `ssh-keygen` with such a scalar is read by `podssh keygen -y`.

## Done

2026-11-03.

- `vendor/ssh-key`: ssh-key 0.7.0-rc.11, the published crate byte for byte but `.cargo-ok` and two
  test keys that GitHub's push protection refused (`tests/examples/id_ed25519` and its 64-column
  copy, read by the crate's own tests alone), and
  `vendor/patches/ssh-key/0001-ecdsa-short-scalar.patch`; the patch over cargo's copy of the
  release gives the shipped tree (`diff -r`: no other difference). In the place of the release by
  `[patch.crates-io]` in `Cargo.toml` and `fuzz/Cargo.toml`; both locks updated
  (`cargo update -p ssh-key --offline`). `scripts/check-vendored.py` watches it against crates.io's
  newest version, as a copy of a prerelease.
- `cargo test -p podssh-ssh --lib key_file`: 10 passed, one new
  (`an_ecdsa_key_whose_scalar_openssh_writes_short_is_read`, a key made until its scalar has a zero
  first byte and a second under 0x80, written as OpenSSH writes it: read, its public key and scalar
  the ones written). Planted, the release's `ecdsa.rs` in the copy: the test failed at the
  decode.
- Against OpenSSH 9.6p1's `ssh-keygen -t ecdsa -b 256`: the 243rd key had a scalar of 31 bytes;
  `podssh keygen -y -f` on it exited 0 and printed the public key of its `.pub`. The key was
  deleted after.

# T-661: Typing-aware flow control in podssh's SSH client: a bulk channel's window held to a round trip and 40 ms while a key waits

**Source:** the study of osewa, 2026-11-04 (Q99; `docs/research/osewa.md`, `docs/research/osewa-code.md`, `docs/research/osewa-paper.md`).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

osewa keeps a key's echo near the idle echo while a download runs, by holding bulk data to about
the path's rate times (its least round trip plus 40 ms) while the user types. podssh lets 512 KiB
of each channel sit in front of a key: 0.4 s at 10 Mbit/s, 4 s at 1 Mbit/s (inferred; the entry of
the measurement measures it). podssh can do better than osewa here: from the client's side of plain
SSH, so it works against any sshd and through any relay, with nothing installed at the far end.

## Premise

- `crates/podssh-ssh/src/run.rs:30` says "pub(crate) const WINDOW: u32 = 512 * 1024;": one window for
  each channel, on each road.
- russh's client asks its handler for each channel's next window target,
  `vendor/russh/src/client/mod.rs:3189` says "fn adjust_window(&mut self, channel: ChannelId, window: u32) -> u32 {",
  and podssh's handler does not take that hook (no `fn adjust_window` under `crates/`).
- osewa's own lab shows the gain is its flow control, not QUIC: over its TCP WebSocket the echo
  under load was lower than over QUIC (`docs/research/osewa-paper.md`, section 0, item 4).

## Approach

1. podssh's handler takes the hook that the patch of item 2 adds, `window_target` (Correction):
   while a key was typed in the last 2 s, a bulk channel (`direct-tcpip`, SFTP, exec with no pty,
   the agent's) gets rate times (least round trip plus 40 ms), at least 16 KiB and at most the road's
   cap; idle, plus 200 ms. The rate comes from the window's use, the round trip from the window's
   adjusts, end to end (through a proxy, `TCP_INFO` sees only the first leg; Decision 2).
2. A patch of the vendored russh asks the handler for each channel's target at each data message
   (`vendor/patches/russh/0002-window-target.patch`, as T-460's), as the hook of russh 0.65.0 sets
   no target (Correction).
3. podssh's own senders (`cp` and `sftp` uploads, `-L`, `-R`, `-D`, `pipe`) hold their writes while a
   key waits; keys and window adjusts go first. `TCP_NOTSENT_LOWAT` of 16 KiB on podssh's own TCP
   sockets where `setsockopt` takes it, a probe and not an assumption.

## Decision

1. **A patch of the vendored russh, not the hook alone.** The hook cannot do the work: russh keeps
   its answer in a field that nothing reads (Correction). The patch adds a method to russh's
   client `Handler`, `window_target(channel, window) -> u32`, asked at each data message of a
   channel before russh decides whether to adjust its window; its default, `window`, keeps russh's
   behaviour, so the patch changes nothing for a handler that gives no target, and is one for
   russh upstream too (the operator's to send). `adjust_window` still tells of each adjust that went
   out, which the round trip's timing needs. Lost: a patch that only reads `target_window_size`:
   one target for the whole session, and set once an adjust went out, a window late (4 s at
   1 Mbit/s and 512 KiB); a grant as podssh reads the data rather than as russh receives it (the
   paper's form): it touches russh's read halves and its queue of 100 messages, and podssh reads
   each channel at once anyway (`crates/podssh-ssh/src/handler.rs:234` says "Asked for: joined at
   once, as a channel kept unread stops the"); a lane of its own for the session's data in russh's
   writer: a deeper patch, where podssh's senders can hold instead (Approach item 3).
2. **The round trip from the window's adjusts, not from keepalives.** russh sends its
   `keepalive@openssh.com` only after a silence, so never while bulk flows, and gives its reply to
   no handler; a ping of T-332 would wait behind the queue that it should not count. A sample is the
   time from an adjust to the message that carries the first byte that only it allowed, less that
   message's time on the path at the measured rate: end to end, through any relay or proxy. Lost:
   `TCP_INFO` (the proxy's leg alone), and a key's echo (it holds the queue).
3. **The windows drain for a moment** (as BBR's probe of its least round trip): a queue that never
   empties is in each sample, and the least round trip would grow with the queue that the windows
   keep (a download starts with one: the first 512 KiB fill it). At the first key after a pause,
   while bulk presses on its windows, and each 10 s of bulk, each window is 16 KiB until what was
   in flight came at the path's rate and two round trips more, 1 s at most: a few per cent of a
   download. Lost: the least of 5 minutes, as Linux keeps it: a download that began with a full
   queue never sees the path; and a queue read from the arrivals: a bottleneck that never idles
   tells nothing of its delay.
4. **Twice the path's bytes of a round trip at least.** russh adjusts a window once less than half
   is left, so half a target must hold a round trip's bytes, or the path runs dry before each
   adjust arrives: at 1 Mbit/s and 100 ms the margin's target alone (23 KiB) leaves the path idle
   7 ms in each 94. On a path longer than about 80 ms this, not the 40 ms, bounds the queue: half a
   round trip on average, an echo of 1.5 round trips. Lost: a finer adjust in russh (at a quarter
   left): more adjusts, and russh's rule changed for each caller.
5. **Each channel of the destination is held while a key waits, the session's own too**: an echo
   needs far less than 16 KiB, and Ctrl-C shows sooner after `cat` of a large file (the paper's G2,
   item 1). Lost: a list of bulk channels by kind, which the handler cannot learn of the channels
   that podssh opens (russh tells it nothing of them). A channel of a `-J` hop, which carries the
   next connection, gets the road's cap whatever is typed: the connection inside paces its own
   channels, and a smaller window there would only queue at the hop.
6. **Typing is the process's**: a key in any session of this process holds each connection's
   windows (`podssh each --interactive` types to several hosts; one user waits). Lost: per
   connection, which needs the handler's state in the session's code, where only russh's handle is.
7. **podssh's senders hold until the echo, 1 s at most**, the echo being the session's next output.
   Lost: 2 s after each key, as the windows: an upload would stop while the user types; until the
   echo with no limit: a password's prompt echoes nothing. The local side of `-L`, `-R` and `-D` is
   held in `crates/podssh-ssh/src/tally.rs`, the one stream that each forward reads.
8. **Unmeasured, the window of before**: 512 KiB idle, and 16 KiB while a key waits. A channel that
   opens while a key waits still starts with the 512 KiB that russh advertises at its open. Lost: a
   smaller first window, which costs each channel its first round trip.
9. **No switch to turn it off.** Unmeasured, each window is today's; measured, the bound is the
   path's own. Lost: a variable of its own (`PODSSH_PACE=off`), more for the manual and its tests;
   T-660's measurement compares with today's by the plant of the patch.
10. **`TCP_NOTSENT_LOWAT` on the socket of the direct road**, which podssh-cli makes, before and
    after a relay (`crates/podssh-cli/src/ssh/transport/after.rs`). Linux and macOS have the option;
    Windows has none, and `-v` says so.

## Prove

```sh
cargo test -p podssh-ssh --lib
cargo test --manifest-path vendor/russh/Cargo.toml --target-dir .work/russh-target --lib client::window_target
```

With T-660's deep-buffer shape: the echo's p50 under load at most twice the idle echo,
the download within 10% of today's; the hook planted out fails it.

## Correction

Read at `856940b`, the tree of this entry: russh's client asks its handler for no target that it
uses. After an adjust it passes the handler's `adjust_window` the session's
`target_window_size` (`vendor/russh/src/client/mod.rs:100` says "target_window_size: u32,") and
keeps the answer there, but the target of each adjust of CHANNEL_DATA and CHANNEL_EXTENDED_DATA was
the configured window, `self.common.config.window_size`, and nothing read `target_window_size`
again. The hook alone holds no window. The patch of Decision 1 asks at each message:
`vendor/russh/src/client/encrypted.rs:614` says "let target = window_target(client, channel_num, self.common.config.window_size);".

At the merge (2026-11-04) the Prove's second bound did not hold on the slowest path: on the fake
path of 1 Mbit/s and 100 ms, with a key each 300 ms for the whole run, the paced download moved
3,595,483 bytes where today's window moved 4,980,736 (72%), while the key's echo fell from 3,009 ms
to 114 ms (the idle echo is 101 ms); at 10 Mbit/s and 60 ms it moved 93%, the echo 97 ms against
305 ms. Neither a window of three round trips' bytes (74%) nor no drain (72%) moved it: holding the
bulk to a round trip while a key waits costs the rate of a path that slow, as osewa's own bound does.
The test holds that path's download at 70% of today's, the bound that was measured, and T-670
wins the rest back.

## Done

2026-11-04, merged from its draft (`d51f254`).

- The patch `vendor/patches/russh/0002-window-target.patch` (`Handler::window_target`, asked at
  each data message); `crates/podssh-ssh/src/pace/` (the target, the measures of rate and round
  trip, the keys and the senders' turn, the drains); `TCP_NOTSENT_LOWAT` of 16 KiB on each TCP
  socket that podssh dials (`crates/podssh-ws/src/lowat.rs`, moved there at the merge from
  podssh-ssh, so the relay's and a proxy's sockets take it beside the direct road's); `podssh ping
  --under-load` marks its keys and their echoes (T-660's keys were not a user's to the pace).
- `cargo test -p podssh-ssh --lib`: 329 passed (the pace 36); `cargo test --manifest-path
  vendor/russh/Cargo.toml --target-dir .work/russh-target --lib client::window_target`: 5 passed;
  `cargo test -p podssh-ws --lib`: passed; `cargo test -p podssh-ssh -p podssh-cli
  --no-fail-fast`: 2,243 passed, 4 failed, each repaired at the merge and passed again: two of the
  manual's checks (a name in capitals read as a variable; `-W` in the sentence of `-R`), the copy
  test of `-R 64 -B 64K` (64 requests in flight now on the direct road, T-662), and
  `relay_code_role`, whose check read a word of the code's English list in podssh's own lines once
  (it now looks for the code and two of its words in a row; 10 runs passed). Plants:
  `t661-target-unasked` and `t661-no-drain` caught (the second by the slow path's test, its
  `EXPECT` moved at the merge). Clippy and rustfmt clean.
- T-660's matrix, `python3 scripts/feel-matrix.py target/x86_64-unknown-linux-musl/release/podssh
  --runs 3 --roads openssh,direct,role,node`, a key's echo (p50) beside a download, before and
  after: cellular 300 to 98 ms by `--direct`, 254 to 109 ms through the relay role, 255 to 127 ms
  through a node (idle 62 ms; OpenSSH 1,631 ms; osewa's lab 73 to 138 ms); wifi 148 to 69, 124 to
  73, 121 to 85 ms (OpenSSH 816); far 122 ms each, as before; slow 2,963 to 2,399 ms by `--direct`,
  2,779 to 2,680 ms through the role, 2,666 to 486 ms through a node (OpenSSH 16,214). The
  download while typing: cellular 1.1 MiB/s against 1.2, far 0.8 against 2.1. T-670 takes the slow
  link's echo by `--direct` and the role, and the rate while typing.

# T-662: SSH windows that grow to the path where nobody types, to a cap of each road

**Source:** the study of osewa, 2026-11-04 (Q99; `docs/research/osewa.md`, `docs/research/osewa-code.md`, `docs/research/osewa-paper.md`).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** partial

## Problem

One window of 512 KiB bounds a channel to about 5 MiB/s at 100 ms, on each road, also `--direct`
where nothing between asks for it; osewa starts its channels at 4 MiB and OpenSSH at 2 MiB, and
both moved more on a long path in osewa's runs.

## Premise

- `crates/podssh-ssh/src/run.rs:26-30` gives the reason of the 512 KiB: the default relay's bound
  of 2 MiB, which a direct road and podssh's own relay role do not have.
- `crates/podssh-ssh/src/sftp/pipeline.rs:37` holds SFTP's requests in flight.

## Approach

1. Where nobody types (T-661), a bulk channel's window grows to
   twice the measured rate times the round trip, to a cap of the road: 16 MiB on `--direct`, iroh's
   direct path and podssh's relay role; 2 MiB at most on the default relay (under its 1013, T-062);
   768 KiB on the pair road (T-443).
2. SFTP's requests in flight follow the window.

## Decision

1. **The caps** (`crates/podssh-ssh/src/pace/road.rs`): 16 MiB on `--direct` (also the direct road
   after the relay hosts), the iroh road and podssh's relay role; 1.5 MiB through the default relay, a
   quarter under the 2 MiB of its `1013` for the frames around SSH's bytes, and the room that `podssh
   cp` already shares among its tasks there (`RELAY_ROOM`); 768 KiB on the pair's road, the layer's
   window there (a test of podssh-cli holds it to `PAIR_WINDOW`); 512 KiB, the window of before, on each
   road whose hold for a slow reader podssh has not measured (DERP, `cf://`, a forwarder, Shadowsocks,
   VLESS, wstunnel, `--via`, a cloud's tunnel). Lost: 64 MiB on the direct road (the paper's "as memory
   allows"): 16 MiB fills about 1 Gbit/s at 100 ms with the idle margin, and is what each channel may
   hold in memory; 2 MiB on the relay: the very size at which its document closes the session.
2. **The growth is T-661's rule**: its target is twice the round trip's bytes at least, which russh's
   adjust at half the target needs on any long path, idle or not, so this entry adds the caps and their
   share, not a second rule. Idle, the rate times the round trip and 200 ms grows a window that limits
   the rate from round to round, as a start of TCP does.
3. **The channels that carry bulk share the cap**, each with 512 KiB at least, so no channel gets less
   than before and one channel alone gets it all. A `-J` hop's channel gets the whole cap, and each hop
   rides the destination's road (`hop_options`). Lost: the whole cap for each channel (memory of 16 MiB
   for each forward of `-L`); a strict share (four downloads through the relay would get less than
   before).
4. **podssh-cli names the road** (`crates/podssh-cli/src/ssh/window.rs`), from the resolved transport
   and what reached it: a relay host's session with no relay leg and the resumable layer is podssh's
   relay role's (T-173), with neither the direct road's after the relay hosts. A node races its roads;
   the pair's cap holds whichever won, as each node has that road. Lost: the winner's own cap, which
   needs the race's outcome in `Reached`, built in 24 places. The relay role and the iroh road carry
   the resumable layer, whose replay buffer (4 MiB by default, `PODSSH_REPLAY_BUFFER` up to 16 MiB)
   bounds what is unacknowledged: there a window past it waits at the far end, and costs nothing.
5. **SFTP's requests follow the room of their session**: `sftp::Limits::in_flight`, the road's cap,
   which `podssh cp` gives each session that it opens; a pipeline that asks nothing asks for as much as
   its session takes, and `--parallel`'s tasks share it, each with 512 KiB at least, as before through
   the relay. The requests stay at 64 at most (OpenSSH's `sftp -R`): of OpenSSH's blocks of 255 KiB
   they fill 16 MiB; of 32 KiB, 2 MiB. Lost: more requests, which changes what `-R` means and fills a
   server's queue of requests; the check of a relay session's budget counts the relay's room now.
6. **A channel still opens with 512 KiB**, russh's advertised window: it grows from the first measures.
   Lost: a larger first window on the direct road: a channel opened on a slow path would queue it all
   in front of the first key.

## Prove

```sh
cargo test -p podssh-ssh --lib
cargo test -p podssh-ssh --test sftp_pipeline --test sftp_client
cargo test -p podssh-cli --lib -- ssh::window cp::chunks
```

A copy through a shaped stand-in of 100 ms and 100 Mbit/s moves more than twice today's rate.

## Done

Partial, 2026-11-04, merged from its draft (`8d72e03`).

- The caps by road (`crates/podssh-ssh/src/pace/road.rs`): 16 MiB on `--direct`, the iroh road
  and podssh's relay role, 1.5 MiB through the default relay, 768 KiB on a node's pair road, 512
  KiB on each other; the channels that carry bulk share a cap, each with 512 KiB at least; SFTP's
  requests in flight follow the room of the road (`crates/podssh-ssh/src/sftp/pipeline.rs`), also
  `cp`'s chunks and lanes (`crates/podssh-cli/src/ssh/window.rs`, `cp/chunks.rs`, `cp/lanes.rs`,
  `cp/bysftp.rs`).
- `cargo test -p podssh-ssh --lib`: 329 passed, the fake path's test of 100 Mbit/s and 100 ms with
  nobody typing among them (the direct road moves more than twice today's window); `cargo test -p
  podssh-ssh --test sftp_pipeline --test sftp_client`: 8 and 7 passed; `cargo test -p podssh-cli
  --lib -- ssh::window cp::chunks`: 5 passed; `--test copy_pipeline`: 4 passed, its case of `-R 64
  -B 64K` now 64 requests in flight on the direct road. Plant `t662-one-cap`: caught.
- Waits, so the entry is partial: a copy through T-660's shaped stand-in of 100 ms and 100 Mbit/s
  against the window of before.

# T-664: A faster cold connect: TLS tickets kept across runs, a key's signature sent with no query first, and fewer waits before the first command

**Source:** the study of osewa, 2026-11-04 (Q99; `docs/research/osewa.md`, `docs/research/osewa-code.md`, `docs/research/osewa-paper.md`).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

osewa reaches a first command in about three round trips; podssh needs about eight to ten on the
relay road (inferred: the proxy's CONNECT, TLS, the upgrade, SSH's exchange of keys, the
authentication's query and signature, the channel and the command). The entry of the measurement
measures it.

## Premise

- T-444 resumes TLS within one process only.
- RFC 4252, section 7, lets a client send a signed publickey request with no query first.

## Approach

As the Correction moved it:

1. The key exchange group that each TLS server took, kept across runs in the private cache, mode
   0600, as the relay's addresses are (`tls-groups.txt`), so that a later run offers it first and
   meets no HelloRetryRequest; the tickets stay in memory (T-444), and T-672 keeps them across
   runs once a release of rustls lets a client write one; never 0-RTT.
2. The key that a host last took is remembered by its host key, and its signature goes at once, in
   the place of `none` and of the query (a patch of the vendored russh).
3. The session channel's `pty-req` and its `shell` or `exec` go with no wait between them; the
   open still waits for its confirmation.
4. Measure the mint's share of a first run.

## Decision

The draft's calls, 2026-11-04, each with what lost:

1. **TLS tickets across runs: not here (T-672).** rustls 0.23.46 gives a client no way to write a
   ticket or to make one again (Correction). Lost: a patch of rustls in `vendor/`, as russh's
   (T-460): rustls is the TLS of each road, of the relay role's server and of the crates that link
   it (tokio-rustls, quinn's iroh, h2's DNS over HTTPS), with a release about each month (0.23.42 of
   2026-07-13 to 0.23.46 of 2026-10-14), and a fork would hold podssh behind each security release
   of its TLS; and a ticket read out of rustls's `Debug`, which holds no secret by design.
2. **The group of the key exchange is kept instead.** rustls asks its store for it
   (`ClientSessionStore::kx_hint`, public in 0.23), and in TLS 1.3 it is what saves a round trip:
   a server that takes none of the first offer (podssh's is X25519) answers with a
   HelloRetryRequest. The store (`crates/podssh-ws/src/tls/store.rs`) keeps rustls's own cache in
   memory for the tickets, one for each configuration, so T-444's rule holds (a ticket resumed
   under the trust that verified it alone); the groups are the process's, shared by each trust, as
   a group is no secret and checks nothing. The file is text of three fields a line, read with no
   new crate (podssh-ws has no serde derive); 64 servers, 30 days, written again only for a new
   group or once a day. A file that does not read is set aside whole, said once at `-v` where the
   relay opened the session, and made again by the next group. Lost: JSON as
   `relay-addresses.json` (a derive for one file); the cache in podssh-ws, which would repeat
   podssh-relay's rules of a private file (owner, mode, links, Windows's access list): podssh-relay
   gives the file as a `GroupFile` once a run, with the addresses (`addresses::install`).
3. **The key at once, in the place of `none` too.** russh 0.65.0 queries each key first
   (`vendor/russh/src/client/encrypted.rs`: "This is a probe"), so a patch adds
   `Handle::authenticate_publickey_signed`
   (`vendor/patches/russh/0003-publickey-signed-at-once.patch`, numbered after T-661's `0002`);
   its request is built by the code that answers a `USERAUTH_PK_OK`, so its bytes are those of the
   second request of a query. RFC 4252, section 5.2, makes `none` optional, and the failure of the
   signed request lists the methods as `none`'s would: two round trips fewer, where the query alone
   is one. The service's request still waits for its accept, as russh writes the first request
   only then. Lost: `none` first and the signed key after it (one round trip); the query and the
   signature in one flight (a refused key costs the same, and nothing is gained over the request
   at once).
4. **Which keys go at once.** A key file that opens with no question (no passphrase, or one that a
   passphrase opened earlier in the run), not RSA, which signs through podssh's own signer (T-257),
   and not a security key's, whose touch waits for the server's yes; publickey must be the first
   method. An agent's key goes the usual way: russh signs with an agent after the `PK_OK`, and at
   once it needs a second hook in the patch; the record keeps an agent's key all the same, for that
   step. Lost: a passphrase asked before the first request, which a host that no longer takes the
   key would have the user type for nothing.
5. **The record of the keys.** A host is the SHA-256 of the user and of the host key's blob, so the
   file names no host and no user, as OpenSSH hashes `known_hosts`; a key is its fingerprint; 128
   hosts, 90 days, a write only for a new key or once a day. A refusal forgets the host's key, and
   the usual way does not offer that key again (a refusal counts against the server's
   `MaxAuthTries`). podssh-ssh holds the format (`crates/podssh-ssh/src/accepted.rs`); podssh-cli
   gives the cache's file where each command starts (`crates/podssh-cli/src/pins.rs`), as
   podssh-ssh has no cache. Lost: a field of `Options`, which each hop's options would carry for
   one record a run.
6. **The pty and the command together.** podssh waited for the pty's answer before the command's
   request; now the command's goes first, as OpenSSH's client sends its requests, and the answers
   are read in their order. Not with `--expect`, `--sudo` or `--su`, `-A`, `-X` or `--attach`: each
   reads the pty's answer, or waits for an answer of its own, between the two. The open still
   waits: a channel's request names the server's number of the channel, which its confirmation
   gives (RFC 4254, section 5.1). Lost: a control master's sessions
   (`crates/podssh-ssh/src/mux/msession.rs`), which skip both handshakes already.

## Prove

```sh
cargo test -p podssh-ws --lib -- tls::groups
cargo test -p podssh-ws --test tls_group
cargo test -p podssh-ws --test tls_resume
cargo test -p podssh-relay --lib -- tls_groups
cargo test -p podssh-ssh --lib
cargo test -p podssh-ssh --test cold_connect
cargo test --manifest-path vendor/russh/Cargo.toml --target-dir .work/russh-target --lib client::encrypted::tests::a_key_signed_at_once
```

Planted: the eight plants of T-664 in `scripts/plants/`, each of which must fail its test. T-660's
`--connect-runs` at 120 ms: two round trips fewer than before for a command, three for a shell.

## Correction

2026-11-04, the draft:

- Item 1 cannot be done with rustls 0.23.46: `Tls13ClientSessionValue::new` is `pub(crate)`, its
  fields are private and it has no encoding (read in cargo's copy of the crate, its module
  `msgs::persist`), so a store sees tickets that it can neither write nor make again.
  `rustls/rustls:rustls/src/msgs/persist.rs` changed on the line of 0.24 by rustls/rustls#2907
  ("client: make client cache values serializable", merged 2026-02-06), which no release carries:
  the newest is 0.23.46 of 2026-10-14 (read through <https://web.pkgforge.dev/llms.txt> on
  2026-11-04; rustls/rustls#3103, closed as not planned, points to it).
- Item 1's round trip: TLS 1.3 with no early data resumes in one round trip, as a full handshake
  takes (RFC 8446, section 2.2), so a ticket kept across runs saves the certificate's bytes and
  its check, and a round trip only with TLS 1.2 (a proxy that intercepts TLS); in TLS 1.3, the round
  trip that item 1 can save is a HelloRetryRequest's, which the kept group saves. The study's "That
  saves 1 RTT" (`docs/research/osewa-paper.md`, G4) holds for TLS 1.2 alone.
- Item 3: the session's open cannot go with its requests, which carry the channel number that the
  confirmation gives; the pty's request and the command's can, and go together.

## Done

2026-11-04, merged from its draft (`a467f09`; its patch of russh made again at the merge against
the tree with T-661's, `vendor/patches/russh/0003-publickey-signed-at-once.patch`, as the draft's
was cut before it; the draft's entry of TLS tickets is T-672).

- The key exchange's group that a relay host took is kept, mode 0600 (`tls-groups.txt`), so a later
  run meets no HelloRetryRequest (`crates/podssh-ws/src/tls/groups.rs`,
  `crates/podssh-relay/src/tls_groups.rs`); TLS tickets across runs wait for rustls (T-672). The key
  that a host took is kept by a hash of the user and the host's key (`accepted-keys.txt`), and its
  signature goes in the first request, with no `none` and no query (`crates/podssh-ssh/src/accepted.rs`,
  `keys_at_once.rs`, the patch of russh); a host that no longer takes it lets the usual way go on.
  The pty's request and the command's go together, but with `--expect`, `--sudo`, `--su`, `-A`,
  `-X` or `--attach`.
- `cargo test -p podssh-ws --lib -- tls::groups`: 8 passed; `--test tls_group --test tls_resume`: 3
  and 3; `cargo test -p podssh-relay --lib -- tls_groups`: 3; `cargo test -p podssh-ssh --lib`: 333;
  `--test cold_connect`: 3; the russh patch's tests (`--lib client::`, 35 passed with the patch's
  own). `cargo test -p podssh-ssh -p podssh-cli -p podssh-ws --no-fail-fast` on a clean build:
  2,753 passed, 0 failed. Plants: each of the eight `t664-*` caught.
- At the merge, the test of the pty and the command together could not pass against russh's
  server, which keeps one flag of a reply for each channel and drops a second answer that it holds
  (`vendor/russh/src/server/session.rs`, `channel_success`): the server now answers each request at
  once, its bytes reach the client 300 ms late, and it times the gap between the two requests (the
  plant of a client that waits for the pty's answer is caught).
- Measured, `python3 scripts/feel-matrix.py target/x86_64-unknown-linux-musl/release/podssh --runs 3
  --roads openssh,direct,role,node --shapes none,cellular,far`, a cold connect and `true` (p50),
  each login to OpenSSH 9.6p1's sshd, which takes the signed first request: cellular 517 to 391 ms
  by `--direct`, 772 to 645 ms through the relay role, 897 to 814 ms through a node (OpenSSH's own
  client 608 ms); far 993 to 747, 1,492 to 1,243 and 1,672 to 1,426 ms (OpenSSH 1,081 ms).

# T-669: Compression of a terminal's output on the relay roads, measured against the session's 64 MiB

**Source:** the study of osewa, 2026-11-04 (Q99; `docs/research/osewa.md`, `docs/research/osewa-code.md`, `docs/research/osewa-paper.md`).
**Category:** measurement
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The default relay ends a session at 64 MiB, and a terminal's output compresses well (osewa
measures 6 to 8 times); osewa compresses its server's output by default. SSH's compression is
opt-in in podssh.

## Premise

- `crates/podssh-ssh/src/run_config.rs` takes `-C` and `Compression`, off by default.

## Approach

1. Measure the bytes that a `top` session and a build's output send in an hour, with and without
   `-C`, on the relay road, and the CPU it costs.
2. Write the figures; a default stays off (the paper's study: compression with a context across
   messages is a side channel, and costs CPU on data that does not compress).

## Decision

- **No default of compression from this entry.** Lost: osewa's default, for the side channel and
  the CPU above; the figures go to the operator with the entry's Done.

## Prove

```sh
cargo test -p podssh-ssh --lib
```

The figures, with their commands, in `docs/STATUS.md`.

# T-670: The download's rate while a key waits on a slow path: win back what T-661 gives up

**Source:** the merge of T-661, 2026-11-04 (its Correction).
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** partial

## Problem

T-661 holds a bulk channel to about a round trip of the path while a key waits. On a path of 1
Mbit/s and 100 ms, with a key each 300 ms, the download moves 72% of what today's fixed window
moves, for an echo of 114 ms where today's is 3,009 ms. A user who types beside a long download on
a slow link pays that much of the download.

## Premise

- `crates/podssh-ssh/src/pace/sim_tests.rs`, the test `on_a_slow_long_path_too`, holds the paced
  download at 70% of today's at least; at 10 Mbit/s and 60 ms it moves 93%.
- Neither a target of three round trips' bytes nor a run with no drain moved the slow path's rate
  (T-661's Correction).
- T-660's matrix with T-661 (2026-11-04): on the slow link (1 Mbit/s, 100 ms, 1% loss) a key's
  echo beside a download is 2,399 ms by `--direct` and 2,680 ms through the relay role, where a
  node's road gives 486 ms (idle 103 ms); the download while typing on the far link (50 Mbit/s,
  120 ms) is 0.8 MiB/s where it was 2.1.

## Approach

1. Find where the rate goes on the fake path: the rate's samples while the window bounds the flow
   (a window that limits the rate measures that limit), russh's adjust at half the window, and the
   server's packets of 32 KiB against a window of a few of them.
2. A probe of the rate, as BBR's gain of 1.25 for one round trip in eight, so the measured rate can
   rise to the path's while the echo stays within twice the idle one.
3. The test's bound goes back to 90% of today's, and its echo's bound stays.

## Decision

1. **The cause on the fake path: one message a round trip; so a channel takes the server's messages
   of 8 KiB at most** (`PACKET`, `crates/podssh-ssh/src/pace/mod.rs`, asked at each channel's open
   in `crates/podssh-ssh/src/run_config.rs`). Read in a port of the fake path to Python, which gave
   T-661's merged figures to the byte (3,595,483 bytes, an echo of 114 ms): while a key waits, the
   window, 24,798 bytes, went as one message of 24,798 bytes each 298 ms, a round trip and its own
   198 ms on the path. A server sends a grant smaller than its largest message as one message;
   podssh counts a message once the whole of it came; and russh's adjust at half adds what a
   smaller message freed to the next grant. So a window of a message or two moves one message at a
   time, and a window of k round trips' bytes moves k/(k+1) of the path: twice, 67% (T-661's 72%);
   three times, 75% (its 74%). Only the size that a channel asks for splits a grant, so 23 KB is
   three messages of 8 KiB. Lost: 16 KiB (75%: a message and a half); 4 KiB (99.9% and an echo of
   156 ms, against 99.5% and 162 ms, for twice the messages of 8 KiB on a fast path); a window of
   more round trips (the echo); a size from the measured path (russh asks for it at each channel's
   open, and the session's channel opens before anything is measured).
2. **russh tops a window up once a quarter of it is used** (a patch,
   `vendor/patches/russh/0004-window-low.patch`: `Handler::window_low`, the room left under which
   russh adjusts, asked after `window_target`; its default is russh's half). Under the half, a
   window that bounds the flow lets about half of itself through each round trip (0.52 to 0.56 in
   the port), so the rate measured from it, times twice the round trip (T-661's floor, the larger
   term on a path of more than 80 ms), gives back the same window: on the far link it never grew
   while a key waited (inferred; the port, whose server overshoots each grant by a message, did not
   reproduce the 0.8 MiB/s). Measured, podssh gives three quarters of the target: three quarters
   come each round trip, T-661's four thirds hold, and a target of the rate times the round trip
   and the margin grows by the margin each round trip while it bounds the flow; the floor of twice
   the round trip's bytes goes. Lost: an adjust at each message (a message up for each message
   down); at an eighth used (a target of 8/7 gave 142,840 at 60 s in the least round trip's test,
   under its 150,000); Approach item 2's probe, BBR's 1.25 for one round trip in eight (25% each
   eight round trips: about 70 round trips from 0.8 to 6 MiB/s on the far link, against seven, and
   a quarter window of queue each eighth); russh's rule changed for each caller (its server, and a
   handler that gives no room, keep the half).
3. **Unmeasured, russh's half.** T-661's Decision 8 keeps the window of before while nothing is
   measured, and its adjust at half is part of it: with the quarter there, a channel opened while a
   key waits keeps all of its first 512 KiB in flight, and T-660's run under load waited 4.1 s at
   its first key, not 3.4 s (the port: a p50 of 1,288 ms, against 567).
4. **A drain ends at its first clean round trip, `DRAIN_MAX` at most, not at a guess.** The raw
   samples of T-661's matrix (its run's file direct.slow.json under .work/feel/, which git
   ignores): the echo falls from 3,561 ms at the first key to 102 ms at 6.75 s, then 4,195 ms at
   6.9 s, a grant of about 512 KB; the role's jumps each 2.5 s. The port with the bench's loss (a
   segment in a hundred, held a round trip, as `scripts/fake_shape.py` does) gives 2.5 to 3.7 s:
   the drain ended at T-661's guess, what was in flight at the best rate of the last seconds and
   twice a round trip, here 100 ms as none was timed; the best rate was a burst after a loss's
   stall, 1.7 times the path's, so the drain ended a second before its queue came, with no clean
   round trip, and the target came from the queue's round trip (1.8 s): 742 KB. Ended at its first
   clean round trip, the port's p50 of 40 keys is 567 to 666 ms, the first window's queue at the
   first key. Not the road: the node's queue at its first key was 1.2 s where `--direct`'s was
   3.6 s, and the port gives the same with a cap of 512 KiB, 768 KiB or 16 MiB. A round trip is
   clean once no other channel that carries bulk has more than a held window in flight; T-661 took
   any channel's first. Lost: a better guess (the rate's best reads a burst on a lossy link: T-673).
5. **The lossy link's test bounds what this entry repairs**: the p50 of its 40 keys at most eight
   idle echoes, of the last 20 at most four (the port: 567 and 325 ms; with T-661's guess 2,396 ms
   each). A key after the drain on that link still waits about three idle echoes, for the rate's
   burst: T-673.
6. **The patch is 0004**: a draft of T-664 has a 0003 of its own, and the names never meet.

## Prove

```sh
cargo test -p podssh-ssh --lib pace::sim_tests
cargo test -p podssh-ssh --lib pace
cargo test --manifest-path vendor/russh/Cargo.toml --target-dir .work/russh-target --lib client::window_target
```

On the slow path, the download at 90% of today's at least, the echo's p50 at most twice the idle
echo; T-660's matrix on the slow link, before and after.

## Correction

- The Premise's "neither a target of three round trips' bytes nor a run with no drain moved the
  slow path's rate" holds: it is Decision 1's one message a round trip, where k round trips' bytes
  move k/(k+1) of the path, whatever drains.
- The Premise's node road (486 ms) differs by its queue at the first key, not by its road (Decision
  4).
- Approach item 1's third candidate is the fake path's cause (Decision 1), its first two the far
  link's (Decision 2); the drains' cadence is sound, their end was not (Decision 4). Approach item
  2 is not done: Decision 2 grows a window that bounds the flow without a probe.

## Done

Partial, 2026-11-04, merged from its draft (`88c9a2d`; its patch of russh made again at the merge
against the tree with T-664's, `vendor/patches/russh/0004-window-low.patch`; its entry of the lossy
link's rate is T-673).

- The causes, found by a port of the pace and of the fake path that gave T-661's figures to the
  byte: a slow path's whole window went as one message each round trip (podssh now asks for
  messages of 8 KiB, `pace::PACKET`, and tops a window up once a quarter of it is used, by
  `Handler::window_low` of the patch); a drain ended on a guess where a loss's stall made a burst
  (it now ends at its first clean round trip, once no other bulk channel has bytes in flight).
- `cargo test -p podssh-ssh --lib pace`: 43 passed; the fake slow path moves 4,953,775 bytes of
  today's 4,980,736 (99%, the test's bound back at 90%) with an echo of 162 ms, where today's is
  3,009 ms; the cellular path 99% at 113 ms. The russh patch's tests (`--lib client::`): 39 passed.
  `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,289 passed, 0 failed. Plants:
  `t670-drain-guess`, `t670-half-room`, `t670-low-unasked`, `t670-others-ignored`,
  `t670-packet-unasked`, `t661-no-drain` and `t661-target-unasked` caught; at the merge
  `t670-packet-unasked` was missed by the wire's test (russh's server in this process sent small
  messages anyway), so a test of the client's configuration now holds the size asked for, and the
  plant aims at it. Clippy and rustfmt clean.
- T-660's matrix, `python3 scripts/feel-matrix.py target/x86_64-unknown-linux-musl/release/podssh
  --runs 3 --roads openssh,direct,role,node --shapes cellular,slow,far`, a key's echo (p50) beside a
  download, before and after: slow 2,399 to 390 ms by `--direct` and 2,680 to 547 ms through the
  relay role (OpenSSH 16,265 ms), but 486 to 761 ms through a node; cellular 98 to 120 ms by
  `--direct` and 109 to 139 ms through the role, its download while typing 1.2 MiB/s again; far
  122 ms as before, its download while typing 1.1 MiB/s (0.8 after T-661, 2.1 before it).
- Waits, so the entry is partial: the download while typing on the far link, and the node's road on
  the slow link.

# T-672: TLS tickets kept across runs, once a release of rustls lets a client write one

**Source:** T-664's draft, 2026-11-04 (the study of osewa, Q99; `docs/research/osewa-paper.md`, G4).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** blocked

## Problem

A run's first TLS handshake with each relay host is a whole one: rustls keeps its tickets in the
process's memory alone (T-444), so each run receives the certificate's chain again and checks it,
and through a proxy that intercepts TLS with TLS 1.2 it pays the round trip that a resumption
saves there. In TLS 1.3 with no early data, a resumption takes one round trip, as a whole
handshake does (T-664's Correction), so the gain there is bytes and a check, not time on the path.

## Premise

- rustls 0.23.46 gives a client no way to write a ticket or to make one again:
  `Tls13ClientSessionValue::new` is `pub(crate)`, and the type has no encoding (T-664's Correction).
- rustls/rustls#2907 ("client: make client cache values serializable") was merged on 2026-02-06 on
  the line of 0.24, and no release carries it (the newest, 0.23.46 of 2026-10-14, read on
  2026-11-04).

## Approach

1. Once a release of rustls encodes a client's session value: rustls, tokio-rustls and the crates
   that link them moved to it, as Dependabot moves a dependency.
2. The store of sessions of T-664 (`crates/podssh-ws/src/tls/store.rs`) writes each TLS 1.3 ticket
   to a private file of the cache, mode 0600, beside the groups: by the server's name and by the
   trust that verified the session (T-444's rule: a resumed handshake checks no certificate), at
   most a few tickets a server, each used once and removed when it is taken, none past its
   lifetime; never early data. A ticket is a secret: never in a log, never in a `Debug`.
3. A file that does not read is set aside, as the groups' is.

## Prove

```sh
cargo test -p podssh-ws --test tls_resume
```

Two processes against rustls's server: the second's first handshake is `Resumed`; under another
trust, `Full`. Planted: a ticket written and not read, and the test fails.

## Blocker

rustls's maintainers: a release of rustls that carries rustls/rustls#2907, which podssh's
dependencies then take. Nothing in podssh waits for it but this entry; T-664 keeps the group of
the key exchange, which the release of 0.23 lets a store keep.

# T-673: The rate's best on a lossy link: a burst after a loss's stall read as the path's rate

**Source:** the draft of T-670, 2026-11-04 (its Decision 5).
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The pace's rate is the best of its samples of the last 5 to 10 s, each the bytes of an interval of a
round trip at least over its length. On a link that loses packets, a lost one holds each byte
behind it a round trip, and they then come at once. In the port of T-661's fake path with the loss
of `scripts/fake_shape.py` (a segment in a hundred, 1 Mbit/s, 100 ms), one sample read 213,269 B/s
on a path of 125,000, and the first sample of a download 202,271; the best kept each for 5 to 10 s,
the target was twice the path's, and a key after T-670's drain waited three idle echoes (296 to
325 ms, idle 101) where the same path with no loss gives 162 ms.

## Premise

- `crates/podssh-ssh/src/pace/path.rs:125` says "pub(super) fn count(&mut self, now: Instant, n: u64) -> bool {":
  an interval ends at the first message past its length, which after a stall is the stall's first,
  so the next interval opens with the rest of the burst.
- `crates/podssh-ssh/src/pace/path.rs:10` says "/// A rate is the best of the samples of the last 5 to 10 s; older, none:".

## Approach

1. An interval ends at the end of a burst: a message that came within a quarter of a message's time
   at the best rate after the one before it belongs to the interval before; a burst longer than an
   interval ends it anyway. In the port this read the sample after a stall as 124,302 B/s.
2. Find why the first sample of a download still read 202,271 with that rule and a gap of 1 ms, in
   the port, before any rate.
3. A drain's clean round trip that a loss held reads long (124.5 ms on a path of 100 in the port):
   the least of a drain's round trips, not its first.

## Prove

```sh
cargo test -p podssh-ssh --lib pace
```

On the fake path's slow lossy link (`on_a_slow_lossy_link_the_drain_waits_for_its_queue`), the last
20 keys' p50 at most twice the idle echo.
