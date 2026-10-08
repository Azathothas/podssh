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
  is `no` (`crates/podssh-cli/src/ssh/resolve.rs:174-179`). The chain then
  never offers a key (`crates/podssh-ssh/src/auth.rs:83-89`).
- The denial adds the notes of the keys with no condition
  (`crates/podssh-ssh/src/auth.rs` line 115 at `475aea9`). `PublicKeys::notes` writes "no key
  was offered" when nothing was offered (`crates/podssh-ssh/src/keys.rs:91-104`).
- The reporter's output (GitHub #7): the line
  `Permission denied (publickey,keyboard-interactive).`, the note about
  keyboard-interactive, then the wrong note.
- The gate's check "password with BatchMode" runs this case against OpenSSH
  (`scripts/interop.sh:166-168`). It only looks for the password note, so its
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
   (`crates/podssh-ssh/src/keys.rs:105-111`) the same condition as step 1.
5. Keep `PublicKeys::new` for each login (`crates/podssh-ssh/src/auth.rs:78`),
   so that only the notes change. No document changes: `docs/cli.md:213-235`
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
runs the gate, where `scripts/interop.sh:166-168` also asserts that the
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
  unexpected EOF to one sentence (`crates/podssh-ssh/src/run.rs:224-230`).
  `run` prints it first, and the relay's reason second
  (`crates/podssh-ssh/src/run.rs` lines 38-46 at `80f20bf`,
  `crates/podssh-ssh/src/relay_stream.rs:37-53`).
- The form `HOST: the connection closed unexpectedly` comes only from the
  handshake (`crates/podssh-ssh/src/run.rs` lines 108-122 at `80f20bf`).
  Thus both reported drops happened before the first key exchange ended.
- The handler keeps no SSH_MSG_DISCONNECT: it has no `disconnected` callback
  (`crates/podssh-ssh/src/handler.rs` lines 31-59 at `80f20bf`), and the
  default of russh 0.64.1 drops the reason.
- The relay's contract gives no close codes for the forward path;
  `docs/relay.md:142-154` lists them, read from the relay's source.
  `1011 write failed: ...` means that the relay could not write to the
  target. The KTM report saw it with 0 bytes, on a target that the relay
  could dial but not use (read in the report, not verified here).
- The reporter's second comment reads `1011` as "relay backpressure, over 1
  MiB queued". That row is in the contract's table of reverse close codes
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:160-166`, row
  `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`). On the
  forward path, backpressure closes with `1013` at 2 MiB (`docs/relay.md:153`,
  `docs/relay.md:164-168`). The comment on the SSH window
  (`crates/podssh-ssh/src/run.rs` lines 25-29 at `80f20bf`) also cites the
  reverse row.

## Approach

1. Classify a forward-path close in one place, next to
   `close_code_and_reason` (`crates/podssh-ws/src/session.rs:298-306`), which
   `podssh ssh` and `podssh proxy` both use. Map the code and the reason of
   `docs/relay.md:147-154` to a hop. Relay to target: `1011` with
   `connect failed`, `write failed`, `target closed before sending anything`
   or `wrong target banner`, and `1013 target write backlog`. Client to
   relay: `1011` with `client send failed` or `client error`,
   `1013 client receive backlog`, and no Close. A relay limit: `1001`,
   `1009`. A normal end: `1000`. Give an unknown code as it is.
2. Keep the server's SSH_MSG_DISCONNECT: implement `Handler::disconnected` in
   `crates/podssh-ssh/src/handler.rs`. Store the reason code and the text,
   made safe with `podssh_ws::text::one_line`, as the handler stores
   `refusal` (`crates/podssh-ssh/src/handler.rs:17-19`).
3. In `run` (`crates/podssh-ssh/src/run.rs` lines 34-48 at `80f20bf`), write one first line from
   three sources, in this order: a relay close other than 1000, the server's
   disconnect, then `describe`. Example: "railway.new: the relay lost its
   connection to railway.new:22 (relay close 1011: write failed: Network
   connection lost.)". Keep the code and the reason verbatim:
   `scripts/interop-faults.sh:121` looks for them.
4. Write a second line that says what to do. For the hop from the relay to
   the target: another relay host (`--relay-host`), and
   `podssh relay trace HOST:PORT` when T-058 exists.
5. Use the same classification in `podssh proxy`
   (`crates/podssh-cli/src/proxy.rs` lines 252-280 at `80f20bf`). Keep `CODE REASON` in its line:
   `scripts/interop-faults.sh:140` looks for `1009 session byte cap`.
6. Correct the comment on the window (`crates/podssh-ssh/src/run.rs` lines
   25-29 at `80f20bf`). The window of 512 KiB stays: it is below both limits.
7. Update `docs/relay.md` (lines 155-158 at `80f20bf`) and `docs/STATUS.md:197`. T-025 uses the
   classification for its retry rule. T-227 is a different path
   (`--direct`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws -- forward_close
cargo test -p podssh-ssh -- first_line
sh scripts/dev.sh check
```

The first test has one case for each row of `docs/relay.md:147-154`, and one
for an unknown code. The second builds the first line from each kind of
`RelayEnd`, from a server disconnect, and from a bare russh error. In the
gate, a new stand-in relay in `scripts/interop-faults.sh` (mode
`close:1:1011`, with its name added at `scripts/interop-faults.sh:11`) drops
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
**Status:** open

## Problem

A relay drop ends `podssh ssh` with 255, also when nothing has run on the
server yet. One reporter saw 1 drop in 180 short sessions from one edge
(KTM), and one more in a run of `scripts/sandbox-check.sh`. A script cannot
retry safely: it cannot tell a drop before the command started from a drop
after it.

## Premise

Read:

- `podssh_relay::open` fails over and repeats rounds only until the
  WebSocket upgrade succeeds (`crates/podssh-relay/src/open.rs:172-211`).
  After the upgrade, a relay close ends the run
  (`crates/podssh-ssh/src/run.rs:38-47`).
- Both reported drops printed `HOST: the connection closed unexpectedly`,
  which only the SSH handshake prints (`crates/podssh-ssh/src/run.rs:137-159`).
  At that point no request has reached the server.
- The command starts with the exec, shell or subsystem request
  (`crates/podssh-ssh/src/session.rs:61-78`). `-W` reads stdin only after its
  channel opens (`crates/podssh-ssh/src/forward.rs:22-46`). `-N` never reads
  stdin (`crates/podssh-ssh/src/run.rs:97-105`).
- Measured by the reporter (read in the reports, not verified here): on one
  target the drop came back 3 times in 3, while other targets worked in the
  same minute, also with a client that shares no code with podssh. A blind
  retry can fail again.
- `podssh proxy` is a byte pipe and cannot know when a replay is safe. This
  entry is for `podssh ssh` only.

## Approach

1. Make `run_inner` (`crates/podssh-ssh/src/run.rs:78-112`) report the phase
   that a failure reached: the handshake, the authentication, the session
   request sent, or data moved. Keep the exit codes of OpenSSH.
2. In `connect_and_run` (`crates/podssh-cli/src/ssh/mod.rs:72-119`), open a
   new relay session and run again only when the failure came before the
   session request, and before `-W` read a byte of stdin.
3. Decide by the close, with the classification of T-024. The link from the
   client to the relay, or no Close: go to the next relay host, as `open`
   does for a failed upgrade (`crates/podssh-relay/src/open.rs:52-76`). The
   link from the relay to the target: try once more, then stop. Never retry
   `1001`, `1009` or `1013`.
4. Wait with the jittered backoff that exists
   (`crates/podssh-relay/src/open.rs:261-275`). Bound the whole by the rounds
   of `ConnectionAttempts` (`crates/podssh-cli/src/ssh/resolve.rs:291`) and
   the deadline of each host.
5. Never prompt again without a person: under `BatchMode`, or with no
   terminal and no `SSH_ASKPASS`, a retry that needs a prompt stops. Keep a
   typed password in memory (zeroized) for the retry; do not ask twice.
6. Say each retry on stderr, with the hop and the reason. Document the rule
   in `docs/cli.md:195-211`, and add a row to `docs/STATUS.md`.

## Decision

Recommendation: retry inside podssh, and only before the session request.
Only podssh knows whether the request was sent, and `podssh ssh` keeps the
exit code 255 of OpenSSH (`docs/cli.md:205-208`). The alternative, a distinct
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
`scripts/fake-relay.py:14-21`. Through it, `exit 5` still gives 5, with one
retry note. A second case drops after the exec request: exit 255, and a file
that the command appends to has one line. Planted defect: retry in each
phase, and that file has two lines.

# T-026: A session that ends with no exit status never reads as a success

**Source:** GitHub #23 (the ask "Never report success when the session died
without an exit status"), and the sleepinginsummer/agent-ssh-cli report in
GitHub #21 (item 10). Read here on `3ee70dc`.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

A script must not read exit 0 when the server gave no exit status. podssh
follows OpenSSH on its main path, but two paths still give 0 with no status:
`-N` ended by the server, and a closed stdout before the status came. The
exit codes of OpenSSH for these paths are not measured.

## Premise

Read:

- A channel that closes with no `exit-status` and no `exit-signal` gives 255
  (`crates/podssh-ssh/src/io.rs:132`, `crates/podssh-ssh/src/session.rs:18-19`,
  `crates/podssh-ssh/src/session.rs:104`). A channel that ends with no Close
  is `Lost`: an error, and 255 (`crates/podssh-ssh/src/io.rs:94`,
  `crates/podssh-ssh/src/session.rs:105`).
- A closed stdout (EPIPE) gives the status so far, or 0 when none came
  (`crates/podssh-ssh/src/io.rs:106-110`).
- `-N` gives 0 when the connection ends with no error
  (`crates/podssh-ssh/src/run.rs:97-105`). russh 0.64.1 ends the session with
  no error when the server sends SSH_MSG_DISCONNECT.
- `-W` gives 0 when the far end closes and when stdout closes
  (`crates/podssh-ssh/src/forward.rs:52-56`), and 255 when the connection
  died (`crates/podssh-ssh/src/forward.rs:74-80`).
- An exit status above 255 gives 255 (`crates/podssh-ssh/src/io.rs:115-117`).
  OpenSSH passes the value to `exit()`, so 256 reads as 0 there. podssh's
  rule is safer, and stays.
- `docs/cli.md:211` says only that a closed stdout ends the session cleanly.

## Approach

1. Measure first, in `scripts/interop.sh`, with the `ssh` of OpenSSH as the
   control: the client is in the image since T-238 (`openssh-client-default`,
   `scripts/interop.sh:32-33`). Compare the exit codes of both clients for:
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
5. Write the measured rule in `docs/cli.md:195-211`, and the measurement in
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
stdout, and `-W`. Also, `docs/STATUS.md:68` says that Tailscale SSH sends no
status for a login shell, and that both clients exit 0. With no status,
podssh gives 255 (`crates/podssh-ssh/src/session.rs:104`), so that server
probably sends an exit status of 0. Check it with `ssh -v` of OpenSSH, which
logs each `exit-status` request, and correct the row.

# T-027: Host certificates and `@cert-authority` in `known_hosts` (GitHub #29)

**Source:** GitHub #29 (2026-10-08; read by the reporter, not measured); the
lablup/bssh report in GitHub #18, #20 and #22 (item 8, "`@cert-authority`
rejection"); the known gap in `docs/STATUS.md:211` and `SECURITY.md:77-79`.
Each claim read again here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A host that the user trusts through a `@cert-authority` line, and through no
plain key line, cannot be reached. Under strict checking, or with no
terminal, podssh refuses it as unknown. With `accept-new`, podssh records the
host's plain key, and the trust in the CA is lost for that host: the user
ends up with pinned keys where the CA was the intent.

## Premise

Read:

- `known_hosts` parses the marker (`crates/podssh-ssh/src/known_hosts.rs:21-27`,
  `crates/podssh-ssh/src/known_hosts.rs:131`), and the lookup uses only lines
  with no marker, besides `@revoked`
  (`crates/podssh-ssh/src/known_hosts.rs:62-85`). `CertAuthority` has two
  hits in `crates/` and `docs/`: the definition and the parse.
- The check takes the plain key of what russh gives
  (`crates/podssh-ssh/src/handler.rs:71`). The comment at
  `crates/podssh-ssh/src/handler.rs:68-70` says that OpenSSH falls back the
  same way when no CA line matches; podssh never looks for a CA line.
- The refusal comes from the policy: `crates/podssh-ssh/src/hostkey.rs:66-70`
  (`yes`), `crates/podssh-ssh/src/hostkey.rs:75-79` (BatchMode),
  `crates/podssh-ssh/src/hostkey.rs:99-106` (no terminal). `accept-new`
  records the plain key (`crates/podssh-ssh/src/hostkey.rs:71-73`). GitHub #29
  cites line 91, which builds the question about other key types.
- `ssh-key` 0.7.0-rc.11 is in the tree (`Cargo.lock:3621`).
  `Certificate::validate_at` checks the signature, the SHA-256 fingerprint of
  the CA and the validity window. The caller must check the certificate type,
  the principals and the critical options (the crate's documentation).

## Approach

The order of GitHub #29: parse the certificate, look up a CA line, and fall
back to the plain key only when no CA line matches.

1. Ask for certificates: when a `@cert-authority` line matches the name of a
   hop, set `host_key_certificates` in `client_config`
   (`crates/podssh-ssh/src/run.rs:165-211`) to the algorithms of
   `preferred.key`. A host with no CA line keeps today's negotiation.
2. Add a lookup of CA keys in `crates/podssh-ssh/src/known_hosts.rs`, beside
   the `@revoked` arm (`crates/podssh-ssh/src/known_hosts.rs:66-71`). Match CA
   lines with the name `host` or `[host]:port`
   (`crates/podssh-ssh/src/known_hosts.rs:53-60`).
3. In `check_server_key` (`crates/podssh-ssh/src/handler.rs:67-86`), branch on
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
   never makes a plain key known. Correct `crates/podssh-ssh/src/handler.rs:68-70`.
   When certificates work, change `docs/STATUS.md:211` and `SECURITY.md:77-79`.

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
`client_config` does not set it (`crates/podssh-ssh/src/run.rs:165-211`). So
a server always presents its plain key. The words "checked as plain keys"
in `docs/STATUS.md` and `SECURITY.md` were not exact either: podssh never
asks for a certificate. They were corrected in the change that wrote this
entry. The effect that GitHub #29 gives is correct.

# T-028: `accept-new` when `known_hosts` cannot be written: verify, and say that the key was not recorded

**Source:** the lablup/bssh report in GitHub #18, #20 and #22 (item 8:
"`accept-new` must still verify when there is no home directory/unusable
file"; read in the report). Read here on `3ee70dc`.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** open

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
  (`crates/podssh-cli/src/ssh/resolve.rs:167-171`). `record` then says "no
  known_hosts file is configured" (`crates/podssh-ssh/src/hostkey.rs:122-128`).
- A failed write logs "it will be checked again next time", and the key is
  accepted (`crates/podssh-ssh/src/hostkey.rs:129-139`).
- The lookup skips a file that it cannot open or read, as if it were missing
  (`crates/podssh-ssh/src/known_hosts.rs:103-108`). A key recorded in an
  unreadable file never makes a key "changed".
- The lookup runs before `record`, so a changed or revoked key in a readable
  file is still refused (`crates/podssh-ssh/src/hostkey.rs:42-61`).
- `podssh doctor` fails when the default file cannot be written
  (`crates/podssh-cli/src/doctor/host.rs:27-54`).

Not measured here: each case needs a server.

## Approach

1. In `entries_for` (`crates/podssh-ssh/src/known_hosts.rs:100-119`), tell a
   missing file (NotFound) from a file that cannot be read (another error,
   or not a regular file). Give the unreadable files to the policy.
2. In `Policy::check` (`crates/podssh-ssh/src/hostkey.rs:42-61`), refuse an
   unknown key under `accept-new` and `no` when a user file exists and cannot
   be read: podssh cannot verify. Name the file, the error, and the remedy
   (`-o UserKnownHostsFile=FILE`, or the fingerprint of T-031).
3. Reword `record` (`crates/podssh-ssh/src/hostkey.rs:121-140`), at INFO: the
   key is accepted for this connection only; it was not recorded, and why
   (`HOME` is not set, `UserKnownHostsFile none`, or the write error); the
   next run cannot detect a changed key.
4. Check the file type before the open: a FIFO blocks an open for reading.
5. Update `docs/cli.md:213-235` (one line) and the manual's note on host keys
   (`crates/podssh-cli/src/man/notes.rs:23-26`).

## Decision

Recommendation: no other place for host keys; say clearly that the key was
not recorded. A fallback directory moves the trust without the user's
choice, and `docs/target-environment.md:90-92` forbids a silent fallback
that changes the behaviour. The alternative, the token cache's chain of
directories (`docs/target-environment.md:85-89`), lost: a key recorded in
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

# T-029: Two processes that record the same new host key at the same time

**Source:** the lablup/bssh report in GitHub #18, #20 and #22 (item 8:
"first-use recording serialized across processes"; read in the report).
Read here on `3ee70dc`.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

Two runs of podssh that meet the same new host at the same moment both
record it. With the same key, the file gets a second line. With two
different keys (one from a man in the middle, on one of the paths), both are
recorded, and later each is accepted as known.

## Premise

Read: the check reads the files, then `record` appends; nothing between them
sees another process (`crates/podssh-ssh/src/hostkey.rs:42-61`,
`crates/podssh-ssh/src/hostkey.rs:121-140`). `append` opens the file for
appending and writes one line (`crates/podssh-ssh/src/known_hosts.rs:206-241`),
so two lines do not mix, but nothing stops the second record. A lookup
accepts a key that any plain line of the host holds
(`crates/podssh-ssh/src/known_hosts.rs:72-75`), so two recorded keys of one
type are both "known". OpenSSH appends the same way (not measured here). Not
measured: a race needs two processes; the test below makes it certain.

## Approach

1. In `append` (`crates/podssh-ssh/src/known_hosts.rs:206-241`), lock the open
   file with `std::fs::File::try_lock`. It is stable since Rust 1.89, the
   minimum that `crates/podssh-ssh/Cargo.toml:8` declares, and it needs no new
   dependency (`flock` on Unix, `LockFileEx` on Windows). Try again for 5 s at
   most; never wait without a limit.
2. Under the lock, read the file again and look the name up. The same key:
   write nothing. Another key of the same type: return a new result, and let
   `record` refuse with the changed-key message
   (`crates/podssh-ssh/src/hostkey.rs:143-160`). Else append.
3. Hold the lock only for the read and the write, never across a prompt.
4. When the file system refuses locks, append as today, with a verbose note
   (a fallback that says so, `AGENTS.md:195`).

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

# T-030: Each hop of a `-J` chain checks its own host key

**Source:** the l0ng-ai/tty7 report in GitHub #20 ("Per-hop `known_hosts`",
`l0ng-ai/tty7:crates/tty7-core/src/daemon/ssh/connect.rs`, lines 396-398,
487 and 556; read in the report, not verified here). Read here on `3ee70dc`.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

In a chain `-J a,b c`, each hop is a different server. The key of one hop
must never be checked under the name of another hop, or a key can be
accepted for the wrong host.

## Premise

Read: each hop gets its own name for the check, its host and its port, as
`host` or `[host]:port` (`crates/podssh-ssh/src/run.rs:119-130`,
`crates/podssh-ssh/src/known_hosts.rs:53-60`). `HostKeyAlias` applies to the
destination only (`crates/podssh-ssh/src/run.rs:120-123`). The order of
host-key algorithms comes from the keys recorded for that hop
(`crates/podssh-ssh/src/run.rs:170-193`). The gate's check "-J through
OpenSSH to Dropbear" (`scripts/interop.sh:218-219`) passes only when this
holds: both hops are 127.0.0.1, both keys are Ed25519 and differ, and each
is recorded under its own port.

## Approach

The code is correct (see the Correction). The work is a direct regression
test, and a documented difference from OpenSSH.

1. Move the name of a hop (`crates/podssh-ssh/src/run.rs:119-125`) into a
   function. Test it: a jump hop on port 22, a jump hop on port 2222, and the
   destination with and without `HostKeyAlias`.
2. In `scripts/interop.sh`, after the `-J` check, start from an empty file
   under `accept-new`. The file must then hold exactly `[127.0.0.1]:2201` and
   `[127.0.0.1]:2203`. Then change only the jump's line: the run must exit
   255, and the message must name `[127.0.0.1]:2201`.
3. Write in `docs/cli.md:62-75` that podssh applies the `-o` options to each
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

# T-031: Accept only the host key that a fingerprint names, for scripts with no `known_hosts`

**Source:** the sleepinginsummer/agent-ssh-cli report in GitHub #21 (item 6,
`trust-host --fingerprint`); the willykeenan/warren report in GitHub #18
(item 4, `trust NAME --expect FINGERPRINT`). Read in the reports. Read and
measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

An agent in a new sandbox has no `known_hosts`, but often gets the
fingerprint of the server from its operator. Today it must choose between
`accept-new` (trust on first use, with the relay in the middle) and the
refusal of an unknown host. podssh has no flag that says: accept this key,
and no other.

## Premise

- Read: the host-key question accepts a typed fingerprint
  (`crates/podssh-ssh/src/hostkey.rs:95-112`), and an `SSH_ASKPASS` program
  can answer it (`crates/podssh-ssh/src/prompt.rs:49-74`). A script then
  needs an askpass program that it can run, which a noexec sandbox can
  refuse.
- Read: OpenSSH has no keyword for this. podssh refuses
  `KnownHostsCommand` (`crates/podssh-cli/src/ssh/options.rs:153-157`,
  `crates/podssh-cli/src/ssh/keywords.rs:84`).
- Measured, offline (`PODSSH_OFFLINE=1`):
  `podssh ssh --host-key-fingerprint SHA256:abc example.invalid true` gives
  `unknown flag '--host-key-fingerprint'`, exit 64.

## Approach

1. Add the long flag `--host-key-fingerprint SHA256:B64[,SHA256:B64...]` to
   `SSH_FLAGS` (`crates/podssh-cli/src/flags.rs:112-233`), and to `ONCE`
   (`crates/podssh-cli/src/ssh/args.rs:53-59`). Refuse a malformed value with
   exit 64 before anything connects.
2. Carry it in `Options` (`crates/podssh-ssh/src/options.rs:163-218`) and
   `Policy` (`crates/podssh-ssh/src/hostkey.rs:17-27`), for the destination
   only, as `HostKeyAlias` (`crates/podssh-ssh/src/run.rs:120-123`).
3. In `Policy::check`, refuse a revoked key and a changed key first, as today
   (`crates/podssh-ssh/src/hostkey.rs:50-57`). Then accept a key whose SHA-256
   fingerprint (`crates/podssh-ssh/src/known_hosts.rs:257-260`) is in the
   list, and record nothing. Refuse any other key, also under `accept-new`
   and `no`, with the fingerprint seen and the ones expected.
4. Jump hops keep the normal policy; say so in the help.
5. The flag's row gives the help and the manual. Update `docs/cli.md:48-91`,
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

# T-032: Run a remote command under `sudo` or `su`, with the password from `SSH_ASKPASS`

**Source:** the sleepinginsummer/agent-ssh-cli report in GitHub #21 (item 7,
`--sudo` and `--su`, `sleepinginsummer/agent-ssh-cli:native/src/privilege.rs`);
the totoshko88/RustConn report in GitHub #24 (item 8, sudo and su
injection). Read in the reports. Read and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

An agent with no terminal cannot run `sudo` on the server when `sudo` asks
for a password: the prompt goes to a remote pty that nobody types into, or
`sudo` refuses with no tty. A password on the command line is not
acceptable.

## Premise

- Read: podssh asks for passwords on the terminal or through `SSH_ASKPASS`
  (`crates/podssh-ssh/src/prompt.rs:49-74`), and refuses when nobody can
  answer (`crates/podssh-ssh/src/prompt.rs:76-88`). A remote command is one
  string for the remote shell (`crates/podssh-ssh/src/session.rs:66-69`).
  Local stdin goes to the channel only after the exec request
  (`crates/podssh-ssh/src/io.rs:48-53`).
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
   `crates/podssh-ssh/src/session.rs:20-21`), stop with 255 and say why.
4. `--su`, a second step: `su` reads only a terminal, so it needs `-tt`. Send
   the password only for a prompt that ends the output with no newline after
   it, before M2, and once.
5. Put the filter in a new module, crates/podssh-ssh/src/elevate.rs. Hook it
   into `handle_msg` (`crates/podssh-ssh/src/io.rs:104-138`) and the stdin
   branch (`crates/podssh-ssh/src/io.rs:56-87`), and keep `io.rs` under 500
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

# T-033: Record a session as asciicast v2, and play it again

**Source:** the rssh-org/rssh report in GitHub #24 (item 2, "Session
recording in asciicast v2"); the Petyok/SSHub report in GitHub #22 (item 8,
session logging and a log browser). Read in the reports. Read and measured
here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A user or an agent cannot keep a record of what a session showed, with its
timing, for an audit or to show a problem again. podssh has no recording
and no player.

## Premise

- Read: each output of a session passes `handle_msg`
  (`crates/podssh-ssh/src/io.rs:104-114`), and each window change passes the
  resize branch (`crates/podssh-ssh/src/io.rs:96-98`). The size at the start
  is `terminal::size` (`crates/podssh-ssh/src/terminal/mod.rs:54`).
  `podssh-ssh` has no JSON dependency
  (`crates/podssh-ssh/Cargo.toml:17-28`).
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
   suggestion step would mix them (`docs/cli.md:121-130`). Add it to `VERBS`
   (`crates/podssh-cli/src/flags.rs:398-425`), to
   `crates/podssh-cli/src/positionals.rs`, to dispatch, and to `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:95`).
5. Refuse a file whose header is not version 2. Skip unknown event types.
6. Write the risks in the manual: the output can hold secrets (a printed
   key, a password that a remote program echoes); a recording sends control
   sequences to your terminal again, so play only files that you trust.

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

# T-034: `podssh agent`: an SSH agent inside podssh, with no separate binary

**Source:** the operator's ruling of 2026-10-08 on Q5: the agent and the
credential helper are parts of podssh (`docs/decisions.md`). The key stores
that the reports in GitHub #21, #22 and #24 ask for (read in the reports).
Read and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** L
**Status:** open

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
  Pageant (`crates/podssh-ssh/src/keys.rs:259-290`). It offers the agent's
  keys first (`crates/podssh-ssh/src/keys.rs:115-167`), and skips the agent's
  certificates (`crates/podssh-ssh/src/keys.rs:123-126`).
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
   (`crates/podssh-relay/src/cache.rs:1-8`). On Windows: a named pipe that
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
   (`crates/podssh-cli/src/flags.rs:398-425`), in
   `crates/podssh-cli/src/positionals.rs` and in `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:95`); `docs/cli.md`;
   "Nothing listens" in `SECURITY.md:59-62`; `docs/STATUS.md`.

## Decision

Recommendation: the agent stays in the foreground, and the user starts it
with `&`. podssh refuses to go to the background (`-f`,
`crates/podssh-cli/src/flags.rs:209-210`), and one life cycle is easier to
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

# T-227: `--direct` has no limit on a stuck write, but the relay leg fails after 60 s (GitHub #36)

**Source:** GitHub #36 (2026-10-08): read by the reporter and marked
plausible; the hang was not observed. Each link read again here on
`3ee70dc`.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

On the relay road, a write that makes no progress for 60 s ends the session.
On the direct road (`--direct`), nothing limits a write. If the peer stops
reading below SSH (a TCP zero window that never opens, or a path that drops
each packet after the connection is up), `podssh ssh --direct` can wait for
ever. `docs/design.md:170` says "A stuck write | Fails after 60 s" and names
no road.

## Premise

Read:

- `client_config` sets `inactivity_timeout: None`
  (`crates/podssh-ssh/src/run.rs:205`). russh 0.64.1 races each write against
  that timer in `flush_or_timeout`; with `None`, the timer never fires, so
  only the write can end the wait.
- The relay leg limits each write: `WRITE_TIMEOUT` is 60 s
  (`crates/podssh-ws/src/client.rs:34-35`, given to the session at
  `crates/podssh-ws/src/client.rs:183`), and `write` applies it
  (`crates/podssh-ws/src/session.rs:241-251`). Then the copy task stops
  (`crates/podssh-ssh/src/relay_stream.rs:95-100`), the next ping meets the
  same limit and ends the read task (`crates/podssh-ws/src/session.rs:162-165`,
  `crates/podssh-ssh/src/relay_stream.rs:106-117`), and russh's next write
  fails. So the relay road ends a stuck write in about 60 to 130 s.
- The direct road gives russh the TCP stream with only `nodelay` set
  (`crates/podssh-cli/src/ssh/mod.rs:140-143`,
  `crates/podssh-ws/src/dial.rs:224-226`).
- russh takes SSH window credit before it writes, so a remote program that
  stops reading makes the session idle, not stuck (GitHub #36). Only a stall
  below SSH causes the hang.
- The stand-in relay's `stall:` mode reads the client's frames and drops them
  (`scripts/fake-relay.py:159-163`), so no fault tests a stuck write today.
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
   `crates/podssh-cli/src/ssh/mod.rs:120-149` changes, and both roads behave
   the same.
3. The other change: set `inactivity_timeout` at
   `crates/podssh-ssh/src/run.rs:205`. russh resets that timer only in a loop
   round that sent no keepalive, podssh's keepalive interval is also 60 s
   (`crates/podssh-ssh/src/options.rs:239`), and the timer also ends a
   session that is only idle. Measure an idle session with
   `ServerAliveInterval=0` before this choice.
4. Keep the forwarder as a fault in `scripts/interop-faults.sh`, with the
   exit code and the time as its check.
5. Name both roads in `docs/design.md:170`, and add the fault to
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
**Status:** open

## Problem

podssh asks for a key passphrase or a server password at each run, on the
terminal or through `SSH_ASKPASS`. A script must keep an askpass program
that it can run, and a sandbox can refuse to run a file from each directory
that it can write (sandbox A: `/tmp`, `/dev/shm` and `$HOME`, T-001). Other
clients store credentials; podssh stores none.

## Premise

Read:

- A prompt goes to `SSH_ASKPASS` or to the terminal; with neither, podssh
  refuses and names the remedy (`crates/podssh-ssh/src/prompt.rs:49-88`).
  The askpass program's answer is zeroized
  (`crates/podssh-ssh/src/prompt.rs:100-117`).
- The prompts for a credential: the passphrase of a key file
  (`crates/podssh-ssh/src/keys.rs:200-220`), the password
  (`crates/podssh-ssh/src/auth.rs:208-229`), and the answers of
  keyboard-interactive (`crates/podssh-ssh/src/auth.rs:153-206`).
- podssh stores no credential but the relay token cache, readable by the
  owner only (`crates/podssh-relay/src/cache.rs:1-8`).
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

# T-229: Hardware keys (FIDO2 `sk-` keys) in `podssh keygen`, the client and `podssh agent`

**Source:** the operator's ruling of 2026-10-08 on Q5 (`docs/decisions.md`);
the totoshko88/RustConn report in GitHub #24 (item 6: FIDO2 and PKCS#11;
read in the report). Read and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

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
  (`crates/podssh-ssh/src/options.rs:254-261`). `known_hosts::key_type` names
  them (`crates/podssh-ssh/src/known_hosts.rs:251-252`), and `ssh-key`
  0.7.0-rc.11 has their algorithms.
- Read: podssh offers each key that an agent lists
  (`crates/podssh-ssh/src/keys.rs:115-167`), so an `sk-` key in OpenSSH's
  `ssh-agent`, with its device present, can work today. Not measured.
- Read: `-I` (PKCS#11) is refused by name
  (`crates/podssh-cli/src/flags.rs:213-214`).
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
  (`crates/podssh-ssh/src/options.rs` lines 202-203). The manual says "the
  SSH handshake" only (`crates/podssh-cli/src/ssh/keywords.rs` line 28,
  `crates/podssh-cli/src/flags.rs` lines 167-168).
- `connect` limits `connect_stream` only
  (`crates/podssh-ssh/src/run.rs` lines 137-159); `auth::authenticate` runs
  with no limit (line 160 there).
- In russh 0.64.1, an authentication request waits for its reply with no
  limit (`wait_recv_reply`), and keepalives start only after the
  authentication succeeds. So nothing ends the wait on the direct road.
- On the relay road, nothing moves while podssh waits, so the relay closes
  the session after 180 s with no payload (`docs/relay.md:113`). The relay's
  own keepalive frames keep the ping watcher content meanwhile.
- A prompt has its own limit when nobody watches the terminal (60 s, T-005;
  `docs/cli.md:227-230`). A person who types slowly must not meet a limit
  of the server.

Not measured: it needs a server that stalls.

## Approach

1. Measure first, with the forwarder of T-227 in the fault harness, set to
   pass the key exchange, then to hold the server's replies. Run
   `timeout 300 podssh ssh --direct ... true`: the reading predicts the time
   limit (exit 124).
2. Limit each wait for an answer of the server with `ConnectTimeout`, at
   `9fefff2`: the `none` request (`crates/podssh-ssh/src/auth.rs` lines
   64-68), a key (`crates/podssh-ssh/src/keys.rs` lines 73-76), an agent key
   (line 148 there), keyboard-interactive (`crates/podssh-ssh/src/auth.rs`
   lines 162-165 and 194) and the password (lines 214-218 there).
3. Do not count a local prompt: each prompt runs before its request
   (`crates/podssh-ssh/src/auth.rs:146-151`). Pitfall: an agent that asks its
   user to confirm a signature (`ssh-add -c`) runs inside the agent request.
4. On expiry, end with 255, and name the step, as "HOST did not answer the
   publickey request within 60 s".
5. Make the comment and the manual (`crates/podssh-cli/src/ssh/keywords.rs:28-29`,
   `crates/podssh-cli/src/flags.rs:167-168`) say the same: the handshake, and
   each answer during the authentication.
   `docs/cli.md:233-235` asks for a limit on the whole operation.

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
  64 MiB (`docs/relay.md:115`).
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
   (`crates/podssh-cli/src/ssh/resolve.rs:59-71`), and the host name from the
   system; never `getpwuid` (`crates/podssh-cli/src/ssh/resolve.rs:74-86`).
3. Compute `%C` as OpenSSH does, and check it against `ssh -G` (step 6).
4. Refuse an unknown token with exit 64, before anything connects, and name
   it.
5. Do not expand `-E`, as OpenSSH does not.
6. T-043 uses the same function for `ssh_config`. Name the tokens in the
   manual's notes and in `docs/cli.md:48-91`.

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
(`scripts/interop.sh:32-33`) when T-026 has not. Planted defect: map `%u` to
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
