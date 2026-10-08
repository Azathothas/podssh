This file holds the work on the command line of podssh: the parser and its
refusals, `--help` and `podssh man`, the options of `podssh ssh` and
`podssh proxy`, the time limit of the commands that need one, and
`podssh keygen`. The rules behind these tables are in `docs/cli.md`.

# T-007: Bracketed IPv6 literal destinations are refused (GitHub #2)

**Source:** GitHub #2 (Nemo-010, 2026-10-08), re-measured by the reporter on
`3a88e1d`; measured again here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`podssh ssh` and `podssh proxy` refuse each IPv6 literal with exit 64 before
they connect: `[V6]`, `[V6]:PORT`, `user@[V6]:PORT` and a bare `V6`. An
IPv6-only target cannot be reached by its address, but `docs/cli.md`
(lines 53-54 at `eaf9822`) says that "an IPv6 literal needs brackets". OpenSSH with
`ProxyCommand='podssh proxy %h %p'` fails too: it gives `%h` as the bare
literal.

## Premise

Measured offline (`PODSSH_OFFLINE=1`, the debug binary of `3ee70dc`):
`podssh proxy '[::1]' 22` exits 64, "'[' is not allowed".
`podssh proxy 2607:99c0:900:da::1 8079` and
`podssh ssh -T 'root@[2607:99c0:900:da::1]:8079' true` (also the bare, the
`ssh://` and the `-J` forms) exit 64, "':' is not allowed". `--direct` and
`-W '[V6]:8079'` reach the offline stop (255): only the relay path refuses.
OpenSSH 10.3p1 (`ssh -G -F none`, offline) gives `hostname 2001:db8::1` for
`root@[2001:db8::1]` and for `root@2001:db8::1`, and port 22 for
`[2001:db8::1]:8079`: it reads no port there.

Read: `parse_hop` already removes the brackets
(`crates/podssh-cli/src/ssh/resolve.rs:325-365`). The refusal is `check_host`
(`crates/podssh-relay/src/relay.rs:158-174`), called at
`crates/podssh-cli/src/ssh/resolve.rs:228`, `crates/podssh-cli/src/proxy.rs:108`
and in `forward_path` (`crates/podssh-relay/src/relay.rs:116-129`); since this
entry, each calls `check_target` there. Tests assert the refusal:
`crates/podssh-relay/src/relay.rs:222`, and `crates/podssh-cli/tests/proxy.rs`
(lines 49-50 at `eaf9822`).

Not known: how `/connect/<host>/<port>` takes a literal. The contract does not
say, and says "numeric hosts must be a strict dotted quad"
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:231`). Read in
GitHub #2, not verified here: the relay's `/trace` dials `[V6]:8079`.

## Approach

1. Measure first: an ignored live test in `crates/podssh-relay/tests/live.rs`,
   built like `open_github` (`crates/podssh-relay/tests/live.rs:15-24`), so the
   token stays in the process. It opens one public IPv6 target, chosen with
   `/trace`, by three paths: the bare literal, `%5B` and `%5D`, raw brackets.
   Give `/trace` its token in a header file, never on argv (`AGENTS.md`,
   section 4). Write the answers in `docs/relay.md`.
2. A target check beside `check_host`: a name that `check_host` accepts, or
   text that `std::net::Ipv6Addr` parses. A zone id does not parse, so the rule
   of `crates/podssh-relay/src/relay.rs:116-122` holds. Keep `check_host` for
   relay hosts, which are TLS names (`crates/podssh-relay/src/relay.rs:98-114`,
   `crates/podssh-relay/src/pool.rs:79`).
3. `forward_path` writes the literal in the measured form. `podssh ssh` uses
   the new check at `crates/podssh-cli/src/ssh/resolve.rs:228`, and refuses
   `-4` with an IPv6 literal (64).
4. `podssh proxy` (`crates/podssh-cli/src/proxy.rs:97-110`): `HOST PORT` takes
   a bare literal (the `%h %p` form) or `[V6]`. One word takes `[V6]:PORT` and
   refuses `V6:PORT`: `2001:db8::1:22` is itself an address. Reuse the rule of
   `split_host_port` (`crates/podssh-ws/src/dial.rs:369-390`).
5. Messages use `podssh_ws::dial::authority` (`crates/podssh-ws/src/dial.rs:349-356`),
   not `host:port` (`crates/podssh-cli/src/ssh/mod.rs:75`,
   `crates/podssh-cli/src/proxy.rs:87`, where it is used since this entry). `known_hosts` keeps the literal as
   typed: `host_name` writes `[V6]:PORT` as OpenSSH does
   (`crates/podssh-ssh/src/known_hosts.rs:53-60`).
6. Same commit: `docs/cli.md:54-67`, the help at
   `crates/podssh-cli/src/positionals.rs:20` and
   `crates/podssh-cli/src/positionals.rs:47`, an example in
   `crates/podssh-cli/src/man/examples.rs:8-49`, `docs/relay.md`,
   `docs/STATUS.md`. Use `2001:db8::/32` in offline tests only: the relay
   refuses that range.

## Decision

Recommendation: send the form that the relay takes, in this order of
preference: the bare literal (`/connect/2001:db8::1/22`), then the brackets
percent-encoded. RFC 3986 allows `:` in a path segment, and does not allow a
raw `[` or `]` there. Raw brackets lost: a proxy or an edge can refuse them.
Use them only if the relay takes no other form. If it takes none, keep the
refusal with a message that says so, and ask the operator for a relay change.

## Prove

```sh
cargo test -p podssh-relay --lib -- ipv6
cargo test -p podssh-cli --test ssh_args -- ipv6
cargo test -p podssh-cli --test proxy -- ipv6
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh proxy 2001:db8::1 22 </dev/null; test $? -eq 69
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh ssh -T 'u@[2001:db8::1]:8079' true </dev/null; test $? -eq 255
cargo test -p podssh-relay --test live -- --ignored ipv6
```

The unit tests pass each IPv6 form, and refuse a zone id and `V6:PORT`. The
binary runs reach the offline stop (69 and 255, not 64), so no check of the
client refuses the literal. The live test shows the relay's answer. Plant:
make the new check refuse `:` again; both binary runs then exit 64.

## Correction

2026-10-08, measured (the Approach, step 1): the relay takes an IPv6 address
in `/connect/<host>/<port>` in each form tried: bare, `%5B` and `%5D`, raw
brackets, and `%3A` for each colon. The reading of GitHub #2 holds:
`/trace` reports `dialed_literal: true` and `address_family: 6`. But
`/trace` says `ok` for a dial that carries no byte: the relay's egress
reached no IPv6 host. Through it, the session opens and closes at once with
`1011 target closed before sending anything` (T-253, blocked on the relay's
operator).

## Done

2026-10-08, in the commit "IPv6 addresses as targets: podssh sends the bare
literal to the relay".

- `podssh_relay::relay::check_target` takes a host name or a bare IPv6
  address (no zone id); `forward_path` writes the bare address
  (`/connect/2001:db8::1/22`). A relay host stays a TLS name (`check_host`).
- `podssh ssh` takes `u@V6`, `u@[V6]:PORT`, `ssh://u@[V6]:PORT` and the same
  forms in `-J` and `-W`. `-4` with an IPv6 address and `-6` with an IPv4
  address exit 64.
- `podssh proxy` takes `V6 PORT` (OpenSSH's `%h %p`), `[V6] PORT` and
  `[V6]:PORT`. `V6:PORT` in one word exits 64, and the message names the
  brackets.
- Messages bracket an IPv6 address (`podssh_ws::dial::authority`).
  `known_hosts` files a port other than 22 as `[V6]:PORT`, as before.
- When the relay closes the session to an IPv6 target at once, podssh adds
  a note: "an IPv6 target that closes at once usually means that the relay
  has no IPv6 route out", and for `ssh` the `--direct` remedy.
- `cargo test -p podssh-relay --lib -- ipv6` (2 tests),
  `cargo test -p podssh-cli --test ssh_args -- ipv6` and
  `cargo test -p podssh-cli --test proxy -- ipv6` pass. Offline,
  `podssh proxy 2001:db8::1 22` exits 69 and
  `podssh ssh -T 'u@[2001:db8::1]:8079' true` exits 255. Planted (the old
  refusal of `:` in `check_target`): both exit 64.
- Live (`cargo test -p podssh-relay --test live -- --ignored ipv6
  --nocapture`): the relay took `/connect/2001:4860:4860::8888/853`, then
  closed the session with 1011.
- The manual (a note for `ssh` and for `proxy`, an example, the help of
  both destinations), `docs/cli.md`, `docs/relay.md`, `README.md` and
  `docs/STATUS.md` say the same.

# T-008: The `--timeout` refusal with no terminal names `chat` for each command, and contradicts itself (GitHub #6)

**Source:** GitHub #6 (Nemo-010, 2026-10-08), re-measured by the reporter on
`3a88e1d`; measured again here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

With no terminal, `podssh cp`, `mv`, `relay` and `chat` exit 64 and show the
example `podssh chat --send '#chan hi' --timeout 30s` for each of them. The
second line, "Without it a script cannot hang for ever — it hangs for ever.",
contradicts itself. The first line shows an internal name, `(Pipe)`. The four
commands are not implemented, so a script is told to fix a command line that
would change nothing.

## Premise

Measured offline (stdin from `/dev/null`, stdout to a file): `podssh cp`,
`mv`, `relay` and `chat` exit 64 with the three lines above. With
`--timeout 5s` each exits 70, "'cp' is not implemented yet; nothing was
done." `podssh status`, `node` and `operator x` (no `--timeout` row) exit 70.

Read: dispatch runs the `--timeout` gate (`crates/podssh-cli/src/dispatch.rs` lines 186-196 at `37ace00`)
before the refusal of a verb that is not implemented
(`crates/podssh-cli/src/dispatch.rs:216-224`). `require_timeout` writes the
fixed text and has no verb to name (`crates/podssh-cli/src/non_interactive.rs` lines 194-201 at `37ace00`).
`podssh ts` uses the same function (`crates/podssh-cli/src/ts.rs:43-50`), so a
build with the `ts` feature shows the chat example for `ts` too (read, not
measured: the debug binary has no `ts`).

## Approach

1. In the `Parsed::Command` arm, refuse a verb of `VERB_OWNER`
   (`crates/podssh-cli/src/flags.rs:422-430`) before the gate. Keep one usage
   error first: a `--timeout` value that was given and does not parse is 64
   (`docs/cli.md:158-159`).
2. Give `require_timeout` the verb's name. The message names that verb, gives
   one true reason, and shows an example for that verb only. Replace
   `({attachment:?})` with words: "stdin or stdout is not a terminal", or
   "--jsonl was given".
3. Pass `"ts"` from `crates/podssh-cli/src/ts.rs:43-50`.
4. Change the tests that use `chat` for the gate
   (`crates/podssh-cli/src/dispatch.rs:395-448`,
   `crates/podssh-cli/tests/non_interactive.rs` lines 252-284 at `37ace00`). `ts` is the only verb
   that runs the gate today (`crates/podssh-cli/tests/ts_behave.rs:205-211`).
5. Same commit: `docs/STATUS.md`. `docs/cli.md:169` needs no change.

## Decision

Recommendation: a verb that does nothing says so first (exit 70), the
reporter's second option. It has nothing to bound, and a 64 tells a script
that its command line is wrong when it is not. The alternative, the gate first
with the right verb, lost: it still asks for a flag that changes nothing. A
malformed `--timeout` value stays 64 for each verb, because it is wrong in
each case.

## Prove

```sh
cargo test -p podssh-cli --test non_interactive -- not_implemented_before_the_timeout the_timeout_refusal_names_the_verb
cargo test -p podssh-cli --lib -- dispatch::tests
cargo test -p podssh-cli --features ts --test ts_behave -- ts_without_timeout_in_a_pipe_is_usage_64
for v in cp mv relay chat; do
  PODSSH_OFFLINE=1 timeout 20 target/debug/podssh "$v" </dev/null 2>/tmp/t008.err
  test $? -eq 70 && grep -q 'not implemented yet' /tmp/t008.err && ! grep -q -- --send /tmp/t008.err || exit 1
done
```

The new process test (crates/podssh-cli/tests/non_interactive.rs) runs the
four verbs with no terminal and expects 70, and `cp --timeout 30x` expects 64.
The new unit test expects `podssh ts` in the message, and no `chat` and no
`Pipe`. The loop checks the real binary. Plant: put the gate back before the
refusal; the process test gets 64.

## Done

2026-10-08, in the commit "A command that is not implemented says so before
the --timeout gate".

- Dispatch: a verb of `VERB_OWNER` skips the gate. A `--timeout` that was
  given and does not parse is still 64; then the refused flags (64); then
  the refusal "not implemented yet" (70).
- `require_timeout` takes the verb: "podssh ts: --timeout DURATION is
  required when stdin or stdout is not a terminal: nobody may be there to
  stop a run that waits." and "Example: podssh ts --timeout 30s -W
  HOST:PORT". With `--jsonl`, the reason is "--jsonl was given". No internal
  name, and no other verb.
- `cargo test -p podssh-cli --lib -- dispatch::tests`: 13 passed, among them
  `the_timeout_refusal_names_the_verb`. `cargo test -p podssh-cli --test
  non_interactive`: 19 passed, among them `not_implemented_before_the_timeout`
  and `the_timeout_refusal_names_the_verb`. In the container,
  `sh scripts/dev.sh test -p podssh-cli --features podssh-cli/ts --test
  ts_behave`: 10 passed, 1 ignored (live).
- The loop of the Prove, offline on Windows: `cp`, `mv`, `relay` and `chat`
  exit 70 with "not implemented yet" and no `--send`. Planted (the gate
  before the refusal): each exits 64, and `not_implemented_before_the_timeout`
  fails.
- Found by the full run: `the_p_split_is_visible_in_the_binarys_output`
  (`crates/podssh-cli/tests/binary_streams.rs`) asserted the old order, 64
  for a piped `cp` with no `--timeout`. It now expects 70 and "not
  implemented yet". `cargo test --no-fail-fast`: 734 passed, 0 failed, 6
  ignored.

# T-009: A missing flag value is reported as an unknown flag (GitHub #8)

**Source:** GitHub #8 (Nemo-010, 2026-10-08), re-measured by the reporter on
`3a88e1d`; measured again here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A known flag with no value is reported as an unknown flag, with its long name
and its value name joined: `podssh ssh -p` prints
`podssh: unknown flag '--port <PORT>'.` The user then looks for another flag.
A refused flag with no value (`podssh ssh -L`) also says "unknown flag", and
not its refusal and its replacement. The last line of the message, about a
dropped `-o`, does not apply.

## Premise

Measured offline: exit 64 and `unknown flag` for each of these:

- `podssh ssh --port`, `ssh -p`, `ssh host -p`: `'--port <PORT>'`.
- `podssh ssh -o`: `'--option <NAME=VALUE>'`.
- `podssh keygen -t ed25519 -f`: `'--file <FILE>'`.
- `podssh proxy --relay-host`, `podssh doctor --ca-file`: the same form.
- `podssh ssh -L`: `'--forward-local <SPEC>'`. `podssh ssh -l -x host`:
  `'--login-name <USER>'` (clap reads `-x` as a flag).

Read: clap 4.6.7 (`Cargo.lock`) reports a missing value as
`ErrorKind::InvalidValue`, with an empty `InvalidValue` context and
`InvalidArg` set to the flag's display, `--port <PORT>` (its `empty_value` and
`verify_num_args`, read in the local cargo registry). podssh sends this kind to
the `_` arm (`crates/podssh-cli/src/clap_error.rs` lines 70-77 at `3cd368b`). The token is
flag-shaped (`crates/podssh-cli/src/clap_error.rs:110-112`), so the arm calls
`unknown_flag` (`crates/podssh-cli/src/refuse.rs:29-45`).

## Approach

1. In `rebuild_error` (`crates/podssh-cli/src/clap_error.rs:33-89`), before
   the `_` arm, read `InvalidValue` with an empty value as a missing value.
2. Find the row: take the long name between `--` and the first space of
   `InvalidArg`, and look it up in the verb's rows (`crate::flags::verb_for`).
3. Add `refuse::missing_value`: `podssh ssh: -p (--port) needs a value: PORT.`,
   then `Run 'podssh ssh --help'`. Exit 64. clap gives the long spelling also
   when the user typed `-p`, so print both spellings.
4. A `Refused` row with no value gets its own refusal: a value would not change
   the answer. Move the refusal text of `refusals`
   (`crates/podssh-cli/src/dispatch.rs:234-242`) to `refuse.rs`, so the two
   cannot differ.
5. A long name with no row keeps today's message, as a fallback.
6. Same commit: `docs/cli.md:47-51` (a flag with no value names the flag and
   its value), `docs/STATUS.md`.

Pitfall: `-l -x`: OpenSSH takes `-x` as the user, clap takes it as a flag. Say
"needs a value", and do not guess.

## Prove

```sh
cargo test -p podssh-cli --test tree -- a_missing_value_names_the_flag
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh ssh -p </dev/null 2>/tmp/t009.err
test $? -eq 64 && grep -q 'needs a value' /tmp/t009.err && ! grep -q 'unknown flag' /tmp/t009.err
```

The new test in `crates/podssh-cli/tests/tree.rs` covers each measured case:
`needs a value` with both spellings, and no `unknown flag`. `ssh -L` names
`-W HOST:PORT`. The control: `ssh --no-such-flag` still says `unknown flag`.
Plant: remove the new arm; the test reads `unknown flag` and fails.

## Done

2026-10-08, in the commit "A flag with no value names the flag and its
value".

- The premise, measured again with the `probe_clap` example (now it takes a
  command line, `cargo run -p podssh-cli --example probe_clap -- ssh -p`):
  kind `InvalidValue`, an empty `InvalidValue`, and `InvalidArg` as
  `--port <PORT>`, also for `-p`; `ssh --no-such-flag` is `UnknownArgument`.
- `rebuild_error` reads that shape as a missing value, finds the row by its
  long name in the verb's table, and gives `refuse::missing_value`:
  "podssh ssh: -p (--port) needs a value: PORT." and the help hint. A
  refused row gives the refusal that it gives with a value. A long name
  with no row keeps the old message.
- `refuse::refused` is the one text of a refused flag; `dispatch` and the
  new arm both use it. The unused `refuse::refused_flag` is gone.
- `cargo test -p podssh-cli --test tree`: 13 passed, among them
  `a_missing_value_names_the_flag` with each measured case and the control.
  The binary, offline: `podssh ssh -p` exits 64 with "needs a value" and no
  "unknown flag". Planted (the new arm off): the test fails, and the binary
  says `unknown flag '--port <PORT>'`.
- `docs/cli.md` and `docs/STATUS.md` say the same.

# T-010: `podssh --help` with other words prints the help and drops the words silently (GitHub #10)

**Source:** GitHub #10 (Nemo-010, 2026-10-08); measured here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh --help` followed by other words prints the top-level help, exits 0,
and ignores the words. `podssh --help --json` gives no sign that `--json` does
not exist, against "No option is dropped silently" (`docs/cli.md:47-51`).
`podssh --help ssh` prints the top-level help, not the help of `ssh`.
`podssh --version` drops its other words in the same way.

## Premise

Measured offline:

- `podssh --help --json`, `--help ssh`, `-h doctor`, `--help --help`: exit 0,
  the same 1558 bytes of top-level help.
- `podssh --version --json`, `-V example.org`: exit 0, `podssh 0.1.0`.
- Controls: `podssh --json` is exit 64, `unknown flag '--json'`.
  `podssh ssh --help --json` and `podssh man --json` are exit 64 too.

Read: `parse` returns at the first word when it is `-h`, `--help`, `-V` or
`--version` (`crates/podssh-cli/src/tree.rs` lines 266-272 at `56b466b`), and never reads the
rest. For a verb, clap reads each word before `--help` is answered
(`crates/podssh-cli/src/tree.rs:355-364`), so an unknown word is refused there.

## Approach

1. At `crates/podssh-cli/src/tree.rs:265-277`: `-h` or `--help` alone is
   `Parsed::Help("")`. With one more word that names a verb
   (`crate::flags::verb_for`), it is `Parsed::Help` of that verb, as
   `podssh VERB --help` is. Any other word is `Parsed::Usage`:
   `unknown_flag` for a flag-shaped word
   (`crates/podssh-cli/src/refuse.rs:29-45`), else a message that names it.
2. `-V` or `--version` with any other word is `Parsed::Usage` (exit 64).
3. Keep the verb level as it is: `podssh ssh --help host` prints the help of
   `ssh`, after clap has checked each word.
4. If the top-level help text changes (`TOP_OPTIONS`,
   `crates/podssh-cli/src/flags.rs:455-458`), update its test
   `no_top_level_option_runs_into_its_description`
   (`crates/podssh-cli/src/help.rs:311-328`). Same commit: `docs/cli.md:47-51`,
   `docs/STATUS.md`.
5. The JSON that GitHub #10 asks for is T-050. This entry only stops the drop.

## Decision

Recommendation: `podssh --help VERB` prints the help of VERB. Users type it,
and its meaning is clear, so the word is answered, not dropped. The
alternative, refuse each other word, lost: it refuses a clear request. Each
word that is not a verb is refused.

## Prove

```sh
cargo test -p podssh-cli --test tree -- the_top_level_help_drops_no_word
cargo test -p podssh-cli --test plants -- the_control_help_and_version_are_not_refusals
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh --help --json </dev/null >/tmp/t010.out 2>/tmp/t010.err
test $? -eq 64 && test ! -s /tmp/t010.out && grep -q -- --json /tmp/t010.err
```

The new test in `crates/podssh-cli/tests/tree.rs`: `--help --json`,
`--help ssh extra` and `--version --json` are `Parsed::Usage`;
`--help ssh` is the help of `ssh`; `--help` alone is the top-level help. The
existing control keeps `--help`, `-h`, `--version` and `-V` alone working.
Plant: restore the early return for `--help`; the new test fails on
`--help --json`.

## Done

2026-10-08, in the commit "podssh --help and --version drop no word".

- `tree::parse`: `-h` or `--help` with a word that names a verb is the help
  of that verb (`--help scp` is the help of `cp`); a flag-shaped word, or a
  second word, is `Parsed::Usage`; another word is refused as an unknown
  subcommand, with its suggestion (`--help sssh`). `-V` or `--version` with
  any word is `Parsed::Usage`. The message: "podssh: --help takes no word
  '--json'." and the hint.
- The top-level help says "Print help; --help COMMAND prints the help of one
  command"; its test `no_top_level_option_runs_into_its_description` follows.
- `cargo test -p podssh-cli`: each test passes, among them
  `the_top_level_help_drops_no_word` and the control
  `the_control_help_and_version_are_not_refusals`. The binary, offline:
  `podssh --help --json` exits 64, stdout empty, stderr names `--json`.
  Planted (the early return back): the test fails, and the binary prints
  1605 bytes of help with exit 0.
- `docs/cli.md` and `docs/STATUS.md` say the same. GitHub #10 stays open
  for T-050.

# T-011: A host or target that starts with `-` can be read as a flag

**Source:** GitHub #22 (the Petyok/SSHub report: reject leading-dash hosts,
pass the destination after `--`), GitHub #25 (the USBoverSSH report: strict
input validation) and GitHub #23 (the cubic-vm/cubic report: a documented `--`
contract); read in the reports, not verified here. Measured here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A script that runs `podssh ssh "$HOST" uptime` with a host it did not write
can have that host read as a flag. `-oHostName=evil.example` as the first word
sets an option, and the next word becomes the destination. podssh refuses each
word that starts with `-` in the place of a host, but no help, manual page or
example tells a script to put `--` before the host. In `podssh proxy`, a host
read as a flag gives "missing PORT", which hides the cause.

## Premise

Measured offline (`PODSSH_OFFLINE=1`):

- `podssh ssh -v -oHostName=evil.example real.example true` connects to
  `evil.example:22` (the offline stop, 255). With `--` first it is 64, "a host
  name cannot start with '-'". `--relay-host=evil.example` there sets the relay.
- `podssh proxy --relay-host=evil.example 22` is 64, `missing PORT`.
- Exit 64: `ssh -- -oProxyCommand=x`, `ssh -- user@-x true`, `ssh -J=-x host`
  (`crates/podssh-cli/src/ssh/resolve.rs:361-363`); `ssh --relay-host=-x host`,
  `proxy -- -oX 22`, `proxy - 22` (`crates/podssh-relay/src/relay.rs:167-169`).
  `ssh -- host -x` runs the command `-x`: `--` ends the options.
- `ssh --direct -oHostName=-x host true` reaches the offline stop: `HostName`
  replaces the host (`crates/podssh-cli/src/ssh/resolve.rs` line 92 at `4bceef6`) with no check.
- OpenSSH 10.3p1 (`ssh -G -F none`, offline) refuses `-- -oProxyCommand=x` and
  `-J -x host` (255), so it never gives such a `%h` to `podssh proxy`.

Read: no option makes podssh start a program: `ProxyCommand` is refused and
`LocalCommand` is ignored (`crates/podssh-cli/src/ssh/keywords.rs:69-78`). The
risk is a changed option (a host, a relay, a trust store), not a command.

## Approach

1. Document `--`: `usage_tail` (`crates/podssh-cli/src/help.rs:248-259`) gives
   `[OPTIONS] [--] [user@]host [COMMAND...]` for `ssh` and
   `[OPTIONS] [--] HOST PORT` for `proxy`; `--help` and the synopsis of the
   manual (`crates/podssh-cli/src/man/model.rs:183-187`) read it.
2. A note for `ssh` and `proxy` (`crates/podssh-cli/src/man/notes.rs:19-66`)
   and an example (`crates/podssh-cli/src/man/examples.rs:8-49`). Pitfall: the
   notes test reads a bare `--` as a flag that does not exist
   (`crates/podssh-cli/src/man/notes.rs:150-156`); teach `flag_exists`
   (`crates/podssh-cli/src/man/notes.rs:119-133`) that `--` ends the options.
3. `podssh proxy` (`crates/podssh-cli/src/proxy.rs:97-102`): when HOST or PORT
   is missing and a relay or trust flag was given, add one line: a HOST that
   starts with `-` is read as a flag; put `--` before it.
4. Check `HostName` with the rule of the destination: one function for the
   checks at `crates/podssh-cli/src/ssh/resolve.rs:358-363`, also called at
   `crates/podssh-cli/src/ssh/resolve.rs:110-116`.
5. Same commit: `docs/cli.md:54-67` (the `--` rule, and a host that starts
   with `-` is refused, as OpenSSH refuses it), `docs/STATUS.md`.

## Decision

Recommendation: keep OpenSSH's parsing, and document `--`. podssh reads options
before and after the destination, as OpenSSH does
(`crates/podssh-cli/src/positionals.rs:11-14`), so a caller needs `--` with
OpenSSH too. The alternative, no options after the first positional, lost: it
breaks `podssh ssh host -p 2222`, and it does not protect the word before the
destination.

## Prove

```sh
cargo test -p podssh-cli --test leading_dash
cargo test -p podssh-cli --lib -- man::
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh ssh --direct -o HostName=-x -l u host true </dev/null 2>/tmp/t011.err
test $? -eq 64 && ! grep -q PODSSH_OFFLINE /tmp/t011.err
```

The new test file crates/podssh-cli/tests/leading_dash.rs runs the binary with
`PODSSH_OFFLINE=1` for each shape above. A refusal is exit 64 with no
`PODSSH_OFFLINE` line, so nothing came near a connection. Its control:
`ssh -l u -- host -x` reaches the offline stop. The manual tests accept the
new note and example. Plant: delete the `-` check in `parse_hop`;
`ssh --direct -l u -- -x true` then reaches the offline stop, and the test
fails.

## Done

2026-10-08, in the commit "A host that starts with -: refused also as
HostName, and -- is documented".

- The usage line of `ssh` is `[OPTIONS] [--] [user@]host [COMMAND...]`, and
  of `proxy` `[OPTIONS] [--] HOST PORT`; `--help` and the synopsis of the
  manual read it. The manual has a note for `ssh` and for `proxy`, and an
  example (`podssh ssh -- user@example.org uptime`); the notes check knows
  that `--` ends the options.
- One rule, `host_rule`, for a destination, a `-J` hop, a `-W` target and
  `-o HostName`: not empty, not starting with `-`. `-o HostName=-x` had
  reached the connection; now it is 64.
- `podssh proxy`: when HOST or PORT is missing and a relay or trust flag was
  given, a line says that a HOST that starts with - is read as a flag, and
  to put -- before it. The usage line shows `[--]`.
- `cargo test -p podssh-cli`: each test passes, among them the new
  `crates/podssh-cli/tests/leading_dash.rs` (3 tests: nine shapes refused
  with 64 and no `PODSSH_OFFLINE` line, the proxy remedy, and the control
  `ssh -l u -- host -x`, which reaches the offline stop) and the manual
  tests. The binary, offline: `ssh --direct -o HostName=-x -l u host true`
  exits 64. Planted (the `-` check off): the test fails, and both that run
  and `ssh --direct -l u -- -x true` reach the offline stop.
- `docs/cli.md` and `docs/STATUS.md` say the same.

# T-012: `PODSSH_TIMEOUT` gives the default of `--timeout` (GitHub #12)

**Source:** GitHub #12 (Nemo-010, 2026-10-08), also listed in GitHub #23;
measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

With no terminal, each verb with a `--timeout` row needs the flag on each
call. An agent that runs many commands cannot set the limit once. GitHub #12
asks for `PODSSH_TIMEOUT` as the default, with the flag first.

## Premise

Measured offline: `PODSSH_TIMEOUT=5s podssh mv` and
`PODSSH_TIMEOUT=5s podssh chat --send '#c hi'` still exit 64 with the
`--timeout` refusal. No file of `crates/` or `docs/` names the variable.

Read: the `--timeout` rows are those of `cp` and `mv`
(`crates/podssh-cli/src/flags.rs:255-256`), `chat`
(`crates/podssh-cli/src/flags.rs:268-269`), `ts`
(`crates/podssh-cli/src/flags.rs:297-298`) and `relay`
(`crates/podssh-cli/src/flags.rs:315-316`). Each but `ts` exits 70
(`crates/podssh-cli/src/flags.rs:422-430`), and `ts` needs its feature. So the
variable matters when `cp`, `mv` and `relay` exist. `ssh` and `proxy` have no
`--timeout`.

## Approach

1. One reader in `crates/podssh-cli/src/non_interactive.rs`, with the variable
   lookup passed in, as `proxy_from_vars` does
   (`crates/podssh-ws/src/dial.rs:141-162`): the flag, else a `PODSSH_TIMEOUT`
   that is not empty, else nothing. It returns the text and its source.
2. Call it at both gate sites: `crates/podssh-cli/src/dispatch.rs:191-204` and
   `crates/podssh-cli/src/ts.rs:43-50`. Parse with `parse_timeout`
   (`crates/podssh-cli/src/non_interactive.rs:136-180`): a whole duration,
   never zero.
3. A malformed value names its source: `--timeout` (exit 64), or
   `PODSSH_TIMEOUT` (exit 78, see Decision). The variable never bounds `ssh`
   or `proxy`.
4. Same commit: a row in `VARIABLES` (`crates/podssh-cli/src/man/facts.rs:48-90`),
   which `each_variable_in_the_source_is_documented` requires
   (`crates/podssh-cli/src/man/facts.rs:327-340`); "default: env
   PODSSH_TIMEOUT" in the help of each `--timeout` row, as `--relay-host` says
   it (`crates/podssh-cli/src/flags.rs:169-170`); `docs/cli.md:192-194`;
   `docs/STATUS.md`.
5. Do this after T-008, so that a verb that does nothing still exits 70 first.

## Decision

Recommendation: a malformed `PODSSH_TIMEOUT` exits 78 (`EX_CONFIG`). The
command line is correct and a setting is not (`docs/decisions.md`, "Exit
codes"). The alternative, 64 as for the flag, lost: a script would look for
the fault in its arguments. Note that a bad `PODSSH_RELAY` exits 64 today
(measured: `PODSSH_RELAY='bad host!' podssh proxy example.org 22`); this
entry does not change it.

## Prove

```sh
cargo test -p podssh-cli --test non_interactive -- podssh_timeout
cargo test -p podssh-cli --lib -- man::facts
cargo test -p podssh-cli --features ts --test ts_behave -- podssh_timeout
```

The first runs the reader with a supplied lookup: the flag wins, the variable
is used, an empty value is unset, and `30x` from the variable is 78 and names
`PODSSH_TIMEOUT`. The second checks ENVIRONMENT against the source in both
directions. The third runs the binary of a `ts` build: with
`PODSSH_TIMEOUT=30s`, `podssh ts` passes the gate and stops at the missing key
file (77, as `crates/podssh-cli/tests/ts_behave.rs:37-48`); without it, 64.
Plant: drop the variable from the reader; the third test gets 64.

# T-013: The help groups the commands by purpose

**Source:** GitHub #23 (the cubic-vm/cubic report, item 10: "Consistent
success feedback + command grouping help", cubic issues 451 and 548); read in
the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`podssh --help` lists 13 commands in one list, in the order of the table. The
five commands that work are mixed with seven that are not implemented, and
with `ts`, which is not in the default build. A new user must read each line
to find what works. The manual's "Commands" table and the refusals for a
missing or unknown command show the same list.

## Premise

Measured offline: the `SUBCOMMANDS:` block of `podssh --help` is ssh, proxy,
node, operator, chat, cp, mv, man, relay, status, doctor, keygen, ts. Seven
lines say "(not implemented yet)" and `ts` says "(not in this build)".
`podssh man --no-pager` shows the same order under "Commands".

Read: one table, `VERBS` (`crates/podssh-cli/src/flags.rs:380-411`), has no
group. Four places render it: `top_level_help`
(`crates/podssh-cli/src/help.rs:138-161`), the start of the manual
(`crates/podssh-cli/src/man/model.rs:120-126`), `unknown_verb`
(`crates/podssh-cli/src/refuse.rs:124-128`) and `no_arguments`
(`crates/podssh-cli/src/refuse.rs:153-164`).

## Approach

1. Add the group to the table in `crates/podssh-cli/src/flags.rs`: a field of
   `Verb` (`crates/podssh-cli/src/flags.rs:367-378`), or one list of groups. A
   new test in `crates/podssh-cli/tests/flag_table.rs` asserts that each verb
   is in exactly one group, as `every_verb_has_an_owner_so_no_verb_can_be_a_silent_stub`
   does for owners (`crates/podssh-cli/tests/flag_table.rs:89`).
2. Render the groups in `--help` and in the manual's "Commands" table. Keep
   the availability note of each line (`crates/podssh-cli/src/help.rs:168-175`).
3. Keep the two refusal lists flat, or raise their limit with a reason:
   `a_refusal_is_a_line_not_a_usage_dump` allows 18 lines
   (`crates/podssh-cli/src/refuse.rs:246-247`), and the list for
   `example.org` has 17.
4. Update `scripts/interop-man.sh:36-37` in the same commit. It reads the
   `SUBCOMMANDS:` block up to the first blank line, and takes the first word
   of each line as a verb. A heading or a blank line between groups breaks it.
5. Same commit: `docs/STATUS.md`.

## Decision

Recommendation: group by purpose, with the availability note on each line.
For example: "Connect" (ssh, proxy, ts), "This host" (doctor, keygen, status),
"Files" (cp, mv), "Reverse mode" (node, operator), and one group each for
relay, chat and man. Purpose does not change between releases and builds. The
alternative, the working commands first, lost: the groups would move with
each milestone and with the `ts` feature.

## Prove

```sh
cargo test -p podssh-cli --test flag_table -- each_verb_is_in_one_group
cargo test -p podssh-cli --lib -- help::tests refuse::tests man::model
cargo test -p podssh-cli --test man_flag_parity
sh scripts/dev.sh check
```

The first test fails when a verb is in no group or in two. The second and the
third check the help, the refusals and the manual against the table. The gate
runs `scripts/interop-man.sh` with its planted page, so a block that the
script cannot read fails there. Plant: put one verb in two groups; the first
test fails.

# T-014: `podssh man` writes the whole manual from the binary (GitHub #1)

**Source:** GitHub #1 (Azathothas, 2026-10-08).
**Category:** feature
**Milestone:** M3
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

`podssh man` printed a roff page. A host with only the binary could not read
it, and a manual that is written by hand drifts from the code. GitHub #1 asked
for the whole manual from the binary, with `--no-pager`.

## Premise

Read in the commit message of `d0b16a3`: `podssh man` wrote roff only, and its
`Fl` macro showed blank flag names (T-015).

## Approach

The binary builds the manual as data from its own tables, and two renderers
write it:

1. The model (`crates/podssh-cli/src/man/model.rs`), the text renderer
   (`crates/podssh-cli/src/man/text.rs`) and the roff renderer
   (`crates/podssh-cli/src/man/roff.rs`).
2. The facts from constants (`crates/podssh-cli/src/man/facts.rs`), the notes
   (`crates/podssh-cli/src/man/notes.rs`), the examples
   (`crates/podssh-cli/src/man/examples.rs`), and one table of `-o` keywords
   that the parser also reads (`crates/podssh-cli/src/ssh/keywords.rs`).
3. The pager: `PAGER`, else `less`, else its own
   (`crates/podssh-cli/src/pager.rs`); `--no-pager`, `--roff` and
   `podssh man SECTION`.

## Prove

```sh
cargo test -p podssh-cli --test man_page
cargo test -p podssh-cli --test man_flag_parity
cargo test -p podssh-cli --lib -- man::
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh man --no-pager </dev/null >/tmp/t014.out 2>/tmp/t014.err
test $? -eq 0 && test -s /tmp/t014.out && test ! -s /tmp/t014.err
```

The tests check the manual against the code in both directions: flags, `-o`
keywords and their defaults, variables, exit codes, examples and notes. The
binary run writes the whole manual to stdout and nothing to stderr.

## Done

2026-10-08, commit `d0b16a3` ("podssh man: the whole manual from the binary,
as text"; `Closes #1`).

- `cargo test -p podssh-cli` passed on Windows, with the man tests:
  `crates/podssh-cli/tests/man_page.rs`, `crates/podssh-cli/tests/man_flag_parity.rs`,
  and the drift tests in `crates/podssh-cli/src/man/facts.rs`,
  `crates/podssh-cli/src/man/notes.rs`, `crates/podssh-cli/src/man/examples.rs`
  and `crates/podssh-cli/src/ssh/keywords.rs`.
- The container gate step `scripts/interop-man.sh` passed in CI run
  37755468121 (`d0b16a3`, success).
- The checks of the binary are in `docs/STATUS.md`, section "`podssh man`,
  measured".
- GitHub #1 closed 2026-10-08 09:16Z.
- Measured again here on `3ee70dc` (offline): `podssh man --no-pager` exits 0
  with 31,620 bytes and nothing on stderr; `podssh man nonsense` exits 64 and
  lists the sections.

# T-015: The manual showed blank flag names under groff and mandoc (GitHub #4, audit C7)

**Source:** GitHub #4 (Nemo-010, 2026-10-08), the verification of audit item
C7, re-measured by the reporter on `3a88e1d`.
**Category:** defect
**Milestone:** M3
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`podssh man | groff -man -Tascii` showed each option without its flag names:
"Print help" in place of `-h, --help`. mandoc did the same. So the page was of
no use as the only reference on a host with just the binary.

## Premise

Read in GitHub #4 and measured for the change: the page defined a macro `Fl`
with the body `\fB\$*\fR`, and groff 1.23.0 and mandoc printed blank flag
names (`docs/STATUS.md`, section "`podssh man`, measured"). The tests read the
roff source and not a renderer, so CI stayed green.

## Approach

1. The roff writer uses only standard man(7) requests and defines no macro
   (`crates/podssh-cli/src/man/roff.rs:1-13`). A flag is a `.TP` term in bold.
2. The gate renders the page with groff and mandoc, and finds each flag
   spelling of `--help` in both (`scripts/interop-man.sh`). A planted page
   must fail (`scripts/interop-man.sh:109-120`).
3. `docs/cli.md:28-32` states the rule.

## Prove

```sh
cargo test -p podssh-cli --lib -- man::roff
cargo test -p podssh-cli --test man_page -- a_real_renderer_shows_each_flag_name
sh scripts/dev.sh check
```

The first checks the requests (`crates/podssh-cli/src/man/roff.rs:161`) and
the `.TP` term of each flag (`crates/podssh-cli/src/man/roff.rs:187`). The
second renders the page when the host has groff or mandoc, and says so when
it has neither. The gate runs `scripts/interop-man.sh` with both renderers,
`groff -ww`, `mandoc -Tlint -W error` and the planted page.

## Done

2026-10-08, commit `d0b16a3` (`Fixes #4`).

- `scripts/interop-man.sh` in the container gate: groff (`-ww`, no warning)
  and mandoc (`-Tlint -W error`, no error) show all 48 flag spellings from
  `--help`, and a planted page with one flag term removed fails. CI run
  37755468121 passed.
- GitHub #4 closed 2026-10-08 09:16Z.
- Measured again here on `3ee70dc` (offline): `podssh man --roff` exits 0 with
  32,583 bytes and nothing on stderr. It has no `.de` request, uses only the 11
  requests of `MACROS`, and has 184 `.TP` terms. This Windows host has no groff
  or mandoc, so the rendering was not repeated here.

# T-016: Each flag of OpenSSH 10.3p1 answers by name (GitHub #5, audit C10)

**Source:** GitHub #5 (Nemo-010, 2026-10-08), audit item C10, re-measured by
the reporter on `3a88e1d`.
**Category:** defect
**Milestone:** M3
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

Sixteen flags in the usage of OpenSSH 10.3p1 had no row in the table of
`podssh ssh`. `-c`, `-m`, `-X`, `-Y`, `-O` and the others gave a bare
"unknown flag", against the rule that each flag of OpenSSH is supported or
refused by name.

## Premise

Measured by the reporter on the release binary and on `3a88e1d`:
`podssh ssh -c aes128-ctr x@h true` exited 64 with `unknown flag '-c'`, and
the same for the other fifteen.

## Approach

1. Rows in `SSH_FLAGS`: `-c -m -f -G -I -K -M -O -S -Q -w -X -Y -y` are refused
   by name with what to use instead (`crates/podssh-cli/src/flags.rs:204-232`).
   `-k` is supported and `-g` is accepted with no effect
   (`crates/podssh-cli/src/flags.rs:182-186`).
2. A refusal with nothing to use instead says "Leave it out."
   (`crates/podssh-cli/src/dispatch.rs:234-242`), and `--help` shows
   "(refused)" (`crates/podssh-cli/src/help.rs:100-103`).
3. A test holds the reviewed set (`crates/podssh-cli/tests/flag_table.rs:15-30`).
   `docs/cli.md:76-79` states the rule.

## Prove

```sh
cargo test -p podssh-cli --test flag_table
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh ssh -c aes128-ctr x@h true </dev/null 2>/tmp/t016.err
test $? -eq 64 && grep -q 'Leave it out' /tmp/t016.err
```

`the_ssh_short_flags_are_exactly_the_reviewed_set` fails when a flag is added
or removed without an edit of the reviewed set. The binary run shows a refusal
by name.

## Done

2026-10-08, commit `0c93a7c` (`Fixes #5`).

- The reviewed set: `SSH_SHORT_FLAGS = "plinJNstTeC46WEFvqVoxaPLRDABbkgcmfGIKMOSQwXYy"`.
- `cargo test -p podssh-cli` passed on Windows. The CI run of `eacd94e`, which
  contains `0c93a7c`, passed.
- GitHub #5 closed 2026-10-08 09:29Z.
- Measured again here on `3ee70dc` (offline): `-c aes128-ctr`, `-X` and
  `-O check` exit 64 with "... is refused. Leave it out." and the reason; `-G`
  exits 64 with "Use podssh man ssh instead."

# T-017: A repeated flag follows OpenSSH; `-J` and `-W` only once (GitHub #16)

**Source:** GitHub #16 (talaria0101, 2026-10-08), with the reporter's narrower
scope in a comment; the KTM report, review 2.
**Category:** defect
**Milestone:** M3
**Priority:** P0
**Effort:** S
**Status:** done

## Problem

`podssh ssh` kept the last value of a repeated value flag. `-J a -J b` dropped
the first hop with no message, so the session took another path to the host.
`-p 2222 -p 22` connected to port 22, where OpenSSH connects to 2222. A
repeated `--relay-host` cut a failover list to its last host.

## Premise

Measured by the reporter on the release binary and on `4853e6c`:
`-J a.invalid -J b.invalid` dialled only `b.invalid`, and `-p 2222 -p 22`
connected to port 22; `ssh -G -p 2222 -p 22` of OpenSSH gives `port 2222`.
Read then: each value flag but `-i` and `-o` was `ArgAction::Set`.

## Approach

1. The value flags of `ssh` keep each value (`ArgAction::Append`,
   `crates/podssh-cli/src/tree.rs:60-67`).
2. `SshArgs::from_matches` picks the value as OpenSSH does: the first `-p` and
   `-l`, the last `-e`, `-E` and `-F`, and the first value of each `-o`
   keyword (`crates/podssh-cli/src/ssh/args.rs:78-133`).
3. `ONCE` and `repeated` refuse a second `-J`, `-W`, `--relay-host`,
   `--relay-addr` or `--ca-file` with exit 64 before anything connects
   (`crates/podssh-cli/src/ssh/args.rs:49-73`, called at
   `crates/podssh-cli/src/tree.rs:452-456`).
4. `docs/cli.md:70-75` and a note of the manual
   (`crates/podssh-cli/src/man/notes.rs:40-42`) state the rule.

## Prove

```sh
cargo test -p podssh-cli --test ssh_args
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh ssh -J a.invalid -J b.invalid host </dev/null 2>/tmp/t017.err
test $? -eq 64 && grep -q 'was given 2 times' /tmp/t017.err
```

`a_repeated_value_follows_openssh` and
`a_flag_that_may_be_given_once_is_refused_when_repeated` in
`crates/podssh-cli/tests/ssh_args.rs` assert the value that wins and each
refusal. The control is one `-J` with two hops. The binary run refuses the
second `-J` before any connection.

## Done

2026-10-08, commit `3ee70dc`, pushed. Its `Fixes #16` closed GitHub #16.

- Measured against `ssh -G` of OpenSSH 10.3p1, rule by rule (`docs/STATUS.md`,
  section "`podssh ssh`, measured", the row of repeated flags).
- `cargo test -p podssh-cli --test ssh_args`: 15 of 15 on Windows.
- The binary: `podssh ssh -J a.invalid -J b.invalid host` exits 64 with "-J was
  given 2 times; give the hops as one comma list, as in -J a,b."
- Measured again here on `3ee70dc` (offline): the same; `-W` twice and
  `--relay-host` twice exit 64; `-v -p 2222 -p 22 -l first -l second host true`
  says "connecting to host:2222".
- P0, because `-J a -J b` changed the path to the host with no message.

# T-018: `podssh keygen -p` and `-c`: change the passphrase and the comment of a key

**Source:** the lablup/bssh report in GitHub #18, #20 and #22, item 5
("cross-check podssh keygen flag coverage", `lablup/bssh:src/bin/bssh_keygen.rs`);
read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A host with no working `ssh-keygen` cannot change the passphrase or the
comment of a key: the `ssh-keygen` of OpenSSH does not run without a user
database entry (`docs/cli.md:144-145`). `podssh keygen -p` and `-c` exit 64
with "unknown flag", not a refusal by name. podssh's own message for a PEM key
names `ssh-keygen -p -f FILE` as the remedy
(`crates/podssh-ssh/src/keygen.rs:161-164`), a program that may not run there.

## Premise

Measured offline: `podssh keygen -p -f k`, `-c -f k` and `-P old -f k` exit 64
with `unknown flag`. The usage of OpenSSH 10.3p1 (`ssh-keygen -?`, offline):
`-p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase] [-P old_passphrase] [-Z cipher]`
and `-c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]`.

Read: `KEYGEN_FLAGS` has generation, `-y` and `-l`
(`crates/podssh-cli/src/flags.rs:345-365`). The parts exist: decryption with a
prompt (`crates/podssh-cli/src/keygen.rs:187-218`), a new passphrase asked
twice (`crates/podssh-cli/src/keygen.rs:167-185`), encryption as OpenSSH does
it (`crates/podssh-ssh/src/keygen.rs:76-83`), and the refusal of a passphrase
on argv (`crates/podssh-cli/src/keygen.rs:74-81`).

## Approach

1. Rows in `KEYGEN_FLAGS`: `-p`, `-c` and `-P PHRASE`. `-P` follows `-N`: only
   `-P ''` is accepted; another value is refused (64) and not kept
   (`NewPassphrase`, `crates/podssh-cli/src/keygen.rs:24-32`).
2. Read the key with each format that `podssh ssh -i` reads:
   `russh::keys::decode_secret_key`, the reader behind `load_secret_key`
   (`crates/podssh-ssh/src/keys.rs:190`). Ask for the old passphrase on the
   terminal or through `SSH_ASKPASS`, as `-y` does. With neither, refuse at
   once and name `-P ''` and `-N ''` (as `crates/podssh-cli/src/keygen.rs:168-172`).
3. `-p`: ask for the new passphrase twice (or take `-N ''`), and encrypt with
   `keygen::protect`. `-c`: take `-C` or ask; refuse a control character, as
   `crates/podssh-cli/src/keygen.rs:106-109` does. Write the OpenSSH format.
4. A new invariant beside "never over an existing file" (`docs/cli.md:146`):
   write a new file in the same directory (`create_new`, mode 0600), read it
   back, decrypt it with the new passphrase, compare its public key with the
   original, then rename it over the original. Never write a different key
   over the file. For `-c`, write `FILE.pub` again.
5. Same commit: the PEM message at `crates/podssh-ssh/src/keygen.rs:161-164`
   names `podssh keygen -p`; `docs/cli.md:140-152`, the notes of `keygen`
   (`crates/podssh-cli/src/man/notes.rs:81-89`), `docs/STATUS.md`.

## Decision

Recommendation: keep no copy of the old file. A copy keeps the key under the
old passphrase, or with none, which the user wanted to change. The
alternative, a `FILE.old` as `ssh-keygen -R` keeps for `known_hosts`, lost for
that reason. For a key in another format, write the OpenSSH format, as
`ssh-keygen -p` does; to keep PEM needs the writers of T-022.

## Prove

```sh
cargo test -p podssh-cli --test keygen -- change
sh scripts/dev.sh check
```

New tests in `crates/podssh-cli/tests/keygen.rs`: `-p` with `SSH_ASKPASS`
changes the passphrase and keeps the public key; `-P secret` and `-N secret`
are refused and the digest of the file does not change; `-c -C new` changes
the comment in the key and in `.pub`. New checks in
`scripts/interop-keygen.sh`: OpenSSH's `ssh-keygen -y -P NEW` decrypts the
result, the old passphrase fails, and `sshd` still accepts the key. Plant: skip
the compare of step 4 and write a fresh key; the public-key test fails.

# T-019: `podssh keygen -F`, `-R` and `-H`: find, remove and hash `known_hosts` entries

**Source:** the lablup/bssh report in GitHub #18, #20 and #22, item 5
(`lablup/bssh:src/bin/bssh_keygen.rs`); read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

podssh refuses a changed host key and shows both fingerprints. Then the user
must remove the old line from `known_hosts` by hand: `ssh-keygen -R` does not
run without a user database entry, and `podssh keygen` has no `-R`. A host
with only podssh also cannot look a host up (`-F`) or hash a file (`-H`).

## Premise

Measured offline: `podssh keygen -F example.org`, `-R example.org` and `-H`
exit 64 with `unknown flag`. Measured with the `ssh-keygen` of OpenSSH 10.3p1
on a scratch file that holds one public host key (offline):

- `-F github.com -f FILE` prints `# Host github.com found: line 2` and the
  line, exit 0. A missing host prints nothing, exit 1. `-F` also finds a hashed
  line.
- `-R other.example -f FILE` prints the found line, "FILE updated." and
  "Original contents retained as FILE.old", exit 0. A missing host prints
  "Host missing.example not found in FILE", exit 0.
- `-H -f FILE` writes each host as `|1|salt|hash`, keeps the comment line,
  keeps `FILE.old`, and warns that `FILE.old` holds the names.

Read: podssh matches hashed lines with HMAC-SHA1
(`crates/podssh-ssh/src/known_hosts.rs:145-179`), finds the lines of a host
with their numbers (`crates/podssh-ssh/src/known_hosts.rs:100-119`), and
appends without a rewrite (`crates/podssh-ssh/src/known_hosts.rs:206-241`).
The default files are the ones of `podssh ssh`
(`crates/podssh-cli/src/man/facts.rs:103`).

## Approach

1. Rows in `KEYGEN_FLAGS` (`crates/podssh-cli/src/flags.rs:345-365`):
   `-F HOST`, `-R HOST` and `-H`. `-f FILE` selects the file; else the first
   user `known_hosts` file. Accept `[host]:port`, as `host_name` writes it
   (`crates/podssh-ssh/src/known_hosts.rs:53-60`).
2. `-F`: reuse `entries_for`, and print the lines of OpenSSH; exit 1 when no
   line matches.
3. `-R` and `-H`: one rewrite: a new file in the same directory (`create_new`,
   mode 0600) that keeps each line it does not change byte for byte
   (comments, unknown markers, lines that do not parse), `FILE.old`, then a
   rename. A line with a wildcard or a negated pattern cannot be hashed: keep
   it, and say so.
4. `-H`: a random salt of 20 bytes and the HMAC-SHA1 of `hashed_matches`, so
   podssh and OpenSSH both find the result.
5. Same commit: `docs/cli.md:140-152`, the notes of `keygen`, `docs/STATUS.md`.

Pitfall: a rewrite can lose a key that `podssh ssh` appends at the same moment
(T-029). Read the file again just before the rename, and refuse if it changed.

## Prove

```sh
cargo test -p podssh-ssh --lib -- known_hosts
cargo test -p podssh-cli --test keygen -- known_hosts
sh scripts/dev.sh check
```

Unit tests: the rewrite keeps the other lines byte for byte, and `matches`
finds a line that `-H` wrote. New checks in `scripts/interop-keygen.sh`:
OpenSSH's `ssh-keygen -F` finds each host in a file that `podssh keygen -H`
hashed, and `podssh keygen -F` finds each host that `ssh-keygen -H` hashed.
Plant: drop the comment lines in the rewrite; the byte test fails.

# T-020: `podssh keygen -Y`: SSH signatures

**Source:** the lablup/bssh report in GitHub #18, #20 and #22, item 5
(`lablup/bssh:src/bin/bssh_keygen.rs`); read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A host with only podssh cannot sign a file with an SSH key, or verify such a
signature (PROTOCOL.sshsig): the `ssh-keygen` of OpenSSH does not run without
a user database entry. git's SSH signing calls `ssh-keygen -Y` (git's
documentation, not verified here).

## Premise

Measured offline: `podssh keygen -Y sign -f k -n file` exits 64 with
`unknown flag '-Y'`. The usage of OpenSSH 10.3p1 (offline): `-Y sign -f
key_file -n namespace file`, `-Y verify -f allowed_signers_file -I
signer_identity -n namespace -s signature_file [-r krl_file]`,
`-Y check-novalidate`, `-Y find-principals` and `-Y match-principals`.

Read: the key library in the tree, `ssh-key` 0.7.0-rc.11 (`Cargo.lock`), has
`SshSig` with its PEM armour, `PrivateKey::sign(namespace, hash, msg)` and
`PublicKey::verify(namespace, msg, sig)` (its sshsig.rs, private.rs and
public.rs, read in the local cargo registry; not built here). podssh-ssh uses
that crate as `russh::keys::ssh_key` (`crates/podssh-ssh/src/keygen.rs:11-14`).

## Approach

1. Rows: `-Y OP`, `-n NAMESPACE`, `-s FILE` and `-I IDENTITY`. `-f` keeps its
   row, with a help that names both uses (a key, or an allowed-signers file).
   `-n` and `-s` mean other things with CA signing (T-021): one row for each
   letter, with a help for each mode, and tests for the combinations.
2. `sign`: read the private key as `-y` does (a passphrase by prompt or
   `SSH_ASKPASS`, never from argv). Sign with SHA-512. Write `FILE.sig` with
   `create_new`, never over a file.
3. `verify`, `check-novalidate`, `find-principals`, `match-principals`: parse
   the allowed-signers format of ssh-keygen(1) (principals, `namespaces=`,
   `valid-after=`, `valid-before=`, `cert-authority`), with the pattern
   matcher of `known_hosts` (`crates/podssh-ssh/src/known_hosts.rs:182-204`).
   Print the lines and the exit codes of OpenSSH.
4. Refuse `-r` (a key revocation list) by name until podssh reads one.
5. Same commit: `docs/cli.md:140-152`, the notes of `keygen`, `docs/STATUS.md`.

Pitfalls: read the signed file as bytes, never as text. A namespace that does
not match is a failure, never a warning.

## Prove

```sh
cargo test -p podssh-cli --test keygen -- sign
sh scripts/dev.sh check
```

New checks in `scripts/interop-keygen.sh`: OpenSSH's `ssh-keygen -Y verify`
accepts each podssh signature (Ed25519, ECDSA and RSA), `podssh keygen -Y
verify` accepts each OpenSSH signature, and both refuse a changed file and a
wrong namespace. Plant: sign with the namespace `file` whatever `-n` says;
OpenSSH's verify with `-n git` then fails.

# T-021: `podssh keygen -s`: user and host certificates

**Source:** the lablup/bssh report in GitHub #18, #20 and #22, item 5
(`lablup/bssh:src/bin/bssh_keygen.rs`); read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A host with only podssh cannot sign a user key or a host key with a CA key
(PROTOCOL.certkeys), and cannot print a certificate. Certificates with a short
validity give access to many hosts with no edit of each `authorized_keys`.

## Premise

Measured offline: `podssh keygen -s ca -I id -n u k.pub` exits 64 with
`unknown flag '-s'`. The usage of OpenSSH 10.3p1 (offline):
`-I certificate_identity -s ca_key [-hU] [-D pkcs11_provider] [-n principals]
[-O option] [-V validity_interval] [-z serial_number] file ...`, and `-L`.

Read: `ssh-key` 0.7.0-rc.11 (`Cargo.lock`) has a certificate builder: a random
nonce, the serial, the type, the key id, the principals, critical options,
extensions, and `sign` (its certificate/builder.rs, read in the local cargo
registry). `podssh ssh` uses no certificate: it ignores `CertificateFile`
(`crates/podssh-cli/src/ssh/keywords.rs:64`), and it checks host certificates
as plain keys (`docs/STATUS.md`, section "Components"). T-027 covers that side.

## Approach

1. Rows: `-s CA`, `-I ID`, `-n PRINCIPALS`, `-V INTERVAL`, `-z SERIAL`,
   `-O OPTION` (repeatable), `-h` (a host certificate) and `-L`. `-h` is free:
   a verb declares only `--help` (`crates/podssh-cli/src/tree.rs:78-91`). `-V`
   is a validity here, not the version: say so in `--help`, as the help says
   it for `-P` (`crates/podssh-cli/src/help.rs:230-241`).
2. Read the CA key as `-y` reads a private key (a passphrase by prompt or
   `SSH_ASKPASS`).
3. Build the certificate with the builder of the library, and write
   `FILE-cert.pub` with `create_new`.
4. `-V`: the forms of ssh-keygen(1) (`+52w`, `YYYYMMDD[HHMMSS]`, a pair,
   `always:forever`); a malformed interval is exit 64. `-O`: `clear`,
   `force-command=`, `source-address=`, and the `no-` and `permit-` options;
   refuse the others by name.
5. `-L`: print the certificate as `ssh-keygen -L` does.
6. Same commit: `docs/cli.md:140-152`, the notes of `keygen`, `docs/STATUS.md`.

## Decision

Recommendation: user and host certificates in one step: `-h` changes only the
type and the default extensions. The alternative, user certificates first,
lost: it saves little, and leaves `-h` as an unknown flag. The check of
`@cert-authority` in `podssh ssh` stays in T-027.

## Prove

```sh
cargo test -p podssh-cli --test keygen -- certificate
sh scripts/dev.sh check
```

New checks in `scripts/interop-keygen.sh`: `ssh-keygen -L` reads each
certificate that podssh makes; `sshd` with `TrustedUserCAKeys` accepts a user
certificate for a login with the `ssh` of OpenSSH; `sshd` refuses a
certificate whose validity has ended. Plant: ignore `-n` when podssh signs;
the `sshd` login check fails.

# T-022: `podssh keygen -e`, `-i` and `-m`: convert key formats

**Source:** the lablup/bssh report in GitHub #18, #20 and #22, item 5
(`lablup/bssh:src/bin/bssh_keygen.rs`); read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

`podssh keygen -y` and `-l` refuse a PEM or PKCS#8 private key, and the
message names `ssh-keygen -p -f FILE`
(`crates/podssh-ssh/src/keygen.rs:161-164`), which does not run without a user
database entry. `podssh ssh -i` reads the same file. A host with only podssh
cannot export a public key for another system (RFC 4716, PKCS#8), or import
one.

## Premise

Measured offline: `podssh keygen -e -f k.pub`, `-i -f k.pub` and
`-m PEM -f k` exit 64 with `unknown flag`. The usage of OpenSSH 10.3p1
(offline): `-i [-f input_keyfile] [-m key_format]`,
`-e [-f input_keyfile] [-m key_format]`, and `-m format` with a new key and
with `-p`.

Read: `read_key_file` takes only an OpenSSH private key or a public key line
(`crates/podssh-ssh/src/keygen.rs:151-172`). `podssh ssh -i` loads a key with
`russh::keys::load_secret_key` (`crates/podssh-ssh/src/keys.rs:190`), which
calls `decode_secret_key`: OpenSSH, PKCS#1 RSA, PKCS#8 (also encrypted), SEC1
EC and PuTTY PPK. russh also has `encode_pkcs8_pem` and
`encode_pkcs8_pem_encrypted` (russh 0.64.1, `Cargo.lock`; its
keys/format/mod.rs, read in the local cargo registry).

## Approach

1. `read_key_file`: give a `-----BEGIN` block that is not OpenSSH to
   `decode_secret_key`, so `-y` and `-l` read each key that `podssh ssh -i`
   reads. An encrypted PEM key asks for its passphrase, as `-y` does.
2. Rows: `-e`, `-i` and `-m FORMAT`: `RFC4716` (the default for `-e` and
   `-i`), `PKCS8` and `PEM`.
3. `-e`: write the public key to stdout, in the format of `-m`. `-i`: read a
   public key in that format, and write the OpenSSH line to stdout.
4. `-m` with a new key and with `-p` (T-018): write the private key in that
   format; use `encode_pkcs8_pem_encrypted` when there is a passphrase.
5. Same commit: `docs/cli.md:140-152`, the notes of `keygen`, `docs/STATUS.md`.

Pitfalls: no new C dependency. A format that a key type does not have (PEM
for Ed25519) is refused by name.

## Decision

Recommendation: `-i` imports public keys only, and a private key in another
format goes through `-p` (T-018). podssh never prints a private key
(`crates/podssh-cli/src/keygen.rs:6-9`). The alternative, `-i` prints the
private key on stdout as `ssh-keygen` does, lost for that reason.

## Prove

```sh
cargo test -p podssh-ssh --lib -- keygen
cargo test -p podssh-cli --test keygen -- convert
sh scripts/dev.sh check
```

New checks in `scripts/interop-keygen.sh`: `ssh-keygen -i -m PKCS8` reads
what `podssh keygen -e -m PKCS8` writes, and the reverse, for each key type;
`podssh keygen -y` reads a PEM key that `ssh-keygen -m PEM` wrote, and prints
the line of `ssh-keygen -y`. Plant: drop the PEM branch of `read_key_file`;
the last check fails.

# T-230: The help and the manual say that `-R` is refused because podssh never binds

**Source:** found while the entries T-007 to T-022 were written (the report of
the writer of this file); measured here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh ssh --help` says "-L, -R and -D are refused by name: podssh never
binds a listener.", and `podssh man ssh` says it with "never listens on a
port". This is wrong for `-R`: the server listens, and podssh only connects
out. `docs/cli.md:100-103` says that the refusal of `-R` must not say that
podssh never binds. The refusal of `-R` also says "Use -W HOST:PORT instead",
but `-W` carries a connection in the other direction.

## Premise

Measured offline:

- `podssh ssh --help` has the line "-L, -R and -D are refused by name: podssh
  never binds a listener." `podssh man ssh --no-pager` has "-L, -R and -D are
  refused by name: podssh never listens on a port. Use -W HOST:PORT ...".
- `podssh ssh -R 8080:localhost:80 host`: exit 64, "-R SPEC is refused. Use
  -W HOST:PORT instead. remote forwarding is not in the first release."
- Control: `podssh ssh -o RemoteForward=8080:localhost:80 host`: exit 64,
  "remote forwarding is not implemented yet", with no listener and no `-W`.

Read: the texts are at `crates/podssh-cli/src/help.rs` (lines 205-206 at
`25ab0e7`), `crates/podssh-cli/src/man/notes.rs` (lines 31-32 at `25ab0e7`)
and in the `-R` row (`crates/podssh-cli/src/flags.rs` lines 194-195 at
`25ab0e7`). The keyword's text is at `crates/podssh-cli/src/ssh/options.rs:148`.
A test keeps the wrong replacement: `the_forwarding_rows_all_name_w` asserts
that `forward-remote` names `-W HOST:PORT`
(`crates/podssh-cli/tests/flag_table.rs` lines 68-77 at `25ab0e7`).

## Approach

1. The `-R` row (`crates/podssh-cli/src/flags.rs:194-195`): the help "remote
   forwarding is not implemented yet", the words of `-o RemoteForward`; the
   replacement `no flag`, so the refusal says "Leave it out."
   (`crates/podssh-cli/src/dispatch.rs:234-242`).
2. `crates/podssh-cli/src/help.rs:232-234` and
   `crates/podssh-cli/src/man/notes.rs:31-33`: `-L` and `-D` need a local
   listener and are refused, and `-W HOST:PORT` carries one connection; `-R`
   is not implemented yet.
3. `crates/podssh-cli/tests/flag_table.rs:67-86`: keep `-W` for `-L` and `-D`.
   For `-R`, assert that its row names no `-W` and no listener.
4. Only texts change; T-035 implements `-R` (M8). `docs/cli.md:95-104` already
   gives the rule. Same commit: `docs/STATUS.md`.

Pitfall: the manual tests read these texts. `each_name_in_a_note_exists`
checks each flag that a note names (`crates/podssh-cli/src/man/notes.rs:183-187`),
and the parity tests compare the sentence of each row in `--help` and in the
manual (`crates/podssh-cli/tests/man_flag_parity.rs`). Change the row and both
notes in one commit.

## Prove

```sh
cargo test -p podssh-cli --test flag_table -- the_forwarding_rows
cargo test -p podssh-cli --lib -- help::tests man::notes
cargo test -p podssh-cli --test man_flag_parity
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh ssh -R 8080:localhost:80 host </dev/null 2>/tmp/t230.err
test $? -eq 64 && grep -q 'not implemented yet' /tmp/t230.err && ! grep -q -- '-W' /tmp/t230.err
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh ssh --help </dev/null >/tmp/t230.out; ! grep -q -- '-R.*never' /tmp/t230.out
```

## Done

2026-10-08, in the commit "The -R refusal gives its own cause, not the
listener".

- The `-R` row says "remote forwarding is not implemented yet", the words of
  `-o RemoteForward`, and has nothing to use instead, so its refusal says
  "Leave it out." `--help` and the manual give `-L` and `-D` the listener as
  their cause and `-W HOST:PORT` in their place, and give `-R` a sentence of
  its own. The comments in `dispatch.rs` and `tree.rs` that quoted the old
  text follow it.
- Prove: `cargo test -p podssh-cli --test flag_table -- the_forwarding_rows`
  (1 passed), `cargo test -p podssh-cli --lib -- help::tests man::notes`
  (11 passed, with the new tests `the_lines_about_r_name_no_listener` and
  `the_note_about_r_names_no_listener`), and
  `cargo test -p podssh-cli --test man_flag_parity` (5 passed). The binary:
  `podssh ssh -R 8080:localhost:80 host` exits 64 with "-R SPEC is refused.
  Leave it out." and "remote forwarding is not implemented yet.", and names
  no `-W`; no line of `podssh ssh --help` has `-R` and "never".
- Plant: the old `-R` row fails the flag-table test and the help test; the
  old notes of `--help` and of the manual fail the two new tests.

The changed table test pins the replacement of each forwarding row. The binary
runs show the refusal of `-R` with no `-W`, and no help line that joins `-R`
and "never". Plant: put `-W HOST:PORT` back in the `-R` row; the table test
fails.

# T-231: A bad `PODSSH_RELAY` or `PODSSH_RELAY_ADDR` exits 64, not 78

**Source:** found while T-012 was written (the report of the writer of this
file); measured here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A `PODSSH_RELAY` or `PODSSH_RELAY_ADDR` that cannot be used makes
`podssh proxy`, `podssh ssh` and `podssh doctor` exit 64, the code of a usage
error. The command line is correct; a setting of the environment is not.
`docs/cli.md:158-159` and `docs/decisions.md` ("Exit codes") give 78
(`EX_CONFIG`) for a configuration error. A script that reads 64 looks for the
fault in its arguments.

## Premise

Measured offline (`PODSSH_OFFLINE=1`):

- `PODSSH_RELAY='bad host!' podssh proxy example.org 22`: exit 64,
  `bad relay "bad host!": ...`. The same for `podssh ssh -l u host true`.
- `PODSSH_RELAY_ADDR=nonsense`, with the same two commands: exit 64,
  `PODSSH_RELAY_ADDR: "nonsense" is not HOST=IP`.
- Control: `podssh proxy --relay-host 'bad host!' example.org 22` is 64, and
  that is correct: there the fault is in the command line.

Read: `select_relays` (`crates/podssh-relay/src/relay.rs:55-75`) and
`pins::apply` (`crates/podssh-cli/src/pins.rs` lines 10-20 at `cd3fea5`) give
one error for the flag and for the variable. Each caller maps it to 64, at
`cd3fea5`: `crates/podssh-cli/src/proxy.rs` lines 60-71,
`crates/podssh-cli/src/ssh/mod.rs` lines 33-43 (through
`crates/podssh-cli/src/ssh/resolve.rs` line 183), and
`crates/podssh-cli/src/doctor/mod.rs` lines 47-56 (read, not run). The code 78
exists (`crates/podssh-cli/src/exitmap.rs:54`), and `podssh proxy` gives it for
a bad proxy URL or token (`crates/podssh-cli/src/proxy.rs:158-171`).

## Approach

1. Keep the source of the value: `select_relays` and `pins::apply` tell a bad
   flag from a bad variable (an error type, or the flag parsed first and then
   the variable).
2. A bad flag stays 64. A bad variable is 78 in `proxy`, `ssh` and `doctor`;
   the message names the variable, as it does now.
3. Same commit: the 78 row of EXIT STATUS
   (`crates/podssh-cli/src/man/facts.rs:258-263`) names `PODSSH_RELAY`,
   `PODSSH_RELAY_ADDR` and each command; `docs/STATUS.md`. T-012 gives
   `PODSSH_TIMEOUT` the same rule.

## Decision

Recommendation: 78 also for `podssh ssh`. Its own failures are 255, as in
OpenSSH, but a usage error before anything is attempted is already 64 there
(`crates/podssh-cli/src/ssh/mod.rs` lines 37-43 at `cd3fea5`), and OpenSSH does not read these
variables, so it has no code to copy. The alternative, 255 for `ssh`, lost: a
script could not tell a bad setting from a failed connection.

## Prove

```sh
cargo test -p podssh-cli --test proxy -- a_bad_variable_is_a_configuration_error
PODSSH_OFFLINE=1 PODSSH_RELAY='bad host!' timeout 20 target/debug/podssh proxy example.org 22 </dev/null; test $? -eq 78
PODSSH_OFFLINE=1 PODSSH_RELAY_ADDR=nonsense timeout 20 target/debug/podssh ssh -l u host true </dev/null; test $? -eq 78
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh proxy --relay-host 'bad host!' example.org 22 </dev/null; test $? -eq 64
```

The new test in `crates/podssh-cli/tests/proxy.rs` runs the binary with each
bad variable for `proxy`, `ssh` and `doctor`, and expects 78 and the variable's
name on stderr. The last command is the control: a bad flag stays 64. Plant:
map the variable's error to 64 again; the test and the two checks of 78 fail.

## Done

2026-10-08, in the commit "A bad relay variable is a configuration error
(78)".

- `crates/podssh-cli/src/relay_settings.rs` (new): `Refusal`, a message
  with its exit code, and `relays`, which selects the relay hosts and names
  the source of a bad value: `--relay-host` (64) or `PODSSH_RELAY` (78).
  `pins::apply` gives 64 for `--relay-addr` and 78 for `PODSSH_RELAY_ADDR`.
  `proxy`, `doctor` and `ssh` print the refusal and return its code;
  `resolve_or_refuse` carries it through the resolution of `ssh`, which
  still checks the command line first.
- The 78 row of EXIT STATUS names both variables and the three commands,
  and `docs/cli.md` gives the rule.
- Prove: `cargo test -p podssh-cli --test proxy --
  a_bad_variable_is_a_configuration_error` passed (78 and the variable's
  name for `proxy`, `ssh` and `doctor`, with each variable; 64 for each
  flag). The binary: `PODSSH_RELAY='bad host!' podssh proxy example.org 22`
  gave 78, `PODSSH_RELAY_ADDR=nonsense podssh ssh -l u host true` gave 78,
  and `podssh proxy --relay-host 'bad host!' example.org 22` gave 64.
  `cargo test -p podssh-cli`: 238 passed.
- Plant: both variables mapped to 64 again. The test failed (`left: 64,
  right: 78` for `PODSSH_RELAY` with `proxy`), and the two binary checks
  gave 64.

# T-232: `gate_prompt` and `PromptSite` are used only by tests, and name flags that do not exist

**Source:** found while T-008 and T-012 were written (the report of the
writer of this file); read here on `3ee70dc`.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`crates/podssh-cli/src/non_interactive.rs` holds a second prompt gate that no
command calls. Its module comment says that this gate is the only path to a
prompt, which is false. Its refusals name flags that podssh does not have
(`--accept-new`, `--relay URL`) and ids of a former planning process (E01,
E13). A reader who trusts the comment changes the wrong code, and a test keeps
the false flag name.

## Premise

Read: no source outside the module and the tests uses `gate_prompt`,
`PromptSite` or `force_interactive` (a search of `crates/` for each name). The
texts: `--accept-new` at `crates/podssh-cli/src/non_interactive.rs:245-246`,
`--relay URL` at `crates/podssh-cli/src/non_interactive.rs:255`, E01 at
`crates/podssh-cli/src/non_interactive.rs:259-260`; the claim at
`crates/podssh-cli/src/non_interactive.rs:9-13`. A test asserts the false
flag (`crates/podssh-cli/tests/non_interactive.rs:225`).

The real gate is `can_ask` (`crates/podssh-ssh/src/prompt.rs:78`), called at
`crates/podssh-ssh/src/auth.rs:161`, `crates/podssh-ssh/src/auth.rs:215`,
`crates/podssh-ssh/src/keys.rs:201` and `crates/podssh-cli/src/keygen.rs:169`.
Its refusals name the real remedies (`docs/cli.md:178-180`). Commands use
these parts of the module, which stay: `Attachment`, `resolve`, `resolve_tty`,
`parse_timeout`, `require_timeout` (`crates/podssh-cli/src/dispatch.rs:191-204`,
`crates/podssh-cli/src/ts.rs:43-50`) and `refuse_jsonl_in_proxy`
(`crates/podssh-cli/src/tree.rs:319-323`).

## Approach

1. Remove `force_interactive` and the variant `Attachment::ForcedInteractive`
   (`crates/podssh-cli/src/non_interactive.rs:78-96`), `PromptSite`
   (`crates/podssh-cli/src/non_interactive.rs:112-134`) and `gate_prompt`
   (`crates/podssh-cli/src/non_interactive.rs:219-280`).
2. Remove their tests (`crates/podssh-cli/tests/non_interactive.rs:40-55`,
   `crates/podssh-cli/tests/non_interactive.rs:143-202` and
   `crates/podssh-cli/tests/non_interactive.rs:216-226`), and take
   `ForcedInteractive` out of `missing_timeout_outside_a_terminal_is_usage_64`
   (`crates/podssh-cli/tests/non_interactive.rs:100-117`).
3. Write the module comment again (`crates/podssh-cli/src/non_interactive.rs:1-28`):
   what the module holds and why, with no `⛔` and no planning ids
   (`AGENTS.md`, section 5, rule 6).

## Decision

Recommendation: remove. podssh-ssh asks, so its `can_ask` is the gate, and its
refusals name the real remedies. The alternative, connect `gate_prompt` with
real flag names, lost: two gates for one decision can disagree, and this crate
does not hold the prompts. T-005 works on the real gate.

## Prove

```sh
cargo test -p podssh-cli
grep -rn "gate_prompt\|PromptSite\|force_interactive\|accept-new (E13)" crates; test $? -eq 1
```

The tests pass without the removed code. The search finds none of its names
(grep exits 1 when nothing matches). Plant: restore `gate_prompt`; the search
finds it, and the second line fails.

# T-233: The help of a command that is not implemented does not say so

**Source:** found by the writer of `TODO/copy.md`; measured here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh cp --help` prints seven options of `cp` and exits 0, with no sign that
`cp` is not implemented. Each command that exits 70 does the same, and so does
`ts` in a build without the `ts` feature. Only the top-level help marks them.
`docs/cli.md:35-38` says that `--help` and the manual mark such a command. A
user reads options such as `--timeout` and `-r`, and then gets exit 70.

## Premise

Measured offline: `podssh node`, `operator`, `chat` (also `irc`), `cp` (also
`scp`), `mv`, `relay`, `status` and `ts`, each with `--help`, exit 0, and the
text has no "not implemented" and no "not in this build". Controls:
`podssh --help` marks each of them (`crates/podssh-cli/src/help.rs:144`), and
the manual says "Not implemented yet. The command exits 70 and does nothing."
with no options (`crates/podssh-cli/src/man/model.rs` lines 188-200 at
`fdbba30`).

Read, at `fdbba30`: `verb_help` (`crates/podssh-cli/src/help.rs` lines
178-216) never calls `availability_note` (lines 169-175 there). The test
`a_command_that_does_not_work_says_so_in_both` checks only the top-level help
(`crates/podssh-cli/tests/man_flag_parity.rs` lines 113-124), so the gap
passes.

## Approach

1. In `verb_help`, for a verb that is not `Works`
   (`crates/podssh-cli/src/flags.rs:443-451`): the title with the note, the
   sentence of the manual, and no option but `--help`, as the manual does.
2. Keep that sentence in one place, so that `--help` and the manual
   (`crates/podssh-cli/src/man/model.rs` lines 188-200 at `fdbba30`) cannot
   differ.
3. Extend `a_command_that_does_not_work_says_so_in_both` to the help of each
   such verb.
4. `scripts/interop-man.sh:36-37` already skips these verbs (it drops each line
   with "(not "). Same commit: `docs/STATUS.md`.

## Decision

Recommendation: no options, as in the manual. The options of a command that
does nothing cannot be used. The alternative, the options with a mark, lost: a
script that reads `--help` still finds flags that do nothing.

## Prove

```sh
cargo test -p podssh-cli --test man_flag_parity -- a_command_that_does_not_work_says_so_in_both
for v in node operator chat cp mv relay status ts; do
  PODSSH_OFFLINE=1 timeout 20 target/debug/podssh "$v" --help </dev/null >/tmp/t233.out
  test $? -eq 0 && grep -q 'not implemented yet\|not in this build' /tmp/t233.out || exit 1
done
```

The extended test reads the help of each verb that does not work. The loop
checks the binary of the default build, where `ts` is not built. Plant: remove
the note from `verb_help`; the test fails on `cp`.

## Done

2026-10-08, in the commit "The help of a command that does not work says
so".

- `availability_sentence` in `crates/podssh-cli/src/help.rs` holds the one
  sentence for a command that is not implemented and for one that is not
  in this build. `verb_help` marks the title as the top-level help does,
  gives the sentence, and shows no option but `--help`; the manual takes the
  same sentence. The notes under the options of `ssh`, `cp` and `mv` moved
  to `verb_notes`, so the test of the `-P` note of `cp` still reads it.
- Prove: `cargo test -p podssh-cli --test man_flag_parity --
  a_command_that_does_not_work_says_so_in_both` passed: for each command
  that does not work, the title is marked, its help and the manual have
  the sentence, and its help has no option but `--help`. The loop over
  `node`, `operator`, `chat`, `cp`, `mv`, `relay`, `status` and `ts` with
  the default build: each exits 0 and says "not implemented yet" or "not in
  this build".
- Plant: `verb_help` without the sentence. The test failed on the first
  such command, `node` ("its help lacks the sentence"), not on `cp` as the
  Prove expected: the test reads the commands in the order of the table.

# T-234: `podssh man relay` shows the command and not the topic THE RELAY, and the list of sections names `relay` twice

**Source:** found by the writer of `TODO/transport.md` (measured there);
measured again here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

Two sections of the manual have the key `relay`: the command `relay` and the
topic THE RELAY (hosts, failover, tokens, liveness, DNS, trust and the idle
limit). `podssh man relay` shows the command, a stub of five lines, and no
name selects the topic. The list of sections that an unknown name prints has
`relay` twice, and the help of the SECTION argument offers `relay` as a topic.

## Premise

Measured offline: `podssh man relay --no-pager` exits 0 with 159 bytes: the
heading `RELAY` and "Not implemented yet. ...". `podssh man nonsense` exits
64, and its list has `relay` twice. The whole manual has the heading THE RELAY
(`podssh man --no-pager`).

Read: the key of the topic is `relay` (`crates/podssh-cli/src/man/facts.rs`
line 39 at `02e4e1f`).
The commands come before the topics (`crates/podssh-cli/src/man/model.rs:75-81`),
and `find` takes the first match (`crates/podssh-cli/src/man/model.rs:61-67`).
The SECTION help names `relay` (`crates/podssh-cli/src/positionals.rs` line
37 at `02e4e1f`).
`each_verb_and_alias_finds_its_section` passes, because the command wins
(`crates/podssh-cli/src/man/model.rs:321-330`).

## Approach

1. Give the topic a key of its own, for example `relay-facts` (the term of
   `docs/cli.md:16-17`). Keep the heading THE RELAY.
2. The section of the command `relay` names the topic in one line.
3. A new test: no two sections share a key or an alias, and each topic key
   finds its own section.
4. Change the SECTION help (`crates/podssh-cli/src/positionals.rs:37`):
   `the_section_argument_names_each_topic` requires each topic key in it
   (`crates/podssh-cli/src/man/model.rs:388-399`). Same commit: `docs/STATUS.md`.

## Decision

Recommendation: a unique key for the topic. Then a name selects one section,
and the list names each section once. The alternative, `podssh man relay`
shows both sections, lost: the list still names `relay` twice, and the name
keeps two meanings when the command exists (M4).

## Prove

```sh
cargo test -p podssh-cli --lib -- man::model
cargo test -p podssh-cli --test man_page
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh man relay-facts --no-pager </dev/null >/tmp/t234.out; test $? -eq 0 && head -1 /tmp/t234.out | grep -q 'THE RELAY'
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh man nonsense </dev/null 2>/tmp/t234.err; test $? -eq 64 && test "$(grep -cx '  relay' /tmp/t234.err)" -eq 1
```

The new test fails when two sections share a name. The binary runs select the
topic by its new key, and find `relay` once in the list. Plant: give the topic
the key `relay` again; the new test fails.

## Done

2026-10-08, in the commit "podssh man relay-facts selects THE RELAY".

- The topic THE RELAY has the key `relay-facts`, the term of
  `docs/cli.md`; `relay` selects the command. The section of the command
  points to the topic in one sentence. The help of SECTION names
  `relay-facts`.
- A new test, `each_name_selects_one_section`: no two sections share a key
  or an alias, and each topic's key finds that topic.
- Prove: `cargo test -p podssh-cli --lib -- man::model` (8 passed, with the
  new test) and `cargo test -p podssh-cli --test man_page` (8 passed).
  `podssh man relay-facts --no-pager` exits 0 and its first line is
  `THE RELAY`; `podssh man nonsense` exits 64, and its list names `relay`
  once and `relay-facts` once.
- Plant: the key `relay` again. The new test failed: "\"relay\" names two
  sections".

# T-235: The help puts `--help` at a different indent from the other options

**Source:** found by the writer of `TODO/transport.md` (measured on `relay`
and `proxy`, the source line not found there); measured here on `3ee70dc`,
and the source line found.
**Category:** defect
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

In the help of each command, `--help` starts 4 columns to the left of the
other long options, and its text starts in a column of its own. The block
reads as two tables, and a reader that parses it by column can miss `--help`.

## Premise

Measured offline, with the spaces counted: in `podssh proxy --help` and
`podssh relay --help`, 8 spaces come before each long option and 4 before
`--help`. The text of `--help` starts after 12 characters; the text of the
other rows starts at their common column. In `podssh ssh --help`, a short
option starts after 4 spaces and its long name after 8; `--help` again starts
after 4, with its text at character 13.

Read: `--help` has a line of its own, `format!("{:<12}{}", "    --help", ...)`
(`crates/podssh-cli/src/help.rs:217-221`), outside `flag_line`
(`crates/podssh-cli/src/help.rs:76-85`). `flag_column` measures only the
verb's own rows (`crates/podssh-cli/src/help.rs:33-42`).

## Approach

1. Write `HELP_FLAG` with `flag_line`, and compute `flag_column` over the
   verb's rows and `HELP_FLAG` together. Then `--help` has the indent of a
   long-only row and the common text column.
2. Keep `--help` as the last line of the block, with no blank line before it:
   `options_block` stops at the first blank line
   (`crates/podssh-cli/tests/man_extract/mod.rs:35-52`).
   `scripts/interop-man.sh:44-46` reads an option line at any indent.
3. Add `--help` to the layout test `no_flag_runs_into_its_description`
   (`crates/podssh-cli/src/help.rs:373-408`), or add a test that each
   long-only line and `--help` start in one column.
4. The block before a command (`  -h, --help`) is another table and stays as
   it is. Same commit: `docs/STATUS.md`.

## Prove

```sh
cargo test -p podssh-cli --lib -- help::tests
cargo test -p podssh-cli --test man_flag_parity
PODSSH_OFFLINE=1 timeout 20 target/debug/podssh proxy --help </dev/null >/tmp/t235.out; grep -q '^        --help ' /tmp/t235.out
```

The new layout test compares the indent and the text column of `--help` with
the other rows of each verb. The parity tests still read the same flags. The
binary check finds `--help` after 8 spaces. Plant: restore the `{:<12}` line;
the layout test fails.
