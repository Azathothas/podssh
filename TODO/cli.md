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
(`crates/podssh-cli/src/ssh/hop.rs:30-78`). The refusal is `check_host`
(`crates/podssh-ws/src/names.rs:8-24`, re-exported by `podssh_relay::relay`), called at
`crates/podssh-cli/src/ssh/resolve.rs:354`, `crates/podssh-cli/src/proxy.rs:211`
and in `forward_path` (`crates/podssh-relay/src/relay.rs:163-176`); since this
entry, each calls `check_target` there. Tests assert the refusal:
`crates/podssh-relay/src/relay.rs:297`, and `crates/podssh-cli/tests/proxy.rs`
(lines 49-50 at `eaf9822`).

Not known: how `/connect/<host>/<port>` takes a literal. The contract does not
say, and says "numeric hosts must be a strict dotted quad"
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:231`). Read in
GitHub #2, not verified here: the relay's `/trace` dials `[V6]:8079`.

## Approach

1. Measure first: an ignored live test in `crates/podssh-relay/tests/live.rs`,
   built like `open_github` (`crates/podssh-relay/tests/live.rs:15-31`), so the
   token stays in the process. It opens one public IPv6 target, chosen with
   `/trace`, by three paths: the bare literal, `%5B` and `%5D`, raw brackets.
   Give `/trace` its token in a header file, never on argv (`AGENTS.md`,
   section 4). Write the answers in `docs/relay.md`.
2. A target check beside `check_host`: a name that `check_host` accepts, or
   text that `std::net::Ipv6Addr` parses. A zone id does not parse, so the rule
   of `crates/podssh-relay/src/relay.rs:163-169` holds. Keep `check_host` for
   relay hosts, which are TLS names (`crates/podssh-relay/src/relay.rs:148-161`,
   `crates/podssh-relay/src/pool.rs:147`).
3. `forward_path` writes the literal in the measured form. `podssh ssh` uses
   the new check at `crates/podssh-cli/src/ssh/resolve.rs:354`, and refuses
   `-4` with an IPv6 literal (64).
4. `podssh proxy` (`crates/podssh-cli/src/proxy.rs:203-213`): `HOST PORT` takes
   a bare literal (the `%h %p` form) or `[V6]`. One word takes `[V6]:PORT` and
   refuses `V6:PORT`: `2001:db8::1:22` is itself an address. Reuse the rule of
   `split_host_port` (`crates/podssh-ws/src/dial.rs:447-466`).
5. Messages use `podssh_ws::dial::authority` (`crates/podssh-ws/src/dial.rs:427-434`),
   not `host:port` (`crates/podssh-cli/src/ssh/transport.rs:165`,
   `crates/podssh-cli/src/proxy.rs:131`, where it is used since this entry). `known_hosts` keeps the literal as
   typed: `host_name` writes `[V6]:PORT` as OpenSSH does
   (`crates/podssh-ssh/src/known_hosts.rs:89-96`).
6. Same commit: `docs/cli.md` (lines 62-75 at `3cbf215`), the help at
   `crates/podssh-cli/src/positionals.rs:20` and
   `crates/podssh-cli/src/positionals.rs:189`, an example in
   `crates/podssh-cli/src/man/examples.rs:8-215`, `docs/relay.md`,
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
(`crates/podssh-cli/src/dispatch.rs:288-296`). `require_timeout` writes the
fixed text and has no verb to name (`crates/podssh-cli/src/non_interactive.rs` lines 194-201 at `37ace00`).
`podssh ts` uses the same function (`crates/podssh-cli/src/ts.rs:54-63`), so a
build with the `ts` feature shows the chat example for `ts` too (read, not
measured: the debug binary has no `ts`).

## Approach

1. In the `Parsed::Command` arm, refuse a verb of `VERB_OWNER`
   (`crates/podssh-cli/src/flags.rs`, line 453 at `7aa955a`) before the gate. Keep one usage
   error first: a `--timeout` value that was given and does not parse is 64
   (`docs/cli.md:2463-2464`).
2. Give `require_timeout` the verb's name. The message names that verb, gives
   one true reason, and shows an example for that verb only. Replace
   `({attachment:?})` with words: "stdin or stdout is not a terminal", or
   "--jsonl was given".
3. Pass `"ts"` from `crates/podssh-cli/src/ts.rs:54-63`.
4. Change the tests that use `chat` for the gate
   (`crates/podssh-cli/src/dispatch.rs`, lines 424-477 at `7aa955a`,
   `crates/podssh-cli/tests/non_interactive.rs` lines 252-284 at `37ace00`). `ts` is the only verb
   that runs the gate today (`crates/podssh-cli/tests/ts_behave.rs:220-226`).
5. Same commit: `docs/STATUS.md`. `docs/cli.md:2506` needs no change.

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
flag-shaped (`crates/podssh-cli/src/clap_error.rs:111-113`), so the arm calls
`unknown_flag` (`crates/podssh-cli/src/refuse.rs:28-44`).

## Approach

1. In `rebuild_error` (`crates/podssh-cli/src/clap_error.rs:33-90`), before
   the `_` arm, read `InvalidValue` with an empty value as a missing value.
2. Find the row: take the long name between `--` and the first space of
   `InvalidArg`, and look it up in the verb's rows (`crate::flags::verb_for`).
3. Add `refuse::missing_value`: `podssh ssh: -p (--port) needs a value: PORT.`,
   then `Run 'podssh ssh --help'`. Exit 64. clap gives the long spelling also
   when the user typed `-p`, so print both spellings.
4. A `Refused` row with no value gets its own refusal: a value would not change
   the answer. Move the refusal text of `refusals`
   (`crates/podssh-cli/src/dispatch.rs:306-314`) to `refuse.rs`, so the two
   cannot differ.
5. A long name with no row keeps today's message, as a fallback.
6. Same commit: `docs/cli.md:56-60` (a flag with no value names the flag and
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
not exist, against "No option is dropped silently" (`docs/cli.md:56-60`).
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
(`crates/podssh-cli/src/tree.rs:234-243`), so an unknown word is refused there.

## Approach

1. At `crates/podssh-cli/src/tree.rs:140-152`: `-h` or `--help` alone is
   `Parsed::Help("")`. With one more word that names a verb
   (`crate::flags::verb_for`), it is `Parsed::Help` of that verb, as
   `podssh VERB --help` is. Any other word is `Parsed::Usage`:
   `unknown_flag` for a flag-shaped word
   (`crates/podssh-cli/src/refuse.rs:28-44`), else a message that names it.
2. `-V` or `--version` with any other word is `Parsed::Usage` (exit 64).
3. Keep the verb level as it is: `podssh ssh --help host` prints the help of
   `ssh`, after clap has checked each word.
4. If the top-level help text changes (`TOP_OPTIONS`,
   `crates/podssh-cli/src/flags.rs:464-467`), update its test
   `no_top_level_option_runs_into_its_description`
   (`crates/podssh-cli/src/help.rs:342-357`). Same commit: `docs/cli.md:56-60`,
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
  (`crates/podssh-cli/src/ssh/hop.rs:74-76`); `ssh --relay-host=-x host`,
  `proxy -- -oX 22`, `proxy - 22` (`crates/podssh-ws/src/names.rs:17-19`).
  `ssh -- host -x` runs the command `-x`: `--` ends the options.
- `ssh --direct -oHostName=-x host true` reaches the offline stop: `HostName`
  replaces the host (`crates/podssh-cli/src/ssh/resolve.rs` line 92 at `4bceef6`) with no check.
- OpenSSH 10.3p1 (`ssh -G -F none`, offline) refuses `-- -oProxyCommand=x` and
  `-J -x host` (255), so it never gives such a `%h` to `podssh proxy`.

Read, at `61e55d1`: no option made podssh start a program: `ProxyCommand` is refused and
`LocalCommand` was ignored (`crates/podssh-cli/src/ssh/keywords.rs` lines 93-103; T-191 runs it with
`PermitLocalCommand yes`, as OpenSSH does). The risk is a changed option (a host, a relay, a trust store), not a command.

## Approach

1. Document `--`: `usage_tail` (`crates/podssh-cli/src/help.rs:268-290`) gives
   `[OPTIONS] [--] [user@]host [COMMAND...]` for `ssh` and
   `[OPTIONS] [--] HOST PORT` for `proxy`; `--help` and the synopsis of the
   manual (`crates/podssh-cli/src/man/model.rs:186-190`) read it.
2. A note for `ssh` and `proxy` (`crates/podssh-cli/src/man/notes_ssh.rs:4-292` and `crates/podssh-cli/src/man/notes.rs:58-169`)
   and an example (`crates/podssh-cli/src/man/examples.rs:8-215`). Pitfall: the
   notes test reads a bare `--` as a flag that does not exist
   (`crates/podssh-cli/src/man/notes.rs:393-401`); teach `flag_exists`
   (`crates/podssh-cli/src/man/notes.rs:360-376`) that `--` ends the options.
3. `podssh proxy` (`crates/podssh-cli/src/proxy.rs:203-208`): when HOST or PORT
   is missing and a relay or trust flag was given, add one line: a HOST that
   starts with `-` is read as a flag; put `--` before it.
4. Check `HostName` with the rule of the destination: one function for the
   checks at `crates/podssh-cli/src/ssh/hop.rs:71-76`, also called at
   `crates/podssh-cli/src/ssh/resolve.rs:214-221`.
5. Same commit: `docs/cli.md` (lines 62-75 at `3cbf215`; the `--` rule, and a host that starts
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
**Status:** done

## Problem

With no terminal, each verb with a `--timeout` row needs the flag on each
call. An agent that runs many commands cannot set the limit once. GitHub #12
asks for `PODSSH_TIMEOUT` as the default, with the flag first.

## Premise

Measured offline: `PODSSH_TIMEOUT=5s podssh mv` and
`PODSSH_TIMEOUT=5s podssh chat --send '#c hi'` still exit 64 with the
`--timeout` refusal. No file of `crates/` or `docs/` names the variable.

Read: the `--timeout` rows are those of `cp` and `mv`
(`crates/podssh-cli/src/flags/copy.rs:47-48`), `chat`
(`crates/podssh-cli/src/flags.rs`, lines 274-275 at `7aa955a`), `ts`
(`crates/podssh-cli/src/flags.rs:353-354`) and `relay`
(`crates/podssh-cli/src/flags.rs` lines 317-318 at `af0a163`). Each but `ts` exits 70
(`crates/podssh-cli/src/flags.rs` lines 436-443 at `af0a163`), and `ts` needs its feature. So the
variable matters when `cp`, `mv` and `relay` exist. `ssh` and `proxy` have no
`--timeout`.

## Approach

1. One reader in `crates/podssh-cli/src/non_interactive.rs`, with the variable
   lookup passed in, as `proxy_from_vars` does
   (`crates/podssh-ws/src/dial.rs:107-121`): the flag, else a `PODSSH_TIMEOUT`
   that is not empty, else nothing. It returns the text and its source.
2. Call it at both gate sites: `crates/podssh-cli/src/dispatch.rs:249-267` and
   `crates/podssh-cli/src/ts.rs:54-63`. Parse with `parse_timeout`
   (`crates/podssh-cli/src/non_interactive.rs:123-169`): a whole duration,
   never zero.
3. A malformed value names its source: `--timeout` (exit 64), or
   `PODSSH_TIMEOUT` (exit 78, see Decision). The variable never bounds `ssh`
   or `proxy`.
4. Same commit: a row in `VARIABLES` (`crates/podssh-cli/src/man/facts.rs:45-260`),
   which `each_variable_in_the_source_is_documented` requires
   (`crates/podssh-cli/src/man/facts/tests.rs:57-70`); "default: env
   PODSSH_TIMEOUT" in the help of each `--timeout` row, as `--relay-host` says
   it (`crates/podssh-cli/src/flags.rs:171-172`); `docs/cli.md:2582-2584`;
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
file (77, as `crates/podssh-cli/tests/ts_behave.rs:56-64`); without it, 64.
Plant: drop the variable from the reader; the third test gets 64.

## Correction

2026-10-09: the note in the Decision is out of date. Since T-231, a bad
`PODSSH_RELAY` exits 78 too, by the same rule as this entry.

## Done

2026-10-09, in the commit "PODSSH_TIMEOUT gives the default of --timeout".

- `crates/podssh-cli/src/non_interactive.rs`: `timeout_text` reads the
  flag, else a `PODSSH_TIMEOUT` that is not empty, with the lookup passed
  in; `require_timeout_or_env` gives a bad value of the variable `Config`
  (78) and a message that names it, and leaves the flag's rules as they
  were. `parse_duration` names the setting in its refusal. Both gate sites
  use it (`dispatch.rs` and `ts.rs`); a command that is not implemented
  still exits 70 before the gate (T-008).
- The help of each `--timeout` row says "default: env PODSSH_TIMEOUT"; the
  variable has a row in ENVIRONMENT; `docs/cli.md` gives the rule.
- Prove: `cargo test -p podssh-cli --test non_interactive -- podssh_timeout`
  passed (the flag wins, the variable is used, an empty value is no value,
  `30x` from the variable is 78 and names it, `30x` from the flag is 64);
  `cargo test -p podssh-cli --lib -- man::facts` passed (the variable is in
  the source and in ENVIRONMENT). The `ts` test ran in the container (a `ts`
  build): with `PODSSH_TIMEOUT=30s`, `podssh ts` passed the gate and
  stopped at the missing key file (77); without it, 64; with `30x`, 78.
- Plant, in the container: the reader looked up another name; the `ts`
  test got 64 for 77.

# T-013: The help groups the commands by purpose

**Source:** GitHub #23 (the cubic-vm/cubic report, item 10: "Consistent
success feedback + command grouping help", cubic issues 451 and 548); read in
the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

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

Read, at `3a78cff`: one table, `VERBS` (`crates/podssh-cli/src/flags.rs:347-408`), has no
group. Four places render it: `top_level_help`
(`crates/podssh-cli/src/help.rs`, lines 132-146), the start of the manual
(`crates/podssh-cli/src/man/model.rs`, lines 120-126), `unknown_verb`
(`crates/podssh-cli/src/refuse.rs:120-124`) and `no_arguments`
(`crates/podssh-cli/src/refuse.rs:149-160`).

## Approach

1. Add the group to the table in `crates/podssh-cli/src/flags.rs`: a field of
   `Verb` (`crates/podssh-cli/src/flags.rs:334-345`), or one list of groups. A
   new test in `crates/podssh-cli/tests/flag_table.rs` asserts that each verb
   is in exactly one group, as `every_verb_has_an_owner_so_no_verb_can_be_a_silent_stub`
   does for owners (`crates/podssh-cli/tests/flag_table.rs:104`).
2. Render the groups in `--help` and in the manual's "Commands" table. Keep
   the availability note of each line (`crates/podssh-cli/src/help.rs:191-198`).
3. Keep the two refusal lists flat, or raise their limit with a reason:
   `a_refusal_is_a_line_not_a_usage_dump` allows 18 lines
   (`crates/podssh-cli/src/refuse.rs:237-238`), and the list for
   `example.org` has 17.
4. Update `scripts/interop-man.sh` (lines 35-36 at `3a78cff`) in the same commit. It reads the
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

Taken, with these calls made in the work (2026-10-11). One list of groups, `GROUPS` in
`crates/podssh-cli/src/flags.rs`, beside `VERBS`, so that a test can find a verb listed twice,
which a field of `Verb` could not be. Eighteen commands are in eight groups: Connect (ssh,
proxy, pipe, ts), Copy files (cp, mv, scp, sftp), Keys (keygen, agent), Check this host and the
path (doctor, status, ping), The reverse road (node, operator), Messages (chat), The relay
(relay) and This manual (man). `--help` prints each group's name two spaces in, and its verbs four
spaces in, with no blank line, so the block still ends at the end of the list; the manual's
"Commands" has each group's name, then its table. The two refusals keep their flat lists.
`scripts/interop-man.sh` takes as a verb each line of the block with four spaces before a
letter, where it took the first word of each line: a group's name of two words is no verb.

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

## Correction

Measured at `3a78cff`: `podssh --help` lists 18 commands (ssh, proxy, pipe, node, operator, chat,
cp, scp, sftp, mv, man, relay, status, doctor, keygen, ts, agent, ping), and none says "(not
implemented yet)"; only `ts` says "(not in this build)" in a build without the feature. The
problem of one long list stands; the mix of working and missing commands is gone.

## Done

2026-10-11. `GROUPS` in `crates/podssh-cli/src/flags.rs:410-427`; `--help`
(`crates/podssh-cli/src/help.rs:157-184`) and the manual's "Commands"
(`crates/podssh-cli/src/man/model.rs:120-131`) print the commands in their groups.
- `cargo test -p podssh-cli --test flag_table -- each_verb_is_in_one_group`: 1 passed. Planted:
  `ssh` also in "Copy files"; the test failed.
- `cargo test -p podssh-cli`: 538 passed, 0 failed, 31 ignored (the help, the refusals, the
  manual and the parity of the flags among them); clippy. `scripts/interop-man.sh`'s new reading
  of the block gave the same 17 verbs (all but `ts`, not in this build); the gate runs it with its
  planted page at this push.

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
   must fail (`scripts/interop-man.sh:114-125`).
3. `docs/cli.md:28-32` states the rule.

## Prove

```sh
cargo test -p podssh-cli --lib -- man::roff
cargo test -p podssh-cli --test man_page -- a_real_renderer_shows_each_flag_name
sh scripts/dev.sh check
```

The first checks the requests (`crates/podssh-cli/src/man/roff.rs:157`) and
the `.TP` term of each flag (`crates/podssh-cli/src/man/roff.rs:183`). The
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
   by name with what to use instead (`crates/podssh-cli/src/flags.rs:252-281`).
   `-k` is supported and `-g` is accepted with no effect
   (`crates/podssh-cli/src/flags.rs`, lines 205-209 at `97146aa`).
2. A refusal with nothing to use instead says "Leave it out."
   (`crates/podssh-cli/src/dispatch.rs:306-314`), and `--help` shows
   "(refused)" (`crates/podssh-cli/src/help.rs:121-124`).
3. A test holds the reviewed set (`crates/podssh-cli/tests/flag_table.rs:15-30`).
   `docs/cli.md:414-418` states the rule.

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
   `crates/podssh-cli/src/tree.rs:68-78`).
2. `SshArgs::from_matches` picks the value as OpenSSH does: the first `-p` and
   `-l`, the last `-e`, `-E` and `-F`, and the first value of each `-o`
   keyword (`crates/podssh-cli/src/ssh/args.rs:170-286`).
3. `ONCE` and `repeated` refuse a second `-J`, `-W`, `--relay-host`,
   `--relay-addr` or `--ca-file` with exit 64 before anything connects
   (`crates/podssh-cli/src/ssh/args.rs:126-165`, called at
   `crates/podssh-cli/src/tree.rs:463-467`).
4. `docs/cli.md:408-413` and a note of the manual
   (`crates/podssh-cli/src/man/notes_ssh.rs:265-267`) state the rule.

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
**Status:** done

## Problem

A host with no working `ssh-keygen` cannot change the passphrase or the
comment of a key: the `ssh-keygen` of OpenSSH does not run without a user
database entry (`docs/cli.md:1515-1516`). `podssh keygen -p` and `-c` exit 64
with "unknown flag", not a refusal by name. podssh's own message for a PEM key
names `ssh-keygen -p -f FILE` as the remedy
(`crates/podssh-ssh/src/keygen.rs`, lines 163-166 at `bdbe658`), a program that may not run there.

## Premise

Measured offline: `podssh keygen -p -f k`, `-c -f k` and `-P old -f k` exit 64
with `unknown flag`. The usage of OpenSSH 10.3p1 (`ssh-keygen -?`, offline):
`-p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase] [-P old_passphrase] [-Z cipher]`
and `-c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]`.

Read: `KEYGEN_FLAGS` has generation, `-y` and `-l`
(`crates/podssh-cli/src/flags/keygen.rs:8-71`). The parts exist: decryption with a
prompt (`crates/podssh-cli/src/keygen.rs`, lines 342-373 at `8290fe1`), a new passphrase asked
twice (`crates/podssh-cli/src/keygen.rs:380-399`), encryption as OpenSSH does
it (`crates/podssh-ssh/src/keygen.rs:90-103`), and the refusal of a passphrase
on argv (`crates/podssh-cli/src/keygen.rs:129-136`).

## Approach

1. Rows in `KEYGEN_FLAGS`: `-p`, `-c` and `-P PHRASE`. `-P` follows `-N`: only
   `-P ''` is accepted; another value is refused (64) and not kept
   (`NewPassphrase`, `crates/podssh-cli/src/keygen.rs:27-35`).
2. Read the key with each format that `podssh ssh -i` reads:
   `russh::keys::decode_secret_key`, the reader behind `load_secret_key`
   (`crates/podssh-ssh/src/keys.rs`, line 231 at `fe19445`). Ask for the old passphrase on the
   terminal or through `SSH_ASKPASS`, as `-y` does. With neither, refuse at
   once and name `-P ''` and `-N ''` (as `crates/podssh-cli/src/keygen.rs:382-386`).
3. `-p`: ask for the new passphrase twice (or take `-N ''`), and encrypt with
   `keygen::protect`. `-c`: take `-C` or ask; refuse a control character, as
   `crates/podssh-cli/src/keygen.rs:289-292` does. Write the OpenSSH format.
4. A new invariant beside "never over an existing file" (`docs/cli.md:1517`):
   write a new file in the same directory (`create_new`, mode 0600), read it
   back, decrypt it with the new passphrase, compare its public key with the
   original, then rename it over the original. Never write a different key
   over the file. For `-c`, write `FILE.pub` again.
5. Same commit: the PEM message at `crates/podssh-ssh/src/keygen.rs` (lines 184-187 at `8290fe1`)
   names `podssh keygen -p`; `docs/cli.md:1511-1614`, the notes of `keygen`
   (`crates/podssh-cli/src/man/notes_keygen.rs:4-50`), `docs/STATUS.md`.

## Decision

Recommendation: keep no copy of the old file. A copy keeps the key under the
old passphrase, or with none, which the user wanted to change. The
alternative, a `FILE.old` as `ssh-keygen -R` keeps for `known_hosts`, lost for
that reason. For a key in another format, write the OpenSSH format, as
`ssh-keygen -p` does; to keep PEM needs the writers of T-022.

Taken, with these calls made in the work (2026-10-11). The questions and the lines printed are
those of `ssh-keygen`: "Enter old passphrase: ", "Enter new passphrase (empty for no
passphrase): ", "Enter same passphrase again: " and "Enter new comment: "; `-p` prints "Your
identification has been saved with the new passphrase.", and `-c` "Old comment: OLD" and
"Comment 'NEW' applied". `-p` with `-c`, either of them with `-y` or `-l`, and `-c` with `-N` are
refused (64), and each needs `-f FILE`. The new file is `.NAME.podssh-new-PID` beside the key,
made by `podssh_relay::cache::create_new_private` (mode 0600; on Windows an access list of its
own, T-274). The work found that ssh-key's `encrypt` drops the comment from the public half of a
key, so the `FILE.pub` of each key made with a passphrase had no comment: `keygen::protect` keeps
it now, for `-c` and for a new key.

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

## Done

2026-10-11. `podssh keygen -p` and `-c` in `crates/podssh-cli/src/keygen_change.rs:21-88`, their
flags at `crates/podssh-cli/src/flags/keygen.rs:21-26` and their refusals at
`crates/podssh-cli/src/keygen.rs:137-144` and `:245-264`; `keygen::protect` keeps the comment
(`crates/podssh-ssh/src/keygen.rs:90-103`).
- `cargo test -p podssh-cli --test keygen -- change`: 3 passed; `cargo test -p podssh-cli --lib --
  keygen_change`: 1 passed; `cargo test -p podssh-ssh --lib -- keygen`: 5 passed. Planted, each
  restored: a fresh key written over the file with the compare skipped (the Prove's plant) failed
  `change_passphrase_keeps_the_key` ("the key changed"); `same_key` taking each key failed
  `only_the_same_key_replaces_the_file`; `protect` without the comment failed
  `change_comment_in_the_key_and_in_its_public_file`.
- Against the `ssh-keygen` of OpenSSH for Windows 10.0p2: after `-p`, `ssh-keygen -y -P NEW`
  printed the same key, and the old passphrase exited 255; after `-c`, `ssh-keygen -y` and
  `FILE.pub` gave the new comment; after `-p` to no passphrase, `-P ''` opened the key. Keys that
  `ssh-keygen -m PEM` and `-m PKCS8` made (RSA, also encrypted, and ECDSA) and the plain PuTTY
  keys of ssh-key 0.7.0-rc.11's tests became keys of OpenSSH with the same public key. Encrypted
  keys of PKCS#8 and of PuTTY were refused before any question, and an encrypted ECDSA key in PEM
  was "incorrect passphrase" with its passphrase; `podssh ssh -i` reads them the same way (T-287).
  A key that `podssh keygen` made on Windows took the access list of its directory, and OpenSSH
  refused it (T-288).
- `scripts/interop-keygen.sh` has seven new checks, `keygen.change.*` (the floor of keygen is 35):
  OpenSSH opens the key with the new passphrase and not with the old one, the mode stays 600,
  sshd accepts the key, and OpenSSH reads the new comment, which `FILE.pub` has too. The gate runs
  them at this push.
- `cargo test -p podssh-cli`: 542 passed, 0 failed, 31 ignored; `cargo test -p podssh-ssh`: 112
  passed; clippy.

# T-019: `podssh keygen -F`, `-R` and `-H`: find, remove and hash `known_hosts` entries

**Source:** the lablup/bssh report in GitHub #18, #20 and #22, item 5
(`lablup/bssh:src/bin/bssh_keygen.rs`); read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

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
(`crates/podssh-ssh/src/known_hosts.rs:274-308`), finds the lines of a host
with their numbers (`scan`, `crates/podssh-ssh/src/known_hosts.rs:149-179`), and
appends without a rewrite (`crates/podssh-ssh/src/known_hosts.rs`, lines 323-372 at `f6b7676`).
The default files are the ones of `podssh ssh`
(`crates/podssh-cli/src/man/data.rs:163`).

## Approach

1. Rows in `KEYGEN_FLAGS` (`crates/podssh-cli/src/flags/keygen.rs:8-71`):
   `-F HOST`, `-R HOST` and `-H`. `-f FILE` selects the file; else the first
   user `known_hosts` file. Accept `[host]:port`, as `host_name` writes it
   (`crates/podssh-ssh/src/known_hosts.rs:89-96`).
2. `-F`: reuse `entries_for`, and print the lines of OpenSSH; exit 1 when no
   line matches.
3. `-R` and `-H`: one rewrite: a new file in the same directory (`create_new`,
   mode 0600) that keeps each line it does not change byte for byte
   (comments, unknown markers, lines that do not parse), `FILE.old`, then a
   rename. A line with a wildcard or a negated pattern cannot be hashed: keep
   it, and say so.
4. `-H`: a random salt of 20 bytes and the HMAC-SHA1 of `hashed_matches`, so
   podssh and OpenSSH both find the result.
5. Same commit: `docs/cli.md:1511-1614`, the notes of `keygen`, `docs/STATUS.md`.

Pitfall: a rewrite can lose a key that `podssh ssh` appends at the same moment
(T-029). Read the file again just before the rename, and refuse if it changed.

## Decision

Taken, with these calls made in the work (2026-10-11), after a measure of the
`ssh-keygen` of OpenSSH for Windows 10.0p2 on a file of each kind of line. The
lines, the messages and the exit codes are that `ssh-keygen`'s: `-F` prints
`# Host HOST found: line N` and a space, then `CA`, `REVOKED` or nothing, then
the line; `-q` the lines alone; `-H` with `-F` each name hashed; exit 1 when no
line names the host. `-R` prints `# Host HOST found: line N` for each line
removed (not with `-q`), then `FILE updated.` and `Original contents retained as
FILE.old`, and keeps `@revoked` and `@cert-authority` lines; a missing host is
`Host HOST not found in FILE` on stderr, exit 0. `-H` writes each name of a line
on a line of its own, hashed in lower case, keeps a marked line, a hashed name
and a wildcard line (with OpenSSH's warning), and warns that `FILE.old` holds the
names. Three calls differ, to lose nothing: `-R` keeps a line that names the
host through a wildcard, whose key is for other hosts too, and says so (OpenSSH
removes it); a line that is no line of a host key is kept as it is (OpenSSH
refuses to rewrite the file); and `-H` with no name to hash leaves the file as
it is. A missing file exits 1, podssh's code for a failure (OpenSSH 255). For
the pitfall: the rewrite holds the lock of `append` from its read to its
rename, and `append`, once it holds the lock, looks again at which file the path
names, and opens it again when another took its place; the plant of an `append`
that writes to the file it locked lost its line. A symbolic link stays, and its
target is rewritten. `FILE.old` and the new file are made by
`podssh_relay::cache::create_new_private`.

## Prove

```sh
cargo test -p podssh-ssh --lib -- known_hosts
cargo test -p podssh-cli --test keygen_known_hosts
sh scripts/dev.sh check
```

Unit tests: the rewrite keeps the other lines byte for byte, and `matches`
finds a line that `-H` wrote. New checks in `scripts/interop-keygen.sh`:
OpenSSH's `ssh-keygen -F` finds each host in a file that `podssh keygen -H`
hashed, and `podssh keygen -F` finds each host that `ssh-keygen -H` hashed.
Plant: drop the comment lines in the rewrite; the byte test fails.

## Done

2026-10-11. `find`, `remove`, `hash` and `rewrite` in
`crates/podssh-ssh/src/known_hosts/edit.rs:89-288`, on the bytes of the file;
`append` opens the file again when a rewrite took its place
(`crates/podssh-ssh/src/known_hosts.rs:342-410`); the flags at
`crates/podssh-cli/src/flags/keygen.rs:35-40`, and the command in
`crates/podssh-cli/src/keygen_hosts.rs:23-180`.
- `cargo test -p podssh-ssh --lib -- known_hosts`: 8 passed on Windows (9 in the build image, with
  the link): the lines found are those that `ssh-keygen -F` printed; `-R` keeps every other line
  byte for byte (a comment, a blank line, a CRLF line, spacing, a line that is not UTF-8, the
  marked lines, a last line with no line end); `-H` hashes each name and podssh's lookup finds it;
  the hash of "Two.Example" equals the one that OpenSSH's `-H` wrote; a rewrite keeps `FILE.old`;
  a run of `append` that waited for the lock during a rewrite wrote its line to the new file.
  Planted, each restored: the comment lines dropped (the Prove's plant) failed the byte test; an
  `append` that writes to the file it locked failed the test of the wait ("the line went to the
  file replaced"); a name hashed as typed failed the test of OpenSSH's hash and the lookup of
  "Indented.Example".
- `cargo test -p podssh-cli --test keygen_known_hosts`: 4 passed.
- Beside the `ssh-keygen` of OpenSSH for Windows 10.0p2, on copies of one file (2026-10-11): 21 of
  22 commands (`-F` of 11 hosts, `-q -F`, `-F -H` of a wildcard line, `-R` of 7 hosts, `-q -R`
  and `-H`) printed the same lines on stdout and stderr and exited the same; after each `-R`, the
  file and `FILE.old` were equal byte for byte, and after `-H` the lines not hashed were the same.
  The 22nd is the call above: `-R x.wild.example` kept `*.wild.example`.
- `scripts/interop-keygen.sh` has six new checks, `keygen.known_hosts.*` (the floor of keygen is
  47): against OpenSSH in the box, `-F` prints the lines and codes of `ssh-keygen -F`, each tool
  finds the hosts that the other hashed, and `-R` leaves the file and `FILE.old` of
  `ssh-keygen -R`. The gate runs them at this push.
- `cargo test -p podssh-ssh`: 126 passed; `cargo test -p podssh-cli`: 548 passed, 0 failed, 31
  ignored; clippy; rustfmt. In the build image: the tests of `known_hosts`, `keygen` and
  `ssh_host_keys` passed.

# T-020: `podssh keygen -Y`: SSH signatures

**Source:** the lablup/bssh report in GitHub #18, #20 and #22, item 5
(`lablup/bssh:src/bin/bssh_keygen.rs`); read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

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
that crate as `russh::keys::ssh_key` (`crates/podssh-ssh/src/keygen.rs:11-13`).

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
   matcher of `known_hosts` (`crates/podssh-ssh/src/known_hosts.rs:311-333`).
   Print the lines and the exit codes of OpenSSH.
4. Refuse `-r` (a key revocation list) by name until podssh reads one.
5. Same commit: `docs/cli.md:1511-1614`, the notes of `keygen`, `docs/STATUS.md`.

Pitfalls: read the signed file as bytes, never as text. A namespace that does
not match is a failure, never a warning.

## Decision

Taken, with these calls made in the work (2026-10-11), after a measure of the
`ssh-keygen -Y` of OpenSSH for Windows 10.0p2. The lines, the messages and their
streams are OpenSSH's: `sign` says `Signing file F` and `Write signature to
F.sig` on stderr (not with `-q`), or `Signing data on standard input`; `verify`
says `Good "NS" signature for P with TYPE key SHA256:...` (with `-O
print-pubkey`, the key's line too), else `Could not verify signature.` on stdout
and why on stderr: `Couldn't verify signature: namespace does not match`,
`Signature verification failed: incorrect signature`, `FILE:N: key is not
permitted for use in signature namespace "NS"` or `FILE:N: key has expired:
verify time T > valid-before T` (in local time), and nothing for a principal
that no line names; `find-principals` prints each principal of each line that
allows the key in the signature's namespace and at the time, and passes over a
refused line in silence; `match-principals` prints the principals of each line
that names `-I`; else `No principal matched.`. The calls of podssh's: a failure
exits 1 (OpenSSH 255), and a usage error 64; an existing `FILE.sig` is never
written over (OpenSSH asks), and the message names it; without `-U` the agent
signs when it holds the key of `-f`, as OpenSSH does, else the private key of
`-f`, read in each format of T-287, its passphrase asked; with `-U`, the agent
alone. The data is hashed as it is read. A signature made with a certificate,
and the `cert-authority` lines that would allow it, wait for T-289: ssh-key reads
the key of a signature as a plain key, and such a signature is named, never
misread. The flags: `-Y OP`, `-n NAMESPACE`, `-s FILE`, `-I PRINCIPAL`, `-O
OPTION` (each kept), `-U`, and `-r` refused by name; a positional `FILE` for
`sign`. The help of `-n`, `-s` and `-I` names their use with `-Y`; T-021 adds
their use with a CA.

## Prove

```sh
cargo test -p podssh-cli --test keygen_sign
sh scripts/dev.sh check
```

New checks in `scripts/interop-keygen.sh`: OpenSSH's `ssh-keygen -Y verify`
accepts each podssh signature (Ed25519, ECDSA and RSA), `podssh keygen -Y
verify` accepts each OpenSSH signature, and both refuse a changed file and a
wrong namespace. Plant: sign with the namespace `file` whatever `-n` says;
OpenSSH's verify with `-n git` then fails.

## Done

2026-10-11. Signatures and allowed signers in `crates/podssh-ssh/src/sshsig.rs:1-364`; an RSA key
signs through `RsaSigner::sign_sha512` (`crates/podssh-ssh/src/rsa_key.rs:62-69`), and the keys of
the agent come from `agent_keys` (`crates/podssh-ssh/src/keys.rs:384-390`). The command is
`crates/podssh-cli/src/keygen_sign.rs:1-478`, its flags at `crates/podssh-cli/src/flags/keygen.rs:41-52` and `:69-70`.
- `cargo test -p podssh-ssh --lib -- sshsig`: 6 passed: the signatures of OpenSSH's (Ed25519 in
  `git`; RSA in `file` with SHA-256) verify, and refuse another namespace and changed data with
  OpenSSH's words; each kind of key signs with each hash, an RSA key with `rsa-sha2-512`; the lines
  of allowed signers parse as ssh-keygen(1) reads them; times are local unless they end in Z;
  principals match with their case and negation; a line refuses with OpenSSH's words.
- `cargo test -p podssh-cli --test keygen_sign`: 4 passed; `--test agent_cli`: 4 passed, among them
  `-Y sign -U` with the key that `podssh agent` held, then its refusal once the agent forgot it.
  Planted, each restored: the namespace `file` whatever `-n` said (the Prove's plant) failed the
  test of the CLI ("namespace does not match"); a line's namespaces passed over, and an RSA
  signature named `rsa-sha2-256`, each failed a unit test.
- Beside the `ssh-keygen` of OpenSSH for Windows 10.0p2 (2026-10-11): each verified the other's
  signatures of an Ed25519, an ECDSA and an RSA key, and refused changed data and another
  namespace; 19 of 19 commands of `verify`, `check-novalidate`, `find-principals` and
  `match-principals` printed the same lines on stdout and stderr, and failed alike.
- `scripts/interop-keygen.sh` has twelve new checks, `keygen.sign.*` (the floor of keygen is 59):
  for each kind of key, each tool verifies the other's signature, and both refuse changed data and
  another namespace. The gate runs them at this push.
- `cargo test -p podssh-ssh`: 132 passed; `cargo test -p podssh-cli`: 553 passed, 0 failed, 31
  ignored; clippy; rustfmt. In the build image: the tests of `sshsig`, `keygen_sign`, `agent_cli`
  and `keygen` passed.
- At `b37abb3` the job `windows` of CI failed: its checkout, with CRLF, gave the signed test data a
  CR, and the check of OpenSSH's signature over it failed. `6078e57` keeps the bytes of the test
  data of signatures and certificates (`.gitattributes`): a checkout with `core.autocrlf=true` gave
  `hello, signed\r\n` before, and keeps the signed bytes after.

# T-021: `podssh keygen -s`: user and host certificates

**Source:** the lablup/bssh report in GitHub #18, #20 and #22, item 5
(`lablup/bssh:src/bin/bssh_keygen.rs`); read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

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
(`crates/podssh-cli/src/ssh/keywords.rs:90`), and it checks host certificates
as plain keys (`docs/STATUS.md`, section "Components"). T-027 covers that side.

## Approach

1. Rows: `-s CA`, `-I ID`, `-n PRINCIPALS`, `-V INTERVAL`, `-z SERIAL`,
   `-O OPTION` (repeatable), `-h` (a host certificate) and `-L`. `-h` is free:
   a verb declares only `--help` (`crates/podssh-cli/src/tree.rs:89-98`). `-V`
   is a validity here, not the version: say so in `--help`, as the help says
   it for `-P` (`crates/podssh-cli/src/help.rs:243-261`).
2. Read the CA key as `-y` reads a private key (a passphrase by prompt or
   `SSH_ASKPASS`).
3. Build the certificate with the builder of the library, and write
   `FILE-cert.pub` with `create_new`.
4. `-V`: the forms of ssh-keygen(1) (`+52w`, `YYYYMMDD[HHMMSS]`, a pair,
   `always:forever`); a malformed interval is exit 64. `-O`: `clear`,
   `force-command=`, `source-address=`, and the `no-` and `permit-` options;
   refuse the others by name.
5. `-L`: print the certificate as `ssh-keygen -L` does.
6. Same commit: `docs/cli.md:1511-1614`, the notes of `keygen`, `docs/STATUS.md`.

## Decision

Recommendation: user and host certificates in one step: `-h` changes only the
type and the default extensions. The alternative, user certificates first,
lost: it saves little, and leaves `-h` as an unknown flag. The check of
`@cert-authority` in `podssh ssh` stays in T-027.

Taken, with these calls made in the work (2026-10-11), after a measure of the
`ssh-keygen -s` and `-L` of OpenSSH for Windows 10.0p2. The messages and the
lines are OpenSSH's: `Signed user key F-cert.pub: id "ID" serial N for
NAMES valid VALIDITY` on stderr (not with `-q`), the validity as `forever`,
`before T`, `after T` or `from T to T` in local time; `-L` with its fields,
its indents, `(none)`, and `UNKNOWN FLAG OPTION` or `UNKNOWN OPTION: HEX (len
N)` for an option that it does not know; `Must specify key id (-I) when
certifying`, `Invalid certificate life specification`, `Empty certificate
validity interval`, `Invalid serial number`, `Unsupported certificate option`.
`+TIME` alone starts a minute back, as OpenSSH's `((now - 59) / 60) * 60`. A
user certificate has the five `permit-` extensions unless `-O` changes them;
a host certificate has no option. One call differs from the Approach: as
OpenSSH does, `FILE-cert.pub` replaces the one that is there, whole, by a
rename (the Approach said `create_new`): a certificate is public, and a
renewal makes it again. A failure exits 1 (OpenSSH 255), and a usage error 64.
An RSA CA signs through aws-lc-rs with `rsa-sha2-512`, or `rsa-sha2-256` with
`-t`, through one signer that ssh-key's builder calls, in
`crates/podssh-ssh/src/rsa_key.rs`; the check of T-257 now allows `try_sign`
in that file alone. `-U` certifies with a CA in the agent: the certificate is
built once to learn what is signed, and again with the agent's signature.
`-D` (PKCS#11) is refused by name. The rows `-n`, `-s`, `-I`, `-O` and `-U`
say their use with `-Y` and with `-s`; the help of `keygen` says that `-V`
here is a validity.

## Prove

```sh
cargo test -p podssh-cli --test keygen_cert
sh scripts/dev.sh check
```

New checks in `scripts/interop-keygen.sh`: `ssh-keygen -L` reads each
certificate that podssh makes; `sshd` with `TrustedUserCAKeys` accepts a user
certificate for a login with the `ssh` of OpenSSH; `sshd` refuses a
certificate whose validity has ended. Plant: ignore `-n` when podssh signs;
the `sshd` login check fails.

## Done

2026-10-11. Certificates in `crates/podssh-ssh/src/cert.rs:1-424`, signed by an RSA CA through
`Detached` (`crates/podssh-ssh/src/rsa_key.rs:87-115`); the command in
`crates/podssh-cli/src/keygen_cert.rs:1-199`, its new flags at
`crates/podssh-cli/src/flags/keygen.rs:53-60` and `:67-68`.
- `cargo test -p podssh-ssh --lib -- cert::`: 5 passed: `-L` of a certificate of OpenSSH's prints
  the lines that OpenSSH printed for it (each kind of option among them); `-V`, `-z` and `-O` as
  ssh-keygen takes them, and their refusals in its words; an Ed25519, an ECDSA and an RSA CA
  certify, with each SHA for RSA, and the certificate holds against its CA and not after its
  end. `cargo test -p podssh-ssh --test no_rsa_private_op`: 2 passed, its plants found.
- `cargo test -p podssh-cli --test keygen_cert`: 4 passed; `--test agent_cli`: 5 passed, among
  them `-s CA.pub -U` with the CA that `podssh agent` held. Planted, each restored: `-n` ignored
  when podssh signs (the Prove's plant) failed the test of the CLI; an RSA CA signing with SHA-256
  whatever `-t` said failed a unit test (ssh-key's builder checks the signature it is given:
  "certificate validation failed"); a host certificate with a user's extensions failed two.
- Beside the `ssh-keygen` of OpenSSH for Windows 10.0p2 (2026-10-11): 16 of 16 commands (user and
  host certificates, two keys at once, options, an Ed25519, an ECDSA and an RSA CA, `-t
  rsa-sha2-256`, `always:` and `:forever`, `-q`, and five refusals) printed the same lines and
  failed alike; each tool's `-L` of both tools' certificates printed the same, the signing CA
  among it.
- `scripts/interop-keygen.sh` has nine new checks, `keygen.cert.*` (the floor of keygen is 68):
  `ssh-keygen -L` reads the certificates of an Ed25519 and an RSA CA, and a host certificate; an
  sshd that trusts those CAs (`TrustedUserCAKeys`, no `authorized_keys`) lets OpenSSH's ssh in
  with each, and refuses one that has expired and one for another principal. The gate runs them
  at this push.
- `cargo test -p podssh-ssh`: 137 passed; `cargo test -p podssh-cli`: 558 passed, 0 failed, 31
  ignored; clippy; rustfmt. In the build image: the tests of `cert`, `keygen_cert`, `agent_cli`,
  `keygen_sign` and the check of T-257 passed.
- At `8290fe1` the gate's step release failed in CI: in the box, `-V -5m:+1h` was refused with 64,
  as clap read a value that starts with `-` as flags, where getopt takes the next word; the checks
  of an expired certificate and of another principal then passed with no certificate made. The next
  commit lets `-V` take such a value (`crates/podssh-cli/src/tree.rs:41-46`), tests it
  (`a_validity_may_start_with_a_hyphen`; planted, the old parse failed it with 64), and counts
  each of the two refusals only once its certificate is made.

# T-022: `podssh keygen -e`, `-i` and `-m`: convert key formats

**Source:** the lablup/bssh report in GitHub #18, #20 and #22, item 5
(`lablup/bssh:src/bin/bssh_keygen.rs`); read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

`podssh keygen -y` and `-l` refuse a PEM or PKCS#8 private key, and the
message names `ssh-keygen -p -f FILE`
(`crates/podssh-ssh/src/keygen.rs`, lines 163-166 at `bdbe658`), which does not run without a user
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
(`crates/podssh-ssh/src/keygen.rs`, lines 174-195 at `8290fe1`). `podssh ssh -i` loads a key with
`russh::keys::load_secret_key` (`crates/podssh-ssh/src/keys.rs`, line 231 at `fe19445`), which
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
5. Same commit: `docs/cli.md:1511-1614`, the notes of `keygen`, `docs/STATUS.md`.

Pitfalls: no new C dependency. A format that a key type does not have (PEM
for Ed25519) is refused by name.

## Decision

Recommendation: `-i` imports public keys only, and a private key in another
format goes through `-p` (T-018). podssh never prints a private key
(`crates/podssh-cli/src/keygen.rs:6-9`). The alternative, `-i` prints the
private key on stdout as `ssh-keygen` does, lost for that reason.

Taken, with these calls made in the work (2026-10-11), after a measure of the
`ssh-keygen` of OpenSSH for Windows 10.0p2. `-e` writes OpenSSH's forms: RFC
4716 with its comment `N-bit TYPE, converted by USER@HOST from OpenSSH` and lines
of 70; PKCS8, a SubjectPublicKeyInfo; PEM, PKCS#1 for RSA and a
SubjectPublicKeyInfo for ECDSA; an Ed25519 key has RFC 4716 only, and the others
are refused by name, as OpenSSH refuses them. `-i` reads each, its RFC 4716
headers passed over (continued with `\`), and a PEM block of `PUBLIC KEY` or
`RSA PUBLIC KEY` under either `-m PKCS8` or `-m PEM`. `-m` with a new key or
`-p` writes PEM (PKCS#1, SEC1) encrypted with AES-128-CBC as OpenSSH writes it,
or PKCS#8 encrypted with PBES2 (PBKDF2 with HMAC-SHA256, 100 000 rounds,
AES-256-CBC), where OpenSSH's has 2048 rounds; an Ed25519 key keeps OpenSSH's
format, as `ssh-keygen` does, and podssh says so. `-y`, `-l` and `-e` read a key
in each format of T-287 through one loader of the CLI, which asks for the
passphrase; `-l` and `-e` read the public half of an OpenSSH key, or `FILE.pub`,
with no question. `read_key_file` of the library reads the other formats too, for
an unencrypted key. A failure exits 1 (OpenSSH 255) and a usage error 64.

## Prove

```sh
cargo test -p podssh-ssh --lib -- convert
cargo test -p podssh-cli --test keygen_convert
sh scripts/dev.sh check
```

New checks in `scripts/interop-keygen.sh`: `ssh-keygen -i -m PKCS8` reads
what `podssh keygen -e -m PKCS8` writes, and the reverse, for each key type;
`podssh keygen -y` reads a PEM key that `ssh-keygen -m PEM` wrote, and prints
the line of `ssh-keygen -y`. Plant: drop the PEM branch of `read_key_file`;
the last check fails.

## Correction

Read after T-018 (2026-10-11): the message of `read_key_file` names `podssh keygen -p -f FILE`
(`crates/podssh-ssh/src/keygen.rs`, lines 184-187 at `8290fe1`), which writes a key of PEM, PKCS#8 or PuTTY in the
format of OpenSSH; `-y` and `-l` still refuse such a file. Since T-287 (2026-10-11), each key
file is read through `podssh_ssh::key_file` (`crates/podssh-ssh/src/key_file.rs:25-42`), which asks
for the passphrase of an encrypted key of each format and opens an encrypted PEM key of RSA or
ECDSA; `-y` can read through it.

## Done

2026-10-11. The forms of other systems in `crates/podssh-ssh/src/convert.rs:1-318`, an encrypted
PEM key written by `encrypt_pem` (`crates/podssh-ssh/src/key_file.rs:211-235`); the command in
`crates/podssh-cli/src/keygen_convert.rs:1-72`, the key loader and the text of `-m` at
`crates/podssh-cli/src/keygen_convert.rs:74-143`, and the flags at `crates/podssh-cli/src/flags/keygen.rs:61-66`.
- `cargo test -p podssh-ssh --lib -- convert`: 3 passed: `-e` writes, byte for byte, what OpenSSH's
  `ssh-keygen -e` wrote for its Ed25519, ECDSA (P-256, P-384, P-521) and RSA keys in each form,
  and `-i` reads each back; the refusals name their reason; `-m PEM` and `-m PKCS8` keys of RSA and
  each curve read back through `key_file`, plain and encrypted.
- `cargo test -p podssh-cli --test keygen_convert`: 4 passed. Planted, each restored: `-y` reading
  OpenSSH's format alone (the Prove's plant, in the loader that `-y` uses now) failed two tests; an
  RSA SubjectPublicKeyInfo named as ECDSA failed the test of OpenSSH's bytes; `-m` ignored for a
  new key failed the test of the forms.
- Beside the `ssh-keygen` of OpenSSH for Windows 10.0p2 (2026-10-11), 51 of 51 checks held: `-e`
  wrote what OpenSSH wrote in each form for Ed25519, ECDSA and RSA (the comment of RFC 4716
  apart), and refused Ed25519's PKCS8 and PEM; each tool read the other's exports (OpenSSH's `-i`
  of PKCS8 and PEM exits with no word in this build, and the box checks it); `-y` and `-l` read
  OpenSSH's PEM and PKCS8 keys, plain and encrypted, `-l` with no `.pub`; OpenSSH read the keys of
  `-m PEM` and `-m PKCS8`, plain and encrypted, and of `-p -m PEM`.
- `scripts/interop-keygen.sh` has eleven new checks, `keygen.convert.*` (the floor of keygen is
  79): against OpenSSH in the box, each tool reads the other's PKCS8 exports of ECDSA and RSA and
  RFC 4716 exports of Ed25519, `-y` reads the keys of `ssh-keygen -m PEM`, and OpenSSH reads the
  keys of `-m pem` and `-m pkcs8` with their passphrase. The gate runs them at this push.
- `cargo test -p podssh-ssh`: 140 passed; `cargo test -p podssh-cli`: 563 passed, 0 failed, 31
  ignored; clippy; rustfmt. In the build image: the tests of `convert`, `key_file`, `keygen`,
  `cert`, each `keygen_*` test file, `flag_table` and the manual passed.
- `flags.rs`, `keygen.rs` and `man/notes.rs` of the CLI had gone over 500 lines: the flags and
  the notes of `keygen` moved to `crates/podssh-cli/src/flags/keygen.rs:1-71` and
  `crates/podssh-cli/src/man/notes_keygen.rs:1-50`, as those of the other commands are, and the
  key loader to `keygen_convert.rs`; the manual did not change.

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
out. `docs/cli.md`, lines 153-156 at `a9299c4` says that the refusal of `-R` must not say that
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
`25ab0e7`). The keyword's text is at `crates/podssh-cli/src/ssh/options.rs`, line 162 at `a9299c4`.
A test keeps the wrong replacement: `the_forwarding_rows_all_name_w` asserts
that `forward-remote` names `-W HOST:PORT`
(`crates/podssh-cli/tests/flag_table.rs` lines 68-77 at `25ab0e7`).

## Approach

1. The `-R` row (`crates/podssh-cli/src/flags.rs`, lines 206-207 at `a9299c4`): the help "remote
   forwarding is not implemented yet", the words of `-o RemoteForward`; the
   replacement `no flag`, so the refusal says "Leave it out."
   (`crates/podssh-cli/src/dispatch.rs:306-314`).
2. `crates/podssh-cli/src/help.rs`, lines 213-215 at `a9299c4` and
   `crates/podssh-cli/src/man/notes.rs`, lines 70-72 at `a9299c4`: `-L` and `-D` need a local
   listener and are refused, and `-W HOST:PORT` carries one connection; `-R`
   is not implemented yet.
3. `crates/podssh-cli/tests/flag_table.rs`, lines 82-98 at `a9299c4`: keep `-W` for `-L` and `-D`.
   For `-R`, assert that its row names no `-W` and no listener.
4. Only texts change; T-035 implements `-R` (M8). `docs/cli.md`, lines 148-157 at `a9299c4` already
   gives the rule. Same commit: `docs/STATUS.md`.

Pitfall: the manual tests read these texts. `each_name_in_a_note_exists`
checks each flag that a note names (`crates/podssh-cli/src/man/notes.rs`, lines 445-449 at `a9299c4`),
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
`docs/cli.md:2463-2464` and `docs/decisions.md` ("Exit codes") give 78
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

Read: `select_relays` (`crates/podssh-relay/src/relay.rs:107-125`) and
`pins::apply` (`crates/podssh-cli/src/pins.rs` lines 10-20 at `cd3fea5`) give
one error for the flag and for the variable. Each caller maps it to 64, at
`cd3fea5`: `crates/podssh-cli/src/proxy.rs` lines 60-71,
`crates/podssh-cli/src/ssh/mod.rs` lines 33-43 (through
`crates/podssh-cli/src/ssh/resolve.rs` line 183), and
`crates/podssh-cli/src/doctor/mod.rs` lines 47-56 (read, not run). The code 78
exists (`crates/podssh-cli/src/exitmap.rs:63`), and `podssh proxy` gives it for
a bad proxy URL or token (`crates/podssh-cli/src/proxy.rs:274-287`).

## Approach

1. Keep the source of the value: `select_relays` and `pins::apply` tell a bad
   flag from a bad variable (an error type, or the flag parsed first and then
   the variable).
2. A bad flag stays 64. A bad variable is 78 in `proxy`, `ssh` and `doctor`;
   the message names the variable, as it does now.
3. Same commit: the 78 row of EXIT STATUS
   (`crates/podssh-cli/src/man/facts.rs` lines 263-268 at `332ee58`) names `PODSSH_RELAY`,
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
**Status:** done

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
texts, in `crates/podssh-cli/src/non_interactive.rs`: `--accept-new` at lines 281-282 at `8c05b5e`,
`--relay URL` at line 289 at `8c05b5e`, E01 at lines 293-294 at `8c05b5e`; the claim at
lines 9-13 at `8c05b5e`. A test asserts the false
flag (`crates/podssh-cli/tests/non_interactive.rs`, line 185 at `8c05b5e`).

The real gate is `can_ask` (`crates/podssh-ssh/src/prompt.rs:82`), called at
`crates/podssh-ssh/src/auth.rs:189`, `crates/podssh-ssh/src/auth.rs:306`,
`crates/podssh-ssh/src/keys.rs:321` and `crates/podssh-cli/src/keygen.rs:382`.
Its refusals name the real remedies (`docs/cli.md:2544-2546`). Commands use
these parts of the module, which stay: `Attachment`, `resolve`, `resolve_tty`,
`parse_timeout`, `require_timeout` (`crates/podssh-cli/src/dispatch.rs:249-267`,
`crates/podssh-cli/src/ts.rs:54-63`) and `refuse_jsonl_in_proxy`
(`crates/podssh-cli/src/tree.rs:194-197`).

## Approach

1. Remove `force_interactive` and the variant `Attachment::ForcedInteractive`
   (`crates/podssh-cli/src/non_interactive.rs`, lines 78-96 at `8c05b5e`), `PromptSite`
   (lines 112-134 at `8c05b5e`) and `gate_prompt` (lines 255-308 at `8c05b5e`).
2. Remove their tests (`crates/podssh-cli/tests/non_interactive.rs`, lines 40-48,
   118-165 and 179-186 at `8c05b5e`), and take
   `ForcedInteractive` out of `missing_timeout_outside_a_terminal_is_usage_64`
   (lines 89-98 at `8c05b5e`).
3. Write the module comment again (`crates/podssh-cli/src/non_interactive.rs`, lines 1-28 at
   `8c05b5e`): what the module holds and why, with no `⛔` and no planning ids
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

## Correction

2026-10-12: the false flags were gone before this entry was done. T-244 (`e3ea638`, 2026-10-09)
wrote the refusals of `gate_prompt` again: `--accept-new` became
`-o StrictHostKeyChecking=accept-new`, `--relay URL` became `--relay-host HOST` or
`PODSSH_RELAY`, and E01, E13 and E33 became words; the test then asserted the real option, and
the search of the Prove for "accept-new (E13)" found nothing before this change. The rest held
at `8c05b5e`: no command called `gate_prompt`, `PromptSite` or `force_interactive`; the module
comment still said that `gate_prompt` was the only path to a prompt; and the doc of
`Attachment` named `--non-interactive` and `--interactive`, which podssh does not have. The
Approach stands, and it also takes those two names out of the doc of `Attachment`.

## Done

2026-10-13.

- `crates/podssh-cli/src/non_interactive.rs`: `force_interactive`,
  `Attachment::ForcedInteractive`, `PromptSite` and `gate_prompt` are gone, with the arm of
  `require_timeout` that named `--interactive`. The module comment says what the module holds
  (the attachment, the time limit and its variable, the two refusals of `--jsonl`), that it asks
  nothing and gates no prompt, as podssh-ssh's `prompt::can_ask` is the gate, and which exit
  code each refusal gives. The doc of `Attachment` says that `Forced` is `--jsonl`; those of
  `Refusal` and `is_non_interactive` no longer speak of prompts. What the commands use stays:
  `Attachment`, `resolve`, `resolve_tty`, `timeout_text`, `require_timeout_or_env`,
  `parse_timeout`, `parse_duration`, `require_timeout` and the two refusals.
- `crates/podssh-cli/tests/non_interactive.rs`: the tests of the removed code are gone
  (`forced_interactive_is_refused_unless_both_fds_are_ttys`,
  `every_prompt_site_refuses_outside_a_terminal_and_names_its_remedy`,
  `a_changed_host_key_refuses_even_on_a_terminal`, `other_sites_allow_a_terminal` and
  `a_refusal_names_the_site_and_the_remedy`); `missing_timeout_outside_a_terminal_is_usage_64`
  checks `Pipe` and `Forced`; the comment of the file no longer names `gate_prompt`. No other
  source, test or document named the removed code.
- Prove, Windows 11: `cargo test -p podssh-cli`: 762 passed, 0 failed, 34 ignored. The search
  of the Prove: no line, exit 1. Planted, the module as it was restored: the search finds 16
  lines; restored, none. Clippy and rustfmt: clean.
- Nothing waits for T-251: the entry has no run in the build image.

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
`docs/cli.md:43-46` says that `--help` and the manual mark such a command. A
user reads options such as `--timeout` and `-r`, and then gets exit 70.

## Premise

Measured offline: `podssh node`, `operator`, `chat` (also `irc`), `cp` (also
`scp`), `mv`, `relay`, `status` and `ts`, each with `--help`, exit 0, and the
text has no "not implemented" and no "not in this build". Controls:
`podssh --help` marks each of them (`crates/podssh-cli/src/help.rs:176`), and
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
   (`crates/podssh-cli/src/flags.rs:452-460`): the title with the note, the
   sentence of the manual, and no option but `--help`, as the manual does.
2. Keep that sentence in one place, so that `--help` and the manual
   (`crates/podssh-cli/src/man/model.rs` lines 188-200 at `fdbba30`) cannot
   differ.
3. Extend `a_command_that_does_not_work_says_so_in_both` to the help of each
   such verb.
4. `scripts/interop-man.sh:37-38` already skips these verbs (it drops each line
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
(`crates/podssh-cli/src/man/model.rs:327-336`).

## Approach

1. Give the topic a key of its own, for example `relay-facts` (the term of
   `docs/cli.md:16-17`). Keep the heading THE RELAY.
2. The section of the command `relay` names the topic in one line.
3. A new test: no two sections share a key or an alias, and each topic key
   finds its own section.
4. Change the SECTION help (`crates/podssh-cli/src/positionals.rs:112`):
   `the_section_argument_names_each_topic` requires each topic key in it
   (`crates/podssh-cli/src/man/model.rs:394-405`). Same commit: `docs/STATUS.md`.

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
**Status:** done

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
(`crates/podssh-cli/src/help.rs`, line 215 at `8c05b5e`), outside `flag_line`
(`crates/podssh-cli/src/help.rs:73-82`). `flag_column` measures only the
verb's own rows (`crates/podssh-cli/src/help.rs:34-39`).

## Approach

1. Write `HELP_FLAG` with `flag_line`, and compute `flag_column` over the
   verb's rows and `HELP_FLAG` together. Then `--help` has the indent of a
   long-only row and the common text column.
2. Keep `--help` as the last line of the block, with no blank line before it:
   `options_block` stops at the first blank line
   (`crates/podssh-cli/tests/man_extract/mod.rs:35-52`).
   `scripts/interop-man.sh:48-50` reads an option line at any indent.
3. Add `--help` to the layout test `no_flag_runs_into_its_description`
   (`crates/podssh-cli/src/help.rs:404-440`), or add a test that each
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

## Done

2026-10-13.

- `crates/podssh-cli/src/help.rs`: `block_rows` gives a verb's rows and then `HELP_FLAG`, and
  `options_lines` writes them with `flag_line` in one column, which `flag_column` measures over
  them all. `verb_help` calls it for each verb, also for a command that does not work here, whose
  block is `--help` alone. So `--help` starts 8 spaces in, as each long option with no short form
  does, its text starts in the column of the other rows, and it is the last line of the block,
  with no blank line before it. The block of the options before a command (`  -h, --help`) did
  not change.
- Tests: `no_flag_runs_into_its_description` (`help::tests`) checks `--help` with the verb's rows,
  in the column of the block (step 3's first form). The new test
  `help_starts_in_the_columns_of_the_other_options` is in
  `crates/podssh-cli/tests/man_flag_parity.rs`, not in `help::tests`: with it, `help.rs` had 516
  lines. It reads the text of each verb's `--help` through the parity gate's own reader of the
  block: each long name, `--help` among them, starts 8 characters in; each description beside
  its flag starts in the column of the text of `--help`; and `--help` is the last line.
- `docs/STATUS.md`: a row in Commands.
- Prove, Windows 11: `cargo test -p podssh-cli --lib -- help::tests`, 8 passed; `cargo test
  -p podssh-cli --test man_flag_parity`, 6 passed; `podssh proxy --help` has `--help` after 8
  spaces, its text in the column of the other rows. Planted, `--help` out of the rows and the
  `{:<12}` line again in `options_lines`: `help_starts_in_the_columns_of_the_other_options`
  failed; restored, it passed.
- Waits for T-251: `scripts/interop-man.sh` in the build image, which takes an option line at
  any indent, so it should read the same spellings as before.

# T-288: On Windows, `podssh keygen` writes a private key with the access list of its directory

**Source:** the work of T-018 (2026-10-11): OpenSSH for Windows refused a key that `podssh keygen`
had made.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

On Unix, `podssh keygen` makes the private key with mode 0600, and a missing directory with mode
0700 (`crates/podssh-ssh/src/keygen.rs`, lines 93-136 at `a0757ed`). On Windows it sets neither: the key takes the
entries that its directory passes down, so each user or group that may read the directory may
read the key, and OpenSSH for Windows refuses to use it. The notes of `keygen` say that the private
key has mode 0600 (`crates/podssh-cli/src/man/notes.rs`, lines 334-335 at `a0757ed`).

## Premise

Measured on Windows 11 with OpenSSH for Windows 10.0p2 (2026-10-11), in a directory of this
checkout whose access list gives Modify to a group of sandbox users and to two other accounts:

- `podssh keygen -q -N '' -f DIR/k`: `icacls` shows only inherited entries on `k`, the three that
  may modify it among them. `ssh-keygen -y -f DIR/k` says "Bad permissions. Try removing
  permissions for user: ..." and "WARNING: UNPROTECTED PRIVATE KEY FILE!".
- `ssh-keygen -q -t ed25519 -N '' -f DIR/k`, OpenSSH's own: the key has an access list of its
  own, none of it inherited: the Administrators and SYSTEM with full control, and the owner with
  Modify. `k.pub` has the same, and Everyone may read it.
- A key that `podssh keygen -p` or `-c` rewrote (T-018) is made by
  `podssh_relay::cache::create_new_private`, with an access list of its own (T-274):
  `ssh-keygen -y` read it.

## Approach

1. Write the private key with `podssh_relay::cache::create_new_private` (Unix: mode 0600, never
   through a symlink; Windows: the user, SYSTEM and the Administrators, nothing inherited), and
   make a missing directory with `podssh_relay::cache::private_dir`. `write_pair` is in
   podssh-ssh, which does not depend on podssh-relay: it takes the two as functions, and the CLI
   passes them.
2. The notes of `keygen` and `docs/cli.md` say what the key gets on Windows.

## Prove

```sh
cargo test -p podssh-cli --test keygen -- private
```

On Windows the test makes a key in a directory that the group Users may modify, and checks it with
`podssh_relay::cache::closed`, and with OpenSSH's `ssh-keygen -y` when that is installed. Plant:
write the key with `OpenOptions`, as now; the test fails.

## Done

2026-10-11. `write_pair` makes the files of a key pair with the makers that its caller passes,
`KeyFiles` (`crates/podssh-ssh/src/keygen.rs:112-173`), and the CLI passes podssh-relay's
(`crates/podssh-cli/src/keygen.rs:371-378`): the private key by `create_new_private`, a missing
directory by `private_dir`, and `FILE.pub` by the new `create_new_public`
(`crates/podssh-relay/src/cache.rs:358-377`), on Windows with an access list of its own that lets
Everyone read it, as OpenSSH's `ssh-keygen` makes it. `FILE.pub` is removed and made again, so
that it never keeps a list that lets others change it, also after `-c`.
- `cargo test -p podssh-cli --test keygen -- private`: 2 passed. On Windows the test opened the
  scratch directory's files to the group Users (Modify): `podssh_relay::cache::closed` found the
  key closed, the `.pub` and the new directory closed to changes, and the `ssh-keygen` of OpenSSH
  for Windows 10.0p2 printed the key's public line. Planted, each restored: the key, the `.pub`
  or the missing directory made as before, by `OpenOptions` or `create_dir_all`; each failed the
  test ("the group Users (S-1-5-32-545) may write it"). In the build image the same test passed,
  with the modes 0600, 0644 and 0700.
- `cargo test -p podssh-relay --all-features`: 243 passed, 0 failed, 16 ignored; `cargo test -p
  podssh-ssh`: 112 passed; `cargo test -p podssh-cli`: 543 passed, 0 failed, 31 ignored; clippy.

# T-289: `podssh keygen -Y` with certificates: a signature made with a certificate, and `cert-authority` lines

**Source:** the work of T-020 (2026-10-11).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

OpenSSH's `ssh-keygen -Y sign` signs with a certificate when the key of `-f` has one, and
`-Y verify` accepts such a signature when a line of the allowed signers marked `cert-authority`
names the certificate's CA (ssh-keygen(1), ALLOWED SIGNERS; read in the manual, not verified
here). `podssh keygen -Y` (T-020) refuses a signature made with a certificate, by name, and a
`cert-authority` line allows no signature.

## Premise

Read in ssh-key 0.7.0-rc.11 (the local cargo registry): `SshSig` keeps the key of a signature as a
`KeyData` (its `src/sshsig.rs`, line 269), which holds no certificate, so its parser refuses a
signature whose key is one. Read: podssh names such a signature (`read_signature`,
`crates/podssh-ssh/src/sshsig.rs`, lines 93-103 at `3224a88`) and passes over a `cert-authority`
line (`names_key`, lines 332-335 at `3224a88`).

## Approach

1. Read a signature whose key is a certificate: the blob of PROTOCOL.sshsig parsed here, and the
   certificate with `ssh_key::Certificate`. Verify the signature with the certificate's key.
2. A `cert-authority` line allows it when its key is the certificate's CA, the certificate is a
   user certificate valid at the time, and one of its principals is `-I` (`verify`); as the checks
   of a host certificate (T-027, `crates/podssh-ssh/src/hostcert.rs`).
3. `-Y sign` with `-f KEY-cert.pub` signs with the certificate, as OpenSSH does; `-f KEY` signs
   with the plain key, also when `KEY-cert.pub` is there (the Correction).
4. `find-principals` prints the principals of the certificate that a `cert-authority` line allows.

## Decision

Taken, with these calls made in the work (2026-10-12). OpenSSH's sources were not on this host:
the calls follow ssh-keygen(1) and OpenSSH's `ssh-keygen.c`, `sshsig.c` and `sshkey.c` as the writer
knew them, and each message below is a string of the `ssh-keygen` of Git for Windows and of the
`ssh-keygen` of OpenSSH for Windows here (read with grep in the binaries, not run). The checks
`keygen.sigcert.*` of `scripts/interop-keygen.sh` measure them against OpenSSH at T-251.

- Signing: `-f KEY-cert.pub` signs with that certificate, as OpenSSH's `load_sign_key` does: the
  private key is the path without `-cert.pub` (or `.pub`), and must hold the certificate's key
  (`Public key F doesn't match private K`; none there: `No private key found for public key "F"`).
  `-f KEY` signs with the plain key, also with `KEY-cert.pub` beside it (the Correction). The agent
  signs when it holds the certificate's key; an agent that holds it only in a certificate is asked
  by the certificate, as OpenSSH's ssh-agent finds a key by it.
- The blob of PROTOCOL.sshsig with a certificate as its key is read and written in podssh-ssh's
  `sshsig_cert`, with ssh-key's types for its parts (`Certificate`, `Signature`, `HashAlg`). The
  signature is then ssh-key's `SshSig` with the certificate's key, so each check of T-020 runs on
  it unchanged; its reserved field is read and passed over, as OpenSSH passes it. A certificate
  whose CA signature fails is refused as the signature is read (`Couldn't parse signature: ...`), as
  OpenSSH's parser checks it.
- A `cert-authority` line: the checks of OpenSSH's `sshkey_cert_check_authority` for a signature
  (a user certificate, `valid-after <= now < valid-before`, a list of principals, and `-I` in it
  as written, with no wildcard), in its order and its words, said on stderr as
  `FILE:N: certificate not authorized: REASON`; then the line's namespaces and times, as for a
  key. ssh-key's `validate_at` with the CA of the line checks it again, a redundant check. The
  critical options are not read, as OpenSSH's signatures do not read them: they restrict a login.
  The alternative, to refuse an unknown critical option as T-027 refuses one of a host
  certificate, lost: OpenSSH accepts such a signature, and a git that verifies with each tool
  would get two answers.
- A plain line names only a plain signature, and a `cert-authority` line only a certificate's, as
  OpenSSH's `sshkey_equal` compares the types. The alternative, a plain line of the key that also
  allows the signature of its certificate, lost for the same reason.
- `find-principals`: of a `cert-authority` line, the principals of the certificate that its patterns
  match, pattern by pattern (OpenSSH's `cert_filter_principals`); with none,
  `FILE:N: no valid principals found` on stderr, and the line is passed over.
- What is printed: the type with `-CERT` (`ED25519-CERT`) and the fingerprint of the certificate's
  key, as OpenSSH's `sshkey_type` and `sshkey_fingerprint` give them; `-O print-pubkey` prints the
  certificate's line.

## Prove

```sh
cargo test -p podssh-ssh --lib -- sshsig
cargo test -p podssh-cli --test keygen_sign -- cert
```

Tests with certificates made with ssh-key's builder, as the tests of T-027 make them. New checks in
`scripts/interop-keygen.sh`: a key certified with OpenSSH's `ssh-keygen -s`, its signature
verified by each tool against a `cert-authority` line. Plant: accept a certificate of another CA;
the test of the CA fails.

## Correction

2026-10-12. The Problem ("when the key of `-f` has one") and Approach step 3, as it was first
written, say that `-Y sign -f KEY` signs with `KEY-cert.pub` when it is there, "as OpenSSH does".
OpenSSH's `sig_sign` reads the public key of `-f` with `sshkey_load_public`,
which tries FILE, then `FILE.pub`, then the private key, and never `FILE-cert.pub`; it signs with a
certificate when `-f` names it, and `load_sign_key` then finds the private key by dropping
`-cert.pub` (its message `%s looks like a public key, using private key path %s instead` is a
string of the `ssh-keygen` binary here). Read as the writer knew the source; not run here. The work
follows OpenSSH: `-f KEY-cert.pub` signs with the certificate, and `-f KEY` with the plain key.
Taking `KEY-cert.pub` for `-f KEY` would make a signature that a plain line of the key no longer
allows, where OpenSSH's own signature of `-f KEY` passes. The check
`keygen.sigcert.key_beside_signs_plain` measures OpenSSH's choice at T-251.

## Done

2026-10-13. Signatures made with a certificate, and the `cert-authority` lines that allow them, in
`crates/podssh-ssh/src/sshsig_cert.rs:1-197`: the blob read (`:74`) and written (`:109`), the
checks of a line (`not_authorized`, `:145`) and the principals of `find-principals` (`:178`).
`read_signature` gives a `Signed`, the signature and its certificate
(`crates/podssh-ssh/src/sshsig.rs:24-30`, `:134-140`); `names_key` names a CA's certificate
(`:359-364`); an agent that holds a key only in a certificate signs by it (`:106-119`). The
command: `-f KEY-cert.pub` in `crates/podssh-cli/src/keygen_sign.rs:182-236`, the lines of `verify`
and `check-novalidate` (`:339-397`) and `find-principals` (`:414-454`). The manual's note
(`crates/podssh-cli/src/man/notes_keygen.rs:24-28`), the help of `-f`
(`crates/podssh-cli/src/flags/keygen.rs:17-18`), `docs/cli.md` (section of `keygen`) and
`docs/STATUS.md` say it.

- `cargo test -p podssh-ssh --lib -- sshsig`: 11 passed on Windows 11 and in the build image. The new tests, in
  `crates/podssh-ssh/src/sshsig_cert_tests.rs` with certificates of ssh-key's builder (through
  `cert::certify`): `a_signature_made_with_a_certificate_is_written_and_read` (an Ed25519, an ECDSA
  and an RSA key: the armour, the certificate read back, the check, changed data refused),
  `a_certificate_that_its_ca_did_not_sign_is_refused`,
  `a_cert_authority_line_names_the_certificate_ca_alone`,
  `a_certificate_refuses_with_openssh_words` and `find_principals_filters_those_of_the_certificate`.
  The tests of T-020 in `sshsig_tests.rs` take the `Signed`.
- `cargo test -p podssh-cli --test keygen_sign`: 8 passed on Windows 11 and in the build image. The new tests, with keys and
  certificates of `podssh keygen` and `podssh keygen -s`:
  `a_certificate_signs_and_its_cert_authority_line_allows_it` (OpenSSH's lines of `verify`,
  `check-novalidate`, `find-principals` and `-O print-pubkey`, and another principal refused),
  `a_certificate_of_another_ca_or_a_plain_line_allows_nothing` (the test of the CA),
  `a_key_beside_its_certificate_signs_without_it` and
  `certificate_signatures_refused_in_openssh_words` (expired, not yet valid, a host certificate, no
  principal, no private key, another private key).
- `cargo test -p podssh-cli --test agent_cli -- cert`: 2 passed (the whole binary 6 in the build image). The new test
  `keygen_signs_with_a_certificate_of_the_agents_key`: `-Y sign -U -f KEY-cert.pub` signs with the
  key of `podssh agent`, and `check-novalidate` names an `ED25519-CERT` key. The branch of an agent
  that holds the key only in a certificate has no test: `podssh agent` holds no certificate, and
  OpenSSH's `ssh-add` adds the plain key with its certificate.
- The whole of `--test keygen_sign` and `--test agent_cli`, the tests of the manual
  (`cargo test -p podssh-cli --lib -- man`, 42 passed), clippy 1.99 in the build image, rustfmt
  and `cargo todo check`: clean. `python scripts/check-repo.py`: ok.
- The Prove's plant, a certificate of another CA accepted (`names_key` with no comparison of the
  CA: `Some(_) => signer.cert_authority`):
  `a_cert_authority_line_names_the_certificate_ca_alone` and
  `a_certificate_of_another_ca_or_a_plain_line_allows_nothing` failed; restored, they passed; the
  second fails because the
  line of the other CA then says `certificate not authorized` on stderr, where nothing is due.
- `scripts/interop-keygen.sh` has eight new checks, `keygen.sigcert.*` (the floor of keygen is 87):
  a key certified with OpenSSH's `ssh-keygen -s` signs with `-f KEY-cert.pub` in each tool, each
  verifies the other's signature by a `cert-authority` line, both print the same lines for
  `find-principals` and `check-novalidate`, both refuse another principal, a line of another CA and
  a plain line of the key, and `-f KEY` beside the certificate signs plain in each. In the build
  image (the steps `lint` and `release`, green; interop 517 passed, 0 failed), against OpenSSH
  10.3p1's `ssh-keygen`: the 8 passed, `keygen` 87 of 87. So OpenSSH refuses a signature of a
  certificate by a plain line of its key, and filters the certificate's principals by the line,
  as the Decision read from memory of its source.

# T-357: `doctor` names `pipe` alone as a listener, and its module says that it alone calls `bind()`

**Source:** GitHub #69 (Nemo-010, 2026-10-31), its asks 1 and 3 as its amendment restates them;
its ask 2, a listen after the bind, is T-358.
**Category:** defect
**Milestone:** backlog
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`podssh doctor` binds a TCP socket and a Unix socket, closes each, and reports each answer as
`ok`. Where the host refuses the bind, the line says that only `pipe` would listen; five more
features listen: `-L` and `-D`, on a port or a path, the control socket of `-M`, `podssh agent`
and `podssh session`. Where the host allows the bind, the line does not say that a bind is not a
listener, so it reads as a listener that works. The module says that its probes are the only
place where podssh calls `bind()`, and the help of `pipe` says that it joins two streams with no
listener. A user who asks doctor whether `-L` can work on this host is told the wrong thing, or
nothing.

## Premise

- Read: `bind_inet` makes a TCP socket, binds 127.0.0.1 port 0, reads its name and closes it,
  with no `listen()` (`crates/podssh-cli/src/doctor/unix.rs` lines 137-161 at `48a8744`); each answer is `ok`, and
  `crates/podssh-cli/src/doctor/unix.rs` line 164 at `48a8744` says "only podssh pipe tcp-listen: would listen".
  The Unix probe ends each answer the same way:
  `crates/podssh-cli/src/doctor/unix.rs` line 186 at `48a8744` says "podssh listens only for podssh pipe unix-listen:".
  The lines are `bind AF_INET` and `bind AF_UNIX` (`crates/podssh-cli/src/doctor/host.rs` lines 20-21 at `48a8744`),
  and the module's head says of its probes that podssh needs none of them:
  `crates/podssh-cli/src/doctor/unix.rs` line 4 at `48a8744` says "needs none of these".
- Read: `crates/podssh-cli/src/doctor/mod.rs` line 15 at `48a8744` says "The bind probes here are the only place
  podssh calls". The listener scan of `scripts/check-repo.py` allows a `bind(` in 17 files
  (`scripts/check-repo.py:138-157`), and these listen, each when the user asks: `pipe`'s
  `tcp-listen:` and `unix-listen:` (`crates/podssh-cli/src/pipe/listen.rs:118-132`, `:159-183`),
  the control socket of `-M` (`:185-193`), `-L` and `-D` on a port or a path
  (`crates/podssh-cli/src/ssh/local_bind.rs:78-88`, `:111-128`), `podssh agent`
  (`crates/podssh-cli/src/agent/serve.rs:38-41`) and `podssh session`
  (`crates/podssh-cli/src/session/daemon.rs:163`); on Windows, `bind` and `listen` together
  (`crates/podssh-cli/src/pipe/listen_win.rs:136`).
- Read: a refused listener exits 77 in `pipe`, `podssh agent` and `podssh session`
  (`crates/podssh-cli/src/pipe/listen.rs:48-55`), and 255 in `-L` and `-D`, with the system's
  words and "this host refuses the listener" (`crates/podssh-cli/src/ssh/local_bind.rs:89-93`).
  The issue's amendment says that `-L` exits 77: it exits 255, as OpenSSH's ssh does for a
  failure of its own (`crates/podssh-ssh/src/run.rs:23`).
- Read: `crates/podssh-cli/src/flags.rs` line 364 at `48a8744` says "join two byte streams, as socat does, with no
  listener", though `pipe` listens for `tcp-listen:` and `unix-listen:` since T-177; the note of
  the manual says it right, "with no listener unless one side asks for one"
  (`crates/podssh-cli/src/man/notes.rs:172`).
- Read: doctor's rule: a condition that podssh is built for, no listener among them, is a fact,
  reported `ok`, and `FAIL` is kept for what stops podssh or one of its fallbacks
  (`crates/podssh-cli/src/doctor/mod.rs:6-9`); `docs/cli.md:1343-1349` says the same.

## Approach

1. The module's comment (`crates/podssh-cli/src/doctor/mod.rs` lines 15-16 at `48a8744`) says what is true: the
   probes of doctor bind and close; each other bind is a listener that the user asks for, or the
   UDP socket of a road, and the listener scan of `scripts/check-repo.py` holds their files. The
   head of `crates/podssh-cli/src/doctor/unix.rs` names what needs each probe's capability.
2. The detail of a refused bind names each feature that cannot listen here, by family: for
   AF_INET, `-L` and `-D` on a port and `pipe tcp-listen:`; for AF_UNIX, `-L` and `-D` on a path,
   the control socket of `-M`, `podssh agent`, `podssh session` and `pipe unix-listen:`; and it
   says that the roads need no listener. The detail of a bind that worked says that `listen()` was
   not tried, so the same features may still be refused (until T-358).
3. One table in doctor of the features that listen, each with its family, and a test that each
   verb and flag of the table is in the flag tables (`crates/podssh-cli/src/flags.rs`), so that a
   later change that renames one meets the test.
4. The about of `pipe` (`crates/podssh-cli/src/flags.rs` lines 363-364 at `48a8744`) names its listeners, as the
   manual's note does. `docs/cli.md` ("`podssh doctor`") gives the words of the new lines.

## Decision

A refused bind stays `ok`, with the features named. `FAIL` lost: the hosts that podssh is built
for refuse the bind (sandbox A for AF_INET, `docs/STATUS.md:279`; the measured cage by the
operator's report, `docs/target-environment.md:25`), and doctor exits 1 on a `FAIL`, so each run
there would fail where each road works (`crates/podssh-cli/src/doctor/mod.rs:6-9`). A fourth
status lost: the report and its JSON have three (`docs/cli.md:1370-1373`). The issue's grade by a
run for a listener feature lost: doctor is given no feature to check, and each feature refuses on
its own, with the system's words.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib doctor
cargo test -p podssh-cli --test flag_table
python scripts/check-repo.py
```

The details of a refused and of an allowed bind, from the function that writes them, given a
planted error: each names the features of its family, and the allowed one says that no
`listen()` was tried. Planted: a verb of the table renamed; the test against the flag tables
fails.

## Done

2026-10-31, in one change with T-358, whose listen replaces the words of item 2 for a bind that
worked ("listen() was not tried"): the line now says what the listen did.

- `crates/podssh-cli/src/doctor/listeners.rs`: the table `LISTENERS` of the features that listen,
  each with its family (AF_INET: `-L` and `-D` on a port, `pipe tcp-listen:`; AF_UNIX: `-L` and
  `-D` on a path, the control socket of `-M`, `podssh agent`, `podssh session`, `pipe
  unix-listen:`), and the words of the lines: a refused bind or listen ends "so ... cannot listen
  here; no road needs a listener", each feature of its family named, and stays `ok` (the
  Decision).
- The module's comment says what is true (`crates/podssh-cli/src/doctor/mod.rs:15-18`), the head
  of `crates/podssh-cli/src/doctor/unix.rs` names what needs each probe, and the about of `pipe`
  names its listeners.
- Tests: `doctor::listeners::tests`, three: a refused bind names each listener of its family and
  no other, a bind that worked says what its listen did, the list in words; `cargo test -p
  podssh-cli --lib doctor`, 33 passed. `flag_table`'s
  `each_listener_that_doctor_names_is_a_verb_and_a_form_of_the_tables`, 9 passed; planted, the
  verb `session` written `sessions`, it failed ("sessions: no such verb"). `python3
  scripts/check-repo.py`, exit 0. `docs/cli.md` gives the lines.

# T-358: `doctor` measures a bind and never a listen, so a host that refuses `listen()` reads as one that listens

**Source:** GitHub #69 (Nemo-010, 2026-10-31), its ask 2: `listen()` after `bind()` on the same
socket, then close.
**Category:** defect
**Milestone:** backlog
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A host can allow `bind()` and refuse `listen()`: a seccomp filter takes each call apart, and the
policy of an LSM can refuse listening for one family. On such a host doctor says that the bind
works, and `-L`, `-D`, `-M`, `podssh agent`, `podssh session` and the `-listen:` addresses of
`pipe` each fail at `listen()`. Each of them takes the bind and the listen as its probe; doctor
alone measures less than they use, so it cannot answer what a user asks it.

## Premise

- Read: doctor's probes bind and close with no `listen()`
  (`crates/podssh-cli/src/doctor/unix.rs` lines 137-166 and 200-231 at `48a8744`). The listeners make the socket,
  bind and listen in one attempt, which is their probe
  (`crates/podssh-cli/src/pipe/listen.rs:1-6`, `crates/podssh-cli/src/ssh/local_bind.rs:1-6`).
- Read: T-038 and T-177 knew it. `TODO/forwarding.md:501-504` says "A seccomp filter can allow",
  and `TODO/pipe.md:420-422` says "A bind that works does not prove"; T-177 kept doctor as it
  was, and `TODO/pipe.md:448-449` says "doctor stays bind-and-close".
- Read: `AGENTS.md` lines 248-250 at `48a8744` says "closes it without listening" of doctor's bind in rule 2;
  `SECURITY.md` lines 112-113 at `48a8744`, `docs/architecture.md` lines 133-134 at `48a8744` and `docs/cli.md` lines 1346-1347 at `48a8744` say the same.
  The ruling of 2026-10-08 lets a listener open when the user asks for it and a probe at run time
  allows the bind (`docs/decisions.md:33`). A listen of doctor's is no listener that the user asks
  for, so it waits for a ruling: Q53.
- Read: the measured cage's listening was not measured, and stands on the operator's report
  (`docs/target-environment.md:25`); sandbox A's AF_UNIX bind was doctor's bind
  (`docs/STATUS.md:279`), so whether it listens is not known. The box refuses each bind
  (`scripts/box/seccomp.json:5-10`): it has no case of a bind allowed and a listen refused.
- Read, in the issue (measured by its reporter on a development host, not with podssh): a bind
  of an AF_INET stream socket refused, where an AF_INET datagram socket and an AF_UNIX socket
  bound. Inferred: each call and each family is a gate of its own, so one line cannot stand for
  another.

## Approach

1. After the bind, `listen(fd, 1)` on the same socket, then close: nothing is accepted, and
   nothing is left. For AF_INET on 127.0.0.1 port 0; for AF_UNIX on the file in the temporary
   directory, made mode 0600 as `pipe` makes its socket
   (`crates/podssh-cli/src/pipe/listen.rs:195-207`), and on Linux on an abstract name. With
   `PODSSH_LISTEN=no` (`crates/podssh-cli/src/pipe/listen.rs:22-39`) no listen is made, and the
   line says so.
2. The lines `listen AF_INET` and `listen AF_UNIX`, each with what happened: bound and listened;
   bound, and `listen()` refused with its error; or the bind refused. A refusal names the features
   that cannot listen here (T-357's table), and stays `ok` by T-357's Decision.
3. `AGENTS.md` (rule 2), `SECURITY.md`, `docs/architecture.md` (rule 3) and `docs/cli.md` say what
   doctor does; the listener scan allows `listen(` in `crates/podssh-cli/src/doctor/unix.rs`
   (`scripts/check-repo.py` line 152 at `48a8744`).
4. The box: a second seccomp profile beside `scripts/box/seccomp.json`, which allows `bind` and
   refuses `listen` with EPERM, for doctor's line and for the refusals of `pipe`, `-L` and
   `podssh agent`.

## Decision

The operator's ruling of 2026-10-31 on Q53 (`docs/decisions.md`): `doctor` may call `listen()` once
on each socket that it binds, with a backlog of 1, on 127.0.0.1 port 0 and on a Unix socket of mode
0600 in the temporary directory, accept nothing, and close each at once; never with
`PODSSH_LISTEN=no`. Rule 2 of `AGENTS.md`, `SECURITY.md` and `docs/architecture.md` say so in the
same change.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib doctor
sh scripts/test_in_box.sh   # with the second profile, which refuses listen
```

Natively: the lines from the function that writes them, given each answer of the bind and of the
listen. In the box with the second profile: `listen AF_INET` says that the bind worked and
`listen()` was refused, and `podssh pipe tcp-listen:0 -` exits 77 with the same error. Planted:
the listen left out; the line says that the bind worked, and the check of the box fails. The run
in the box waits for T-251.

## Done

2026-10-31, under the operator's ruling on Q53: doctor's lines are `listen AF_INET` and `listen
AF_UNIX`. After the bind, one `listen()` with a backlog of 1, nothing accepted, the socket closed
at once; the socket file is made mode 0600 before it listens; on Linux the abstract name too; with
`PODSSH_LISTEN=no` no listen is tried, and the line says that the variable turns the listeners
off. Here: "127.0.0.1:41303: bound, listened and closed with no connection taken; so -L on a
port, -D on a port and podssh pipe tcp-listen: can listen here".

- Tests: `doctor::unix::tests::listen_once_makes_the_socket_listen` reads `SO_ACCEPTCONN` after
  the probe; planted, an answer of `Listened` with no listen made, it failed ("the socket does not
  listen"), where the words alone passed. `a_probe_listens_once_and_says_so`, and the three of
  `doctor::listeners`; `cargo test -p podssh-cli --lib doctor`, 33 passed; clippy `-D warnings`
  and rustfmt clean.
- Rule 2 of `AGENTS.md`, `SECURITY.md`, `docs/architecture.md` (rule 3) and `docs/cli.md` say
  what doctor does; the listener scan allows `listen(` in `crates/podssh-cli/src/doctor/unix.rs`.
- The box: `scripts/box/seccomp-nolisten.json` allows the bind and refuses `listen` with EPERM,
  selected by `BOX_SECCOMP=nolisten sh scripts/test_in_box.sh`. Its run, and the plant of the
  listen left out there, wait for T-251.
- 2026-10-31, after the close: CI's job macos failed this test at b9e007c (build run
  41181675084), as macOS refuses to read `SO_ACCEPTCONN` (`getsockopt` gave -1 on macos-15).
  The test now also connects to the socket with a bound of 10 s, which completes into the
  backlog of a socket that listens and is refused by one that does not, on each Unix;
  `SO_ACCEPTCONN` stays a second witness on Linux. Planted again, `Listened` with no listen
  made: refused, "the socket does not listen: ... Connection refused", at the connect's check.
