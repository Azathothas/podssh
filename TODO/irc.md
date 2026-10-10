This file holds the work on the IRC client in crates/podssh-core/src/irc/: one entry for each row I1
to I8 of the former defects page (`git show 3ee70dc:docs/defects.md`), and the research that
decides how `podssh chat` works (T-099). No command uses the client, and `podssh chat` exits 70.
The client is sans-IO, so its unit tests need no network. The live probe
`crates/podssh-cli/examples/live_irc.rs` reaches real servers through the relay, with a token from
the environment, the cache or a mint, never printed (`docs/development.md:454-461`). Each defect was read
again on `3ee70dc`.

# T-091: I1: `CAP END` is sent only after 001

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I1 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The client sends `CAP LS 302`, `NICK` and `USER`, and then waits for `001` before it sends
`CAP END`. An IRCv3 server holds the registration until it gets `CAP END`, so it never sends
`001`. Both sides wait until the server's registration limit closes the connection. Thus the
client cannot register on a server that supports `CAP`.

## Premise

Read: the comment says that registration is incomplete until `CAP END`, and then makes `CAP END`
wait for `001` (`crates/podssh-core/src/irc/cap.rs`, lines 22-28 at `9460b4e`). Only `on_registration` makes `CAP END`
(`crates/podssh-core/src/irc/cap.rs`, lines 187-193 at `9460b4e`), and only `001` calls it
(`crates/podssh-core/src/irc/session.rs`, lines 323-332 at `9460b4e`). `ACK` and `NAK` send nothing
(`crates/podssh-core/src/irc/cap.rs`, lines 125-144 at `9460b4e`). A test asserts the wrong order
(`crates/podssh-core/tests/session.rs`, lines 200-223 at `9460b4e`). A `421` for `CAP` before `001` sets `Refused`
(`crates/podssh-core/src/irc/session.rs`, lines 318-322 at `9460b4e`), and the live probe can then drop the server
(`crates/podssh-cli/examples/live_irc.rs:220-223`).

Read: `docs/irc.md:20` says that libera, OFTC and tilde refuse the relay's addresses. They support
`CAP`, so this defect alone explains "closed before `001`". The record does not say if that run
used `--no-cap` (`crates/podssh-cli/examples/live_irc.rs:72-74`). The claim is not proven.

## Approach

1. Send `CAP END` when the server answers the last `CAP REQ` with `ACK` or `NAK`, and at once when
   nothing is wanted (`crates/podssh-core/src/irc/cap.rs`, lines 125-144 at `9460b4e`, `crates/podssh-core/src/irc/cap.rs:199-213`).
   Send it after the last line of a list (T-092). Invariant: `CAP END` never waits for `001`.
2. Remove the `001` gate (`crates/podssh-core/src/irc/cap.rs`, lines 183-193 at `9460b4e`,
   `crates/podssh-core/src/irc/session.rs`, lines 325-331 at `9460b4e`). `Stage::Ended` still stops a second `CAP END`.
3. Read a `421` for `CAP` as "no `CAP` here": send no `CAP END`, and do not set `Refused`.
4. Correct the comments at `crates/podssh-core/src/irc/cap.rs`, lines 9-28 at `9460b4e` and
   `crates/podssh-core/src/irc/session.rs`, lines 22-24 at `9460b4e`, and remove the test at
   `crates/podssh-core/tests/session.rs`, lines 200-223 at `9460b4e`. Record the new network results in
   `docs/irc.md:13-25`, and update `docs/STATUS.md:308`, in the same commit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test cap_end
cargo test -p podssh-core --no-fail-fast
cargo run -q -p podssh-cli --example live_irc -- --target irc.undernet.org
```

The new file crates/podssh-core/tests/cap_end.rs holds `cap_end_follows_the_answer_to_the_request`
(`ACK` and `NAK`), `cap_end_is_sent_at_once_when_nothing_is_wanted` and
`cap_end_is_not_sent_after_a_421_for_cap`. Plant: put the `001` gate back; the first test must
fail. The last command is live; it takes a token as `podssh ssh` does, never prints it, and must print
`LIVE-IRC-OK`. With no `--bundle FILE`, it uses podssh's own trust
(`crates/podssh-cli/examples/live_irc.rs:87-92`).
Then run it with `--target irc.libera.chat` and `--target irc.oftc.net`, and record the results.

## Correction

2026-10-10: undernet, libera and OFTC are not among the test targets of `AGENTS.md` (section
4), so the live runs were not made; whether a session may make them is the operator's question
Q39 (`TODO/PROGRESS.md`). The registration was measured against a real server instead: ngircd
27 on the loopback of the build image, which holds the registration until `CAP END`. It also
addresses its `ACK` to the client's nick (`CAP podtest ACK :multi-prefix`), which the parser
read as a verb named `podtest`; step 3 of T-094 repairs that, and is done here, as the repair of
this entry registers on no such server without it.

## Done

2026-10-10. `CAP END` answers the server's `ACK` or `NAK` of the request, and goes at once when
nothing is wanted, with no empty `CAP REQ`; the `001` gate is gone
(`crates/podssh-core/src/irc/cap.rs`, `crates/podssh-core/src/irc/session.rs`). A `421` for
`CAP` is a server with no `CAP`: no `CAP END`, and no refusal of the registration. A server's
`CAP` that names the nick as its target keeps its verb
(`crates/podssh-core/src/irc/command.rs`). The comments say the order that the protocol needs,
and the test that asserted the old order is gone.
- Native, Windows 11: `cargo test -p podssh-core --test cap_end`, 4 passed, over the lines
  that ngircd 27 sent a client (captured in the build image): the `ACK` and the `NAK` each end
  the negotiation, a list that leaves nothing to ask ends it at once, a `421` for `CAP` is no
  refusal while one for another command is, and a `CAP` to a nick keeps its verb. Planted, the
  `001` gate: the first test fails. `cargo test --workspace`: 1122 passed, 0 failed,
  38 ignored.
- In the build image, with ngircd 27 on the loopback: `PODSSH_IRC_SERVER=127.0.0.1:6668 cargo
  test -p podssh-core --test irc_server -- --ignored` registered (`001`). Planted, the `001`
  gate: no `001` in 15 s, the server still waiting after `CAP REQ`, as the defect was. clippy
  with no warning.
- `docs/irc.md` and `docs/STATUS.md` say so. The live runs of the Prove wait for Q39 and T-251.

# T-092: I2: the client asks for each offered capability

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I2 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

When the server lists its capabilities, the client asks for all of them, except a token that is
exactly `sasl`. With `CAP LS 302`, a server sends values, such as `sasl=PLAIN,EXTERNAL`. The client
sends them back in `CAP REQ`, which is not valid, so the server refuses the whole request. A list
on several lines gives one request for each line, with the marker `*` as a capability. The client
can also turn on capabilities that change the lines it reads, such as `extended-join`.

## Premise

Read: `observe` keeps each token except one equal to `sasl`, so `sasl=PLAIN` passes, and it sends
a `REQ` for each `LS` line (`crates/podssh-core/src/irc/cap.rs`, lines 115-125 at `54b90c3`). `request_message` asks for
each offered token (`crates/podssh-core/src/irc/cap.rs`, lines 175-185 at `54b90c3`). `cap_parts` reads the middle
parameters as names (`crates/podssh-core/src/irc/cap.rs`, lines 251-260 at `54b90c3`), so in `CAP * LS * :a b` the
second `*` is a name. podssh needs only `znc.in/self-message`
(`crates/podssh-core/src/irc/mod.rs`, lines 64-72 at `54b90c3`). With `extended-join`, the real name in a `JOIN` echo is
read as keys (`crates/podssh-core/src/irc/command.rs`, lines 60-64 at `93de442`). The one test of the filter uses one
line with no values (`crates/podssh-core/tests/session.rs`, lines 212-224 at `54b90c3`).

Known from `ircv3/ircv3-specifications:extensions/capability-negotiation.md`, not read in this
session: a `REQ` is all or nothing, a `302` list uses `name=value`, and a line with `*` before its
trailing is not the last.

## Approach

1. Parse each token as `name[=value]` (`crates/podssh-core/src/irc/cap.rs`, lines 251-260 at `54b90c3`). Add up the
   lines while a line has the `*` marker, and answer only after the last line.
2. Ask only for names in a constant list of capabilities that podssh implements, next to
   `CAP_SELF_MESSAGE` (`crates/podssh-core/src/irc/mod.rs`, lines 64-72 at `54b90c3`). Never send a value. With no
   wanted name, end at once (T-091).
3. On `ACK`, enable only the names asked for; a `-` prefix turns one off
   (`crates/podssh-core/src/irc/cap.rs`, lines 126-134 at `54b90c3`). Read `NEW` and `DEL` only with `cap-notify`, and
   correct the comment at `crates/podssh-core/src/irc/cap.rs`, lines 144-148 at `54b90c3`, which says `LS`.
4. Update `docs/STATUS.md`, line 308 at `54b90c3` in the same commit.

## Decision

Recommendation: a fixed list of what podssh implements, because a capability can change the
grammar that podssh reads. The alternative, all but a list of refused names (`sasl`, `sts`), lost
because it cannot know what servers add later. Also add `echo-message`, with its own test: it
proves delivery where `znc.in/self-message` is absent, and the session must show each echo once.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test cap_list
cargo test -p podssh-core --no-fail-fast
```

The new file crates/podssh-core/tests/cap_list.rs holds `only_listed_capabilities_are_requested`,
`a_value_is_never_sent_back`, `a_list_on_several_lines_gives_one_request` and
`the_continuation_marker_is_not_a_capability`. Its input is a `CAP LS 302` reply captured from a
real server, kept byte for byte with the server, version and date (`docs/development.md:467-468`).
Plant: remove the list filter; the first test must fail with `sasl=PLAIN` in the `REQ`. Then repeat
the live runs of T-091; the probe prints the offered and enabled capabilities.

## Correction

2026-10-10 (T-094): a `JOIN` of three parameters, which only `extended-join` sends, is no longer
read as keys: the parser keeps it whole, as an unknown command
(`crates/podssh-core/src/irc/command.rs:76-85`), so the session reports no join for it. The fixed
list of step 2 keeps `extended-join` off. Measured in the build image: ergo 2.18.0 lists its
capabilities with values, and the request that sends them back is refused, as the problem says;
the registration still ends (T-091).

2026-10-10 (T-092), captured in the build image from ngircd 27, InspIRCd 4.11.0 with its IRCv3
modules and ergo 2.18.0, where the entry reads otherwise:

- ergo sends its list on two lines, the first `CAP * LS * :…`, and values in both
  (`sasl=PLAIN,EXTERNAL,SCRAM-SHA-256`, `draft/languages=17,en,…`); InspIRCd ends its list with a
  space; ngircd offers `multi-prefix` alone. Each refused `CAP REQ :sasl=PLAIN`, and InspIRCd
  refused `CAP REQ :echo-message znc.in/self-message` whole, as it offers no `self-message`: the
  request names only names that the server offered. ergo writes its `ACK` and `NAK` of one name as
  a middle (`CAP * ACK echo-message`).
- `cap-notify` needs no request: `CAP LS 302` turns it on (IRCv3), and podssh always sends 302, so
  `NEW` and `DEL` are read.
- With `echo-message` on, a message to the client's own nick came back twice, as delivered and as
  echoed, one copy after the other, on InspIRCd and on ergo; a message to a channel came back once.
  The session shows the second copy no more (`Event::Echo`), and an echo of a file line is no line
  of a peer's.
- The plant of the Prove now shows `sasl`, not `sasl=PLAIN`, in the request: a value is left out
  as the list is read.

## Done

2026-10-10, in the commit that closes this entry. Each token of a `CAP` list is read as
`name[=value]`, the value left out; the names of an `LS` add up while a line has the `*` marker,
and one request goes after the last line, of the names of `WANTED_CAPS`
(`crates/podssh-core/src/irc/mod.rs`) that the server offers: `echo-message` and
`znc.in/self-message`, never a value; with none, `CAP END` at once. An `ACK` enables only what was
asked, and `-name` turns one off; `NEW` and `DEL` are read. With `echo-message`, a message of this
client that comes back is `Event::Echo`, shown once, and the live probe takes it as its proof.
`docs/irc.md` and `docs/STATUS.md` say so; the tests of T-091 now take InspIRCd's lines for a
request and its answer, as ngircd's list leaves nothing to ask.

Native, Windows 11: `cargo test -p podssh-core --test cap_list`, 7 passed, on the replies and the
echoes captured byte for byte; `cargo test -p podssh-core`, 107 passed, 0 failed, 1 ignored.
Planted, a request with no list filter: the first test fails, with `sasl` and each other offered
name in the request. clippy with `-D warnings`: no warning. `cargo test --workspace
--no-fail-fast`: 1182 passed, 0 failed, 38 ignored. In the build image, `cargo test -p
podssh-core --test irc_server -- --ignored` registered and joined a channel on each of the three:
enabled nothing on ngircd, `echo-message` on InspIRCd, and both on ergo. Waits for Q39 and T-251:
the live runs on public networks.

# T-093: I3: text is not checked for CR, LF and NUL

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I3 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The client puts its caller's text into IRC lines with no check. `send_privmsg("#c", "a\r\nQUIT")`
writes two lines, and the server runs the second as a command. A channel name, a nick, a reason and
the file name of a transfer offer have the same problem. A future `podssh chat` passes text from a
user, a file or another program.

## Premise

Read: `send_privmsg` checks the registration and the length only
(`crates/podssh-core/src/irc/session_send.rs`, lines 25-39 at `c3eb09d`). `to_line` joins the parameters with no check,
and `to_wire` adds the CRLF (`crates/podssh-core/src/irc/encode.rs`, lines 64-95 at `c3eb09d`). The other writers do not
check either (`crates/podssh-core/src/irc/session_send.rs`, lines 46-60 at `c3eb09d`,
`crates/podssh-core/src/irc/session_send.rs`, lines 93-95 at `c3eb09d`, `crates/podssh-core/src/irc/session_parts.rs`, lines 64-90 at `93de442`).
The offer and `deny` write a name or a reason between `|` separators as it is
(`crates/podssh-core/src/irc/transfer/wire.rs`, lines 225-229 at `c3eb09d`, `crates/podssh-core/src/irc/transfer/wire.rs`, lines 272-277 at `c3eb09d`).

Read: the receiver keeps the peer's file name as it arrives
(`crates/podssh-core/src/irc/transfer/wire.rs`, lines 183-191 at `c3eb09d`). A caller that writes the file under that
name can write outside its directory with `../`. That half is not in row I3, but the same check
covers it.

## Approach

1. Check each parameter in `Message::to_wire` (`crates/podssh-core/src/irc/encode.rs`, lines 92-95 at `c3eb09d`), which
   each written byte passes, and make it return `Result`. A middle is not empty, does not start
   with `:`, and has no space, CR, LF or NUL. A trailing has no CR, LF or NUL.
2. Refuse early in `send_privmsg` with a new `SessionError::Unsafe`, which names the field and the
   character, escaped.
3. Refuse a transfer name or reason with `|`, CR, LF or NUL. On receive, give the caller a base
   name only (`crates/podssh-core/src/irc/transfer/recv.rs`, lines 89-91 at `c3eb09d`).
4. Update the callers (`crates/podssh-cli/examples/live_irc/support.rs:197-205`) and
   `docs/STATUS.md:308` in the same commit.

## Decision

Recommendation: refuse; never remove characters and never split. The module's rule is "a refusal,
never a truncation" (`crates/podssh-core/src/irc/session_send.rs:8-11`), and `--sendfile` already
sends each line as one message (`crates/podssh-cli/src/flags.rs:268-269`). The alternative, remove
CR and LF, lost because it changes the user's text with no message.

2026-10-10, in the work:
- `send_join` and `send_part` refuse before they change the session's memory, as `send_privmsg`
  does, and return `Result`. With the check in the encoder alone, a channel that it refuses would
  stay remembered, and be refused again at each reconnect; a refused `PART` now forgets nothing.
  A `,` in a channel or a key is refused there too: `JOIN` and `PART` write their lists with
  commas, so it would name a second channel that the memory does not know. Taking a list in one
  call lost, as the memory keeps one name for each channel.
- `Sender::new` checks the transfer's id and the file's name, once, and returns `Result`: each
  line carries the id, and the offer the name. An empty id or name is refused, as the peer would
  read an empty field; an empty reason of `deny` stays legal, as the format allows it.
- The base name is what follows the last `/` or `\`, the same on each system. `Path::file_name`
  lost: its answer differs between Windows and Linux. A name with no base (empty, `.` or `..`), a
  `:` (on Windows `C:x` is a path on drive C, and `a:b` a stream) or a control character is
  refused, not changed: taking what follows a `:` too lost, as it renames `notes:v2` with no
  word.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test unsafe_text
cargo test -p podssh-core --no-fail-fast
```

The new file crates/podssh-core/tests/unsafe_text.rs (the session and transfer test files have 469
and 473 lines) holds `crlf_in_a_privmsg_is_refused`, `nul_cr_or_lf_in_each_parameter_is_refused`,
`a_space_in_a_target_is_refused`, `an_offer_name_with_a_bar_is_refused` and
`a_peer_file_name_becomes_a_base_name`. Plant: remove the check from `to_wire`; the first test must
fail, because the wire then holds `\r\nQUIT`. The second command shows that the callers still pass.

## Done

2026-10-10. A caller's text cannot change the line it is written in.
- `Message::to_wire` checks each part and returns `Result` (`crates/podssh-core/src/irc/encode.rs`):
  a CR, LF or NUL anywhere is refused, and so are a space, a leading `:` or nothing in a middle
  (each parameter but the trailing, the prefix and the command) and a space, `;` or `=` in a
  tag's key. The refusal, `Unsafe`, names the field and the character, escaped, and its byte.
  `to_line` stays unchecked, for logs and round trips.
- The session refuses first, by the caller's names (`SessionError::Unsafe`;
  `crates/podssh-core/src/irc/session_send.rs`): `send_privmsg` the target and the text, and
  `send_join` and `send_part` the channel, the key and the reason, before they change the memory.
- `Sender::new` and `deny` refuse `|`, CR, LF and NUL in the transfer's id, the file's name and
  the reason (`check_field`), and the receiver keeps the peer's name as a base name (`base_name`,
  `crates/podssh-core/src/irc/transfer/recv.rs`). The live example says why a message was not
  sent, and the test with a real server writes through `to_wire`.
- Native, Windows 11: `cargo test -p podssh-core --test unsafe_text`, 5 passed: the tests of the
  Prove, over each parameter of `PRIVMSG`, `NOTICE`, `JOIN`, `PART`, `TOPIC`, `QUIT`, `PONG`,
  `NICK`, `USER` and `CAP`, the command, the prefix and a tag's key, each with NUL, CR and LF and
  a control that passes. Planted, `to_wire` with no check: `crlf_in_a_privmsg_is_refused` fails,
  the wire holding `\r\nQUIT`, and two other tests with it; planted, the receiver keeping the
  peer's name: `a_peer_file_name_becomes_a_base_name` fails. `cargo test -p podssh-core
  --no-fail-fast`: 90 passed, 0 failed, 1 ignored. clippy with no warning. `cargo test
  --workspace`: 1127 passed, 0 failed, 38 ignored.

# T-094: I4: trailing forms of JOIN, NICK and PRIVMSG are dropped

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I4 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The last IRC parameter can come with or without a colon. The parser wants a middle for `JOIN` and
`NICK`, and a trailing for `PRIVMSG` and `NOTICE`. Thus `:a!u@h JOIN :#c`, `:a!u@h NICK :b` and
`:a!u@h PRIVMSG #c word` do not parse, and the session drops them. A `CAP` reply to a nick, such as
`CAP alice ACK :x`, gets the verb `Unknown`, so the negotiation stops.

## Premise

Read: `JOIN` and `NICK` count middles only (`crates/podssh-core/src/irc/command.rs`, lines 49-51 at `93de442`,
`crates/podssh-core/src/irc/command.rs`, lines 119-122 at `93de442`). `PRIVMSG` and `NOTICE` require a trailing
(`crates/podssh-core/src/irc/command.rs`, lines 39-48 at `93de442`). A line that does not parse is dropped
(`crates/podssh-core/src/irc/session.rs`, lines 314-325 at `36166be`). `JOIN` reads keys from the trailing
(`crates/podssh-core/src/irc/command.rs`, lines 60-64 at `93de442`), but the encoder writes them as a middle
(`crates/podssh-core/src/irc/command_view.rs`, lines 28-39 at `93de442`), so a parsed `JOIN #c key` loses its key.
`CAP` takes only `*` as a target (`crates/podssh-core/src/irc/command.rs`, lines 147-164 at `9460b4e`); a nick then
stands where the verb must be, and `observe` sends nothing (`crates/podssh-core/src/irc/cap.rs:189`).

Read: the fixture has none of these forms, and no line in it was captured from a real server
(`crates/podssh-core/tests/fixtures/grammar.txt`, lines 8-11 at `93de442`). Which server sends which form is not
measured here.

## Approach

1. Count the trailing as the last parameter: one list, the middles and then the trailing, read by
   position (`crates/podssh-core/src/irc/command.rs`, lines 25-36 at `93de442`). Keep `Trailing.colon`, so a parsed line
   encodes to the same bytes (`crates/podssh-core/src/irc/message.rs`, lines 214-233 at `93de442`).
2. `JOIN`: the channels from the first parameter, the keys from the second. `NICK`: the first
   parameter. `PRIVMSG` and `NOTICE`: the target and the last parameter; no text stays an error.
3. `CAP`: when the second parameter is a verb, the first is the target, `*` or a nick.
4. Capture these forms from real servers into the fixture, with the server, version and date. Add
   the capture option to `crates/podssh-cli/examples/live_irc/support.rs`, because the probe's main
   file has 473 lines. Update `docs/STATUS.md:308`. T-198 fuzzes this parser later.

## Decision

Recommendation: one parameter list for all commands. The alternative, a repair in each match arm,
lost because the next command with an optional colon then fails in the same way.

2026-10-10, in the work:
- A `colon` on `Join`, `Part`, `Mode` and `Nick`, whose last parameter can sit in a middle field;
  a trailing field keeps its own. None on `Message`, which 28 places build. `Names` and `List`,
  which only a client sends, read a trailing as their last channel and write it as a middle,
  with the same meaning.
- A known command with more parameters than its grammar is kept whole, as `Unknown`: the
  `JOIN #c account :Real Name` of `extended-join` would otherwise give a key, and
  `PRIVMSG #c word more` a text that no server would deliver. T-092 asks only for capabilities
  that podssh reads, so a `JOIN` of three parameters does not arrive. Reading the first fields
  and dropping the rest lost: the line would encode to other bytes, and its meaning is not
  podssh's to guess.
- `PING` keeps its token as before, the middles joined with a space: no measured server writes
  it in another form. `PONG` gains the server that a server's answer names first: the
  keepalive of T-098 matches the token of that answer, which ergo writes as a middle.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test grammar
cargo test -p podssh-core --no-fail-fast
```

New tests in crates/podssh-core/tests/grammar.rs: `the_trailing_forms_of_join_nick_and_privmsg_parse`
(over the captured lines), `a_parsed_join_keeps_its_key` and `a_cap_reply_to_a_nick_keeps_its_verb`.
The test `every_fixture_line_parses_and_re_encodes_to_itself` must pass over the new lines too.
Plant: require a middle for `JOIN` again; the first test must fail. The second command runs the
session tests on the new parser.

## Correction

2026-10-10 (T-091): step 3 is done. A `CAP` whose second parameter is a verb takes the first as
its target, `*` or a nick (`crates/podssh-core/src/irc/command.rs`), as ngircd 27 answers
`CAP podtest ACK :multi-prefix`; `a_server_s_cap_names_its_target_a_star_or_the_nick` in
`crates/podssh-core/tests/cap_end.rs` checks it over ngircd's lines, and stands for the test
`a_cap_reply_to_a_nick_keeps_its_verb` of the Prove.

2026-10-10, measured: captured in the build image, on the loopback, with three clients that sent
each form with and without its colon: ngircd 27, ergo 2.18.0 and InspIRCd 4.11.0 (charybdis 4.1.2
did not start with a minimal configuration). ngircd and InspIRCd write `JOIN :#t` and
`NICK :pa2`, ergo `JOIN #t` and `NICK pa2`. ergo also writes `TOPIC #t newtopic`,
`PART #t bye` and `QUIT Quit`, which the parser read as no topic, a second channel and no
reason; InspIRCd writes `MODE #t +k :secret` and ngircd `MODE pa2 :+i`, whose last flag the
parser dropped. No server wrote a `PRIVMSG` or `NOTICE` without its colon. So the defect is
wider than the problem says: each command that read its last field in one form only. And
InspIRCd 4 with no cap module answers nothing to `CAP LS`, not even `421`, and welcomes the
client: the negotiation of T-091 then stayed at `LsSent`, which this entry repairs too.

## Done

2026-10-10. Each field of a command is read by its place in one list, the middles and then the
trailing, and a last parameter in a middle field keeps how it was written
(`crates/podssh-core/src/irc/command.rs`; `colon` in `crates/podssh-core/src/irc/message.rs`,
written back by `crates/podssh-core/src/irc/encode.rs`). `JOIN :#t`, `NICK :pa2`,
`PART #t bye`, `TOPIC #t newtopic`, `QUIT Quit`, `MODE #t +k :secret` and `PRIVMSG #c word`
parse, and encode to their own bytes; so does a server's answer to `PING`, `PONG <server>
[:]<token>`, whose server `Command::Pong` now keeps; a parsed `JOIN #c key` keeps its key; a
known command with more parameters than its grammar is kept whole. A welcome before any answer
to `CAP LS` ends the negotiation (`crates/podssh-core/src/irc/session.rs`). The fixture holds 23
lines captured from the three servers, each named with its version and the date
(`crates/podssh-core/tests/fixtures/grammar.txt`). The live probe writes each byte that a server
sends to `--capture FILE`, with a line `# HOST:PORT` before each session
(`crates/podssh-cli/examples/live_irc/support.rs`): 73 when the file cannot be made, 64 with no
file, measured.
- Native, Windows 11: `cargo test -p podssh-core --test grammar`, 17 passed: the new
  `the_trailing_forms_of_join_nick_and_privmsg_parse` over the captured lines,
  `a_server_s_pong_names_the_server_then_the_token`, `a_parsed_join_keeps_its_key` and
  `a_known_command_with_more_parameters_than_its_grammar_is_kept_whole`, and
  `every_fixture_line_parses_and_re_encodes_to_itself` over the 23 new lines. `--test session`:
  `a_join_echo_and_a_part_in_either_form_reach_the_session`; `--test cap_end`:
  `a_welcome_before_any_answer_to_cap_ls_ends_the_negotiation`, over InspIRCd's line. Planted, a
  `JOIN` that wants a middle: the first test and the round trip of the fixture fail; planted, no
  end at the welcome: the new test of `cap_end` fails. `cargo test -p podssh-core
  --no-fail-fast`: 96 passed, 0 failed, 1 ignored. clippy with no warning. `cargo test
  --workspace`: 1133 passed, 0 failed, 38 ignored.
- In the build image, `PODSSH_IRC_SERVER=127.0.0.1:PORT cargo test -p podssh-core --test
  irc_server -- --ignored`, which now also joins a channel and waits for the server's echo of the
  `JOIN`: passed with ngircd 27, InspIRCd 4.11.0 and ergo 2.18.0. Planted, a `JOIN` that wants a
  middle: with ngircd, `unparsed line dropped: JOIN needs 1 parameter(s)`, and no join in 15 s.
- The runs of the live probe with `--capture` on public networks wait for Q39 and T-251.

# T-095: I5: PART, KICK, 005, a new connection and 433 are handled incorrectly

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I5 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The session does not know its own nick, so it takes each `JOIN` and `PART` as its own. A `PART` by
any user removes the channel, so a reconnect does not join it again. A `KICK` is not handled, so a
reconnect joins a channel that the user was removed from. Each `005` line replaces the lines
before it. A reconnect keeps the old state. A `433` during registration ends the session.

## Premise

Read: `Session` has no field for its nick (`crates/podssh-core/src/irc/session.rs`, lines 162-182 at `36166be`), and
`JOIN` and `PART` ignore the prefix (`crates/podssh-core/src/irc/session.rs`, lines 369-385 at `36166be`). The test
named for a kick sends another user's `PART` and expects the channel to go
(`crates/podssh-core/tests/session.rs`, lines 163-172 at `36166be`): it asserts the defect. `KICK` has no variant
(`crates/podssh-core/src/irc/message.rs`, lines 115-206 at `36166be`), and it ends as "unhandled command"
(`crates/podssh-core/src/irc/session.rs`, lines 422-428 at `36166be`). Each `005` builds a new map
(`crates/podssh-core/src/irc/session.rs`, lines 337-340 at `36166be`).

Read: `reconnect_burst` only adds `JOIN` lines (`crates/podssh-core/src/irc/session.rs`, lines 250-256 at `36166be`).
`registered` stays `Yes`, the reassembler keeps its `overflowed` flag, and `pending_pongs` keeps old
tokens. `Negotiation::reconnect` has no caller (`crates/podssh-core/src/irc/cap.rs`, lines 232-241 at `36166be`). A
`433` sets `Refused` and sends nothing (`crates/podssh-core/src/irc/session.rs`, lines 353-357 at `36166be`), against
its comment (`crates/podssh-core/src/irc/session.rs`, lines 40-44 at `36166be`). A test asserts the refusal
(`crates/podssh-core/tests/session.rs`, lines 243-252 at `36166be`), and the live probe works around it
(`crates/podssh-cli/examples/live_irc.rs`, lines 221-228 at `36166be`).

## Approach

1. Keep the current nick: from the target of `001` (`crates/podssh-core/src/irc/numeric.rs`, lines 149-151 at `36166be`)
   and from each `NICK` of that nick. Compare nicks with the server's `CASEMAPPING`
   (`crates/podssh-core/src/irc/isupport.rs`, lines 138-154 at `36166be`), not with ASCII only.
2. Change the channel memory on `JOIN` and `PART` only for the current nick. The joins and parts of
   other users become events about them.
3. Add `Command::Kick { channel, user, reason }`; forget the channel only when `user` is the current
   nick. Keep `crates/podssh-core/src/irc/message.rs` (419 lines) at 500 lines or fewer.
4. Merge the `005` lines into one `Isupport`; a `-TOKEN` removes a token.
5. Make `reconnect_burst` set `registered` to `Pending`, call `Negotiation::reconnect`, and make a
   new `Reassembler`, `pending_pongs` and `Isupport`. Keep `ChannelMemory`.
6. On a `433` before `001`, send `NICK` with a suffix that fits `NICKLEN`, three times at most, and
   then report `Refused`. After `001`, a `433` is an event.
7. Rewrite the two tests, remove the work-around, and update `docs/STATUS.md`, line 308 at `36166be`, in one commit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test own_nick
cargo test -p podssh-core --no-fail-fast
cargo run -q -p podssh-cli --example live_irc -- --target irc.undernet.org --pair ID --role listen
```

The new file crates/podssh-core/tests/own_nick.rs has one test for each rule above, such as
`a_part_by_another_user_keeps_the_channel`; its `005` case uses the lines captured in T-094. Plant:
remove the prefix check on `PART`; that test must fail. The last command is live: run it with
`--role send` and the same ID in a second shell, as two separate clients (`docs/irc.md:23-25`).
Both must print `LIVE-IRC-OK`, so the reset does not break registration.

## Correction

2026-10-10: the Prove's `005` case wanted the lines that T-094 captured, and its log kept only
ngircd's. The lines of this entry were captured again from the three servers in the build image:
each sends several `005` lines (ngircd 27 two, InspIRCd 4.11.0 and ergo 2.18.0 three), with
`CASEMAPPING` in the first and `NICKLEN` in a later one; a `KICK`'s reason comes as the trailing
from ngircd and InspIRCd and as a middle from ergo (`KICK #t pb out`); a nick in use before
registration is `433 * pa`, and the welcome after `NICK pa_` names `pa_`. The live run of the Prove
goes to undernet, which waits for Q39.

## Done

2026-10-10, in the commit that closes this entry. The session keeps its nick
(`crates/podssh-core/src/irc/session_recv.rs`): the target of `001`, then each `NICK` of it,
compared by `CASEMAPPING` (`Isupport::same`). A `JOIN` or a `PART` changes the channels to rejoin
only for that nick, and another user's is `Event::PeerJoined` or `Event::PeerLeft`. `KICK` has its
command; a kick of this client forgets the channel (`Event::Kicked`), of another is
`Event::PeerLeft`. The `005` lines add up, and `-TOKEN` takes one away. `reconnect_burst` starts a
new connection: not registered, the negotiation again, a new reassembler, no pongs, no `005`, the
wanted nick, and the same channels. A `433` before `001` sends `NICK` with `_`, `__` and `___`, cut
to fit `NICKLEN`, then refuses; after `001` it is an event. The two tests that held the defects are
rewritten, the live probe's own retry is gone, and `session.rs` gives its receive path to
`session_recv.rs`, as it went over 500 lines. `docs/irc.md` and `docs/STATUS.md` say so.

Native, Windows 11: `cargo test -p podssh-core --test own_nick`, 7 passed, on the captured lines;
`cargo test -p podssh-core`, 115 passed, 0 failed, 1 ignored. Planted, a `PART` with no prefix
check: `a_part_by_another_user_keeps_the_channel` fails. clippy with `-D warnings`: no warning.
`cargo test --workspace --no-fail-fast`: 1190 passed, 0 failed, 38 ignored. In the build
image, `--test irc_server -- --ignored` registered and joined on ngircd, InspIRCd and ergo. Waits
for Q39 and T-251: the live pair on undernet.
# T-096: I6: the line framing loses lines, and its buffer has no limit

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I6 (high). Confirmed
here on `3ee70dc` by reading the code and its tests.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The reassembler returns an error for a whole push when one line in it is too long or is not UTF-8,
so the good lines before it in that push are lost. After a complete line that is too long, the next
good line is skipped too. While a peer sends a line with no end, the buffer grows with no limit. A
line in Latin-1, which older networks carry, ends the session.

## Premise

Read: `drain` returns `Err` on a long or non-UTF-8 line, and the lines in `out` are lost
(`crates/podssh-core/src/irc/framing.rs`, lines 128-195 at `016baab`); the comment at
`crates/podssh-core/src/irc/framing.rs`, lines 188-192 at `016baab` says the opposite. After a complete long line, it
sets `overflowed` (`crates/podssh-core/src/irc/framing.rs`, lines 174-183 at `016baab`), although the LF of that line is
gone (`crates/podssh-core/src/irc/framing.rs`, line 145 at `016baab`). The next push then skips the next complete line
(`crates/podssh-core/src/irc/framing.rs`, lines 131-137 at `016baab`). The control test shows it: `PING :after` never
comes out (`crates/podssh-core/tests/reassembly.rs`, lines 231-247 at `016baab`). With no LF, the bytes stay and grow
(`crates/podssh-core/src/irc/framing.rs`, lines 197-202 at `016baab`, `crates/podssh-core/src/irc/framing.rs`, lines 92-95 at `016baab`).

Read: a non-UTF-8 line is an error (`crates/podssh-core/src/irc/framing.rs`, lines 212-226 at `016baab`), which
`Session::on_bytes` returns with `?` (`crates/podssh-core/src/irc/session.rs`, lines 268-269 at `016baab`). The live
probe then ends the attempt (`crates/podssh-cli/examples/live_irc/support.rs`, lines 156-159 at `016baab`). The only
network that took the relay is undernet (`docs/irc.md:22`); its use of Latin-1 is not measured.

## Approach

1. Return the good lines and the errors together. One bad line never hides another line.
2. Set `overflowed` only for a line with no end yet. While it is set, keep no bytes: drop all up to
   the next LF, so the buffer stays at `max_line` or less.
3. Decode a non-UTF-8 line as Latin-1, and mark it, so the caller can say so.
4. In `Session::on_bytes`, turn each line error into `Event::Protocol`, and go on
   (`crates/podssh-core/src/irc/session.rs`, lines 265-280 at `016baab`).
5. Correct the comments at `crates/podssh-core/src/irc/framing.rs`, lines 28-33 at `016baab` (the quote is about case
   mapping) and `crates/podssh-core/src/irc/framing.rs`, lines 121-126 at `016baab`. Update `docs/STATUS.md:308`.

## Decision

Recommendation: Latin-1 when UTF-8 fails. Each byte keeps its character, and Latin-1 is the usual
older encoding on IRC. U+FFFD for each bad byte lost because it destroys text that the user can
read. Keeping the error lost because one line from one user then ends the session.

2026-10-10, in the work:
- `push` returns what each line became, in order: `Framed::Line`, `Framed::Latin1` or
  `Framed::Lost`. `Session::on_bytes` then cannot fail, so it returns the messages and the events
  and no `Result`, and `SessionError::Frame` is gone. Keeping a `Result` that never fails lost: its
  caller would still handle an error that cannot come.
- A line with no end yet is over the limit once the buffer holds `max_line` bytes: a legal one
  holds its content and the CR of its CRLF, `max_line - 1` at most. The old check, the buffer
  plus 2, took a legal line at the limit that a frame split after its CR for an over-long one.
  Such a line is reported once, when it passes the limit, with what had come of it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test reassembly
cargo test -p podssh-core --test framing_limits
```

Change the test at `crates/podssh-core/tests/reassembly.rs`, lines 225-256 at `016baab` to expect `PING :after`. The new
file crates/podssh-core/tests/framing_limits.rs holds `lines_before_a_bad_line_are_kept`,
`an_endless_line_keeps_the_buffer_at_the_limit` (1 MiB with no LF in 64 KiB pushes; `pending_len()`
stays at `DEFAULT_MAX_LINE` or less) and `latin1_text_is_decoded` (the byte `0xe9` becomes U+00E9).
Plant: set `overflowed` after a complete long line again; the changed test must fail.

## Done

2026-10-10. The reassembler hands out the lines and the losses together, in their order
(`crates/podssh-core/src/irc/framing.rs`): a line past the limit is `Framed::Lost`, and the lines
before and after it come out; `overflowed` is set only for a line with no end yet, and while it is
set no byte of that line is kept, so the buffer holds `max_line - 1` bytes at most. A line that is
not UTF-8 is read as Latin-1 and marked `Framed::Latin1`. `Session::on_bytes` turns each loss and
each Latin-1 line into an `Event::Protocol` and goes on (`crates/podssh-core/src/irc/session.rs`);
the live probe no longer ends an attempt on a bad line. The comments that said the opposite, or
quoted RFC 2812 for what it does not say, are corrected.
- Native, Windows 11: `cargo test -p podssh-core --test reassembly`, 16 passed, the control now
  expecting `PING :after`; `--test framing_limits`, 4 passed: `lines_before_a_bad_line_are_kept`,
  `an_endless_line_keeps_the_buffer_at_the_limit` (1 MiB with no LF in 64 KiB pushes,
  `pending_len()` at `DEFAULT_MAX_LINE` or less), `latin1_text_is_decoded` (`0xe9` is U+00E9, and the
  session reads the line and says so) and `a_line_at_the_limit_split_after_its_cr_is_kept`.
  Planted, `overflowed` set after a complete long line: the changed test fails, and two others;
  planted, the bytes of a skipped line kept: the buffer test fails at 65536 bytes held.
  `cargo test -p podssh-core --no-fail-fast`: 100 passed, 0 failed, 1 ignored. clippy with no
  warning. `cargo test --workspace`: 1137 passed, 0 failed, 38 ignored.

# T-097: I7: file chunks are too long with the server's prefix, and the last acknowledgement is wrong

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I7 (high). Confirmed
here on `3ee70dc` by reading the code; the line lengths are computed from the format.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A file chunk fits in 512 bytes as podssh writes it, but the server adds `:nick!user@host ` when it
relays the line, which can then pass 512 bytes. A server that cuts it there breaks the base64, and
the receiver refuses the chunk. When the last chunk is short, the receiver acknowledges the chunk
before it, so the sender never finishes. Each acknowledgement goes to a fixed channel, `#transfer`.
The transfer never ran against a real server.

## Premise

Read: `chunk_line_length` measures a line to `#x` with no prefix
(`crates/podssh-core/src/irc/transfer/wire.rs`, lines 271-282 at `ab7292d`), and the tests use it
(`crates/podssh-core/tests/transfer.rs`, lines 67-82 at `ab7292d`).

Computed here from the format (`crates/podssh-core/src/irc/transfer/wire.rs`, lines 234-236 at `ab7292d`): a chunk of
320 bytes to `#podssh-1a2b`, with a 16-character id, chunk 196607 at offset 62914240, is 499 bytes
on the wire. With the prefix `:podssh-1a2b3c!~podssh@203.0.113.77 ` the relayed line is 535 bytes;
with a host name of 63 bytes, 586.

Read: `ack` names `bytes_received / chunk_bytes - 1` and sends to `#transfer`
(`crates/podssh-core/src/irc/transfer/recv.rs`, lines 182-187 at `ab7292d`). For 1000 bytes it names chunk 2 after
chunk 3, but the sender waits for 3 (`crates/podssh-core/src/irc/transfer/send.rs`, lines 131-140 at `ab7292d`). No test
calls `ack` (`crates/podssh-core/tests/transfer.rs`, lines 175-176 at `ab7292d`). `accept` writes the bytes before it
checks the index (`crates/podssh-core/src/irc/transfer/recv.rs`, lines 165-177 at `ab7292d`). The receiver keeps the
whole file in memory, for any total that the offer gives (`crates/podssh-core/src/irc/transfer/recv.rs`, lines 87-106 at `ab7292d`).

## Approach

1. Compute the chunk size for each offer: 510 bytes, less the worst prefix
   (`1 + NICKLEN + 1 + USERLEN + 1 + 63 + 1`, from `005`; `USERLEN` is 10 plus 1 when absent), less
   the header. Put it in the offer; the receiver checks against it, between 48 and 320 bytes.
2. `ack(target)`: name the chunk just accepted, by count, and send it to the transfer's target.
3. In `accept`, check the index before the bytes go into the file.
4. Limit the receiver's memory: a size limit from the caller, or a sink that the caller owns. A
   file is taken only when the user accepts it (`docs/decisions.md:44`).
5. Update `docs/irc.md`, lines 31-37 at `ab7292d` and `docs/STATUS.md`, line 308 at `ab7292d` in the same commit.

## Decision

Recommendation: a chunk size for each offer, from the server's limits and the target. The
alternative, a smaller fixed chunk, lost because the prefix and the channel name differ by server
and by channel (a channel name can take 200 bytes). One fixed size is too large on one server or
slow on all.

Decision (2026-10-10): the user name counts `USERLEN` and one more, also when the server sends
`USERLEN`: a server that no ident answered puts a `~` before the name (ngircd 27 writes
`pa!~pa@…`), which its `USERLEN` need not count. The host counts `HOSTLEN` when the server sends it
(InspIRCd 4.11.0 sends 64), else 63. The receiver gives each chunk's bytes to the caller and keeps
only their SHA-256, rather than a limit on the size that it keeps: a caller writes the file where
the user accepted it anyway, and the receiver's memory is then one chunk whatever the offer says.
Lost: a limit on the size, which would still hold up to that limit in memory.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test transfer_relayed
cargo test -p podssh-core --no-fail-fast
```

The new file crates/podssh-core/tests/transfer_relayed.rs holds
`a_chunk_line_fits_512_with_the_worst_prefix` (`NICKLEN` 30, a channel of 50 characters, the last
chunk of 60 MiB), `the_last_ack_names_the_short_last_chunk` (1000 bytes; the sender completes on the
receiver's acks), `the_ack_goes_to_the_transfer_target` and `a_wrong_index_writes_nothing`. Plant:
measure without the prefix again; the first test must fail. Live: 1 MiB between two separate
clients on undernet (`docs/irc.md`, lines 23-25 at `ab7292d`), with equal SHA-256, from a new file of the probe.

## Correction

2026-10-10: measured in the build image, with two clients through each server: a chunk sized for
the relayed line crosses ngircd 27, InspIRCd 4.11.0 and ergo 2.18.0 whole, at 285, 267 and 267
bytes. The sender sends each chunk as soon as the last is acknowledged, and InspIRCd, at its rate
limit of 10 commands a second with no fake lag, closed it within a second of a 64 KiB transfer;
with no rate limit the 64 KiB arrived whole. The pace of the sender is T-275. The live run of the
Prove goes to undernet, which waits for Q39.

## Done

2026-10-10, in the commit that closes this entry. `chunk_bytes` (`crates/podssh-core/src/irc/transfer/wire.rs`)
sizes the chunks of a transfer: the most that keeps the line that the server relays, with the
sender's longest prefix in front, within 512 bytes, from `NICKLEN`, `USERLEN` and `HOSTLEN` of the
server's `005` and the target's name; a multiple of 3, between 48 and 320, else the transfer is
refused. The offer carries the size, and the receiver checks it and the count of chunks. `ack`
names the chunk just accepted by the count, and goes to the target that the caller names. `accept`
checks the index before it takes a byte, and gives the bytes to the caller: the receiver keeps their
SHA-256, and no file. `chunk_line_length` measures a line with the worst prefix. `docs/irc.md` and
`docs/STATUS.md` say so.

Native, Windows 11: `cargo test -p podssh-core --test transfer_relayed`, 6 passed; `cargo test -p
podssh-core`, 121 passed, 0 failed, 2 ignored. Planted, a size without the prefix: chunks of 300
bytes, a relayed line of 618, and the first test fails. clippy with `-D warnings`: no warning. `cargo
test --workspace --no-fail-fast`: 1196 passed, 0 failed, 39 ignored. In the build image,
`--test transfer_server -- --ignored` carried 2000 bytes between two clients through each of the
three servers, and 64 KiB through InspIRCd with no rate limit, each with the same SHA-256. Waits for
Q39 and T-251: 1 MiB on undernet.
# T-098: I8: the keepalive sends a visible channel message

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I8 (medium).
Confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

To stop the relay's idle cut, the client sends a `PRIVMSG` to a channel every 60 s. Its text is
`podssh/N` after a zero-width space. Other clients in the channel show it, and channel logs keep
it. It also needs a channel: a session in no channel has nothing to send. A client `PING` is
payload for the relay too, and nobody sees it.

## Premise

Read: the heartbeat is a `PRIVMSG` to a target (`crates/podssh-core/src/irc/session_send.rs:89-106`)
with the text `\u{200b}podssh/N` (`crates/podssh-core/src/irc/reap.rs:53-64`), every third of 180 s
(`crates/podssh-core/src/irc/reap.rs:38-51`).

Read: the module says that IRC `PONG` lines cannot keep a session open
(`crates/podssh-core/src/irc/reap.rs:5-15`). The relay's rule is about its own keepalives, the
empty frames every 25 s (`docs/relay.md:72-73`, `docs/relay.md:125`). An IRC `PING` and its `PONG`
are bytes of the stream, so they are payload.

Measured on SSH, not on IRC: payload keepalives every 60 s kept a relay session for 602 s; with
none, the relay cut it after 184 s (`docs/STATUS.md:120-121`).

## Approach

1. Send `PING :podssh-<generation>` when the client side is quiet for one period. Reuse
   `payload_plan_for` (`crates/podssh-core/src/irc/reap.rs:105-139`).
2. Count the matching `PONG` as a reception (`received_since_last_beat`). A server answers
   `PONG <server> :<token>`, so match the trailing (`crates/podssh-core/src/irc/command.rs:153-161`).
3. Remove the `PRIVMSG` heartbeat and its parser
   (`crates/podssh-core/src/irc/session_send.rs:89-106`, `crates/podssh-core/src/irc/reap.rs:53-75`,
   `crates/podssh-core/src/irc/session_recv.rs:97-104`). No released podssh sends it.
4. Rewrite the test at `crates/podssh-core/tests/session.rs:319-338`. Correct the comments at
   `crates/podssh-core/src/irc/reap.rs:5-29` and the test name at
   `crates/podssh-core/tests/transfer.rs:382-407`.
5. Update `docs/STATUS.md:308` in the same commit.

Pitfall: a server can limit the rate of `PING` lines. One `PING` in 60 s is far below the usual
limits (not measured).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test keepalive
cargo test -p podssh-core --no-fail-fast
```

The new file crates/podssh-core/tests/keepalive.rs holds `the_keepalive_is_a_ping_and_never_a_privmsg`
and `a_matching_pong_counts_as_a_reception`. Plant: return the `PRIVMSG` heartbeat; the first test
must fail. Live: give the probe an idle mode. An idle session on undernet must stay open for 10 min
with no channel message. With the keepalive off (the control), the relay must close it at about
180 s with `1001 idle timeout` (`docs/relay.md:187`).

## Correction

2026-10-10 (T-094), measured in the build image: to `PING :tok123`, ngircd 27 and InspIRCd 4.11.0
answer `:srv PONG srv :tok123`, and ergo 2.18.0 answers `:ergo.test PONG ergo.test tok123`, the
token as a middle. `Command::Pong` keeps the server and the token, the last parameter in either
form (`crates/podssh-core/src/irc/command.rs:153-161`), so step 2 matches `token`, not only a
trailing; the three lines are in the fixture of the grammar.

# T-099: `podssh chat` on the roads between two podssh ends, end-to-end encrypted

**Source:** `docs/ROADMAP.md:244-246`; the operator's ruling of 2026-10-08 on
chat (`docs/decisions.md`): the roads first, after M6, and IRC as a second
transport (T-252); the decision of 2026-10-01 that two users on constrained
hosts chat and share files (`docs/decisions.md:47`).
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

Two users on constrained hosts must chat and share files. `podssh chat` does
not exist: it exits 70. The IRC client sends plain text that the relay and
the IRC server read, and most public networks refused the relay
(`docs/irc.md:13-25`).

## Premise

Measured on `3ee70dc`: `podssh chat --timeout 5s </dev/null`, and the same
with `podssh irc`, exit 70 with "'chat' is not implemented yet; nothing was
done." Read: podssh executes nothing that it receives and takes no file on
its own (`docs/decisions.md:44`). The roads exist after M6: the reverse road
(T-078, T-083, T-084), the iroh road (T-162), and end-to-end encryption
between two podssh ends (T-088). No flag of `chat` names a peer or a server
today (`crates/podssh-cli/src/flags.rs:265-277`,
`crates/podssh-cli/src/positionals.rs:39-41`).

## Approach

1. The command line: `podssh chat PEER`, where PEER is a node name (the
   reverse road) or an iroh ticket. T-252 adds `--irc SERVER CHANNEL`. Change
   `crates/podssh-cli/src/flags.rs:265-277`, the positionals and the manual in
   the same commit.
2. The protocol, over the encrypted channel of T-088: lines of text, and
   files in chunks with digests, as T-097 does for IRC. A line that the peer
   does not acknowledge shows as not delivered. Invariant: podssh executes
   nothing that it receives, and writes a file only when the user accepts it.
3. A peer that is offline: the sender keeps the lines in memory up to a
   limit, and says so. Nothing goes to disk unasked.
4. The terminal: plain lines on stdin and stdout, so that a script or an
   agent can use it. No TUI: podssh is a CLI (`docs/decisions.md`).
5. A test in two boxes through the live relay, built like the script of
   T-085: text, and files of 0, 1 and 5,000,000 bytes with equal digests.
6. Docs in the same commit: `docs/irc.md` (a section on chat), `docs/cli.md`,
   `docs/STATUS.md`, and the gap of plain text in `SECURITY.md:133`, which the
   roads do not have.

## Decision

The operator ruled on 2026-10-08: the roads first, end to end encrypted, and
IRC as a second transport (T-252). The roads won because both users run
podssh, and no third party reads the text.

## Prove

```sh
cargo test -p podssh-cli --test chat_cli     # the command line and the manual
sh scripts/chat-in-boxes.sh path/to/podssh   # two boxes, the live relay, text and files
```

The script exits 0 when each line and each file arrives once, with equal
digests, and a file that the user did not accept is not written. Planted
defect: write a file with no accept; the script must fail.

# T-252: `podssh chat --irc`: IRC as a second transport for chat

**Source:** the operator's ruling of 2026-10-08 on chat (`docs/decisions.md`):
IRC through public servers as a second transport, after the roads (T-099).
The IRC client in `crates/podssh-core/src/irc/` and its defects T-091 to
T-098.
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The IRC client exists, and no command uses it. A user whose peer does not
run podssh, or who wants a public channel, has no chat.

## Premise

Read: the client is sans-IO, and T-091 to T-098 repair its defects. Measured
on 2026-10-05: of seven public networks, only `irc.undernet.org:6667`
accepted the relay's addresses (`docs/irc.md:13-25`). On port 6667 the relay
and each server read the text (`SECURITY.md:133`).

## Approach

1. After T-091 and T-092: measure the networks again through the relay, on
   port 6667, and on 6697 with TLS inside the relay stream. Record each
   answer with its date in `docs/irc.md:13-25`.
2. `podssh chat --irc SERVER[:PORT] CHANNEL`: TLS inside the relay stream by
   default (port 6697). Plain text on 6667 only with a flag that names the
   risk, and one line about it on stderr. The nick comes from a flag or a
   variable.
3. Files: the chunks with digests of T-097, each only when the user accepts
   it.
4. The same lines on stdin and stdout as T-099, so that a script uses both
   alike.
5. A test against a real IRC server in the gate (a container with an IRC
   daemon), and an ignored live test against one public network.

Added by T-275 (2026-10-10): pace each line of a transfer with `transfer::Pace`, and on a close
during a transfer say that a server may close a client that sends faster than it allows, then
resume from the last acknowledged chunk on the next connection.

## Decision

Recommendation: TLS by default, so that the relay sees only TLS. Plain text
by default lost: the relay and each hop would read each line.

## Prove

```sh
cargo test -p podssh-core
cargo test -p podssh-cli --test chat_irc
sh scripts/dev.sh check      # the gate's IRC server: text and one file with equal digests
```

Planted defect: connect to port 6697 without TLS; the test against the
gate's server must fail at the handshake.

# T-275: The transfer sends as fast as its acknowledgements come, and a server's rate limit closes it

**Source:** T-097 (2026-10-10), measured in the build image with InspIRCd 4.11.0.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A sender writes each chunk as soon as the last one is acknowledged. On a short path that is
dozens of lines a second, and a server that limits the rate of commands, with no fake lag to
slow the client down instead, closes the connection: the transfer ends with no word but the
close.

## Premise

Measured on 2026-10-10 in the build image (`crates/podssh-core/tests/transfer_server.rs`, two
clients on the loopback): through InspIRCd 4.11.0 with its connect class at `commandrate="10000"`
(10 commands a second), `threshold="100"` and `fakelag="no"`, the sender of a 64 KiB transfer was
closed within a second; with no rate limit the same transfer arrived whole, in 246 chunks. Read:
the sender has no pace (`crates/podssh-core/src/irc/transfer/send.rs`); `Sender::next_chunk_message`
gives the next chunk at once after `Sender::acknowledge`.

## Approach

1. A pace for the lines of a transfer, the sender's chunks and the receiver's acknowledgements:
   a rate that a caller sets, with a default that a server's flood control takes (measure the
   defaults of ngircd 27, InspIRCd 4.11.0, ergo 2.18.0 and undernet's ircu), and the time the
   next line may go, so that a sans-IO caller waits it.
2. A close during a transfer says that the server may have closed a fast sender, and the
   transfer resumes from the last acknowledged chunk on the next connection.

## Decision

Decision (2026-10-10): five lines at once, then five a second, by default: half the rate at which
InspIRCd 4.11.0 closed a sender, measured, and above none of the rates that slow a client down
instead (ngircd 27, ergo 2.18.0, InspIRCd's own default). A caller sets another. Lost: no pace,
which a server with no fake lag ends; and a pace learned from the server's lag, which a server
that closes at once gives no time to learn.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test transfer_relayed
```

A test holds the pace: the time of each line, by a clock that the test gives. In the build image,
`--test transfer_server -- --ignored` with `PODSSH_IRC_TRANSFER_BYTES=65536` passes through
InspIRCd with its rate limit at 10 commands a second. Planted: no pace; that run is closed.

## Correction

2026-10-10: step 2 is the work of the command that runs a transfer over IRC, and none does yet:
T-252 builds it, and its Approach now says to pace the lines and to say why a close during a
transfer may come, then resume from the last acknowledged chunk, which the receiver's `accept`
from a chunk index already allows. The defaults of undernet's ircu wait for Q39, with each live
run on a public network.

## Done

2026-10-10, in the commit that closes this entry. `transfer::Pace`
(`crates/podssh-core/src/irc/transfer/pace.rs`) gives the time that the next line of a transfer
waits, by a clock that the caller gives: a burst, then a rate, five and five a second by default.
The test of two clients through a real server paces each chunk and each acknowledgement.
`docs/irc.md`, `docs/STATUS.md` and T-252 say so.

Native, Windows 11: `cargo test -p podssh-core --test transfer_relayed`, 7 passed, the pace among
them, by a clock that the test gives. `cargo test --workspace --no-fail-fast`: 1197 passed, 0
failed, 39 ignored. clippy with `-D warnings`: no warning. In the build image, with
InspIRCd 4.11.0 at `commandrate="10000"`, `threshold="100"` and `fakelag="no"`, `--test
transfer_server -- --ignored` carried 64 KiB paced, in 246 chunks and 50 s, with the same SHA-256;
planted, the same run at 1000 lines a second was closed. Paced, 2000 bytes crossed ngircd 27 and
ergo 2.18.0.
