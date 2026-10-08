This file holds the work on the IRC client in crates/podssh-core/src/irc/: one entry for each row I1
to I8 of the former defects page (`git show 3ee70dc:docs/defects.md`), and the research that
decides how `podssh chat` works (T-099). No command uses the client, and `podssh chat` exits 70.
The client is sans-IO, so its unit tests need no network. The live probe
`crates/podssh-cli/examples/live_irc.rs` reaches real servers through the relay, with a token that
is minted, used and removed in one shell (`docs/development.md:228-236`). Each defect was read
again on `3ee70dc`.

# T-091: I1: `CAP END` is sent only after 001

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I1 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The client sends `CAP LS 302`, `NICK` and `USER`, and then waits for `001` before it sends
`CAP END`. An IRCv3 server holds the registration until it gets `CAP END`, so it never sends
`001`. Both sides wait until the server's registration limit closes the connection. Thus the
client cannot register on a server that supports `CAP`.

## Premise

Read: the comment says that registration is incomplete until `CAP END`, and then makes `CAP END`
wait for `001` (`crates/podssh-core/src/irc/cap.rs:22-28`). Only `on_registration` makes `CAP END`
(`crates/podssh-core/src/irc/cap.rs:194-200`), and only `001` calls it
(`crates/podssh-core/src/irc/session.rs:331-340`). `ACK` and `NAK` send nothing
(`crates/podssh-core/src/irc/cap.rs:128-147`). A test asserts the wrong order
(`crates/podssh-core/tests/session.rs:217-247`). A `421` for `CAP` before `001` sets `Refused`
(`crates/podssh-core/src/irc/session.rs:326-330`), and the live probe can then drop the server
(`crates/podssh-cli/examples/live_irc.rs:232-235`).

Read: `docs/irc.md:18` says that libera, OFTC and tilde refuse the relay's addresses. They support
`CAP`, so this defect alone explains "closed before `001`". The record does not say if that run
used `--no-cap` (`crates/podssh-cli/examples/live_irc.rs:75-77`). The claim is not proven.

## Approach

1. Send `CAP END` when the server answers the last `CAP REQ` with `ACK` or `NAK`, and at once when
   nothing is wanted (`crates/podssh-core/src/irc/cap.rs:128-147`, `crates/podssh-core/src/irc/cap.rs:178-188`).
   Send it after the last line of a list (T-092). Invariant: `CAP END` never waits for `001`.
2. Remove the `001` gate (`crates/podssh-core/src/irc/cap.rs:190-200`,
   `crates/podssh-core/src/irc/session.rs:333-339`). `Stage::Ended` still stops a second `CAP END`.
3. Read a `421` for `CAP` as "no `CAP` here": send no `CAP END`, and do not set `Refused`.
4. Correct the comments at `crates/podssh-core/src/irc/cap.rs:9-28` and
   `crates/podssh-core/src/irc/session.rs:22-24`, and remove the test at
   `crates/podssh-core/tests/session.rs:217-247`. Record the new network results in
   `docs/irc.md:12-24`, and update `docs/STATUS.md:188`, in the same commit.

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
fail. The last command is live, with a token in that shell only, and must print `LIVE-IRC-OK`.
Give `--bundle FILE` when no bundle is at `crates/podssh-cli/examples/live_irc/support.rs:19-23`.
Then run it with `--target irc.libera.chat` and `--target irc.oftc.net`, and record the results.

# T-092: I2: the client asks for each offered capability

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I2 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

When the server lists its capabilities, the client asks for all of them, except a token that is
exactly `sasl`. With `CAP LS 302`, a server sends values, such as `sasl=PLAIN,EXTERNAL`. The client
sends them back in `CAP REQ`, which is not valid, so the server refuses the whole request. A list
on several lines gives one request for each line, with the marker `*` as a capability. The client
can also turn on capabilities that change the lines it reads, such as `extended-join`.

## Premise

Read: `observe` keeps each token except one equal to `sasl`, so `sasl=PLAIN` passes, and it sends
a `REQ` for each `LS` line (`crates/podssh-core/src/irc/cap.rs:114-127`). `request_message` asks for
each offered token (`crates/podssh-core/src/irc/cap.rs:178-188`). `cap_parts` reads the middle
parameters as names (`crates/podssh-core/src/irc/cap.rs:249-258`), so in `CAP * LS * :a b` the
second `*` is a name. podssh needs only `znc.in/self-message`
(`crates/podssh-core/src/irc/mod.rs:66-74`). With `extended-join`, the real name in a `JOIN` echo is
read as keys (`crates/podssh-core/src/irc/command.rs:67-71`). The one test of the filter uses one
line with no values (`crates/podssh-core/tests/session.rs:249-266`).

Known from `ircv3/ircv3-specifications:extensions/capability-negotiation.md`, not read in this
session: a `REQ` is all or nothing, a `302` list uses `name=value`, and a line with `*` before its
trailing is not the last.

## Approach

1. Parse each token as `name[=value]` (`crates/podssh-core/src/irc/cap.rs:249-258`). Add up the
   lines while a line has the `*` marker, and answer only after the last line.
2. Ask only for names in a constant list of capabilities that podssh implements, next to
   `CAP_SELF_MESSAGE` (`crates/podssh-core/src/irc/mod.rs:66-74`). Never send a value. With no
   wanted name, end at once (T-091).
3. On `ACK`, enable only the names asked for; a `-` prefix turns one off
   (`crates/podssh-core/src/irc/cap.rs:128-137`). Read `NEW` and `DEL` only with `cap-notify`, and
   correct the comment at `crates/podssh-core/src/irc/cap.rs:148-152`, which says `LS`.
4. Update `docs/STATUS.md:188` in the same commit.

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
real server, kept byte for byte with the server, version and date (`docs/development.md:242-243`).
Plant: remove the list filter; the first test must fail with `sasl=PLAIN` in the `REQ`. Then repeat
the live runs of T-091; the probe prints the offered and enabled capabilities.

# T-093: I3: text is not checked for CR, LF and NUL

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I3 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The client puts its caller's text into IRC lines with no check. `send_privmsg("#c", "a\r\nQUIT")`
writes two lines, and the server runs the second as a command. A channel name, a nick, a reason and
the file name of a transfer offer have the same problem. A future `podssh chat` passes text from a
user, a file or another program.

## Premise

Read: `send_privmsg` checks the registration and the length only
(`crates/podssh-core/src/irc/session_send.rs:25-42`). `to_line` joins the parameters with no check,
and `to_wire` adds the CRLF (`crates/podssh-core/src/irc/encode.rs:64-95`). The other writers do not
check either (`crates/podssh-core/src/irc/session_send.rs:49-66`,
`crates/podssh-core/src/irc/session_send.rs:99-105`, `crates/podssh-core/src/irc/session_parts.rs:64-97`).
The offer and `deny` write a name or a reason between `|` separators as it is
(`crates/podssh-core/src/irc/transfer/wire.rs:249-253`, `crates/podssh-core/src/irc/transfer/wire.rs:304-312`).

Read: the receiver keeps the peer's file name as it arrives
(`crates/podssh-core/src/irc/transfer/wire.rs:195-203`). A caller that writes the file under that
name can write outside its directory with `../`. That half is not in row I3, but the same check
covers it.

## Approach

1. Check each parameter in `Message::to_wire` (`crates/podssh-core/src/irc/encode.rs:92-95`), which
   each written byte passes, and make it return `Result`. A middle is not empty, does not start
   with `:`, and has no space, CR, LF or NUL. A trailing has no CR, LF or NUL.
2. Refuse early in `send_privmsg` with a new `SessionError::Unsafe`, which names the field and the
   character, escaped.
3. Refuse a transfer name or reason with `|`, CR, LF or NUL. On receive, give the caller a base
   name only (`crates/podssh-core/src/irc/transfer/recv.rs:89-91`).
4. Update the callers (`crates/podssh-cli/examples/live_irc/support.rs:146-158`) and
   `docs/STATUS.md:188` in the same commit.

## Decision

Recommendation: refuse; never remove characters and never split. The module's rule is "a refusal,
never a truncation" (`crates/podssh-core/src/irc/session_send.rs:8-11`), and `--sendfile` already
sends each line as one message (`crates/podssh-cli/src/flags.rs:262-263`). The alternative, remove
CR and LF, lost because it changes the user's text with no message.

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

# T-094: I4: trailing forms of JOIN, NICK and PRIVMSG are dropped

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I4 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The last IRC parameter can come with or without a colon. The parser wants a middle for `JOIN` and
`NICK`, and a trailing for `PRIVMSG` and `NOTICE`. Thus `:a!u@h JOIN :#c`, `:a!u@h NICK :b` and
`:a!u@h PRIVMSG #c word` do not parse, and the session drops them. A `CAP` reply to a nick, such as
`CAP alice ACK :x`, gets the verb `Unknown`, so the negotiation stops.

## Premise

Read: `JOIN` and `NICK` count middles only (`crates/podssh-core/src/irc/command.rs:56-58`,
`crates/podssh-core/src/irc/command.rs:126-129`). `PRIVMSG` and `NOTICE` require a trailing
(`crates/podssh-core/src/irc/command.rs:46-55`). A line that does not parse is dropped
(`crates/podssh-core/src/irc/session.rs:295-306`). `JOIN` reads keys from the trailing
(`crates/podssh-core/src/irc/command.rs:67-71`), but the encoder writes them as a middle
(`crates/podssh-core/src/irc/command_view.rs:28-39`), so a parsed `JOIN #c key` loses its key.
`CAP` takes only `*` as a target (`crates/podssh-core/src/irc/command.rs:160-177`); a nick then
stands where the verb must be, and `observe` sends nothing (`crates/podssh-core/src/irc/cap.rs:170`).

Read: the fixture has none of these forms, and no line in it was captured from a real server
(`crates/podssh-core/tests/fixtures/grammar.txt:8-11`). Which server sends which form is not
measured here.

## Approach

1. Count the trailing as the last parameter: one list, the middles and then the trailing, read by
   position (`crates/podssh-core/src/irc/command.rs:27-43`). Keep `Trailing.colon`, so a parsed line
   encodes to the same bytes (`crates/podssh-core/src/irc/message.rs:188-207`).
2. `JOIN`: the channels from the first parameter, the keys from the second. `NICK`: the first
   parameter. `PRIVMSG` and `NOTICE`: the target and the last parameter; no text stays an error.
3. `CAP`: when the second parameter is a verb, the first is the target, `*` or a nick.
4. Capture these forms from real servers into the fixture, with the server, version and date. Add
   the capture option to `crates/podssh-cli/examples/live_irc/support.rs`, because the probe's main
   file has 473 lines. Update `docs/STATUS.md:188`. T-198 fuzzes this parser later.

## Decision

Recommendation: one parameter list for all commands. The alternative, a repair in each match arm,
lost because the next command with an optional colon then fails in the same way.

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

# T-095: I5: PART, KICK, 005, a new connection and 433 are handled incorrectly

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I5 (high). Confirmed
here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The session does not know its own nick, so it takes each `JOIN` and `PART` as its own. A `PART` by
any user removes the channel, so a reconnect does not join it again. A `KICK` is not handled, so a
reconnect joins a channel that the user was removed from. Each `005` line replaces the lines
before it. A reconnect keeps the old state. A `433` during registration ends the session.

## Premise

Read: `Session` has no field for its nick (`crates/podssh-core/src/irc/session.rs:154-169`), and
`JOIN` and `PART` ignore the prefix (`crates/podssh-core/src/irc/session.rs:346-362`). The test
named for a kick sends another user's `PART` and expects the channel to go
(`crates/podssh-core/tests/session.rs:177-186`): it asserts the defect. `KICK` has no variant
(`crates/podssh-core/src/irc/message.rs:123-166`), and it ends as "unhandled command"
(`crates/podssh-core/src/irc/session.rs:392-398`). Each `005` builds a new map
(`crates/podssh-core/src/irc/session.rs:316-320`).

Read: `reconnect_burst` only adds `JOIN` lines (`crates/podssh-core/src/irc/session.rs:236-242`).
`registered` stays `Yes`, the reassembler keeps its `overflowed` flag, and `pending_pongs` keeps old
tokens. `Negotiation::reconnect` has no caller (`crates/podssh-core/src/irc/cap.rs:202-211`). A
`433` sets `Refused` and sends nothing (`crates/podssh-core/src/irc/session.rs:326-330`), against
its comment (`crates/podssh-core/src/irc/session.rs:43-47`). A test asserts the refusal
(`crates/podssh-core/tests/session.rs:288-297`), and the live probe works around it
(`crates/podssh-cli/examples/live_irc.rs:224-231`).

## Approach

1. Keep the current nick: from the target of `001` (`crates/podssh-core/src/irc/numeric.rs:149-151`)
   and from each `NICK` of that nick. Compare nicks with the server's `CASEMAPPING`
   (`crates/podssh-core/src/irc/isupport.rs:141-157`), not with ASCII only.
2. Change the channel memory on `JOIN` and `PART` only for the current nick. The joins and parts of
   other users become events about them.
3. Add `Command::Kick { channel, user, reason }`; forget the channel only when `user` is the current
   nick. Keep `crates/podssh-core/src/irc/message.rs` (419 lines) at 500 lines or fewer.
4. Merge the `005` lines into one `Isupport`; a `-TOKEN` removes a token.
5. Make `reconnect_burst` set `registered` to `Pending`, call `Negotiation::reconnect`, and make a
   new `Reassembler`, `pending_pongs` and `Isupport`. Keep `ChannelMemory`.
6. On a `433` before `001`, send `NICK` with a suffix that fits `NICKLEN`, three times at most, and
   then report `Refused`. After `001`, a `433` is an event.
7. Rewrite the two tests, remove the work-around, and update `docs/STATUS.md:188`, in one commit.

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
`--role send` and the same ID in a second shell, as two separate clients (`docs/irc.md:22-24`).
Both must print `LIVE-IRC-OK`, so the reset does not break registration.

# T-096: I6: the line framing loses lines, and its buffer has no limit

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I6 (high). Confirmed
here on `3ee70dc` by reading the code and its tests.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The reassembler returns an error for a whole push when one line in it is too long or is not UTF-8,
so the good lines before it in that push are lost. After a complete line that is too long, the next
good line is skipped too. While a peer sends a line with no end, the buffer grows with no limit. A
line in Latin-1, which older networks carry, ends the session.

## Premise

Read: `drain` returns `Err` on a long or non-UTF-8 line, and the lines in `out` are lost
(`crates/podssh-core/src/irc/framing.rs:128-198`); the comment at
`crates/podssh-core/src/irc/framing.rs:191-195` says the opposite. After a complete long line, it
sets `overflowed` (`crates/podssh-core/src/irc/framing.rs:174-186`), although the LF of that line is
gone (`crates/podssh-core/src/irc/framing.rs:145`). The next push then skips the next complete line
(`crates/podssh-core/src/irc/framing.rs:131-137`). The control test shows it: `PING :after` never
comes out (`crates/podssh-core/tests/reassembly.rs:242-258`). With no LF, the bytes stay and grow
(`crates/podssh-core/src/irc/framing.rs:200-205`, `crates/podssh-core/src/irc/framing.rs:92-95`).

Read: a non-UTF-8 line is an error (`crates/podssh-core/src/irc/framing.rs:215-229`), which
`Session::on_bytes` returns with `?` (`crates/podssh-core/src/irc/session.rs:265-266`). The live
probe then ends the attempt (`crates/podssh-cli/examples/live_irc/support.rs:101-104`). The only
network that took the relay is undernet (`docs/irc.md:20`); its use of Latin-1 is not measured.

## Approach

1. Return the good lines and the errors together. One bad line never hides another line.
2. Set `overflowed` only for a line with no end yet. While it is set, keep no bytes: drop all up to
   the next LF, so the buffer stays at `max_line` or less.
3. Decode a non-UTF-8 line as Latin-1, and mark it, so the caller can say so.
4. In `Session::on_bytes`, turn each line error into `Event::Protocol`, and go on
   (`crates/podssh-core/src/irc/session.rs:262-277`).
5. Correct the comments at `crates/podssh-core/src/irc/framing.rs:28-33` (the quote is about case
   mapping) and `crates/podssh-core/src/irc/framing.rs:121-126`. Update `docs/STATUS.md:188`.

## Decision

Recommendation: Latin-1 when UTF-8 fails. Each byte keeps its character, and Latin-1 is the usual
older encoding on IRC. U+FFFD for each bad byte lost because it destroys text that the user can
read. Keeping the error lost because one line from one user then ends the session.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-core --test reassembly
cargo test -p podssh-core --test framing_limits
```

Change the test at `crates/podssh-core/tests/reassembly.rs:236-267` to expect `PING :after`. The new
file crates/podssh-core/tests/framing_limits.rs holds `lines_before_a_bad_line_are_kept`,
`an_endless_line_keeps_the_buffer_at_the_limit` (1 MiB with no LF in 64 KiB pushes; `pending_len()`
stays at `DEFAULT_MAX_LINE` or less) and `latin1_text_is_decoded` (the byte `0xe9` becomes U+00E9).
Plant: set `overflowed` after a complete long line again; the changed test must fail.

# T-097: I7: file chunks are too long with the server's prefix, and the last acknowledgement is wrong

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row I7 (high). Confirmed
here on `3ee70dc` by reading the code; the line lengths are computed from the format.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A file chunk fits in 512 bytes as podssh writes it, but the server adds `:nick!user@host ` when it
relays the line, which can then pass 512 bytes. A server that cuts it there breaks the base64, and
the receiver refuses the chunk. When the last chunk is short, the receiver acknowledges the chunk
before it, so the sender never finishes. Each acknowledgement goes to a fixed channel, `#transfer`.
The transfer never ran against a real server.

## Premise

Read: `chunk_line_length` measures a line to `#x` with no prefix
(`crates/podssh-core/src/irc/transfer/wire.rs:287-301`), and the tests use it
(`crates/podssh-core/tests/transfer.rs:71-89`).

Computed here from the format (`crates/podssh-core/src/irc/transfer/wire.rs:257-259`): a chunk of
320 bytes to `#podssh-1a2b`, with a 16-character id, chunk 196607 at offset 62914240, is 499 bytes
on the wire. With the prefix `:podssh-1a2b3c!~podssh@203.0.113.77 ` the relayed line is 535 bytes;
with a host name of 63 bytes, 586.

Read: `ack` names `bytes_received / chunk_bytes - 1` and sends to `#transfer`
(`crates/podssh-core/src/irc/transfer/recv.rs:162-170`). For 1000 bytes it names chunk 2 after
chunk 3, but the sender waits for 3 (`crates/podssh-core/src/irc/transfer/send.rs:139-148`). No test
calls `ack` (`crates/podssh-core/tests/transfer.rs:186-187`). `accept` writes the bytes before it
checks the index (`crates/podssh-core/src/irc/transfer/recv.rs:145-157`). The receiver keeps the
whole file in memory, for any total that the offer gives (`crates/podssh-core/src/irc/transfer/recv.rs:68-87`).

## Approach

1. Compute the chunk size for each offer: 510 bytes, less the worst prefix
   (`1 + NICKLEN + 1 + USERLEN + 1 + 63 + 1`, from `005`; `USERLEN` is 10 plus 1 when absent), less
   the header. Put it in the offer; the receiver checks against it, between 48 and 320 bytes.
2. `ack(target)`: name the chunk just accepted, by count, and send it to the transfer's target.
3. In `accept`, check the index before the bytes go into the file.
4. Limit the receiver's memory: a size limit from the caller, or a sink that the caller owns. A
   file is taken only when the user accepts it (`docs/decisions.md:41`).
5. Update `docs/irc.md:26-32` and `docs/STATUS.md:188` in the same commit.

## Decision

Recommendation: a chunk size for each offer, from the server's limits and the target. The
alternative, a smaller fixed chunk, lost because the prefix and the channel name differ by server
and by channel (a channel name can take 200 bytes). One fixed size is too large on one server or
slow on all.

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
clients on undernet (`docs/irc.md:22-24`), with equal SHA-256, from a new file of the probe.

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

Read: the heartbeat is a `PRIVMSG` to a target (`crates/podssh-core/src/irc/session_send.rs:68-85`)
with the text `\u{200b}podssh/N` (`crates/podssh-core/src/irc/reap.rs:53-64`), every third of 180 s
(`crates/podssh-core/src/irc/reap.rs:38-51`).

Read: the module says that IRC `PONG` lines cannot keep a session open
(`crates/podssh-core/src/irc/reap.rs:5-15`). The relay's rule is about its own keepalives, the
empty frames every 25 s (`docs/relay.md:61-62`, `docs/relay.md:90`). An IRC `PING` and its `PONG`
are bytes of the stream, so they are payload.

Measured on SSH, not on IRC: payload keepalives every 60 s kept a relay session for 602 s; with
none, the relay cut it after 184 s (`docs/STATUS.md:79-80`).

## Approach

1. Send `PING :podssh-<generation>` when the client side is quiet for one period. Reuse
   `payload_plan_for` (`crates/podssh-core/src/irc/reap.rs:105-139`).
2. Count the matching `PONG` as a reception (`received_since_last_beat`). A server answers
   `PONG <server> :<token>`, so match the trailing (`crates/podssh-core/src/irc/command.rs:125`).
3. Remove the `PRIVMSG` heartbeat and its parser
   (`crates/podssh-core/src/irc/session_send.rs:68-85`, `crates/podssh-core/src/irc/reap.rs:53-75`,
   `crates/podssh-core/src/irc/session.rs:365-372`). No released podssh sends it.
4. Rewrite the test at `crates/podssh-core/tests/session.rs:355-381`. Correct the comments at
   `crates/podssh-core/src/irc/reap.rs:5-29` and the test name at
   `crates/podssh-core/tests/transfer.rs:386-408`.
5. Update `docs/STATUS.md:188` in the same commit.

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
180 s with `1001 idle timeout` (`docs/relay.md:127`).

# T-099: `podssh chat` on the roads between two podssh ends, end-to-end encrypted

**Source:** `docs/ROADMAP.md:237-239`; the operator's ruling of 2026-10-08 on
chat (`docs/decisions.md`): the roads first, after M6, and IRC as a second
transport (T-252); the decision of 2026-10-01 that two users on constrained
hosts chat and share files (`docs/decisions.md:44`).
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

Two users on constrained hosts must chat and share files. `podssh chat` does
not exist: it exits 70. The IRC client sends plain text that the relay and
the IRC server read, and most public networks refused the relay
(`docs/irc.md:12-24`).

## Premise

Measured on `3ee70dc`: `podssh chat --timeout 5s </dev/null`, and the same
with `podssh irc`, exit 70 with "'chat' is not implemented yet; nothing was
done." Read: podssh executes nothing that it receives and takes no file on
its own (`docs/decisions.md:41`). The roads exist after M6: the reverse road
(T-078, T-083, T-084), the iroh road (T-162), and end-to-end encryption
between two podssh ends (T-088). No flag of `chat` names a peer or a server
today (`crates/podssh-cli/src/flags.rs:259-271`,
`crates/podssh-cli/src/positionals.rs:31-33`).

## Approach

1. The command line: `podssh chat PEER`, where PEER is a node name (the
   reverse road) or an iroh ticket. T-252 adds `--irc SERVER CHANNEL`. Change
   `crates/podssh-cli/src/flags.rs:259-271`, the positionals and the manual in
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
   `docs/STATUS.md`, and the gap of plain text in `SECURITY.md:69`, which the
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
accepted the relay's addresses (`docs/irc.md:12-24`). On port 6667 the relay
and each server read the text (`SECURITY.md:69`).

## Approach

1. After T-091 and T-092: measure the networks again through the relay, on
   port 6667, and on 6697 with TLS inside the relay stream. Record each
   answer with its date in `docs/irc.md:12-24`.
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
