# Chat (milestone M8)

`podssh chat` lets two users on constrained hosts talk and exchange files.
It runs between two podssh ends, over the end-to-end channel of a road
(T-099), so the relay sees ciphertext only. IRC through public servers is
the second transport (T-252): podssh speaks IRC itself, and the relay
carries the bytes, as for SSH. No command uses the IRC client yet. It has
known defects ([TODO/irc.md](../TODO/irc.md), T-097 and T-098): among them,
it sends plain text through the relay. Since T-091 the registration finishes
on a server that holds it until `CAP END`: measured with ngircd 27 on the
loopback of the build image, 2026-10-10.

The operator ruled on 2026-10-08: the roads first, and IRC second
([decisions.md](decisions.md); [design.md](design.md), section 8).

## Between two podssh ends

One side waits, and the other reaches it, as on each road:

```sh
podssh relay pair NAME        # once: the pair, kept under the label NAME
podssh chat --listen NAME     # the side that waits: the node of the pair
podssh chat NAME              # the side that reaches: its operator
```

The side that reaches needs the pair too, or its operator's part in
`--pair-file`. `podssh man chat` has each flag.

- Each line of stdin is a message, and each message of the peer is a line of
  stdout, `NICK: TEXT`, with each control character and each direction
  override removed, as from each text of a peer. `/file PATH` offers a file, `/accept ID [PATH]` takes
  one, `/decline ID` refuses it, `/quit` ends, and `//` starts a message with
  `/`. Notices go to stderr; `--jsonl` puts each message and each event on
  stdout as one JSON object. Nothing that the peer sends is run.
- A file is written only once the user accepts it, with `/accept` or with
  `--accept-dir DIR`: under a temporary name in its directory, checked
  against the SHA-256 of the offer, then given its name with a hard link,
  which fails on a file that is there. Its name is the last part of the
  offered one. The peer hears whether the file was kept.
- The peer acknowledges each message. A message with no acknowledgement when
  a conversation ends is said, as not delivered, and the exit is 0 only when
  each was acknowledged.
- One peer at a time: another is told that the chat is busy, and exits 75.
  When the peer leaves, the side that waits takes the next one.
- While no peer is there, the lines wait in memory, 1000 lines or 1 MiB at
  most; podssh then reads no more input until some go, and says so. The side
  that reaches tries again each 5 s while the relay answers that no node
  serves the pair (`503 reverse: node offline`), or after the peer left.
- For a script: `--send MESSAGE` ends once the message is acknowledged,
  `--file PATH` once the file arrived whole, `--sendfile FILE` sends each line
  of FILE, and `--accept-dir DIR` takes each file. A side with
  `--accept-dir` stays until the peer leaves, as files can come after its
  stdin ended. `--timeout` is required when stdin or stdout is not a
  terminal.
- The channel is always on, with the keys of `podssh node` and `podssh
  operator`: `--key`, `--ephemeral-key` and `--allow` at the side that waits;
  `--client-key` and `--node-key` at the side that reaches, which pins the
  other side's key at its first sight in `known-nodes`. A changed key, or a
  key that the allowlist refuses, exits 77.

The protocol is `crates/podssh-core/src/chat/`, with no I/O: records of a
type byte, a 32-bit length and a body. A greeting with the version and the
nick comes first; then text with an id and its acknowledgement; a file's
offer (its name, size and SHA-256), the accept or the decline, its chunks of
64 KiB at most, in order and only after the accept, and the receiver's word
on the digest; and the word that the chat is busy. A length past its type's
limit is refused before its body is read.

## IRC: servers that accept the relay

Measured on 2026-10-07 through relay version r2:

| Server | Result |
| --- | --- |
| libera, OFTC, tilde | Closed before the welcome (`001`). They answer normally from a normal host, so they refuse the relay's addresses. |
| rizon, snoonet | Dropped the connection with no message. |
| `irc.undernet.org:6667` | **Works.** Two podssh clients exchanged messages byte for byte, and a message split across WebSocket frames was joined again. |

Undernet has no IRCv3: `CAP LS` gives `421`, and a message to yourself gives
`401`. The server drops channel messages from a second connection of the
same user, so a live test needs two separate clients. These runs came before
T-091, whose client could not register where the server holds the
registration for `CAP END`, as a server of IRCv3 does. The operator allowed
short runs on undernet, libera and OFTC again on 2026-10-10 (Q39).

## IRC: files

- DCC cannot work: the receiver connects to the sender, and neither side can
  accept a connection.
- Files go through the server as chunks, each with its own length and
  digest. IRC has no integrity check, so a dropped frame is otherwise a hole
  with no message.
- The receiver keeps the sender's name for a file as a base name, with no
  directory, so the file goes where the receiver chose. A name with no base,
  or with a `:` (a drive or a stream on Windows), is refused (T-093).
- The server puts the sender's prefix, `:nick!user@host `, in front of each
  line it relays, so a chunk is sized for each transfer: the most that keeps
  the relayed line within 512 bytes, from the server's `NICKLEN`,
  `USERLEN` (one more for a `~`) and `HOSTLEN`, and the target's name;
  between 48 and 320 bytes. The offer carries the size, and the receiver
  checks it (T-097). Measured 2026-10-10 in the build image: chunks of 285
  bytes on ngircd 27, 267 on InspIRCd 4.11.0 and on ergo 2.18.0.
- Each chunk is acknowledged by its index, to the transfer's target, so the
  short last chunk ends the transfer. The receiver keeps no file: it gives
  each chunk's bytes to the caller as they come, and keeps their SHA-256.
- Each line of a transfer, a chunk or an acknowledgement, waits its turn:
  five at once, then five a second by default (T-275). A server that limits
  the rate of commands with no fake lag closes a client that sends faster:
  InspIRCd 4.11.0 at 10 commands a second closed an unpaced sender within a
  second, and let a paced 64 KiB through, in 50 s (measured 2026-10-10).
  ngircd 27 and ergo 2.18.0 slow a fast client down instead.

## IRC: connection handling

- To connect again, send CAP, NICK and USER again and join the channels
  again. Do not send QUIT first. A new connection keeps nothing of the old
  one but its channels: not the registration, the `005`, a half line or the
  nick that a `433` gave (T-095).
- The session knows its own nick: the one that `001` names, and each
  `NICK` of it after, compared by the server's `CASEMAPPING`. Another
  user's `JOIN` and `PART` are events about them, and keep the channels; a
  `KICK` of this client forgets its channel, so a reconnect does not join
  it again. A server writes the reason of a `KICK` as the trailing (ngircd
  27, InspIRCd 4.11) or as a middle (ergo 2.18). Each server sends several
  `005` lines, and they add up; a `-TOKEN` takes one away.
- A nick in use before `001` (`433 * nick`) is tried again with `_`, `__`
  and `___`, cut to fit `NICKLEN`, and refused after that; the welcome then
  names the nick in use (measured 2026-10-10 with the three servers). After
  `001`, a `433` is only an event.
- Answer `PING` with its token, byte for byte.
- A caller's text never changes a line: a CR, LF or NUL is refused, and so
  is a space in a target or a channel. podssh never removes a character, and
  never splits a message (T-093).
- A server writes a command's last parameter with or without its colon, as
  it chooses: ngircd 27 and InspIRCd 4 write `JOIN :#t` and `NICK :b`, ergo
  2.18 `JOIN #t`, `PART #t bye` and `QUIT Quit` (measured 2026-10-10). podssh
  reads each field by its place, and keeps a line with more parameters than
  its command has whole (T-094).
- A server with no `CAP` answers `421`, or nothing at all (InspIRCd 4 with no
  cap module); its welcome then ends the negotiation (T-094).
- podssh asks only for the capabilities whose lines it reads:
  `echo-message` and `znc.in/self-message` (T-092). A capability changes
  what the server sends, so `extended-join` and the like are never asked
  for. With `CAP LS 302` a server gives values (`sasl=PLAIN,EXTERNAL`) and
  may send its list over several lines, each but the last with a `*`
  before its trailing (ergo 2.18); podssh answers once, after the last
  line, with names alone, as a request that carries a value, or a name
  that the server did not offer, is refused whole (ngircd 27, InspIRCd
  4.11, ergo 2.18; measured 2026-10-10).
- With `echo-message`, the server sends each message of the client back:
  that is the proof of delivery. A message to the client's own nick comes
  back twice, as delivered and as echoed (InspIRCd 4.11, ergo 2.18); podssh
  shows it once, and never reads an echo as a peer's message or file line.
- One bad line costs no other (T-096): a line past 8 KiB is dropped whole and
  reported, and the lines around it come through; a line with no end keeps
  nothing of itself in memory; a line that is not UTF-8 is read as Latin-1,
  the older encoding of IRC, and the caller is told.
