# Chat over IRC (milestone M8)

`podssh chat` lets two users on constrained hosts talk and exchange files.
podssh speaks IRC itself, and the relay carries the bytes, as for SSH. No
command uses the client yet. The client has known defects ([TODO/irc.md](../TODO/irc.md),
T-092 to T-098): among them, it sends plain text through the relay. Since
T-091 the registration finishes on a server that holds it until `CAP END`:
measured with ngircd 27 on the loopback of the build image, 2026-10-10.

The operator decides when chat starts, and whether it stays on IRC or moves
to the roads between two podssh ends ([design.md](design.md), section 8).

## Servers that accept the relay

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
registration for `CAP END`, as a server of IRCv3 does; whether a session may
test on the public networks again is the operator's question Q39.

## Files

- DCC cannot work: the receiver connects to the sender, and neither side can
  accept a connection.
- Files go through the server as chunks, each with its own length and
  digest. IRC has no integrity check, so a dropped frame is otherwise a hole
  with no message.

## Connection handling

- To connect again, send CAP, NICK and USER again and join the channels
  again. Do not send QUIT first.
- Answer `PING` with its token, byte for byte.
