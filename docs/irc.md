# Chat over IRC (milestone 8)

`podssh chat` lets two users on constrained hosts talk and exchange files.
podssh speaks IRC itself and the relay carries the bytes, as for SSH. The
current client has known defects (see [audit-2026-10-08.md](audit-2026-10-08.md)):
it hangs at registration on IRCv3 servers and sends plaintext through the
relay.

## Which servers accept the relay

Measured 2026-10-07 through relay version r2:

| server | result |
| --- | --- |
| libera, OFTC, tilde | closed before the welcome (`001`); they answer normally from an ordinary host, so they refuse the relay's addresses |
| rizon, snoonet | dropped the connection silently |
| `irc.undernet.org:6667` | **works**: two podssh clients exchanged messages byte for byte, and a message split across WebSocket frames was reassembled |

Undernet has no IRCv3: `CAP LS` returns `421`, a message to yourself returns
`401`, and channel messages from a second connection of the same user are
dropped. Live tests therefore need two separate clients.

## Files

- DCC cannot work: the receiver dials the sender, and neither side can accept
  a connection.
- Files go through the server as chunks, each with its own length and digest.
  IRC has no integrity check, so a dropped frame would otherwise be a silent
  hole.

## Connection handling

- To reconnect, send CAP, NICK and USER again and rejoin the channels, without
  sending QUIT first.
- Answer `PING` by echoing its token byte for byte.
