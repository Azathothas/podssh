# Known defects

This page lists the open defects in the code. Each row gives the defect, the
file, and the severity.

- When you repair a defect, remove its row in the same commit.
- When you find a defect that you cannot repair now, add a row.
- Do not give line numbers. They change when the code changes.

Severity:

- **high**: a real session fails, or the security is weak.
- **medium**: the behaviour is wrong in a case that can occur.
- **low**: the defect is cosmetic, or it cannot occur yet.

## podssh-ws: TLS and WebSocket

| ID | File | Defect | Severity |
| --- | --- | --- | --- |
| W10 | `crates/podssh-ws/src/frame.rs` | The decoder does not check that a received control frame has FIN set and a payload of 125 bytes or fewer. | medium |
| W13 | `crates/podssh-ws/src/crypto/random.rs` | `OsRng::fill_bytes` panics when the operating system cannot supply random bytes. It must return the error. | low |
| W14 | `crates/podssh-ws/src/probe.rs` | `PrintChain` accepts every certificate, and it is a public export of the library. Move it into the example that uses it. | medium |

## podssh-transport: relay protocol framing

Only about 600 source lines are used outside the tests: `adapt.rs`,
`socket.rs` (`WsSocket`, `Leg`) and `forward.rs` (`ForwardRunner`). Repair
T1, T2, T5, T8 and T9 before the reverse legs (milestone M4) use this crate.

| ID | File | Defect | Severity |
| --- | --- | --- | --- |
| T1 | `crates/podssh-transport/src/socket.rs`, `src/adapt.rs` | `send_text` sends a binary frame. The relay reads the node's `{"type":"ready"}` message as a session-id prefix and closes the leg with 1003. The reverse node leg cannot work. The test double records each send as binary, so the tests do not show the defect. | high |
| T2 | `crates/podssh-transport/src/socket.rs` | A received Close frame becomes `Unexpected`. The close code and the reason are lost. | high |
| T5 | `crates/podssh-transport/src/socket.rs` | The `ready` gate is not enforced. `recv_data` and `recv_control` each take the frame type of the other and refuse it. | high |
| T7 | `crates/podssh-transport/src/backpressure/` | The module is not used. Its model (the completion of local writes) does not show the relay's queue, and its ledger has two defects. The SSH channel windows give the real flow control. | medium |
| T8 | `crates/podssh-transport/src/error.rs` | A `403` is not retried, but a new token repairs an expired self-minted token. A `503` is retried, which the relay's contract does not allow. | medium |
| T9 | `crates/podssh-transport/src/endpoint.rs` | The host and node names are not validated or escaped (`/`, `?`, `#`, `..`). | medium |
| T10 | `crates/podssh-transport/src/transport.rs`, `src/backoff.rs` | The `Transport` trait has no implementation. `Backoff` is used only by tests; `podssh-relay` has its own. | low |

## podssh-core/irc: IRC client

No command uses this client yet. It sends plain text to a public IRC server
through the relay, so the relay can read the chat and the file bytes.

| ID | File | Defect | Severity |
| --- | --- | --- | --- |
| I1 | `crates/podssh-core/src/irc/cap.rs`, `session.rs` | `CAP END` is sent only after 001. An IRCv3 server holds the registration until `CAP END`, so the registration does not finish. A test asserts the wrong order. | high |
| I2 | `crates/podssh-core/src/irc/cap.rs` | The client requests every offered capability. It handles `sasl=...` values and a `CAP LS` of more than one line incorrectly. | high |
| I3 | `crates/podssh-core/src/irc/encode.rs`, `transfer/` | Text is not checked for CR, LF and NUL. `send_privmsg("#c", "a\r\nQUIT")` sends a QUIT. | high |
| I4 | `crates/podssh-core/src/irc/command.rs` | The trailing forms `JOIN :#c` and `NICK :n`, and a `PRIVMSG` with no colon, are dropped. The nick target of CAP is not parsed. | high |
| I5 | `crates/podssh-core/src/irc/session.rs` | A PART from any user removes the channel. KICK is not handled. Each 005 line replaces the ISUPPORT values. A reconnect does not reset the state. A 433 gets no alternative nick. | high |
| I6 | `crates/podssh-core/src/irc/framing.rs` | An overflow or a line that is not UTF-8 loses lines. The buffer has no limit. A Latin-1 line stops the session. | high |
| I7 | `crates/podssh-core/src/irc/transfer/` | A chunk is longer than 512 bytes when the server adds its prefix. The acknowledgement index is wrong for a short last chunk. The transfer was never run against a real server. | high |
| I8 | `crates/podssh-core/src/irc/reap.rs` | The keepalive sends a visible channel message every 60 s. A client `PING` does the same work and shows nothing. | medium |

## podssh-terminal: line discipline

No command uses this crate yet.

| ID | File | Defect | Severity |
| --- | --- | --- | --- |
| L1 | `crates/podssh-terminal/src/session.rs` | The mode selection is the wrong way round. When the server gives no pty (the case this crate is for), each key rings the bell and the session ends. When a pty is given, the crate adds a local echo to the remote echo. | high |
| L2 | `crates/podssh-terminal/src/` | The crate has no raw mode and no window-size query or resize. (`podssh-ssh` has its own terminal code, which works.) | high |
| L3 | `crates/podssh-terminal/src/echo/inspect.rs`, `echo/editing.rs` | The cursor counts bytes, not characters. Editing text that is not ASCII corrupts the screen. | high |
| L4 | `crates/podssh-terminal/src/escape.rs` | `ESC O x` (F1 to F4, arrows in application mode) rings the bell and inserts letters. A single Escape removes the next key. | high |
| L5 | `crates/podssh-terminal/src/echo/editing.rs`, `passthrough.rs` | The `~` forms of Delete, Home and End are not handled. Home and End move the buffer cursor but not the screen cursor. Passthrough refuses Ctrl-Z, Ctrl-S and Ctrl-Q even with a real remote pty. Remote output writes over the line that is being edited. | medium |

## podssh-cli and podssh-ts

| ID | File | Defect | Severity |
| --- | --- | --- | --- |
| C2 | `crates/podssh-cli/src/ts.rs` | The status query and the peer lookup are outside the `--timeout` limit. A missing netmap makes `podssh ts` wait forever. | high |
| C3 | `crates/podssh-ts/src/pipe.rs` | A local end of input cancels the remote-to-stdout direction, so a reply that comes after it is lost. A test asserts this behaviour. | high |
| C9 | `crates/podssh-ts/` | The automatic mode always selects `tcp`: its probe only checks that a key exists. Ephemeral nodes are not logged out. The live test with two nodes was never run. | medium |

## podssh-probe

| ID | File | Defect | Severity |
| --- | --- | --- | --- |
| P1 | `crates/podssh-probe/` | No command uses the crate. `scripts/check-relay-spec.py` does the same check against the live relay. | low |

## Build and tools

| ID | File | Defect | Severity |
| --- | --- | --- | --- |
| B7 | `scripts/dev.sh`, `scripts/gate.sh`, `.github/workflows/` | The build image `rust:1-alpine` is not pinned to a digest. | low |
| B8 | `scripts/dev.sh` | The script has about 600 lines. Split it. | low |
