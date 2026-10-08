# Terminal handling

How `podssh ssh` drives the local terminal (milestone 2). Most of this was
worked out against two sibling projects that face the same hosts, podbox and
sandhome; their file names refer to those repositories, not to this one.

## Choosing a mode

Three inputs decide what happens to keystrokes, not one:

1. whether the server granted a pty (`pty-req` answered SUCCESS);
2. whether podssh's own stdin and stdout are terminals;
3. whether the far side already runs a line discipline of its own.

The third is why "no pty, so echo locally" is wrong: podbox's server never
grants a pty, yet it echoes, edits and handles Ctrl-C itself under
`ForceCommand`, so local echo would show every keystroke twice.

| server pty | local stdin/stdout | podssh does |
| --- | --- | --- |
| granted | terminal | local terminal in raw mode; bytes pass through; window size sent, and again on every resize |
| granted | not a terminal (`-tt`) | bytes pass through; the size comes from `COLUMNS`/`LINES`, else 80x24 |
| refused | terminal | local terminal left in its normal mode, so its own line discipline gives echo and editing; "no pty on the server" printed once on stderr |
| refused | not a terminal | a plain pipe, as for a command |

The in-process line discipline (`crates/podssh-terminal`) is for what is left:
a person typing through a frontend that is not a tty and sends raw keystrokes,
to a server that has no pty and no line discipline of its own. It has to be
chosen explicitly; the absence of a pty alone must never select it (that is
the inverted mode selection the 2026-10-08 audit records as L1).

## `-t`, `-T` and `RequestTTY`

OpenSSH's default is `RequestTTY auto`: a pty for an interactive shell when
stdin is a terminal, none for a command. `-t` is `yes` (a pty when stdin is a
terminal), `-tt` is `force` (a pty even without a local terminal), `-T` is
`no`. With piped stdio the session runs without a pty: sandhome treated a pipe
as a terminal and put ANSI codes into `jq -r` output.

## `pty-req` (RFC 4254 §6.2)

- It needs no `/dev/ptmx` on the client.
- The dimensions are informational and zero dimensions are ignored; the local
  terminal is the only source of a window size.
- The reply is SUCCESS or FAILURE with no reason. After a FAILURE the channel
  is still usable for `shell` or `exec`.
- `window-change` has no reply; send it only after a grant.
- Bound the wait for the reply and treat silence as a refusal. Never cache the
  answer between sessions.
- A client refuses a `pty-req` that arrives from the server.

## `TERM`

Send the local `TERM` unchanged. When it is unset or empty, send
`xterm-256color`: a pty with no usable `TERM` breaks full-screen programs
(`less` prints "'unknown': I need something more specific." even on a real
pty), and it is the server's terminfo database that has to resolve the name.

## When podssh supplies the line discipline

Byte rules to carry over from podbox (`crates/podbox-ssh/src/session.rs`):

- DEL and BS erase left; Ctrl-U erases the line, Ctrl-W a word; Ctrl-A and
  Ctrl-E go home and end; up and down recall history, left and right move the
  cursor.
- CR and LF both submit, and the LF of a CRLF pair is swallowed.
- Redraw is `\r`, prompt, buffer, `ESC[K`, `\r`, prompt, buffer up to the
  cursor.
- A line holds at most 65536 bytes (the excess is dropped with a bell). History
  keeps 100 entries and skips consecutive duplicates.
- A shell on a pipe prints no prompt and keeps no history, so podbox prints a
  static `$ ` itself and owns the history.

Parse whole escape sequences: a CSI is `ESC [`, parameter bytes 0x30–0x3F,
intermediate bytes 0x20–0x2F and a final byte 0x40–0x7E; `ESC O x` is a
sequence too. podbox reads only the one byte after `ESC [`, so F5
(`ESC [ 1 5 ~`) rings the bell and then types `5~`. A sequence that is not
interpreted as a whole is refused as a whole, so `ESC [ 1 C` rings instead of
moving the cursor.

Refusals ring the bell and change nothing, because silence reads as
acceptance:

- Ctrl-Z: with no job control a stopped shell has nothing to return to, and the
  session wedges.
- Ctrl-S and Ctrl-Q: there is no IXON underneath, so nothing to stop.
- Escape sequences other than the arrows, Home and End are dropped; passing
  `ESC[?1049h` through corrupts scrollback.
- Ctrl-D past the last character is the one refusal that is silent.

`fg`, `bg` and `jobs` pass through to the shell. `less`, `vi` and `top` need a
real pty; sandhome warned when one of about 20 such command names was typed.

Newlines: expand a lone `\n` to `\r\n` exactly when the remote has no pty and
podssh holds the local terminal in raw mode. Never translate when the remote
has a pty, or for command output going to a pipe or a file.

## Open

- **Ctrl-C without a remote pty.** There `0x03` is just a byte. The only
  protocol mechanism is the RFC 4254 §6.9 `signal` request, which a server may
  ignore; which servers honour it is UNKNOWN. The M2 exit criteria include
  Ctrl-C.

## Testing

Linux test machines grant ptys, so the no-pty paths have to be forced:
`sshd -o PermitTTY=no`, a server that never answers `pty-req`, and runs with no
local terminal. Include a podbox-style shell-only server, which refuses `exec`
and has no sftp subsystem.
