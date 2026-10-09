# Terminal handling

This page tells how `podssh ssh` uses the local terminal, and when podssh
must supply the line discipline itself. Some rules come from two sibling
projects that face the same hosts, podbox and sandhome. Their file names on
this page are in those repositories.

## Select a mode

Three inputs select what happens to the keys:

1. Did the server grant a pty (`pty-req` answered SUCCESS)?
2. Are podssh's own stdin and stdout terminals?
3. Does the remote side run a line discipline of its own?

The third input is necessary. The server of podbox never grants a pty, but it
echoes, edits and handles Ctrl-C under `ForceCommand`. A local echo there
shows each key two times.

| Server pty | Local stdin and stdout | podssh does |
| --- | --- | --- |
| granted | terminal | Sets the local terminal to raw mode; bytes pass through; sends the window size, and sends it again after each resize. |
| granted | not a terminal (`-tt`) | Bytes pass through. The size comes from `COLUMNS` and `LINES`, else 80x24. |
| refused | terminal | Keeps the local terminal in its normal mode, so its line discipline gives echo and editing. Prints "no pty on the server" one time on stderr. |
| refused | not a terminal | A plain pipe, as for a command. |

The line discipline in the process (`crates/podssh-terminal`) is for the
case that remains: keys arrive raw, and nothing below edits them, neither a
pty nor a line discipline. Three facts choose its mode (`Mode::select`):
a pty below, a line discipline below, and the caller's selection. It
echoes and edits only when it is selected and neither is below; `podssh
serve` with no `/dev/ptmx` selects it (T-111), and a client flag may later.
In each other case the session is transparent: each byte goes both ways as
it came, with no echo and no refusal. The absence of a pty alone never
selects it (T-125). No command uses the crate yet (milestone M5).

## `-t`, `-T` and `RequestTTY`

- The default of OpenSSH is `RequestTTY auto`: a pty for an interactive
  shell when stdin is a terminal, and no pty for a command.
- `-t` is `yes`: a pty when stdin is a terminal.
- `-tt` is `force`: a pty, also with no local terminal.
- `-T` is `no`.
- With stdin and stdout on pipes, the session runs with no pty. A pipe that
  is treated as a terminal puts ANSI codes into data (sandhome did this with
  `jq -r`).

## `pty-req` (RFC 4254, section 6.2)

- It needs no `/dev/ptmx` on the client.
- The dimensions are information only, and zero dimensions are ignored. The
  local terminal is the only source of a window size.
- The reply is SUCCESS or FAILURE, with no reason. After a FAILURE, the
  channel can still run `shell` or `exec`.
- `window-change` has no reply. Send it only after a grant.
- Put a limit on the wait for the reply, and treat no reply as a refusal.
  Never keep the answer for the next session.
- A client refuses a `pty-req` that comes from the server.

## `TERM`

Send the local `TERM` with no change. When `TERM` is not set or is empty,
send `xterm-256color`. With no usable `TERM`, full-screen programs fail on a
real pty (`less` prints "'unknown': I need something more specific."). The
terminfo database of the server must resolve the name.

## The Windows console

- Raw mode turns off echo, line input and the processing of Ctrl-C, and
  turns on virtual-terminal input and output. podssh then sends Ctrl-C to
  the remote side as a byte.
- podssh restores the console's input and output modes when the session
  ends, and also when podssh panics.
- A console has no resize signal, so podssh reads the window size every
  500 ms. On Unix, SIGWINCH gives the change.
- Prompts use `CONIN$` and `CONOUT$`, so they work when stdin and stdout are
  redirected.

`scripts/interop-conpty.py` checks these items in a real pseudo console.

## When podssh supplies the line discipline

These byte rules come from podbox (`crates/podbox-ssh/src/session.rs`):

- DEL and BS erase to the left. Ctrl-U erases the line, Ctrl-W a word.
  Ctrl-A and Ctrl-E go to the start and the end. Up and down recall the
  history; left and right move the cursor.
- CR and LF both submit the line. The LF of a CRLF pair is ignored.
- On one row, a redraw is `\r`, the prompt, the buffer, `ESC[K`, `\r`, the
  prompt, and the buffer up to the cursor.
- The caller gives the terminal's size: the client measures its terminal,
  and `podssh serve` reads `pty-req` and `window-change`. Raw mode stays in
  `podssh-ssh`. A line wider than the terminal takes several rows, and a
  wide character that does not fit at the end of a row starts the next one.
  The redraw then goes up to the first row (`ESC [ n A`), writes `\r`, the
  prompt and the line, clears below with `ESC [ J`, and moves the cursor back
  by rows and columns. A row that the line fills ends with `\r\n`, so the
  terminal's cursor never waits in the last column. Backspace at the start
  of a row redraws, because `\b` does not go up a row. Enter and Ctrl-C leave
  from the last row. A new width draws the line again on a row of its own.
  With no size, or a width of 0, the redraw stays on one row. A line taller
  than the screen is not drawn right: `ESC [ A` stops at the top row.
- A line holds 65536 bytes or fewer; the extra bytes are dropped with a
  bell. The history keeps 100 entries and skips a repeat of the last entry.
- With `IUTF8` from the modes of `pty-req`, the cursor steps over whole
  characters, and an accent moves with its letter; without it, over bytes,
  as a terminal with no `IUTF8` does. The screen moves by cells
  (`unicode-width`): a wide character takes 2, an accent 0, and a control
  byte or a byte that is not UTF-8 the 1 cell of its echo. Backspace, Ctrl-W,
  Ctrl-D and the arrows act on whole characters, and the arrows write
  `ESC [ n D` or `ESC [ n C` for a step of n cells. The line and the history
  keep the bytes as typed; the cap drops a character whole, never half of it.
- A shell on a pipe prints no prompt and keeps no history. Thus podbox
  prints a static `$ ` and keeps the history itself.

Parse each escape sequence as a whole:

- A CSI is `ESC [`, then parameter bytes 0x30 to 0x3F, intermediate bytes
  0x20 to 0x2F, and a final byte 0x40 to 0x7E.
- `ESC O x` (SS3) is also a sequence, read as a CSI is: some terminals put
  a parameter before the final (`ESC O 2 P`). `ESC O A` to `ESC O D`,
  `ESC O H` and `ESC O F`, the arrows, Home and End of a terminal in
  application mode, act as their CSI forms, and the screen moves by the CSI
  form. On the keypad in application mode, `ESC O M` is Enter, and
  `ESC O j` to `ESC O y` and `ESC O X` type `*+,-./`, the digits and `=`.
- The Linux console sends F1 to F5 as `ESC [ [ A` to `ESC [ [ E`, so
  `ESC [ [` takes one more byte.
- `ESC` starts a new sequence wherever it comes. A control byte ends a
  sequence and is a key of its own: an escape never takes Ctrl-C, Ctrl-D or
  Enter.
- `ESC` and a key with no pause is an Alt key: one bell, and the key is not
  typed, each byte of a UTF-8 character included.
- A lone `ESC`, or a sequence cut short, rings once when no byte came for
  50 ms, and the next key is typed as usual. The crate reads no clock: while
  `Session::waiting` is true, the caller calls `Session::on_idle` after
  50 ms with no byte.
- If podssh does not interpret a sequence, it refuses the whole sequence:
  F1 to F4, in each of these forms, ring once and type nothing. (A parser
  that reads one byte after `ESC [` makes F5, `ESC [ 1 5 ~`, ring the bell
  and then type `5~`.)

A refusal rings the bell and changes nothing, because silence looks like
acceptance:

- Ctrl-Z: with no job control, a stopped shell has nothing to return to,
  and the session stops.
- Ctrl-S and Ctrl-Q: there is no IXON below, so there is nothing to stop.
- Escape sequences other than the arrows, Home, End and the keypad's keys
  are dropped. If `ESC[?1049h` passes through, it corrupts the scrollback.
- A lone Escape, and Alt with a key: no key is bound to them.
- Ctrl-D after the last character is the only refusal with no bell.

`fg`, `bg` and `jobs` go to the shell. `less`, `vi` and `top` need a real
pty; sandhome gave a warning when one of about 20 such command names was
typed. Where `/dev/ptmx` is missing, `podssh serve` makes a tty when a probe
allows it (T-248): a new devpts instance, or a tty in user space that answers
the child's tty system calls.

Newlines: change a lone `\n` to `\r\n` only when the remote side has no pty
and podssh holds the local terminal in raw mode. Never change newlines when
the remote side has a pty, or for command output that goes to a pipe or a
file.

## Open

- **Ctrl-C with no remote pty.** There, `0x03` is only a byte. The only
  mechanism of the protocol is the `signal` request (RFC 4254, section 6.9),
  and a server can ignore it. It is not known which servers honour it.

## Tests

Linux test hosts grant ptys, so a test must force the paths with no pty:
`sshd -o PermitTTY=no`, a server that never answers `pty-req`, and runs with
no local terminal. Include a shell-only server like podbox's, which refuses
`exec` and has no sftp subsystem.
