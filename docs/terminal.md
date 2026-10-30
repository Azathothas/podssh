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

## What podssh reads from the terminal

podssh acts on few bytes of the terminal, and passes each other one
unchanged (T-130). The escapes are one table,
`crates/podssh-ssh/src/escape.rs` (`ESCAPES`), which the input, `~?` and
the manual read; a test holds the manual's note to it.

- **A client with a pty** (the local terminal raw): the escape character,
  `~` unless `-e` names another (`-e none`: none), at the start of a line,
  and the key after it: `~.` ends the session and sends nothing after it,
  `~R` asks for a re-key, `~C` opens OpenSSH's command line (`ssh> `),
  which adds and stops forwards (T-291, [cli.md](cli.md)), `~#` lists the
  forwards with what each carried, `~d` leaves the shell to a far end that
  keeps shells ("Detach and attach again" below) and goes as typed
  elsewhere, `~Z` sends a file by ZMODEM, `~?` lists the escapes, and `~~`
  sends one `~`; another key goes with the `~` before it. A resize sends
  the new size. Each other byte passes unchanged, as the remote side reads
  it: Ctrl-C, Ctrl-Z, Ctrl-D, Ctrl-S, Ctrl-Q, Escape, the sequences of the
  keys, of the mouse and of a bracketed paste; only the line of `~C`, and a
  question or a transfer of ZMODEM, take the keys ("ZMODEM in a session"
  below). The line of `~C` is read from the session's own keys, with echo,
  Backspace and Ctrl-U; Enter ends it, Ctrl-C and Ctrl-D give it up, and
  the keys after its Enter go to the session. No key of the line reaches
  the server.
- **A client with no pty:** podssh reads no byte; stdin is the command's
  data, escapes are off, and Ctrl-C is the local terminal's signal to
  podssh, which sends `signal INT` to the command first ("Ctrl-C with no
  remote pty" below).
- **A session through a control master** (T-039): the master reads its
  escapes, with the escape character that the client sent. It offers no
  `~C`, as OpenSSH's master offers none to a client: `~C` goes to the
  server as typed.
- **The broadcast, `podssh each --interactive`** (T-185): the local
  terminal keeps its normal mode, and podssh reads whole lines; a line
  that starts with `:` is for podssh. The terminal turns two keys into
  signals: `Ctrl-\` (SIGQUIT) on Unix and Ctrl-Break on Windows is the
  emergency stop, and Ctrl-C goes to no host (`docs/cli.md`, "The
  broadcast: `--interactive`").
- **The line discipline of `podssh serve`**, when serve exists (T-107 to
  T-113): the keys and sequences that it acts on and those that it refuses
  are in "When podssh supplies the line discipline" below; each other byte
  passes unchanged.

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
  ends, and also when podssh panics. Ctrl-Break, a closed window, logoff
  and shutdown end podssh through the console's default handler, which
  runs no destructor: a console control handler puts the modes back first
  (T-295).
- A console has no resize signal, so podssh reads the window size every
  500 ms. On Unix, SIGWINCH gives the change.
- Prompts use `CONIN$` and `CONOUT$`, so they work when stdin and stdout are
  redirected.
- podssh sets no code page. Output goes to the console through Rust's
  standard output, which writes the console in UTF-16, so text in UTF-8
  shows whatever the code page is. That writer refuses a byte that is not
  UTF-8, so podssh first writes each such sequence as U+FFFD, as a terminal
  of Linux shows it, and keeps a character that the end of a message cuts
  for the next one (T-294). A pipe or a file gets the bytes unchanged.

`scripts/interop-conpty.py` checks these items in a real pseudo console
against a server with a shell, and `crates/podssh-cli/tests/console.rs`
against the test's own server, in each run of the tests on Windows.

What a pseudo console showed (T-132, 2026-10-12, Windows 11,
`crates/podssh-cli/tests/console.rs`):

| Item | Measured | |
| --- | --- | --- |
| Text in UTF-8 that is not ASCII (`héllo € ✓`) | Shows as sent. | No fault. |
| A byte that is not UTF-8 (`0xff`) in the output | Before T-294, the text before it showed, and the byte and each later byte of the session were lost while the session went on: Rust's console writer refuses the byte (`rust-lang/rust:library/std/src/sys/stdio/windows.rs`, `write`), and podssh took the refusal for a stdout that is gone. Since T-294 the byte shows as U+FFFD, and the output goes on. | Fault, repaired: T-294. |
| Ctrl-Break in a session with a pty | podssh ends with `0xC000013A`. Before T-295 the console's input mode stayed raw: `0x3f0`, where it was `0x1f7`; since T-295 it is `0x1f7` again. | Fault, repaired: T-295. |
| `~.` in the same session | The mode is `0x1f7` again. | No fault. |
| A resize | Reaches the server 450 to 505 ms after it. | Kept: the poll costs 500 ms at most; an event of the console would need `ReadConsoleInputW` in place of the stream of bytes that podssh reads. |

### csshw

csshw (`whme/csshw`, at `6dd773b`) is a cluster SSH tool for Windows: it
opens a console window for each host, runs OpenSSH's `ssh` in it, and sends
the keys of its own window to each. Each of its console calls against
podssh (T-132, from GitHub #24):

| csshw | podssh | |
| --- | --- | --- |
| A console window of its own for each host (`CreateProcessW`), with the keys of its window written into each (`WriteConsoleInputW`) | One session, in the console where podssh runs | Not needed: podssh is the SSH client, and drives no window. |
| Keys read as input records (`ReadConsoleInputW`), other events skipped | Keys read as a stream of bytes, with virtual-terminal input | Not needed: the remote pty wants a terminal's bytes, which a key record would need a translation into. |
| `ENABLE_PROCESSED_INPUT` off, so that Ctrl-C reads as a key | The same, in raw mode | Same. |
| At its end, Ctrl-C to each process of a host's console (`GenerateConsoleCtrlEvent`) | Starts no process in its console; a `ProxyCommand` ends with podssh | Not needed. |
| The colour of a whole window by its state (`SetConsoleTextAttribute`, `FillConsoleOutputAttribute`; `disabled_console_color`), and a repaint of the edge that the fill misses (`InvalidateRect`) | No colour of its own: the remote side's colours are escape sequences | Not needed. |
| A clear screen by `ScrollConsoleScreenBufferW` and `SetConsoleCursorPosition` | The remote side clears with escape sequences | Not needed. |
| The title, place, size and border colour of each window, DPI awareness, the version of Windows | None | Not needed: the layout of many windows. |
| No code page set | None set; output in UTF-16 (measured above) | Same. |
| ConPTY, which the report of #24 names | podssh runs in a console or in a pseudo console | csshw has no code for a pseudo console: its hosts' windows are classic consoles. |

No item of csshw is a fault of podssh. The two faults above came from the
measurements that the comparison asked for.

## When podssh supplies the line discipline

These byte rules come from podbox (`crates/podbox-ssh/src/session.rs`):

- DEL and BS erase to the left. Ctrl-U erases the line, Ctrl-W a word.
  Ctrl-A and Ctrl-E go to the start and the end. Up and down recall the
  history; left and right move the cursor.
- Home and End do as Ctrl-A and Ctrl-E, in each form a terminal sends:
  `ESC [ H` and `ESC [ F`, `ESC O H` and `ESC O F`, and the VT220 and rxvt
  `ESC [ 1 ~` or `ESC [ 7 ~` and `ESC [ 4 ~` or `ESC [ 8 ~`. Each of these
  keys moves the screen's cursor with the line's. Delete (`ESC [ 3 ~`)
  deletes the character under the cursor, and never ends input.
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
- Escape sequences other than the arrows, Home, End, Delete and the
  keypad's keys are dropped: Insert, the page keys and F5 and above ring
  once. If `ESC[?1049h` passes through, it corrupts the scrollback.
- A lone Escape, and Alt with a key: no key is bound to them.
- Ctrl-D or Delete after the last character is the only refusal with no
  bell.

`fg`, `bg` and `jobs` go to the shell. `less`, `vi` and `top` need a real
pty; sandhome gave a warning when one of about 20 such command names was
typed. Where `/dev/ptmx` is missing, `podssh serve` makes a tty when a probe
allows it (T-248): a new devpts instance, or a tty in user space that answers
the child's tty system calls.

The program's output while a line is under edit: the line is hidden (up to
its first row, `\r`, and `ESC [ K` or `ESC [ J`), the output is written, and
the prompt and the line are drawn again below it, with the cursor in its
place. Output never lands in the line or changes it. Output that stops
inside a row, such as a program's own prompt or a progress bar drawn with
`\r`, stays as it is, and the line comes back on the next row at the next
key.

Newlines: in the line discipline, each `\n` of the program's output becomes
`\r\n`, as a pty's `ONLCR` makes it: the program writes to a pipe, and the
terminal is raw. Never change newlines when the remote side has a pty, or
for command output that goes to a pipe or a file.

## Ctrl-C with no remote pty

With no remote pty, Ctrl-C is the local terminal's, and it ends podssh;
`0x03` would be only a byte of the command's input. The command on the
server runs on: in the build image, OpenSSH 10.3p1 and Dropbear 2026.91
each still ran `sleep` after their client had ended. The protocol's one
way to stop it is the `signal` request (RFC 4254, section 6.9), which a
server may ignore. `crates/podssh-ssh/tests/signal_request.rs` measures
what a server does with it (T-131): podssh's client logs in, runs a command
with no pty, sends `signal INT` after 1 s, and reads what ends the channel
within 5 s. In `exec sleep 30`, `sleep` is the process that the server
started; in `sleep 30; true`, a shell waits for its child.

| Server, 2026-10-12 | `exec sleep 30` | `sleep 30; true` |
| --- | --- | --- |
| OpenSSH 10.3p1, the build image | Ended by `INT` at once; the channel closed. | The same: sshd signals the session's process group (its log: `session_signal_req: signal INT, killpg(...)`). |
| Dropbear 2026.91, the build image | Ended by `INT` at once; the channel closed. | Ignored: Dropbear signals the process that it started (`kill`, `mkj/dropbear:src/svr-chansession.c`, line 468 at `17549ea`), here the shell, which waits for `sleep`. Both still ran after the client left. |
| russh 0.64.1 with its default handler (the test's own server) | Ignored. | Not run. |
| Tailscale SSH | Not measured: the tailnet's hosts were offline. | |
| `railway.new` | Not measured: it refused an anonymous visitor (Q42). | |

Decision: the client sends `signal INT` on Ctrl-C when the session has no
remote pty and runs a command or a shell (T-293). OpenSSH then stops the
command and each process of its group, and Dropbear a command that is the
process that it started. With a remote pty nothing changes: Ctrl-C is a
byte, and the remote pty's line discipline signals the foreground group.

What podssh does since T-293 (`crates/podssh-ssh/src/terminal/interrupt.rs`):

- In a session with no remote pty that runs a command or a shell (not
  `-N`, `-W` or `-s`: OpenSSH's sshd refuses the request for a subsystem),
  podssh takes SIGINT, or `CTRL_C_EVENT` in a Windows console, while the
  channel is open. Before the session, as at a prompt, Ctrl-C ends podssh
  as before.
- The first Ctrl-C sends `signal INT` and waits 2 s for the channel's end;
  the command's signal or status is then the exit code, as for each
  command: 130 when `INT` ended it.
- A second Ctrl-C, or the end of the wait with no end of the command, ends
  podssh with 130, the code that a shell gives a process that SIGINT ended,
  on Windows too; `--result-file` says `interrupted`. `-v` says each step.
- `--no-signal` keeps OpenSSH's behaviour, whose client sends no request:
  no handler, and Ctrl-C ends podssh at once (on Windows by the console's
  own handler, with `0xC000013A`).
- A SIGINT that was ignored when podssh started (a script's `&` leaves it
  so) stays ignored, as in OpenSSH's client. A Windows process that
  ignores Ctrl-C gets no event.
- A session through a control master is the master's: its client ends at
  SIGINT with 255, as before (T-039).

`crates/podssh-cli/tests/ssh_interrupt.rs` runs podssh against the test's
server on the loopback, whose command writes each `signal` request that it
gets and ends by it, or runs on: SIGINT on Unix, and Ctrl-C typed into a
pseudo console on Windows.

## Detach and attach again

A user can leave a shell running and join it again later, from a new
podssh process or from another host, where the far end keeps shells
(T-158). tmux does this on a server that has tmux; a cage usually has none.
The keys and the sequence numbers of the SSH connection live in the client
process, above the resumable layer, so a new process cannot go on with the
connection's bytes: the far end keeps the shell, and a new SSH login joins
it. A client in the background that keeps the connection and takes
attaches over a local socket lost: it needs a listener, and it dies with
the client's host.

- **The offer.** A far end that keeps shells names `keep.v1` in the
  `GREETING` of the resumable layer, and `podssh ssh` names it in its
  `OPEN`; as for each feature, a name counts only when both sides give it.
  A podssh node never names it: its SSH server is another program, which
  keeps no shell. The road of `node://NAME`, raced with `--iroh-ticket`
  too, learns the offer before the SSH login. The iroh road alone
  (`iroh:TICKET`) does not read it yet, so no shell is kept there.
- **`~d`.** With the offer, in a session of a shell with a pty on a
  terminal, `~d` at the start of a line sends `env detach@podssh NAME` on
  the shell's channel, with a reply asked. NAME is new (8 hexadecimal
  digits), or the name that the session attached. SUCCESS: the far end
  keeps the shell and closes the channel; podssh prints "HOST keeps the
  shell as NAME" and exits 0, and `--result-file` says `detached`.
  FAILURE: a line, and the session goes on. Nothing typed after `~d` in
  the same read is sent. With no offer, `~d` is two bytes for the server,
  as before.
- **`--attach NAME DEST`.** A new login asks for a pty, as `-tt` does,
  and before `shell` sends `env attach@podssh NAME`; with `--take`, `env
  take@podssh yes`; and `env from@podssh ID` when `PODSSH_SHELL_ID` is set
  where podssh runs. Each waits for its reply, and a FAILURE is a far end
  that joins no shell (255). The far end then joins the shell to the
  channel, or refuses with its words on stderr and an exit status, which
  podssh exits with.
- **`--attach DEST`.** The subsystem `shells@podssh`: one line for each
  kept shell, its name and `attached` or `detached`.
- **The far end decides.** One client has a shell at a time; `--take`
  takes it, and the far end ends the other client's channel. The far end
  puts `PODSSH_SHELL_ID` in the environment of each shell that it starts,
  and refuses an attach whose `from@podssh` names the shell to join: a
  shell joined to a client inside it would feed its own output back.
- **The requests are `env` and `subsystem` requests**, which the handler
  of russh's server sees. russh 0.64.1 answers a channel request or a
  global request of another name with FAILURE and calls no handler, so a
  request of podssh's own type would never reach `podssh serve`.
- **Where shells are kept.** `podssh serve` (T-107 to T-110, which the
  operator holds) keeps them, with the lease and the limits of T-159; the
  screen that a client finds on an attach is T-161's. Against a standard
  sshd, `--persist` keeps the shell in tmux (T-178).

`crates/podssh-cli/tests/attach.rs` tests it with a stand-in of the far
end in the test process: the layer as `podssh serve` speaks it, with
`keep.v1`, and a russh server whose shells outlive their client, behind a
node in plain mode on the stand-in relay. In a pseudo console on Windows,
or a pty on Linux, it sets a variable in a shell, types `~d`, lists the
kept shells, attaches by name from a new process, and reads the variable
back.

## Where kept output may start

A far end that keeps a shell keeps a ring of its recent output (T-159),
and a client that attaches gets what the ring holds (T-161). A full ring
drops its oldest bytes, and its first byte could then be inside an escape
sequence or a UTF-8 character: the terminal would show the end of the
sequence as text, a full-screen program would draw wrongly, or a part of a
title would show on the command line (GitHub #31). A resume of the
resumable layer never meets this: it sends again each byte that the other
side did not acknowledge (T-152).

`crates/podssh-terminal/src/grammar.rs` (T-221) reads the output as a
terminal does, and finds each boundary: a place where a terminal that
starts to read shows no part of a sequence. Its ring
(`podssh_terminal::grammar::Ring`) drops bytes only up to a boundary.

- Text is at a boundary at each byte but a UTF-8 continuation byte.
- `ESC` starts a sequence wherever it comes. `ESC` and a byte 0x30 to
  0x7E is one, with intermediate bytes 0x20 to 0x2F between them or not. A
  CSI ends at its final byte, 0x40 to 0x7E; a control byte inside it does
  not end it. An OSC ends with ST (`ESC \`) or BEL; a DCS, SOS, PM and APC
  with ST alone. CAN and SUB end each sequence.
- Where terminals differ, there is no boundary: the byte that cuts a UTF-8
  character short starts none (vte drops it), and 0x9C, the 8-bit ST, ends
  no string (vte ends a DCS with it; a UTF-8 terminal does not).
- A sequence or a character that waits 10 s for its next byte is broken.
  The next boundary is then the byte after the next newline, or the `ESC`
  of the next full repaint: `ESC [ 2 J`, `ESC [ ? 1049 h`, `?1047h`,
  `?47h`, or the reset `ESC c`. The caller gives the time of each chunk.
- The ring keeps a boundary for each 1/256 of its size, the first after a
  broken sequence, and the newest, so a cut drops at most about 1/256 of
  the ring more than it must.

`crates/podssh-terminal/tests/grammar_boundary.rs` cuts the output that
real programs wrote (vim, and an interactive bash whose prompt sets the
title; `scripts/capture-terminal.py` adds less and top from a pty of
Linux) at each offset, and checks the first byte kept against anstyle-parse,
vte's parser: a terminal that starts there does what the terminal that read
the whole stream does. No far end keeps a shell yet, so no ring is used:
`podssh serve` will hold one for each kept shell (T-159).

## ZMODEM in a session

Some servers give a shell and nothing else: no SFTP, and exec refused. A
file can then cross inside the terminal session, with `sz` and `rz` of
lrzsz on the server and ZMODEM in podssh (T-148). The code is
`crates/podssh-ssh/src/zmodem/`; the protocol is Chuck Forsberg's "The
ZMODEM Inter Application File Transfer Protocol" (1988), and the section
numbers below are its.

- **When podssh watches.** Only in a session with a pty, a raw local
  terminal and a terminal on stdout, and when `PODSSH_ZMODEM` is not `off`.
  With no terminal nothing is watched, so nothing is ever received: the
  bytes go to stdout as they come. A session through a control master is
  not watched, and `~Z` there says so.
- **The start.** `sz` prints `rz\r`, then the hex header ZRQINIT:
  `**`, ZDLE (0x18), `B00` and twelve more hex digits ("may be scanned for
  B00", 8.1). `rz` prints "rz waiting to receive." and the hex header
  ZRINIT, `B01`. A start counts only when its 14 hex digits are whole and
  their CRC-16 holds; text that only looks like one passes unchanged. The
  bytes of a start that the end of a message cut wait for the next message,
  100 ms at most.
- **Receive.** podssh asks where the files go: Enter takes the directory of
  the last answer (the current directory at first), a path changes it (`~`
  at its start is the home directory), and Ctrl-C refuses and sends the
  cancel sequence (eight CAN and ten backspaces, 8.4). A name that the
  server sends counts by its last
  component, which must be one that may be written here. Each file comes
  as T-134 writes a copy: to `.NAME.podssh-RANDOM.part` beside it, with the
  CRC of each subpacket checked; at ZEOF the length must be what came and
  what ZFILE said; then the file gets the server's time and its mode
  (without the write bits of the group and others), and a rename gives it
  its name. A name that is taken is replaced only after the answer `y`;
  else the server's file is skipped (ZSKIP). A transfer that ends before
  ZEOF removes the temporary file.
- **Send.** When `rz` waits, podssh asks for a local file. `~Z` asks first,
  then types `rz` and Enter on the server ("The sending program may send
  the string "rz\r"", 8.1). The file goes as ZFILE (binary, no option for a
  name that exists, so that the server's `rz` keeps its own rule), then
  ZDATA's subpackets of 1024 bytes, ZCRCE and ZEOF; a ZRINIT after ZEOF
  says that it is whole, and ZFIN and "OO" end the session.
- **Limits.** Each wait for a frame has 10 s, the spec's response time
  (8.1); after it the last header goes again, and after 4 waits ("40
  seconds total") the transfer ends with the cancel sequence and the
  session goes on. A ZRPOS at the same place 4 times also ends it. Ctrl-C
  during a transfer stops it; each other key is dropped, as it would land
  in the protocol's stream. A file of 4 GiB or more is refused: positions
  have 32 bits. A command from the server (ZCOMMAND, `sz -c`) never runs.
- **What crosses.** Headers in hex, and in binary with CRC-16 or CRC-32 as
  the receiver allows (CANFC32); ZDLE escapes of ZDLE, DLE, XON and XOFF
  with and without the parity bit, and of CR after `@` (7.2), as lrzsz
  sends them; each control character when the receiver asks (ESCCTL).
  podssh's ZRINIT is `B0100000023be50`, the flags of lrzsz's `rz`.

`crates/podssh-ssh/tests/zmodem.rs` checks the search for a start, the
frames and their CRCs against vectors from the spec, the limits, and a
file each way. The gate's check (`scripts/interop-pty.py`, `pty.zmodem.*`)
runs `sz` and `rz` of lrzsz in a real pty; Alpine has no lrzsz package
now, and the check says `env` without one (T-148's Correction).

## Tests

Linux test hosts grant ptys, so a test must force the paths with no pty:
`sshd -o PermitTTY=no`, a server that never answers `pty-req`, and runs with
no local terminal. Include a shell-only server like podbox's, which refuses
`exec` and has no sftp subsystem.

The terminal oracle (T-200) judges what a terminal shows, not the bytes. A
test that compares bytes with bytes that a person wrote passes when both
share a mistake, such as a wrong column or lines that step down like
stairs. The model is the `vt100` crate, a VT terminal in raw mode, in the
tests only (`crates/podssh-terminal/tests/screen/mod.rs`); the tests of
podssh-ws and podssh-ssh read the same file. Each test compares rows, the
cursor and the attributes of cells:

- `cargo test -p podssh-terminal --test oracle`: after each key of a run,
  the screen shows the prompt and the line from the first column of a row,
  wrapped as the terminal wraps them, with nothing after them, and the
  cursor in the cell where the next character after the text before the
  line's cursor lands. What the screen must show is the model's own drawing
  of the prompt and the line on an empty screen. The runs come from a fixed
  generator: keys of one and two cells, each editing key in each form,
  output, and a lone Escape, on 8, 16 and 20 columns and with no width.
- `cargo test -p podssh-ws --test terminal_oracle`: hostile text after
  `one_line` stays on its row, the cursor moves by its width, and no cell
  takes an attribute; after `multi_line`, each line is a row.
- `cargo test -p podssh-ssh --test terminal_oracle`: each line of a message
  and of the help of `~?` starts at the first column in raw mode
  (`log::message_text`).

The model must agree with tmux before it judges podssh: each sequence of a
fixed corpus (`crates/podssh-terminal/tests/screen/corpus.txt`) goes
through both, and the rows and the cursor must be the same
(`cargo test -p podssh-terminal --test calibration`). `PODSSH_TEST_TMUX`
names tmux; the gate installs it and names it, and with no tmux on the host
the check says that it did not run.
