This file holds the defects of the line discipline in `crates/podssh-terminal`,
the rows L1 to L5 of the former defects page (`git show 3ee70dc:docs/defects.md`),
as T-125 to T-129. `podssh serve` needs the crate on a host with no
`/dev/ptmx` (T-111), so they come before it. No command uses the crate yet
(`docs/STATUS.md:220`), so each defect is P2 at most. Three small terminal
items for the backlog follow.

# T-125: L1: the mode selection of the line discipline is the wrong way round

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row L1
(high); confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The crate selects its mode from two facts: the server granted a pty, and the
remote program is a shell. With no pty, which is the case the crate is for,
each key rings the bell and ends the session. With a pty and a shell, it adds
a local echo to the echo of the remote pty, so each key shows two times.

## Premise

- Read: `Mode::from_grant` gives `NoPty` for no pty, `Cooked` for a pty and a
  shell, and `Passthrough` for a pty and another program
  (`crates/podssh-terminal/src/session.rs` lines 79-85 at `6e77829`). In `NoPty`, each local byte
  sets `ended` and returns a bell (`crates/podssh-terminal/src/session.rs` lines 169-174 at `6e77829`).
  In `Cooked`, the discipline echoes each byte
  (`crates/podssh-terminal/src/echo/editing.rs:180-212`).
- Read, at `6e77829`: tests pin the wrong table (`crates/podssh-terminal/tests/keys.rs` lines 315-326,
  `crates/podssh-terminal/tests/keys.rs` lines 328-346), and plant E builds
  `Session::new(true, true)` (`crates/podssh-terminal/tests/plants.rs` line 327).
- Read: the rule: three inputs select the mode, the user selects the
  discipline, and the absence of a pty alone never selects it
  (`docs/terminal.md:10-18`, and lines 27-32 at `6e77829`). On the server side,
  serve selects it when the cage has no `/dev/ptmx` (`docs/design.md:156-160`).

## Approach

1. Replace `Mode::from_grant` with a choice from three facts: a pty below, a
   line discipline below, and an explicit selection. `Cooked` only when there
   is no pty and no discipline below, and the caller selected it.
2. Each other case is `Transparent`: each byte passes both ways unchanged,
   with no echo and no refusal. Keep the frame and resize logic of
   `Passthrough` in it (`crates/podssh-terminal/src/window.rs:143-151`).
3. Remove `NoPty` and its path that rings the bell and ends the session.
   Remove `remote_is_shell`: a caller cannot know it.
4. The callers give the facts: serve with no `/dev/ptmx` selects the
   discipline (T-111); a client flag can select it later. Invariant: the
   absence of a pty alone never selects `Cooked`.
5. Rewrite the tests above to the new table. Same commit:
   `docs/terminal.md` ("Select a mode"), `docs/STATUS.md:220`, and the module notes
   (`crates/podssh-terminal/src/session.rs:1-46`,
   `crates/podssh-terminal/src/lib.rs:18-34`). Remove the warning markers
   from the lines that you change (`AGENTS.md:194-195`).

## Decision

2026-10-09: `Session` no longer carries the `TERM` choice (`with_term`,
`term`, `term_choice`): they answered only beside `has_pty`, which is gone,
and no caller used them; `term.rs` stays for the work that needs it (T-126).
Keeping them lost: an accessor whose guard is gone would always answer, for
nobody. A selection over a pty gives `Transparent` with no error: the caller
reads `mode()` and can say so.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal --test keys -- mode_
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal --no-fail-fast
```

New tests in crates/podssh-terminal/tests/keys.rs:
`mode_a_granted_pty_adds_no_local_echo` (with a pty below, a typed byte goes
to the remote side once, and nothing is echoed),
`mode_no_pty_and_no_selection_is_transparent` (no bell; the session
continues), and `mode_the_selected_discipline_echoes_and_edits`. Plant:
restore `(true, true) => Mode::Cooked`; the first test fails on the echo. No
command uses the crate, so no check of the binary applies; T-111 runs it
through serve.

## Done

2026-10-09, in the commit "The line discipline runs only when it is selected
and nothing below echoes".

- `crates/podssh-terminal/src/session.rs`: `Facts` (`pty_below`,
  `discipline_below`, `selected`) and `Mode::select`; `Mode` is `Cooked` or
  `Transparent`; `NoPty`, `from_grant`, `has_pty` and the path that rang the
  bell and ended the session are gone. The module notes state the rule.
- `crates/podssh-terminal/src/passthrough.rs`: the transparent leg passes
  each byte as it came, Ctrl-Z, Ctrl-S and Ctrl-Q too, and a chunk as one
  event (`forward_local_bytes`); `refusal.rs`, `echo.rs` and `lib.rs` no
  longer say that it refuses. T-129's step 3 is thereby done, and T-129
  records the lone `\n` that the cooked mode now meets.
- Tests: `mode_a_granted_pty_adds_no_local_echo`,
  `mode_no_pty_and_no_selection_is_transparent`,
  `mode_the_selected_discipline_echoes_and_edits`,
  `mode_each_combination_of_the_three_facts` and
  `mode_transparent_passes_ctrl_z_s_q` in place of the two that pinned the
  old table; the other sessions of `keys.rs` and `plants.rs` built from the
  facts; `legs`, `selected` and `over_a_pty` in the harness.
- `docs/terminal.md`, "Select a mode", and `docs/STATUS.md`.
- Prove: `cargo test -p podssh-terminal --test keys -- mode_`: 5 passed.
  `cargo test -p podssh-terminal --no-fail-fast`: 100 passed. Plant,
  restored: `Mode::select` cooked whenever selected: the first test failed
  on the echo (the local leg held `ab`, the erase and a prompt), and the table of
  eight rows failed too.

# T-126: L2: the line discipline has no raw mode and no window size

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row L2
(high); confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The crate has no raw mode, and it never learns the window size. Its redraw
assumes that the prompt and the line fit in one row. With a line longer than
the width, `\r` goes back only to the start of the last row, and each redraw
writes over the rows above it.

## Premise

- Read: no `termios`, `TIOCGWINSZ` or `libc` call is in
  `crates/podssh-terminal/src`; `libc` is declared and not used
  (`crates/podssh-terminal/Cargo.toml` lines 10-11 at `8d3f63d`). The notes say that the crate
  never reads the size and never sends (`crates/podssh-terminal/src/window.rs:37-42`).
- Read: the redraw is `\r`, the prompt, the line, `ESC [ K`, `\r`, the prompt
  and the line up to the cursor (`crates/podssh-terminal/src/echo.rs:197-207`):
  one row. `Session::on_resize` gives the size to `Window` only
  (`crates/podssh-terminal/src/session.rs:196-201`).
- Read: `podssh-ssh` has a raw mode and a size that work, and the gate checks
  them (`crates/podssh-ssh/src/terminal/unix.rs:12-76`,
  `crates/podssh-ssh/src/terminal/windows.rs:31-111`, `docs/STATUS.md:65`).
- Read: the crate has its own `TERM` rule: it replaces `dumb` and `unknown`,
  and reads `PODSSH_TERM` (`crates/podssh-terminal/src/term.rs:47-53`). The
  documented rule sends `TERM` unchanged (`docs/terminal.md:60-65`). The
  manual does not name `PODSSH_TERM`, and its variable test does not read
  this crate (`crates/podssh-cli/src/man/facts.rs:240-241`).

## Approach

1. Raw mode and the size measurement stay in `podssh-ssh` (see Decision):
   reuse them, and make no second copy.
2. The crate takes a `Size` when it is made and at each resize;
   `Session::on_resize` gives it to the cooked discipline too.
3. The redraw counts rows: the cells of the prompt and the line, divided by
   the columns. It moves up with `ESC [ n A` to the first row, writes from
   `\r`, and puts the cursor by row and column. T-127 gives the cells.
4. One `TERM` rule: remove the crate's selection, because the caller sends
   the `TERM` of the request. Remove the unused `libc` dependency.
5. Same commit: `docs/terminal.md` (who owns raw mode and the size),
   `docs/STATUS.md:220`.

## Decision

Recommendation: the crate stays sans-IO and takes the size as input
(`docs/architecture.md:93-97`); raw mode stays in `podssh-ssh`. The two
callers differ: the client measures its own terminal, and serve (T-111) has
no terminal and gets the size from `pty-req` and `window-change`. Raw mode in
the crate lost: serve has nothing to make raw, and the client's working code
would be copied, and two copies drift.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal --test discipline -- rows_
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal --no-fail-fast
cargo tree -p podssh-terminal -e normal
```

New tests in crates/podssh-terminal/tests/discipline.rs:
`rows_a_long_line_redraws_from_its_first_row` (20 columns, a 30-byte line,
Ctrl-A, then an insert: the bytes hold `ESC [ 1 A`) and
`rows_the_width_follows_a_resize`. Plant: ignore the width in the redraw;
the first test fails. `cargo tree` shows no `libc` for the crate.

## Correction

2026-10-09: T-127 removed the unused `libc` of step 5 (its commit, "With
IUTF8, the line discipline's cursor steps over characters and its screen
moves by cells").

# T-127: L3: the cursor counts bytes, not characters

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row L3
(high); confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The cursor and each edit count bytes. In UTF-8 text, Backspace erases one
byte of a two-byte character: the screen loses a whole cell, the line keeps
half a character, and Enter submits a broken byte. The arrows move one byte
and one cell, so the screen cursor and the line drift apart. A wide
character takes two cells and counts as one.

## Premise

- Read, at `8d3f63d`: the cursor is a byte offset (`crates/podssh-terminal/src/echo/inspect.rs` lines 23-29).
  `erase_left` removes one byte and rubs out one cell
  (`crates/podssh-terminal/src/echo/editing.rs` lines 64-77). The arrows move one
  byte and echo one cell (`crates/podssh-terminal/src/echo/editing.rs` lines 143-150).
  The redraw writes `line[..cursor]`, which can end inside a character
  (`crates/podssh-terminal/src/echo.rs` lines 182-192).
- Read, at `8d3f63d`: the history keeps `String::from_utf8_lossy` copies
  (`crates/podssh-terminal/src/echo.rs` lines 212-224), so a line that is not UTF-8
  comes back changed when it is recalled.
- Read: the client sends `IUTF8` in its pty modes
  (`crates/podssh-ssh/src/terminal/unix.rs:145-151`), so serve (T-111) knows
  from `pty-req` whether the terminal is UTF-8. `unicode-width` is not in
  `Cargo.lock`.

## Approach

1. Keep the line as bytes. Move the cursor by characters (UTF-8 boundaries)
   when the caller says that the terminal is UTF-8 (`IUTF8`), else by bytes,
   as now.
2. Screen motion counts cells: a wide character is 2 cells, a combining mark
   0, a byte that is not UTF-8 1 (see Decision).
3. Backspace, Ctrl-W, Ctrl-D and the arrows act on whole characters; the
   rubout and the arrow echo use the cell count (`ESC [ n D`).
4. The history keeps bytes (`Vec<u8>`), not lossy strings.
5. Same commit: `docs/terminal.md:81-102` (the rules), `docs/STATUS.md:220`.

## Decision

Recommendation: the `unicode-width` crate for the cell widths. It is pure
Rust (the no-C rule of the library crates holds), small, and the table that
most Rust terminal programs use. A table of podssh's own lost: each Unicode
release would need a change by hand.

2026-10-09, three more. **A character typed in parts waits** in the
discipline until it is whole, and a byte that cannot continue it puts its
bytes into the line as typed: the line and the screen then never hold half a
character, also in an insert mid-line. Inserting each byte at once lost: a
redraw would show a lone lead byte. **A control byte or a broken byte takes
1 cell**, the cell of its raw echo, as the bytes mode counts it now; drawing
them as `^X` and U+FFFD, as readline does, lost for now: it changes what the
user sees, which no entry asks for. **The default is bytes** (`Discipline::new`,
`Session::new`); `with_utf8(true)` is for a caller that read `IUTF8`. What
`podssh serve` does when `pty-req` carries no `IUTF8` at all is T-111's to
decide: the client sends it on Linux and Windows, not on macOS.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal --test discipline -- utf8_
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal --no-fail-fast
```

New tests in crates/podssh-terminal/tests/discipline.rs:
`utf8_backspace_erases_one_character` (U+00E9, bytes 0xC3 0xA9, then
Backspace: the submitted line is empty, and one cell is rubbed out),
`utf8_left_moves_over_a_wide_character_by_two_cells` (U+6F22 gives
`ESC [ 2 D`), and `utf8_a_line_that_is_not_utf8_is_recalled_unchanged`.
Plant: give `erase_left` its one-byte step again; the first test fails with
a stray 0xC3.

## Done

2026-10-09, in the commit "With IUTF8, the line discipline's cursor steps
over characters and its screen moves by cells".

- `crates/podssh-terminal/src/echo/units.rs`: the steps of a line (a
  character with its zero-width marks, or a byte), their cells by
  `unicode-width`, and the motion of `n` cells.
- `echo/editing.rs`: Backspace, Ctrl-W, Ctrl-D and the arrows by step and
  cells; the insert waits for a whole character, and the cap drops one whole.
  `echo.rs`: `with_utf8`, the history as bytes, the parts of a character
  put in as typed when the next byte cannot continue them.
  `session.rs`: `Session::with_utf8`.
- `Cargo.toml`: `unicode-width` 0.2.2 (MIT or Apache-2.0, no dependency, no
  build script). `crates/podssh-terminal/Cargo.toml`: the `libc` that no
  code used is gone. Re-resolving moved `errno` and `rustix` to the
  `windows-sys` 0.61.2 that the lock file already held.
- Tests: the entry's three in `tests/discipline.rs`, and
  `utf8_without_iutf8_the_cursor_counts_bytes` (the control),
  `utf8_an_accent_moves_with_its_letter`,
  `utf8_ctrl_w_rubs_out_the_cells_of_wide_characters`,
  `utf8_ctrl_d_deletes_the_whole_character_under_the_cursor`,
  `utf8_a_character_typed_into_the_middle_arrives_whole` and
  `utf8_the_line_cap_never_splits_a_character`; three unit tests of
  `units.rs`.
- `docs/terminal.md` ("When podssh supplies the line discipline") and
  `docs/STATUS.md`.
- Prove: `cargo test -p podssh-terminal --test discipline -- utf8_`: 9
  passed. `cargo test -p podssh-terminal --no-fail-fast`: 112 passed. Plant,
  restored: `erase_left` by one byte: the first test failed, the submitted
  line holding a stray 0xC3.

# T-128: L4: `ESC O x` keys ring the bell, and a single Escape removes the next key

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row L4
(high); confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

Terminals send F1 to F4 as `ESC O P` to `ESC O S`, and the arrows as
`ESC O A` to `ESC O D` in application mode. The discipline rings the bell
for `ESC O` and then types the letter into the line. A lone Escape takes the
next key with it: a letter is lost, and a Ctrl-C after Escape stops nothing.

## Premise

- Read: after `ESC`, each byte that is not `[` is refused and consumed
  (`crates/podssh-terminal/src/escape.rs:128-138`). So `O` is consumed, and
  the byte after it (`P`, `A`) is a fresh key that is inserted
  (`crates/podssh-terminal/src/echo.rs:294-304`,
  `crates/podssh-terminal/src/echo.rs:338`).
- Read: the path that gives a control byte back to the key handling
  (`Restart`) exists only in the CSI state
  (`crates/podssh-terminal/src/escape.rs:157-161`). So `ESC` then Ctrl-C
  loses the Ctrl-C, against the module's own note
  (`crates/podssh-terminal/src/escape.rs:40-45`). Its test covers `ESC [ 1`
  then Ctrl-C only (`crates/podssh-terminal/src/escape.rs:290-306`).
- Read: tests pin the loss: `ESC x a` gives a bell and `a`
  (`crates/podssh-terminal/tests/keys.rs:253-261`,
  `crates/podssh-terminal/src/escape.rs:308-313`). The rule says that
  `ESC O x` is a sequence (`docs/terminal.md:108`).

## Approach

1. Add an SS3 state: `ESC O` and one final byte (0x40 to 0x7E) are one
   sequence. `ESC O A` to `ESC O D`, `ESC O H` and `ESC O F` act as their CSI
   forms. F1 to F4 ring the bell once and insert nothing.
2. After a lone `ESC`, a control byte is a fresh key (`Restart`), as in the
   CSI state. Invariant: an escape never consumes Ctrl-C, Ctrl-D or Enter.
3. A printable byte after a lone `ESC`: see Decision.
4. Rewrite the tests that pin the loss. Same commit: `docs/terminal.md:104-111`,
   `docs/STATUS.md:220`.

## Decision

Recommendation: the caller gives the discipline an idle tick when no byte
came for 50 ms after an `ESC`. A lone `ESC` and then the tick ring the bell
and reset, so the next key is typed as usual. `ESC` and a byte within 50 ms
are an Alt key: one bell, and nothing is inserted. Both callers are
asynchronous and have a timer. The alternative with no timer, which types
each byte after a lone `ESC`, lost: Alt+b would insert a `b`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal --test keys -- escape_
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal --no-fail-fast
```

New tests in crates/podssh-terminal/tests/keys.rs:
`escape_ss3_arrows_move_like_csi_arrows`,
`escape_f1_to_f4_ring_once_and_insert_nothing`,
`escape_then_ctrl_c_still_signals`, and
`escape_alone_then_idle_keeps_the_next_key`. Plant: remove the SS3 state;
the first test fails with `A` in the line.

# T-129: L5: Delete, Home and End, Ctrl-Z, Ctrl-S, Ctrl-Q, and remote output over the edited line

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row L5
(medium); confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Four faults. Delete, Home and End ring the bell in their `~` forms. Home,
End, Ctrl-A and Ctrl-E move the cursor of the line but not of the screen, so
the next insert shows at the wrong place. Passthrough refuses Ctrl-Z, Ctrl-S
and Ctrl-Q over a real pty, where job control and flow control work. Output
that arrives during an edit is written over the edited line.

## Premise

- Read: `ESC [ 3 ~` (Delete), `ESC [ 1 ~` and `ESC [ 7 ~` (Home), and
  `ESC [ 4 ~` and `ESC [ 8 ~` (End) carry a parameter, and each final with a
  parameter is refused (`crates/podssh-terminal/src/echo/editing.rs:142-145`).
- Read: `ESC [ H` and `ESC [ F` move the cursor and send nothing
  (`crates/podssh-terminal/src/echo/editing.rs:152-159`); Ctrl-A and Ctrl-E
  do the same (`crates/podssh-terminal/src/echo.rs:330-337`). Tests pin the
  silence (`crates/podssh-terminal/tests/discipline.rs:175-203`).
- Read, at `6e77829`: passthrough refuses `0x1a`, `0x11` and `0x13`
  (`crates/podssh-terminal/src/passthrough.rs` lines 89-95,
  `crates/podssh-terminal/src/refusal.rs:33-35`), and a test pins it
  (`crates/podssh-terminal/src/passthrough.rs` lines 223-236).
- Read: in the cooked mode, remote bytes go out as they come, and the edited
  line is not drawn again (`crates/podssh-terminal/src/session.rs:177-179`,
  `crates/podssh-terminal/src/passthrough.rs:68-74`).

## Approach

1. Read the parameter of a `~` final: 1 and 7 are Home, 4 and 8 are End, 3
   is Delete (delete under the cursor, as Ctrl-D in a line). Other numbers
   (Insert, Page Up, F5 and above) ring the bell once.
2. Home, End, Ctrl-A and Ctrl-E send the motion: `ESC [ n D` or `ESC [ n C`
   by cells (T-127), or a redraw.
3. The transparent mode of T-125 refuses nothing. Ctrl-Z, Ctrl-S and Ctrl-Q
   stay refused in the cooked mode only (`docs/terminal.md:116-119`).
4. Output during an edit: `\r` and `ESC [ K` clear the edited line, the
   output is written, then the prompt and the line are drawn again with the
   cursor in place. Invariant: output never changes the line under edit.
5. Rewrite the tests that pin the old behaviour. Same commit:
   `docs/terminal.md:113-121`, `docs/STATUS.md:220`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal -- l5_
CARGO_BUILD_JOBS=4 cargo test -p podssh-terminal --no-fail-fast
```

New tests in crates/podssh-terminal/tests/discipline.rs and keys.rs:
`l5_delete_tilde_deletes_under_the_cursor`,
`l5_home_and_end_move_the_screen_cursor`,
`l5_transparent_mode_passes_ctrl_z_s_q`, and
`l5_output_during_an_edit_redraws_the_line` (output arrives after `ab` is
typed: the bytes end with the prompt and `ab`, and Enter submits `ab`).
Plants: restore the silent Home; restore the refusal in the transparent mode.
Each makes its test fail.

## Correction

2026-10-09 (T-125): step 3 is done: the transparent mode refuses nothing.
The cooked mode now runs only with nothing below, so the program's output
reaches it from a pipe, with no `ONLCR`: T-111 adds the `\r` before a lone
`\n` (its Premise), and step 4 draws that output over the edited line.

# T-130: State which terminal sequences podssh reads and which it passes unchanged

**Source:** GitHub #18 and GitHub #19 (nikhiljha/rose
`nikhiljha/rose:doc/spec.md`, lines 19-42, "Terminal Feature Boundary");
`docs/terminal.md:104-121`.
**Category:** docs
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A user cannot tell which keys and sequences podssh acts on. When podssh
takes a byte, it looks like a fault of the remote program. When podssh
passes a sequence, a user can expect podssh to act on it. No page lists both.

## Premise

- Read: in a session with a pty, the client acts only on the escape
  character at the start of a line: `~.`, `~R`, `~?` and `~~`
  (`crates/podssh-ssh/src/escape.rs:1-13`, `crates/podssh-ssh/src/escape.rs:30-70`).
  Each other byte goes to the channel (`crates/podssh-ssh/src/io.rs:58-67`).
- Read: the line discipline acts on the arrows, Home, End and its control
  keys, and refuses other sequences (`docs/terminal.md:104-121`). T-128 and
  T-129 change that list.
- Read in the reports of GitHub #18 and #19, not verified here: rose states
  its terminal boundary in its spec. rose is GPL: read the spec, copy no code.

## Approach

1. Add a section "What podssh reads from the terminal" to `docs/terminal.md`.
   For each mode (a client with a pty, a client with no pty, serve with a
   pty, serve with the line discipline), list the bytes that podssh acts on,
   the bytes that it refuses, and say that each other byte passes unchanged.
2. Put the same list in the manual's notes for `ssh`
   (`crates/podssh-cli/src/man/notes.rs:6-21`), and for `serve` when it
   exists.
3. A drift test: each escape command of `crates/podssh-ssh/src/escape.rs:8-13`
   is in the note, and the note names no other.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli -- terminal_note
"$BIN" man ssh --no-pager >ssh.txt; grep -q 'passes unchanged' ssh.txt
```

The new test `the_terminal_note_names_each_escape` in
crates/podssh-cli/src/man/notes.rs compares the note with the `Command` enum.
Plant: add an escape command to the code and not to the note; the test
fails. The binary (`$BIN`) prints the note in its manual.

# T-131: Which servers honour the `signal` request for Ctrl-C with no remote pty

**Source:** `docs/terminal.md:134-138` (section "Open").
**Category:** measurement
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

With no remote pty, Ctrl-C is only the byte 0x03 on the channel, and a
command on the server does not stop. RFC 4254 (section 6.9) has a `signal`
request, but a server can ignore it, and it is not known which servers act
on it. podssh cannot select a behaviour without that fact.

## Premise

- Read: `docs/terminal.md:134-138` records the question as open.
- Read: podssh's client never sends a `signal` request: no call in
  `crates/podssh-ssh/src`. With no remote pty, the local terminal stays in
  its normal mode (`docs/terminal.md:24`), so Ctrl-C stops podssh itself.
- Read: the russh client has `Channel::signal`
  (`Eugeny/russh:russh/src/channels/mod.rs`, line 244 at `22c3b88`), so a test can send
  the request. `podssh serve` will act on it (T-108).

## Approach

1. A test client in crates/podssh-ssh/tests/signal_request.rs, ignored by
   default: exec `sleep 30` with no pty, send `signal INT` after 1 s, and
   record whether the channel ends within 5 s, and with which status or
   signal.
2. Run it in the gate's container against OpenSSH's sshd and Dropbear
   (`scripts/interop.sh:73-84`). Run it by hand against Tailscale SSH
   (`--direct`) and `railway.new` through the relay, with a throwaway key,
   as in `docs/STATUS.md:66`.
3. Record a table (server, version, result) in `docs/terminal.md` in place of
   the open item, and in `docs/STATUS.md`.
4. With the table, decide in `docs/terminal.md` whether the client sends
   `signal INT` on Ctrl-C when there is no remote pty. A change of the client
   is a new entry.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test signal_request -- --ignored
grep -n 'signal' docs/terminal.md
```

The test prints one line for each server, and exits 0 when each server was
measured, whether it acted or not. A russh server in the test that ignores
the request must read as "ignored"; that is the plant. The grep shows the
recorded table.

# T-132: Compare the Windows console handling with csshw's

**Source:** GitHub #24 (whme/csshw `whme/csshw:src/utils/windows.rs`:
`disabled_console_color`, ConPTY handling).
**Category:** research
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

podssh handles the Windows console itself: raw mode, VT input and output,
the size by a poll, and prompts on `CONIN$`. csshw is a Rust SSH tool for
Windows consoles that handles console quirks explicitly. A comparison can
find a case that the 14 console checks of podssh do not cover.

## Premise

- Read: the console code: `crates/podssh-ssh/src/terminal/windows.rs:68-111`
  (raw mode, restored on drop and on panic),
  `crates/podssh-ssh/src/terminal/windows.rs:115-138` (pty modes),
  `crates/podssh-ssh/src/terminal/windows.rs:142-181` (prompts), and the size
  poll every 500 ms (`crates/podssh-ssh/src/io.rs:179-227`). The checks of
  `scripts/interop-conpty.py` pass 14 of 14 (`docs/STATUS.md:69`).
- Read: podssh sets no console code page, and remote output goes through
  Rust's standard output (`crates/podssh-ssh/src/io.rs:140-150`). Rust's
  documentation of `std::io::Stdout` says that a console refuses bytes that
  are not UTF-8. podssh then ends the session as if stdout were closed
  (`crates/podssh-ssh/src/io.rs:106-111`). Not measured.
- Read in the report of GitHub #24, not verified here: csshw handles console
  color and ConPTY quirks in `whme/csshw:src/utils/windows.rs`.

## Approach

1. Read csshw at the commit of the report (`6dd773b`). List each console
   mode, code page and call that it sets, and each quirk that it handles.
2. Write a table in the section "The Windows console" of `docs/terminal.md`
   (`docs/terminal.md:67-79`): each item of csshw against podssh, with
   "same", "podssh lacks it" or "not needed", and the reason.
3. Measure the candidates in a real console with `scripts/interop-conpty.py`:
   output that is not UTF-8 (`printf '\377'` on the server), the code page,
   Ctrl-Break, and a resize event against the poll.
4. Each difference that is a fault gets a new entry; each item that podssh
   keeps different gets its reason in the table.

## Prove

```sh
grep -n 'csshw' docs/terminal.md
grep -n 'UTF-8' docs/terminal.md
```

The first grep shows the table, and the second the measured result for
output that is not UTF-8 in a console. The ConPTY run that measured it uses
a server, as in `docs/STATUS.md:69`, and its output is recorded in
`docs/STATUS.md`.
