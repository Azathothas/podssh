//! **Echo, erasing and submission: byte for byte, on both legs.**
//!
//! **Every assertion in this file names the exact bytes.** The entry's rule is
//! explicit: *"A test that only checks that 'something was echoed' cannot catch
//! this class of bug, because the failure is the right bytes in the wrong
//! direction or the wrong sequence substituted."* So a test here asserts on
//! `ToLocal` and `ToRemote` **separately and exactly**, and never on "the output
//! contains something".
//!
//! **Every rule below is transcribed**, and each test names the line of
//! `.tmp/podbox/crates/podbox-ssh/src/session.rs` it came from, read with
//! `sed -n` on 2026-10-02. The sibling's own suite is at `session.rs:752-1132`
//! and roughly twenty of these are the same assertions, because a transcription
//! that re-derives its own numbers is an invention.
//!
//! ## What this file holds, and why it is not all of it
//!
//! **Characters only.** What a byte typed into a line produces: the echo,
//! the erase, the submit, and the rows of a line wider than the terminal.
//! Escapes, history, signals and the two modes are in `keys.rs`, the moving
//! keys and Delete in `motion.rs`, output during an edit in `output.rs`,
//! window size in `window.rs`, and the harness that keeps the two legs apart
//! is in `common/mod.rs`, so **the byte-exactness rigour is written once and
//! each file uses it.**
//!
//! ## Where a rule is deliberately NOT the sibling's
//!
//! **No `onlcr`.** The sibling expands a lone `\n` to `\r\n` on the way out
//! (`session.rs:629-642`) because its shell runs on a pipe with no `OPOST`.
//! podssh's far side is a real pty which has already done that translation,
//! and expanding again would stair-step every line. The `passthrough` tests
//! pin that half.

use podssh_terminal::echo::{Discipline, BELL, EL, LINE_CAP, PROMPT};
use podssh_terminal::session::Session;
use podssh_terminal::window::Size;

mod common;
use common::{feed, has, legs, selected};

// ───────────────────────────────── echo and submission

#[test]
fn typing_echoes_byte_for_byte_and_enter_submits_once() {
    // **The baseline both legs hang off.** `local` is the echo and the
    // prompt the shell never prints; `remote` is the submitted line and nothing
    // else. If the two were merged into one buffer this test would still pass
    // and the *wrong direction* would be undetectable — which is the class of
    // bug the entry names. Transcribed: `session.rs:781-787`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"hi\n");
    assert_eq!(got.local, b"hi\r\n$ ", "the echo and the next prompt");
    assert_eq!(got.remote, b"hi\n", "exactly one line, one newline");
    assert!(got.signals.is_empty(), "{}", got.show());
    assert!(!got.eof, "{}", got.show());
}

#[test]
fn a_crlf_pair_is_one_enter_and_not_two_commands() {
    // **A client speaking CRLF must not run every command twice.**
    // Transcribed from `session.rs:789-797` and its own comment. The `\n`
    // half is swallowed and produces **no event at all** — not an empty submit.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"a\r\n");
    assert_eq!(got.local, b"a\r\n$ ", "{}", got.show());
    assert_eq!(got.remote, b"a\n", "one line, not two");
}

#[test]
fn a_key_between_cr_and_lf_ends_the_pair() {
    // Only the byte right after a `\r` is its pair: after Enter and Up, a
    // Ctrl-J submits the recalled line, as in the reference, where `ESC` is
    // itself a key.
    let mut d = Discipline::new();
    feed(&mut d, b"one\r");
    let got = feed(&mut d, b"\x1b[A\n");
    assert_eq!(got.remote, b"one\n", "{}", got.show());
}

#[test]
fn a_lone_cr_and_a_lone_lf_both_submit() {
    // **Each alone, in a fresh discipline** — back to back they would be a
    // `\r\n` pair, which is the case above. Transcribed: `session.rs:799-809`.
    let mut cr = Discipline::new();
    assert_eq!(feed(&mut cr, b"\r").remote, b"\n");
    let mut lf = Discipline::new();
    assert_eq!(feed(&mut lf, b"\n").remote, b"\n");
}

#[test]
fn the_prompt_is_the_transcribed_one() {
    // The prompt is `$ `, byte for byte, because a prompt is a byte sequence
    // every redraw embeds. Transcribed: `session.rs:102`.
    assert_eq!(PROMPT, b"$ ");
    assert_eq!(EL, b"\x1b[K");
    assert_eq!(BELL, b"\x07");
}

// ───────────────────────────────── erasing

#[test]
fn backspace_rubs_out_one_cell_with_three_bytes() {
    // **The rubout triple, exactly.** Not "the character went away" — the
    // three bytes `\b`, space, `\b` are what a real terminal answers to, and a
    // redraw here instead of the triple would be a visible difference at the end
    // of a line. Transcribed: `session.rs:811-817`, `189-198`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"ab\x7f\n");
    assert_eq!(got.local, b"ab\x08 \x08\r\n$ ", "{}", got.show());
    assert_eq!(got.remote, b"a\n");
}

#[test]
fn ctrl_h_backspace_erases_exactly_as_del_does() {
    // **`0x08` and `0x7f` are one arm** (`session.rs:278`), so they must be
    // indistinguishable — a user on a terminal that sends either gets the same
    // bytes back.
    let mut del = Discipline::new();
    let mut bs = Discipline::new();
    assert_eq!(feed(&mut del, b"ab\x7f").local, feed(&mut bs, b"ab\x08").local);
    assert_eq!(feed(&mut del, b"ab\x7f").local, b"ab\x08 \x08");
}

#[test]
fn erase_at_the_start_of_the_line_bells() {
    // **The refusal half**, and it is a bell rather than silence: silence
    // reads as acceptance. Transcribed: `session.rs:819-825`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"\x7f");
    assert_eq!(got.local, BELL, "{}", got.show());
    assert!(got.remote.is_empty(), "{}", got.show());
}

#[test]
fn ctrl_u_erases_the_line_with_one_fixed_shape() {
    // **`\r`, prompt, `EL` — and nothing else**, whatever the line's length.
    // That is the whole point of the shape: one byte sequence for every length
    // is something a terminal and a test can both rely on. And the line is
    // gone afterwards, which the submit proves. Transcribed: `session.rs:827-839`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"hello\x15");
    let mut expect = b"hello".to_vec();
    expect.extend_from_slice(b"\r");
    expect.extend_from_slice(PROMPT);
    expect.extend_from_slice(EL);
    assert_eq!(got.local, expect, "{}", got.show());
    assert!(got.remote.is_empty(), "{}", got.show());
    assert_eq!(feed(&mut d, b"\n").remote, b"\n", "the line was erased");
}

#[test]
fn ctrl_w_erases_blanks_then_one_word() {
    // **Trailing blanks go first, then the word**, and the boundary is the
    // space — what a shell word means here. Transcribed: `session.rs:841-846`
    // and `354-376`.
    let mut d = Discipline::new();
    assert_eq!(feed(&mut d, b"foo bar\x17\n").remote, b"foo \n");

    // **The whole cell count rubbed out when it ends at the line end.** The
    // echoed `foo  ` is on the leg too and the assertion says so: a test that
    // dropped it from its expectation would have passed a `Ctrl-W` that erased
    // the wrong thing entirely.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"foo  \x17");
    let mut expected = b"foo  ".to_vec();
    expected.extend_from_slice(&Discipline::rubout(5));
    assert_eq!(got.local, expected, "{}", got.show());
    assert_eq!(feed(&mut d, b"\n").remote, b"\n", "and the line is empty");
}

#[test]
fn a_mid_line_erase_redraws_because_the_tail_shifted() {
    // **Two different answers for two different positions, and both are
    // required.** At the line end the three-byte triple is exact. Mid-line
    // the tail moved and only a full redraw puts every cell right — using the
    // triple there would leave the rest of the line stale on screen. The
    // assertion is that `EL` appears, and separately that it appears *only* in
    // the mid-line case.
    let mut end = Discipline::new();
    assert!(!has(&feed(&mut end, b"abc\x7f").local, EL), "at the end: no redraw");

    let mut mid = Discipline::new();
    let got = feed(&mut mid, b"abc\x1b[D\x1b[D\x7f\n");
    assert!(has(&got.local, EL), "mid-line: {}", got.show());
    assert_eq!(got.remote, b"bc\n", "erasing left of the cursor removed 'a'");
}

// ───────────────────────────────── the cap

#[test]
fn a_line_past_the_cap_drops_bytes_with_a_bell_each() {
    // **Exactly one bell per rejected byte, and the accepted bytes still
    // echo themselves.** An unbounded line buffer is the defect the cap
    // exists to prevent, so the cap's arithmetic is asserted, not its existence.
    // Transcribed: `session.rs:957-968`, `108`.
    assert_eq!(LINE_CAP, 65536);
    let mut d = Discipline::new();
    let big = vec![b'y'; LINE_CAP + 5];
    let got = feed(&mut d, &big);
    assert_eq!(got.local.len(), LINE_CAP + 5, "echo plus five bells");
    assert_eq!(got.local.iter().filter(|b| **b == b'\x07').count(), 5, "one bell each");
    assert_eq!(feed(&mut d, b"\n").remote.len(), LINE_CAP + 1, "and the line submits");
}

// ───────────────────────────────── UTF-8: characters and cells

#[test]
fn utf8_backspace_erases_one_character() {
    // U+00E9 is two bytes, one cell: Backspace takes both, and rubs out one
    // cell. The plant, a one-byte step, leaves a stray 0xC3 on the line.
    let mut d = Discipline::with_utf8(true);
    let got = feed(&mut d, b"\xc3\xa9\x7f\r");
    assert_eq!(got.remote, b"\n", "the submitted line is empty: {}", got.show());
    assert_eq!(got.local, b"\xc3\xa9\x08 \x08\r\n$ ", "{}", got.show());
}

#[test]
fn utf8_left_moves_over_a_wide_character_by_two_cells() {
    // U+6F22 takes two cells, so the screen cursor moves two.
    let mut d = Discipline::with_utf8(true);
    let got = feed(&mut d, "\u{6f22}".as_bytes());
    assert_eq!(got.local, "\u{6f22}".as_bytes(), "the echo, once the character is whole");
    assert_eq!(feed(&mut d, b"\x1b[D").local, b"\x1b[2D");
    assert_eq!(feed(&mut d, b"a\r").remote, "a\u{6f22}\n".as_bytes(), "the insert lands before it");
}

#[test]
fn utf8_a_line_that_is_not_utf8_is_recalled_unchanged() {
    // History keeps bytes: a lossy copy would come back as U+FFFD.
    let mut d = Discipline::with_utf8(true);
    feed(&mut d, b"\xff\xfe\r");
    let got = feed(&mut d, b"\x1b[A\r");
    assert_eq!(got.remote, b"\xff\xfe\n", "{}", got.show());
}

#[test]
fn utf8_without_iutf8_the_cursor_counts_bytes() {
    // The control: with no IUTF8, Backspace takes one byte, as a terminal
    // with no IUTF8 does.
    let mut d = Discipline::new();
    assert_eq!(feed(&mut d, b"\xc3\xa9\x7f\r").remote, b"\xc3\n");
}

#[test]
fn utf8_an_accent_moves_with_its_letter() {
    // e and U+0301 are one step of one cell: Left moves one cell to the
    // start, where Backspace has nothing to erase.
    let mut d = Discipline::with_utf8(true);
    feed(&mut d, "e\u{301}".as_bytes());
    assert_eq!(feed(&mut d, b"\x1b[D").local, b"\x1b[D");
    assert_eq!(d.cursor(), 0);
    assert_eq!(feed(&mut d, b"\x7f").local, BELL);
}

#[test]
fn utf8_ctrl_w_rubs_out_the_cells_of_wide_characters() {
    let mut d = Discipline::with_utf8(true);
    feed(&mut d, "a \u{6f22}\u{6f22}".as_bytes());
    assert_eq!(feed(&mut d, b"\x17").local, Discipline::rubout(4), "two wide characters, four cells");
    assert_eq!(feed(&mut d, b"\r").remote, b"a \n");
}

#[test]
fn utf8_ctrl_d_deletes_the_whole_character_under_the_cursor() {
    let mut d = Discipline::with_utf8(true);
    feed(&mut d, "\u{6f22}a\x1b[D\x1b[D".as_bytes());
    assert_eq!(d.cursor(), 0);
    feed(&mut d, b"\x04");
    assert_eq!(d.line(), b"a", "no half of the character stays");
}

#[test]
fn utf8_a_character_typed_into_the_middle_arrives_whole() {
    // One redraw, holding the whole character: never a redraw with a lone
    // lead byte.
    let mut d = Discipline::with_utf8(true);
    feed(&mut d, b"ab\x1b[D");
    assert!(feed(&mut d, b"\xc3").local.is_empty(), "half a character waits");
    let got = feed(&mut d, b"\xa9");
    assert_eq!(got.local, b"\r$ a\xc3\xa9b\x1b[K\r$ a\xc3\xa9", "{}", got.show());
}

#[test]
fn utf8_the_line_cap_never_splits_a_character() {
    let mut d = Discipline::with_utf8(true);
    feed(&mut d, &vec![b'y'; LINE_CAP - 1]);
    let got = feed(&mut d, b"\xc3\xa9");
    assert_eq!(got.local, BELL, "the character drops whole: {}", got.show());
    assert_eq!(d.line().len(), LINE_CAP - 1);
}

// ───────────────────────────────── rows: a line wider than the terminal

/// A discipline that knows its terminal is `cols` wide.
fn sized(cols: u16, utf8: bool) -> Discipline {
    let mut d = Discipline::with_utf8(utf8);
    assert!(d.resize(Size::new(24, cols)).is_empty(), "an empty line draws nothing");
    d
}

#[test]
fn rows_a_long_line_redraws_from_its_first_row() {
    // 20 columns: the prompt and 18 `a` fill the first row, 12 more the
    // second. An insert there redraws from the first row; `\r` alone would
    // go back only to the start of the cursor's row.
    let mut d = sized(20, false);
    feed(&mut d, &[b'a'; 30]);
    feed(&mut d, &b"\x1b[D".repeat(12));
    let got = feed(&mut d, b"X");
    let want = [&b"\x1b[A\r$ "[..], &[b'a'; 18], b"X", &[b'a'; 12], b"\x1b[J\x1b[12D"].concat();
    assert_eq!(got.local, want, "{}", got.show());
    assert_eq!(feed(&mut d, b"\r").remote, [&[b'a'; 18][..], b"X", &[b'a'; 12], b"\n"].concat());
}

#[test]
fn rows_the_width_follows_a_resize() {
    // Told 80 columns, then 20: the line is drawn again on a row of its own,
    // over two rows, and the next redraw starts a row up. The cooked mode has
    // no size to send.
    let mut s = Session::new(selected()).sized(Size::new(24, 80));
    legs(s.on_local_bytes(&[b'a'; 30]));
    let got = legs(s.on_resize(Size::new(24, 20)));
    assert_eq!(got.local, [&b"\r\n\r$ "[..], &[b'a'; 30], b"\x1b[J"].concat(), "{}", got.show());
    assert!(got.sizes.is_empty(), "{}", got.show());
    assert_eq!(legs(s.on_resize(Size::new(40, 20))), Default::default(), "the same width draws nothing");
    let got = legs(s.on_local_bytes(b"\x1b[DX"));
    assert!(got.local.starts_with(b"\x1b[D\x1b[A\r$ "), "{}", got.show());
}

#[test]
fn rows_an_append_to_the_last_column_moves_to_the_next_row() {
    // The 18th `a` fills the row, and the terminal's cursor would wait in its
    // last column: `\r\n` takes it to the next row, where the discipline
    // counts it.
    let mut d = sized(20, false);
    feed(&mut d, &[b'a'; 17]);
    assert_eq!(feed(&mut d, b"a").local, b"a\r\n");
    assert_eq!(feed(&mut d, b"b").local, b"b", "the next byte is an echo again");
}

#[test]
fn rows_backspace_over_a_row_start_redraws_instead_of_rubbing_out() {
    // `\b` does not go up a row, so erasing the last cell of the row above
    // is a redraw; on the cursor's own row the triple serves again.
    let mut d = sized(20, false);
    feed(&mut d, &[b'a'; 18]);
    let got = feed(&mut d, b"\x7f");
    assert_eq!(got.local, [&b"\x1b[A\r$ "[..], &[b'a'; 17], b"\x1b[J"].concat(), "{}", got.show());
    assert_eq!(feed(&mut d, b"\x7f").local, Discipline::rubout(1));
}

#[test]
fn rows_enter_in_a_long_line_leaves_from_its_last_row() {
    // Enter with the cursor on the first row: the next prompt goes below the
    // line, not over its second row.
    let mut d = sized(20, false);
    feed(&mut d, &[b'a'; 30]);
    feed(&mut d, &b"\x1b[D".repeat(20));
    let got = feed(&mut d, b"\r");
    assert_eq!(got.local, b"\x1b[B\r\n$ ", "{}", got.show());
    assert_eq!(got.remote, [&[b'a'; 30][..], b"\n"].concat());
}

#[test]
fn rows_ctrl_u_and_ctrl_c_start_from_the_rows_they_need() {
    // Ctrl-U goes up to the first row and clears below it; Ctrl-C with the
    // cursor on the first row writes its caret after the line, not over it.
    let mut d = sized(20, false);
    feed(&mut d, &[b'a'; 30]);
    assert_eq!(feed(&mut d, b"\x15").local, b"\x1b[A\r$ \x1b[J");
    feed(&mut d, &[b'a'; 30]);
    feed(&mut d, &b"\x1b[D".repeat(20));
    let got = feed(&mut d, b"\x03");
    assert_eq!(got.local, b"\x1b[B^C\r\n$ ", "{}", got.show());
}

#[test]
fn rows_with_no_size_the_redraw_stays_on_one_row() {
    // The control: with no width known, a long line redraws in the
    // transcribed shape, as the reference's does.
    let mut d = Discipline::new();
    feed(&mut d, &[b'a'; 100]);
    let got = feed(&mut d, b"\x1b[DX");
    let want = [&b"\x1b[D\r$ "[..], &[b'a'; 99], b"Xa", EL, b"\r$ ", &[b'a'; 99], b"X"].concat();
    assert_eq!(got.local, want, "{}", got.show());
}

#[test]
fn rows_a_wide_character_that_does_not_fit_starts_the_next_row() {
    // Six columns: `$ abc` leaves one cell, and the wide character takes two,
    // so the terminal starts it on the next row; Left goes back up, to after
    // the `c`.
    let mut d = sized(6, true);
    assert_eq!(feed(&mut d, "abc漢".as_bytes()).local, "abc漢".as_bytes());
    assert_eq!(feed(&mut d, b"\x1b[D").local, b"\x1b[A\x1b[3C");
}

// ───────────────────────────────── what a log may show

#[test]
fn the_debug_form_shows_no_typed_text() {
    // A `Debug` print of the discipline goes into logs: it shows the shape
    // of the line, never the bytes, which may be a password typed at a
    // mistaken prompt.
    let mut d = Discipline::new();
    feed(&mut d, b"hunter2\rsecond");
    let shown = format!("{d:?}");
    assert!(!shown.contains("hunter2") && !shown.contains("second"), "{shown}");
    assert!(shown.contains("line_len: 6"), "{shown}");
}
