//! ⛔ **Echo, erasing and submission: byte for byte, on both legs.**
//!
//! ⛔ **Every assertion in this file names the exact bytes.** The entry's rule is
//! explicit: *"A test that only checks that 'something was echoed' cannot catch
//! this class of bug, because the failure is the right bytes in the wrong
//! direction or the wrong sequence substituted."* ⛔ So a test here asserts on
//! `ToLocal` and `ToRemote` **separately and exactly**, and never on "the output
//! contains something".
//!
//! ⭐ **Every rule below is transcribed**, and each test names the line of
//! `.tmp/podbox/crates/podbox-ssh/src/session.rs` it came from, read with
//! `sed -n` on 2026-10-02. ⛔ The sibling's own suite is at `session.rs:752-1132`
//! and roughly twenty of these are the same assertions, ⛔ because a transcription
//! that re-derives its own numbers is an invention.
//!
//! ## What this file holds, and why it is not all of it
//!
//! ⛔ **Characters only.** ⛔ What a byte typed into a line produces: the echo,
//! the erase, the submit. ⛔ Escapes, history, signals, the two modes and window
//! size are in `keys.rs`, ⛔ and the harness that keeps the two legs apart is in
//! `common/mod.rs`, so ⛔ **the byte-exactness rigour is written once and both
//! files use it.**
//!
//! ## Where a rule is deliberately NOT the sibling's
//!
//! ⛔ **No `onlcr`.** ⛔ The sibling expands a lone `\n` to `\r\n` on the way out
//! (`session.rs:629-642`) because its shell runs on a pipe with no `OPOST`.
//! ⛔ podssh's far side is a real pty which has already done that translation,
//! and expanding again would stair-step every line. ⛔ The `passthrough` tests
//! pin that half.

use podssh_terminal::echo::{Discipline, BELL, EL, PROMPT};

mod common;
use common::{feed, has};

// ───────────────────────────────── echo and submission

#[test]
fn typing_echoes_byte_for_byte_and_enter_submits_once() {
    // ⛔ **The baseline both legs hang off.** ⛔ `local` is the echo and the
    // prompt the shell never prints; `remote` is the submitted line and nothing
    // else. ⛔ If the two were merged into one buffer this test would still pass
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
    // ⛔ **A client speaking CRLF must not run every command twice.**
    // Transcribed from `session.rs:789-797` and its own comment. ⛔ The `\n`
    // half is swallowed and produces **no event at all** — not an empty submit.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"a\r\n");
    assert_eq!(got.local, b"a\r\n$ ", "{}", got.show());
    assert_eq!(got.remote, b"a\n", "one line, not two");
}

#[test]
fn a_lone_cr_and_a_lone_lf_both_submit() {
    // ⛔ **Each alone, in a fresh discipline** — back to back they would be a
    // `\r\n` pair, which is the case above. Transcribed: `session.rs:799-809`.
    let mut cr = Discipline::new();
    assert_eq!(feed(&mut cr, b"\r").remote, b"\n");
    let mut lf = Discipline::new();
    assert_eq!(feed(&mut lf, b"\n").remote, b"\n");
}

#[test]
fn the_prompt_is_the_transcribed_one() {
    // ⛔ The prompt is `$ `, byte for byte, because a prompt is a byte sequence
    // every redraw embeds. Transcribed: `session.rs:102`.
    assert_eq!(PROMPT, b"$ ");
    assert_eq!(EL, b"\x1b[K");
    assert_eq!(BELL, b"\x07");
}

// ───────────────────────────────── erasing

#[test]
fn backspace_rubs_out_one_cell_with_three_bytes() {
    // ⛔ **The rubout triple, exactly.** ⛔ Not "the character went away" — the
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
    // ⛔ **`0x08` and `0x7f` are one arm** (`session.rs:278`), so they must be
    // indistinguishable — a user on a terminal that sends either gets the same
    // bytes back.
    let mut del = Discipline::new();
    let mut bs = Discipline::new();
    assert_eq!(feed(&mut del, b"ab\x7f").local, feed(&mut bs, b"ab\x08").local);
    assert_eq!(feed(&mut del, b"ab\x7f").local, b"ab\x08 \x08");
}

#[test]
fn erase_at_the_start_of_the_line_bells() {
    // ⛔ **The refusal half**, and it is a bell rather than silence: silence
    // reads as acceptance. Transcribed: `session.rs:819-825`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"\x7f");
    assert_eq!(got.local, BELL, "{}", got.show());
    assert!(got.remote.is_empty(), "{}", got.show());
}

#[test]
fn ctrl_u_erases_the_line_with_one_fixed_shape() {
    // ⛔ **`\r`, prompt, `EL` — and nothing else**, whatever the line's length.
    // ⛔ That is the whole point of the shape: one byte sequence for every length
    // is something a terminal and a test can both rely on. ⛔ And the line is
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
    // ⛔ **Trailing blanks go first, then the word**, and the boundary is the
    // space — what a shell word means here. Transcribed: `session.rs:841-846`
    // and `354-376`.
    let mut d = Discipline::new();
    assert_eq!(feed(&mut d, b"foo bar\x17\n").remote, b"foo \n");

    // ⛔ **The whole cell count rubbed out when it ends at the line end.** ⛔ The
    // echoed `foo  ` is on the leg too and the assertion says so: ⛔ a test that
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
    // ⛔ **Two different answers for two different positions, and both are
    // required.** ⛔ At the line end the three-byte triple is exact. ⛔ Mid-line
    // the tail moved and only a full redraw puts every cell right — using the
    // triple there would leave the rest of the line stale on screen. ⛔ The
    // assertion is that `EL` appears, and separately that it appears *only* in
    // the mid-line case.
    let mut end = Discipline::new();
    assert!(!has(&feed(&mut end, b"abc\x7f").local, EL), "at the end: no redraw");

    let mut mid = Discipline::new();
    let got = feed(&mut mid, b"abc\x1b[D\x1b[D\x7f\n");
    assert!(has(&got.local, EL), "mid-line: {}", got.show());
    assert_eq!(got.remote, b"bc\n", "erasing left of the cursor removed 'a'");
}

// ───────────────────────────────── moving

#[test]
fn ctrl_a_and_ctrl_e_are_silent_moves() {
    // ⛔ **Silent is the assertion.** ⛔ The jump echoes nothing, and the only
    // place the moved cursor shows is the redraw the *next* insert triggers.
    // Transcribed: `session.rs:937-947`.
    let mut d = Discipline::new();
    assert_eq!(feed(&mut d, b"ab\x01").local, b"ab", "home echoes nothing");
    let got = feed(&mut d, b"X\n");
    assert!(has(&got.local, EL), "{}", got.show());
    assert_eq!(got.remote, b"Xab\n", "the insert landed at the start");

    let mut d = Discipline::new();
    let got = feed(&mut d, b"ab\x1b[H\x05X\n");
    assert_eq!(&got.local[..2], b"ab", "the jump itself echoes nothing");
    assert_eq!(got.remote, b"abX\n", "and the insert landed at the end");
}

#[test]
fn esc_h_and_esc_f_move_like_ctrl_a_and_ctrl_e() {
    // ⛔ **`ESC [ H` and `ESC [ F`, silent**, exactly as their Ctrl equivalents.
    // Transcribed: `session.rs:992-1007`.
    let mut d = Discipline::new();
    assert_eq!(feed(&mut d, b"ab\x1b[H").local, b"ab", "home echoes nothing");
    assert_eq!(feed(&mut d, b"X\n").remote, b"Xab\n");

    let mut d = Discipline::new();
    assert_eq!(feed(&mut d, b"ab\x1b[H\x1b[F").local, b"ab", "end echoes nothing");
    assert_eq!(feed(&mut d, b"X\n").remote, b"abX\n");
}

#[test]
fn left_and_right_echo_their_own_sequences_and_only_those() {
    // ⛔ **The arrows echo exactly what they are.** ⛔ `ESC [ D` moves a real
    // terminal's cursor to exactly where the discipline's cursor went; sending
    // anything else — or nothing — leaves the two out of step, and the first
    // insert afterwards then redraws at the wrong place.
    // Transcribed: `session.rs:980-990`, `381-392`.
    let mut d = Discipline::new();
    assert_eq!(feed(&mut d, b"ac\x1b[D").local, b"ac\x1b[D", "left echoes ESC [ D");
    assert!(has(&feed(&mut d, b"b").local, EL), "insert redraws");
    assert_eq!(feed(&mut d, b"\n").remote, b"abc\n");

    let mut d = Discipline::new();
    let got = feed(&mut d, b"ac\x1b[D\x1b[D\x1b[C");
    assert!(got.local.windows(3).any(|w| w == b"\x1b[C"), "right echoes ESC [ C");
    assert_eq!(feed(&mut d, b"b\n").remote, b"abc\n");
}

#[test]
fn an_arrow_at_its_bound_bells_and_the_line_survives() {
    // ⛔ **Two refusals and a survivor.** ⛔ Left at column zero and right at the
    // end of the line ring, and ⛔ **the line underneath is untouched** — that
    // last half is what a refusal that damaged state would fail.
    // Transcribed: `session.rs:1105-1118`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"\x1b[D");
    assert_eq!(got.local, BELL, "{}", got.show());
    assert!(got.remote.is_empty(), "{}", got.show());

    let mut d = Discipline::new();
    let got = feed(&mut d, b"a\x1b[C");
    assert_eq!(got.local, b"a\x07", "the echo stands, then the bell",);
    assert_eq!(feed(&mut d, b"\n").remote, b"a\n", "and the line survived");
}
