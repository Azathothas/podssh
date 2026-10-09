//! **The moving keys and Delete: the line's cursor and the screen's together.**
//!
//! The arrows, Home and End move the cursor of the line and the cursor of the
//! screen by the same step, so the next key lands where the user sees the
//! cursor: on one row by `ESC [ n D` and `ESC [ n C`, and over rows by
//! `ESC [ n A` and `ESC [ n B` too. Delete removes the character under the
//! cursor and never ends input. Each key is asserted in each form a terminal
//! sends it, byte for byte.

use podssh_terminal::echo::{Discipline, BELL, EL};
use podssh_terminal::window::Size;

mod common;
use common::{feed, has};

// ───────────────────────────────── Home and End

#[test]
fn l5_home_and_end_move_the_screen_cursor() {
    // Each form of Home after `abc`: Ctrl-A, `ESC [ H`, `ESC O H`, and the
    // VT220 and rxvt `ESC [ 1 ~` and `ESC [ 7 ~`; then each form of End. The
    // screen's cursor goes with the line's, so `d` lands at the end.
    let homes: [&[u8]; 5] = [b"\x01", b"\x1b[H", b"\x1bOH", b"\x1b[1~", b"\x1b[7~"];
    let ends: [&[u8]; 5] = [b"\x05", b"\x1b[F", b"\x1bOF", b"\x1b[4~", b"\x1b[8~"];
    for (home, end) in homes.iter().zip(ends) {
        let mut d = Discipline::new();
        feed(&mut d, b"abc");
        assert_eq!(feed(&mut d, home).local, b"\x1b[3D", "{home:02x?}");
        assert_eq!(feed(&mut d, end).local, b"\x1b[3C", "{end:02x?}");
        assert_eq!(feed(&mut d, b"d").local, b"d", "the screen's cursor is at the end");
        assert_eq!(feed(&mut d, b"\r").remote, b"abcd\n");
    }
    // Home at the start, and End at the end, move nothing.
    let mut d = Discipline::new();
    assert!(feed(&mut d, b"\x01\x05").local.is_empty());
}

#[test]
fn l5_home_and_then_an_insert_lands_at_the_start() {
    // The insert after Home redraws from the start of the line, and the
    // cursor stays after the inserted byte.
    let mut d = Discipline::new();
    feed(&mut d, b"ab\x01");
    let got = feed(&mut d, b"X");
    assert!(has(&got.local, EL), "{}", got.show());
    assert!(got.local.ends_with(b"\r$ X"), "{}", got.show());
    assert_eq!(feed(&mut d, b"\n").remote, b"Xab\n");
}

#[test]
fn l5_home_on_a_long_line_moves_up_a_row() {
    // 20 columns, 30 `a`: the end is on the second row, so Home goes up a
    // row and back to the column after the prompt, and End goes back down.
    let mut d = Discipline::new();
    d.resize(Size::new(24, 20));
    feed(&mut d, &[b'a'; 30]);
    assert_eq!(feed(&mut d, b"\x01").local, b"\x1b[A\x1b[10D");
    assert_eq!(feed(&mut d, b"\x05").local, b"\x1b[B\x1b[10C");
}

// ───────────────────────────────── Delete, and the other `~` keys

#[test]
fn l5_delete_tilde_deletes_under_the_cursor() {
    // `ESC [ 3 ~` deletes under the cursor and redraws; at the end of a line,
    // and on an empty one, it does nothing, and it never ends input as Ctrl-D
    // on an empty line does.
    let mut d = Discipline::new();
    feed(&mut d, b"abc\x1b[D\x1b[D");
    let got = feed(&mut d, b"\x1b[3~");
    assert_eq!(got.local, b"\r$ ac\x1b[K\r$ a", "{}", got.show());
    assert_eq!(feed(&mut d, b"\r").remote, b"ac\n");

    let mut d = Discipline::new();
    for line in [&b""[..], b"x"] {
        feed(&mut d, line);
        let got = feed(&mut d, b"\x1b[3~");
        assert!(got.local.is_empty() && !got.eof, "{line:?}: {}", got.show());
    }
}

#[test]
fn l5_other_tilde_keys_ring_once() {
    // Insert, Page Up and Down, F5, F12, and Ctrl+Left: one bell each, and
    // the line unchanged.
    let keys: [&[u8]; 6] = [b"\x1b[2~", b"\x1b[5~", b"\x1b[6~", b"\x1b[15~", b"\x1b[24~", b"\x1b[1;5D"];
    for key in keys {
        let mut d = Discipline::new();
        feed(&mut d, b"ab");
        let got = feed(&mut d, key);
        assert_eq!(got.local, BELL, "{key:02x?}: {}", got.show());
        assert_eq!(feed(&mut d, b"\r").remote, b"ab\n", "{key:02x?}");
    }
}

// ───────────────────────────────── the arrows

#[test]
fn left_and_right_echo_their_own_sequences_and_only_those() {
    // **The arrows echo exactly what they are.** `ESC [ D` moves a real
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
    // **Two refusals and a survivor.** Left at column zero and right at the
    // end of the line ring, and **the line underneath is untouched** — that
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
