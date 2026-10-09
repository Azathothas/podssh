//! **The program's output while a line is under edit.**
//!
//! In the cooked mode the program writes to a pipe while the user edits.
//! Its output must never land in the line or change it: the line is hidden,
//! the output written with each `\n` as `\r\n`, and the line drawn again
//! below it. Output that stops inside a row waits for the next key.

use podssh_terminal::session::Session;
use podssh_terminal::window::Size;

mod common;
use common::{legs, selected};

#[test]
fn l5_output_during_an_edit_redraws_the_line() {
    // After `ab`, output ends its row: the line is cleared, the output
    // written with `\r\n`, and the prompt and `ab` drawn below it.
    let mut s = Session::new(selected());
    legs(s.on_local_bytes(b"ab"));
    let got = legs(s.on_remote_bytes(b"one\ntwo\n"));
    assert_eq!(got.local, b"\r\x1b[Kone\r\ntwo\r\n$ ab", "{}", got.show());
    assert_eq!(legs(s.on_local_bytes(b"\r")).remote, b"ab\n", "the line was not changed");
}

#[test]
fn l5_output_puts_the_cursor_back_mid_line() {
    // The cursor two cells left of the end comes back two cells left.
    let mut s = Session::new(selected());
    legs(s.on_local_bytes(b"abc\x1b[D\x1b[D"));
    let got = legs(s.on_remote_bytes(b"x\n"));
    assert_eq!(got.local, b"\r\x1b[Kx\r\n$ abc\x1b[2D", "{}", got.show());
    assert_eq!(legs(s.on_local_bytes(b"Y\r")).remote, b"aYbc\n");
}

#[test]
fn l5_output_that_stops_inside_a_row_waits_for_the_next_key() {
    // A program's own prompt has no newline: it stays as it is, and the
    // line comes back on the next row at the next key.
    let mut s = Session::new(selected());
    legs(s.on_local_bytes(b"ab"));
    assert_eq!(legs(s.on_remote_bytes(b"Name: ")).local, b"\r\x1b[KName: ");
    assert_eq!(legs(s.on_remote_bytes(b"\r50%")).local, b"\r50%", "a progress bar draws in place");
    assert_eq!(legs(s.on_local_bytes(b"c")).local, b"\r\n$ abc");
    assert_eq!(legs(s.on_local_bytes(b"\r")).remote, b"abc\n");
}

#[test]
fn l5_output_during_an_edit_of_a_long_line_clears_each_row() {
    // 20 columns and 30 `a`: the line takes two rows, so the clear starts a
    // row up and clears below, not only to the end of a row.
    let mut s = Session::new(selected()).sized(Size::new(24, 20));
    legs(s.on_local_bytes(&[b'a'; 30]));
    let got = legs(s.on_remote_bytes(b"x\n"));
    let want = [&b"\x1b[A\r\x1b[Jx\r\n$ "[..], &[b'a'; 30]].concat();
    assert_eq!(got.local, want, "{}", got.show());
}

#[test]
fn l5_after_the_end_of_input_only_the_newlines_change() {
    // Ctrl-D on an empty line ends input; what the program writes after it
    // goes as it came, with `\r\n`, and no prompt is drawn.
    let mut s = Session::new(selected());
    assert!(legs(s.on_local_bytes(b"\x04")).eof);
    assert_eq!(legs(s.on_remote_bytes(b"bye\n")).local, b"bye\r\n");
    assert!(s.on_remote_bytes(b"").is_empty());
}
