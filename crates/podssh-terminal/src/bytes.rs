//! Rendering bytes legibly, for a failing assertion.
//!
//! ⛔ **This exists because `vec![27, 91, 75]` names nothing.** A test that
//! fails on a byte sequence has to print that sequence, and the difference
//! between `\x1b\OK` and `[27, 91, 75]` is the difference between a bug you can
//! see and one you have to re-derive.
//!
//! ⛔ **Lossy, on purpose, and named as lossy.** A lossless spelling would have
//! to decide how to write `\x07`, and every choice it made would be a
//! convention this repository then had to explain. `std`'s
//! `u8::escape_ascii` is already in the tree, so this is that, applied to a
//! slice and with the three whitespace bytes spelled the way a terminal test
//! reads best.

/// A byte string with every non-printing byte written as an escape.
///
/// `\n`, `\r` and `\t` are spelled as themselves because they appear constantly
/// in a line discipline's output and `\x0a` is harder to read than `\n`. Every
/// other byte below 0x20, and every byte above 0x7e, is `\xNN`.
pub fn show(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for b in bytes {
        match *b {
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(*b as char),
            other => {
                use std::fmt::Write;
                let _ = write!(out, "\\x{other:02x}");
            }
        }
    }
    out
}

/// `show`, wrapped in quotes.
///
/// ⛔ **The quotes are added by hand, not by `{:?}`.** ⛔ `show` has already
/// written every backslash as part of an escape, so running `{:?}` over its
/// output escapes those backslashes a *second* time and `\x1b` reads as
/// `\\x1b` ⛔ — a string that looks right and is wrong by one layer. ⛔ The test
/// for this helper asserts against `show`'s own escapes, which is what caught
/// it.
pub fn quoted(bytes: &[u8]) -> String {
    format!("\"{}\"", show(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shows_control_bytes_as_escapes() {
        // ⛔ **The EL from the transcription, spelled the way the tests read
        // it.** If this changed, every redraw assertion in the suite would
        // print a string nobody can check by eye.
        assert_eq!(quoted(b"\x1b[K"), r#""\x1b[K""#);
        assert_eq!(quoted(b"ab\x08 \x08"), r#""ab\x08 \x08""#);
    }

    #[test]
    fn leaves_printable_bytes_alone() {
        assert_eq!(quoted(b"abc -_."), r#""abc -_.""#);
    }

    #[test]
    fn high_bytes_do_not_become_replacement_characters() {
        // ⛔ A byte above 0x7e must stay an escape and not become U+FFFD, or
        // two different inputs print identically and the assertion compares
        // equal strings that meant different bytes.
        assert_eq!(quoted(&[0xc3, 0xa9]), r#""\xc3\xa9""#);
        assert_ne!(show(&[0xc3]), show(&[0xa9]));
    }

    #[test]
    fn whitespace_is_spelled_readably() {
        assert_eq!(quoted(b"\r\n\t"), r#""\r\n\t""#);
    }
}