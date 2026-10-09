//! Characters and cells: where the cursor may stop, and how wide each step is
//! on the screen.
//!
//! **The line keeps the bytes as typed.** With UTF-8 (the client's `IUTF8`),
//! the cursor steps over whole characters, and a character takes the
//! zero-width marks after it along, as an accent moves with its letter; a
//! byte that is no part of a character is a step of its own. Without UTF-8,
//! each byte is a step, as a terminal with no `IUTF8` counts. The cells of a
//! step come from `unicode-width`: a wide character takes two, a mark none,
//! and a control byte or a broken one the one cell that its raw echo takes.

use unicode_width::UnicodeWidthChar;

/// One step of the cursor: where it starts in the line, its bytes, and its
/// cells on the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unit {
    pub start: usize,
    pub len: usize,
    pub cells: usize,
}

/// The length of the UTF-8 character that `lead` starts, or `None` for a
/// byte that starts none.
pub(crate) fn utf8_len(lead: u8) -> Option<usize> {
    match lead {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

/// The character at the start of `bytes`, and its length, if they hold a
/// whole one.
fn decode(bytes: &[u8]) -> Option<(char, usize)> {
    let n = utf8_len(*bytes.first()?)?;
    let c = std::str::from_utf8(bytes.get(..n)?).ok()?.chars().next()?;
    Some((c, n))
}

/// The steps of `line`, in order.
pub(crate) fn units(line: &[u8], utf8: bool) -> Vec<Unit> {
    let mut out: Vec<Unit> = Vec::new();
    let mut at = 0;
    while at < line.len() {
        let (len, cells) = match decode(&line[at..]) {
            Some((c, n)) if utf8 => (n, c.width().unwrap_or(1)),
            _ => (1, 1),
        };
        // A zero-width mark joins the step before it.
        match out.last_mut() {
            Some(prev) if utf8 && cells == 0 => prev.len += len,
            _ => out.push(Unit { start: at, len, cells }),
        }
        at += len;
    }
    out
}

/// The step that ends at `at`, if one does.
pub(crate) fn before(line: &[u8], utf8: bool, at: usize) -> Option<Unit> {
    units(&line[..at], utf8).last().copied()
}

/// The step that starts at `at`, if one does.
pub(crate) fn after(line: &[u8], utf8: bool, at: usize) -> Option<Unit> {
    units(line, utf8).into_iter().find(|u| u.start == at)
}

/// A motion of the screen cursor by `cells`, left (`D`) or right (`C`): the
/// count is written only when it is not 1, so a step of one cell stays
/// `ESC [ D`, the reference's bytes.
pub(crate) fn motion(cells: usize, direction: u8) -> Vec<u8> {
    match cells {
        1 => vec![0x1b, b'[', direction],
        n => format!("\x1b[{n}{}", direction as char).into_bytes(),
    }
}

/// Whether `unit` is one space: the boundary of a word for Ctrl-W.
pub(crate) fn blank(line: &[u8], unit: Unit) -> bool {
    unit.len == 1 && line[unit.start] == b' '
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wide_character_is_two_cells_and_an_accent_moves_with_its_letter() {
        let line = "a\u{6f22}e\u{301}".as_bytes();
        let got: Vec<(usize, usize)> = units(line, true).iter().map(|u| (u.len, u.cells)).collect();
        assert_eq!(got, vec![(1, 1), (3, 2), (3, 1)]);
    }

    #[test]
    fn without_utf8_each_byte_is_a_step_and_a_broken_byte_is_one_cell() {
        assert_eq!(units("\u{e9}".as_bytes(), false).len(), 2);
        let broken = units(b"\xff\xc3", true);
        assert_eq!(broken.iter().map(|u| (u.len, u.cells)).collect::<Vec<_>>(), vec![(1, 1), (1, 1)]);
    }

    #[test]
    fn a_motion_of_one_cell_has_no_count() {
        assert_eq!(motion(1, b'D'), b"\x1b[D");
        assert_eq!(motion(2, b'C'), b"\x1b[2C");
    }
}
