//! The program's output while a line is under edit.
//!
//! **Output never lands in the line, and never changes it.** The cooked mode
//! runs with nothing below that echoes, so the program writes to a pipe while
//! the user edits: its bytes would land in the middle of the edited line, and
//! the next redraw would draw the line over them. So the line is hidden first
//! (up to its first row, `\r`, and a clear), the output is written, and the
//! prompt and the line are drawn again below it, with the cursor in its place.
//!
//! **Output that stops inside a row waits.** A program's own prompt, or a
//! progress bar drawn with `\r`, stays as it is; the line comes back on the
//! next row at the next key, or when the output ends its row.
//!
//! **Each `\n` becomes `\r\n`**, as a pty's `ONLCR` makes it: the program
//! writes to a pipe, and the client's terminal is raw, so a bare `\n` would
//! step down the screen like stairs. A `\r\n` becomes `\r\r\n`, which a
//! terminal shows the same, so no state is carried from one chunk to the
//! next. **READ**, `.tmp/podbox/crates/podbox-ssh/src/session.rs:624-641`.

use super::screen::{csi, motion, ED};
use super::{Discipline, Event, EL, PROMPT};

/// Each `\n` as `\r\n`, as `ONLCR` makes it.
pub(crate) fn onlcr(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 8);
    for b in bytes {
        if *b == b'\n' {
            out.push(b'\r');
        }
        out.push(*b);
    }
    out
}

impl Discipline {
    /// Output from the program, written around the line under edit: the
    /// line hidden, the output, and the line drawn again below it once the
    /// output ends its row.
    pub fn output(&mut self, bytes: &[u8]) -> Vec<Event> {
        if bytes.is_empty() {
            return vec![];
        }
        let mut out = if self.hidden { Vec::new() } else { self.hide() };
        out.extend(onlcr(bytes));
        self.hidden = bytes.last() != Some(&b'\n');
        if !self.hidden {
            out.extend(self.show());
        }
        vec![Event::ToLocal(out)]
    }

    /// The line under edit back on a row of its own, when output hid it and
    /// stopped inside a row. Nothing otherwise.
    pub(crate) fn unhide(&mut self) -> Vec<Event> {
        if !self.hidden {
            return vec![];
        }
        self.hidden = false;
        let mut out = b"\r\n".to_vec();
        out.extend(self.show());
        vec![Event::ToLocal(out)]
    }

    /// Up to the first row of the area, `\r`, and a clear of the rows it
    /// took.
    fn hide(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        csi(&mut out, self.shown.row, b'A');
        out.push(b'\r');
        out.extend_from_slice(if self.drawn_end.row == 0 { EL } else { ED });
        out
    }

    /// The prompt and the line from the start of a fresh row, and the cursor
    /// in its place.
    fn show(&mut self) -> Vec<u8> {
        let end = self.place(self.line.len());
        let cursor = self.place(self.cursor);
        let mut out = PROMPT.to_vec();
        out.extend_from_slice(&self.line);
        if end.col == 0 && end.row > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend(motion(end, cursor));
        self.drawn_end = end;
        self.shown = cursor;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::onlcr;

    #[test]
    fn each_newline_becomes_crlf_and_nothing_else_changes() {
        assert_eq!(onlcr(b"a\nb\r\nc"), b"a\r\nb\r\r\nc");
        assert_eq!(onlcr(b"no newline\r"), b"no newline\r");
        assert!(onlcr(b"").is_empty());
    }
}
