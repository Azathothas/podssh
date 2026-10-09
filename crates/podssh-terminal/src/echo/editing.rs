//! Erasing, moving, and inserting: the edits a key makes to a line.
//!
//! **Transcribed from `.tmp/podbox/crates/podbox-ssh/src/session.rs`,** and
//! each method names the line it came from. This is a split of [`super`], not
//! a second implementation: **the reference is 1132 lines in one file and
//! this repository's gate forbids a source file over 500 lines**, so the
//! transcription is cut by responsibility and **not one byte rule was
//! re-derived or dropped to make it fit.** The suite is the same 96 tests
//! before and after the split.
//!
//! ## What is here
//!
//! - [`Discipline::signal_key`] — Ctrl-C and Ctrl-\: drop the line, echo the
//!   caret notation, report the signal. The interrupted line never ran, so
//!   history never saw it. **`session.rs:297-308`**
//! - [`Discipline::eof_or_delete`] — Ctrl-D at three positions, three answers.
//!   **`session.rs:310-321`**
//! - [`Discipline::erase_left`] — DEL and BS, one character. **`session.rs:323-338`**
//! - [`Discipline::erase_line`] — Ctrl-U. **`session.rs:340-352`**
//! - [`Discipline::erase_word`] — Ctrl-W: blanks first, then the word.
//!   **`session.rs:354-376`**
//! - [`Discipline::escape`] — the final byte of a sequence, `ESC [` or `ESC O`.
//!   **`session.rs:378-403`**
//! - [`Discipline::home`] and [`Discipline::end`] — the line's cursor and the
//!   screen's together; [`Discipline::delete_under`] — Delete.
//! - [`Discipline::insert`] — an ordinary byte, or a refusal at the cap.
//!   **`session.rs:437-453`**
//!
//! **`pub(crate)`, not `pub`.** These are called from [`super::Discipline::key`]
//! in another module, and `pub(crate)` is the whole of what that needs: they
//! stay invisible outside the crate, so a caller cannot drive a half-finished
//! edit that the byte rules never sanctioned.

use super::screen::{csi, motion, ED};
use super::units::{after, before, blank, units, utf8_len, Unit};
use super::Discipline;
use crate::echo::{Event, Sig, BELL, EL, LINE_CAP, PROMPT};
use crate::escape::{Intro, Param};

impl Discipline {
    /// A signal character: drop the line being edited, echo the caret notation a
    /// terminal shows, print a fresh prompt, and report the signal. The
    /// interrupted line never ran, so history never saw it.
    /// **READ**, `session.rs:297-308`.
    pub(crate) fn signal_key(&mut self, sig: Sig, caret: &[u8]) -> Vec<Event> {
        // Over several rows the caret goes after the line, not over it.
        let mut echo = if self.drawn_end.row > 0 { motion(self.shown, self.drawn_end) } else { Vec::new() };
        self.line.clear();
        self.cursor = 0;
        self.saved = None;
        self.hpos = None;
        echo.extend_from_slice(caret);
        echo.extend_from_slice(PROMPT);
        self.reset_area();
        vec![Event::ToLocal(echo), Event::Signal(sig)]
    }

    /// Ctrl-D: end of input on an empty line, delete the character under the
    /// cursor on a live one, and nothing at all at the very end.
    /// **READ**, `session.rs:310-321`.
    pub(crate) fn eof_or_delete(&mut self) -> Vec<Event> {
        if self.line.is_empty() {
            return vec![Event::Eof];
        }
        self.delete_under()
    }

    /// Delete, the VT220's Remove: the character under the cursor goes, and
    /// nothing at the very end. It never ends input, as Ctrl-D on an empty
    /// line does.
    pub(crate) fn delete_under(&mut self) -> Vec<Event> {
        let Some(u) = after(&self.line, self.utf8, self.cursor) else { return vec![] };
        self.line.drain(u.start..u.start + u.len);
        vec![Event::ToLocal(self.redraw())]
    }

    /// Home: the line's cursor to the start, and the screen's with it, so
    /// the next key lands where the user sees the cursor.
    pub(crate) fn home(&mut self) -> Vec<Event> {
        self.cursor = 0;
        self.move_shown()
    }

    /// End: the line's cursor to the end, and the screen's with it.
    pub(crate) fn end(&mut self) -> Vec<Event> {
        self.cursor = self.line.len();
        self.move_shown()
    }

    /// The screen's cursor to the line's, by rows and columns.
    fn move_shown(&mut self) -> Vec<Event> {
        let to = self.place(self.cursor);
        let out = motion(self.shown, to);
        self.shown = to;
        if out.is_empty() {
            vec![]
        } else {
            vec![Event::ToLocal(out)]
        }
    }

    /// Erase the character left of the cursor, and the cells it took. At the
    /// very start there is nothing to erase, and the bell says so.
    /// **READ**, `session.rs:323-338`.
    pub(crate) fn erase_left(&mut self) -> Vec<Event> {
        let Some(u) = before(&self.line, self.utf8, self.cursor) else {
            return vec![Event::ToLocal(BELL.to_vec())];
        };
        self.cursor = u.start;
        self.line.drain(u.start..u.start + u.len);
        // At the end the triple suffices where `\b` reaches the cells;
        // mid-line the tail shifted and only a redraw puts every cell right.
        if self.cursor == self.line.len() {
            if let Some(out) = self.rubout_at_end(u.cells) {
                return vec![Event::ToLocal(out)];
            }
        }
        vec![Event::ToLocal(self.redraw())]
    }

    /// Erase the whole line, wherever the cursor sits: `\r`, prompt, and clear,
    /// which is one fixed shape for every length on one row. **READ**,
    /// `session.rs:340-352`. Over several rows, up to the first row first, and
    /// `ESC [ J` clears the rows below too.
    pub(crate) fn erase_line(&mut self) -> Vec<Event> {
        if self.line.is_empty() {
            return vec![Event::ToLocal(BELL.to_vec())];
        }
        let rows = self.drawn_end.row > 0;
        let mut out = Vec::new();
        csi(&mut out, self.shown.row, b'A');
        self.line.clear();
        self.cursor = 0;
        out.extend_from_slice(b"\r");
        out.extend_from_slice(PROMPT);
        out.extend_from_slice(if rows { ED } else { EL });
        self.reset_area();
        vec![Event::ToLocal(out)]
    }

    /// Erase back over one word: trailing blanks, then non-blanks. The boundary
    /// rule is spaces, matching what a shell word means here.
    /// **READ**, `session.rs:354-376`.
    pub(crate) fn erase_word(&mut self) -> Vec<Event> {
        if self.cursor == 0 {
            return vec![Event::ToLocal(BELL.to_vec())];
        }
        let steps = units(&self.line[..self.cursor], self.utf8);
        let mut i = steps.len();
        let mut cells = 0;
        while i > 0 && blank(&self.line, steps[i - 1]) {
            i -= 1;
            cells += steps[i].cells;
        }
        while i > 0 && !blank(&self.line, steps[i - 1]) {
            i -= 1;
            cells += steps[i].cells;
        }
        let from = steps[i].start;
        self.line.drain(from..self.cursor);
        self.cursor = from;
        if self.cursor == self.line.len() {
            if let Some(out) = self.rubout_at_end(cells) {
                return vec![Event::ToLocal(out)];
            }
        }
        vec![Event::ToLocal(self.redraw())]
    }

    /// The final byte of an `ESC [` or an `ESC O` sequence. The two share the
    /// arrows, Home and End, because a terminal in application mode sends the
    /// second form; only `ESC O` has the keypad.
    ///
    /// **Arrows echo their own sequences**, which move a real terminal's
    /// cursor exactly where the local cursor went, and Home and End move it
    /// too. The VT220 editing keys come as `ESC [ n ~`: 1 and 7 are Home, 4
    /// and 8 End, and 3 Delete. **Everything else bells and drops**, and that is
    /// not an omission — see `session.rs:54-55`, *"any escape sequence outside
    /// arrows, Home, and End is dropped"*. A discipline that passes an
    /// untested sequence to a client that is *not* full-screen corrupts the
    /// scrollback. **READ**, `session.rs:378-403`.
    ///
    /// **The parameter is load-bearing.** **`ESC [ 1 C` is a real sequence** —
    /// "cursor forward one" — and **it is refused rather than treated as a
    /// plain `C`.** Handling it as `C` would move the cursor as though the `1`
    /// had never been sent, and a discipline that interprets sequences it has
    /// not tested is a discipline that will corrupt somebody's terminal. This
    /// is the entry's rule applied to a sequence the reference never met: *"a
    /// discipline that silently drops a sequence its client was promised is worse
    /// than one that rings a bell"*.
    pub(crate) fn escape(&mut self, intro: Intro, b: u8, param: Param) -> Vec<Event> {
        match (intro, b, param) {
            (Intro::Csi, b'~', Param::Number(1 | 7)) => return self.home(),
            (Intro::Csi, b'~', Param::Number(4 | 8)) => return self.end(),
            (Intro::Csi, b'~', Param::Number(3)) => return self.delete_under(),
            (_, _, Param::None) => {}
            _ => return vec![Event::ToLocal(BELL.to_vec())],
        }
        match b {
            b'A' => self.history_up(),
            b'B' => self.history_down(),
            // A step is a whole character, and the screen moves by its cells.
            b'C' if self.cursor < self.line.len() => self.step(after(&self.line, self.utf8, self.cursor), b'C'),
            b'D' if self.cursor > 0 => self.step(before(&self.line, self.utf8, self.cursor), b'D'),
            b'H' => self.home(),
            b'F' => self.end(),
            // The keypad in application mode: Enter submits, and each other
            // key types the character it shows, `ESC O j` to `ESC O y` being
            // `*+,-./` and the digits. F1 to F4, `ESC O P` to `ESC O S`, ring.
            b'M' if intro == Intro::Ss3 => self.submit(),
            b'X' if intro == Intro::Ss3 => self.insert(b'='),
            b'j'..=b'y' if intro == Intro::Ss3 => self.insert(b - 0x40),
            _ => vec![Event::ToLocal(BELL.to_vec())],
        }
    }

    /// The cursor over one step, left or right, and the motion that takes the
    /// screen's cursor to its place: none for a step of no cells, and up or
    /// down a row where the step crosses one.
    fn step(&mut self, unit: Option<Unit>, direction: u8) -> Vec<Event> {
        let Some(u) = unit else { return vec![Event::ToLocal(BELL.to_vec())] };
        self.cursor = if direction == b'C' { u.start + u.len } else { u.start };
        let to = self.place(self.cursor);
        let out = motion(self.shown, to);
        self.shown = to;
        if out.is_empty() {
            vec![]
        } else {
            vec![Event::ToLocal(out)]
        }
    }

    /// An ordinary byte. With UTF-8, the byte of a character typed in parts
    /// waits until the character is whole; a byte that starts none, or a
    /// character that is not valid, goes in as bytes. **READ**,
    /// `session.rs:437-453`.
    pub(crate) fn insert(&mut self, b: u8) -> Vec<Event> {
        if !self.utf8 {
            return self.insert_unit(&[b]);
        }
        self.partial.push(b);
        let whole = match utf8_len(self.partial[0]) {
            Some(n) if self.partial.len() < n => return vec![],
            Some(n) if self.partial.len() == n => std::str::from_utf8(&self.partial).is_ok(),
            _ => false,
        };
        let parts = std::mem::take(&mut self.partial);
        if whole {
            return self.insert_unit(&parts);
        }
        parts.into_iter().flat_map(|p| self.insert_unit(&[p])).collect()
    }

    /// One whole step into the line: appended with its echo, or inserted
    /// mid-line with a redraw. A step that would pass the cap drops whole,
    /// with a bell, so the cap never splits a character.
    pub(crate) fn insert_unit(&mut self, unit: &[u8]) -> Vec<Event> {
        if self.line.len() + unit.len() > LINE_CAP {
            return vec![Event::ToLocal(BELL.to_vec())];
        }
        if self.cursor == self.line.len() {
            self.line.extend_from_slice(unit);
            self.cursor += unit.len();
            vec![Event::ToLocal(self.append_echo(unit))]
        } else {
            self.line.splice(self.cursor..self.cursor, unit.iter().copied());
            self.cursor += unit.len();
            vec![Event::ToLocal(self.redraw())]
        }
    }
}
