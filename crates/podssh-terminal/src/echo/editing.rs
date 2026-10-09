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
//! - [`Discipline::erase_left`] — DEL and BS. **`session.rs:323-338`**
//! - [`Discipline::erase_line`] — Ctrl-U. **`session.rs:340-352`**
//! - [`Discipline::erase_word`] — Ctrl-W: blanks first, then the word.
//!   **`session.rs:354-376`**
//! - [`Discipline::escape`] — the final byte of a sequence. **`session.rs:378-403`**
//! - [`Discipline::insert`] — an ordinary byte, or a refusal at the cap.
//!   **`session.rs:437-453`**
//!
//! **`pub(crate)`, not `pub`.** These are called from [`super::Discipline::key`]
//! in another module, and `pub(crate)` is the whole of what that needs: they
//! stay invisible outside the crate, so a caller cannot drive a half-finished
//! edit that the byte rules never sanctioned.

use super::Discipline;
use crate::echo::{Event, Sig, BELL, EL, LINE_CAP, PROMPT};

impl Discipline {
    /// A signal character: drop the line being edited, echo the caret notation a
    /// terminal shows, print a fresh prompt, and report the signal. The
    /// interrupted line never ran, so history never saw it.
    /// **READ**, `session.rs:297-308`.
    pub(crate) fn signal_key(&mut self, sig: Sig, caret: &[u8]) -> Vec<Event> {
        self.line.clear();
        self.cursor = 0;
        self.saved = None;
        self.hpos = None;
        let mut echo = caret.to_vec();
        echo.extend_from_slice(PROMPT);
        vec![Event::ToLocal(echo), Event::Signal(sig)]
    }

    /// Ctrl-D: end of input on an empty line, delete under the cursor on a live
    /// one, and nothing at all at the very end. **READ**, `session.rs:310-321`.
    pub(crate) fn eof_or_delete(&mut self) -> Vec<Event> {
        if self.line.is_empty() {
            return vec![Event::Eof];
        }
        if self.cursor < self.line.len() {
            self.line.remove(self.cursor);
            return vec![Event::ToLocal(self.redraw())];
        }
        vec![]
    }

    /// Erase one cell left of the cursor. At the very start there is nothing to
    /// erase, and the bell says so. **READ**, `session.rs:323-338`.
    pub(crate) fn erase_left(&mut self) -> Vec<Event> {
        if self.cursor == 0 {
            return vec![Event::ToLocal(BELL.to_vec())];
        }
        self.cursor -= 1;
        self.line.remove(self.cursor);
        // At the end the triple suffices; mid-line the tail shifted and only a
        // redraw puts every cell right.
        if self.cursor == self.line.len() {
            vec![Event::ToLocal(Self::rubout(1))]
        } else {
            vec![Event::ToLocal(self.redraw())]
        }
    }

    /// Erase the whole line, wherever the cursor sits: `\r`, prompt, and clear,
    /// which is one fixed shape for every length. **READ**, `session.rs:340-352`.
    pub(crate) fn erase_line(&mut self) -> Vec<Event> {
        if self.line.is_empty() {
            return vec![Event::ToLocal(BELL.to_vec())];
        }
        self.line.clear();
        self.cursor = 0;
        let mut out = b"\r".to_vec();
        out.extend_from_slice(PROMPT);
        out.extend_from_slice(EL);
        vec![Event::ToLocal(out)]
    }

    /// Erase back over one word: trailing blanks, then non-blanks. The boundary
    /// rule is spaces, matching what a shell word means here.
    /// **READ**, `session.rs:354-376`.
    pub(crate) fn erase_word(&mut self) -> Vec<Event> {
        if self.cursor == 0 {
            return vec![Event::ToLocal(BELL.to_vec())];
        }
        let mut n = 0;
        while self.cursor > 0 && self.line[self.cursor - 1] == b' ' {
            self.cursor -= 1;
            self.line.remove(self.cursor);
            n += 1;
        }
        while self.cursor > 0 && self.line[self.cursor - 1] != b' ' {
            self.cursor -= 1;
            self.line.remove(self.cursor);
            n += 1;
        }
        if self.cursor == self.line.len() {
            vec![Event::ToLocal(Self::rubout(n))]
        } else {
            vec![Event::ToLocal(self.redraw())]
        }
    }

    /// The final byte of an `ESC [` sequence.
    ///
    /// **Arrows echo their own sequences**, which move a real terminal's
    /// cursor exactly where the local cursor went. Home and End stay silent
    /// until the next redraw. **Everything else bells and drops**, and that is
    /// not an omission — see `session.rs:54-55`, *"any escape sequence outside
    /// arrows, Home, and End is dropped"*. A discipline that passes an
    /// untested sequence to a client that is *not* full-screen corrupts the
    /// scrollback. **READ**, `session.rs:378-403`.
    ///
    /// **`bare` is load-bearing.** **`ESC [ 1 C` is a real sequence** —
    /// "cursor forward one" — and **it is refused rather than treated as a
    /// plain `C`.** Handling it as `C` would move the cursor as though the `1`
    /// had never been sent, and a discipline that interprets sequences it has
    /// not tested is a discipline that will corrupt somebody's terminal. This
    /// is the entry's rule applied to a sequence the reference never met: *"a
    /// discipline that silently drops a sequence its client was promised is worse
    /// than one that rings a bell"*.
    pub(crate) fn escape(&mut self, b: u8, bare: bool) -> Vec<Event> {
        if !bare {
            return vec![Event::ToLocal(BELL.to_vec())];
        }
        match b {
            b'A' => self.history_up(),
            b'B' => self.history_down(),
            b'C' if self.cursor < self.line.len() => {
                self.cursor += 1;
                vec![Event::ToLocal(b"\x1b[C".to_vec())]
            }
            b'D' if self.cursor > 0 => {
                self.cursor -= 1;
                vec![Event::ToLocal(b"\x1b[D".to_vec())]
            }
            b'H' => {
                self.cursor = 0;
                vec![]
            }
            b'F' => {
                self.cursor = self.line.len();
                vec![]
            }
            _ => vec![Event::ToLocal(BELL.to_vec())],
        }
    }

    /// An ordinary byte: append at the end with a one-byte echo, or insert
    /// mid-line with a redraw. Past the cap the byte drops with a bell, and the
    /// bell is the whole answer. **READ**, `session.rs:437-453`.
    pub(crate) fn insert(&mut self, b: u8) -> Vec<Event> {
        if self.line.len() >= LINE_CAP {
            return vec![Event::ToLocal(BELL.to_vec())];
        }
        if self.cursor == self.line.len() {
            self.line.push(b);
            self.cursor += 1;
            vec![Event::ToLocal(vec![b])]
        } else {
            self.line.insert(self.cursor, b);
            self.cursor += 1;
            vec![Event::ToLocal(self.redraw())]
        }
    }
}
