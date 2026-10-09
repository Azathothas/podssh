//! The read-only accessors: what a caller may see, and what it may not change.
//!
//! **Read-only on purpose, and that is the whole reason this is a separate
//! file.** Every accessor below returns a borrow and no accessor can change
//! anything, so **the cursor cannot be desynchronised from the buffer by a
//! caller** and there is no second write path beside the byte rules.
//!
//! **`swallow_next_lf` is the odd one out and it earns its place.** It
//! reports whether the next `\n` is the second half of a `\r\n` the discipline
//! itself just emitted, **because the far side is a real pty and its
//! `ONLCR` will answer the submit's `\r\n` with a `\r\n` of its own.** The
//! cooked discipline swallows the half that arrives from the user; this is how
//! a caller knows the half that arrives from the program is the same fact.

use super::Discipline;
use crate::echo::Event;

impl Discipline {
    pub fn line(&self) -> &[u8] {
        &self.line
    }

    /// Where the cursor sits, as a byte offset. **A byte offset, not a
    /// character count**: the cursor counts bytes, like a terminal without
    /// IUTF8, so erasing half of a multibyte character sends the other half to
    /// the shell. **READ**, `session.rs:31-32`.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The history as it stands, oldest first. Read-only, for the same reason
    /// as `line`.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Submit whatever is on the line and end input, as client EOF does.
    ///
    /// **Transcribed from the EOF arm of the supervisor**, `session.rs:530-536`:
    /// a partial line is submitted first, and then input ends the same way
    /// Ctrl-D on an empty line does. **The line is submitted even when it is
    /// empty**, because the sibling's own tests pin that: an empty submit is
    /// `b"\n"` on the forward leg (`session.rs:836-838`).
    pub fn submit_and_end(&mut self) -> Vec<Event> {
        let mut events = self.submit();
        events.push(Event::Eof);
        events
    }

    /// Whether a submit is the one half of a `\r\n` pair that is still open.
    ///
    /// **Needed by the driver, and needed only there.** A submit is echoed
    /// with `\r\n` and the terminal answers with `\r\n` of its own; whichever
    /// half arrives first opens this flag and the other is swallowed. Without
    /// it the far half is read as a second empty submission.
    pub fn swallow_next_lf(&self) -> bool {
        self.last_was_cr
    }
}
