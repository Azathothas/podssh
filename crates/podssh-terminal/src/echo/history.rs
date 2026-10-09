//! Recall: history, the cap, and the line set aside while browsing it.
//!
//! **Transcribed from `.tmp/podbox/crates/podbox-ssh/src/session.rs`,** each
//! method naming the line it came from. A split of [`super`], for the reason
//! given there: the 500-line gate is why these are separate files, **and no
//! history rule was re-derived or dropped to make the split fit.**
//!
//! ## What is here
//!
//! - [`Discipline::history_up`] — walk older, parking the uncommitted line on
//!   the first press. **`session.rs:405-420`**
//! - [`Discipline::history_down`] — walk newer, and past the newest restore the
//!   parked line. **`session.rs:422-435`**
//!
//! **The parked line is load-bearing.** Without it, `Up` would silently
//! destroy what the user was typing: press Up on a half-typed command and the
//! half-typed command is gone, with no bell and no way back.

use super::Discipline;
use crate::echo::{Event, BELL};

impl Discipline {
    /// History up: set the uncommitted line aside on first browse, then walk
    /// older. Both ends answer with a bell. **READ**, `session.rs:405-420`.
    pub(crate) fn history_up(&mut self) -> Vec<Event> {
        if self.history.is_empty() {
            return vec![Event::ToLocal(BELL.to_vec())];
        }
        match self.hpos {
            None => {
                self.saved = Some(std::mem::take(&mut self.line));
                self.cursor = 0;
                self.recall(self.history.len() - 1)
            }
            Some(0) => vec![Event::ToLocal(BELL.to_vec())],
            Some(i) => self.recall(i - 1),
        }
    }

    /// History down: walk newer, and past the newest restore the line the
    /// browse set aside. **READ**, `session.rs:422-435`.
    pub(crate) fn history_down(&mut self) -> Vec<Event> {
        match self.hpos {
            None => vec![Event::ToLocal(BELL.to_vec())],
            Some(i) if i + 1 < self.history.len() => self.recall(i + 1),
            Some(_) => {
                self.line = self.saved.take().unwrap_or_default();
                self.cursor = self.line.len();
                self.hpos = None;
                vec![Event::ToLocal(self.redraw())]
            }
        }
    }
}
