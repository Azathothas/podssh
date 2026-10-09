//! The refusal catalogue: what this terminal will not do, and why.
//!
//! **A refusal answers with a bell and changes nothing.** Silence would read
//! as acceptance, and a user who cannot tell "not supported" from "did nothing"
//! files the bug in the wrong place. This is the sibling's rule verbatim —
//! **READ**, `.tmp/podbox/crates/podbox-ssh/src/session.rs:37-40`: *"Refusals
//! answer with a bell and change nothing, never with silence that could read as
//! acceptance."*
//!
//! ## Why the catalogue is data and not only behaviour
//!
//! **A refusal that changes nothing and says nothing is indistinguishable
//! from one that was never implemented.** So every refusal is a named value
//! here, [`REFUSALS`] lists them, and a caller can print what the terminal will
//! not do before a key is pressed — which is what "the user can hear the
//! refusal and can act on it" requires.
//!
//! ## One list, two modes
//!
//! **The byte-level refusals live in [`refuses`], and both disciplines use
//! that one function.** Ctrl-Z, Ctrl-Q and Ctrl-S are refused in the cooked
//! mode **and** in pass-through — **READ**, `session.rs:271`, which refuses
//! `0x1a | 0x11 | 0x13` in a single match arm. A list written twice is a list
//! that drifts, and a refusal that answers differently per mode is a refusal a
//! user cannot learn.

use crate::echo::BELL;

/// **The byte-level refusals, in one place.** Transcribed from
/// `session.rs:271`. **A function and not a `const` array** so that a module
/// which needs the test — both disciplines do — cannot hold a copy that has
/// drifted from this one.
pub fn refuses(b: u8) -> bool {
    matches!(b, 0x1a | 0x11 | 0x13)
}

/// The byte a refusal answers with. **A helper so no caller can build its own
/// bell**, which is how two modules end up disagreeing about what a refusal
/// looks like on the wire.
pub fn refusal_bytes() -> Vec<u8> {
    BELL.to_vec()
}

/// One refused terminal operation, named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Ctrl-Z: suspend. No job control without a terminal, and a stopped
    /// shell with no foreground to return to is a wedged session.
    /// **READ**, `session.rs:44-45`.
    Suspend,
    /// Ctrl-Q / Ctrl-S: flow control. No `IXON` below, so there is nothing
    /// to stop. **READ**, `session.rs:46`.
    FlowControl,
    /// An escape sequence outside `ESC [ A B C D H F`, in the cooked mode.
    /// Dropped rather than interpreted: a discipline that passes an untested
    /// sequence to a client that is *not* full-screen corrupts the scrollback.
    /// **READ**, `session.rs:54-55`.
    CursorAddressing,
    /// An erase at the very start of the line, or `Ctrl-U`/`Ctrl-W` on an empty
    /// one. There is nothing to erase, and the bell says so rather than
    /// leaving the user pressing a key that does nothing.
    /// **READ**, `session.rs:325-327`, `342-344`, `357-359`.
    NothingToErase,
    /// History walked past either end. **READ**, `session.rs:416-417`, `425-426`.
    NoMoreHistory,
    /// A cursor move at either bound. **READ**, `session.rs:385`, `389`.
    AtLineBound,
    /// A byte past [`crate::echo::LINE_CAP`].
    /// **READ**, `session.rs:441-443`.
    LineTooLong,
    /// `Ctrl-D` past the last cell of a line: not end of input, and not a
    /// deletion either. This one is **silent**, and deliberately so —
    /// **READ**, `session.rs:1035-1044`: *"Past the last cell there is nothing to
    /// delete: no bell, no redraw, no shell bytes."* It is listed here anyway,
    /// because **a documented silence is a decision and an undocumented one is
    /// a bug** — and because a reader who needs the whole set has one place to
    /// read it.
    NothingToDelete,
}

impl Refusal {
    /// Which byte triggers this refusal, where **one** byte triggers it.
    ///
    /// **`None` for everything else, on purpose.** `FlowControl` is two
    /// bytes, `CursorAddressing` is a class of sequence, and the position
    /// refusals are not bytes at all — they are where the cursor was. Naming
    /// a single byte for them would be a lie a reader could act on.
    pub fn trigger(self) -> Option<u8> {
        match self {
            Refusal::Suspend => Some(0x1a),
            _ => None,
        }
    }

    /// Why, in words a user could be told.
    ///
    /// **Short enough to print and specific enough to act on**, which is the
    /// bar the entry sets: *"the user can hear the refusal and can act on it"*.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::Suspend => "suspend is refused: no job control without a terminal",
            Refusal::FlowControl => "flow control is refused: there is no IXON to stop",
            Refusal::CursorAddressing => "this escape sequence is refused: it is not a key podssh interprets",
            Refusal::NothingToErase => "there is nothing to erase here",
            Refusal::NoMoreHistory => "history does not go further in that direction",
            Refusal::AtLineBound => "the cursor is already at that end of the line",
            Refusal::LineTooLong => "the line is at its byte cap; the byte was dropped",
            Refusal::NothingToDelete => "there is nothing to delete here",
        }
    }

    /// **Whether this refusal rings the bell.** **Exactly one does not**,
    /// and it is the one the sibling is silent about on purpose
    /// (`session.rs:1035-1044`). A method rather than an assumption inside the
    /// bell code, because **an implementation that rang a bell for
    /// `Ctrl-D`-at-end would be a behaviour change to a transcribed rule**, and
    /// it would be invisible in a diff of the byte rules.
    pub fn rings(self) -> bool {
        !matches!(self, Refusal::NothingToDelete)
    }
}

/// The catalogue, as a list. **Exported so a caller can print what this
/// terminal will not do.**
pub const REFUSALS: [Refusal; 8] = [
    Refusal::Suspend,
    Refusal::FlowControl,
    Refusal::CursorAddressing,
    Refusal::NothingToErase,
    Refusal::NoMoreHistory,
    Refusal::AtLineBound,
    Refusal::LineTooLong,
    Refusal::NothingToDelete,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_refusal_names_a_reason_worth_reading() {
        // **A refusal with no reason is a bug report waiting to be filed.**
        assert_eq!(REFUSALS.len(), 8);
        for refusal in REFUSALS {
            assert!(!refusal.reason().is_empty(), "{refusal:?} has no reason");
            assert!(refusal.reason().len() > 10, "{refusal:?} has a useless reason");
        }
    }

    #[test]
    fn only_suspend_names_a_single_trigger_byte() {
        // **The check that keeps the honesty of `trigger`.** Ctrl-Z is one
        // byte. Flow control is two, cursor addressing is a class of
        // sequences, and the rest are positions. A single byte for any of them
        // would be a lie a reader could act on.
        assert_eq!(Refusal::Suspend.trigger(), Some(0x1a));
        assert!(refuses(Refusal::Suspend.trigger().expect("just asserted")));
        for refusal in REFUSALS.iter().filter(|r| **r != Refusal::Suspend) {
            assert_eq!(refusal.trigger(), None, "{refusal:?} is not one byte");
        }
    }

    #[test]
    fn exactly_one_refusal_is_silent_and_that_one_is_documented() {
        // **The transcription's own asymmetry, pinned.** The sibling
        // answers a `Ctrl-D` past the last cell with nothing at all
        // (`session.rs:1035-1044`), and every other refusal rings. If a
        // refactor made `NothingToDelete` ring, a user pressing Ctrl-D at the
        // end of a line would start hearing a bell that the tested reference
        // never rang — a behaviour change hidden inside a tidy-up.
        let silent: Vec<&str> = REFUSALS.iter().filter(|r| !r.rings()).map(|r| r.reason()).collect();
        assert_eq!(silent, ["there is nothing to delete here"]);
        assert!(!Refusal::NothingToDelete.rings());
        for refusal in REFUSALS.iter().filter(|r| **r != Refusal::NothingToDelete) {
            assert!(refusal.rings(), "{refusal:?} must ring");
        }
    }

    #[test]
    fn the_byte_list_is_exactly_three_and_the_others_are_not_refused() {
        // **The control for the byte guard.** A guard that refuses everything
        // looks exactly like a good guard, so every byte that must pass is
        // asserted against the same function both modes use.
        for b in [0x1au8, 0x11, 0x13] {
            assert!(refuses(b), "byte {b:#x} must be refused");
        }
        for b in [b'a', b'\r', b'\n', 0x7f, 0x1b, 0x03, 0x1c, 0x04, 0x15, 0x17] {
            assert!(!refuses(b), "byte {b:#x} must not be refused");
        }
    }

    #[test]
    fn the_bell_is_the_bell_the_transcription_names() {
        // **One bell, one place.** A caller that built its own would be how
        // two modules end up disagreeing about what a refusal looks like on the
        // wire.
        assert_eq!(refusal_bytes(), b"\x07".to_vec());
        assert_eq!(refusal_bytes(), BELL.to_vec());
    }
}
