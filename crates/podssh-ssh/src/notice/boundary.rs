//! Where the session's output leaves the terminal's parser (T-302): at its
//! ground state, or inside an escape sequence or a UTF-8 character. A
//! notice writes its own sequences only at the ground state: an `ESC` inside
//! a sequence of the far end would end that sequence, and the rest of it,
//! which comes later, would show as text.
//!
//! The states are the few of a VT parser that matter here (ECMA-48, and the
//! parser of the vt100 crate that the tests' oracle runs): an escape, its
//! intermediates, a control sequence, and a control string (OSC, DCS, SOS,
//! PM, APC). CAN and SUB end each sequence; `ESC` starts a new one wherever
//! it comes. A control string ends at ST (`ESC \`), and an OSC at BEL too.

/// The state of the terminal's parser after the bytes so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum State {
    #[default]
    Ground,
    /// This many continuation bytes of a UTF-8 character are still to come.
    Utf8(u8),
    Escape,
    /// `ESC` and bytes of 0x20 to 0x2F, before the final byte.
    Intermediate,
    Csi,
    /// A control string; `bel` when BEL ends it too (an OSC).
    String {
        bel: bool,
    },
    /// `ESC` inside a control string: ST when `\` follows.
    StringEscape,
}

/// The parser's state across the pieces of the session's output.
#[derive(Debug, Clone, Copy, Default)]
pub struct Boundary {
    state: State,
}

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;

impl Boundary {
    /// Whether the terminal reads the next byte as the start of something
    /// new: no sequence and no character is open.
    pub fn at_ground(&self) -> bool {
        self.state == State::Ground
    }

    /// The terminal reads `bytes`.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state = next(self.state, b);
        }
    }
}

fn next(state: State, b: u8) -> State {
    match state {
        State::Ground => ground(b),
        // A byte that does not continue the character starts anew.
        State::Utf8(left) if b & 0xc0 == 0x80 => {
            if left > 1 {
                State::Utf8(left - 1)
            } else {
                State::Ground
            }
        }
        State::Utf8(_) => ground(b),
        _ if b == CAN || b == SUB => State::Ground,
        State::String { bel } => match b {
            ESC => State::StringEscape,
            BEL if bel => State::Ground,
            _ => state,
        },
        State::StringEscape if b == b'\\' => State::Ground,
        // An `ESC` that is not ST ends the string and starts a sequence.
        State::StringEscape => next(State::Escape, b),
        _ if b == ESC => State::Escape,
        // Other controls act inside a sequence and leave it open.
        _ if b < 0x20 => state,
        State::Escape => match b {
            b'[' => State::Csi,
            b']' => State::String { bel: true },
            b'P' | b'X' | b'^' | b'_' => State::String { bel: false },
            0x20..=0x2f => State::Intermediate,
            _ => State::Ground,
        },
        State::Intermediate => match b {
            0x20..=0x2f => State::Intermediate,
            _ => State::Ground,
        },
        State::Csi => match b {
            0x40..=0x7e => State::Ground,
            _ => State::Csi,
        },
    }
}

/// The state after `b` at the ground state: an escape, the first byte of a
/// UTF-8 character, or nothing open.
fn ground(b: u8) -> State {
    match b {
        ESC => State::Escape,
        0xc2..=0xdf => State::Utf8(1),
        0xe0..=0xef => State::Utf8(2),
        0xf0..=0xf4 => State::Utf8(3),
        _ => State::Ground,
    }
}
