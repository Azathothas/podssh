//! Where a stream of terminal output may start (T-221, GitHub #31).
//!
//! A kept shell's ring of output drops its oldest bytes (T-159), and a
//! client that attaches gets the rest from its first byte. If that byte is
//! inside an escape sequence or a UTF-8 character, the terminal shows the
//! end of the sequence as text: a full-screen program draws wrongly, or a
//! part of a title shows on the command line. The [`Tracker`] reads the
//! output as a terminal does, and finds each place where a cut is clean: a
//! [`Boundary`]. The [`Ring`] drops bytes only up to one.
//!
//! The grammar is ECMA-48's, read with the states of the DEC parser that
//! xterm and vte follow (vt100.net/emu/dec_ansi_parser):
//!
//! - Text is at a boundary at each byte but a UTF-8 continuation byte.
//! - `ESC` starts a sequence wherever it comes. `ESC` and a byte 0x30 to
//!   0x7E is one, with intermediate bytes 0x20 to 0x2F between them or not.
//! - A CSI (`ESC [`) ends at its final byte, 0x40 to 0x7E. A control byte
//!   inside it is acted on, and the CSI goes on.
//! - An OSC (`ESC ]`) ends with ST (`ESC \`) or BEL. A DCS (`ESC P`), SOS
//!   (`ESC X`), PM (`ESC ^`) and APC (`ESC _`) end with ST alone.
//! - CAN and SUB end each sequence.
//!
//! Where terminals differ, the tracker finds no boundary: a boundary too few
//! costs the ring a few more bytes, a wrong one shows garbage. So the byte
//! that cuts a UTF-8 character short starts none (vte drops that byte, and a
//! terminal that reads it shows it), and 0x9C, the 8-bit ST, ends no string
//! (vte ends a DCS with it; to a UTF-8 terminal it is a continuation byte).
//!
//! A sequence or a character that waits [`BROKEN_AFTER`] for its next byte
//! is broken: the program that began it will not end it, and what comes
//! after cannot be read as the grammar says. The next start is then the
//! byte after the next newline, or the next full repaint: `ESC [ 2 J`, a
//! switch to the alternate screen (`ESC [ ? 1049 h`, `?1047h`, `?47h`) or a
//! reset (`ESC c`), from its `ESC`. The caller gives the time with each
//! chunk; the module reads no clock.

use std::time::{Duration, Instant};

pub mod ring;

pub use ring::Ring;

/// A sequence that waits this long for its next byte is broken (the rule of
/// GitHub #31).
pub const BROKEN_AFTER: Duration = Duration::from_secs(10);

/// The bytes after an `ESC` that start the stream again after a broken
/// sequence: a full repaint or a reset.
const REPAINTS: [&[u8]; 5] = [b"[2J", b"[?1049h", b"[?1047h", b"[?47h", b"c"];
/// The longest of [`REPAINTS`].
const REPAINT_MAX: usize = 7;

const BEL: u8 = 0x07;
const LF: u8 = 0x0a;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;
const ESC: u8 = 0x1b;

/// A place where the stream may start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boundary {
    /// The offset of the byte that starts clean: a terminal that reads from
    /// it shows no part of a sequence as text.
    pub at: u64,
    /// The first boundary after a broken sequence: after a newline, or at a
    /// repaint.
    pub restart: bool,
}

/// What the tracker is inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Text.
    Ground,
    /// A UTF-8 character with this many continuation bytes to come.
    Utf8(u8),
    /// After `ESC`.
    Escape,
    /// `ESC` and intermediate bytes.
    EscapeIntermediate,
    /// A CSI, until its final byte.
    Csi,
    /// An OSC, until ST or BEL.
    Osc,
    /// A DCS, SOS, PM or APC, until ST.
    ControlString,
    /// A sequence that never ended: the offset of the last `ESC`, and the
    /// bytes after it while they may begin a repaint.
    Broken { esc: Option<u64>, seen: [u8; REPAINT_MAX], len: u8 },
}

/// The reader of a stream of terminal output.
#[derive(Debug, Clone)]
pub struct Tracker {
    state: State,
    /// The offset of the next byte.
    offset: u64,
    /// When the last chunk came.
    last: Option<Instant>,
    /// The next boundary is the first after a broken sequence.
    restart: bool,
}

impl Default for Tracker {
    fn default() -> Self {
        Tracker::new()
    }
}

impl Tracker {
    /// A tracker at the start of a stream, which is a boundary.
    pub fn new() -> Self {
        Tracker { state: State::Ground, offset: 0, last: None, restart: false }
    }

    /// Reads a chunk of the output that came at `now`, and gives `found`
    /// each boundary in it, in order.
    pub fn feed(&mut self, chunk: &[u8], now: Instant, mut found: impl FnMut(Boundary)) {
        if chunk.is_empty() {
            return;
        }
        let waited = self.last.map(|last| now.saturating_duration_since(last));
        if self.open() && waited.is_some_and(|w| w >= BROKEN_AFTER) {
            self.state = State::Broken { esc: None, seen: [0; REPAINT_MAX], len: 0 };
        }
        self.last = Some(now);
        for &b in chunk {
            if let Some(boundary) = self.step(b) {
                found(boundary);
            }
        }
    }

    /// The bytes read so far: the offset of the next byte.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Whether a sequence or a character is open, so that a long wait
    /// breaks it; and so that output that pauses inside one has not
    /// stopped yet (`podssh session wait --idle`, T-186).
    pub fn open(&self) -> bool {
        !matches!(self.state, State::Ground | State::Broken { .. })
    }

    /// One byte: the boundary that it shows, if any.
    fn step(&mut self, b: u8) -> Option<Boundary> {
        let at = self.offset;
        self.offset += 1;
        if let State::Broken { .. } = self.state {
            return self.watch(b, at);
        }
        let clean = self.state == State::Ground && !is_continuation(b);
        self.state = next(self.state, b);
        clean.then(|| self.found(at))
    }

    fn found(&mut self, at: u64) -> Boundary {
        Boundary { at, restart: std::mem::take(&mut self.restart) }
    }

    /// A byte after a broken sequence: only a newline or a repaint starts
    /// the stream again.
    fn watch(&mut self, b: u8, at: u64) -> Option<Boundary> {
        let State::Broken { esc, seen, len } = &mut self.state else { return None };
        match b {
            LF => {
                self.state = State::Ground;
                self.restart = true;
                None
            }
            ESC => {
                *esc = Some(at);
                *len = 0;
                None
            }
            _ => {
                let start = (*esc)?;
                let n = usize::from(*len);
                if n == REPAINT_MAX {
                    *esc = None;
                    return None;
                }
                seen[n] = b;
                *len += 1;
                let so_far = &seen[..=n];
                if REPAINTS.contains(&so_far) {
                    self.state = State::Ground;
                    self.restart = true;
                    return Some(self.found(start));
                }
                if !REPAINTS.iter().any(|r| r.starts_with(so_far)) {
                    *esc = None;
                }
                None
            }
        }
    }
}

/// A UTF-8 continuation byte: never the first byte of anything.
fn is_continuation(b: u8) -> bool {
    (0x80..=0xbf).contains(&b)
}

/// The state after `b`, in each state but a broken one.
fn next(state: State, b: u8) -> State {
    match (state, b) {
        // ESC, CAN and SUB act in each state.
        (_, ESC) => State::Escape,
        (_, CAN | SUB) => State::Ground,
        (State::Ground, 0xc2..=0xdf) => State::Utf8(1),
        (State::Ground, 0xe0..=0xef) => State::Utf8(2),
        (State::Ground, 0xf0..=0xf4) => State::Utf8(3),
        (State::Ground, _) => State::Ground,
        (State::Utf8(left), 0x80..=0xbf) if left > 1 => State::Utf8(left - 1),
        (State::Utf8(_), 0x80..=0xbf) => State::Ground,
        // The byte that cuts a character short is read as itself.
        (State::Utf8(_), _) => next(State::Ground, b),
        (State::Escape, b'[') => State::Csi,
        (State::Escape, b']') => State::Osc,
        (State::Escape, b'P' | b'X' | b'^' | b'_') => State::ControlString,
        (State::Escape | State::EscapeIntermediate, 0x20..=0x2f) => State::EscapeIntermediate,
        (State::Escape | State::EscapeIntermediate, 0x30..=0x7e) => State::Ground,
        (State::Csi, 0x40..=0x7e) => State::Ground,
        (State::Osc, BEL) => State::Ground,
        // Each other byte, a control byte among them, leaves the sequence
        // open.
        (state, _) => state,
    }
}

#[cfg(test)]
mod tests;
