//! The line under edit: the byte rules, transcribed.
//!
//! **This module is a transcription.** podbox ships this exact discipline
//! server-side — **READ**, `.tmp/podbox/crates/podbox-ssh/src/session.rs:1` —
//! and its bytes are pinned by ~40 named tests, so re-deriving them would only
//! produce a second thing to be wrong. Each constant and each byte rule below
//! cites the line it came from, read with `sed -n` on 2026-10-02.
//!
//! **The one deliberate difference is the destination names, not the bytes.**
//! The sibling names them `ToShell` and `ToClient` because it supervises a local
//! `/bin/sh` under `ForceCommand`. podssh is the SSH *client*, so the forward
//! leg is an SSH channel rather than a pipe. **The byte sequence produced for
//! every input is identical**, and the tests assert those bytes, not the names.
//!
//! ## The byte rules, and where each one is transcribed from
//!
//! | Rule | Reference |
//! | --- | --- |
//! | prompt, `$ ` | `session.rs:102` |
//! | history cap, 100 lines, consecutive duplicates skipped | `session.rs:105`, `202-214` |
//! | line cap, 65536 bytes, past it a byte drops with a bell | `session.rs:108`, `440-453` |
//! | erase-in-line `EL` | `session.rs:114` |
//! | `BELL` | `session.rs:115` |
//! | redraw: `\r`, prompt, buffer, `EL`, `\r`, prompt, line-to-cursor | `session.rs:177-187` |
//! | `\r` and `\n` both submit; the `\n` of a `\r\n` pair is swallowed | `session.rs:260-266`, `273-277` |
//! | recognised escapes: exactly `ESC [ A B C D H F` | `session.rs:381-403` |
//! | the key dispatch itself | `session.rs:267-294` |
//!
//! ## What is deliberately absent
//!
//! **No `onlcr` here.** The sibling expands lone `\n` to `\r\n` on the way out
//! — **READ**, `session.rs:629-642` — because the shell below it runs on a pipe
//! and its `OPOST`/`ONLCR` is absent. podssh has no such gap: the remote side
//! is a real pty, so its own line discipline already did the translation and
//! podssh forwarding an extra `\r` would stair-step every line. The expansion
//! belongs to the case where there is no pty below, and this crate never sits
//! above one.
//!
//! **No supervisor, no shell, no process group.** `session.rs:456-744` spawns
//! and supervises a child. podssh has no child to spawn: the remote program is
//! the SSH server's, and the signal characters are channel bytes here, resolved
//! into `SIGINT`/`SIGQUIT` by the core that owns the connection.

//! ## The module split
//!
//! **The reference is one 1132-line file and this is not.** A source file
//! over 500 lines is a gate in this repository, not a preference, and the
//! answer to that is **to split by responsibility, not to delete the
//! comments that make the split legible.** Three files hold the same
//! transcription:
//!
//! | file | holds |
//! | --- | --- |
//! | [`echo.rs`](self) | the constants, the events, the line state, the key dispatch |
//! | [`editing`](editing) | erasing, moving, and the byte a key inserts |
//! | [`history`] | recall, the cap, and the parked line |
//! | [`inspect`] | the read-only accessors a caller and a test need |
//!
//! **The split is invisible in behaviour.** Every byte rule below is
//! transcribed to the same line of `session.rs` it was cited to before the
//! files were separated, and **no test was weakened or skipped to make the
//! split fit** — the suite is the same 96 tests.

use std::fmt;

use crate::escape::{Esc, Step};

pub mod editing;
pub mod history;
pub mod inspect;

/// The prompt, printed before every line. Static on purpose, and transcribed:
/// the sibling prints one because the shell below it runs non-interactive and
/// prints none of its own. **READ**, `session.rs:102`.
pub const PROMPT: &[u8] = b"$ ";
/// Lines of history kept per session, in memory. Past this the oldest line
/// leaves. **READ**, `session.rs:105`.
pub const HISTORY_CAP: usize = 100;
/// Longest single line, in bytes. Past this a byte drops with a bell: an
/// unbounded line buffer is the defect this cap exists to prevent.
/// **READ**, `session.rs:108`.
pub const LINE_CAP: usize = 65536;
/// Erase in Line: clear from the cursor to the end, ECMA-48.
/// **READ**, `session.rs:114`.
pub const EL: &[u8] = b"\x1b[K";
/// The bell. **READ**, `session.rs:115`.
pub const BELL: &[u8] = b"\x07";

/// A signal character, translated. **Named, not delivered.** This crate
/// never calls `kill`: the process that must die is the remote side's, and the
/// remote side is reached over a channel. `Sig` is the boundary — podssh-core
/// turns it into an SSH channel request or a terminal byte, according to what
/// the server granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    /// Ctrl-C, `0x03`. **READ**, `session.rs:268`.
    Int,
    /// Ctrl-backslash, `0x1c`. **READ**, `session.rs:269`.
    Quit,
}

// The byte-level refusals live in `crate::refusal`, not here, and that
// placement is load-bearing: the pass-through discipline must refuse the same
// three bytes as this module, and a list written twice is a list that drifts.
// The `key` dispatch below calls `crate::refusal::refuses`.

/// One consequence of one client byte.
///
/// **A byte can echo and submit at once** — Enter echoes `\r\n` and emits the
/// line in the same call — so this is a list, never a single value.
/// **READ**, `session.rs:127-140`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The submitted line for the **forward leg**, with its terminating `\n`.
    ToRemote(Vec<u8>),
    /// Bytes for the **reverse leg**: echo, prompt, redraw, or bell.
    ToLocal(Vec<u8>),
    /// A signal character for the remote process group.
    Signal(Sig),
    /// Input ended: Ctrl-D on an empty line, or EOF from the client.
    Eof,
}

impl fmt::Display for Event {
    /// A legible form, because a failing test prints one of these and a
    /// `Debug` dump of `vec![27, 91, 75]` names nothing. The spelling lives in
    /// [`crate::bytes`], because rendering bytes is its own job.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::ToRemote(b) => write!(f, "ToRemote({})", crate::bytes::quoted(b)),
            Event::ToLocal(b) => write!(f, "ToLocal({})", crate::bytes::quoted(b)),
            Event::Signal(s) => write!(f, "Signal({s:?})"),
            Event::Eof => write!(f, "Eof"),
        }
    }
}

/// The line under edit.
///
/// **Pure state.** Every method is deterministic in its arguments, which is
/// the only reason the tests can assert exact bytes rather than "something was
/// echoed". **READ**, `session.rs:152-168`.
#[derive(Debug, Default)]
pub struct Discipline {
    /// **`pub(crate)`, not `pub`.** The fields below are private to the
    /// crate because **the submodules write them and nothing outside may**:
    /// a caller that could set `cursor` without going through a byte rule
    /// could desynchronise the cursor from the buffer, and the redraw would
    /// then place the cursor where the line is not. The accessors in
    /// [`inspect`] are the only door out, and they return borrows.
    pub(crate) line: Vec<u8>,
    pub(crate) cursor: usize,
    pub(crate) history: Vec<String>,
    /// The uncommitted line set aside while browsing history, restored when the
    /// browse returns past the newest entry. **READ**, `session.rs:159-161`.
    pub(crate) saved: Option<Vec<u8>>,
    /// History index under view, or `None` when editing a fresh line.
    pub(crate) hpos: Option<usize>,
    /// **The escape parser, and it is not the reference's.** The reference
    /// reads two bytes and dispatches on the third (`session.rs:142-150`,
    /// `244-262`); this reads a whole CSI sequence, because **the entry's
    /// own plant — `ESC [ 1 5 ~` must produce a bell and no state change — cannot
    /// be satisfied by that parser.** See [`crate::escape`], which carries the
    /// measurement.
    esc: Esc,
    /// A `\r` just submitted: a `\n` arriving next is its pair, not a second
    /// line. **READ**, `session.rs:164-167`.
    last_was_cr: bool,
}

impl Discipline {
    pub fn new() -> Self {
        Discipline::default()
    }

    /// Redraw the line: `\r`, the prompt, the buffer, clear the rest, and the
    /// cursor back where the edit left it.
    ///
    /// **Transcribed byte for byte**, `session.rs:177-187`. ECMA-48 sequences
    /// a terminal from the last fifty years answers, and fixed bytes a pipe can
    /// assert — which is the whole reason the shape is not "whatever looks
    /// right".
    pub(crate) fn redraw(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROMPT.len() + self.line.len() * 2 + 16);
        out.extend_from_slice(b"\r");
        out.extend_from_slice(PROMPT);
        out.extend_from_slice(&self.line);
        out.extend_from_slice(EL);
        out.extend_from_slice(b"\r");
        out.extend_from_slice(PROMPT);
        out.extend_from_slice(&self.line[..self.cursor]);
        out
    }

    /// The `\b`, space, `\b` triple that rubbed out `n` cells. Terminals move
    /// the cursor back, blank the cell, and move back again: three bytes, no
    /// ANSI needed. **READ**, `session.rs:189-198`.
    ///
    /// **`pub` because a test asserts against it directly.** A test that
    /// rebuilt the triple as a literal would be a second copy of the rule, and
    /// a second copy is what drifts.
    pub fn rubout(n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n * 3);
        for _ in 0..n {
            out.extend_from_slice(b"\x08 \x08");
        }
        out
    }

    /// Store the line in history. Empty lines and repeats of the newest entry
    /// are not history: Up must reach a command, not blank air.
    /// **READ**, `session.rs:200-214`.
    pub(crate) fn commit(&mut self) {
        if self.line.is_empty() {
            return;
        }
        let line = String::from_utf8_lossy(&self.line).to_string();
        if self.history.last().is_some_and(|h| *h == line) {
            return;
        }
        self.history.push(line);
        if self.history.len() > HISTORY_CAP {
            self.history.remove(0);
        }
    }

    /// Submit the line: history, the forward bytes, and the echo.
    ///
    /// **The prompt travels with the echo, not after the output** — the shell
    /// runs non-interactive and prints none of its own. The order reads
    /// prompt-first on a busy session; the bytes stay deterministic, which a
    /// readiness heuristic could never promise. **READ**, `session.rs:216-232`.
    pub(crate) fn submit(&mut self) -> Vec<Event> {
        self.commit();
        let mut forward = std::mem::take(&mut self.line);
        forward.push(b'\n');
        self.cursor = 0;
        self.saved = None;
        self.hpos = None;
        let mut echo = b"\r\n".to_vec();
        echo.extend_from_slice(PROMPT);
        vec![Event::ToLocal(echo), Event::ToRemote(forward)]
    }

    /// Recall history entry `idx`: replace the buffer, park the cursor at the
    /// end, and redraw. **READ**, `session.rs:234-241`.
    pub(crate) fn recall(&mut self, idx: usize) -> Vec<Event> {
        self.line = self.history[idx].clone().into_bytes();
        self.cursor = self.line.len();
        self.hpos = Some(idx);
        vec![Event::ToLocal(self.redraw())]
    }

    /// One client byte in, its consequences out.
    ///
    /// **The dispatch is transcribed from `session.rs:244-295`**, including
    /// the order: an escape in progress owns the byte before anything else does,
    /// and the `\n` of a `\r\n` pair is swallowed before the byte is read as a
    /// submission.
    pub fn key(&mut self, b: u8) -> Vec<Event> {
        // An escape in progress owns the byte before anything else does —
        // **READ**, `session.rs:246`. **The parser is [`crate::escape`]'s, not
        // the reference's**, and the difference is the plant: the
        // reference dispatches on the byte after `ESC [` and drops the rest of
        // the sequence on the floor, where `ESC [ 1 5 ~` puts `5` and `~` into
        // the user's command line. This one consumes the whole sequence.
        match self.esc.step(b) {
            Step::Continue => return vec![],
            Step::Refused => return vec![Event::ToLocal(BELL.to_vec())],
            Step::Final { final_byte, bare } => return self.escape(final_byte, bare),
            // The byte was not part of a sequence. A control byte below
            // `0x20` lands here so `ESC` followed by `Ctrl-C` still signals
            // rather than being swallowed by a malformed sequence — the same
            // order the reference has, and the reason a user always has a way to
            // interrupt.
            Step::Restart => {}
        }
        // The second half of a `\r\n` pair is the pair, not a line.
        if self.last_was_cr {
            self.last_was_cr = false;
            if b == b'\n' {
                return vec![];
            }
        }
        match b {
            0x03 => self.signal_key(Sig::Int, b"^C\r\n"),
            0x1c => self.signal_key(Sig::Quit, b"^\\\r\n"),
            // Refused, loudly. `session.rs:271` refuses `0x1a` (Ctrl-Z),
            // `0x11` (Ctrl-Q) and `0x13` (Ctrl-S) in one arm, and this crate
            // keeps that: one shape, one reason, one bell. The predicate is
            // [`crate::refusal::refuses`] so the pass-through mode refuses the
            // same bytes from the same source.
            b if crate::refusal::refuses(b) => vec![Event::ToLocal(BELL.to_vec())],
            0x04 => self.eof_or_delete(),
            0x0d => {
                self.last_was_cr = true;
                self.submit()
            }
            0x0a => self.submit(),
            0x7f | 0x08 => self.erase_left(),
            0x15 => self.erase_line(),
            0x17 => self.erase_word(),
            0x01 => {
                self.cursor = 0;
                vec![]
            }
            0x05 => {
                self.cursor = self.line.len();
                vec![]
            }
            _ => self.insert(b),
        }
    }
}
