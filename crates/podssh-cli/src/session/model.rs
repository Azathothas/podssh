//! What a session's daemon keeps of its output (T-186), sans-IO: the caller
//! gives the time.
//!
//! - The screen, as a terminal of the pty's size shows it: `vt100`, the
//!   model of the terminal oracle (T-200), so that `capture` reads rows of
//!   text, not bytes with sequences in them.
//! - The last 64 KiB as they came, from a clean place of the terminal's
//!   grammar: the ring of T-221, so that a raw capture never starts inside
//!   a sequence or a character.
//! - The text of the output since the last send, for `wait --match`: the
//!   bytes with each sequence and each control byte but LF and TAB taken
//!   out, so that a colour between two letters does not hide a match.
//! - When the output last came, read with the grammar's tracker: output
//!   that pauses inside a sequence has not stopped, until the grammar calls
//!   the sequence broken.

use std::time::{Duration, Instant};

use podssh_terminal::grammar::{Ring, Tracker, BROKEN_AFTER};

/// What a raw capture keeps, and the most text that a match reads.
pub const KEPT: usize = 64 * 1024;

const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;
const ESC: u8 = 0x1b;

pub struct Model {
    screen: vt100::Parser,
    ring: Ring,
    tracker: Tracker,
    plain: Plain,
    /// The text since the last send: its last [`KEPT`] bytes.
    since: Vec<u8>,
    born: Instant,
    last_output: Option<Instant>,
    last_send: Option<Instant>,
}

impl Model {
    /// A model of a terminal of `rows` and `cols`, from `now`.
    pub fn new(rows: u16, cols: u16, now: Instant) -> Self {
        Model {
            screen: vt100::Parser::new(rows.max(1), cols.max(1), 0),
            ring: Ring::new(KEPT),
            tracker: Tracker::new(),
            plain: Plain::default(),
            since: Vec::new(),
            born: now,
            last_output: None,
            last_send: None,
        }
    }

    /// Output that came at `now`.
    pub fn output(&mut self, bytes: &[u8], now: Instant) {
        self.screen.process(bytes);
        self.ring.push(bytes, now);
        self.tracker.feed(bytes, now, |_| {});
        self.plain.feed(bytes, &mut self.since);
        if self.since.len() > KEPT {
            let cut = self.since.len() - KEPT;
            self.since.drain(..cut);
        }
        self.last_output = Some(now);
    }

    /// A send at `now`: a match reads from here on, and quiet counts from
    /// here.
    pub fn sent(&mut self, now: Instant) {
        self.last_send = Some(now);
        self.since.clear();
    }

    /// How much longer the output must stay quiet to have stopped for
    /// `idle`: zero once it has. Quiet counts from the last output or the
    /// last send, the later, so that a wait right after a send waits for
    /// what the send brings. Output that pauses inside a sequence or a
    /// character has not stopped until the grammar calls it broken.
    pub fn idle_left(&self, idle: Duration, now: Instant) -> Duration {
        let since = [self.last_output, self.last_send].into_iter().flatten().max().unwrap_or(self.born);
        let quiet = now.saturating_duration_since(since);
        let need = if self.tracker.open() { idle.max(BROKEN_AFTER) } else { idle };
        need.saturating_sub(quiet)
    }

    /// Whether `text` came in the output since the last send.
    pub fn matched(&self, text: &[u8]) -> bool {
        !text.is_empty() && self.since.windows(text.len()).any(|w| w == text)
    }

    /// The screen's rows as text, with no blank at the end of a row and no
    /// empty row at the end, as `tmux capture-pane` gives them; each row
    /// ends with a newline.
    pub fn screen(&self) -> String {
        let screen = self.screen.screen();
        let (_, cols) = screen.size();
        let mut rows: Vec<String> = screen.rows(0, cols).map(|row| row.trim_end_matches(' ').to_string()).collect();
        while rows.last().is_some_and(String::is_empty) {
            rows.pop();
        }
        rows.iter().map(|row| format!("{row}\n")).collect()
    }

    /// The cursor's row and column, from 0.
    pub fn cursor(&self) -> (u16, u16) {
        self.screen.screen().cursor_position()
    }

    /// The rows and the columns of the screen.
    pub fn size(&self) -> (u16, u16) {
        self.screen.screen().size()
    }

    /// The last bytes, as they came, from a clean place of the grammar.
    pub fn raw(&self) -> Vec<u8> {
        self.ring.kept()
    }
}

/// The reader of the text of terminal output, for a match: the states of
/// the grammar of `podssh_terminal::grammar`, and each text byte kept but
/// the control bytes other than LF and TAB. A sequence may be cut between
/// two chunks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Plain {
    #[default]
    Text,
    /// After `ESC`, with intermediate bytes or none.
    Escape,
    Csi,
    /// An OSC (ended by BEL too), a DCS, SOS, PM or APC: until ST.
    Str { osc: bool },
}

impl Plain {
    /// Read `chunk`, and put its text on `out`.
    fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        for &b in chunk {
            *self = match (*self, b) {
                // ESC, CAN and SUB act in each state.
                (_, ESC) => Plain::Escape,
                (_, CAN | SUB) => Plain::Text,
                (Plain::Text, b'\n' | b'\t' | 0x20..=0x7e | 0x80..=0xff) => {
                    out.push(b);
                    Plain::Text
                }
                (Plain::Escape, b'[') => Plain::Csi,
                (Plain::Escape, b']') => Plain::Str { osc: true },
                (Plain::Escape, b'P' | b'X' | b'^' | b'_') => Plain::Str { osc: false },
                (Plain::Escape, 0x30..=0x7e) | (Plain::Csi, 0x40..=0x7e) => Plain::Text,
                (Plain::Str { osc: true }, BEL) => Plain::Text,
                // Each other byte, a control byte among them, leaves the state
                // as it is; ST is ESC and `\`, which ESC begins.
                (state, _) => state,
            };
        }
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
