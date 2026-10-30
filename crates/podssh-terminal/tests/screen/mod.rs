//! The terminal oracle (T-200): bytes in, a screen out. A model of a VT
//! terminal, the `vt100` crate, reads the bytes that podssh writes to a
//! terminal, and a test asks what a person would see: each row, where the
//! cursor is, and whether a cell took a color or an attribute. A test that
//! compares bytes with bytes that a person wrote passes when both share a
//! mistake: a wrong cursor column, or lines that step down like stairs.
//!
//! The model is a terminal in raw mode, as podssh's own is in a session: a
//! line feed moves down and keeps the column, since no `ONLCR` turns it into
//! CR LF. `tests/calibration.rs` of podssh-terminal checks the model against
//! tmux on a fixed corpus (`tests/screen/corpus.txt`), in the gate's
//! container. The tests of podssh-ws and podssh-ssh read this file through
//! `#[path]`, so that there is one model.

// Each test binary uses a part of it.
#![allow(dead_code)]

/// `n`, or 1 for none: a terminal has a row and a column at least.
fn at_least_one(n: u16) -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(n).unwrap_or(std::num::NonZeroU16::MIN)
}

/// A model terminal, and what it shows.
pub struct Screen {
    parser: vt100::Parser,
}

impl Screen {
    /// An empty screen of `rows` and `cols`, the cursor at the top left;
    /// vt100 0.18 takes neither as zero.
    pub fn new(rows: u16, cols: u16) -> Screen {
        Screen { parser: vt100::Parser::new(at_least_one(rows), at_least_one(cols), 0) }
    }

    /// The screen after `bytes`, from an empty one.
    pub fn of(rows: u16, cols: u16, bytes: &[u8]) -> Screen {
        let mut screen = Screen::new(rows, cols);
        screen.feed(bytes);
        screen
    }

    /// The terminal reads `bytes`.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    /// Rows, then columns.
    pub fn size(&self) -> (u16, u16) {
        let (rows, cols) = self.parser.screen().size();
        (rows.get(), cols.get())
    }

    /// The text of each row, with no blank cell at its end.
    pub fn rows(&self) -> Vec<String> {
        let (_, cols) = self.size();
        self.parser.screen().rows(0, cols).map(|row| row.trim_end().to_string()).collect()
    }

    /// The rows up to the last one that holds a character: what a person
    /// reads.
    pub fn text(&self) -> Vec<String> {
        let mut rows = self.rows();
        while rows.last().is_some_and(|row| row.is_empty()) {
            rows.pop();
        }
        rows
    }

    /// The cursor: its row and its column, each from 0.
    pub fn cursor(&self) -> (u16, u16) {
        self.parser.screen().cursor_position()
    }

    /// The character of a cell, with its accents. Empty for a blank cell,
    /// for a cell that a space blanked, and for the second cell of a wide
    /// character: a person sees no difference between them.
    pub fn glyph(&self, row: u16, col: u16) -> String {
        let Some(cell) = self.parser.screen().cell(row, col) else { return String::new() };
        let text = cell.contents().to_string();
        if text == " " {
            String::new()
        } else {
            text
        }
    }

    /// The first cell that holds `glyph`, row by row.
    pub fn find(&self, glyph: &str) -> Option<(u16, u16)> {
        let (rows, cols) = self.size();
        (0..rows).flat_map(|row| (0..cols).map(move |col| (row, col))).find(|&(row, col)| self.glyph(row, col) == glyph)
    }

    /// The last row whose first cell holds `glyph`.
    pub fn last_row_starting(&self, glyph: &str) -> Option<u16> {
        let (rows, _) = self.size();
        (0..rows).rev().find(|&row| self.glyph(row, 0) == glyph)
    }

    /// Each cell that took a color, bold, italic, underline or inverse.
    /// Text from a peer must give none.
    pub fn styled(&self) -> Vec<(u16, u16)> {
        let (rows, cols) = self.size();
        let screen = self.parser.screen();
        let mut out = Vec::new();
        for row in 0..rows {
            for col in 0..cols {
                let Some(cell) = screen.cell(row, col) else { continue };
                let plain = cell.fgcolor() == vt100::Color::Default
                    && cell.bgcolor() == vt100::Color::Default
                    && !cell.bold()
                    && !cell.italic()
                    && !cell.underline()
                    && !cell.inverse();
                if !plain {
                    out.push((row, col));
                }
            }
        }
        out
    }

    /// Whether the terminal moved to its other screen, as `ESC [ ? 1049 h`
    /// makes it.
    pub fn alternate(&self) -> bool {
        self.parser.screen().alternate_screen()
    }

    /// The screen as a person sees it, for the message of a failed check:
    /// each row between bars, and the cursor.
    pub fn show(&self) -> String {
        let (row, col) = self.cursor();
        let mut out = format!("the cursor at row {row}, column {col}\n");
        for (i, text) in self.rows().iter().enumerate() {
            out.push_str(&format!("{i:>3} |{text}|\n"));
        }
        out
    }
}
