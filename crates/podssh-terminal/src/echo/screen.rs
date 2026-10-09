//! The rows of the edit area: where each cell of the prompt and the line
//! falls when they are wider than the terminal, and the motions between two
//! cells.
//!
//! **A place is counted from the first row of the prompt**, so the area is
//! the same whatever row of the screen it starts on. With no width known,
//! everything is on row 0, and the discipline draws as on one row.
//!
//! **The terminal's rules, as xterm and VTE apply them**: writing past the
//! last column wraps to the next row; a wide character that does not fit in
//! the rest of a row starts the next one and leaves the rest blank; `CUU`,
//! `CUD`, `CUF` and `CUB` stop at the margins, and a backspace does not go
//! up a row. A full row is left at once (the discipline writes `\r\n` there),
//! so a place never waits on a pending wrap. **A line taller than the screen
//! is not drawn right**: `ESC [ A` stops at the top row.

use super::units::units;
use super::{Discipline, Event, PROMPT};
use crate::window::Size;

/// A cell of the edit area: its row from the first row of the prompt, and
/// its column.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Place {
    pub row: usize,
    pub col: usize,
}

/// Erase in Display, below the cursor: clears the rows that a longer area
/// left below the new one.
pub(crate) const ED: &[u8] = b"\x1b[J";

/// `ESC [ n` and a final byte, for a motion of `n`. A count of 1 is left out,
/// as the arrow keys send it, and a count of 0 writes nothing.
pub(crate) fn csi(out: &mut Vec<u8>, n: usize, final_byte: u8) {
    if n == 0 {
        return;
    }
    out.extend_from_slice(b"\x1b[");
    if n > 1 {
        out.extend_from_slice(n.to_string().as_bytes());
    }
    out.push(final_byte);
}

/// The motion from one place to another: rows first, then columns.
pub(crate) fn motion(from: Place, to: Place) -> Vec<u8> {
    let mut out = Vec::new();
    if to.row < from.row {
        csi(&mut out, from.row - to.row, b'A');
    } else {
        csi(&mut out, to.row - from.row, b'B');
    }
    if to.col < from.col {
        csi(&mut out, from.col - to.col, b'D');
    } else {
        csi(&mut out, to.col - from.col, b'C');
    }
    out
}

/// The place after a glyph of `cells` drawn at `at`.
pub(crate) fn advance(at: Place, cells: usize, width: Option<usize>) -> Place {
    let Some(w) = width else {
        return Place { row: 0, col: at.col + cells };
    };
    let mut at = start(at, cells, width);
    at.col += cells;
    if at.col >= w {
        at = Place { row: at.row + 1, col: 0 };
    }
    at
}

/// Where a glyph of `cells` drawn at `at` begins: on the next row, when it
/// does not fit in the rest of this one.
pub(crate) fn start(at: Place, cells: usize, width: Option<usize>) -> Place {
    match width {
        Some(w) if at.col > 0 && at.col + cells > w => Place { row: at.row + 1, col: 0 },
        _ => at,
    }
}

impl Discipline {
    /// The place after byte `i` of the line: the prompt's cells, then each
    /// step's. The prompt is ASCII, one cell a byte.
    pub(crate) fn place(&self, i: usize) -> Place {
        let mut at = Place::default();
        for _ in PROMPT {
            at = advance(at, 1, self.width);
        }
        for u in units(&self.line[..i], self.utf8) {
            at = advance(at, u.cells, self.width);
        }
        at
    }

    /// A fresh area: the prompt drawn, the line empty, and the screen's
    /// cursor after the prompt.
    pub(crate) fn reset_area(&mut self) {
        self.shown = self.place(0);
        self.drawn_end = self.shown;
    }

    /// The terminal's size, when it is first known and at each change. A
    /// size of 0 is no size. **A new width draws the line again on a row of
    /// its own**: a terminal that reflows has moved the old rows to places
    /// this crate cannot know, and a fresh row is the one place it can.
    pub fn resize(&mut self, size: Size) -> Vec<Event> {
        let width = size.is_usable().then_some(usize::from(size.cols));
        if width == self.width {
            return vec![];
        }
        self.width = width;
        if self.line.is_empty() && self.drawn_end.row == 0 {
            self.reset_area();
            return vec![];
        }
        self.shown = Place::default();
        self.drawn_end = Place::default();
        let mut out = b"\r\n".to_vec();
        out.extend(self.redraw());
        vec![Event::ToLocal(out)]
    }

    /// The bytes of a step appended at the end of the line: the screen's
    /// cursor to the end first, if a silent move left it elsewhere, then the
    /// echo, and `\r\n` when the step filled its row, so the terminal's
    /// cursor does not wait in the last column.
    pub(crate) fn append_echo(&mut self, unit: &[u8]) -> Vec<u8> {
        let cells = units(unit, self.utf8).iter().map(|u| u.cells).sum();
        let mut out = motion(self.shown, self.drawn_end);
        out.extend_from_slice(unit);
        let end = advance(self.drawn_end, cells, self.width);
        if end.col == 0 && end.row > self.drawn_end.row {
            out.extend_from_slice(b"\r\n");
        }
        self.drawn_end = end;
        self.shown = end;
        out
    }

    /// The rubout of the last `cells` of the drawn line, which the line has
    /// already lost, when `\b` can make it: the screen's cursor at the end,
    /// and the cells on its row, ending where the line now ends. `\b` does
    /// not go up a row, and does not take a mark off its letter, so each
    /// other case is a redraw (`None`).
    pub(crate) fn rubout_at_end(&mut self, cells: usize) -> Option<Vec<u8>> {
        let end = self.place(self.line.len());
        let back = self.shown.col.checked_sub(cells).map(|col| Place { row: self.shown.row, col });
        if cells == 0 || self.shown != self.drawn_end || back != Some(end) {
            return None;
        }
        self.shown = end;
        self.drawn_end = end;
        Some(Discipline::rubout(cells))
    }

    /// The redraw over several rows: up to the first row of the area, `\r`,
    /// the prompt and the line, `\r\n` when the line filled its last row,
    /// `ESC [ J` for the rows that a longer area left below, and the cursor
    /// back to its place.
    pub(crate) fn redraw_rows(&self, end: Place, cursor: Place) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROMPT.len() + self.line.len() + 24);
        csi(&mut out, self.shown.row, b'A');
        out.push(b'\r');
        out.extend_from_slice(PROMPT);
        out.extend_from_slice(&self.line);
        if end.col == 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(ED);
        out.extend(motion(end, cursor));
        out
    }

    /// The motion from the screen's cursor down to the last row of the area,
    /// so that what follows is written below the line, not over it. Nothing
    /// on one row.
    pub(crate) fn down_to_last_row(&self) -> Vec<u8> {
        let mut out = Vec::new();
        csi(&mut out, self.drawn_end.row.saturating_sub(self.shown.row), b'B');
        out
    }

    /// Whether the line filled its last row, so the screen's cursor already
    /// stands at the start of a fresh row.
    pub(crate) fn on_fresh_row(&self) -> bool {
        self.drawn_end.row > 0 && self.drawn_end.col == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(row: usize, col: usize) -> Place {
        Place { row, col }
    }

    #[test]
    fn a_count_of_one_is_left_out_and_zero_writes_nothing() {
        let mut out = Vec::new();
        csi(&mut out, 1, b'D');
        csi(&mut out, 0, b'A');
        csi(&mut out, 12, b'C');
        assert_eq!(out, b"\x1b[D\x1b[12C");
    }

    #[test]
    fn a_motion_moves_rows_first_then_columns() {
        assert_eq!(motion(at(1, 2), at(0, 5)), b"\x1b[A\x1b[3C");
        assert_eq!(motion(at(0, 19), at(2, 0)), b"\x1b[2B\x1b[19D");
        assert!(motion(at(1, 1), at(1, 1)).is_empty());
    }

    #[test]
    fn a_full_row_is_left_at_once_and_a_wide_glyph_wraps_whole() {
        let w = Some(20);
        assert_eq!(advance(at(0, 18), 1, w), at(0, 19));
        assert_eq!(advance(at(0, 19), 1, w), at(1, 0), "the last column fills the row");
        assert_eq!(advance(at(0, 19), 2, w), at(1, 2), "a wide glyph starts the next row");
        assert_eq!(start(at(0, 19), 2, w), at(1, 0));
        assert_eq!(advance(at(0, 18), 2, w), at(1, 0), "a wide glyph that fits exactly");
        assert_eq!(advance(at(3, 4), 0, w), at(3, 4), "a mark takes no cell");
    }

    #[test]
    fn with_no_width_every_place_is_on_the_first_row() {
        assert_eq!(advance(at(0, 500), 2, None), at(0, 502));
        assert_eq!(start(at(0, 500), 2, None), at(0, 500));
    }

    #[test]
    fn the_prompt_takes_its_cells_and_a_size_of_zero_is_no_width() {
        let mut d = Discipline::new();
        assert_eq!(d.place(0), at(0, 2));
        assert!(d.resize(Size::new(24, 0)).is_empty());
        assert_eq!(d.width, None);
        assert!(d.resize(Size::new(24, 2)).is_empty());
        assert_eq!(d.place(0), at(1, 0), "a prompt of two cells fills a row of two");
    }
}
