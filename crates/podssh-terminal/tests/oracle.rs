//! The line discipline as a terminal shows it (T-200). After each key, the
//! screen of a model terminal (`tests/screen/`) must show the prompt and
//! the line from the first column of a row, wrapped as the terminal wraps
//! them, with nothing after them; and the cursor in the cell where the
//! next character after the text before the line's cursor would land. What
//! the screen must show is the model's own drawing of the prompt and the
//! line, from an empty screen: the discipline's bytes never judge
//! themselves. These are the regression tests of T-127 (the cursor counts
//! cells, not bytes) and of T-129 (Home, End, Delete, and output over the
//! line under edit), on a screen.
//!
//! The runs of keys come from a fixed xorshift, so that a failure repeats;
//! its message names the seed, the steps so far and both screens.

mod screen;
use screen::Screen;

use podssh_terminal::bytes::quoted;
use podssh_terminal::echo::{Discipline, Event, PROMPT};
use podssh_terminal::window::Size;

/// One thing that happens to a session.
#[derive(Clone, Copy)]
enum Step {
    /// A key: its bytes, as a terminal sends them.
    Key(&'static [u8]),
    /// A lone Escape, then no byte for the idle time.
    Escape,
    /// Output of the program.
    Output(&'static [u8]),
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Step::Key(bytes) => write!(f, "{}", quoted(bytes)),
            Step::Escape => write!(f, "ESC-then-idle"),
            Step::Output(bytes) => write!(f, "output{}", quoted(bytes)),
        }
    }
}

/// A model terminal, and the discipline that draws on it.
struct Run {
    d: Discipline,
    screen: Screen,
    /// The steps so far, for the message of a failed check.
    log: Vec<String>,
    /// Output hid the line, and nothing drew it again yet.
    hidden: bool,
    /// Input ended: Ctrl-D on an empty line.
    ended: bool,
}

impl Run {
    /// A screen of `rows` and `cols` with the first prompt on it, as the
    /// caller prints it. With `width`, the discipline knows the width, as
    /// from a client that measured its terminal.
    fn new(rows: u16, cols: u16, utf8: bool, width: bool) -> Run {
        let mut d = Discipline::with_utf8(utf8);
        if width {
            assert!(d.resize(Size::new(rows, cols)).is_empty(), "an empty line draws nothing");
        }
        Run { d, screen: Screen::of(rows, cols, PROMPT), log: Vec::new(), hidden: false, ended: false }
    }

    /// One step, then the check of the screen while the line is shown.
    fn step(&mut self, step: Step) -> Result<(), String> {
        if self.ended {
            return Ok(());
        }
        let events = match step {
            Step::Key(bytes) => bytes.iter().flat_map(|b| self.d.key(*b)).collect(),
            Step::Escape => {
                let mut events = self.d.key(0x1b);
                events.extend(self.d.idle());
                events
            }
            Step::Output(bytes) => self.d.output(bytes),
        };
        for event in events {
            match event {
                Event::ToLocal(bytes) => self.screen.feed(&bytes),
                Event::Eof => self.ended = true,
                _ => {}
            }
        }
        self.hidden = match step {
            Step::Output([]) => self.hidden,
            Step::Output(bytes) => bytes.last() != Some(&b'\n'),
            _ => false,
        };
        self.log.push(step.to_string());
        if self.hidden || self.ended {
            return Ok(());
        }
        self.check()
    }

    /// The screen shows the prompt and the line, and the cursor in its
    /// cell.
    fn check(&self) -> Result<(), String> {
        let (rows, cols) = self.screen.size();
        let fail = |why: String| -> Result<(), String> {
            Err(format!("{why}\nthe steps: {}\nthe screen:\n{}", self.log.join(" "), self.screen.show()))
        };
        let Some(top) = self.screen.last_row_starting("$") else {
            return fail("no row starts with the prompt".into());
        };
        let line = self.d.line();
        let want = Screen::of(rows, cols, &[PROMPT, line].concat());
        let mark = Screen::of(rows, cols, &[PROMPT, &line[..self.d.cursor()], &b"#"[..]].concat());
        let Some((row, col)) = mark.find("#") else {
            return fail("the mark of the cursor is not on the model's screen".into());
        };
        let room = rows - top;
        if want.text().len() > usize::from(room) {
            return fail(format!("the prompt and the line take {} rows, and {room} are left", want.text().len()));
        }
        for i in 0..room {
            for c in 0..cols {
                let (got, wanted) = (self.screen.glyph(top + i, c), want.glyph(i, c));
                if got != wanted {
                    return fail(format!(
                        "row {} column {c} shows {got:?}, where the prompt and the line put {wanted:?}\n\
                         the line: {}\nwhat the screen must show from row {top}:\n{}",
                        top + i,
                        quoted(line),
                        want.show()
                    ));
                }
            }
        }
        if self.screen.cursor() != (top + row, col) {
            return fail(format!(
                "the cursor is at {:?}, where the line's cursor, byte {} of {}, puts it at {:?}",
                self.screen.cursor(),
                self.d.cursor(),
                line.len(),
                (top + row, col)
            ));
        }
        Ok(())
    }
}

/// Each of `all` on a screen of `rows` and `cols` whose width the
/// discipline knows, checked after each.
fn steps(rows: u16, cols: u16, utf8: bool, all: &[Step]) {
    let mut run = Run::new(rows, cols, utf8, true);
    for step in all {
        if let Err(why) = run.step(*step) {
            panic!("{rows}x{cols}, utf8 {utf8}: {why}");
        }
    }
}

/// Each byte of `text` as a key of its own.
fn typed(text: &'static [u8]) -> Vec<Step> {
    text.chunks(1).map(Step::Key).collect()
}

const LEFT: Step = Step::Key(b"\x1b[D");
const RIGHT: Step = Step::Key(b"\x1b[C");
const BACKSPACE: Step = Step::Key(b"\x7f");
const DELETE: Step = Step::Key(b"\x1b[3~");
const ENTER: Step = Step::Key(b"\r");

#[test]
fn screen_t127_a_wide_character_and_an_accent_take_their_cells() {
    // `a`, a wide character, an `e` with its accent typed after it, and
    // `b`; Left over each, Backspace over the `a`, an insert at the start,
    // and Enter. The cursor stands on cells, not on bytes.
    let accent = Step::Key("\u{301}".as_bytes());
    let wide = Step::Key("\u{4e2d}".as_bytes());
    let mut all = vec![Step::Key(b"a"), wide, Step::Key(b"e"), accent, Step::Key(b"b")];
    all.extend([LEFT, LEFT, LEFT, BACKSPACE, Step::Key(b"x"), RIGHT, RIGHT, ENTER]);
    steps(8, 16, true, &all);
}

#[test]
fn screen_t127_backspace_takes_a_whole_character_off_the_screen() {
    // A character of two bytes and one of three, each erased by one
    // Backspace at the end of the line, where the rubout serves.
    let all = [Step::Key("\u{e9}".as_bytes()), Step::Key("\u{4e2d}".as_bytes()), BACKSPACE, BACKSPACE, Step::Key(b"z")];
    steps(4, 20, true, &all);
}

#[test]
fn screen_t126_a_wide_character_that_does_not_fit_starts_the_next_row() {
    // Six columns: `$ abc` leaves one cell, and the wide character starts
    // the next row. Left puts the cursor after the `c`, Right after the wide
    // character, and Backspace brings the line back to one row.
    let mut all = typed(b"abc");
    all.extend([Step::Key("\u{6f22}".as_bytes()), LEFT, RIGHT, BACKSPACE, Step::Key(b"d"), Step::Key(b"e")]);
    steps(6, 6, true, &all);
}

#[test]
fn screen_t129_home_end_and_delete_on_a_line_of_three_rows() {
    // 10 columns: `$ ` and 25 letters take three rows. Home goes up to the
    // first, End back down; Delete takes a letter from the middle; an insert
    // at the start draws the three rows again; Ctrl-U clears them.
    let mut all = typed(b"abcdefghijklmnopqrstuvwxy");
    let home = Step::Key(b"\x1b[H");
    let end = Step::Key(b"\x1bOF");
    all.extend([home, end, home, RIGHT, RIGHT, DELETE, Step::Key(b"\x1b[1~"), Step::Key(b"X")]);
    all.extend([Step::Key(b"\x05"), DELETE, LEFT, Step::Key(b"\x04"), Step::Key(b"\x1b[7~"), Step::Key(b"\x15")]);
    steps(8, 10, true, &all);
}

#[test]
fn screen_t129_output_goes_above_the_line_under_edit() {
    // Output that ends its row goes above the line, which comes back below
    // it with the cursor mid-line; output that stops inside a row waits,
    // and the next key brings the line back on a row of its own; output
    // longer than a row wraps above it.
    let mut all = typed(b"abcdef");
    all.extend([LEFT, LEFT, Step::Output(b"one\ntwo\n"), Step::Output(b"Name: "), Step::Key(b"x")]);
    all.extend([Step::Output(b"a row longer than sixteen\n"), RIGHT, ENTER, Step::Output(b"after\n")]);
    steps(10, 16, true, &all);
}

#[test]
fn screen_t129_history_and_ctrl_c_on_rows() {
    // Two lines into the history, one of two rows; Up brings each back,
    // Down returns to the line set aside; Ctrl-C mid-line starts a fresh
    // prompt below.
    let mut all = typed(b"a long first line");
    all.push(ENTER);
    all.extend(typed(b"two"));
    all.extend([ENTER, Step::Key(b"x"), Step::Key(b"\x1b[A"), Step::Key(b"\x1b[A"), Step::Key(b"\x1b[B")]);
    all.extend([Step::Key(b"\x1b[B"), LEFT, Step::Key(b"\x03"), Step::Key(b"\x1b[A"), Step::Key(b"\x17")]);
    steps(8, 12, true, &all);
}

/// A fixed xorshift, so that a run repeats.
struct Rng(u32);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0 as usize % n
    }
}

/// What a run types: ASCII that is neither `$` nor `#`, which the checks
/// look for.
const TYPED: &[&[u8]] = &[b"a", b"b", b"c", b"x", b"y", b"z", b" ", b"0", b"7", b"-", b"/", b"."];

/// What a run types with IUTF8 besides: characters of two bytes and one
/// cell, and of three bytes and two cells. An accent typed alone is left
/// out: echoed after a row that the line filled, it lands on the next row,
/// where a terminal has no letter to put it on.
const WIDE: &[&[u8]] = &["\u{e9}".as_bytes(), "\u{fc}".as_bytes(), "\u{4e2d}".as_bytes(), "\u{30a2}".as_bytes()];

/// The keys that edit, in each form a terminal sends. A control byte that
/// the discipline types into the line (TAB, VT, FF and the like) is left
/// out: its echo moves a terminal's cursor in a way of its own, where the
/// discipline counts one cell for it (T-127's decision). A table: one kind
/// of key to a row (rustfmt::skip).
#[rustfmt::skip]
const EDITS: &[&[u8]] = &[
    b"\x7f", b"\x08", b"\x15", b"\x17", b"\x01", b"\x05", b"\x04", b"\x03", b"\x1c",
    b"\r", b"\n", b"\r\n", b"\x1bOM",
    b"\x1b[D", b"\x1b[C", b"\x1b[A", b"\x1b[B", b"\x1bOD", b"\x1bOC",
    b"\x1b[H", b"\x1b[F", b"\x1bOH", b"\x1bOF", b"\x1b[1~", b"\x1b[4~", b"\x1b[7~", b"\x1b[8~", b"\x1b[3~",
    b"\x1bOj", b"\x1bOy", b"\x1bOX",
    b"\x1b[2~", b"\x1b[5~", b"\x1b[15~", b"\x1b[1;5D", b"\x1bOP", b"\x1a", b"\x11", b"\x13",
];

/// Output of the program: with an end of row, and without one.
const OUTPUT: &[&[u8]] = &[b"out\n", b"two words\n", b"line one\nline two\n", b"no end", b"x", b"\n"];

/// A run of `len` steps from `seed`: mostly typing, then the keys that
/// edit, some output, and now and then a lone Escape.
fn run_of(seed: u32, utf8: bool, len: usize) -> Vec<Step> {
    let mut rng = Rng(seed.max(1));
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let roll = rng.below(100);
        let step = if roll < 55 && utf8 && rng.below(3) == 0 {
            Step::Key(WIDE[rng.below(WIDE.len())])
        } else if roll < 55 {
            Step::Key(TYPED[rng.below(TYPED.len())])
        } else if roll < 92 {
            Step::Key(EDITS[rng.below(EDITS.len())])
        } else if roll < 98 {
            Step::Output(OUTPUT[rng.below(OUTPUT.len())])
        } else {
            Step::Escape
        };
        out.push(step);
    }
    out
}

/// Runs of up to 48 steps on one terminal, one for each seed. The screens
/// hold the longest line that 48 steps can make: a line taller than the
/// screen is not drawn right, as `docs/terminal.md` says.
fn runs(rows: u16, cols: u16, utf8: bool, width: bool, seeds: std::ops::Range<u32>) {
    for seed in seeds {
        let mut run = Run::new(rows, cols, utf8, width);
        let len = 1 + Rng(seed.wrapping_mul(0x9e37_79b9).max(1)).below(48);
        for step in run_of(seed, utf8, len) {
            if let Err(why) = run.step(step) {
                panic!("{rows}x{cols}, utf8 {utf8}, width known {width}, seed {seed}: {why}");
            }
        }
    }
}

#[test]
fn screen_runs_of_keys_with_iutf8_on_16_columns() {
    runs(12, 16, true, true, 1..301);
}

#[test]
fn screen_runs_of_keys_with_iutf8_on_8_columns() {
    runs(16, 8, true, true, 1001..1301);
}

#[test]
fn screen_runs_of_keys_without_iutf8_on_20_columns() {
    runs(10, 20, false, true, 2001..2301);
}

#[test]
fn screen_runs_with_no_width_known_stay_on_one_row() {
    runs(6, 200, true, false, 3001..3201);
}
