//! What podssh said about itself, kept for the report that a program of
//! `PODSSH_ERROR_PROGRAM` gets when podssh fails (T-195): the last [`LINES`]
//! lines of podssh's own messages, [`BYTES`] at most, from both of its
//! writers, [`crate::Log`] and the stderr of the command line. Nothing is
//! kept until [`start`], so a run with no such program keeps nothing. A
//! server's banner and a session's bytes never come here: they are not
//! podssh's words.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// The lines kept, at most.
pub const LINES: usize = 64;
/// The bytes of the lines kept, at most.
pub const BYTES: usize = 16 * 1024;
/// A longer line is cut, so that one line cannot push out the others.
pub const LINE: usize = 2048;

static ON: AtomicBool = AtomicBool::new(false);
static SAID: Mutex<Said> = Mutex::new(Said::new());

/// The last lines, oldest first, and their bytes.
#[derive(Debug, Default)]
pub struct Said {
    lines: VecDeque<String>,
    bytes: usize,
}

impl Said {
    pub const fn new() -> Self {
        Said { lines: VecDeque::new(), bytes: 0 }
    }

    /// Keep each line of `text` that is not blank, and drop the oldest
    /// past the bounds.
    pub fn keep(&mut self, text: &str) {
        for line in text.split('\n') {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() {
                continue;
            }
            let line = cut(line);
            self.bytes += line.len();
            self.lines.push_back(line);
            while self.lines.len() > LINES || self.bytes > BYTES {
                match self.lines.pop_front() {
                    Some(old) => self.bytes -= old.len(),
                    None => break,
                }
            }
        }
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

/// `line`, cut at [`LINE`] bytes on a character's boundary.
fn cut(line: &str) -> String {
    if line.len() <= LINE {
        return line.to_string();
    }
    let mut end = LINE;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &line[..end])
}

/// Keep podssh's messages from now on.
pub fn start() {
    ON.store(true, Ordering::Relaxed);
}

/// Whether podssh keeps its messages.
pub fn on() -> bool {
    ON.load(Ordering::Relaxed)
}

/// Keep the lines of `text`, a message of podssh's own, when [`start`] ran.
pub fn keep(text: &str) {
    if on() {
        SAID.lock().unwrap_or_else(|e| e.into_inner()).keep(text);
    }
}

/// The lines kept, oldest first.
pub fn lines() -> Vec<String> {
    SAID.lock().unwrap_or_else(|e| e.into_inner()).lines()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_lines_are_kept_within_both_bounds() {
        let mut said = Said::new();
        for i in 0..100 {
            said.keep(&format!("podssh: line {i}\n"));
        }
        let lines = said.lines();
        assert_eq!(lines.len(), LINES);
        assert_eq!(lines.first().map(String::as_str), Some("podssh: line 36"));
        assert_eq!(lines.last().map(String::as_str), Some("podssh: line 99"));

        let mut said = Said::new();
        let long = "x".repeat(1000);
        for _ in 0..40 {
            said.keep(&long);
        }
        let kept: usize = said.lines().iter().map(String::len).sum();
        assert!(kept <= BYTES, "{kept}");
        assert_eq!(said.lines().len(), BYTES / 1000);
    }

    #[test]
    fn a_message_of_lines_gives_each_and_no_blank_one() {
        let mut said = Said::new();
        said.keep("podssh: one\r\npodssh: two\n\n  \npodssh: three");
        assert_eq!(said.lines(), ["podssh: one", "podssh: two", "podssh: three"]);
    }

    #[test]
    fn a_long_line_is_cut_on_a_character() {
        let line = "é".repeat(LINE);
        let kept = cut(&line);
        assert!(kept.len() <= LINE + 3, "{}", kept.len());
        assert!(kept.ends_with("..."));
        assert_eq!(cut("short"), "short");
    }
}
