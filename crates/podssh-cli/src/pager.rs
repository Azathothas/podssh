//! The pager. ⛔ **A function, not a `Command`.**
//!
//! ⛔ `docs/spec/06-cli.md`:196-197: *"`--no-pager` writes to stdout and exits.
//! Without it, podssh pages the output **itself** — it does not invoke
//! `less`."* ⛔ So there is no child process on this path at all, and ⛔ that is
//! a property of the code rather than a claim about the host: nothing here can
//! spawn anything, because nothing here names a process.
//!
//! ⛔ **Why a pager child is the hazard and not merely a preference.**
//! `docs/spec/02-architecture.md`:108-121 records a pager as a program podssh
//! might spawn that *"needs a slave fd, and on this host it cannot have one"*,
//! ⛔ and `less` is a demonstrated hazard on the remote side even where it
//! exists: **READ**, `sandhome` `shell/faketty:89-93`, `less` answers
//! `'unknown': I need something more specific.` ⛔ The four roff tools and
//! `less` are recorded MISSING on the podbox base
//! (`06-cli.md`:167-185), and ⛔ `docs/TODO/RULES.md`:162-163 forbids depending
//! on a capability that has not been probed.
//!
//! ⛔ **A pager that waits on a key nobody presses is a hang, not a pager**
//! (`docs/TODO/cli/man.md`:181). ⛔ So the decision to page is made by the
//! caller from [`Tty`], and a reader end-of-file **stops** the pager rather
//! than being waited on.

use std::io::{BufRead, Write};

/// How many lines a screenful is.
///
/// ⛔ **A fixed constant, not a terminal-size probe**, which is the same choice
/// E31 made for `--help`'s width and for the same reason: a probe pulls in a
/// capability this host has not measured, and ⛔ `RULES.md`:162-163 forbids
/// depending on one. ⛔ 24 is the terminal that a constrained host is most
/// likely to be, and a wrong guess costs a keypress rather than a hang.
pub const PAGE_LINES: usize = 24;

/// ⛔ **The terminal state, passed in rather than asked for in here.**
/// ⛔ `false` means *not a terminal* **or** *could not be asked*, and the pager
/// treats both the same way it treats "no": do not page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tty {
    pub stdin: bool,
    pub stdout: bool,
}

impl Tty {
    /// Ask the operating system, once, from the code that owns the real file
    /// descriptors.
    ///
    /// ⛔ `std::io::IsTerminal` and not a hand-rolled `isatty`: it is in `std`,
    /// it is stable since Rust 1.70, and this workspace's declared MSRV is
    /// 1.82 (`Cargo.toml`:18). ⛔ A second `isatty` per platform would be a
    /// second thing to be wrong on a platform nobody tested.
    pub fn probed() -> Tty {
        use std::io::IsTerminal as _;
        Tty {
            stdin: std::io::stdin().is_terminal(),
            stdout: std::io::stdout().is_terminal(),
        }
    }

    /// The state a **test** gets: no terminal, so no paging, so no test can
    /// block on a key. ⛔ This is the whole reason the state is a parameter.
    pub fn none() -> Tty {
        Tty::default()
    }

    /// Whether paging is allowed at all. ⛔ **Both** ends must be a terminal: a
    /// page written to a terminal that cannot be read a key from is a page
    /// that stops forever.
    pub fn can_page(&self) -> bool {
        self.stdin && self.stdout
    }
}

/// What the user pressed at a `-- more --` prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Any key that is not `q` or end-of-file: show the next screenful.
    Next,
    /// `q` or `Q`: stop here.
    Quit,
    /// The reader ended. ⛔ **A stop, not a wait** — a pager that waits on a
    /// descriptor that will never answer is the hang `man.md`:181 names.
    Eof,
}

/// Read one key from `from`.
pub fn read_key(from: &mut dyn BufRead) -> Key {
    let mut byte = [0u8; 1];
    match from.read(&mut byte) {
        Ok(0) => Key::Eof,
        Ok(_) => match byte[0] {
            b'q' | b'Q' => Key::Quit,
            _ => Key::Next,
        },
        // A read error is treated as end-of-file: the alternative is a pager
        // that retries forever on a descriptor that is refusing.
        Err(_) => Key::Eof,
    }
}

/// Write `text` a screenful at a time, waiting for one key between screenfuls.
///
/// ⛔ **The prompt is a diagnostic and goes to `err`.** `06-cli.md`:251-252:
/// *"stdout is protocol data or the answer, and nothing else."* ⛔ A pager's
/// `-- more --` written to stdout corrupts the page for anything that pipes
/// `podssh man` into a file — it is plant 8 in `man.md`:234, and it is the
/// reason this function takes two writers.
///
/// ⛔ **The page is written verbatim.** `text.lines()` drops the terminator and
/// each line is written back with one, so paging through to the end produces
/// byte-for-byte what `--no-pager` writes — which is the property
/// `tests/man_page.rs` asserts against the real binary.
pub fn page(
    text: &str,
    keys: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> std::io::Result<()> {
    let lines: Vec<&str> = text.lines().collect();
    let mut start = 0;
    while start < lines.len() {
        let end = (start + PAGE_LINES).min(lines.len());
        for line in &lines[start..end] {
            writeln!(out, "{line}")?;
        }
        start = end;
        if start >= lines.len() {
            break;
        }
        write!(err, "-- more -- (space: next page, q: quit) ")?;
        err.flush()?;
        let key = read_key(keys);
        writeln!(err)?;
        if key != Key::Next {
            break;
        }
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn lines(n: usize) -> String {
        let mut s = String::new();
        for i in 0..n {
            s.push_str(&format!("line {i}\n"));
        }
        s
    }

    /// ⛔ **The control: a reader that never quits gets the whole page.**
    /// ⛔ Without this, "the pager stops on `q`" is satisfied by a pager that
    /// writes nothing.
    #[test]
    fn a_reader_that_never_quits_gets_the_whole_page() {
        let text = lines(PAGE_LINES * 3 + 7);
        let mut keys = Cursor::new(vec![b' '; 10]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        page(&text, &mut keys, &mut out, &mut err).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), text);
    }

    #[test]
    fn q_stops_at_the_screenful() {
        let text = lines(PAGE_LINES * 3);
        let mut keys = Cursor::new(b"q".to_vec());
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        page(&text, &mut keys, &mut out, &mut err).unwrap();
        let written: Vec<&str> = std::str::from_utf8(&out).unwrap().lines().collect();
        assert_eq!(written.len(), PAGE_LINES, "one screenful, then stop");
    }

    /// ⛔ **Plant 8, as a unit test.** ⛔ The prompt is a diagnostic, and
    /// `06-cli.md`:251-252 puts diagnostics on stderr in every subcommand.
    #[test]
    fn the_prompt_never_reaches_stdout() {
        let text = lines(PAGE_LINES + 1);
        let mut keys = Cursor::new(b" ".to_vec());
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        page(&text, &mut keys, &mut out, &mut err).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("more"), "{out}");
        assert!(String::from_utf8(err).unwrap().contains("-- more --"));
        assert_eq!(out, text);
    }

    /// ⛔ **End-of-file stops the pager.** ⛔ `man.md`:232's plant 6 is "the
    /// pager waits for a key with no TTY": with no input left there is nothing
    /// to wait for, and a pager that waits anyway is a hang. ⛔ This test is
    /// the unit half of the guard; the binary half is
    /// `tests/man_page.rs`, which reads a redirect from `/dev/null`.
    #[test]
    fn end_of_file_stops_the_pager_and_does_not_wait() {
        let text = lines(PAGE_LINES * 2);
        let mut keys = Cursor::new(Vec::new());
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        page(&text, &mut keys, &mut out, &mut err).unwrap();
        let written: Vec<&str> = std::str::from_utf8(&out).unwrap().lines().collect();
        assert_eq!(written.len(), PAGE_LINES, "stopped at the first screenful");
    }

    #[test]
    fn only_a_terminal_that_can_be_read_may_page() {
        assert!(!Tty::none().can_page());
        assert!(!Tty { stdin: true, stdout: false }.can_page());
        assert!(!Tty { stdin: false, stdout: true }.can_page());
        assert!(Tty { stdin: true, stdout: true }.can_page());
    }
}
