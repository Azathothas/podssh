//! The progress of a copy (T-145) and of its run (T-472). One gauge for the
//! run, which each road feeds: a file in one stream, the chunks of
//! `--parallel`, the files K at once, and the copy by exec. On stderr, when
//! it is a terminal and `-q` is not given, one line that a carriage return
//! rewrites, 4 times a second at most: the file in flight, and with several
//! files the run's count. Where stderr is no terminal, `cp`, `mv` and `run`
//! write a plain line each [`EVERY_IN_PIPE`] once the run is that old, so
//! that a long copy shows that it lives and a short one stays silent; a
//! carriage return would make a log of lines that overwrite each other.
//! `scp`, `sftp`, `edit` and `job` write none there, as OpenSSH's scp and
//! sftp write none. With `--jsonl`, a `progress` object on stdout each
//! second for each file. The mode is the run's, set once by the command.

use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Where the progress of the run goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    /// A line on stderr, which is a terminal.
    Line,
    /// A plain line on stderr, which is no terminal (T-472).
    Plain,
    /// `progress` objects on stdout (`--jsonl`).
    Json,
}

static MODE: OnceLock<Mode> = OnceLock::new();

/// A pipe gets a plain line this often, and only once the run is this old.
pub const EVERY_IN_PIPE: Duration = Duration::from_secs(10);

/// A terminal's line is drawn again this often at most.
const LINE_EVERY: Duration = Duration::from_millis(250);

/// The mode of the run: `jsonl`, else a line when stderr is a terminal and
/// the run is not quiet, else a plain line when the command writes one
/// (`plain`: `cp`, `mv` and `run`) and the run is not quiet.
/// `PODSSH_PROGRESS=line` or `off` sets the line on or off whatever stderr
/// is.
pub fn init(jsonl: bool, quiet: bool, plain: bool) -> Mode {
    use std::io::IsTerminal;
    let forced = std::env::var("PODSSH_PROGRESS").ok();
    let mode = choose(jsonl, quiet, plain, forced.as_deref(), std::io::stderr().is_terminal());
    *RUN.lock().unwrap_or_else(|e| e.into_inner()) = Some(Run::new());
    *MODE.get_or_init(|| mode)
}

/// What [`init`] chooses, from `PODSSH_PROGRESS` (`forced`) and whether
/// stderr is a terminal.
pub fn choose(jsonl: bool, quiet: bool, plain: bool, forced: Option<&str>, terminal: bool) -> Mode {
    match (jsonl, forced) {
        (true, _) => Mode::Json,
        (false, Some("line")) => Mode::Line,
        (false, Some("off")) => Mode::Off,
        _ if quiet => Mode::Off,
        _ if terminal => Mode::Line,
        _ if plain => Mode::Plain,
        _ => Mode::Off,
    }
}

fn mode() -> Mode {
    MODE.get().copied().unwrap_or(Mode::Off)
}

/// A count of bytes, short: B, KiB, MiB or GiB.
pub fn bytes(n: u64) -> String {
    match n {
        n if n < 1 << 10 => format!("{n} B"),
        n if n < 1 << 20 => format!("{:.1} KiB", n as f64 / 1024.0),
        n if n < 1 << 30 => format!("{:.1} MiB", n as f64 / f64::from(1 << 20)),
        n => format!("{:.2} GiB", n as f64 / f64::from(1 << 30)),
    }
}

/// Bytes a second, of `n` bytes in `took`.
fn rate(n: u64, took: Duration) -> u64 {
    let secs = took.as_secs_f64();
    if secs > 0.0 {
        (n as f64 / secs) as u64
    } else {
        0
    }
}

/// A name as a line shows it: a control character of a far name, a
/// carriage return or an escape, is a `?`, so that the line stays one line.
pub fn shown(name: &str) -> String {
    name.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// The line of a copy: its name, the bytes done of the total, the percent,
/// the rate since the start, and the time left at that rate.
pub fn line(name: &str, done: u64, total: u64, took: Duration) -> String {
    let secs = took.as_secs_f64();
    let rate = if secs > 0.0 { done as f64 / secs } else { 0.0 };
    let percent = (done.min(total) * 100).checked_div(total).unwrap_or(100) as u32;
    let left = if rate > 0.0 && total > done {
        let s = ((total - done) as f64 / rate).ceil() as u64;
        format!("{}:{:02} left", s / 60, s % 60)
    } else {
        "--:-- left".to_string()
    };
    format!("{name}  {} of {}  {percent}%  {}/s  {left}", bytes(done), bytes(total), bytes(rate as u64))
}

/// The line of a run of several files on a terminal (T-472): the file in
/// flight, the run's files done of its files, its bytes and its rate.
pub fn run_line(name: &str, ended: usize, files: usize, sent: u64, took: Duration) -> String {
    format!("{name}  {ended} of {files} files  {}  {}/s", bytes(sent), bytes(rate(sent, took)))
}

/// The plain line of a run in a pipe (T-472): the run's files done of its
/// files, its bytes, how long it ran, its rate, and the file in flight with
/// its bytes done of its total.
pub fn plain_line(ended: usize, files: usize, sent: u64, took: Duration, now: Option<(&str, u64, u64)>) -> String {
    let noun = if files == 1 { "file" } else { "files" };
    let secs = took.as_secs();
    let mut text = format!("{ended} of {files} {noun}, {} in {secs} s ({}/s)", bytes(sent), bytes(rate(sent, took)));
    if let Some((name, done, total)) = now {
        text.push_str(&format!("; now {name}, {} of {}", bytes(done), bytes(total)));
    }
    text
}

/// What the gauge knows of the run: its files and its bytes. The file in
/// flight is the one whose gauge draws.
struct Run {
    started: Instant,
    /// The files known so far: each source of the command line, and the
    /// files of each tree once walked.
    files: usize,
    /// The files whose bytes have all gone, and those that needed no copy.
    ended: usize,
    /// The files whose gauge is open now.
    flying: usize,
    /// The bytes that went in this run; an earlier attempt's do not count.
    sent: u64,
    /// Whether the line is on the terminal now.
    on_screen: bool,
    /// When the line, or the plain line, was written last.
    drawn: Option<Instant>,
}

impl Run {
    fn new() -> Run {
        Run {
            started: Instant::now(),
            files: 0,
            ended: 0,
            flying: 0,
            sent: 0,
            on_screen: false,
            drawn: None,
        }
    }

    /// The files of the run, at least those that ended or are in flight.
    fn count(&self) -> usize {
        self.files.max(self.ended + self.flying)
    }
}

static RUN: Mutex<Option<Run>> = Mutex::new(None);

fn with_run<T>(f: impl FnOnce(&mut Run) -> T) -> Option<T> {
    let mut run = RUN.lock().unwrap_or_else(|e| e.into_inner());
    run.as_mut().map(f)
}

/// The run has `n` more files: a source of the command line, or the files
/// of a tree once walked.
pub fn more_files(n: usize) {
    with_run(|run| run.files += n);
}

/// A file of the run that needs no copy: one that `podssh run` leaves as it
/// was, or a second name that a hard link gives.
pub fn passed() {
    with_run(|run| run.ended += 1);
}

/// The progress of one copy, which feeds the run's.
pub struct Gauge {
    name: String,
    total: u64,
    /// The bytes that an earlier attempt brought: they count as done, not in
    /// the rate.
    from: u64,
    done: u64,
    started: Instant,
    /// When this file's `progress` object was written last (`--jsonl`).
    drawn: Option<Instant>,
    ended: bool,
}

impl Gauge {
    /// The copy of `name`, `total` bytes, `from` of them already there.
    pub fn new(name: &str, total: u64, from: u64) -> Gauge {
        with_run(|run| run.flying += 1);
        Gauge { name: name.to_string(), total, from, done: from, started: Instant::now(), drawn: None, ended: false }
    }

    /// `done` bytes are there: drawn when it is time.
    pub fn set(&mut self, done: u64) {
        let moved = done.saturating_sub(self.done);
        self.done = done;
        match mode() {
            Mode::Off => {}
            Mode::Json => self.json(),
            mode => self.run_draw(mode, moved),
        }
    }

    /// `n` more bytes are there, as each chunk of a copy in chunks moves its
    /// own.
    pub fn add(&mut self, n: u64) {
        self.set(self.done + n);
    }

    /// The run's line, on a terminal (`Line`) or in a pipe (`Plain`), when it
    /// is time.
    fn run_draw(&self, mode: Mode, moved: u64) {
        let text = with_run(|run| {
            run.sent += moved;
            let due = match mode {
                Mode::Line => !run.on_screen || run.drawn.is_none_or(|at| at.elapsed() >= LINE_EVERY),
                _ => {
                    run.started.elapsed() >= EVERY_IN_PIPE && run.drawn.is_none_or(|at| at.elapsed() >= EVERY_IN_PIPE)
                }
            };
            if !due {
                return None;
            }
            run.drawn = Some(Instant::now());
            run.on_screen = mode == Mode::Line;
            let name = shown(&self.name);
            let (ended, files, sent, took) = (run.ended, run.count(), run.sent, run.started.elapsed());
            let (done, total) = (self.done.saturating_sub(self.from), self.total.saturating_sub(self.from));
            Some(match mode {
                Mode::Line if files > 1 => run_line(&name, ended, files, sent, took),
                Mode::Line => line(&name, done, total, self.started.elapsed()),
                _ => plain_line(ended, files, sent, took, Some((&name, self.done, self.total))),
            })
        });
        let Some(Some(text)) = text else { return };
        let mut err = std::io::stderr().lock();
        let _ = match mode {
            Mode::Line => write!(err, "\r{text}\x1b[K"),
            _ => writeln!(err, "podssh: {text}"),
        };
        let _ = err.flush();
    }

    /// This file's `progress` object, a second after the start and each
    /// second then, so a copy quicker than that gives its `done` alone.
    fn json(&mut self) {
        let since = self.drawn.unwrap_or(self.started);
        if since.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.drawn = Some(Instant::now());
        let object = serde_json::json!({
            "event": "progress",
            "source": self.name,
            "bytes": self.done,
            "total": self.total,
            "seconds": (self.started.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        });
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{object}");
        let _ = out.flush();
    }

    /// The copy's end, once: the file counts as done when its bytes all went,
    /// and the line is cleared, so that what follows starts at the left.
    pub fn finish(&mut self) {
        if std::mem::replace(&mut self.ended, true) {
            return;
        }
        let whole = self.done >= self.total;
        let clear = with_run(|run| {
            run.flying = run.flying.saturating_sub(1);
            run.ended += usize::from(whole);
            std::mem::take(&mut run.on_screen)
        });
        if clear == Some(true) && mode() == Mode::Line {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[K");
            let _ = err.flush();
        }
    }
}

impl Drop for Gauge {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pipe_gets_a_plain_line_from_cp_mv_and_run_alone() {
        assert_eq!(choose(false, false, true, None, false), Mode::Plain);
        assert_eq!(choose(false, false, false, None, false), Mode::Off, "scp, sftp, edit and job");
        assert_eq!(choose(false, true, true, None, false), Mode::Off, "-q");
        assert_eq!(choose(false, false, true, Some("off"), false), Mode::Off);
        assert_eq!(choose(false, false, true, Some("line"), false), Mode::Line, "a terminal's line in a pipe");
        assert_eq!(choose(false, false, true, None, true), Mode::Line);
        assert_eq!(choose(true, false, true, None, true), Mode::Json);
    }

    #[test]
    fn the_lines_of_a_run_name_its_files_its_bytes_and_the_file_in_flight() {
        let took = Duration::from_secs(10);
        assert_eq!(run_line("a.txt", 3, 20, 5 << 20, took), "a.txt  3 of 20 files  5.0 MiB  512.0 KiB/s");
        let now = Some(("big.iso", 10 << 20, 70 << 20));
        assert_eq!(
            plain_line(0, 1, 10 << 20, took, now),
            "0 of 1 file, 10.0 MiB in 10 s (1.0 MiB/s); now big.iso, 10.0 MiB of 70.0 MiB"
        );
        assert_eq!(plain_line(2, 5, 0, Duration::ZERO, None), "2 of 5 files, 0 B in 0 s (0 B/s)");
        // A far name with a carriage return and an escape stays one line.
        assert_eq!(shown("a\r\x1b[2Jb"), "a??[2Jb");
        let lines = [run_line(&shown("x\ry"), 0, 2, 1, took), plain_line(0, 2, 1, took, Some((&shown("x\ny"), 0, 1)))];
        for text in lines {
            assert!(!text.contains(['\r', '\n', '\x1b']), "{text:?}");
        }
    }
}
