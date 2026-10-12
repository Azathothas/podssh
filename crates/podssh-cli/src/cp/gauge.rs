//! The progress of a copy (T-145): on stderr, one line that a carriage
//! return rewrites, 4 times a second at most, when stderr is a terminal and
//! `-q` is not given; with `--jsonl`, a `progress` object on stdout each
//! second; else nothing, so a pipe gets only the answers. The mode is the
//! run's, set once by the command.

use std::io::Write;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Where the progress of the run goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    /// A line on stderr, which is a terminal.
    Line,
    /// `progress` objects on stdout (`--jsonl`).
    Json,
}

static MODE: OnceLock<Mode> = OnceLock::new();

/// The mode of the run: `jsonl`, else a line when stderr is a terminal and
/// the run is not quiet. `PODSSH_PROGRESS=line` or `off` sets the line on or
/// off whatever stderr is.
pub fn init(jsonl: bool, quiet: bool) -> Mode {
    use std::io::IsTerminal;
    let forced = std::env::var("PODSSH_PROGRESS").ok();
    let mode = match (jsonl, forced.as_deref()) {
        (true, _) => Mode::Json,
        (false, Some("line")) => Mode::Line,
        (false, Some("off")) => Mode::Off,
        _ if !quiet && std::io::stderr().is_terminal() => Mode::Line,
        _ => Mode::Off,
    };
    *MODE.get_or_init(|| mode)
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

/// The progress of one copy.
pub struct Gauge {
    name: String,
    total: u64,
    /// The bytes that an earlier attempt brought: they count as done, not in
    /// the rate.
    from: u64,
    done: u64,
    started: Instant,
    drawn: Option<Instant>,
}

impl Gauge {
    /// The copy of `name`, `total` bytes, `from` of them already there.
    pub fn new(name: &str, total: u64, from: u64) -> Gauge {
        Gauge { name: name.to_string(), total, from, done: from, started: Instant::now(), drawn: None }
    }

    /// `done` bytes are there: drawn when it is time.
    pub fn set(&mut self, done: u64) {
        self.done = done;
        let every = match mode() {
            Mode::Off => return,
            Mode::Line => Duration::from_millis(250),
            Mode::Json => Duration::from_secs(1),
        };
        // The line shows at once; an object comes a second after the start,
        // so a copy quicker than that gives its `done` alone.
        let since = match (self.drawn, mode()) {
            (Some(at), _) => Some(at),
            (None, Mode::Json) => Some(self.started),
            (None, _) => None,
        };
        if since.is_some_and(|at| at.elapsed() < every) {
            return;
        }
        self.drawn = Some(Instant::now());
        self.draw();
    }

    fn draw(&self) {
        let took = self.started.elapsed();
        match mode() {
            Mode::Off => {}
            Mode::Line => {
                let text = line(&self.name, self.done - self.from, self.total - self.from, took);
                let mut err = std::io::stderr().lock();
                let _ = write!(err, "\r{text}\x1b[K");
                let _ = err.flush();
            }
            Mode::Json => {
                let object = serde_json::json!({
                    "event": "progress",
                    "source": self.name,
                    "bytes": self.done,
                    "total": self.total,
                    "seconds": (took.as_secs_f64() * 10.0).round() / 10.0,
                });
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "{object}");
                let _ = out.flush();
            }
        }
    }

    /// The copy's end: the line is cleared, so that what follows starts at
    /// the left.
    pub fn finish(&mut self) {
        if mode() == Mode::Line && self.drawn.is_some() {
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
