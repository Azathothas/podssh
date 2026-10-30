//! A notice while the far end is silent (T-302): a user can then tell a
//! slow program from a link that is gone, before the layer finds the link
//! dead (30 s) and resumes the session on a new one.
//!
//! The road says how long the far end has been silent ([`Silence`]): the
//! resumable layer, which hears an answer to each question of this side
//! within a few round trips (`podssh_relay::session::hearing`). The notice
//! shows its seconds, counting up, and the escape that ends the session:
//!
//! - with a pty on a terminal, in the window's title, saved first on the
//!   terminal's stack of titles and taken back after ([`title`]), so that
//!   the screen of a full-screen program is never written; only where the
//!   terminal is known to keep that stack;
//! - with no pty, where stderr is a terminal, as a line on stderr, and a
//!   line when the far end answers again;
//! - else nowhere: never in a pipe, never with `-q`, never for a session
//!   whose output goes elsewhere (`podssh each`).
//!
//! The notice writes its sequences only where the session's output left the
//! terminal's parser at its ground state ([`Boundary`]), and takes its title
//! back before the far end's next bytes, so that a title that a program sets
//! then is kept.

mod boundary;
#[cfg(test)]
mod tests;
pub mod title;

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// tokio's clock, which a test can pause.
use tokio::time::Instant;

pub use boundary::Boundary;

/// How often the notice reads the far end's silence, and counts up.
pub const TICK: Duration = Duration::from_secs(1);

type Source = Arc<dyn Fn() -> Option<Duration> + Send + Sync>;

/// What a road says of the far end's silence, shared between the road and
/// the session that it carries, as the offer of kept shells is. A road with
/// no such word attaches nothing, and its sessions show no notice.
#[derive(Clone, Default)]
pub struct Silence(Arc<Shared>);

#[derive(Default)]
struct Shared {
    /// How long the far end has said nothing, when a question of this side
    /// waits past its limit; `None` while the far end answers.
    source: Mutex<Option<Source>>,
    /// Whether a session shows the notice in the window's title: the road
    /// then leaves out its own lines of a loss and a resume, which would be
    /// written into the screen.
    titled: AtomicBool,
}

impl std::fmt::Debug for Silence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Silence").field("attached", &self.attached()).field("titled", &self.titled()).finish()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Silence {
    /// The road's word on the far end's silence, from now on.
    pub fn attach(&self, source: impl Fn() -> Option<Duration> + Send + Sync + 'static) {
        *lock(&self.0.source) = Some(Arc::new(source));
    }

    /// Whether a road said that it tells the far end's silence.
    pub fn attached(&self) -> bool {
        lock(&self.0.source).is_some()
    }

    /// How long the far end has been silent, when a question waits past its
    /// limit; `None` while it answers, or with no road's word.
    pub fn silent(&self) -> Option<Duration> {
        let source = lock(&self.0.source).clone();
        source.and_then(|source| source())
    }

    /// Whether a session shows the notice in the window's title now.
    pub fn titled(&self) -> bool {
        self.0.titled.load(Ordering::SeqCst)
    }

    fn set_titled(&self, on: bool) {
        self.0.titled.store(on, Ordering::SeqCst);
    }
}

/// Where a notice shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The window's title, on a terminal that keeps a stack of titles.
    Title,
    /// A line on stderr, with no pty.
    Line,
}

/// What the facts of a session give: the notice's place, or none.
#[derive(Debug, Clone, Copy, Default)]
pub struct Facts {
    /// The local terminal is in raw mode: a pty, and keys on a terminal.
    pub raw: bool,
    pub pty: bool,
    pub stdout_terminal: bool,
    pub stderr_terminal: bool,
    /// `-q`.
    pub quiet: bool,
    /// The session's output goes elsewhere (`podssh each`).
    pub sink: bool,
    /// The terminal is known to keep a stack of titles.
    pub stack: bool,
}

impl Facts {
    /// The notice's place; none in a pipe, with `-q`, or on a terminal in
    /// raw mode that is not known to keep a stack of titles.
    pub fn place(&self) -> Option<Place> {
        if self.quiet || self.sink {
            return None;
        }
        if self.raw {
            return (self.stdout_terminal && self.stack).then_some(Place::Title);
        }
        (!self.pty && self.stderr_terminal).then_some(Place::Line)
    }
}

/// What the notice asks of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// These bytes on stdout, the terminal's.
    Write(Vec<u8>),
    /// This line on stderr.
    Say(String),
}

/// The notice of one session.
#[derive(Debug)]
pub struct Notice {
    place: Place,
    silence: Silence,
    /// The far end, as the notice names it.
    host: String,
    /// The escape character, which ends the session with `.`.
    escape: Option<u8>,
    boundary: Boundary,
    shown: Option<Shown>,
    /// When the notice reads the silence next.
    next: Instant,
}

/// A notice that shows: the seconds that it says, when it began, and the
/// silence then.
#[derive(Debug, Clone, Copy)]
struct Shown {
    seconds: u64,
    since: Instant,
    silent: Duration,
}

impl Notice {
    pub fn new(place: Place, silence: &Silence, host: &str, escape: Option<u8>) -> Notice {
        if place == Place::Title {
            silence.set_titled(true);
        }
        let silence = silence.clone();
        Notice {
            place,
            silence,
            host: host.to_string(),
            escape,
            boundary: Boundary::default(),
            shown: None,
            next: Instant::now() + TICK,
        }
    }

    /// The notice of a session to `host`, by the facts of this process and
    /// `opts`; none when the road tells no silence, or the facts give no
    /// place.
    pub fn for_session(opts: &crate::options::Options, host: &str, raw: bool, pty: bool) -> Option<Notice> {
        if !opts.silence.attached() {
            return None;
        }
        let facts = Facts {
            raw,
            pty,
            stdout_terminal: crate::terminal::stdout_is_terminal(),
            stderr_terminal: crate::terminal::stderr_is_terminal(),
            quiet: opts.log_level == crate::options::LogLevel::Quiet,
            sink: opts.output.is_some(),
            stack: title::known_stack(|name| std::env::var(name).ok()).is_some(),
        };
        let place = facts.place()?;
        Some(Notice::new(place, &opts.silence, host, opts.escape_char))
    }

    /// Whether the notice shows now.
    pub fn shows(&self) -> bool {
        self.shown.is_some()
    }

    /// The session's `data`, on its way to stdout, or to stderr when
    /// `stderr`: the bytes to write before it. A title takes the user's back
    /// before the far end's first bytes, so that a title that they set is
    /// kept; each byte moves the [`Boundary`].
    pub fn before_output(&mut self, data: &[u8], stderr: bool) -> Vec<u8> {
        let mut first = Vec::new();
        if !stderr && self.place == Place::Title && self.shown.is_some() && self.boundary.at_ground() {
            first.extend_from_slice(title::POP);
            self.shown = None;
        }
        self.boundary.feed(data);
        first
    }

    /// The words of the notice, after `seconds` of silence.
    fn text(&self, seconds: u64) -> String {
        let words = format!("no word from {} for {seconds} s", self.host);
        match (self.place, self.escape) {
            (Place::Title, Some(e)) => format!("podssh: {words}, {}. ends the session", shown_key(e)),
            (Place::Title, None) => format!("podssh: {words}"),
            (Place::Line, _) => words,
        }
    }

    /// What the notice does at `now`, when anything: show, count up, or go.
    pub fn tick(&mut self, now: Instant) -> Option<Action> {
        self.next = now + TICK;
        let silent = self.silence.silent();
        let shown = self.shown;
        match (self.place, silent, shown) {
            (Place::Title, Some(silent), shown) => {
                let seconds = silent.as_secs();
                if shown.is_some_and(|s| s.seconds == seconds) || !self.boundary.at_ground() {
                    return None;
                }
                let mut out = if shown.is_none() { title::PUSH.to_vec() } else { Vec::new() };
                out.extend_from_slice(&title::set(&self.text(seconds)));
                let (since, silent) = shown.map_or((now, silent), |s| (s.since, s.silent));
                self.shown = Some(Shown { seconds, since, silent });
                Some(Action::Write(out))
            }
            (Place::Title, None, Some(_)) if self.boundary.at_ground() => {
                self.shown = None;
                Some(Action::Write(title::POP.to_vec()))
            }
            (Place::Line, Some(silent), None) => {
                let seconds = silent.as_secs();
                self.shown = Some(Shown { seconds, since: now, silent });
                Some(Action::Say(self.text(seconds)))
            }
            (Place::Line, None, Some(shown)) => {
                self.shown = None;
                let took = shown.silent + now.saturating_duration_since(shown.since);
                Some(Action::Say(format!("{} answers again, after {} s of silence", self.host, took.as_secs())))
            }
            _ => None,
        }
    }
}

/// The escape character as a person types it: `~`, or `^]` for a control
/// character.
fn shown_key(escape: u8) -> String {
    match escape {
        0x00..=0x1f => format!("^{}", (escape + 0x40) as char),
        0x7f => "^?".to_string(),
        _ => (escape as char).to_string(),
    }
}

/// The notice's next action, at its next tick; never, with no notice.
pub async fn next(notice: Option<&mut Notice>) -> Action {
    let Some(notice) = notice else { return std::future::pending().await };
    loop {
        tokio::time::sleep_until(notice.next).await;
        if let Some(action) = notice.tick(Instant::now()) {
            return action;
        }
    }
}

/// The session ends: the user's title comes back, and the road writes its
/// lines again.
impl Drop for Notice {
    fn drop(&mut self) {
        if self.place != Place::Title {
            return;
        }
        self.silence.set_titled(false);
        if self.shown.is_some() {
            let mut out = std::io::stdout();
            let _ = out.write_all(title::POP);
            let _ = out.flush();
        }
    }
}
