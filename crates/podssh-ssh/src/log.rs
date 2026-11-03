//! What podssh says about itself, on stderr or appended to a file (`-E`), by
//! level. `-q` (`LogLevel QUIET`) silences everything, errors included, as it
//! does in OpenSSH: the exit status still says what happened.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use crate::options::LogLevel;

pub struct Log {
    level: LogLevel,
    file: Option<Mutex<File>>,
    /// Put after `podssh: `, and before a banner, on each line: the host
    /// that a line is about, when one process runs several (T-183).
    prefix: Option<String>,
}

impl std::fmt::Debug for Log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Log").field("level", &self.level).finish()
    }
}

impl Log {
    /// Messages at `level` and above go to stderr.
    pub fn new(level: LogLevel) -> Self {
        Log { level, file: None, prefix: None }
    }

    /// The same log with `prefix` on each line, such as `web1: `.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Messages at `level` and above are appended to `path` instead (`-E`).
    pub fn to_file(level: LogLevel, path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Log { level, file: Some(Mutex::new(file)), prefix: None })
    }

    pub fn level(&self) -> LogLevel {
        self.level
    }

    pub fn error(&self, message: &str) {
        self.at(LogLevel::Error, message);
    }

    pub fn info(&self, message: &str) {
        self.at(LogLevel::Info, message);
    }

    pub fn verbose(&self, message: &str) {
        self.at(LogLevel::Verbose, message);
    }

    pub fn debug(&self, message: &str) {
        self.at(LogLevel::Debug1, message);
    }

    /// Text the server sent for the user, such as a pre-login banner. Shown
    /// at INFO without the `podssh:` prefix. The caller makes it safe first
    /// (`podssh_ws::text::multi_line`).
    pub fn banner(&self, text: &str) {
        if self.level >= LogLevel::Info {
            self.write(text, false);
        }
    }

    fn at(&self, level: LogLevel, message: &str) {
        if self.level >= level {
            // A fact of the process, said once by the first log at -v (T-564).
            self.say_once();
            self.write(message, true);
            // A hint of the binary's after an error that it explains.
            self.hint(level, message);
        } else if level == LogLevel::Error && crate::said::on() {
            // -q hides an error from the screen, not from the report of a
            // failure (T-195).
            crate::said::keep(&host_text(message, true, self.prefix.as_deref(), false));
        }
    }

    fn write(&self, message: &str, prefix: bool) {
        // podssh's own words go into the report of a failure (T-195); a
        // server's banner does not.
        if prefix && crate::said::on() {
            crate::said::keep(&host_text(message, true, self.prefix.as_deref(), false));
        }
        // In raw mode the terminal does not turn LF into CR LF.
        let raw = self.file.is_none() && crate::terminal::raw_active();
        let text = host_text(message, prefix, self.prefix.as_deref(), raw);
        match &self.file {
            Some(file) => {
                let mut file = file.lock().unwrap_or_else(|e| e.into_inner());
                let _ = file.write_all(text.as_bytes());
            }
            None => {
                let mut err = std::io::stderr();
                let _ = err.write_all(text.as_bytes());
                let _ = err.flush();
            }
        }
    }
}

/// The text of one message as podssh writes it: `podssh: ` first when
/// `prefix`, a line break at its end, and each line break as CR LF when
/// `raw`. A terminal in raw mode does not turn LF into CR LF, so each line
/// after a bare LF would start where the one before it ended. Pure, so that
/// a test needs no terminal and no global state (T-200).
pub fn message_text(message: &str, prefix: bool, raw: bool) -> String {
    host_text(message, prefix, None, raw)
}

/// [`message_text`], with `host` after the lead of each line of the message,
/// so that a host's lines can be found among the others' (T-183).
fn host_text(message: &str, prefix: bool, host: Option<&str>, raw: bool) -> String {
    let mut lead = String::from(if prefix { "podssh: " } else { "" });
    lead.push_str(host.unwrap_or_default());
    let mut text = String::with_capacity(message.len() + 10);
    text.push_str(&lead);
    match host {
        Some(_) => text.push_str(&message.trim_end_matches('\n').replace('\n', &format!("\n{lead}"))),
        None => text.push_str(message),
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    if raw {
        text = text.replace("\r\n", "\n").replace('\n', "\r\n");
    }
    text
}

/// Lines of the process that no command owns, such as the limit of open
/// files (T-564): each said once, before the first line of the first log at
/// `-v` or more.
static ONCE: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// What the binary says after an error line that it explains, such as
/// "Too many open files" with the limit (T-564).
static HINT: std::sync::OnceLock<fn(&str) -> Option<String>> = std::sync::OnceLock::new();

/// Say `line` once, before the first line of the first log at `-v` or more.
pub fn say_once_at_verbose(line: String) {
    ONCE.lock().unwrap_or_else(|e| e.into_inner()).push(line);
}

/// Give each error line to `hint`, and say what it returns after the line;
/// the first call holds.
pub fn hint_errors(hint: fn(&str) -> Option<String>) {
    let _ = HINT.set(hint);
}

impl Log {
    fn say_once(&self) {
        if self.level < LogLevel::Verbose {
            return;
        }
        let lines = std::mem::take(&mut *ONCE.lock().unwrap_or_else(|e| e.into_inner()));
        for line in lines {
            self.write(&line, true);
        }
    }

    fn hint(&self, level: LogLevel, message: &str) {
        if level != LogLevel::Error {
            return;
        }
        if let Some(hint) = HINT.get().and_then(|hint| hint(message)) {
            self.write(&hint, true);
        }
    }
}
