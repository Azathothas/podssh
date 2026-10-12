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
            self.write(message, true);
        }
    }

    fn write(&self, message: &str, prefix: bool) {
        // In raw mode the terminal does not turn LF into CR LF.
        let raw = self.file.is_none() && crate::terminal::raw_active();
        let mut lead = String::from(if prefix { "podssh: " } else { "" });
        lead.push_str(self.prefix.as_deref().unwrap_or_default());
        let mut text = String::with_capacity(message.len() + 10);
        text.push_str(&lead);
        // With a prefix each line of a message gets it, so that a host's
        // lines can be found among the others'.
        match &self.prefix {
            Some(_) => text.push_str(&message.trim_end_matches('\n').replace('\n', &format!("\n{lead}"))),
            None => text.push_str(message),
        }
        if !text.ends_with('\n') {
            text.push('\n');
        }
        if raw {
            text = text.replace("\r\n", "\n").replace('\n', "\r\n");
        }
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
