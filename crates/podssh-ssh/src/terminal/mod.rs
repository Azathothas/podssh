//! The local terminal: whether stdin and stdout are terminals, the window
//! size, raw mode for an interactive session, the terminal modes sent with a
//! pty request, and prompts on the controlling terminal.
//!
//! Nothing here assumes a terminal exists. Every function answers "none" or
//! an error when there is no terminal, and callers fall back from there.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

pub use platform::{pty_modes, read_line, RawMode};

/// A window size, in characters and (when known) pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub cols: u32,
    pub rows: u32,
    pub px_width: u32,
    pub px_height: u32,
}

static RAW: AtomicBool = AtomicBool::new(false);

/// Whether podssh currently holds the local terminal in raw mode (log lines
/// then need CR LF).
pub fn raw_active() -> bool {
    RAW.load(Ordering::SeqCst)
}

pub(crate) fn set_raw_active(on: bool) {
    RAW.store(on, Ordering::SeqCst);
}

pub fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

pub fn stdout_is_terminal() -> bool {
    std::io::stdout().is_terminal()
}

/// The terminal's size, if one can be measured.
pub fn size() -> Option<Size> {
    platform::size()
}

/// The size to send when there is no terminal to measure: `COLUMNS` and
/// `LINES` when they hold numbers, else 80x24.
pub fn fallback_size() -> Size {
    let read = |name: &str, default: u32| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|n| (1..=10_000).contains(n))
            .unwrap_or(default)
    };
    Size { cols: read("COLUMNS", 80), rows: read("LINES", 24), px_width: 0, px_height: 0 }
}

/// The `TERM` to send with a pty request: the local one, or `xterm-256color`
/// when it is unset or empty (a pty without a usable `TERM` breaks
/// full-screen programs on the server).
pub fn term_name() -> String {
    match std::env::var("TERM") {
        Ok(t) if !t.trim().is_empty() => t,
        _ => "xterm-256color".to_string(),
    }
}
