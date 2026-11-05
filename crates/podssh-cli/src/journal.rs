//! A service's error lines keep their priority in the journal (T-640).
//! systemd files each line of a unit's stderr at one priority, `info`, so
//! `journalctl -p warning` showed nothing that a node said, not even why it
//! ended. Where stderr is the journal's own stream (`JOURNAL_STREAM` names
//! descriptor 2), an error line also goes to the journal's socket as one
//! entry of its native protocol, at its priority. The stream keeps each line
//! as before, in its order and with its unit, which the journal reads from
//! the stream and could miss on a datagram sent as the process ends; the
//! copy is what a read by priority finds. Elsewhere (a terminal, a pipe, a
//! file, a child that inherited the variable) nothing changes.
//!
//! The copy reaches the service that each line of the stream reaches, on
//! this host, from a socket bound to nothing: no outbound connection of rule
//! 2, and no helper (the call of Q86). Only a line above `info` is copied,
//! as the stream files each line at `info` already: a copy of each would
//! show each line twice in `journalctl -u`.
//!
//! The SSH client's log (`podssh ssh`, a tunnel's session, each command's
//! connection) gives its lines here too, with their priority, a warning's
//! among them (T-674).

use std::io::Write;
use std::sync::OnceLock;

use podssh_ssh::LogLevel;

mod entry;
#[cfg(target_os = "linux")]
mod sink;
#[cfg(test)]
mod tests;

pub use entry::{entry, priority, stream_of, IDENTIFIER, STREAM, WARNING};
#[cfg(target_os = "linux")]
pub use sink::Sink;

/// No sink where no system has the journal.
#[cfg(not(target_os = "linux"))]
pub enum Sink {}

static SINK: OnceLock<Option<Sink>> = OnceLock::new();

/// Find the journal, once, at the start of the binary, before a thread
/// starts and before a service's file sets a variable. Where there is one,
/// the SSH client's log copies its lines to it; elsewhere it copies nothing.
pub fn install() {
    if SINK.get_or_init(probe).is_some() {
        podssh_ssh::log::copy_lines(copy);
    }
}

#[cfg(target_os = "linux")]
fn probe() -> Option<Sink> {
    Sink::probe()
}

#[cfg(not(target_os = "linux"))]
fn probe() -> Option<Sink> {
    None
}

/// `text` as one line on `err`, as before; then, where stderr is the
/// journal's stream, a copy for the journal at `level`'s priority.
pub fn line(err: &mut dyn Write, level: LogLevel, text: &str) {
    line_to(err, SINK.get().and_then(Option::as_ref), level, text);
}

/// [`line`] with the sink given: the tests give their own.
pub fn line_to(err: &mut dyn Write, sink: Option<&Sink>, level: LogLevel, text: &str) {
    let _ = writeln!(err, "{text}");
    if let Some(sink) = sink {
        to_sink(sink, priority(level), text);
    }
}

/// The copy of a line that the SSH client's log put on stderr, at its
/// `priority` (T-674): the log wrote the line, and the sink decides, as for
/// [`line`], whether the journal gets it.
pub fn copy(priority: u8, text: &str) {
    // A test's own sink, on its own thread.
    #[cfg(test)]
    {
        if tests::to_test_sink(priority, text) {
            return;
        }
    }
    if let Some(sink) = SINK.get().and_then(Option::as_ref) {
        to_sink(sink, priority, text);
    }
}

#[cfg(target_os = "linux")]
fn to_sink(sink: &Sink, priority: u8, text: &str) {
    sink.say_at(priority, text);
}

#[cfg(not(target_os = "linux"))]
fn to_sink(sink: &Sink, _: u8, _: &str) {
    match *sink {}
}
