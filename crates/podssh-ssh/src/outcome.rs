//! What a run of `podssh ssh` did, for `--result-file` (T-054): the bytes
//! that crossed its stdin, stdout and stderr, the remote command's status
//! or signal, how its session ended, the class of a failure, and the relay
//! host with its close. A process runs one chain of connections, so the
//! record is the process's, as the counts of the forwards are (T-041):
//! atomics on the data path, a lock elsewhere.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::io::End;
use crate::relay_stream::RelayEnd;

static STDIN: AtomicU64 = AtomicU64::new(0);
static STDOUT: AtomicU64 = AtomicU64::new(0);
static STDERR: AtomicU64 = AtomicU64::new(0);
static FACTS: Mutex<Facts> = Mutex::new(Facts::new());

/// The facts of a run, but its bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// The remote command's exit status.
    pub status: Option<u32>,
    /// The signal that killed it, and whether it dumped core.
    pub signal: Option<(String, bool)>,
    /// How its session ended: `status`, `signal`, `no-status`, `lost`,
    /// `escaped`, `terminated`, `detached` (T-158) or `interrupted` (T-293).
    pub end: Option<&'static str>,
    /// Why the run failed: `connect`, `host-key`, `auth`, `forward`, `relay`
    /// or `session`.
    pub failure: Option<&'static str>,
    /// The relay host that opened the session.
    pub relay_host: Option<String>,
    /// The relay's close: its code, and its reason.
    pub relay_close: Option<(Option<u16>, String)>,
    /// The run handed its stdin, stdout and stderr to a control master
    /// (T-039), which carries their bytes.
    pub shared: bool,
}

impl Facts {
    const fn new() -> Self {
        Facts {
            status: None,
            signal: None,
            end: None,
            failure: None,
            relay_host: None,
            relay_close: None,
            shared: false,
        }
    }
}

/// The record, read once the run is over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    pub stdin: u64,
    pub stdout: u64,
    pub stderr: u64,
    pub facts: Facts,
}

fn facts() -> std::sync::MutexGuard<'static, Facts> {
    FACTS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Bytes read from stdin and sent to the far side.
pub fn stdin(n: usize) {
    STDIN.fetch_add(n as u64, Ordering::Relaxed);
}

/// Bytes written to stdout, or to stderr.
pub fn output(n: usize, stderr: bool) {
    if stderr { &STDERR } else { &STDOUT }.fetch_add(n as u64, Ordering::Relaxed);
}

pub fn status(code: u32) {
    facts().status = Some(code);
}

pub fn signal(name: &str, core_dumped: bool) {
    facts().signal = Some((name.to_string(), core_dumped));
}

/// How a session ended; the last one counts, as `--persist` runs several.
/// A command that a signal killed ends with 128 + its number, as in OpenSSH:
/// `signal` says so.
pub fn ended(end: &End) {
    let mut facts = facts();
    let signalled = facts.signal.is_some();
    facts.end = Some(match end {
        End::Status(_) if signalled => "signal",
        End::Status(_) => "status",
        End::NoStatus => "no-status",
        End::Lost => "lost",
        End::Escaped(_) => "escaped",
        End::Terminated => "terminated",
        End::Detached(_) => "detached",
        End::Interrupted => "interrupted",
    });
}

/// The run handed its descriptors to a control master (T-039): the record
/// counts none of their bytes.
pub fn shared() {
    facts().shared = true;
}

/// How a session through a control master ended: `shared` (the master told
/// the exit code alone: a status, or 128 + a signal), `no-status` or
/// `terminated`.
pub fn shared_ended(end: &'static str) {
    facts().end = Some(end);
}

/// Why the run failed: the first cause said holds, but one that
/// [`failure_is`] puts in its place.
pub fn failed(class: &'static str) {
    facts().failure.get_or_insert(class);
}

/// The cause of the failure, in place of any said before: the relay's own
/// close, as the lines of a failure name the relay first (T-024), or the
/// verdict of the end-to-end channel (T-088), which says more than the
/// session saw.
pub fn failure_is(class: &'static str) {
    facts().failure = Some(class);
}

/// A new connection of the run: a try after a drop of the relay (T-025),
/// or one of `--persist`. What failed before it is no cause of the run's
/// end.
pub fn fresh() {
    facts().failure = None;
}

pub fn relay_host(host: &str) {
    facts().relay_host = Some(host.to_string());
}

/// The relay leg's end, as the relay stream recorded it.
pub fn relay_end(end: &RelayEnd) {
    facts().relay_close = Some(match end {
        RelayEnd::Closed { code, reason } => (*code, reason.clone()),
        RelayEnd::Failed(why) => (None, why.to_string()),
    });
}

pub fn record() -> Record {
    Record {
        stdin: STDIN.load(Ordering::Relaxed),
        stdout: STDOUT.load(Ordering::Relaxed),
        stderr: STDERR.load(Ordering::Relaxed),
        facts: facts().clone(),
    }
}
