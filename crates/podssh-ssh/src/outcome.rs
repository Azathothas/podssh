//! What a run of `podssh ssh` did, for `--result-file` (T-054): the bytes
//! that crossed its stdin, stdout and stderr, the remote command's status
//! or signal, how its session ended, the class of a failure, and the relay
//! host with its close. Each call writes the record of its session: inside
//! [`scoped`] the session's own, so that the hosts of `podssh each` at once
//! keep theirs apart (T-484), else the process's, as `podssh ssh` runs one
//! chain of connections; atomics on the data path, a lock elsewhere. How far
//! the run got ([`crate::retry`]) and the server's last words
//! ([`crate::handler`]) are kept beside them, for the same reason.

use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::io::End;
use crate::relay_stream::RelayEnd;

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
    /// The relay sessions that the run opened: a copy past the relay's
    /// limits opens more than one (T-137, T-486).
    pub relay_sessions: u32,
    /// The relay's close: its code, and its reason.
    pub relay_close: Option<(Option<u16>, String)>,
    /// The run handed its stdin, stdout and stderr to a control master
    /// (T-039), which carries their bytes.
    pub shared: bool,
    /// The destination's SSH version line, made safe for a terminal, and
    /// the method that let the user in (`none`, `publickey`, ...): what
    /// `podssh health --preflight` says of the login (T-482).
    pub server_version: Option<String>,
    pub method: Option<&'static str>,
}

impl Facts {
    const fn new() -> Self {
        Facts {
            status: None,
            signal: None,
            end: None,
            failure: None,
            relay_host: None,
            relay_sessions: 0,
            relay_close: None,
            shared: false,
            server_version: None,
            method: None,
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

/// The record of one session, or of the process.
#[derive(Debug)]
pub struct Recorder {
    stdin: AtomicU64,
    stdout: AtomicU64,
    stderr: AtomicU64,
    facts: Mutex<Facts>,
    /// How far the run got (T-025), which [`crate::retry`] reads.
    pub(crate) phase: AtomicU8,
    /// The server's last SSH_MSG_DISCONNECT, and the connection's last
    /// error in words, as the handler keeps them (T-026, T-227).
    said: Mutex<Option<String>>,
    broke: Mutex<Option<String>>,
}

impl Recorder {
    const fn new() -> Self {
        Recorder {
            stdin: AtomicU64::new(0),
            stdout: AtomicU64::new(0),
            stderr: AtomicU64::new(0),
            facts: Mutex::new(Facts::new()),
            phase: AtomicU8::new(0),
            said: Mutex::new(None),
            broke: Mutex::new(None),
        }
    }

    fn read(&self) -> Record {
        Record {
            stdin: self.stdin.load(Ordering::Relaxed),
            stdout: self.stdout.load(Ordering::Relaxed),
            stderr: self.stderr.load(Ordering::Relaxed),
            facts: lock(&self.facts).clone(),
        }
    }
}

impl Default for Recorder {
    fn default() -> Self {
        Recorder::new()
    }
}

/// The process's record: each call outside [`scoped`] writes it.
static PROCESS: Recorder = Recorder::new();

tokio::task_local! {
    /// The session's record, for each future polled inside [`scoped`].
    static SCOPE: Arc<Recorder>;
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Where the calls write: a session's record, or the process's. A task of
/// the session that runs apart, as the SSH client's task that russh
/// spawns, takes it along: a spawned task has no scope of its own.
#[derive(Debug, Clone, Default)]
pub struct Here(Option<Arc<Recorder>>);

impl Here {
    pub(crate) fn with<R>(&self, f: impl FnOnce(&Recorder) -> R) -> R {
        match &self.0 {
            Some(scope) => f(scope),
            None => f(&PROCESS),
        }
    }

    /// The server's words of a disconnect, for the session that ends.
    pub(crate) fn said(&self, words: String) {
        self.with(|r| *lock(&r.said) = Some(words));
    }

    /// Why the connection failed after its handshake, in words.
    pub(crate) fn broke(&self, why: String) {
        self.with(|r| *lock(&r.broke) = Some(why));
    }
}

/// The record that a call made now writes.
pub fn here() -> Here {
    Here(SCOPE.try_with(Arc::clone).ok())
}

fn with<R>(f: impl FnOnce(&Recorder) -> R) -> R {
    here().with(f)
}

fn facts<R>(f: impl FnOnce(&mut Facts) -> R) -> R {
    with(|r| f(&mut lock(&r.facts)))
}

/// A record of its own for some work, which may end before the record is
/// read: a copy that its `--timeout` dropped keeps the record of what it
/// did (T-486).
#[derive(Debug, Clone, Default)]
pub struct Scope(Arc<Recorder>);

impl Scope {
    pub fn new() -> Scope {
        Scope::default()
    }

    /// `work`, with each call here that its futures make written to this
    /// record, and to no other.
    pub fn run<F: Future>(&self, work: F) -> tokio::task::futures::TaskLocalFuture<Arc<Recorder>, F> {
        SCOPE.scope(self.0.clone(), work)
    }

    /// What the work did so far.
    pub fn record(&self) -> Record {
        self.0.read()
    }
}

/// Run `work` with a record of its own: each call here that its futures
/// make writes it and no other, and the process's stays as it was (T-484).
/// What `work` gave, and its record.
pub async fn scoped<F: Future>(work: F) -> (F::Output, Record) {
    let scope = Scope::new();
    let out = scope.run(work).await;
    (out, scope.record())
}

/// Bytes read from stdin and sent to the far side.
pub fn stdin(n: usize) {
    with(|r| r.stdin.fetch_add(n as u64, Ordering::Relaxed));
}

/// Bytes written to stdout, or to stderr.
pub fn output(n: usize, stderr: bool) {
    with(|r| {
        let counter = if stderr { &r.stderr } else { &r.stdout };
        counter.fetch_add(n as u64, Ordering::Relaxed)
    });
}

pub fn status(code: u32) {
    facts(|f| f.status = Some(code));
}

pub fn signal(name: &str, core_dumped: bool) {
    facts(|f| f.signal = Some((name.to_string(), core_dumped)));
}

/// How a session ended; the last one counts, as `--persist` runs several.
/// A command that a signal killed ends with 128 + its number, as in OpenSSH:
/// `signal` says so.
pub fn ended(end: &End) {
    facts(|f| {
        let signalled = f.signal.is_some();
        f.end = Some(match end {
            End::Status(_) if signalled => "signal",
            End::Status(_) => "status",
            End::NoStatus => "no-status",
            // The status stays in the record beside it (T-461).
            End::Lost | End::Cut(_) => "lost",
            End::Escaped(_) => "escaped",
            End::Terminated => "terminated",
            End::Detached(_) => "detached",
            End::Interrupted => "interrupted",
        });
    });
}

/// The run handed its descriptors to a control master (T-039): the record
/// counts none of their bytes.
pub fn shared() {
    facts(|f| f.shared = true);
}

/// How a session through a control master ended: `shared` (the master told
/// the exit code alone: a status, or 128 + a signal), `no-status` or
/// `terminated`.
pub fn shared_ended(end: &'static str) {
    facts(|f| f.end = Some(end));
}

/// Why the run failed: the first cause said holds, but one that
/// [`failure_is`] puts in its place.
pub fn failed(class: &'static str) {
    facts(|f| {
        f.failure.get_or_insert(class);
    });
}

/// The cause of the failure, in place of any said before: the relay's own
/// close, as the lines of a failure name the relay first (T-024), or the
/// verdict of the end-to-end channel (T-088), which says more than the
/// session saw.
pub fn failure_is(class: &'static str) {
    facts(|f| f.failure = Some(class));
}

/// A new connection of the run: a try after a drop of the relay (T-025),
/// or one of `--persist`. What failed before it is no cause of the run's
/// end.
pub fn fresh() {
    facts(|f| f.failure = None);
}

/// A relay session that `host` opened: the last host, and one more
/// session of the run.
pub fn relay_host(host: &str) {
    facts(|f| {
        f.relay_host = Some(host.to_string());
        f.relay_sessions += 1;
    });
}

/// The destination's login: the version line that its server sent, and
/// the method that let the user in.
pub fn logged_in(version: Option<String>, method: &'static str) {
    facts(|f| {
        f.server_version = version;
        f.method = Some(method);
    });
}

/// The relay leg's end, as the relay stream recorded it.
pub fn relay_end(end: &RelayEnd) {
    facts(|f| {
        f.relay_close = Some(match end {
            RelayEnd::Closed { code, reason } => (*code, reason.clone()),
            RelayEnd::Failed(why) => (None, why.to_string()),
        });
    });
}

/// The record of the session that reads it, or the process's.
pub fn record() -> Record {
    with(Recorder::read)
}

/// The server's last words of a disconnect, taken.
pub(crate) fn take_said() -> Option<String> {
    with(|r| lock(&r.said).take())
}

/// The connection's last error, taken.
pub(crate) fn take_broke() -> Option<String> {
    with(|r| lock(&r.broke).take())
}

/// Whether the server's words or an error are kept, untaken.
pub(crate) fn cause_kept() -> bool {
    with(|r| lock(&r.said).is_some() || lock(&r.broke).is_some())
}

#[cfg(test)]
#[path = "outcome_tests.rs"]
mod tests;
