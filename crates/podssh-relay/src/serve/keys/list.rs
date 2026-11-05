//! Where the relay role reads its list of keys (T-646, GitHub #144): a file
//! of its host, read again for each request (T-448); or the copy of a list
//! that an `https://` URL serves, fetched before the role takes a
//! connection and again each TTL, and read in the request's path with no
//! wait, so that a role in an image with no writable volume changes whom it
//! mints for with no rebuild. A copy older than its TTL and its stale window
//! lets no one mint, as a file that cannot be read does; a fetch that fails
//! leaves the copy to age; an answer of the server's is the list, whatever
//! it holds. The fetch is the binary's ([`Fetch`]): this library holds the
//! copy and its clock.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::identity::allow::Allowlist;
use crate::serve::brake::Clock;

/// How often a list of a URL is fetched again, by default.
pub const TTL: Duration = Duration::from_secs(300);
/// How long past its TTL a copy is read, by default, while its server fails.
pub const STALE: Duration = Duration::from_secs(3600);

/// A fetch's answer: the body of a `200`, or why none came.
pub type Fetching<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;
/// Where the copy says its lines.
pub type Say = Arc<dyn Fn(&str) + Send + Sync>;

/// A list's server: the binary's HTTPS client, or a test's.
pub trait Fetch: Send + Sync {
    /// The body of an answer `200`; `Err` with why none came, in words that
    /// name no part of the URL but its host.
    fn fetch(&self) -> Fetching<'_>;
    /// The list's place, by its host alone: `https://HOST/...`.
    fn shown(&self) -> String;
}

/// A role's list of keys.
#[derive(Clone)]
pub enum List {
    /// A file of its host, read again for each request.
    File(PathBuf),
    /// The copy of a URL's list.
    Fetched(Arc<Fetched>),
}

impl List {
    /// The list now, with no wait; `Err` with why there is none to read,
    /// which the role keeps for its owner.
    pub fn read(&self) -> Result<Allowlist, String> {
        match self {
            List::File(path) => Allowlist::read(path),
            List::Fetched(copy) => {
                // A role whose binary did not start the fetches still gets them.
                copy.start(None);
                copy.read()
            }
        }
    }

    /// Its place, in the role's lines.
    pub fn shown(&self) -> String {
        match self {
            List::File(path) => path.display().to_string(),
            List::Fetched(copy) => copy.shown(),
        }
    }

    /// The copy of a URL's list, when it is one.
    pub fn fetched(&self) -> Option<&Arc<Fetched>> {
        match self {
            List::File(_) => None,
            List::Fetched(copy) => Some(copy),
        }
    }
}

impl From<PathBuf> for List {
    fn from(path: PathBuf) -> List {
        List::File(path)
    }
}

impl std::fmt::Debug for List {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            List::File(path) => f.debug_tuple("File").field(path).finish(),
            // Its host alone: the URL's path may hold a secret of its server.
            List::Fetched(copy) => f.debug_tuple("Fetched").field(&copy.shown()).finish(),
        }
    }
}

/// The list as it came, and when, in ms since the epoch.
struct Held {
    list: Allowlist,
    at: u64,
}

/// The copy of a list that a URL serves.
pub struct Fetched {
    from: Box<dyn Fetch>,
    ttl: Duration,
    stale: Duration,
    clock: Clock,
    copy: Mutex<Option<Held>>,
    started: AtomicBool,
    say: Mutex<Option<Say>>,
}

fn lock<T>(held: &Mutex<T>) -> MutexGuard<'_, T> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

fn ms(span: Duration) -> u64 {
    u64::try_from(span.as_millis()).unwrap_or(u64::MAX)
}

impl Fetched {
    /// The copy of `from`'s list, fetched each `ttl`, and read for `stale`
    /// past it while its server fails; none until its first fetch.
    pub fn new(from: Box<dyn Fetch>, ttl: Duration, stale: Duration) -> Fetched {
        Fetched::on_clock(from, ttl, stale, Arc::new(crate::serve::tokens::now_ms))
    }

    /// [`Fetched::new`] on `clock`, in ms since the epoch: a test's.
    pub fn on_clock(from: Box<dyn Fetch>, ttl: Duration, stale: Duration, clock: Clock) -> Fetched {
        let (copy, started, say) = (Mutex::new(None), AtomicBool::new(false), Mutex::new(None));
        Fetched { from, ttl, stale, clock, copy, started, say }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn stale(&self) -> Duration {
        self.stale
    }

    pub fn shown(&self) -> String {
        self.from.shown()
    }

    /// The list now, with no wait: `Err` with why there is none to read, a
    /// copy that never came or one past its TTL and its stale window.
    pub fn read(&self) -> Result<Allowlist, String> {
        let now = (self.clock)();
        match lock(&self.copy).as_ref() {
            None => Err(format!("{}: no copy of the list has come", self.shown())),
            Some(copy) if now >= copy.at.saturating_add(ms(self.ttl.saturating_add(self.stale))) => {
                let age = now.saturating_sub(copy.at) / 1000;
                Err(format!("{}: its copy of {age} s ago is past its TTL and its stale window", self.shown()))
            }
            Some(copy) => Ok(copy.list.clone()),
        }
    }

    /// Take what a fetch gave at `now`: an answer is the list, whatever it
    /// holds, and a body that is no text holds no key; a failure leaves the
    /// copy to age. The new list, or why none came.
    pub fn put(&self, fetched: Result<Vec<u8>, String>, now: u64) -> Result<Allowlist, String> {
        let list = match String::from_utf8(fetched?) {
            Ok(text) => Allowlist::parse(&text),
            Err(_) => Allowlist::default(),
        };
        *lock(&self.copy) = Some(Held { list: list.clone(), at: now });
        Ok(list)
    }

    /// Fetch the list once, now.
    pub async fn refresh(&self) -> Result<Allowlist, String> {
        let fetched = self.from.fetch().await;
        self.put(fetched, (self.clock)())
    }

    /// Fetch it again each TTL in the runtime of the caller, for as long as
    /// that runs, once for each copy; `say`, when given, hears each line of
    /// it. Outside a runtime it starts nothing, and the next call tries.
    pub fn start(self: &Arc<Self>, say: Option<Say>) {
        if let Some(say) = say {
            *lock(&self.say) = Some(say);
        }
        // Each request reads it: the first look takes no lock.
        if self.started.load(Ordering::SeqCst) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        runtime.spawn(Arc::clone(self).keep());
    }

    fn say(&self, line: &str) {
        let say = lock(&self.say).clone();
        if let Some(say) = say {
            say(line);
        }
    }

    /// The fetches after the first: a line for a fetch that fails, with what
    /// the copy holds then, the first that works after it, a count of keys
    /// that moved, and an answer that holds no key.
    async fn keep(self: Arc<Self>) {
        let (mut failing, mut keys) = (false, self.read().ok().map(|list| list.len()));
        loop {
            tokio::time::sleep(self.ttl).await;
            match self.refresh().await {
                Ok(list) => {
                    let shown = self.shown();
                    match (failing, keys) {
                        (true, _) => self.say(&format!("{shown}: fetched again, {}", count(list.len()))),
                        (false, Some(before)) if before != list.len() => {
                            self.say(&format!("{shown}: {} now, {} before", count(list.len()), count(before)))
                        }
                        _ => {}
                    }
                    if list.is_empty() && !list.bad_lines().is_empty() {
                        self.say(&format!("{shown}: its answer holds no key, so no key mints"));
                    }
                    (failing, keys) = (false, Some(list.len()));
                }
                Err(why) => {
                    let holds = match self.read() {
                        Ok(_) => "its copy is read until its stale window passes",
                        Err(_) => "no copy is read, so no key mints until a fetch works",
                    };
                    self.say(&format!("{}: {why}; {holds}", self.shown()));
                    failing = true;
                }
            }
        }
    }
}

/// A count of keys, in the role's words.
pub fn count(keys: usize) -> String {
    match keys {
        1 => "1 key".to_string(),
        n => format!("{n} keys"),
    }
}

#[cfg(test)]
#[path = "list_tests.rs"]
mod tests;
