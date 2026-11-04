//! The key exchange group that each TLS server took, kept across runs
//! (T-664). podssh offers X25519 first; a server that takes P-256 alone, as a
//! proxy that re-signs TLS under FIPS rules may, answers that offer with a
//! HelloRetryRequest: a round trip more on each run's first connection.
//! rustls asks its store of sessions which group to offer first (the store
//! of `tls/store.rs`), so the group that a server took is kept in a private
//! file of the cache, and the next run offers it at once.
//!
//! A group is no secret and checks nothing: a server that changed its choice
//! asks again, as with no hint, and its new group is kept. The tickets, which
//! are secrets, stay in memory (T-444): rustls 0.23 gives a client no way to
//! write one (T-670).
//!
//! The file is text: the line [`HEADER`], then one line for each server,
//! `NAME GROUP AT_MS`. A file that does not read is set aside whole, said once
//! at `-v`, and made again by the next group taken.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// The first line of the file: its format.
pub const HEADER: &str = "podssh tls groups 1";
/// The servers kept; past it, the one that took its group longest ago goes.
pub const MOST: usize = 64;
/// A group taken longer ago than this is forgotten: a server's choice can
/// change, and a stale hint costs the retry that no hint costs.
pub const MAX_AGE_MS: i64 = 30 * 24 * 3600 * 1000;
/// The same group taken again within this is not written again: a run's
/// connections write the file once.
const REFRESH_MS: i64 = 24 * 3600 * 1000;
/// The longest name kept, as DNS's.
const NAME_MAX: usize = 253;

/// Where the file is kept. The private cache is podssh-relay's
/// (`podssh_relay::tls_groups`); this crate keeps no file of its own.
pub trait GroupFile: Send + Sync {
    /// The file's text; `None` when there is none, or it is not ours to read.
    fn load(&self) -> Option<String>;
    /// Keep `text`. A failure costs a later run its hint, nothing else.
    fn store(&self, text: &[u8]);
}

/// Each server's group, by its name, with when it was taken.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Groups {
    /// The name, lower case with no final dot: the group's number in TLS's
    /// registry, and the time in milliseconds since the epoch.
    pub servers: BTreeMap<String, (u16, i64)>,
}

impl Groups {
    /// The groups of `text` taken within [`MAX_AGE_MS`] of `now_ms`, at most
    /// [`MOST`]. A text that does not read is refused whole, with why: a file
    /// half understood would keep what the rest says otherwise.
    pub fn read(text: &str, now_ms: i64) -> Result<Groups, String> {
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err("its first line is not podssh's".into());
        }
        let mut groups = Groups::default();
        for (at, line) in lines.enumerate() {
            let number = at + 2;
            let fields: Vec<&str> = line.split(' ').collect();
            let [name, group, taken] = fields[..] else {
                return Err(format!("line {number} does not hold a name, a group and a time"));
            };
            let group: u16 = group.parse().map_err(|_| format!("line {number} holds no group"))?;
            let taken: i64 = taken.parse().map_err(|_| format!("line {number} holds no time"))?;
            if !valid_name(name) {
                return Err(format!("line {number} holds no server's name"));
            }
            if now_ms.saturating_sub(taken) < MAX_AGE_MS {
                groups.servers.insert(name.to_string(), (group, taken));
            }
        }
        groups.bound();
        Ok(groups)
    }

    /// The file's text.
    pub fn text(&self) -> String {
        let mut text = format!("{HEADER}\n");
        for (name, (group, taken)) in &self.servers {
            text.push_str(&format!("{name} {group} {taken}\n"));
        }
        text
    }

    /// The group that `name` took last.
    pub fn group(&self, name: &str) -> Option<u16> {
        self.servers.get(&key(name)).map(|(group, _)| *group)
    }

    /// `name` took `group` at `now_ms`. Whether the file is worth writing: a
    /// new server or group, or the same one taken a day or more ago.
    pub fn took(&mut self, name: &str, group: u16, now_ms: i64) -> bool {
        let name = key(name);
        if !valid_name(&name) {
            return false;
        }
        let recent = |(kept, taken): &(u16, i64)| *kept == group && *taken <= now_ms && now_ms - taken < REFRESH_MS;
        if self.servers.get(&name).is_some_and(recent) {
            return false;
        }
        self.servers.insert(name, (group, now_ms));
        self.bound();
        true
    }

    /// At most [`MOST`]: the server that took its group longest ago goes.
    fn bound(&mut self) {
        while self.servers.len() > MOST {
            let Some(oldest) = self.servers.iter().min_by_key(|(_, (_, taken))| *taken).map(|(n, _)| n.clone()) else {
                break;
            };
            self.servers.remove(&oldest);
        }
    }
}

/// A name as the file keeps it: lower case, no final dot.
fn key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// A name that a line can hold: a DNS name or an address, nothing that
/// would split a line or a field.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':' | b'_'))
}

/// The groups of a process, read from their file at the first use after the
/// file is given, and written when a server took another group.
pub struct Kept {
    file: OnceLock<Box<dyn GroupFile>>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    groups: Groups,
    read: bool,
    /// Why the file was set aside, until a run says it.
    note: Option<String>,
}

impl std::fmt::Debug for Kept {
    // The count only, as a store of sessions shows nothing it holds.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let servers = self.lock().groups.servers.len();
        f.debug_struct("Kept").field("servers", &servers).field("file", &self.file.get().is_some()).finish()
    }
}

impl Default for Kept {
    fn default() -> Self {
        Kept::new()
    }
}

impl Kept {
    /// Groups with no file yet: a hint lives as long as the process.
    pub fn new() -> Kept {
        Kept { file: OnceLock::new(), state: Mutex::new(State::default()) }
    }

    /// Keep the groups in `file` from now on. `false` when a file was given
    /// before, which stays.
    pub fn keep_in(&self, file: Box<dyn GroupFile>) -> bool {
        self.file.set(file).is_ok()
    }

    /// The group that `name` took last, in this process or a run before.
    pub fn group(&self, name: &str) -> Option<u16> {
        self.read().groups.group(name)
    }

    /// `name` took `group`: kept, and the file written when it changed.
    pub fn took(&self, name: &str, group: u16) {
        let mut state = self.read();
        if state.groups.took(name, group, now_ms()) {
            if let Some(file) = self.file.get() {
                file.store(state.groups.text().as_bytes());
            }
        }
    }

    /// Why the file was set aside, once: a run says it at `-v`.
    pub fn take_note(&self) -> Option<String> {
        self.lock().note.take()
    }

    /// The state, with the file read once it is given.
    fn read(&self) -> MutexGuard<'_, State> {
        let mut state = self.lock();
        if state.read {
            return state;
        }
        let Some(file) = self.file.get() else { return state };
        state.read = true;
        if let Some(text) = file.load() {
            match Groups::read(&text, now_ms()) {
                // A group taken in this process before the file came wins.
                Ok(groups) => {
                    for (name, kept) in groups.servers {
                        state.groups.servers.entry(name).or_insert(kept);
                    }
                    state.groups.bound();
                }
                Err(why) => {
                    state.note = Some(format!("the cache of the TLS groups that servers took was set aside: {why}"))
                }
            }
        }
        state
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The process's groups, which each of podssh's own TLS configurations
/// shares ([`super::client_config`]).
pub fn process() -> Arc<Kept> {
    static PROCESS: OnceLock<Arc<Kept>> = OnceLock::new();
    PROCESS.get_or_init(|| Arc::new(Kept::new())).clone()
}

/// Keep the process's groups in `file`, once a run (`podssh_relay::tls_groups`).
pub fn keep_in(file: Box<dyn GroupFile>) -> bool {
    process().keep_in(file)
}

/// Why the process's file was set aside, once.
pub fn take_note() -> Option<String> {
    process().take_note()
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
#[path = "groups_tests.rs"]
mod tests;
