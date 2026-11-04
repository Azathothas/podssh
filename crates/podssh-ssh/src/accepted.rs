//! The key that each host took last, kept across runs (T-664): the next login
//! sends that key's signature in its first request, with no `none` and no
//! query before it (RFC 4252, sections 5.2 and 7), two round trips fewer.
//!
//! A host is known by its host key with the user, through a hash, so the file
//! names no host and no user; a key by its fingerprint, which the key files
//! give again. Neither is a secret: the file holds no key and no signature.
//! The caller keeps it in the private cache (podssh-cli, mode 0600), as a
//! [`KeptFile`]; with none, nothing is kept and each login asks first.
//!
//! The file is text: the line [`HEADER`], then one line for each host,
//! `HOST KEY AT_MS`. A file that does not read is set aside whole, said at
//! `-v`, and made again by the next key taken.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// The file's name in the cache.
pub const FILE: &str = "accepted-keys.txt";
/// The first line of the file: its format.
pub const HEADER: &str = "podssh accepted keys 1";
/// The hosts kept; past it, the one that took its key longest ago goes.
pub const MOST: usize = 128;
/// A key taken longer ago than this is forgotten: a wrong guess costs a
/// refused attempt, which counts against the server's limit of attempts.
pub const MAX_AGE_MS: i64 = 90 * 24 * 3600 * 1000;
/// The same key taken again within this is not written again.
const REFRESH_MS: i64 = 24 * 3600 * 1000;

/// Where the file is kept: the caller's private cache.
pub trait KeptFile: Send + Sync {
    /// The file's text; `None` when there is none, or it is not ours to read.
    fn load(&self) -> Option<String>;
    /// Keep `text`. A failure costs a later login its round trips, nothing
    /// else.
    fn store(&self, text: &[u8]);
}

/// Each host's key, with when the host took it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Accepted {
    /// The host's id ([`host_id`]): the key's fingerprint, and the time in
    /// milliseconds since the epoch.
    pub hosts: BTreeMap<String, (String, i64)>,
}

impl Accepted {
    /// The keys of `text` taken within [`MAX_AGE_MS`] of `now_ms`, at most
    /// [`MOST`]. A text that does not read is refused whole, with why.
    pub fn read(text: &str, now_ms: i64) -> Result<Accepted, String> {
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err("its first line is not podssh's".into());
        }
        let mut accepted = Accepted::default();
        for (at, line) in lines.enumerate() {
            let number = at + 2;
            let fields: Vec<&str> = line.split(' ').collect();
            let [host, key, taken] = fields[..] else {
                return Err(format!("line {number} does not hold a host, a key and a time"));
            };
            let taken: i64 = taken.parse().map_err(|_| format!("line {number} holds no time"))?;
            if !valid_host(host) || !valid_key(key) {
                return Err(format!("line {number} holds no host's id or no key's fingerprint"));
            }
            if now_ms.saturating_sub(taken) < MAX_AGE_MS {
                accepted.hosts.insert(host.to_string(), (key.to_string(), taken));
            }
        }
        accepted.bound();
        Ok(accepted)
    }

    /// The file's text.
    pub fn text(&self) -> String {
        let mut text = format!("{HEADER}\n");
        for (host, (key, taken)) in &self.hosts {
            text.push_str(&format!("{host} {key} {taken}\n"));
        }
        text
    }

    /// The fingerprint of the key that `host` took last.
    pub fn key(&self, host: &str) -> Option<&str> {
        self.hosts.get(host).map(|(key, _)| key.as_str())
    }

    /// `host` took `key` at `now_ms`. Whether the file is worth writing: a
    /// new host or key, or the same one taken a day or more ago.
    pub fn took(&mut self, host: &str, key: &str, now_ms: i64) -> bool {
        if !valid_host(host) || !valid_key(key) {
            return false;
        }
        let recent = |(kept, taken): &(String, i64)| kept == key && *taken <= now_ms && now_ms - taken < REFRESH_MS;
        if self.hosts.get(host).is_some_and(recent) {
            return false;
        }
        self.hosts.insert(host.to_string(), (key.to_string(), now_ms));
        self.bound();
        true
    }

    /// `host` no longer took its key. Whether the record changed.
    pub fn forget(&mut self, host: &str) -> bool {
        self.hosts.remove(host).is_some()
    }

    /// At most [`MOST`]: the host that took its key longest ago goes.
    fn bound(&mut self) {
        while self.hosts.len() > MOST {
            let Some(oldest) = self.hosts.iter().min_by_key(|(_, (_, taken))| *taken).map(|(h, _)| h.clone()) else {
                break;
            };
            self.hosts.remove(&oldest);
        }
    }
}

/// A host's id in the file: SHA-256 of the user and of the host key's blob,
/// as the key exchange gave it, in hex. Each is framed with its length, so
/// that no two pairs give one input.
pub fn host_id(user: &str, host_key: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"podssh accepted key\0");
    for part in [user.as_bytes(), host_key] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn valid_host(host: &str) -> bool {
    host.len() == 64 && host.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `SHA256:` and unpadded base64, as `ssh-keygen -l` prints it.
fn valid_key(key: &str) -> bool {
    key.strip_prefix("SHA256:").is_some_and(|rest| {
        !rest.is_empty()
            && rest.len() <= 64
            && rest.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
    })
}

static KEPT: OnceLock<Box<dyn KeptFile>> = OnceLock::new();

/// Keep the keys that hosts took in `file`, once a run. `false` when a file
/// was given before, which stays.
pub fn keep_in(file: Box<dyn KeptFile>) -> bool {
    KEPT.set(file).is_ok()
}

/// The file's record now: empty with no file; `Err` with why a file that did
/// not read was set aside.
fn record() -> Result<Accepted, String> {
    let Some(text) = KEPT.get().and_then(|file| file.load()) else { return Ok(Accepted::default()) };
    Accepted::read(&text, now_ms()).map_err(|why| format!("the cache of the keys that hosts took was set aside: {why}"))
}

/// The fingerprint of the key that the host `id` took last; `Err` says at
/// `-v` why the file was set aside.
pub fn last(id: &str) -> Result<Option<String>, String> {
    Ok(record()?.key(id).map(str::to_string))
}

/// The host `id` took the key of `fingerprint`.
pub fn took(id: &str, fingerprint: &str) {
    let Some(file) = KEPT.get() else { return };
    // A file set aside is made again.
    let mut kept = record().unwrap_or_default();
    if kept.took(id, fingerprint, now_ms()) {
        file.store(kept.text().as_bytes());
    }
}

/// The host `id` refused the key that it took last: forgotten, so that the
/// next login asks first.
pub fn refused(id: &str) {
    let Some(file) = KEPT.get() else { return };
    let mut kept = record().unwrap_or_default();
    if kept.forget(id) {
        file.store(kept.text().as_bytes());
    }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
#[path = "accepted_tests.rs"]
mod tests;
