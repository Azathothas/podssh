//! Who may reach a node (T-163, T-087): the client keys in an allowlist
//! file, as sshd's `authorized_keys` gives access by key, on each road. The
//! file holds one key on each line, as its fingerprint (`SHA256:...`) or as
//! the key in iroh's hex or base32, then an optional comment; a line that
//! starts with `#` is a comment. A line that is not a key lets nobody in,
//! and is named.

use std::path::Path;

use super::{KeyName, PublicKey};
use crate::cache::{self, Others};

/// The keys of an allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    names: Vec<KeyName>,
    /// The numbers of the lines that hold no key, from 1.
    bad: Vec<usize>,
}

impl Allowlist {
    /// The keys of `text`.
    pub fn parse(text: &str) -> Allowlist {
        let mut list = Allowlist::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let word = line.split_whitespace().next().unwrap_or_default();
            match KeyName::parse(word) {
                Some(name) if !list.names.contains(&name) => list.names.push(name),
                Some(_) => {}
                None => list.bad.push(n + 1),
            }
        }
        list
    }

    /// The allowlist in the file at `path`: a file of this user that others
    /// cannot change, as sshd reads `authorized_keys`; others may read it, as
    /// it holds public keys only. A missing file is an error, so the node
    /// says that nobody can get in.
    pub fn read(path: &Path) -> Result<Allowlist, String> {
        match cache::read_own(path, Others::Read)? {
            Some(text) => Ok(Allowlist::parse(&text)),
            None => Err(format!("{}: no such file", path.display())),
        }
    }

    /// Whether `key` may get in.
    pub fn admits(&self, key: &PublicKey) -> bool {
        self.names.iter().any(|name| name.matches(key))
    }

    /// How many keys the list holds.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The numbers of the lines that are not a key, from 1.
    pub fn bad_lines(&self) -> &[usize] {
        &self.bad
    }
}

/// Whether the client `key` may connect, by the allowlist at `path`, read
/// again for each connection so that a key added counts at once, and a key
/// taken away at the next session. `Err` is why not, for the node's log;
/// the client learns only that its key is not let in.
pub fn admits(path: &Path, key: &PublicKey) -> Result<(), String> {
    match Allowlist::read(path) {
        Ok(list) if list.admits(key) => Ok(()),
        Ok(_) => Err(format!("it is not in {}", path.display())),
        Err(why) => Err(why),
    }
}
