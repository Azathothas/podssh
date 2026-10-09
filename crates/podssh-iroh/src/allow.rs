//! Who may reach a node over the iroh road (T-163): the client keys in an
//! allowlist file, as sshd's `authorized_keys` gives access by key. The
//! file holds one key on each line, in iroh's hex (or base32), then an
//! optional comment; a line that starts with `#` is a comment. A line that
//! is not a key lets nobody in, and is named.

use std::collections::HashSet;
use std::path::Path;

use iroh::PublicKey;
use podssh_relay::cache::{self, Others};

/// The QUIC close code of a client whose key the node refuses.
pub const REFUSED: u32 = 403;
/// The reason that goes with [`REFUSED`]. It names no file of the node.
pub const REFUSED_REASON: &str = "this client's key is not in the node's allowlist";

/// The keys of an allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    keys: HashSet<PublicKey>,
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
            match word.parse::<PublicKey>() {
                Ok(key) => {
                    list.keys.insert(key);
                }
                Err(_) => list.bad.push(n + 1),
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
        self.keys.contains(key)
    }

    /// How many keys the list holds.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The numbers of the lines that are not a key, from 1.
    pub fn bad_lines(&self) -> &[usize] {
        &self.bad
    }
}
