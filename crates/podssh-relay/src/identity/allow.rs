//! Who may reach a node (T-163, T-087): the client keys in an allowlist
//! file, as sshd's `authorized_keys` gives access by key, on each road. The
//! file holds one key on each line, as its fingerprint (`SHA256:...`) or as
//! the key in iroh's hex or base32, then an optional comment; a line that
//! starts with `#` is a comment. A line that is not a key lets nobody in,
//! and is named. A word `routes=A,B` right after the key lets it use those
//! routes of the node (T-089), `routes=*` each one; a key with no such word
//! reaches the node's target that has no route, and no route.

use std::path::Path;

use super::{KeyName, PublicKey};
use crate::cache::{self, Others};

/// The keys of an allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    keys: Vec<Entry>,
    /// The numbers of the lines that hold no key, from 1.
    bad: Vec<usize>,
}

/// A key, and the routes that it may use.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    name: KeyName,
    routes: Vec<String>,
    /// `routes=*`: each route.
    all: bool,
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
            let mut words = line.split_whitespace();
            let name = KeyName::parse(words.next().unwrap_or_default());
            let routes = match words.next().and_then(|w| w.strip_prefix("routes=")) {
                None => Some((Vec::new(), false)),
                Some("*") => Some((Vec::new(), true)),
                Some(list) => {
                    let routes: Vec<String> = list.split(',').map(str::to_string).collect();
                    routes.iter().all(|r| podssh_ws::names::check_node_name(r).is_ok()).then_some((routes, false))
                }
            };
            match (name, routes) {
                (Some(name), Some((routes, all))) => match list.keys.iter_mut().find(|e| e.name == name) {
                    // A key on two lines has the routes of both.
                    Some(entry) => {
                        entry.routes.extend(routes);
                        entry.all |= all;
                    }
                    None => list.keys.push(Entry { name, routes, all }),
                },
                _ => list.bad.push(n + 1),
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
        self.keys.iter().any(|e| e.name.matches(key))
    }

    /// Whether `key` may use `route` of the node.
    pub fn grants(&self, key: &PublicKey, route: &str) -> bool {
        self.keys.iter().any(|e| e.name.matches(key) && (e.all || e.routes.iter().any(|r| r == route)))
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

/// Whether the client `key` may use `route` of the node, by the allowlist at
/// `path`, read again for each session (T-089).
pub fn grants(path: &Path, key: &PublicKey, route: &str) -> Result<(), String> {
    match Allowlist::read(path) {
        Ok(list) if list.grants(key, route) => Ok(()),
        Ok(_) => Err(format!("{} does not give it the route {route}", path.display())),
        Err(why) => Err(why),
    }
}
