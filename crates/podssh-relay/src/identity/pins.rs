//! The node keys that an operator has met (T-087), kept as `known_hosts`
//! keeps host keys: one line for each key of a label, `LABEL KEY`, the key
//! as its fingerprint (or as the key itself), in the file `known-nodes` of
//! the cache's directories. The first sight of a label's node pins its key
//! (trust on first use, as the relay's contract asks of a connect token). A
//! key that matches no line of its label is refused, with the file, the line
//! and both fingerprints, and never replaced: only the user removes a line,
//! or adds the new key's.

use std::path::{Path, PathBuf};

use super::{KeyName, PublicKey};
use crate::cache::{self, Others};

/// The file's name in the cache's directories.
pub const FILE: &str = "known-nodes";

/// What the pins say of a node's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// A line of the label names the key.
    Known,
    /// The label had no line: the key is pinned now, in this file.
    Pinned(PathBuf),
    /// The label had no line, and none could be written: why. The session
    /// goes on, and the next one pins.
    NotPinned(String),
}

/// Why a node's key is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// The label's lines name other keys: the first one's fingerprint, the
    /// file and the line, from 1.
    Changed { pinned: String, path: PathBuf, line: usize },
    /// The pins cannot be read (another user's file, one that others can
    /// change, a line of the label that is not a key): the session is
    /// refused, as a pin that cannot be trusted checks nothing.
    Unreadable(String),
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::Changed { pinned, path, line } => {
                write!(f, "line {line} of {} pins {pinned}", path.display())
            }
            PinError::Unreadable(why) => f.write_str(why),
        }
    }
}

/// Check the key of the node of `label` against the pins, and pin it at the
/// first sight.
pub fn check(label: &str, key: &PublicKey) -> Result<Seen, PinError> {
    check_in(&cache::candidate_dirs(), label, key)
}

/// [`check`], with `dirs` as the cache's directories (for tests).
pub fn check_in(dirs: &[PathBuf], label: &str, key: &PublicKey) -> Result<Seen, PinError> {
    let found = find(dirs)?;
    if let Some((path, text)) = &found {
        let mut first: Option<(String, usize)> = None;
        for (n, line) in text.lines().enumerate() {
            let mut words = line.split_whitespace();
            if words.next() != Some(label) || line.trim_start().starts_with('#') {
                continue;
            }
            let Some(name) = words.next().and_then(KeyName::parse) else {
                return Err(PinError::Unreadable(format!(
                    "line {} of {} names the node {label} with no key",
                    n + 1,
                    path.display()
                )));
            };
            if name.matches(key) {
                return Ok(Seen::Known);
            }
            first.get_or_insert((name.fingerprint(), n + 1));
        }
        if let Some((pinned, line)) = first {
            return Err(PinError::Changed { pinned, path: path.clone(), line });
        }
    }
    Ok(pin(dirs, found, label, key))
}

/// The first of `dirs` that has the file, and its text.
fn find(dirs: &[PathBuf]) -> Result<Option<(PathBuf, String)>, PinError> {
    for dir in dirs {
        let path = dir.join(FILE);
        // Others may read the pins, which are public keys; nobody else may
        // change them, as a pin that another user wrote checks nothing.
        match cache::read_own(&path, Others::Read) {
            Ok(Some(text)) => return Ok(Some((path, text))),
            Ok(None) => {}
            Err(why) => return Err(PinError::Unreadable(why)),
        }
    }
    Ok(None)
}

/// Add the line of `label` to the file that was found, or make the file in
/// the first directory that takes it.
fn pin(dirs: &[PathBuf], found: Option<(PathBuf, String)>, label: &str, key: &PublicKey) -> Seen {
    if label.is_empty() || label.starts_with('#') || label.chars().any(char::is_whitespace) {
        return Seen::NotPinned(format!("the label {label:?} cannot be written as a line of {FILE}"));
    }
    let line = format!("{label} {}\n", key.fingerprint());
    let (place, text) = match found {
        Some((path, mut text)) => {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&line);
            (path.parent().map(Path::to_path_buf).into_iter().collect::<Vec<_>>(), text)
        }
        None => (dirs.to_vec(), line),
    };
    match cache::store_file_in_first(&place, FILE, text.as_bytes()) {
        Ok(path) => Seen::Pinned(path),
        Err(why) => Seen::NotPinned(why),
    }
}
