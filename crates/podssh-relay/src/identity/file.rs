//! The key files of each end (T-163, T-087): one Ed25519 seed for each role,
//! a node's for each label and a client's for each user, in a private file
//! made when it is missing. Both roads read the same file, so a node has one
//! identity whichever road an operator takes.
//!
//! The file holds the 32 secret bytes in hex and a newline, as iroh parses a
//! secret key. It is checked as the cache checks a token (a regular file of
//! this user that nobody else can read, no symbolic link followed), but a
//! file that fails is refused with the reason, never replaced: a new key
//! would give the node a new identity, which each operator would have to
//! learn, and a pin would refuse.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::Identity;
use crate::cache::{self, Others};
use crate::session::Entropy;

/// Where a key is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// The file that the user named (`--key FILE`).
    File(PathBuf),
    /// The file of this name in the cache's directories: the first that has
    /// it, else the first that takes a new one. A file under the old name,
    /// when there is one, is the key, so that an identity made before stays.
    Cache { name: String, old: Option<String> },
    /// Nowhere: a key for this run only.
    Ephemeral,
}

/// The client's key file in the cache: one for each user, whichever node it
/// reaches, so that one line in each node's allowlist lets it in.
pub const CLIENT_FILE: &str = "client.key";
/// The client's key file of T-163, still read.
pub const OLD_CLIENT_FILE: &str = "iroh-client.key";

/// The node's key file in the cache for the label `label`.
pub fn node_file(label: &str) -> String {
    format!("node-{}.key", cache::safe_name(label))
}

/// The node's key file of T-163 for `label`, still read.
pub fn old_node_file(label: &str) -> String {
    format!("iroh-node-{}.key", cache::safe_name(label))
}

/// The place of a node's key for `label`, in the cache.
pub fn node_place(label: &str) -> Place {
    Place::Cache { name: node_file(label), old: Some(old_node_file(label)) }
}

/// The place of the client's key, in the cache.
pub fn client_place() -> Place {
    Place::Cache { name: CLIENT_FILE.to_string(), old: Some(OLD_CLIENT_FILE.to_string()) }
}

/// A key, where it is kept, and whether it was made by this call.
pub struct Key {
    pub identity: Identity,
    /// The file; `None` for an ephemeral key.
    pub path: Option<PathBuf>,
    /// Whether the key is new: a node's identity, and its ticket, changed.
    pub made: bool,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("public", &self.identity.public().fingerprint())
            .field("path", &self.path)
            .field("made", &self.made)
            .finish()
    }
}

/// The key kept at `place`, made when there is none.
pub fn load(place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
    load_in(&cache::candidate_dirs(), place, entropy)
}

/// [`load`], with `dirs` as the cache's directories (for tests).
pub fn load_in(dirs: &[PathBuf], place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
    match place {
        Place::Ephemeral => Ok(Key { identity: make(entropy)?, path: None, made: true }),
        Place::File(path) => {
            if let Some(identity) = read(path)? {
                return Ok(Key { identity, path: Some(path.clone()), made: false });
            }
            let identity = make(entropy)?;
            let made = cache::create_private(path, &body(&identity))
                .map_err(|e| format!("{}: could not make the key file: {e}", path.display()))?;
            settled(path.clone(), identity, made)
        }
        Place::Cache { name, old } => {
            // A file that is there and refused stops the search: a key made
            // in the next directory would be a new identity.
            for name in std::iter::once(name).chain(old) {
                for dir in dirs {
                    let path = dir.join(name);
                    if let Some(identity) = read(&path)? {
                        return Ok(Key { identity, path: Some(path), made: false });
                    }
                }
            }
            let identity = make(entropy)?;
            let (path, made) = cache::create_file_in_first(dirs, name, &body(&identity))?;
            settled(path, identity, made)
        }
    }
}

/// The key that was made, or, when another run made the file first, the one
/// in the file.
fn settled(path: PathBuf, identity: Identity, made: bool) -> Result<Key, String> {
    if made {
        return Ok(Key { identity, path: Some(path), made: true });
    }
    match read(&path)? {
        Some(theirs) => Ok(Key { identity: theirs, path: Some(path), made: false }),
        None => Err(format!("{}: the key file went away as it was made", path.display())),
    }
}

/// The key in the file at `path`; `None` when there is no file.
fn read(path: &Path) -> Result<Option<Identity>, String> {
    let Some(text) = cache::read_own(path, Others::NoAccess)? else { return Ok(None) };
    let text = Zeroizing::new(text);
    let word = text.trim();
    // The error names the file only: no part of a secret goes into a message.
    let bad = || format!("{}: not a key (64 hex digits); move it away and podssh makes a new one", path.display());
    if word.len() != 64 {
        return Err(bad());
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    for (i, pair) in word.as_bytes().chunks(2).enumerate() {
        let digit = |c: u8| (c as char).to_digit(16);
        let (Some(high), Some(low)) = (digit(pair[0]), digit(pair[1])) else { return Err(bad()) };
        seed[i] = (high * 16 + low) as u8;
    }
    Ok(Some(Identity::from_seed(&seed)))
}

/// A new key from the OS's random source; an error, not a panic, when the
/// source cannot be read.
fn make(entropy: &mut dyn Entropy) -> Result<Identity, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    entropy.fill(&mut seed[..]).map_err(|_| "the OS gave no random bytes for a new key".to_string())?;
    Ok(Identity::from_seed(&seed))
}

/// The file's text: the seed in lower-case hex and a newline.
fn body(identity: &Identity) -> Zeroizing<Vec<u8>> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let seed = identity.seed();
    let mut text = Zeroizing::new(Vec::with_capacity(65));
    for byte in seed.iter() {
        text.push(HEX[usize::from(byte >> 4)]);
        text.push(HEX[usize::from(byte & 0x0f)]);
    }
    text.push(b'\n');
    text
}
