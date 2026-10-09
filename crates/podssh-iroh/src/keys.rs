//! The keys of the iroh road (T-163): one Ed25519 secret key for each role,
//! a node's and a client's, in a private file made when it is missing. A key
//! is shown by its public half, never by its secret.
//!
//! The file holds the 32 secret bytes in hex and a newline, as iroh parses a
//! secret key. It is checked as the cache checks a token (a regular file of
//! this user that nobody else can read, no symbolic link followed), but a
//! file that fails is refused with the reason, never replaced: a new key
//! would give the node a new ticket, and each client would have to learn it.

use std::path::{Path, PathBuf};

use iroh::{PublicKey, SecretKey};
use podssh_relay::cache::{self, Others};
use podssh_relay::session::Entropy;
use zeroize::Zeroizing;

/// Where a key is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// The file that the user named (`--iroh-key FILE`).
    File(PathBuf),
    /// The file of this name in the cache's directories: the first that has
    /// it, else the first that takes a new one.
    Cache(String),
    /// Nowhere: a key for this run only.
    Ephemeral,
}

/// The client's key file in the cache: one for each user, whichever node it
/// dials, so that one line in each node's allowlist lets it in.
pub const CLIENT_FILE: &str = "iroh-client.key";

/// The node's key file in the cache for the label `label`.
pub fn node_file(label: &str) -> String {
    format!("iroh-node-{}.key", cache::safe_name(label))
}

/// A key, where it is kept, and whether it was made by this call.
pub struct Key {
    pub secret: SecretKey,
    /// The file; `None` for an ephemeral key.
    pub path: Option<PathBuf>,
    /// Whether the key is new: a node's ticket then changed.
    pub made: bool,
}

impl Key {
    pub fn public(&self) -> PublicKey {
        self.secret.public()
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("public", &fingerprint(&self.public()))
            .field("path", &self.path)
            .field("made", &self.made)
            .finish()
    }
}

/// How a key is shown: its public key in iroh's hex, which is not secret, is
/// short, and is what an allowlist takes.
pub fn fingerprint(public: &PublicKey) -> String {
    public.to_string()
}

/// The key kept at `place`, made when there is none.
pub fn load(place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
    load_in(&cache::candidate_dirs(), place, entropy)
}

/// [`load`], with `dirs` as the cache's directories (for tests).
pub fn load_in(dirs: &[PathBuf], place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
    match place {
        Place::Ephemeral => Ok(Key { secret: make(entropy)?, path: None, made: true }),
        Place::File(path) => {
            if let Some(secret) = read(path)? {
                return Ok(Key { secret, path: Some(path.clone()), made: false });
            }
            let secret = make(entropy)?;
            let made = cache::create_private(path, &body(&secret))
                .map_err(|e| format!("{}: could not make the key file: {e}", path.display()))?;
            settled(path.clone(), secret, made)
        }
        Place::Cache(name) => {
            // A file that is there and refused stops the search: a key made
            // in the next directory would be a new identity.
            for dir in dirs {
                let path = dir.join(name);
                if let Some(secret) = read(&path)? {
                    return Ok(Key { secret, path: Some(path), made: false });
                }
            }
            let secret = make(entropy)?;
            let (path, made) = cache::create_file_in_first(dirs, name, &body(&secret))?;
            settled(path, secret, made)
        }
    }
}

/// The key that was made, or, when another run made the file first, the one
/// in the file.
fn settled(path: PathBuf, secret: SecretKey, made: bool) -> Result<Key, String> {
    if made {
        return Ok(Key { secret, path: Some(path), made: true });
    }
    match read(&path)? {
        Some(theirs) => Ok(Key { secret: theirs, path: Some(path), made: false }),
        None => Err(format!("{}: the key file went away as it was made", path.display())),
    }
}

/// The secret key in the file at `path`; `None` when there is no file.
fn read(path: &Path) -> Result<Option<SecretKey>, String> {
    let Some(text) = cache::read_own(path, Others::NoAccess)? else { return Ok(None) };
    let text = Zeroizing::new(text);
    let word = text.trim();
    // The error of iroh's parser holds no part of the text.
    word.parse::<SecretKey>().map(Some).map_err(|_| {
        format!("{}: not an iroh secret key (64 hex digits); move it away and podssh makes a new one", path.display())
    })
}

/// A new key from the OS's random source; an error, not a panic, when the
/// source cannot be read.
fn make(entropy: &mut dyn Entropy) -> Result<SecretKey, String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    entropy.fill(&mut bytes[..]).map_err(|_| "the OS gave no random bytes for a new key".to_string())?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// The file's text: the secret in lower-case hex and a newline.
fn body(secret: &SecretKey) -> Zeroizing<Vec<u8>> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = Zeroizing::new(secret.to_bytes());
    let mut text = Zeroizing::new(Vec::with_capacity(65));
    for byte in bytes.iter() {
        text.push(HEX[usize::from(byte >> 4)]);
        text.push(HEX[usize::from(byte & 0x0f)]);
    }
    text.push(b'\n');
    text
}
