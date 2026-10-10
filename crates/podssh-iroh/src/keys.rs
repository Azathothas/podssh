//! The keys of the iroh road (T-163): the identities of T-087, one Ed25519
//! key for each role, which `podssh-relay` keeps in private files
//! (`podssh_relay::identity::file`), as iroh's secret keys. The pair's road
//! proves the same key in its channel, so a node has one identity on both
//! roads. A key is shown by its fingerprint, never by its secret.

use iroh::{PublicKey, SecretKey};
use podssh_relay::identity::{self, file, Identity};
use podssh_relay::session::Entropy;

pub use podssh_relay::identity::file::{
    client_place, node_file, node_place, old_node_file, Place, CLIENT_FILE, OLD_CLIENT_FILE,
};

/// A key, as iroh takes it and as the channel proves it, where it is kept,
/// and whether it was made by this call.
pub struct Key {
    pub secret: SecretKey,
    pub identity: Identity,
    /// The file; `None` for an ephemeral key.
    pub path: Option<std::path::PathBuf>,
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

/// The identity key that an iroh key is: the same 32 bytes of Ed25519.
pub fn identity_key(public: &PublicKey) -> identity::PublicKey {
    identity::PublicKey(*public.as_bytes())
}

/// A node's name in a destination and in the known hosts (`iroh:` and this):
/// its key in iroh's hex, as T-163 wrote it there, so that a host key kept
/// under the name is still found. A name, not how a key is shown.
pub fn name(public: &PublicKey) -> String {
    public.to_string()
}

/// How a key is shown: its SHA256 fingerprint, as on the pair's road (T-087).
/// It is not secret, and an allowlist takes it, as it takes the key.
pub fn fingerprint(public: &PublicKey) -> String {
    identity_key(public).fingerprint()
}

/// The key kept at `place`, made when there is none.
pub fn load(place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
    file::load(place, entropy).map(as_iroh)
}

/// [`load`], with `dirs` as the cache's directories (for tests).
pub fn load_in(dirs: &[std::path::PathBuf], place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
    file::load_in(dirs, place, entropy).map(as_iroh)
}

fn as_iroh(key: file::Key) -> Key {
    let secret = SecretKey::from_bytes(&key.identity.seed());
    Key { secret, identity: key.identity, path: key.path, made: key.made }
}
