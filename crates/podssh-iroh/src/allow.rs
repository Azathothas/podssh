//! Who may reach a node over the iroh road (T-163): the client keys of the
//! node's allowlist, the same file and the same reading on each road
//! (`podssh_relay::identity::allow`, T-087). A line holds a key's
//! fingerprint, or the key in iroh's hex or base32.

use std::path::Path;

use iroh::PublicKey;

/// The QUIC close code of a client whose key the node refuses.
pub const REFUSED: u32 = 403;
/// The reason that goes with [`REFUSED`]. It names no file of the node.
pub const REFUSED_REASON: &str = "this client's key is not in the node's allowlist";

/// The keys of an allowlist, asked with iroh's keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist(podssh_relay::identity::allow::Allowlist);

impl Allowlist {
    /// The keys of `text`.
    pub fn parse(text: &str) -> Allowlist {
        Allowlist(podssh_relay::identity::allow::Allowlist::parse(text))
    }

    /// The allowlist in the file at `path`; a missing file is an error, so the
    /// node says that nobody can get in.
    pub fn read(path: &Path) -> Result<Allowlist, String> {
        podssh_relay::identity::allow::Allowlist::read(path).map(Allowlist)
    }

    /// Whether `key` may get in.
    pub fn admits(&self, key: &PublicKey) -> bool {
        self.0.admits(&crate::keys::identity_key(key))
    }

    /// How many keys the list holds.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The numbers of the lines that are not a key, from 1.
    pub fn bad_lines(&self) -> &[usize] {
        self.0.bad_lines()
    }
}
