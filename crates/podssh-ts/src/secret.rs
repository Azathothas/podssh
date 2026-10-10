//! The tailnet auth key, as a secret: file/env only, never argv, never printed.
//!
//! Held as the relay token is (`podssh-relay`'s `token.rs`): the bytes are
//! reachable through [`AuthKey::expose`], cleared by [`AuthKey::expire`] and
//! when the key is dropped, with writes that the compiler keeps (`zeroize`),
//! and `Debug` prints a fixed redaction. There is no `Display`.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An auth key whose bytes never reach a log, a usage string, or a `Debug` line.
pub struct AuthKey {
    bytes: Zeroizing<Vec<u8>>,
    expired: bool,
}

impl AuthKey {
    /// Wrap the key bytes, with no copy of a `Zeroizing` buffer. Empty input
    /// is refused: an empty key is a missing key.
    pub fn new(secret: impl Into<Zeroizing<Vec<u8>>>) -> Result<Self, &'static str> {
        let bytes = secret.into();
        if bytes.is_empty() {
            return Err("empty auth key");
        }
        Ok(Self { bytes, expired: false })
    }

    /// Borrow the bytes to hand to `Device::new`. Fails after `expire`.
    pub fn expose(&self) -> Result<&[u8], &'static str> {
        if self.expired {
            return Err("auth key already expired");
        }
        Ok(&self.bytes)
    }

    /// Clear the bytes. After this `expose` fails and the key is gone.
    pub fn expire(&mut self) {
        self.bytes.zeroize();
        self.expired = true;
    }
}

impl Drop for AuthKey {
    fn drop(&mut self) {
        self.expire();
    }
}

/// The bytes are cleared when the key is dropped.
impl ZeroizeOnDrop for AuthKey {}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthKey(REDACTED)")
    }
}
