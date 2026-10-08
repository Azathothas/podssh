//! The tailnet auth key, as a secret: file/env only, never argv, never printed.
//!
//! ⛔ Modelled on `podssh-cli/src/security/token.rs`: the bytes are reachable
//! through [`AuthKey::expose`] and destroyed by [`AuthKey::expire`], and
//! `Debug` prints a fixed redaction. There is no `Display`.

use std::fmt;

/// An auth key whose bytes never reach a log, a usage string, or a `Debug` line.
pub struct AuthKey {
    bytes: Vec<u8>,
    expired: bool,
}

impl AuthKey {
    /// Wrap the key bytes. Empty input is refused: an empty key is a missing key.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, &'static str> {
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

    /// Zero the bytes. After this `expose` fails and the key is gone.
    pub fn expire(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
        self.bytes.clear();
        self.expired = true;
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthKey(REDACTED)")
    }
}
