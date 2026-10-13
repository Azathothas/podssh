//! The login's signers of a security key (T-229): the key file's, which
//! signs in the device when the server took the key, and a wrapper of an
//! agent's, which says the touch that the agent's key waits for. russh
//! asks a signer only after the server's answer to the query, so a key that
//! the server does not take asks for no touch.

use std::sync::Arc;

use russh::keys::agent::AgentIdentity;
use russh::keys::HashAlg;

use super::SkKey;
use crate::log::Log;

/// Why a security key did not sign.
#[derive(Debug)]
pub(crate) struct SkError(pub String);

impl From<russh::SendError> for SkError {
    fn from(_: russh::SendError) -> Self {
        SkError("the session ended".into())
    }
}

impl std::fmt::Display for SkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The key of a key file of a security key, which signs in its device.
pub(crate) struct SkSigner {
    pub key: SkKey,
    pub log: Arc<Log>,
    /// The key as OpenSSH names it in the line of the touch: its type and
    /// fingerprint.
    pub shown: String,
    /// Whether the PIN may be asked: not under `BatchMode`.
    pub may_ask: bool,
}

impl russh::Signer for SkSigner {
    type Error = SkError;

    /// `to_sign`, then its signature as an agent gives it: the length, then
    /// the signature of SSH with the device's flags and counter. The device
    /// waits on a thread of its own.
    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, SkError> {
        let (key, log, shown, may_ask) = (self.key.clone(), self.log.clone(), self.shown.clone(), self.may_ask);
        let data = to_sign.clone();
        let blob = tokio::task::spawn_blocking(move || {
            if key.touch() {
                log.info(&format!("Confirm user presence for key {shown}"));
            }
            let say = |line: &str| log.info(line);
            super::sign_blob(&key, &data, &say, may_ask)
        })
        .await
        .map_err(|_| SkError("the thread of the security key failed".into()))?
        .map_err(SkError)?;
        to_sign.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        to_sign.extend_from_slice(&blob);
        Ok(to_sign)
    }
}

/// An agent's signer that first says `line`, once: the touch that an
/// agent's key of a security key waits for, when the signature is due.
pub(crate) struct Announced<'a, S> {
    pub inner: &'a mut S,
    pub log: &'a Log,
    pub line: Option<String>,
}

impl<S> russh::Signer for Announced<'_, S>
where
    S: russh::Signer + Send,
    S::Error: Send,
{
    type Error = S::Error;

    async fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        if let Some(line) = self.line.take() {
            self.log.info(&line);
        }
        self.inner.auth_sign(key, hash_alg, to_sign).await
    }
}
