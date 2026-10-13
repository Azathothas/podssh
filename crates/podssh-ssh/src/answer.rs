//! A limit on each answer of the server during the authentication: a server
//! that stalls after the key exchange must not hold podssh for ever. The
//! limit is `ConnectTimeout`. A prompt runs before its request, so a person
//! who types slowly never meets it; the time that the agent spends signing
//! (a person may confirm each signature, `ssh-add -c`) does not count either.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::agent::AgentIdentity;
use russh::keys::{Algorithm, HashAlg};
use tokio::time::Instant;

/// The message when `host` did not answer `what` within `limit`.
fn late(host: &str, what: &str, limit: Duration) -> String {
    format!("{host} did not answer {what} within {} s", limit.as_secs())
}

/// Wait for `call`, which waits for an answer of the server, at most `limit`.
pub(crate) async fn within<T>(
    limit: Duration,
    host: &str,
    what: &str,
    call: impl Future<Output = T>,
) -> Result<T, String> {
    tokio::time::timeout(limit, call).await.map_err(|_| late(host, what, limit))
}

/// The time that the agent spent signing, and since when it signs now.
#[derive(Default)]
pub(crate) struct AgentTime {
    since: Option<Instant>,
    spent: Duration,
}

/// An agent whose signing time is kept in an [`AgentTime`]. When the agent
/// fails to sign, `failed` keeps the reason, and russh gets a signature that
/// cannot verify: once the server took the key, russh waits for a signature
/// and drops each other request, so the server must refuse this one for the
/// login to go on with the next key (T-285).
pub(crate) struct Timed<'a, S> {
    pub inner: &'a mut S,
    pub time: Arc<Mutex<AgentTime>>,
    pub failed: Option<String>,
}

impl<S> russh::Signer for Timed<'_, S>
where
    S: russh::Signer + Send,
    S::Error: Send + std::fmt::Display,
{
    type Error = S::Error;

    async fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        let unsigned = to_sign.clone();
        self.time.lock().unwrap_or_else(|e| e.into_inner()).since = Some(Instant::now());
        let signed = self.inner.auth_sign(key, hash_alg, to_sign).await;
        let mut time = self.time.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(start) = time.since.take() {
            time.spent += start.elapsed();
        }
        match signed {
            Ok(data) => Ok(data),
            Err(e) => {
                self.failed = Some(e.to_string());
                Ok(unverifiable(unsigned, key, hash_alg))
            }
        }
    }
}

/// `to_sign`, then a signature of the key's algorithm that each server
/// decodes and none verifies: a server that cannot decode a signature may
/// close the session (russh's does). Ed25519: 64 bytes of zero; RSA: zeros
/// of the modulus's length; ECDSA: r and s of 1. A security key's carries
/// the flags and the counter after it (T-229).
fn unverifiable(mut to_sign: Vec<u8>, key: &AgentIdentity, hash: Option<HashAlg>) -> Vec<u8> {
    let public = key.public_key();
    let ecdsa = vec![0, 0, 0, 1, 1, 0, 0, 0, 1, 1];
    let (name, signature) = match public.algorithm() {
        Algorithm::Rsa { .. } => {
            let size = public.key_data().rsa().and_then(|k| k.n().as_positive_bytes()).map_or(256, <[u8]>::len);
            (Algorithm::Rsa { hash }.to_string(), vec![0u8; size])
        }
        algorithm @ (Algorithm::Ecdsa { .. } | Algorithm::SkEcdsaSha2NistP256) => (algorithm.to_string(), ecdsa),
        other => (other.to_string(), vec![0u8; 64]),
    };
    let trailer = crate::sk::is_sk(&public);
    let blob = 4 + name.len() + 4 + signature.len() + 5 * usize::from(trailer);
    to_sign.extend_from_slice(&(blob as u32).to_be_bytes());
    to_sign.extend_from_slice(&(name.len() as u32).to_be_bytes());
    to_sign.extend_from_slice(name.as_bytes());
    to_sign.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    to_sign.extend_from_slice(&signature);
    if trailer {
        to_sign.push(0x01);
        to_sign.extend_from_slice(&0u32.to_be_bytes());
    }
    to_sign
}

/// As [`within`], but the time in `time` (the agent's) does not count, and
/// the limit never ends a wait while the agent signs.
pub(crate) async fn within_signing<T>(
    limit: Duration,
    host: &str,
    what: &str,
    time: &Mutex<AgentTime>,
    call: impl Future<Output = T>,
) -> Result<T, String> {
    let start = Instant::now();
    tokio::pin!(call);
    loop {
        let (busy, spent) = {
            let t = time.lock().unwrap_or_else(|e| e.into_inner());
            (t.since.map(|s| s.elapsed()), t.spent)
        };
        let server = start.elapsed().saturating_sub(spent + busy.unwrap_or_default());
        if server >= limit && busy.is_none() {
            return Err(late(host, what, limit));
        }
        let wait = if busy.is_some() { limit } else { limit - server };
        tokio::select! {
            out = &mut call => return Ok(out),
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
#[path = "answer_tests.rs"]
mod tests;
