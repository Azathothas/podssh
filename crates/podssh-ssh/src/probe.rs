//! Fetching a server's host key without logging in: the key exchange runs, the
//! key is recorded, and the connection is refused at the host-key check. Used
//! by `podssh doctor` to identify a server by equality with a published
//! fingerprint, never by the shape of its banner. [`login`] goes one step
//! further, for `podssh doctor --full`: it offers a key that no server knows.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{AuthResult, Config, Handler};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::keygen::{self, KeyKind};

struct Recorder(Arc<Mutex<Option<PublicKey>>>);

impl Handler for Recorder {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(key.public_key());
        // Refuse: the probe never authenticates.
        Ok(false)
    }
}

/// The host key the server at the end of `stream` presents, within `within`.
pub async fn host_key<S>(stream: S, within: Duration) -> Result<PublicKey, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let slot = Arc::new(Mutex::new(None));
    let handler = Recorder(slot.clone());
    let config = Arc::new(Config { inactivity_timeout: Some(within), ..Config::default() });
    let outcome = tokio::time::timeout(within, russh::client::connect_stream(config, stream, handler)).await;
    if let Some(key) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
        return Ok(key);
    }
    match outcome {
        Err(_) => Err(format!("no host key within {} s", within.as_secs())),
        Ok(Err(e)) => Err(crate::run::describe(&e)),
        Ok(Ok(_)) => Err("the server sent no host key".into()),
    }
}

/// What a login with a key made for the call came to.
#[derive(Debug)]
pub enum Login {
    /// The server refused the key: the key exchange, the host-key check and
    /// the authentication all ran. `methods` is what it still accepts.
    Refused { key: PublicKey, methods: Vec<String> },
    /// The server let the key in.
    Accepted { key: PublicKey },
    /// The host key was none of `accepted`: the connection ended there, and no
    /// key was offered.
    WrongHostKey { key: PublicKey },
}

/// Accepts only a host key whose fingerprint is in the list, and records it.
struct Gate {
    accepted: Vec<String>,
    seen: Arc<Mutex<Option<PublicKey>>>,
}

impl Handler for Gate {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let key = key.public_key();
        let ok = self.accepted.contains(&crate::known_hosts::fingerprint(&key));
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(key);
        Ok(ok)
    }
}

/// Log in as `user` over `stream` with an Ed25519 key made for this call,
/// kept in memory and never written. The host key must have one of the
/// fingerprints in `accepted`. The whole login is bounded by `within`.
pub async fn login<S>(stream: S, user: &str, accepted: &[String], within: Duration) -> Result<Login, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let seen = Arc::new(Mutex::new(None));
    let handler = Gate { accepted: accepted.to_vec(), seen: seen.clone() };
    let config = Arc::new(Config { inactivity_timeout: Some(within), ..Config::default() });
    let key = keygen::generate(KeyKind::Ed25519, "podssh doctor --full")?;
    let attempt = async {
        let connected = russh::client::connect_stream(config, stream, handler).await;
        let host = seen.lock().unwrap_or_else(|e| e.into_inner()).take();
        let (mut handle, host) = match (connected, host) {
            (Ok(handle), Some(host)) => (handle, host),
            (Err(russh::Error::UnknownKey), Some(key)) => return Ok(Login::WrongHostKey { key }),
            (Ok(_), None) => return Err("the server sent no host key".to_string()),
            (Err(e), _) => return Err(crate::run::describe(&e)),
        };
        let offered = PrivateKeyWithHashAlg::new(Arc::new(key), None);
        match handle.authenticate_publickey(user, offered).await {
            Ok(AuthResult::Success) => Ok(Login::Accepted { key: host }),
            Ok(AuthResult::Failure { remaining_methods, .. }) => Ok(Login::Refused {
                key: host,
                methods: remaining_methods.iter().map(|m| <&str>::from(m).to_string()).collect(),
            }),
            Err(e) => Err(format!("the authentication failed: {}", crate::run::describe(&e))),
        }
    };
    tokio::time::timeout(within, attempt).await.map_err(|_| format!("no answer within {} s", within.as_secs()))?
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
