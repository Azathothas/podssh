//! Fetching a server's host key without logging in: the key exchange runs, the
//! key is recorded, and the connection is refused at the host-key check. Used
//! by `podssh doctor` to identify a server by equality with a published
//! fingerprint, never by the shape of its banner.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{Config, Handler};
use russh::keys::{PublicKey, PublicKeyOrCertificate};
use tokio::io::{AsyncRead, AsyncWrite};

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
