//! A limit on each answer of the server during the authentication: a server
//! that stalls after the key exchange must not hold podssh for ever. The
//! limit is `ConnectTimeout`. A prompt runs before its request, so a person
//! who types slowly never meets it; the time that the agent spends signing
//! (a person may confirm each signature, `ssh-add -c`) does not count either.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::agent::AgentIdentity;
use russh::keys::HashAlg;
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

/// An agent whose signing time is kept in an [`AgentTime`].
pub(crate) struct Timed<'a, S> {
    pub inner: &'a mut S,
    pub time: Arc<Mutex<AgentTime>>,
}

impl<S> russh::Signer for Timed<'_, S>
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
        self.time.lock().unwrap_or_else(|e| e.into_inner()).since = Some(Instant::now());
        let signed = self.inner.auth_sign(key, hash_alg, to_sign).await;
        let mut time = self.time.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(start) = time.since.take() {
            time.spent += start.elapsed();
        }
        signed
    }
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
