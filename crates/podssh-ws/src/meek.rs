//! meek_lite (T-385), Tor's meek as lyrebird's client speaks it: a bridge's
//! bytes in the bodies of HTTP POSTs to its `url=`, through a CDN that
//! `front=` names. The connection and TLS go to the front, with its name in
//! TLS's SNI; `Host` names the URL's host, which the CDN routes by. A proxy
//! that forwards with CONNECT sees the front alone, and POSTs pass where an
//! upgrade is refused.
//!
//! The wire form, read in lyrebird (`transports/meeklite/meek.go`) and in
//! meek-server 0.38.0: one request at a time, each with the session's
//! `X-Session-Id` (32 hex digits, which the server keys its connection to
//! the bridge by) and no `User-Agent`; a body of at most 64 KiB, the bytes
//! that wait joined up to that; the answer's body, at most 64 KiB, is the
//! bridge's. With nothing to send, a poll: at once after any byte either
//! way, else 100 ms, then half as long again each time up to 5 s, so that
//! the server's bytes come back. A failed exchange moves to the next front,
//! 10 times at most, 100 ms apart after a refusal; then the session ends.
//!
//! The connection is HTTP/1.1, kept between requests, opened again when it
//! ends. `utls=` is read and left: TLS is rustls's, checked as each road's
//! (`tls.rs`), never another browser's form.

mod args;
mod carry;
mod exchange;

pub use args::{Args, Front};
pub use carry::Ended;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::pt::Reach;

/// The most bytes in a request's body, and read from an answer's.
pub const MAX_PAYLOAD: usize = 0x10000;
/// The first wait of a poll with nothing to send.
pub const INIT_POLL: Duration = Duration::from_millis(100);
/// The longest wait of a poll.
pub const MAX_POLL: Duration = Duration::from_secs(5);
/// How many exchanges a body may take before the session ends.
pub const MAX_TRIES: usize = 10;
/// The pause after a refusal, before the next front.
pub const RETRY_DELAY: Duration = Duration::from_millis(100);
/// How long one exchange may take, its answer included: meek-server answers
/// within 10 ms of the bridge's bytes, and a CDN adds its own trip.
pub const EXCHANGE_WAIT: Duration = Duration::from_secs(30);

/// The wait of the next poll, after `now` brought nothing either way: from
/// nothing, 100 ms; else half as long again, up to 5 s. In nanoseconds, as
/// Go multiplies a `time.Duration`, so that each step is exact.
pub fn next_poll(now: Duration) -> Duration {
    if now.is_zero() {
        return INIT_POLL;
    }
    let nanos = now.as_nanos().min(u128::from(u64::MAX)) as f64 * 1.5;
    Duration::from_nanos(nanos as u64).min(MAX_POLL)
}

/// A session's id, as lyrebird makes one: the first 16 bytes of SHA-256 of
/// 64 random bytes, in hex. With no random source there is no session:
/// meek-server keys a bridge's connection by it.
pub fn session_id() -> Result<String, String> {
    use sha2::Digest as _;
    let mut seed = [0u8; 64];
    use rustls::crypto::SecureRandom as _;
    crate::crypto::random::OsRandom.fill(&mut seed).map_err(|_| "no random bytes for meek's session id".to_string())?;
    let digest = sha2::Sha256::digest(seed);
    Ok(digest[..16].iter().map(|b| format!("{b:02x}")).collect())
}

/// A session whose first connection is open.
pub struct Session {
    client: exchange::Client,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("front", &self.client.shown()).finish()
    }
}

impl Session {
    /// The URL and the front in use, for a line: no query, no session id.
    pub fn shown(&self) -> String {
        self.client.shown()
    }

    /// Carry `local`'s bytes to the bridge and the bridge's back, until
    /// `local` ends or the exchanges fail.
    pub async fn carry<S: AsyncRead + AsyncWrite + Unpin>(self, local: S) -> Ended {
        carry::run(self.client, local).await
    }
}

/// A session for `args`: a new id, and a connection to the first front that
/// takes one, so that a front out of reach is said before any byte goes.
pub async fn open(args: &Args, reach: &Reach) -> Result<Session, String> {
    let mut client = exchange::Client::new(args, reach.clone())?;
    client.connect_any().await?;
    Ok(Session { client })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_polls_back_off_as_lyrebird_s_do() {
        let mut waits = vec![INIT_POLL];
        for _ in 0..12 {
            waits.push(next_poll(*waits.last().unwrap()));
        }
        let ms: Vec<u128> = waits.iter().map(Duration::as_millis).collect();
        assert_eq!(&ms[..6], &[100, 150, 225, 337, 506, 759]);
        assert_eq!(*ms.last().unwrap(), 5000);
        assert_eq!(next_poll(Duration::ZERO), INIT_POLL);
    }

    #[test]
    fn a_session_id_is_32_hex_digits_and_new_each_time() {
        let (a, b) = (session_id().unwrap(), session_id().unwrap());
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{a}");
        assert_ne!(a, b);
    }
}
