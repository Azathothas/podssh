//! The reach of each later hop of `-J` (T-462, GitHub #86): a `direct-tcpip`
//! channel of the hop before it, opened within the hop's ConnectTimeout, on
//! a stream that marks its first byte. A login that fails with no byte heard
//! then names the hop and its channel: the line of the handshake named the
//! destination alone, and sent the user to debug it, or the network, where
//! nothing behind the hop had answered.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::ChannelStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::handler::Client;
use crate::log::Log;
use crate::options::Hop;
use crate::run::HopError;

/// How often `-v` says that nothing came yet through the hop.
const WAIT_LINE: Duration = Duration::from_secs(10);

/// The reach of one hop: the hop that opens its channel, the channel's
/// target, and the limit of each wait, the hop's ConnectTimeout.
pub(crate) struct Reach {
    /// The hop before, as the lines name a hop.
    through: String,
    /// The channel's target, HOST:PORT.
    target: String,
    limit: Duration,
}

impl Reach {
    pub(crate) fn new(through: String, hop: &Hop, limit: Duration) -> Reach {
        Reach { through, target: podssh_ws::dial::authority(&hop.host, hop.port), limit }
    }

    /// The channel to `hop` from `previous`, within the limit: a hop that
    /// never answers the open would hold the run for ever. A refusal keeps
    /// the hop's own words.
    pub(crate) async fn open(
        &self,
        previous: &Handle<Client>,
        hop: &Hop,
        log: &Log,
    ) -> Result<Heard<ChannelStream<Msg>>, HopError> {
        match tokio::time::timeout(self.limit, crate::forward::open(previous, &hop.host, hop.port)).await {
            Err(_) => Err(HopError::Unreachable(self.unanswered())),
            Ok(Err(refused)) => Err(HopError::Unreachable(refused)),
            Ok(Ok(stream)) => {
                log.verbose(&format!("the hop {} opened a channel to {}", self.through, self.target));
                Ok(Heard::new(stream))
            }
        }
    }

    /// `login` over the channel that `heard` watches. With `-v`, a line each
    /// 10 s while nothing came; a failure with nothing heard names the hop
    /// and its channel, and the line of the login goes to `-v`.
    pub(crate) async fn login<T>(
        &self,
        heard: Arc<AtomicBool>,
        login: impl Future<Output = Result<T, HopError>>,
        log: &Log,
    ) -> Result<T, HopError> {
        let started = tokio::time::Instant::now();
        let say = |line: String| log.verbose(&line);
        let wait = self.waiting(&heard, &say);
        tokio::pin!(login, wait);
        let mut waiting = true;
        let result = loop {
            tokio::select! {
                result = &mut login => break result,
                // Once a byte came, the login alone is awaited.
                () = &mut wait, if waiting => waiting = false,
            }
        };
        match result {
            Err(HopError::Unreachable(why)) if !heard.load(Ordering::Relaxed) => {
                log.verbose(&why);
                Err(HopError::Unreachable(self.unheard(started.elapsed())))
            }
            other => other,
        }
    }

    /// Each [`WAIT_LINE`] while nothing came, a line to `say`; it ends once
    /// a byte came. `Sync`, so that a run's future stays `Send`.
    async fn waiting(&self, heard: &AtomicBool, say: &(dyn Fn(String) + Sync)) {
        let mut waited = Duration::ZERO;
        loop {
            tokio::time::sleep(WAIT_LINE).await;
            if heard.load(Ordering::Relaxed) {
                return;
            }
            waited += WAIT_LINE;
            say(self.still(waited));
        }
    }

    fn unanswered(&self) -> String {
        format!(
            "the hop {} did not answer the open of a channel to {} within {} s",
            self.through,
            self.target,
            self.limit.as_secs()
        )
    }

    /// The failure of a login that heard nothing, `after` its start: the
    /// limit ran out (the handshake's, or TLS's), or the channel ended first.
    fn unheard(&self, after: Duration) -> String {
        if after >= self.limit {
            format!(
                "the hop {} opened its channel to {}, and no byte came on it within {} s: no SSH server \
                 answered behind the hop",
                self.through,
                self.target,
                self.limit.as_secs()
            )
        } else {
            format!(
                "the hop {} opened its channel to {}, and it closed before any byte came: no SSH server \
                 answered behind the hop",
                self.through, self.target
            )
        }
    }

    fn still(&self, waited: Duration) -> String {
        format!("nothing yet from {} through the hop {}, after {} s", self.target, self.through, waited.as_secs())
    }
}

/// A stream that marks the first byte that it reads, as `--direct`'s mark
/// of its proxy (T-317).
pub(crate) struct Heard<S> {
    inner: S,
    heard: Arc<AtomicBool>,
}

impl<S> Heard<S> {
    fn new(inner: S) -> Self {
        Heard { inner, heard: Arc::new(AtomicBool::new(false)) }
    }

    /// The mark, which stays readable once the stream went to russh.
    pub(crate) fn heard(&self) -> Arc<AtomicBool> {
        self.heard.clone()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Heard<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.heard.store(true, Ordering::Relaxed);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Heard<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "hop_tests.rs"]
mod tests;
