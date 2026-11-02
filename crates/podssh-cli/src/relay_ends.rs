//! How a session that a relay host carried ended, for the record of the
//! hosts (T-563): a session that its host's side cut within
//! `failures::SHORT` of its open is a strike, two in a row rest the host,
//! and any other end breaks the row. The stream of each command that reaches
//! its first hop as `podssh ssh` does tells it once SSH lets the stream go;
//! `podssh proxy` and the relay's end of `podssh pipe` tell it at their end.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use podssh_relay::failures;
use podssh_ssh::{RelayEnd, RelayStatus};
use podssh_ws::session::{forward_close, ForwardClose};
use podssh_ws::RelaySession;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// Whether the host's side ended a session that ended with `close`, a Close's
/// code and reason: the relay's Close for its link to podssh, or none at all.
/// The target's end, the client's, a limit of the relay and a close that its
/// table does not list are no cut.
pub fn cut_by(code: Option<u16>, reason: &str) -> bool {
    forward_close(code, reason) == ForwardClose::Client
}

/// [`cut_by`] for the relay leg of an SSH session: a link that failed is a
/// cut, and no end at all (SSH let the stream go first) is none.
pub fn cut(end: Option<&RelayEnd>) -> bool {
    match end {
        None => false,
        Some(RelayEnd::Failed(_)) => true,
        Some(RelayEnd::Closed { code, reason }) => cut_by(*code, reason),
    }
}

/// The stream of a relay session to SSH, which tells the record of its host
/// how the session ended once SSH lets it go: then the relay leg's end, if
/// any, is known, as the leg sets it before its pipe ends.
pub struct Told<S> {
    inner: S,
    status: RelayStatus,
    host: String,
}

/// [`podssh_ssh::relay_stream::spawn`] of a session that `host` opened, with
/// the stream that tells the record how it ended.
pub fn spawn(session: RelaySession, host: &str) -> (Told<DuplexStream>, RelayStatus) {
    let (stream, status) = podssh_ssh::relay_stream::spawn(session);
    (Told { inner: stream, status: status.clone(), host: host.to_string() }, status)
}

impl<S> Drop for Told<S> {
    fn drop(&mut self) {
        let end = self.status.get();
        failures::ended(failures::WEBSOCKET, &self.host, self.status.age(), cut(end.as_ref()));
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Told<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Told<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cut is the host's link: a link that failed, no Close, or the
    /// relay's Close for its link to podssh; never the target's end, a limit
    /// of the relay, or SSH that let go first.
    #[test]
    fn only_an_end_on_the_host_s_side_is_a_cut() {
        let closed = |code, reason: &str| RelayEnd::Closed { code, reason: reason.into() };
        let lost = podssh_ws::SessionError::Idle("the relay sent nothing for 40 s".into());
        assert!(cut(Some(&RelayEnd::Failed(lost))));
        assert!(cut(Some(&closed(None, ""))), "no Close");
        assert!(cut(Some(&closed(Some(1011), "client send failed: reset"))));
        assert!(cut(Some(&closed(Some(1013), "client receive backlog"))));
        for (code, reason) in [
            (1000, "target closed"),
            (1001, "idle timeout"),
            (1009, "session byte cap"),
            (1011, "connect failed: refused"),
            (1011, "write failed: Network connection lost."),
            (4321, "something new"),
        ] {
            assert!(!cut(Some(&closed(Some(code), reason))), "{code} {reason}");
        }
        assert!(!cut(None), "SSH let the stream go first");
    }
}
