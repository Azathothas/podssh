//! How a connection to the relay ended, as podssh's [`ConnectError`] keeps
//! it: the cut of the dial, of the handshake, or of a bound. The cuts of an
//! error of I/O are pod-proxy's, and its tests prove them.

use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::ConnectError;
use crate::cut::{Cut, TlsFailure};
use crate::dial::DialError;

/// A certificate's refusal has no cut; a reset in the handshake has one.
#[test]
fn a_handshake_s_refusal_has_no_cut() {
    let words = crate::tls::context().words();
    let reset = std::io::Error::from(ErrorKind::ConnectionReset);
    let tls = ConnectError::Tls(TlsFailure::of(&reset, words));
    assert_eq!(tls.cut(), Some(Cut::Reset));
    let refused = std::io::Error::new(ErrorKind::InvalidData, "invalid peer certificate: UnknownIssuer");
    assert_eq!(ConnectError::Tls(TlsFailure::of(&refused, words)).cut(), None);
    let late = ConnectError::Timeout { step: "the TLS handshake", after: Duration::from_secs(10) };
    assert_eq!(late.cut(), Some(Cut::TimedOut));
    let dial = DialError::Connect { target: "t:443".into(), detail: "d".into(), cut: Some(Cut::Refused), kind: None };
    assert_eq!(ConnectError::Dial(dial).cut(), Some(Cut::Refused));
    assert_eq!(ConnectError::Refused { status: 403, body: String::new() }.cut(), None);
}

/// A far end of the tests: each write taken; a read ends as `read`
/// says: an error of that kind, the end of the stream, or never.
struct Peer {
    read: Option<Option<ErrorKind>>,
}

impl AsyncRead for Peer {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.read {
            Some(Some(kind)) => Poll::Ready(Err(kind.into())),
            Some(None) => Poll::Ready(Ok(())),
            // Silence: the bound of the handshake ends it.
            None => Poll::Pending,
        }
    }
}

impl AsyncWrite for Peer {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn handshake(read: Option<Option<ErrorKind>>) -> ConnectError {
    let bound = Duration::from_millis(300);
    match crate::tls_over(Peer { read }, "relay.example", &crate::Trust::Default, bound).await {
        Ok(_) => panic!("a handshake with no server completed"),
        Err(e) => e,
    }
}

/// The handshake keeps the kind that ended it: a reset after the
/// ClientHello, a close with nothing, and silence to the bound.
#[tokio::test]
async fn the_handshake_keeps_a_reset_a_close_and_a_timeout_apart() {
    let reset = handshake(Some(Some(ErrorKind::ConnectionReset))).await;
    assert!(matches!(&reset, ConnectError::Tls(_)), "{reset:?}");
    assert_eq!(reset.cut(), Some(Cut::Reset), "{reset}");
    let closed = handshake(Some(None)).await;
    assert_eq!(closed.cut(), Some(Cut::Closed), "{closed}");
    let silent = handshake(None).await;
    assert!(matches!(silent, ConnectError::Timeout { .. }), "{silent:?}");
    assert_eq!(silent.cut(), Some(Cut::TimedOut));
}
