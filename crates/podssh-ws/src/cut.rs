//! How a connection ended when a dial or a TLS handshake failed (T-487):
//! its kind, read from the `std::io::ErrorKind` of the error that ended it,
//! kept beside the words. The words are the system's and differ between
//! systems (Windows says os error 10054 for a reset), so a caller that
//! tells a reset from a timeout reads the kind, never the words.

use std::fmt;
use std::io::ErrorKind;

use crate::client::ConnectError;
use crate::dial::DialError;

/// How a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    /// The far end reset it, or aborted it.
    Reset,
    /// The far end refused it: nothing listens, or a firewall answered so.
    Refused,
    /// Nothing came within the bound.
    TimedOut,
    /// The far end closed it with nothing sent.
    Closed,
    /// Anything else that I/O said.
    Other,
}

impl Cut {
    /// The cut of an error of I/O of this kind.
    pub fn of(kind: ErrorKind) -> Cut {
        match kind {
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => Cut::Reset,
            ErrorKind::ConnectionRefused => Cut::Refused,
            ErrorKind::TimedOut => Cut::TimedOut,
            // A write after the far end went, and a read of its end.
            ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe => Cut::Closed,
            _ => Cut::Other,
        }
    }

    /// The cut as a report names it.
    pub fn words(self) -> &'static str {
        match self {
            Cut::Reset => "reset",
            Cut::Refused => "refused",
            Cut::TimedOut => "timed out",
            Cut::Closed => "closed with nothing",
            Cut::Other => "other",
        }
    }
}

/// Why a TLS handshake failed: the words, and the cut when an error of I/O
/// ended it rather than the handshake's own refusal (a certificate, a
/// protocol), whose kind says nothing of the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFailure {
    pub why: String,
    pub cut: Option<Cut>,
}

impl TlsFailure {
    /// The failure of a handshake that `error` ended, with rustls's words
    /// and what to do about an unknown issuer (T-340).
    pub fn of(error: &std::io::Error) -> TlsFailure {
        let cut = match error.kind() {
            // rustls's own refusal: a certificate, a name, a protocol.
            ErrorKind::InvalidData => None,
            kind => Some(Cut::of(kind)),
        };
        TlsFailure { why: crate::tls::handshake_failure(error), cut }
    }
}

impl fmt::Display for TlsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.why)
    }
}

/// Why a question got no answer, as `doctor` counts it (T-604): the words,
/// and how its connection ended where an error of I/O or a bound ended it.
/// An answer that refused, and a failure after the handshake, have none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missed {
    pub why: String,
    pub cut: Option<Cut>,
}

impl Missed {
    /// Words alone: a failure whose kind says nothing of the path.
    pub fn words(why: impl Into<String>) -> Missed {
        Missed { why: why.into(), cut: None }
    }

    /// A TLS handshake's failure, `TLS: ` and its words, with its cut.
    pub fn tls(error: &std::io::Error) -> Missed {
        let failure = TlsFailure::of(error);
        Missed { why: format!("TLS: {}", failure.why), cut: failure.cut }
    }
}

impl fmt::Display for Missed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.why)
    }
}

/// Words alone: a failure whose kind is not known.
impl From<String> for TlsFailure {
    fn from(why: String) -> TlsFailure {
        TlsFailure { why, cut: None }
    }
}

impl From<&str> for TlsFailure {
    fn from(why: &str) -> TlsFailure {
        TlsFailure { why: why.to_string(), cut: None }
    }
}

impl DialError {
    /// How the dial ended, where its error says: an address's connection,
    /// or the bound.
    pub fn cut(&self) -> Option<Cut> {
        match self {
            DialError::Connect { cut, .. } => *cut,
            DialError::Timeout { .. } => Some(Cut::TimedOut),
            _ => None,
        }
    }
}

impl ConnectError {
    /// How the connection ended, where an error of I/O or a bound ended it:
    /// the dial's, the handshake's, or the bound of a step.
    pub fn cut(&self) -> Option<Cut> {
        match self {
            ConnectError::Dial(e) => e.cut(),
            ConnectError::Tls(failure) => failure.cut,
            ConnectError::Timeout { .. } => Some(Cut::TimedOut),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[test]
    fn each_kind_is_its_cut() {
        assert_eq!(Cut::of(ErrorKind::ConnectionReset), Cut::Reset);
        assert_eq!(Cut::of(ErrorKind::ConnectionAborted), Cut::Reset);
        assert_eq!(Cut::of(ErrorKind::ConnectionRefused), Cut::Refused);
        assert_eq!(Cut::of(ErrorKind::TimedOut), Cut::TimedOut);
        assert_eq!(Cut::of(ErrorKind::UnexpectedEof), Cut::Closed);
        assert_eq!(Cut::of(ErrorKind::PermissionDenied), Cut::Other);
        // A reset in Windows' words is a reset in its kind (WSAECONNRESET).
        #[cfg(windows)]
        assert_eq!(Cut::of(std::io::Error::from_raw_os_error(10054).kind()), Cut::Reset);
    }

    /// A certificate's refusal has no cut; a reset in the handshake has one.
    #[test]
    fn a_handshake_s_refusal_has_no_cut() {
        let refused = std::io::Error::new(ErrorKind::InvalidData, "invalid peer certificate: UnknownIssuer");
        assert_eq!(TlsFailure::of(&refused).cut, None);
        let reset = std::io::Error::from(ErrorKind::ConnectionReset);
        assert_eq!(TlsFailure::of(&reset).cut, Some(Cut::Reset));
        assert_eq!(TlsFailure::from("words").to_string(), "words");
        let tls = ConnectError::Tls(TlsFailure::of(&reset));
        assert_eq!(tls.cut(), Some(Cut::Reset));
        let late = ConnectError::Timeout { step: "the TLS handshake", after: Duration::from_secs(10) };
        assert_eq!(late.cut(), Some(Cut::TimedOut));
        let dial = DialError::Connect { target: "t:443".into(), detail: "d".into(), cut: Some(Cut::Refused) };
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
}
