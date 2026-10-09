//! ⛔ Every way this layer can fail, as values.
//!
//! ⛔ **No variant carries a token, and none formats one.** `Display` is what
//! ends up in a log, and the relay specification's own rule is that a token
//! never enters a log, a URL, a screenshot, or an issue report. An error type
//! that could hold one would make that rule a matter of every call site's
//! discipline rather than a property of the type.

use std::fmt;

/// The three-valued result the doctor reports. `Unknown` is not optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok {
        detail: String,
    },
    Failed {
        detail: String,
    },
    /// ⛔ **A check that could not run.** Never collapsed into `Ok` — four
    /// sibling projects shipped a doctor that reported green over a broken
    /// environment, and the defect recurs three times independently.
    Unknown {
        why: String,
    },
}

impl Verdict {
    /// ⛔ The label the entry's `Prove` block names: `ok`, `FAIL`, `????`.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Ok { .. } => "ok",
            Verdict::Failed { .. } => "FAIL",
            Verdict::Unknown { .. } => "????",
        }
    }

    /// Whether the check passed. `Unknown` never did: a check that could not
    /// run is never counted as passing. (`podssh doctor` counts unknowns
    /// apart from failures, and only a failure fails its run.)
    pub fn is_success(&self) -> bool {
        matches!(self, Verdict::Ok { .. })
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Ok { detail } => write!(f, "ok   {detail}"),
            Verdict::Failed { detail } => write!(f, "FAIL {detail}"),
            Verdict::Unknown { why } => write!(f, "???? {why}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsError {
    /// ⛔ The trust bundle could not be used. The path is always in the
    /// message: a deployment that cannot find its trust store cannot be
    /// diagnosed from "TLS failed".
    Bundle { path: String, why: String },
    /// The `ClientConfig` could not be built.
    Config(String),
    /// The TCP connection or the TLS handshake failed.
    Handshake(String),
    /// The HTTP upgrade to WebSocket failed, with the relay's status line.
    Upgrade { status: u16, why: String },
    /// ⛔ A frame could not be parsed. This is an `Err`, never a panic: an
    /// unparseable frame mid-stream is a peer fault and must end the session
    /// cleanly.
    Frame(String),
    /// A close code arrived from the peer.
    Closed { code: u16, reason: String },
    /// Anything else, with the context that produced it.
    Io(String),
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WsError::Bundle { path, why } => write!(f, "CA bundle {path}: {why}"),
            WsError::Config(why) => write!(f, "TLS configuration: {why}"),
            WsError::Handshake(why) => write!(f, "TLS handshake: {why}"),
            WsError::Upgrade { status, why } => {
                write!(f, "WebSocket upgrade returned {status}: {why}")
            }
            WsError::Frame(why) => write!(f, "WebSocket frame: {why}"),
            WsError::Closed { code, reason } => {
                write!(f, "peer closed with {code}: {reason}")
            }
            WsError::Io(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for WsError {}

impl From<std::io::Error> for WsError {
    fn from(e: std::io::Error) -> Self {
        WsError::Io(e.to_string())
    }
}

/// Why a relay session failed, by class: a caller chooses by the class
/// (reconnect after a dead link, never after a protocol fault) and not by
/// matching text. `Display` gives the text that the session gave before the
/// classes, so a message and a check that read it do not change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// A read or a write of the socket failed: its kind, and the text.
    Io { kind: std::io::ErrorKind, text: String },
    /// No data from the relay within the read limit.
    Idle(String),
    /// A write did not finish within the write limit.
    WriteStalled(String),
    /// A frame or a message that RFC 6455 forbids; a Close 1002 went out.
    Protocol(String),
    /// A message over the size limit; a Close 1009 went out.
    TooLarge(String),
    /// Pings went unanswered: the link is dead ([`crate::RelaySession::watch_liveness`]).
    Dead(String),
    /// The stream ended with no WebSocket Close.
    ClosedWithoutClose(String),
}

impl SessionError {
    /// The text, as `Display` gives it.
    pub fn text(&self) -> &str {
        match self {
            SessionError::Io { text, .. } => text,
            SessionError::Idle(text)
            | SessionError::WriteStalled(text)
            | SessionError::Protocol(text)
            | SessionError::TooLarge(text)
            | SessionError::Dead(text)
            | SessionError::ClosedWithoutClose(text) => text,
        }
    }

    /// The same class, with `what` in front of the text.
    pub fn context(self, what: &str) -> SessionError {
        let text = |t: String| format!("{what}: {t}");
        match self {
            SessionError::Io { kind, text: t } => SessionError::Io { kind, text: text(t) },
            SessionError::Idle(t) => SessionError::Idle(text(t)),
            SessionError::WriteStalled(t) => SessionError::WriteStalled(text(t)),
            SessionError::Protocol(t) => SessionError::Protocol(text(t)),
            SessionError::TooLarge(t) => SessionError::TooLarge(text(t)),
            SessionError::Dead(t) => SessionError::Dead(text(t)),
            SessionError::ClosedWithoutClose(t) => SessionError::ClosedWithoutClose(text(t)),
        }
    }

    /// A failed read or write of the socket.
    pub fn io(e: &std::io::Error) -> SessionError {
        SessionError::Io { kind: e.kind(), text: e.to_string() }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for SessionError {}

/// For a caller that reports text: the same text as before the classes.
impl From<SessionError> for String {
    fn from(e: SessionError) -> String {
        e.to_string()
    }
}
