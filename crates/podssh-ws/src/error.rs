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
    Ok { detail: String },
    Failed { detail: String },
    /// ⛔ **A check that could not run.** Never collapsed into `Ok` — four
    /// sibling projects shipped a doctor that reported green over a broken
    /// environment, and the defect recurs three times independently.
    Unknown { why: String },
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
