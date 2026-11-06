//! frp's protocol, as frpc speaks it to frps (T-498, the operator's ruling
//! Q66; `fatedier/frp` at v0.71.1): a podssh node logs in to the user's own
//! frps as a frpc and registers an STCP service of its name, which has no
//! public port; a podssh client visits it as an STCP visitor with the same
//! secret. podssh speaks frp's wire v1 (frpc's default) on frp's TCP with TLS
//! or its WebSocket over TLS ([`dial`]), with yamux inside ([`mux`]); the
//! control stream is AES-128-CFB with the token's key ([`cfb`]), the work
//! and visitor connections are streams in clear after their first message
//! ([`control`]). frps sees bytes that podssh's own end-to-end channel and
//! resumable layer carry: frp's own encryption of a service stays off.

pub mod cfb;
pub mod control;
pub mod dial;
pub mod msg;
pub mod mux;
pub mod mux_frame;
pub mod node;

#[cfg(test)]
mod tests;

pub use control::{visit, Session};
pub use dial::Server;
pub use mux::Mux;

/// Why a step of frp's protocol failed.
#[derive(Debug)]
pub enum FrpError {
    /// frps refused a step, in its own words.
    Refused { step: &'static str, words: String },
    /// An answer that is not frp's, or none in time.
    Protocol(String),
    /// The connection or the stream ended.
    Ended(String),
}

impl FrpError {
    pub fn io(e: std::io::Error) -> FrpError {
        FrpError::Ended(e.to_string())
    }

    /// Whether frps refused the token: no try again helps.
    pub fn is_bad_token(&self) -> bool {
        matches!(self, FrpError::Refused { words, .. } if words.contains("token"))
    }
}

impl std::fmt::Display for FrpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrpError::Refused { step, words } => write!(f, "frps refused {step}: \"{words}\""),
            FrpError::Protocol(why) | FrpError::Ended(why) => write!(f, "{why}"),
        }
    }
}
