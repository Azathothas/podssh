//! The channel between two podssh ends (T-088): Noise XX over the bytes of a
//! session, so that the relay sees ciphertext only, and each end proves its
//! key of T-087 (`crate::identity`). It runs above the resumable layer: one
//! handshake for each session, which a resume carries on, as the layer gives
//! each byte once and in order.
//!
//! On the wire, each end first sends [`MAGIC`]; then frames, each a 2-byte
//! length and one Noise message. The handshake is `-> e`, `<- e, ee, s, es`
//! and `-> s, se`; the second and third messages carry their sender's
//! Ed25519 key and its signature of the Noise static key, encrypted. The
//! responder, a node, then sends its verdict: let in, or refused with the
//! reason. Each message after it is data, or the clean end of its direction.
//! A stream that ends with no such end is a cut, never a clean end, as the
//! relay can drop the last frames; and a message that fails its check
//! (changed, dropped, repeated or out of order) ends the session, as nothing
//! may be skipped.

mod channel;
pub mod ends;
mod frame;
mod handshake;

use std::fmt;
use std::time::Duration;

pub use channel::Channel;
pub use handshake::{initiate, respond, Asked, Offered};

/// What each end sends first: the channel and its version, so that an end
/// with no channel is told apart at once, before any byte of a session.
pub const MAGIC: &[u8; 13] = b"podssh-e2e/1\n";
/// The Noise protocol.
pub const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
/// The prologue, which binds the handshake to this channel and version.
pub const PROLOGUE: &[u8] = b"podssh-e2e/1";
/// The largest Noise message.
pub const MAX_MESSAGE: usize = 65535;
/// Noise's tag on each message of the transport.
pub const TAG: usize = 16;
/// The most bytes of a session in one message: its type byte and the tag
/// go with them.
pub const MAX_DATA: usize = MAX_MESSAGE - TAG - 1;
/// The bound on each step of the handshake, and on the verdict, in which the
/// node may dial its target.
pub const HANDSHAKE_LIMIT: Duration = Duration::from_secs(30);

/// Why a node refused a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The node's allowlist does not hold this end's key.
    NotAllowed,
    /// The node could not reach its target: why.
    NoTarget(String),
    /// Another reason.
    Other(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NotAllowed => f.write_str("this end's key is not in the node's allowlist"),
            Refusal::NoTarget(why) => write!(f, "the node could not reach its target: {why}"),
            Refusal::Other(why) => f.write_str(why),
        }
    }
}

/// Why the channel failed.
#[derive(Debug)]
pub enum Error {
    /// The stream under the channel failed.
    Io(std::io::Error),
    /// The peer does not speak the channel: what it sent first, made safe.
    NotChannel(String),
    /// The handshake failed: a message that is not Noise's, or a key that
    /// does not sign the peer's Noise key.
    Handshake(String),
    /// A message failed its check: changed, dropped, repeated or out of
    /// order on its way.
    Tampered,
    /// The stream ended before the clean end of its direction.
    Cut,
    /// The node refused this end.
    Refused(Refusal),
    /// This end refused the node's key: why (a changed key, with both
    /// fingerprints).
    NodeKey(String),
    /// A step of the handshake took longer than [`HANDSHAKE_LIMIT`]: which.
    Timeout(&'static str),
    /// A frame or a message that the channel does not have.
    Malformed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "the stream under the channel failed: {e}"),
            Error::NotChannel(saw) => write!(
                f,
                "the other end does not speak podssh's end-to-end channel (it sent {saw}): an older podssh, \
                 or one run with --no-e2e, which must then be given at both ends"
            ),
            Error::Handshake(why) => write!(f, "the channel's handshake failed: {why}"),
            Error::Tampered => f.write_str(
                "a message of the channel failed its check: the relay, or something on the way, changed, \
                 dropped or repeated it",
            ),
            Error::Cut => f.write_str("the channel was cut before its end: the last bytes may be missing"),
            Error::Refused(why) => write!(f, "the node refused the session: {why}"),
            Error::NodeKey(why) => write!(f, "the node's key is not the one expected: {why}"),
            Error::Timeout(step) => write!(f, "{step} did not come within {} s", HANDSHAKE_LIMIT.as_secs()),
            Error::Malformed(why) => write!(f, "the channel carried a message that it does not have: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Cut
        } else {
            Error::Io(e)
        }
    }
}
