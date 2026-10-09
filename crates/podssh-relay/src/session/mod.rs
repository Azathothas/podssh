//! The resumable layer (milestone M6): what lets a session between two
//! podssh ends outlive its link to the relay.
//!
//! The layer runs under SSH, so it carries SSH's ciphertext only. Each side
//! numbers the bytes that it sends with 64-bit offsets from 0 that never
//! reset; the first link of a session sets its id and a 256-bit secret, and
//! after a loss the client proves the secret on a new link through any road
//! and relay host, and each side sends again from the other's received
//! offset (T-152, T-153). The records, the handshake and what the layer
//! defends against are in `docs/design.md`, section 5.
//!
//! - [`record`] and [`decode`]: the records, their encoding, and a decoder
//!   for a byte stream whose frames mean nothing;
//! - [`offset`]: the offsets of each direction: an overlap is dropped, and
//!   nothing after a gap is ever delivered;
//! - [`secret`]: the session id, the nonces, the secret and the proofs;
//! - [`handshake`]: the state machines of the client and the far end, and
//!   the sessions that a far end keeps;
//! - [`link`]: a session past its handshake, record by record, and
//!   [`replay`]: the bytes that it keeps until the peer acknowledges them;
//! - [`client`] and [`far`]: the two ends over tokio streams.
//!
//! All but the last two are sans-IO: bytes and records in, records and
//! events out, with no socket and no clock.

pub mod client;
pub mod decode;
pub mod far;
pub mod handshake;
pub mod link;
pub mod offset;
mod pump;
pub mod record;
pub mod replay;
pub mod secret;

pub use decode::{DecodeError, Decoder};
pub use handshake::{Ask, ClientHandshake, Established, FarHandshake, HandshakeError, Sessions, Step};
pub use link::{Event, Link, LinkError};
pub use offset::{Inbound, OffsetError, Outbound};
pub use pump::{End, Ended};
pub use record::{Acceptance, Hello, Opening, Record, RefuseCode, Role};
pub use replay::{NotKept, Replay};
pub use secret::{Entropy, NoRandom, Nonce, OsEntropy, Proof, Secret, SessionId};

/// The features that this build offers: a side ignores a name that it does
/// not know, and uses a feature only when both sides named it.
pub const FEATURES: &[&str] = &["replay.v1"];

/// What one end of the layer offers and keeps.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The feature names that this end gives in its first record.
    pub features: &'static [&'static str],
    /// The capacity of the replay buffer in each direction (T-152).
    pub replay_capacity: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { features: FEATURES, replay_capacity: replay::DEFAULT_CAPACITY }
    }
}

impl Settings {
    /// The state of a new session: a replay buffer and acknowledgements when
    /// both sides named `replay.v1`, else neither, since a peer that does not
    /// acknowledge would fill the buffer and stop the session.
    pub fn link(&self, established: &Established) -> Link {
        let link = Link::new(established.received, established.peer_received);
        if established.features.iter().any(|name| name == "replay.v1") {
            link.with_replay(self.replay_capacity)
        } else {
            link
        }
    }
}
