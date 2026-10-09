//! The iroh road between two podssh ends (T-162): QUIC between Ed25519 keys,
//! through an iroh relay (HTTPS on port 443, upgraded to a WebSocket) when
//! UDP is refused, and directly when a probe shows that UDP works. It keeps a
//! connection across a lost relay connection and a new address of either
//! end (`docs/design.md`, section 7).
//!
//! The endpoint ([`endpoint`]) is set up as podssh's other roads are: no
//! address lookup, the relays given, podssh's proxy, name resolution
//! ([`resolve`]) and trust store, and UDP only after a probe ([`probe`]). A
//! session is one QUIC stream ([`stream`]) with the ALPN [`ALPN`], which
//! carries the records of the resumable layer (T-151), so that it can go on
//! over another road (T-153). [`far`] serves the sessions of a far end, to
//! the client keys of its allowlist ([`allow`]); [`client`] dials a node by
//! its ticket ([`ticket`]). Each end has its key in a private file
//! ([`keys`]), and its home relay is the first of its list that answers
//! ([`relays`]).

pub mod allow;
pub mod client;
pub mod endpoint;
pub mod far;
pub mod keys;
pub mod probe;
pub mod relays;
pub mod resolve;
pub mod stream;
#[cfg(feature = "test-relay")]
pub mod test_relay;
pub mod ticket;

pub use allow::Allowlist;
pub use client::{carry, Dialer, Failure};
pub use endpoint::{bind, BindError, Options, Udp};
pub use stream::{accept_session, open_session, Stream};

/// The ALPN of podssh's sessions over iroh: a connection with another one
/// is refused in its handshake.
pub const ALPN: &[u8] = b"podssh/1";

/// The features of the resumable layer that each end offers over iroh:
/// those of the relay road but `move.v1`, whose move to a new link keeps a
/// session within the limits of the WebSocket relay's sessions, which a
/// QUIC connection does not have.
pub const FEATURES: &[&str] = &["replay.v1", "heartbeat.v1"];
