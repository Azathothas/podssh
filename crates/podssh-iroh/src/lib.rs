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
//! over another road (T-153). [`far`] serves the sessions of a far end.

pub mod endpoint;
pub mod far;
pub mod probe;
pub mod resolve;
pub mod stream;

pub use endpoint::{bind, BindError, Options, Udp};
pub use stream::{accept_session, open_session, Stream};

/// The ALPN of podssh's sessions over iroh: a connection with another one
/// is refused in its handshake.
pub const ALPN: &[u8] = b"podssh/1";
