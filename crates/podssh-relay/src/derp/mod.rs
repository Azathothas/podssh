//! The DERP road (T-349): a carrier of the reverse road through the DERP
//! servers that Tailscale runs for tailcat, which need no account, or a
//! derper of the user's own; the second carrier that needs no relay of the
//! operator's, after n0's iroh relays (the operator's ruling Q50 makes both
//! a fallback that is tried unasked). DERP runs over a WebSocket at
//! `wss://HOST/derp` on port 443, through `HTTPS_PROXY` ([`dial`]), so it
//! passes where the relay does; it is pure Rust, as this crate must be.
//!
//! A DERP server forwards packets between Curve25519 keys ([`key`],
//! [`frame`]), keeps their order, and drops the oldest of a receiver's 32
//! when they wait. The resumable layer above ends a link at a gap, so under
//! it an adapter numbers the bytes of each link, acknowledges them, and
//! sends again what was lost ([`send`], [`recv`], [`rtt`]), with a window
//! under the server's queue. A link ([`link`]) is a byte stream between a
//! client and a node, each over one connection to the server ([`conn`]),
//! in packets of podssh's own ([`packet`]). A node serves the links that
//! clients open ([`far`]); a client opens them by the node's ticket
//! ([`ticket`], [`client`]), at the node's home or at another server of
//! the fleet ([`servers`]).
//!
//! Each session over it runs the layer and, above the layer, the end-to-end
//! channel (`crate::e2e`), so the server is trusted for availability only:
//! it sees the keys, the sizes and the times, and a change that it makes
//! ends the session.

#[cfg(test)]
mod arq_tests;
pub mod client;
pub mod conn;
pub mod dial;
pub mod far;
pub mod frame;
pub mod key;
pub mod link;
pub mod packet;
pub mod recv;
pub mod rtt;
pub mod send;
pub mod servers;
pub mod ticket;

use std::sync::Arc;

pub use client::{carry, Dialer};
pub use conn::Conn;
pub use far::Node;
pub use key::{Key, Secret};
pub use link::Link;
pub use servers::Server;
pub use ticket::Ticket;

/// Where the lines of a connection go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The features of the resumable layer that each end offers over DERP: those
/// of the iroh road. The relay's limits of a session, which `move.v1`
/// keeps a session within, are not DERP's.
pub const FEATURES: &[&str] = &["replay.v1", "heartbeat.v1"];
