//! Tor through Arti (T-353, the operator's ruling Q52): a stream to a host
//! and a port through the Tor network, for a host whose only way out is
//! HTTPS. Arti builds its circuits as it would anywhere; each connection
//! that it opens to a Tor relay goes through podssh's own dial ([`runtime`]),
//! so through `HTTPS_PROXY` and its credentials as each other road does,
//! and only to the ports that the proxy allows.

pub mod client;
pub mod runtime;

pub use client::{Failure, Options, Tor, TorStream};
