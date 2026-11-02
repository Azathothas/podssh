//! The Piping Server road (T-437): a carrier of the reverse road through a
//! Piping Server, `https://ppng.io` by default, for a proxy that refuses the
//! WebSocket upgrade, which each relay, forwarder and other carrier needs. A
//! Piping Server streams the body of a `POST /PATH` into the answer to a
//! `GET /PATH` (nwtgck/piping-server:src/piping.ts), over plain HTTPS, so
//! both ends dial out and nothing asks for an upgrade. The operator's ruling
//! Q65 lets podssh try `ppng.io` when its user did not ask.
//!
//! The paths come from the pair's secret ([`paths`]), as a Piping Server
//! joins a sender and a receiver by their path alone. The node waits at its
//! door, a GET on a path that only the pair's two ends can name; a client
//! posts a hello there that names a random id for its link, and both ends
//! take the two paths of that id, one for each way. Each end POSTs its way
//! and GETs the other's: over HTTP/2 on one connection where the server's
//! TLS offers it, else over HTTP/1.1 ([`exchange`], [`dial`]). A streamed
//! POST that does not flow within its limit, as through a proxy that holds
//! a request's body until its end, makes the client ask for numbered POSTs,
//! one for each piece, one after another ([`numbered`]).
//!
//! Each session over it runs the resumable layer and, above the layer, the
//! end-to-end channel (`crate::e2e`), so the server is trusted for
//! availability only: it sees the paths, the sizes and the times, and a
//! change that it makes ends the session. [`probe`] tells a refusal of the
//! upgrade on the way from the relay's own word, which is when the road is
//! tried unasked.

pub mod client;
pub mod dial;
pub mod exchange;
pub mod far;
pub mod flow;
pub mod http1;
#[cfg(test)]
mod http1_tests;
pub mod http2;
pub mod numbered;
pub mod paths;
pub mod probe;
pub mod server;

use std::sync::Arc;

pub use client::{carry, Dialer};
pub use exchange::{Failed, Http};
pub use far::Node;
pub use flow::Link;
pub use paths::Secret;
pub use server::Server;

/// Where the lines of the road go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The features of the resumable layer that each end offers over a Piping
/// Server: those of the iroh road. The relay's limits of a session, which
/// `move.v1` keeps a session within, are not a Piping Server's.
pub const FEATURES: &[&str] = &["replay.v1", "heartbeat.v1"];

/// What podssh says it is, in each request.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));
