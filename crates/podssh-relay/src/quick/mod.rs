//! A quick tunnel that podssh makes itself, with no `cloudflared` (T-300):
//! `https://NAME.trycloudflare.com` in front of a node, over HTTP/2 to
//! Cloudflare's edge on TCP port 7844, or over QUIC on UDP port 7844 where
//! no proxy is set and UDP gets there (T-301). The protocol is
//! cloudflared's, which publishes no contract, so podssh pins it to
//! cloudflared 2026.10.6 (commit 35b379a; `docs/design.md`, section 2, "A
//! quick tunnel that podssh makes itself"), as it pins the relay's.
//!
//! - [`capnp`]: the few shapes of Cap'n Proto that the registration needs,
//!   by hand, with no code generator and no C;
//! - [`rpc`]: the messages of Cap'n Proto's RPC for a client of one
//!   capability: bootstrap, call, finish, and the answers;
//! - [`register`]: `registerConnection`, its parameters and its answer;
//! - [`control`]: the control stream, sans-IO: the registration and its end;
//! - [`headers`]: the one header in which an answer of HTTP/2 carries the
//!   origin's headers;
//! - [`api`]: the request for a tunnel, and its reply;
//! - [`connect`]: the first bytes of each QUIC stream, and the request and
//!   answer that follow them (T-301);
//! - `edge` (feature `quick`): where the edge is, and its TLS;
//! - `goaway` (feature `quick`): the edge's GOAWAY, seen as it passes;
//! - `serve` (feature `quick`): the connection to the edge, served over
//!   HTTP/2: the control stream, and each visitor's WebSocket;
//! - `quic` and `quic_serve` (feature `quick`): the same over QUIC, where UDP
//!   reaches the edge (T-301); `visitor`: a WebSocket on such a stream.

pub mod api;
pub mod capnp;
pub mod connect;
pub mod control;
#[cfg(feature = "quick")]
pub mod edge;
#[cfg(feature = "quick")]
pub mod goaway;
pub mod headers;
#[cfg(feature = "quick")]
pub mod quic;
#[cfg(feature = "quick")]
pub mod quic_serve;
pub mod register;
pub mod rpc;
#[cfg(feature = "quick")]
pub mod serve;
#[cfg(feature = "quick")]
pub mod visitor;
