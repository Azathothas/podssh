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
//! - [`configuration`]: the answer to a push of configuration, of which
//!   nothing is kept (T-404);
//! - [`headers`]: the one header in which an answer of HTTP/2 carries the
//!   origin's headers;
//! - [`api`]: the request for a tunnel, and its reply;
//! - [`connect`]: the first bytes of each QUIC stream, and the request and
//!   answer that follow them (T-301);
//! - `edge` (feature `quick`): where the edge is, and its TLS;
//! - `edge_warp` (feature `warp`): the edge inside WARP's tunnel, for a node
//!   whose cage does not reach TCP port 7844 (T-374);
//! - `goaway` (feature `quick`): the edge's GOAWAY, seen as it passes;
//! - `serve` (feature `quick`): the connection to the edge, served over
//!   HTTP/2: the control stream, and each visitor's WebSocket;
//! - `settings` (feature `quick`): HTTP/2's streams and windows there, and
//!   h2's budget of small frames (T-408);
//! - `quic` and `quic_serve` (feature `quick`): the same over QUIC, where UDP
//!   reaches the edge (T-301); `visitor`: a WebSocket on such a stream;
//! - `probe` (feature `quick`): whether UDP reaches the edge, by one packet
//!   that its Version Negotiation answers, before QUIC (T-400);
//! - `roads` and `keep` (feature `quick`): the roads to the edge raced with
//!   a stagger, the first that registers kept, and the node's connection
//!   kept by a new race after each loss (T-400).

pub mod api;
pub mod capnp;
pub mod configuration;
pub mod connect;
pub mod control;
#[cfg(feature = "quick")]
pub mod edge;
#[cfg(feature = "warp")]
pub mod edge_warp;
#[cfg(feature = "quick")]
pub mod goaway;
pub mod headers;
#[cfg(feature = "quick")]
pub mod keep;
#[cfg(feature = "quick")]
pub mod probe;
#[cfg(feature = "quick")]
pub mod quic;
#[cfg(feature = "quick")]
pub mod quic_serve;
pub mod register;
#[cfg(feature = "quick")]
pub mod roads;
pub mod rpc;
#[cfg(feature = "quick")]
pub mod serve;
#[cfg(feature = "quick")]
pub mod settings;
#[cfg(feature = "quick")]
pub mod visitor;

/// The release whose protocol podssh speaks: named where the edge refuses
/// podssh, or answers what podssh does not read, for a change of cloudflared
/// would look so (T-339). `cloudflared-pin.txt` holds its sums.
pub const SPEAKS: &str = "the quick tunnel of cloudflared 2026.10.6";

#[cfg(test)]
mod pin_tests {
    #[test]
    fn the_release_named_is_the_pin_of_the_table() {
        let table = include_str!("cloudflared-pin.txt");
        let tag = table.lines().find_map(|line| line.strip_prefix("tag ")).expect("the table names its tag");
        assert_eq!(super::SPEAKS, format!("the quick tunnel of cloudflared {}", tag.trim()));
        // And the module's own words of the pin.
        assert!(include_str!("mod.rs").contains(&format!("cloudflared {}", tag.trim())));
    }
}
