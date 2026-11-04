//! podssh-relay — reaching podssh's WebSocket-to-TCP relay, as a library.
//!
//! - [`relay`]: which relay hosts to use, in what order (an explicit list, or
//!   the default host followed by alternates from the relay's own pool);
//! - [`pool`]: the pool, as the relay publishes it, cached between runs;
//! - [`health`]: one host's `/health`, as `podssh doctor` and `podssh relay
//!   status` read it;
//! - [`token`] and [`cache`]: tokens from the environment, the cache or a
//!   fresh mint, kept between runs in a private file, never printed;
//! - [`addresses`]: the addresses that carried a session to each relay host,
//!   kept in the cache for a run whose resolver fails (T-344);
//! - [`mod@open`]: a forward session, failing over from host to host with backoff,
//!   one bounded attempt per host;
//! - [`cleartext`]: the road with no TLS on the relay's port, last, with a
//!   token of one session, for a proxy that cuts TLS (T-326);
//! - [`h2_road`]: which forward sessions are streams of one HTTP/2
//!   connection, by RFC 8441's extended CONNECT (T-321), `PODSSH_H2`;
//! - [`http_road`]: the HTTP road (T-319), a forward session over plain
//!   requests of HTTP/1.1 where a proxy refuses the WebSocket upgrade, in its
//!   split form and its serial form, whose server is the relay role's;
//! - [`forward_layer`]: a forward session in the resumable layer, whose far
//!   end is podssh's relay role, so that a standard sshd's session outlives
//!   a drop of the client's link (T-173);
//! - [`keyed`]: a mint or a pair that the relay asks this client's key to
//!   sign (T-448);
//! - `pair` (feature `pair`): the pairs of the reverse road, made, asked
//!   about and stopped on the relay's control host, kept in a private file;
//! - `reverse` (feature `pair`): the node and the operator of the reverse road;
//! - [`session`]: the resumable layer between two podssh ends: its records,
//!   offsets and handshake, and its client and far end over tokio streams;
//! - [`identity`]: who an end is: its key file, its fingerprint, a node's
//!   allowlist and an operator's pins, the same on each road;
//! - [`e2e`]: the channel between two podssh ends, Noise XX above the
//!   resumable layer, in which each end proves its key;
//! - `grant` (feature `grant`): grants used once (T-226), OpenSSH user
//!   certificates that the node checks in the channel before it dials, and
//!   its record of each one used;
//! - [`udp`]: UDP in a stream (T-168): each datagram after its length, and
//!   the flow at the far end, a UDP socket connected to the target;
//! - [`quick`]: a quick tunnel of Cloudflare's that podssh makes itself, with
//!   no `cloudflared` (T-300): the registration's Cap'n Proto and its RPC,
//!   and the headers of its answers;
//! - `derp` (feature `derp`): the DERP road (T-349), through Tailscale's
//!   servers for tailcat or a derper of the user's own, with an adapter
//!   under the resumable layer that sends again what a server drops;
//! - [`transit`]: the transit road (T-436), a pair's carrier through a
//!   magic-wormhole transit relay, Least Authority's by default;
//! - `piping` (feature `piping`): the Piping Server road (T-437), a POST
//!   and a GET for each way of a link, for a proxy that refuses the
//!   WebSocket upgrade;
//! - `opentunnel` (feature `opentunnel`): the OpenTunnel road (T-530), a
//!   blind TLS tunnel with no account, whose client's leg is TLS by name
//!   with no upgrade;
//! - `code` (feature `code`): pairing by a short code (T-086), SPAKE2 over a
//!   magic-wormhole mailbox, which moves a pair's operator's part and each
//!   end's key;
//! - `blocking` (feature `blocking`): a synchronous facade over all of these,
//!   for a caller with no async runtime: it owns a runtime on the current
//!   thread, and refuses a call from inside a tokio runtime.
//!
//! No C compiler is needed (the gate builds this crate with
//! `CC=/nonexistent`), so other projects can depend on it.

pub mod addresses;
#[cfg(feature = "blocking")]
pub mod blocking;
pub mod cache;
pub mod cleartext;
#[cfg(feature = "code")]
pub mod code;
#[cfg(feature = "derp")]
pub mod derp;
pub mod e2e;
pub mod failover;
pub mod failures;
pub mod forward_layer;
#[cfg(feature = "grant")]
pub mod grant;
pub mod h2_road;
pub mod health;
pub mod http_road;
pub mod identity;
pub mod keyed;
pub mod open;
#[cfg(feature = "opentunnel")]
pub mod opentunnel;
#[cfg(feature = "pair")]
pub mod pair;
#[cfg(feature = "piping")]
pub mod piping;
pub mod pool;
// The rank of the relay hosts as measured from this host (T-606).
pub mod quick;
pub mod rank;
// A rank made in a session's background, with RelayRank auto alone (T-608).
pub mod rank_auto;
// The default list in the rank's order, and the samples of each race (T-607).
pub mod rank_list;
pub mod relay;
#[cfg(feature = "pair")]
pub mod reverse;
#[cfg(feature = "serve")]
pub mod serve;
pub mod session;
pub mod token;
pub mod transit;
pub mod udp;

pub use open::{open, Failure, OpenError, Opened, Request};
pub use relay::{Relay, DEFAULT_RELAY_HOST, RELAY_ENV};
