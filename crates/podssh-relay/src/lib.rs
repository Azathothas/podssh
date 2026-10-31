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
//! - `pair` (feature `pair`): the pairs of the reverse road, made, asked
//!   about and stopped on the relay's control host, kept in a private file;
//! - `reverse` (feature `pair`): the node and the operator of the reverse road;
//! - [`session`]: the resumable layer between two podssh ends: its records,
//!   offsets and handshake, and its client and far end over tokio streams;
//! - [`identity`]: who an end is: its key file, its fingerprint, a node's
//!   allowlist and an operator's pins, the same on each road;
//! - [`e2e`]: the channel between two podssh ends, Noise XX above the
//!   resumable layer, in which each end proves its key;
//! - [`udp`]: UDP in a stream (T-168): each datagram after its length, and
//!   the flow at the far end, a UDP socket connected to the target;
//! - [`quick`]: a quick tunnel of Cloudflare's that podssh makes itself, with
//!   no `cloudflared` (T-300): the registration's Cap'n Proto and its RPC,
//!   and the headers of its answers;
//! - `derp` (feature `derp`): the DERP road (T-349), through Tailscale's
//!   servers for tailcat or a derper of the user's own, with an adapter
//!   under the resumable layer that sends again what a server drops;
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
#[cfg(feature = "derp")]
pub mod derp;
pub mod e2e;
pub mod failover;
pub mod failures;
pub mod health;
pub mod identity;
pub mod open;
#[cfg(feature = "pair")]
pub mod pair;
pub mod pool;
pub mod quick;
pub mod relay;
#[cfg(feature = "pair")]
pub mod reverse;
pub mod session;
pub mod token;
pub mod udp;

pub use open::{open, Failure, OpenError, Opened, Request};
pub use relay::{Relay, DEFAULT_RELAY_HOST, RELAY_ENV};
