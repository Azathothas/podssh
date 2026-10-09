//! podssh-relay — reaching podssh's WebSocket-to-TCP relay, as a library.
//!
//! - [`relay`]: which relay hosts to use, in what order (an explicit list, or
//!   the default host followed by alternates from the relay's own pool);
//! - [`pool`]: the pool, as the relay publishes it, cached between runs;
//! - [`token`] and [`cache`]: tokens from the environment, the cache or a
//!   fresh mint, kept between runs in a private file, never printed;
//! - [`open`]: a forward session, failing over from host to host with backoff,
//!   one bounded attempt per host;
//! - `pair` (feature `pair`): the pairs of the reverse road, made, asked
//!   about and stopped on the relay's control host, kept in a private file;
//! - `reverse` (feature `pair`): the node and the operator of the reverse road;
//! - `blocking` (feature `blocking`): a synchronous facade over all of these,
//!   for a caller with no async runtime: it owns a runtime on the current
//!   thread, and refuses a call from inside a tokio runtime.
//!
//! No C compiler is needed (the gate builds this crate with
//! `CC=/nonexistent`), so other projects can depend on it.

#[cfg(feature = "blocking")]
pub mod blocking;
pub mod cache;
pub mod open;
#[cfg(feature = "pair")]
pub mod pair;
pub mod pool;
pub mod relay;
#[cfg(feature = "pair")]
pub mod reverse;
pub mod token;

pub use open::{open, Failure, OpenError, Opened, Request};
pub use relay::{Relay, DEFAULT_RELAY_HOST, RELAY_ENV};
