//! podssh-relay — reaching podssh's WebSocket-to-TCP relay, as a library.
//!
//! - [`relay`]: which relay hosts to use, in what order (an explicit list, or
//!   the default host followed by alternates from the relay's own pool);
//! - [`pool`]: the pool, as the relay publishes it, cached between runs;
//! - [`token`] and [`cache`]: tokens from the environment, the cache or a
//!   fresh mint, kept between runs in a private file, never printed;
//! - [`open`]: a forward session, failing over from host to host with backoff,
//!   one bounded attempt per host.
//!
//! No C compiler is needed (the gate builds this crate with
//! `CC=/nonexistent`), so other projects can depend on it.

pub mod cache;
pub mod open;
pub mod pool;
pub mod relay;
pub mod token;

pub use open::{open, Failure, OpenError, Opened, Request};
pub use relay::{Relay, DEFAULT_RELAY_HOST, RELAY_ENV};
