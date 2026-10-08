//! podssh-ws — reaching the relay: TCP (directly or through an HTTP CONNECT
//! proxy), TLS with podssh's own pure-Rust crypto provider, and RFC 6455.
//!
//! Why a crypto provider of its own: rustls 0.23 ships none in pure Rust, and
//! `ring` and `aws-lc-sys` both need a C compiler, which podssh's default build
//! must not (measured 2026-10-01 with `CC=/nonexistent`). The provider has
//! completed handshakes against the live relay with a verified chain and
//! hostname (`tests/live_handshake.rs`).
//!
//! Verdicts from [`doctor`] are three-valued: `ok`, `FAIL`, and `????` for a
//! check that could not run, which is never reported as passing.

pub mod bundle;
pub mod client;
pub mod crypto;
pub mod dial;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod http;
pub mod probe;
pub mod session;
pub mod text;
pub mod tls;

pub use client::{
    connect, doctor, https_get, https_post_json, ConnectError, Endpoint, WsClientConfig, DEFAULT_IDLE_TIMEOUT,
    DEFAULT_TIMEOUT,
};
pub use dial::{DialError, HttpProxy, ProxyChoice};
pub use error::{Verdict, WsError};
pub use frame::Frame;
pub use session::RelaySession;
pub use tls::Trust;
