//! podssh-ws — reaching the relay: TCP (directly or through an HTTP CONNECT
//! proxy), TLS with podssh's own pure-Rust crypto provider, and RFC 6455.
//! With `--direct` on Linux, TCP can be Multipath TCP on request (`mptcp`).
//! A WebSocket that the user names is dialed with no token (`url`), and a
//! server's side of the handshake answers a client of `podssh pipe
//! ws-listen:` (`server`, T-368). A forwarder of another product carries a
//! target that a template names, over the same dial (`forwarder`, T-369).
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
pub mod clock;
mod close;
pub mod cloudflare;
pub mod crypto;
pub mod dial;
// The road of AWS's EC2 Instance Connect Endpoint (T-351).
pub mod eice;
pub mod error;
// A forwarder of another product, which takes its target from the client
// (T-369).
pub mod forwarder;
pub mod frame;
pub mod handshake;
pub mod http;
// The road of GCP's Identity-Aware Proxy for TCP (T-351).
pub mod iap;
pub mod mptcp;
pub mod names;
#[cfg(feature = "plain-ws")]
pub mod plain;
pub mod proxy;
mod proxy_auth;
mod race;
pub mod resolve;
pub mod server;
pub mod session;
mod socks5;
pub mod stores;
pub mod text;
pub mod tls;
pub mod url;
mod wire;
pub mod write_limit;

pub use client::{
    connect, doctor, https_get, https_post_json, ConnectError, Endpoint, WsClientConfig, DEFAULT_IDLE_TIMEOUT,
    DEFAULT_TIMEOUT, LIVENESS_ALLOWED, LIVENESS_EVERY,
};
pub use dial::{DialError, HttpProxy, Proxy, ProxyChoice, ProxyKind};
pub use error::{SessionError, Verdict, WsError};
pub use frame::Frame;
pub use session::RelaySession;
#[cfg(fuzzing)]
pub use socks5::fuzz_exchange;
pub use tls::Trust;
