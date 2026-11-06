//! podssh-ws — reaching the relay: TCP (directly or through an HTTP CONNECT
//! or SOCKS5 proxy, the dial of `pod-proxy` with podssh's settings: `dial`),
//! TLS with the pure-Rust crypto provider of `pod-tls`, and RFC 6455. With
//! `--direct` on Linux, TCP can be Multipath TCP on request (`mptcp`).
//! A WebSocket that the user names is dialed with no token (`url`), and a
//! server's side of the handshake answers a client of `podssh pipe
//! ws-listen:` (`server`, T-368). A forwarder of another product carries a
//! target that a template names, over the same dial (`forwarder`, T-369),
//! and a Shadowsocks server one that its address header names, over TCP
//! (`shadowsocks`, T-373). Tor's two pluggable transports for a bridge,
//! meek_lite and WebTunnel, are spoken here too (`meek`, `webtunnel`,
//! T-385), so that the Tor road needs no other program. A forward proxy
//! that the user runs over TLS carries a target that CONNECT names, over
//! HTTP/1.1 or HTTP/2 (`via`, T-439). A server of the Wisp protocol carries
//! many TCP streams over one WebSocket (`wisp`, T-438), as a forwarder of
//! `wisp+wss://` too. A VLESS server of the user's carries a target that
//! VLESS's header names, over a WebSocket or XHTTP (`vless`, T-440), and a
//! wstunnel server one that its token names (`wstunnel`, T-441). The same
//! upgrade goes with no TLS on the relay's port (`cleartext`, T-326), last,
//! for a proxy that cuts TLS that it does not know. Where a relay offers it,
//! as podssh's relay role does, the sessions of a process are streams of one
//! HTTP/2 connection, by RFC 8441's extended CONNECT (`h2_road`, T-321).
//!
//! Why a crypto provider of its own: rustls 0.23 ships none in pure Rust, and
//! `ring` and `aws-lc-sys` both need a C compiler, which podssh's default build
//! must not (measured 2026-10-01 with `CC=/nonexistent`). The provider is
//! `pod-tls`'s, with its feature `pure` (PodUtils/podcrates), as are the
//! trust, the TLS server's side and Encrypted Client Hello; [`tls`] holds
//! podssh's settings of them.
//!
//! Verdicts from [`doctor`] are three-valued: `ok`, `FAIL`, and `????` for a
//! check that could not run, which is never reported as passing.

pub mod bundle;
// chisel's WebSocket, to a server that the user runs (T-490).
pub mod chisel;
// The cleartext road on the relay's port, and the probe of GitHub #56 (T-326).
pub mod cleartext;
pub mod client;
pub mod clock;
mod close;
pub mod cloudflare;
// The pure-Rust crypto provider of pod-tls (feature `pure`).
pub use pod_tls::crypto;
// How a dial or a handshake ended, by the kind of its error (T-487), as
// pod-proxy reads it.
pub use pod_proxy::cut;
pub mod dial;
// Encrypted Client Hello, with the list of a name's HTTPS record, when the
// user asks for it (T-642).
pub mod ech;
// The road of AWS's EC2 Instance Connect Endpoint (T-351).
pub mod eice;
pub mod error;
// A forwarder of another product, which takes its target from the client
// (T-369).
pub mod forwarder;
pub mod frame;
// The WebSocket over HTTP/2's extended CONNECT (T-321).
pub mod h2_road;
pub mod handshake;
pub mod http;
// TCP_NOTSENT_LOWAT on each dialed socket (T-661), as pod-proxy sets it.
pub use pod_proxy::lowat;
// The road of GCP's Identity-Aware Proxy for TCP (T-351).
pub mod iap;
// Tor's meek_lite, for a bridge of the Tor road (T-385).
pub mod meek;
// Multipath TCP on the direct road (T-172), as pod-proxy dials it.
pub use pod_proxy::mptcp;
pub mod names;
#[cfg(feature = "plain-ws")]
pub mod plain;
// The proxy that a URL names (T-070), as pod-proxy parses it.
pub use pod_proxy::proxy;
// What meek_lite and WebTunnel share: a bridge's arguments, its URL, the
// connection (T-385).
pub mod pt;
pub mod resolve;
pub mod server;
pub mod session;
// A Shadowsocks server of the user's, in its AEAD form (T-373).
pub mod shadowsocks;
// The stores of trust that are not files, as pod-tls reads them.
pub use pod_tls::stores;
// STUN's messages, for doctor's line nat and the TURN road (T-641, T-621),
// as pod-proxy codes them.
pub use pod_proxy::stun;
pub mod text;
pub mod tls;
pub mod tls_server;
mod tls_wrap;
pub mod url;
// A second proxy over TLS, HTTP/1.1's and HTTP/2's CONNECT (T-439).
pub mod via;
// VLESS over a WebSocket and over XHTTP, to a server that the user runs
// (T-440).
pub mod vless;
// A tick of the clocks that tells a host that slept (T-663).
pub mod wake;
// Tor's WebTunnel, for a bridge of the Tor road (T-385).
pub mod webtunnel;
mod wire;
// Many TCP streams over one WebSocket, by the Wisp protocol (T-438).
pub mod wisp;
// A write that makes no progress fails at its limit, as pod-proxy bounds it.
pub use pod_proxy::write_limit;
// wstunnel's protocol, to a server that the user runs (T-441).
pub mod wstunnel;

pub use client::{
    connect, doctor, https_get, https_post_json, ConnectError, Endpoint, WsClientConfig, DEFAULT_IDLE_TIMEOUT,
    DEFAULT_TIMEOUT, LIVENESS_ALLOWED, LIVENESS_EVERY,
};
pub use cut::{Cut, Missed, TlsFailure};
pub use dial::{DialError, HttpProxy, Proxy, ProxyChoice, ProxyKind};
pub use error::{SessionError, Verdict, WsError};
pub use frame::Frame;
#[cfg(fuzzing)]
pub use pod_proxy::fuzz_exchange;
pub use session::RelaySession;
pub use tls::Trust;
pub use tls_wrap::tls_over;
