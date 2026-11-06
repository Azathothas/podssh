//! podssh-warp — WARP's MASQUE road over HTTP/2 (T-352): Cloudflare's own
//! network carries a TCP stream to any target, from a host whose only way
//! out is HTTPS on port 443, with no account. The operator allowed it on
//! 2026-10-31 (Q52, `docs/decisions.md`).
//!
//! The road, as usque (Diniboy1123/usque) and its fork of connect-ip-go
//! speak it, read on 2026-10-31 (`docs/carriers.md`, the forward road, item
//! 4):
//!
//! - [`register`]: a device, registered once with the API of Cloudflare's
//!   app (`POST /reg`), then given a P-256 key and the tunnel type `masque`
//!   (`PATCH /reg/ID`), whose answer gives the endpoint's key and the
//!   device's addresses; [`device`] keeps them, for a private file. Each
//!   request goes by the [`routes`] of the API in turn (T-562).
//! - [`tls`]: TLS 1.3 with ALPN `h2` and the name [`server_name`], the
//!   device's self-signed certificate ([`key`], [`der`]), and the endpoint's
//!   key pinned: no root signs the endpoint, and a proxy that re-terminates
//!   TLS is named, never trusted.
//! - [`tunnel`]: one CONNECT over HTTP/2, `cf-connect-proto: cf-connect-ip`,
//!   whose bodies carry IP packets in capsules ([`capsule`]).
//! - [`stack`] and [`stream`]: TCP inside, on smoltcp, in this process;
//!   [`dns`]: names asked of Cloudflare's resolver inside the tunnel.
//! - [`road`]: all of it, as one call that opens the tunnel and one that
//!   opens a stream to `HOST:PORT`; a front door that shows another key
//!   than the pinned one sends it to the API for the device's record again
//!   (T-399).
//! - [`probe`]: one connection inside a tunnel that has just opened, so that
//!   a front door which takes TLS and relays nothing is named as such
//!   (T-560).
//! - [`endpoints`]: the device's endpoints in turn, the one that last opened
//!   first, then the record's and the API's peers, one at a time (T-561).
//!
//! Its rules are podssh's: one outbound connection, through `HTTPS_PROXY`
//! when one is set; no listener and no TUN device; no credential in output.
//! The C-free rule of the library crates holds here too.

pub mod capsule;
pub mod der;
pub mod device;
pub mod dns;
pub mod endpoints;
pub mod flow;
// The far end of the stand-in takes connections inside its tunnel.
#[cfg(any(test, feature = "stand-in"))]
pub mod inside;
pub mod key;
mod phy;
pub mod probe;
pub mod register;
pub mod road;
pub mod routes;
pub mod stack;
#[cfg(any(test, feature = "stand-in"))]
pub mod stand_in;
pub mod stream;
pub mod tls;
pub mod tunnel;

#[cfg(test)]
mod tests;

pub use device::Device;
pub use road::{Fault, Warp};
pub use stream::Stream;

/// WARP: the service `cloudflare-warp` of `pod-services`, which holds its
/// API, its front doors, its versions and its Terms.
pub fn service() -> &'static pod_services::Service {
    pod_services::get("cloudflare-warp").expect("pod-services holds the service cloudflare-warp")
}

/// The front door of MASQUE over HTTP/2: the endpoint `masque-v4`.
fn front_door() -> &'static pod_services::Endpoint {
    service().endpoint("masque-v4").expect("cloudflare-warp of pod-services has the endpoint masque-v4")
}

/// The endpoint of HTTP/2, an address: the names of MASQUE had no A record
/// on 2026-10-31, and usque's HTTP/2 mode dials this one (its
/// `config/endpoints.go`, `DefaultEndpointH2V4`).
pub fn endpoint_h2() -> std::net::SocketAddr {
    front_door().socket_addrs().first().copied().expect("masque-v4 of pod-services has an address")
}
/// The port of HTTP/2 at each endpoint, the API's peers too (T-561): the
/// port of a peer in the API's answer is QUIC's or WireGuard's, or 0.
pub fn port_h2() -> u16 {
    front_door().port()
}
/// The name that the client sends in TLS (usque's `internal/consts.go`,
/// `ConnectSNI`).
pub fn server_name() -> &'static str {
    front_door().server_name()
}
/// The authority of the CONNECT (usque's `ConnectURI`, the fact
/// `connect-uri`, with the port that connect-ip-go adds).
pub fn authority() -> String {
    let uri = service().text("connect-uri").expect("cloudflare-warp of pod-services holds the fact connect-uri");
    format!("{}:443", uri.strip_prefix("https://").unwrap_or(uri))
}
/// The MTU of the tunnel: usque's default, and IPv6's minimum.
pub const MTU: usize = 1280;
/// The Terms that a registration accepts, which the user accepts first: the
/// fact `terms-url`.
pub fn terms_url() -> &'static str {
    service().text("terms-url").expect("cloudflare-warp of pod-services holds the fact terms-url")
}
