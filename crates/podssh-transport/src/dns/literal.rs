//! E15 — ⛔ **`Literal` short-circuits everything, and it is the first thing
//! `Chain` does.**
//!
//! ⛔ **READ**, `dropssh` `src/dns.c:314-315`, the sibling's own comment:
//! *"A literal address needs no resolver at all, and saying so is better than
//! asking a DoH server to resolve something that is already an address."* And
//! `src/dns.c:321` / `:327` set `*how = "literal"` and return **without touching
//! any other source**.
//!
//! ⛔ **A dotted quad or an IPv6 literal must never reach a resolver.** Asking a
//! DoH server to resolve something that is already an address is a round trip
//! that can fail for no reason — and on the constrained host, where the whole
//! point of E15 is that a round trip can fail, "for no reason" is a real failure
//! mode.
//!
//! ⛔ **Strictness is deliberate and is not `std`'s leniency.** `ToSocketAddrs`
//! accepts `"127.1"`, `"1.2.3"`, and `::ffff:1.2.3.4`; `Ipv4Addr::from_str`
//! accepts only four dotted decimal octets. ⛔ **This module uses only the
//! `std::net` parsers**, so what counts as a literal here is exactly what a Rust
//! program would dial, and a name that merely looks numeric — `1.2.3.4.5`,
//! `999.1.1.1` — falls through to a resolver and is refused there by name,
//! which is the useful message.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// ⛔ **Is this already an address?** ⛔ **Both families**, because the relay
/// publishes `?family=4` and `?family=6` (live spec line 199) and a v6-only
/// literal is still a literal.
pub fn as_literal(host: &str) -> Option<IpAddr> {
    // ⛔ A bracketed form is stripped here so a caller may pass either spelling.
    // A host string with `[` in it is never a name, and `Ipv6Addr::from_str`
    // rejects the brackets, so without this a valid `[::1]` would fall through
    // to a resolver.
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(v4) = bare.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    if let Ok(v6) = bare.parse::<Ipv6Addr>() {
        return Some(IpAddr::V6(v6));
    }
    None
}

/// ⛔ **Whether the host cannot be anything but a name.** ⛔ Used by the chain to
/// refuse an empty or whitespace host *before* a resolver is asked, because
/// ⛔ **`getaddrinfo("")` has platform-defined behaviour and podssh does not
/// inherit platform-defined behaviour.**
pub fn looks_like_an_address(host: &str) -> bool {
    as_literal(host).is_some()
}

/// ⛔ **The literal's one address, with a port.**
pub fn address(host: &str, port: u16) -> Option<SocketAddr> {
    as_literal(host).map(|ip| SocketAddr::new(ip, port))
}