//! The addresses of the exit's own host (T-432). A range of `--routes`
//! that holds one of them, or a loopback address, would let the net's
//! members reach the services of the node's host itself, which listen for
//! its own users: a wide range (10.0.0.0/8, or ::/0) must not do that by
//! accident, so such an address is dialled only when a range names it
//! alone. The host's addresses are read at each dial, as they change, from
//! the system's list of interfaces where one is read (`getifaddrs` on
//! Unix); a connection whose two ends have one address is the host's own
//! too, which catches what the list missed (Windows, an address added
//! between the read and the dial).

use std::net::{IpAddr, SocketAddr};

use crate::net::policy_words::Range;

/// What makes `ip` the host's own: a loopback or unspecified address, which
/// reaches the host itself, or one of `own`; none for another host's.
pub(crate) fn kind(ip: IpAddr, own: &[IpAddr]) -> Option<&'static str> {
    // An IPv4 address written in IPv6 reaches the same host.
    let plain = ip.to_canonical();
    if plain.is_loopback() || plain.is_unspecified() {
        return Some("a loopback address of the exit's host");
    }
    own.iter().any(|mine| mine.to_canonical() == plain).then_some("an address of the exit's host")
}

/// Why the exit does not dial `ip` of `shown`, the host's own (`what`),
/// when no range of `ranges` names it alone; none when one does.
pub(crate) fn refused(shown: &str, ip: IpAddr, what: &str, ranges: &[Range]) -> Option<String> {
    if ranges.iter().any(|range| range.names_alone(ip)) {
        return None;
    }
    Some(format!(
        "{shown} resolves to {ip}, {what}: a range of the exit's --routes lets it in only when it names that address \
         alone, as {ip}"
    ))
}

/// Whether a connection from `local` to `peer`, dialled at `target`, went
/// to the host itself: straight to the target (no proxy between), and from
/// the same address.
pub(crate) fn looped(local: SocketAddr, peer: SocketAddr, target: SocketAddr) -> bool {
    peer.ip().to_canonical() == target.ip().to_canonical() && local.ip().to_canonical() == peer.ip().to_canonical()
}

/// The host's addresses, from the list of its interfaces; none where it
/// cannot be read.
#[cfg(unix)]
pub(crate) fn addresses() -> Vec<IpAddr> {
    let mut found = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list that freeifaddrs frees,
    // once each entry has been read.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return found;
    }
    let mut at = head;
    while !at.is_null() {
        // SAFETY: each entry of the list lives until freeifaddrs.
        let entry = unsafe { &*at };
        if !entry.ifa_addr.is_null() {
            // SAFETY: ifa_addr points at a sockaddr whose family says its
            // form, and the forms read here are the ones of that family.
            let family = i32::from(unsafe { (*entry.ifa_addr).sa_family });
            if family == libc::AF_INET {
                let sin = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                found.push(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
            } else if family == libc::AF_INET6 {
                let sin6 = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                found.push(IpAddr::from(sin6.sin6_addr.s6_addr));
            }
        }
        at = entry.ifa_next;
    }
    // SAFETY: `head` came from getifaddrs, and nothing reads it after.
    unsafe { libc::freeifaddrs(head) };
    found
}

/// No list is read here: the connection's own check stands alone.
#[cfg(not(unix))]
pub(crate) fn addresses() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_loopback_and_the_host_s_own_addresses_need_a_range_that_names_them_alone() {
        let own = [ip("10.88.0.1"), ip("fd00::5")];
        assert!(kind(ip("127.0.0.2"), &own).unwrap().starts_with("a loopback"));
        assert!(kind(ip("::1"), &own).unwrap().starts_with("a loopback"));
        assert!(kind(ip("::ffff:127.0.0.1"), &own).unwrap().starts_with("a loopback"), "IPv4 written in IPv6");
        assert!(kind(ip("0.0.0.0"), &own).is_some() && kind(ip("::"), &own).is_some(), "the unspecified address");
        assert_eq!(kind(ip("10.88.0.1"), &own), Some("an address of the exit's host"));
        assert_eq!(kind(ip("::ffff:10.88.0.1"), &own), Some("an address of the exit's host"));
        assert_eq!(kind(ip("10.88.0.2"), &own), None);
        let wide = [Range::parse("10.0.0.0/8").unwrap(), Range::parse("127.0.0.0/8").unwrap()];
        let why = refused("db:5432", ip("10.88.0.1"), "an address of the exit's host", &wide).unwrap();
        assert!(why.contains("names that address alone, as 10.88.0.1"), "{why}");
        assert!(refused("x:1", ip("127.0.0.2"), "a loopback address", &wide).is_some());
        for alone in ["10.88.0.1", "10.88.0.1/32"] {
            let named = [Range::parse(alone).unwrap()];
            assert!(refused("db:5432", ip("10.88.0.1"), "an address", &named).is_none(), "{alone}");
        }
    }

    #[test]
    fn a_connection_with_one_address_at_both_ends_went_to_the_host_itself() {
        let at = |text: &str| text.parse::<SocketAddr>().unwrap();
        assert!(looped(at("10.88.0.1:40000"), at("10.88.0.1:22"), at("10.88.0.1:22")));
        assert!(!looped(at("10.88.0.1:40000"), at("10.88.0.7:22"), at("10.88.0.7:22")), "another host");
        // Through a proxy the peer is the proxy, which the exit's check of
        // the target does not judge.
        assert!(!looped(at("127.0.0.1:40000"), at("127.0.0.1:3128"), at("10.88.0.1:22")));
    }

    #[cfg(unix)]
    #[test]
    fn the_host_s_list_holds_its_loopback() {
        let found = addresses();
        assert!(found.iter().any(|a| a.is_loopback()), "{found:?}");
    }
}
