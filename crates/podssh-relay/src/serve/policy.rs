//! Which targets the relay role dials (T-169): a name is resolved first, and
//! each address is checked, so that a name that resolves into a private
//! network is refused as its address would be (`docs/relay.md`, "Limits that
//! users see"). Port 25 is refused, as on the default relay. A relay that
//! its owner runs in a private network, or a test on the loopback, allows
//! private addresses by asking for it. Through the host's proxy (T-457,
//! `super::egress`), the checked addresses are what the proxy is asked for.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::egress::{Egress, Plan};

/// What the relay dials.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Private, loopback and other non-public addresses are dialed too.
    pub private: bool,
    /// Ports that are never dialed.
    pub denied_ports: Vec<u16>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { private: false, denied_ports: vec![25] }
    }
}

/// A target that the policy refuses: the words of a `403` that names it, as
/// the client reads a policy refusal ("not in the ALLOW list").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The policy's: `403`.
    Policy(String),
    /// No address: `502`.
    Unreachable(String),
}

impl Policy {
    /// What to dial for `host:port` through `egress` (T-457): the addresses
    /// of [`Policy::addresses`], each checked; or the name as it came, for
    /// the proxy to resolve, where nothing is checked (`--allow-private`),
    /// no family is asked, and the name goes through a proxy.
    pub async fn plan(&self, host: &str, port: u16, family: Option<u8>, egress: &Egress) -> Result<Plan, Refused> {
        if self.by_name(host, family, egress) {
            self.port_allowed(host, port)?;
            return Ok(Plan::Name(host.to_string(), port));
        }
        self.addresses(host, port, family).await.map(Plan::Addresses)
    }

    /// Whether the name goes to the proxy as it came: nothing of it is to
    /// check, and a proxy can give no family.
    pub fn by_name(&self, host: &str, family: Option<u8>, egress: &Egress) -> bool {
        self.private && family.is_none() && host.parse::<IpAddr>().is_err() && egress.proxy_for(host).is_some()
    }

    /// The addresses to dial for `host:port`, of `family` (4 or 6) when one
    /// is asked, each one that the policy allows.
    pub async fn addresses(&self, host: &str, port: u16, family: Option<u8>) -> Result<Vec<SocketAddr>, Refused> {
        let target = shown(host, port);
        self.port_allowed(host, port)?;
        let found: Vec<SocketAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| Refused::Unreachable(format!("cannot reach {target}: {e}")))?
                .collect(),
        };
        let wanted: Vec<SocketAddr> = found
            .into_iter()
            .filter(|a| match family {
                Some(4) => a.is_ipv4(),
                Some(6) => a.is_ipv6(),
                _ => true,
            })
            .collect();
        if wanted.is_empty() {
            return Err(Refused::Unreachable(format!("cannot reach {target}: no address of the family asked for")));
        }
        if self.private {
            return Ok(wanted);
        }
        // Every address is checked: a name that gives one private address
        // among public ones is refused, as it could be steered to it.
        if let Some(inside) = wanted.iter().find(|a| !public(a.ip())) {
            return Err(Refused::Policy(format!(
                "{target} not in the ALLOW list: it resolves to {}, which is not a public address",
                inside.ip()
            )));
        }
        Ok(wanted)
    }

    /// `Err` for a port that is never dialed, before any name resolves.
    fn port_allowed(&self, host: &str, port: u16) -> Result<(), Refused> {
        match self.denied_ports.contains(&port) {
            true => {
                Err(Refused::Policy(format!("{} not in the ALLOW list: port {port} is refused", shown(host, port))))
            }
            false => Ok(()),
        }
    }
}

/// `host:port`, an IPv6 literal in brackets.
pub fn shown(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Whether `ip` is an address of the public internet.
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let reserved = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        // CGNAT (RFC 6598), the IETF's assignments, benchmarking (RFC 2544).
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19));
    !reserved
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let s = ip.segments();
    let reserved = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link-local
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64, which reaches IPv4 behind it
        || s[0] == 0x2002 // 6to4, likewise
        || (s[0] == 0x2001 && s[1] == 0) // Teredo
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0]) // discard-only
        || s[0..6] == [0, 0, 0, 0, 0, 0]; // IPv4-compatible, deprecated
    !reserved
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn private_and_special_addresses_are_not_public() {
        for text in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "2001:db8::1",
            "64:ff9b::a00:1",
            "2002:a00:1::1",
            "::ffff:10.0.0.1",
            "ff02::1",
            "2001::1",
        ] {
            assert!(!public(ip(text)), "{text} is not public");
        }
        for text in ["140.82.112.3", "1.1.1.1", "2606:4700::1111", "::ffff:140.82.112.3", "100.128.0.1"] {
            assert!(public(ip(text)), "{text} is public");
        }
    }

    #[tokio::test]
    async fn port_25_and_a_private_literal_are_refused_as_policy() {
        let policy = Policy::default();
        let port25 = policy.addresses("140.82.112.3", 25, None).await.unwrap_err();
        assert!(matches!(&port25, Refused::Policy(w) if w.contains("ALLOW list")), "{port25:?}");
        let inside = policy.addresses("10.0.0.1", 22, None).await.unwrap_err();
        assert!(matches!(&inside, Refused::Policy(w) if w.contains("10.0.0.1")), "{inside:?}");
        let allowed = Policy { private: true, ..Policy::default() };
        assert_eq!(allowed.addresses("127.0.0.1", 22, None).await.unwrap().len(), 1);
        let family = allowed.addresses("127.0.0.1", 22, Some(6)).await.unwrap_err();
        assert!(matches!(family, Refused::Unreachable(_)));
    }
}
