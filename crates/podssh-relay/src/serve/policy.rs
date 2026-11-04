//! Which targets the relay role dials (T-169): a name is resolved first, and
//! each address is checked, so that a name that resolves into a private
//! network is refused as its address would be (`docs/relay.md`, "Limits that
//! users see"). Port 25 is refused, as on the default relay. A relay that
//! its owner runs in a private network, or a test on the loopback, allows
//! private addresses by asking for it. Through the host's proxy (T-457,
//! `super::egress`), the checked addresses are what the proxy is asked for.
//! An IPv6 address that this host cannot route out is refused before any
//! dial (T-253, `super::ipv6`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::egress::{Egress, Plan};
use super::ipv6::Ipv6Out;

/// What the relay dials.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Private, loopback and other non-public addresses are dialed too.
    pub private: bool,
    /// Ports that are never dialed.
    pub denied_ports: Vec<u16>,
    /// What this host's way out to IPv6 is known to be (T-253).
    pub ipv6: Ipv6Out,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { private: false, denied_ports: vec![25], ipv6: Ipv6Out::default() }
    }
}

/// A target that the policy refuses: the words of a `403` that names it, as
/// the client reads a policy refusal ("not in the ALLOW list").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The policy's, in words that are the same for each target of its
    /// kind (a port): `403`.
    Policy(String),
    /// A name that the role does not dial for what its resolver found (no
    /// address, none of the family asked for, or one that is not public):
    /// `403`, in one sentence for each such cause, so that a caller cannot
    /// map the role's network by names (GitHub #126). `why` is for the
    /// operator's log alone.
    NotDialed { target: String, why: String },
    /// The role's own fault, which another relay host may not have: `502`.
    Unreachable(String),
}

impl Refused {
    /// The status of the answer.
    pub fn status(&self) -> u16 {
        match self {
            Refused::Policy(_) | Refused::NotDialed { .. } => 403,
            Refused::Unreachable(_) => 502,
        }
    }

    /// The words that the caller gets, after `road: `: never what the
    /// resolver found for a name.
    pub fn said(&self) -> String {
        match self {
            Refused::Policy(why) | Refused::Unreachable(why) => why.clone(),
            Refused::NotDialed { target, .. } => {
                format!("{target} not in the ALLOW list: this relay dials no address of it")
            }
        }
    }

    /// The answer's words with the road's word first: `forward:` for a
    /// refusal, `relay:` for the role's own fault, as the client reads them.
    pub fn answer(&self) -> String {
        match self {
            Refused::Unreachable(_) => format!("relay: {}", self.said()),
            _ => format!("forward: {}", self.said()),
        }
    }

    /// The operator's line, which keeps the cause that the caller loses.
    pub fn logged(&self) -> Option<String> {
        match self {
            Refused::NotDialed { target, why } => Some(format!("refused {target}: {why}")),
            _ => None,
        }
    }
}

impl Policy {
    /// What to dial for `host:port` through `egress` (T-457): the addresses
    /// of [`Policy::addresses`], each checked; or the name as it came, for
    /// the proxy to resolve, where nothing is checked (`--allow-private`),
    /// no family is asked, and the name goes through a proxy. An IPv6
    /// address that this host dials and cannot route is left out, and a
    /// target with no other is unreachable, before the upgrade (T-253).
    pub async fn plan(&self, host: &str, port: u16, family: Option<u8>, egress: &Egress) -> Result<Plan, Refused> {
        if self.by_name(host, family, egress) {
            self.port_allowed(host, port)?;
            return Ok(Plan::Name(host.to_string(), port));
        }
        let plan = self.addresses(host, port, family).await.map(Plan::Addresses)?;
        let refused = |why: String| Refused::Unreachable(format!("cannot reach {}: {why}", shown(host, port)));
        self.ipv6.keep(plan, host, egress).map_err(refused)
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
                .map_err(|e| Refused::NotDialed { target: target.clone(), why: format!("no address: {e}") })?
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
            let why = format!("no address of the family asked for, IPv{}", family.unwrap_or(0));
            return Err(Refused::NotDialed { target, why });
        }
        if self.private {
            return Ok(wanted);
        }
        // Every address is checked: a name that gives one private address
        // among public ones is refused, as it could be steered to it.
        if let Some(inside) = wanted.iter().find(|a| !public(a.ip())) {
            let why = format!("it resolves to {}, which is not a public address", inside.ip());
            return Err(Refused::NotDialed { target, why });
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
        assert_eq!(inside.status(), 403, "{inside:?}");
        assert!(inside.logged().is_some_and(|l| l.contains("10.0.0.1, which is not a public address")), "{inside:?}");
        let allowed = Policy { private: true, ..Policy::default() };
        assert_eq!(allowed.addresses("127.0.0.1", 22, None).await.unwrap().len(), 1);
        let family = allowed.addresses("127.0.0.1", 22, Some(6)).await.unwrap_err();
        assert!(matches!(family, Refused::NotDialed { .. }), "{family:?}");
    }

    // GitHub #126: a name that does not resolve, one that resolves to a
    // private address, and one of no address of the family asked for get
    // the same words, which name no address; the operator's line keeps it.
    #[tokio::test]
    async fn a_private_target_and_a_missing_name_are_both_not_dialed() {
        let policy = Policy::default();
        let private = policy.addresses("localhost", 22, None).await.unwrap_err();
        let missing = policy.addresses("no-such-name.invalid", 22, None).await.unwrap_err();
        let family = policy.addresses("140.82.112.3", 22, Some(6)).await.unwrap_err();
        for (refused, target) in
            [(&private, "localhost:22"), (&missing, "no-such-name.invalid:22"), (&family, "140.82.112.3:22")]
        {
            assert_eq!(refused.status(), 403, "{refused:?}");
            assert_eq!(
                refused.answer(),
                format!("forward: {target} not in the ALLOW list: this relay dials no address of it")
            );
            assert!(!refused.answer().contains("127.0.0.1") && !refused.answer().contains("public"), "{refused:?}");
        }
        assert!(private.logged().is_some_and(|l| l.contains("which is not a public address")), "{private:?}");
        assert!(missing.logged().is_some_and(|l| l.contains("no address")), "{missing:?}");
    }

    #[test]
    fn the_roles_own_fault_stays_a_502_with_its_words() {
        let fault = Refused::Unreachable("cannot reach a.example:22: no route out to IPv6".into());
        assert_eq!(
            (fault.status(), fault.answer()),
            (502, "relay: cannot reach a.example:22: no route out to IPv6".into())
        );
        assert!(fault.logged().is_none());
        let port = Refused::Policy("a.example:25 not in the ALLOW list: port 25 is refused".into());
        assert_eq!(
            (port.status(), port.answer()),
            (403, "forward: a.example:25 not in the ALLOW list: port 25 is refused".into())
        );
    }
}
