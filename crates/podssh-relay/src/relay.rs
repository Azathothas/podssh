//! Which relay hosts podssh talks to, in what order, and the forward path for
//! a target.
//!
//! The default relay is compiled in so podssh works on a host with no setup
//! (operator decision 2026-10-08). `--relay-host` or the `PODSSH_RELAY`
//! environment variable replace it with an ordered list of hosts. With no list
//! given, the default host comes first and alternates from the relay's own
//! pool follow ([`crate::pool`]), so one unreachable host, or a proxy that
//! refuses one name, does not stop podssh. This is the only place the default
//! name appears in library code.

/// The relay podssh uses when nothing else is configured.
pub const DEFAULT_RELAY_HOST: &str = "tcp.ssh.relay.ajam.dev";

/// Environment variable that replaces the relay: `host`, `host:port`, or an
/// ordered list of them separated by commas.
pub const RELAY_ENV: &str = "PODSSH_RELAY";

/// The relay closes a session after this many seconds with no traffic (its
/// `/relays.json`, version 2026-10-03-r2), so keepalives must come sooner.
pub const RELAY_IDLE_SECS: u64 = 180;

/// How many pool hosts follow the default host when no list is given. Each
/// failed host costs one bounded attempt; a handful covers a dead host or a
/// proxy that refuses one name without making a hopeless run slow.
pub const MAX_ALTERNATES: usize = 3;

/// A relay to connect to: TLS on `port` (443 unless stated), certificate
/// checked against `host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub host: String,
    pub port: u16,
}

/// The hosts to try, in order. The first is also the key of the cached pool
/// of hosts; a token is cached for each deployment (`token::token_key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayList {
    pub hosts: Vec<Relay>,
    /// Whether the user named the hosts (then only those are tried).
    pub explicit: bool,
}

impl RelayList {
    /// The first host: the key of the cached pool.
    pub fn primary(&self) -> &Relay {
        &self.hosts[0]
    }
}

/// The hosts to use: the flag, else `PODSSH_RELAY`, else the default followed
/// by up to [`MAX_ALTERNATES`] of `pool` (hosts of the default relay's own
/// pool, best first).
pub fn select_relays(flag: Option<&str>, env: Option<String>, pool: &[String]) -> Result<RelayList, String> {
    let chosen = flag
        .map(str::to_string)
        .or_else(|| env.filter(|v| !v.trim().is_empty()));
    if let Some(value) = chosen {
        let hosts = parse_relay_list(&value)?;
        return Ok(RelayList { hosts, explicit: true });
    }
    let mut hosts = vec![Relay { host: DEFAULT_RELAY_HOST.to_string(), port: 443 }];
    for host in pool {
        if hosts.len() > MAX_ALTERNATES {
            break;
        }
        if let Ok(relay) = parse_relay(host) {
            if !hosts.contains(&relay) {
                hosts.push(relay);
            }
        }
    }
    Ok(RelayList { hosts, explicit: false })
}

/// An ordered list: hosts separated by commas, each as [`parse_relay`]
/// accepts it. Commas only: splitting on spaces too would turn one mistyped
/// value (`"not a host"`) into a list of plausible hosts. Duplicates are
/// dropped; an empty list is an error.
pub fn parse_relay_list(value: &str) -> Result<Vec<Relay>, String> {
    let mut hosts: Vec<Relay> = Vec::new();
    for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let relay = parse_relay(item)?;
        if !hosts.contains(&relay) {
            hosts.push(relay);
        }
    }
    if hosts.is_empty() {
        return Err(format!("no relay host in {value:?}"));
    }
    Ok(hosts)
}

/// Accepts `host`, `host:port`, and the same with an `https://` or `wss://`
/// prefix and an optional trailing `/`, since that is how the relay's own
/// documents write it.
pub fn parse_relay(value: &str) -> Result<Relay, String> {
    let trimmed = value.trim();
    let without_scheme = ["https://", "wss://"]
        .iter()
        .find_map(|s| trimmed.strip_prefix(s))
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    let (host, port) = match without_scheme.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| format!("bad relay port in {value:?}"))?),
        None => (without_scheme, 443),
    };
    check_host(host).map_err(|why| format!("bad relay {value:?}: {why}"))?;
    if port == 0 {
        return Err(format!("bad relay port in {value:?}"));
    }
    Ok(Relay { host: host.to_ascii_lowercase(), port })
}

/// The relay's forward path for `host:port`: `/connect/<host>/<port>`.
///
/// The host is a DNS name, an IPv4 literal or a bare IPv6 literal (see
/// [`check_target`]), so nothing a user types can add a path segment, a
/// query string or a header to the request. The relay takes the bare IPv6
/// literal in the path (measured 2026-10-08), and `:` is valid in a path
/// segment (RFC 3986), where `[` and `]` are not.
pub fn forward_path(host: &str, port: u16) -> Result<String, String> {
    check_target(host)?;
    if port == 0 {
        return Err("port 0 is not a port".into());
    }
    Ok(format!("/connect/{host}/{port}"))
}

/// The checks of a host, a target and a pair name, defined once in
/// `podssh-ws` for each crate that builds a relay path.
pub use podssh_ws::names::{check_host, check_node_name, check_target};

/// Whether `host` is an IPv6 literal (with no brackets).
pub fn is_ipv6_literal(host: &str) -> bool {
    host.parse::<std::net::Ipv6Addr>().is_ok()
}

/// A note for a session to an IPv6 target that the relay closed with
/// `reason`. The relay takes IPv6 targets, but on 2026-10-08 its egress
/// reached none: each such session closed at once with this reason, while
/// IPv4 to the same hosts worked.
pub fn ipv6_note(ipv6_target: bool, reason: &str) -> Option<&'static str> {
    (ipv6_target && reason.contains("target closed before sending anything"))
        .then_some("an IPv6 target that closes at once usually means that the relay has no IPv6 route out")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_relay_comes_first_then_pool_alternates() {
        let pool: Vec<String> = ["a.example", "b.example", "tcp.ssh.relay.ajam.dev", "c.example", "d.example"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let list = select_relays(None, None, &pool).unwrap();
        assert!(!list.explicit);
        let hosts: Vec<&str> = list.hosts.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, vec![DEFAULT_RELAY_HOST, "a.example", "b.example", "c.example"]);
        assert_eq!(list.primary().host, DEFAULT_RELAY_HOST);
        let alone = select_relays(None, Some("  ".into()), &[]).unwrap();
        assert_eq!(alone.hosts, vec![Relay { host: DEFAULT_RELAY_HOST.into(), port: 443 }]);
    }

    #[test]
    fn the_flag_beats_the_environment_and_lists_are_kept_as_given() {
        let list = select_relays(Some("flag.example"), Some("env.example".into()), &["pool.example".into()]).unwrap();
        assert!(list.explicit);
        assert_eq!(list.hosts, vec![Relay { host: "flag.example".into(), port: 443 }]);
        let list = select_relays(None, Some("one.example:8443, two.example ,three.example,one.example:8443".into()), &[]).unwrap();
        let hosts: Vec<(&str, u16)> = list.hosts.iter().map(|r| (r.host.as_str(), r.port)).collect();
        assert_eq!(hosts, vec![("one.example", 8443), ("two.example", 443), ("three.example", 443)]);
        assert!(select_relays(Some(", ,"), None, &[]).is_err());
        assert!(select_relays(Some("good.example,bad host!"), None, &[]).is_err());
        assert!(select_relays(Some("not a host"), None, &[]).is_err(), "spaces never separate hosts");
    }

    #[test]
    fn relay_spellings_from_the_relays_documents_are_accepted() {
        for v in ["wss://tcp-1.ssh.relay.example/", "https://tcp-1.ssh.relay.example", "TCP-1.ssh.relay.example"] {
            assert_eq!(parse_relay(v).unwrap().host, "tcp-1.ssh.relay.example", "{v}");
        }
        assert!(parse_relay("relay.example:0").is_err());
        assert!(parse_relay("relay.example:http").is_err());
        assert!(parse_relay("relay example").is_err());
    }

    #[test]
    fn forward_paths_cannot_be_bent_by_the_target() {
        assert_eq!(forward_path("github.com", 22).unwrap(), "/connect/github.com/22");
        assert_eq!(forward_path("10.1.2.3", 2222).unwrap(), "/connect/10.1.2.3/2222");
        for bad in ["", "a/b", "a?b", "a#b", "a b", "a\r\nX: y", "-oProxy", ".hidden", "[::1]", "a@b"] {
            assert!(forward_path(bad, 22).is_err(), "{bad:?}");
        }
        assert!(forward_path("github.com", 0).is_err());
    }

    /// A pair name goes into `/v1/node/<name>` and `/v1/connect/<name>`:
    /// refused, never encoded, when it could change the path.
    #[test]
    fn node_names_cannot_bend_the_path() {
        for good in ["podssh", "a.b_c-1", "A9", &"n".repeat(128)] {
            assert!(check_node_name(good).is_ok(), "{good:?}");
        }
        let long = "n".repeat(129);
        for bad in ["", "a/b", "a?b", "a#b", "..", ".", "-x", ".x", "a b", "a\r\nX: y", "a%2fb", "a:b", "é", &long] {
            assert!(check_node_name(bad).is_err(), "{bad:?}");
        }
    }

    /// The relay takes the bare literal (measured 2026-10-08); brackets are
    /// for the command line, never for the path.
    #[test]
    fn ipv6_literals_are_targets_and_zones_are_not() {
        assert_eq!(forward_path("2001:db8::1", 22).unwrap(), "/connect/2001:db8::1/22");
        assert_eq!(forward_path("::1", 8079).unwrap(), "/connect/::1/8079");
        // Eight groups: one address, not an address and a port.
        assert_eq!(forward_path("2001:db8::1:22", 22).unwrap(), "/connect/2001:db8::1:22/22");
        assert_eq!(forward_path("::ffff:192.0.2.1", 22).unwrap(), "/connect/::ffff:192.0.2.1/22");
        for bad in ["[2001:db8::1]", "fe80::1%eth0", "fe80::1%25eth0", "2001:db8::1/64", "2001:db8:::1", "a:b", "host:22", ":::"] {
            assert!(forward_path(bad, 22).is_err(), "{bad:?}");
            assert!(check_target(bad).is_err(), "{bad:?}");
        }
        assert!(is_ipv6_literal("2001:db8::1") && !is_ipv6_literal("[2001:db8::1]") && !is_ipv6_literal("192.0.2.1"));
        // Relay hosts stay TLS names, with no IPv6 literal.
        assert!(parse_relay("2001:db8::1").is_err());
    }

    #[test]
    fn ipv6_note_only_for_an_ipv6_target_that_the_relay_closed_at_once() {
        assert!(ipv6_note(true, "target closed before sending anything").is_some());
        assert!(ipv6_note(false, "target closed before sending anything").is_none());
        assert!(ipv6_note(true, "idle timeout").is_none());
    }
}
