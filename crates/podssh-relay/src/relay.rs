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

/// The hosts to try, in order. The first is also the key the token cache is
/// kept under: tokens from one relay deployment are valid on all its hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayList {
    pub hosts: Vec<Relay>,
    /// Whether the user named the hosts (then only those are tried).
    pub explicit: bool,
}

impl RelayList {
    /// The host the token cache is keyed by.
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
/// The host is restricted to the characters of DNS names and IPv4 literals,
/// so nothing a user types can add a path segment, a query string or a header
/// to the request.
pub fn forward_path(host: &str, port: u16) -> Result<String, String> {
    check_host(host)?;
    if port == 0 {
        return Err("port 0 is not a port".into());
    }
    Ok(format!("/connect/{host}/{port}"))
}

/// A host name or IPv4 literal: letters, digits, `.`, `-` and `_`, not
/// starting with `-` or `.`, at most 253 characters.
pub fn check_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("the host is empty".into());
    }
    if host.len() > 253 {
        return Err("the host name is longer than 253 characters".into());
    }
    if host.starts_with(['-', '.']) {
        return Err(format!("{host:?} is not a host name"));
    }
    if let Some(bad) = host.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))) {
        return Err(format!("{host:?} is not a host name ({bad:?} is not allowed)"));
    }
    Ok(())
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
}
