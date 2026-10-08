//! Which relay podssh talks to, and the forward path for a target.
//!
//! The default relay is compiled in so podssh works on a host with no setup
//! (operator decision 2026-10-08). It can be overridden with `--relay-host`
//! or the `PODSSH_RELAY` environment variable. This is the only place the
//! default name appears in library code.

/// The relay podssh uses when nothing else is configured.
pub const DEFAULT_RELAY_HOST: &str = "tcp.ssh.relay.ajam.dev";

/// Environment variable that overrides the relay: `host` or `host:port`.
pub const RELAY_ENV: &str = "PODSSH_RELAY";

/// A relay to connect to: TLS on `port` (443 unless stated), certificate
/// checked against `host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub host: String,
    pub port: u16,
}

/// The relay to use: the flag, else `PODSSH_RELAY`, else the default.
pub fn select_relay(flag: Option<&str>, env: Option<String>) -> Result<Relay, String> {
    let chosen = flag
        .map(str::to_string)
        .or_else(|| env.filter(|v| !v.trim().is_empty()));
    match chosen {
        Some(value) => parse_relay(&value),
        None => Ok(Relay { host: DEFAULT_RELAY_HOST.to_string(), port: 443 }),
    }
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
    fn the_default_relay_is_used_when_nothing_is_set() {
        assert_eq!(
            select_relay(None, None).unwrap(),
            Relay { host: DEFAULT_RELAY_HOST.into(), port: 443 }
        );
        assert_eq!(select_relay(None, Some("  ".into())).unwrap().host, DEFAULT_RELAY_HOST);
    }

    #[test]
    fn the_flag_beats_the_environment() {
        let r = select_relay(Some("flag.example"), Some("env.example".into())).unwrap();
        assert_eq!(r.host, "flag.example");
        assert_eq!(select_relay(None, Some("env.example:8443".into())).unwrap().port, 8443);
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
