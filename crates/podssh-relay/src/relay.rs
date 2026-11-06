//! Which relay hosts podssh talks to, in what order, and the forward path for
//! a target.
//!
//! The default relay is compiled in so podssh works on a host with no setup
//! (operator decision 2026-10-08). `--relay-host` or the `PODSSH_RELAY`
//! environment variable replace it with an ordered list of hosts. With no list
//! given, the default host comes first and alternates from the relay's own
//! pool follow ([`crate::pool`]), so one unreachable host, or a proxy that
//! refuses one name, does not stop podssh. The default deployment, its host
//! and its limits are data of `pod-services` (the service `ajam-relay`).

/// The default deployment of the relay: the service `ajam-relay` of
/// `pod-services`, which holds its host, its limits and its seed.
pub fn deployment() -> &'static pod_services::Service {
    pod_services::get("ajam-relay").expect("pod-services holds the service ajam-relay")
}

/// A limit of the default deployment, a whole number.
fn limit(name: &str) -> u64 {
    let value = deployment().int(name).and_then(|n| u64::try_from(n).ok());
    value.unwrap_or_else(|| panic!("ajam-relay of pod-services holds no fact {name}"))
}

/// The relay podssh uses when nothing else is configured.
pub fn default_relay_host() -> &'static str {
    deployment().endpoint("default").map(|e| e.host()).expect("ajam-relay of pod-services has the endpoint default")
}

/// Environment variable that replaces the relay: `host`, `host:port`, or an
/// ordered list of them separated by commas.
pub const RELAY_ENV: &str = "PODSSH_RELAY";

/// The relay closes a session after this many seconds with no traffic (its
/// `/relays.json`; the fact `idle-timeout-ms`), so keepalives must come
/// sooner.
pub fn relay_idle_secs() -> u64 {
    limit("idle-timeout-ms") / 1000
}

/// The relay ends a session after this many payload bytes, both ways
/// together, with `1009 session byte cap` (the fact `max-session-bytes`).
pub fn session_byte_cap() -> u64 {
    limit("max-session-bytes")
}

/// The relay ends a session after this long (the fact `max-session-ms`).
pub fn session_time_cap() -> std::time::Duration {
    std::time::Duration::from_millis(limit("max-session-ms"))
}

/// podssh's own byte budget for one session, under the cap: the relay
/// counts bytes that podssh has not read yet, and can hold 2 MiB queued, so a
/// copy opens a new session first (T-137). The IRC transfer keeps the same
/// margin for the same reason.
pub const SESSION_BYTE_BUDGET: u64 = 60 << 20;

/// podssh's time budget for one session, half an hour under the cap.
pub const SESSION_TIME_BUDGET: std::time::Duration = std::time::Duration::from_secs(11 * 3600 + 30 * 60);

/// Lowers the byte budget, for a relay with smaller caps or a test; it never
/// raises it.
pub const SESSION_BUDGET_ENV: &str = "PODSSH_SESSION_BUDGET";

/// The byte budget, with `env` (the value of [`SESSION_BUDGET_ENV`]) lowering
/// it: a whole number of bytes, at least 1 MiB. Any other value is ignored.
/// Under the limits of the relay that the run uses ([`byte_budget_under`]).
pub fn byte_budget(env: Option<&str>) -> u64 {
    byte_budget_under(env, &crate::pool::in_use())
}

/// The byte budget under a relay's `limits` (T-342): the compiled-in one, or
/// less with the same margin when the relay's `max_session_bytes` is
/// smaller; a larger one never raises it. Then `env` lowers it.
pub fn byte_budget_under(env: Option<&str>, limits: &crate::pool::Limits) -> u64 {
    let margin = session_byte_cap() - SESSION_BYTE_BUDGET;
    let under = limits.max_session_bytes.and_then(|cap| cap.checked_sub(margin)).filter(|n| *n >= 1 << 20);
    let budget = under.map_or(SESSION_BYTE_BUDGET, |n| n.min(SESSION_BYTE_BUDGET));
    env.and_then(|v| v.trim().parse::<u64>().ok()).filter(|n| *n >= 1 << 20).map_or(budget, |n| n.min(budget))
}

/// The time budget under a relay's `limits` (T-342): the compiled-in one, or
/// half an hour under a smaller `max_session_ms`.
pub fn time_budget(limits: &crate::pool::Limits) -> std::time::Duration {
    let margin = session_time_cap() - SESSION_TIME_BUDGET;
    let under = limits.max_session_ms.map(std::time::Duration::from_millis).and_then(|cap| cap.checked_sub(margin));
    under.filter(|d| !d.is_zero()).map_or(SESSION_TIME_BUDGET, |d| d.min(SESSION_TIME_BUDGET))
}

/// The relay's idle cut under its `limits` (T-342): the compiled-in one, or
/// a smaller `idle_timeout_ms`.
pub fn idle_secs(limits: &crate::pool::Limits) -> u64 {
    let given = limits.idle_timeout_ms.map(|ms| ms / 1000).filter(|s| *s > 0);
    given.map_or(relay_idle_secs(), |s| s.min(relay_idle_secs()))
}

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
    let chosen = flag.map(str::to_string).or_else(|| env.filter(|v| !v.trim().is_empty()));
    if let Some(value) = chosen {
        let hosts = parse_relay_list(&value)?;
        return Ok(RelayList { hosts, explicit: true });
    }
    let mut hosts = vec![Relay { host: default_relay_host().to_string(), port: 443 }];
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

/// The default list followed by `others`, the hosts of other deployments
/// that a signed list names (T-346, [`crate::pool::kept::other_hosts`]),
/// each once; a list that the user named stays the relay alone.
pub fn with_others(mut list: RelayList, others: Vec<Relay>) -> RelayList {
    if list.explicit {
        return list;
    }
    for relay in others {
        if !list.hosts.contains(&relay) {
            list.hosts.push(relay);
        }
    }
    list
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
    let without_scheme =
        ["https://", "wss://"].iter().find_map(|s| trimmed.strip_prefix(s)).unwrap_or(trimmed).trim_end_matches('/');
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

/// The path of a node's socket, `/v1/node/<name>`, for a name that cannot
/// change the path ([`check_node_name`]).
pub fn node_path(name: &str) -> Result<String, String> {
    check_node_name(name)?;
    Ok(format!("/v1/node/{name}"))
}

/// The path of an operator's socket, `/v1/connect/<name>`.
pub fn operator_path(name: &str) -> Result<String, String> {
    check_node_name(name)?;
    Ok(format!("/v1/connect/{name}"))
}

/// The checks of a host, a target and a pair name, defined once in
/// `podssh-ws` for each crate that builds a relay path.
pub use podssh_ws::names::{check_host, check_node_name, check_target};

/// Whether `host` is an IPv6 literal (with no brackets).
pub fn is_ipv6_literal(host: &str) -> bool {
    host.parse::<std::net::Ipv6Addr>().is_ok()
}

/// The words of podssh's relay role for an IPv6 target that its host cannot
/// route out (T-253): its `502` before the upgrade, or its `1011` when a lazy
/// dial meets it after the upgrade.
pub const NO_IPV6_ROUTE: &str = "this relay's host has no IPv6 route out";

/// The default relay's reason for each session to an IPv6 target on
/// 2026-10-08, while IPv4 to the same hosts worked: its egress reached none.
const CLOSED_AT_ONCE: &str = "target closed before sending anything";

/// Whether a relay's Close of a session to an IPv6 target says that the
/// relay reached no IPv6 host (T-253): the default relay's `1011` with
/// [`CLOSED_AT_ONCE`], or the role's own words.
pub fn unreached_ipv6(code: Option<u16>, reason: &str) -> bool {
    code == Some(1011) && (reason.contains(CLOSED_AT_ONCE) || reason.contains(NO_IPV6_ROUTE))
}

/// A note for a session to an IPv6 target that the relay closed with
/// `reason`, the default relay's or the role's: the roads that carry IPv6.
pub fn ipv6_note(ipv6_target: bool, reason: &str) -> Option<&'static str> {
    (ipv6_target && (reason.contains(CLOSED_AT_ONCE) || reason.contains(NO_IPV6_ROUTE))).then_some(
        "an IPv6 target that closes at once usually means that the relay has no IPv6 route out: a relay of \
         yours on a host with IPv6 (podssh relay serve, then --relay-host), a node with IPv6 egress (-J \
         node://NAME) or warp://[ADDR] can carry it",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_budget_is_under_its_cap() {
        // The byte budget stays under the cap, with room for what the relay
        // can hold queued.
        assert!(SESSION_BYTE_BUDGET < session_byte_cap() && session_byte_cap() - SESSION_BYTE_BUDGET >= 2 << 20);
        assert!(SESSION_TIME_BUDGET < session_time_cap());
        // The idle cut is far shorter than either: keepalives handle it.
        assert!(std::time::Duration::from_secs(relay_idle_secs()) < SESSION_TIME_BUDGET);
    }

    #[test]
    fn the_budget_variable_lowers_the_budget_and_never_raises_it() {
        assert_eq!(byte_budget(None), SESSION_BYTE_BUDGET);
        assert_eq!(byte_budget(Some("3000000")), 3_000_000);
        assert_eq!(byte_budget(Some(" 4194304 ")), 4 << 20);
        assert_eq!(byte_budget(Some("999999999999")), SESSION_BYTE_BUDGET, "never above the budget");
        for ignored in ["", "abc", "-5", "1000", "3e6"] {
            assert_eq!(byte_budget(Some(ignored)), SESSION_BYTE_BUDGET, "{ignored:?}");
        }
    }

    #[test]
    fn the_default_relay_comes_first_then_pool_alternates() {
        let pool: Vec<String> = ["a.example", "b.example", "tcp.ssh.relay.ajam.dev", "c.example", "d.example"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let list = select_relays(None, None, &pool).unwrap();
        assert!(!list.explicit);
        let hosts: Vec<&str> = list.hosts.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, vec![default_relay_host(), "a.example", "b.example", "c.example"]);
        assert_eq!(list.primary().host, default_relay_host());
        let alone = select_relays(None, Some("  ".into()), &[]).unwrap();
        assert_eq!(alone.hosts, vec![Relay { host: default_relay_host().into(), port: 443 }]);
    }

    /// T-346: the hosts of other deployments follow the default list, each
    /// once; a list that the user named takes none.
    #[test]
    fn the_pool_then_other_deployments_follow_the_default_host() {
        let other = |h: &str| Relay { host: h.into(), port: 443 };
        let default = select_relays(None, None, &["a.ssh.relay.ajam.dev".into()]).unwrap();
        let others = vec![other("relay.example.org"), other("a.ssh.relay.ajam.dev"), other("relay.example.org")];
        let list = with_others(default, others);
        let hosts: Vec<&str> = list.hosts.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, vec![default_relay_host(), "a.ssh.relay.ajam.dev", "relay.example.org"]);
        let named = with_others(select_relays(Some("mine.example"), None, &[]).unwrap(), vec![other("b.example")]);
        assert_eq!(named.hosts, vec![other("mine.example")], "a list that the user named is the relay alone");
    }

    #[test]
    fn the_flag_beats_the_environment_and_lists_are_kept_as_given() {
        let list = select_relays(Some("flag.example"), Some("env.example".into()), &["pool.example".into()]).unwrap();
        assert!(list.explicit);
        assert_eq!(list.hosts, vec![Relay { host: "flag.example".into(), port: 443 }]);
        let list =
            select_relays(None, Some("one.example:8443, two.example ,three.example,one.example:8443".into()), &[])
                .unwrap();
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

    /// The paths of the contract's table of addresses.
    #[test]
    fn the_paths_are_the_published_ones() {
        assert_eq!(forward_path("github.com", 22).unwrap(), "/connect/github.com/22");
        assert_eq!(node_path("podssh").unwrap(), "/v1/node/podssh");
        assert_eq!(operator_path("podssh").unwrap(), "/v1/connect/podssh");
    }

    /// No name or host bends a path: each that could is refused before a path
    /// exists, and never encoded, as an encoded `/` hides another path.
    #[test]
    fn names_cannot_bend_the_path() {
        let long_name = "n".repeat(129);
        let long_host = "h".repeat(254);
        for bad in ["a/b", "a?b", "a#b", "..", ".", "-x", "a b", "a\r\nX-Injected: 1", ""] {
            assert!(forward_path(bad, 22).is_err(), "{bad:?}");
            assert!(node_path(bad).is_err(), "{bad:?}");
            assert!(operator_path(bad).is_err(), "{bad:?}");
        }
        assert!(forward_path(&long_host, 22).is_err());
        assert!(node_path(&long_name).is_err() && operator_path(&long_name).is_err());
        assert_eq!(node_path("a.b_c-1").unwrap(), "/v1/node/a.b_c-1");
        assert_eq!(operator_path("a.b_c-1").unwrap(), "/v1/connect/a.b_c-1");
        assert_eq!(forward_path("2001:db8::1", 22).unwrap(), "/connect/2001:db8::1/22");
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
        for bad in [
            "[2001:db8::1]",
            "fe80::1%eth0",
            "fe80::1%25eth0",
            "2001:db8::1/64",
            "2001:db8:::1",
            "a:b",
            "host:22",
            ":::",
        ] {
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
        // The role's words (T-253), and the roads that the note names.
        let note = ipv6_note(true, &format!("connect failed: {NO_IPV6_ROUTE}")).unwrap();
        assert!(note.contains("podssh relay serve") && note.contains("node://NAME") && note.contains("warp://"));
    }

    /// The Close of a relay that reached no IPv6 host (T-253): the default
    /// relay's, and the role's after a lazy dial; no other.
    #[test]
    fn a_close_that_says_the_relay_reached_no_ipv6_host() {
        assert!(unreached_ipv6(Some(1011), "target closed before sending anything"));
        assert!(unreached_ipv6(Some(1011), &format!("connect failed: {NO_IPV6_ROUTE} ([2001:db8::7]:22: x)")));
        for (code, reason) in [
            (Some(1000), "target closed before sending anything"),
            (Some(1011), "connect failed: refused"),
            (Some(1011), "write failed: reset"),
            (None, "target closed before sending anything"),
        ] {
            assert!(!unreached_ipv6(code, reason), "{code:?} {reason}");
        }
    }
}
