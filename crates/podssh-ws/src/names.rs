//! The names that go into a relay path: a host for the forward path, and the
//! name of a reverse pair. Each one is checked, never encoded: a `/`, `?`,
//! `#`, `..`, a space or a line break would change the request (another path,
//! a query string, a fragment, a broken request line), and a percent-encoded
//! `/` hides a different path. One definition, for `podssh-relay`, which
//! builds the relay paths.

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

/// A host for the relay to dial: what [`check_host`] accepts, or an IPv6
/// literal with no brackets. A zone id (`%eth0`) does not parse, and a zone
/// names a link-local address, which the relay refuses anyway.
pub fn check_target(host: &str) -> Result<(), String> {
    if host.contains(':') {
        return match host.parse::<std::net::Ipv6Addr>() {
            Ok(_) => Ok(()),
            Err(_) => Err(format!("{host:?} is not a host name or an IPv6 address")),
        };
    }
    check_host(host)
}

/// The name of a reverse pair, in `/v1/node/<name>` and `/v1/connect/<name>`:
/// 1 to 128 bytes of letters, digits, `.`, `-` and `_`, not starting with
/// `-` or `.` (so never `.` or `..`). The contract gives no form for a pair
/// name; this is podbox's rule, which works against the live relay.
pub fn check_node_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the pair name is empty".into());
    }
    if name.len() > 128 {
        return Err("the pair name is longer than 128 characters".into());
    }
    if name.starts_with(['-', '.']) {
        return Err(format!("{name:?} is not a pair name"));
    }
    if let Some(bad) = name.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))) {
        return Err(format!("{name:?} is not a pair name ({bad:?} is not allowed)"));
    }
    Ok(())
}
