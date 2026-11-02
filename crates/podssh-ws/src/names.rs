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
        // A proxy and the relay take a name in ASCII, and podssh has no
        // IDNA of its own: the name's ASCII form is the remedy (T-503).
        if !bad.is_ascii() {
            return Err(format!(
                "{host:?} is not a host name ({bad:?} is not allowed: give the name in its ASCII form, whose \
                 labels beyond ASCII begin xn--)"
            ));
        }
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

/// The longest zone of an IPv6 literal that [`check_direct_target`] takes:
/// an interface's name is 15 bytes on Linux, its index a few digits.
const MOST_ZONE: usize = 64;

/// A host that this host dials itself, or an SSH server for it (T-503):
/// what [`check_target`] accepts, or an IPv6 literal with a zone
/// (`fe80::1%eth0`, `fe80::1%12`), whose interface only a dial from that
/// host can name. The zone is letters, digits, `.`, `-` and `_`.
pub fn check_direct_target(host: &str) -> Result<(), String> {
    let Some((address, zone)) = host.split_once('%') else { return check_target(host) };
    let named = !zone.is_empty()
        && zone.len() <= MOST_ZONE
        && zone.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    match (address.parse::<std::net::Ipv6Addr>(), named) {
        (Ok(_), true) => Ok(()),
        (Ok(_), false) => Err(format!("{host:?}: the zone after '%' is not an interface's name or index")),
        (Err(_), _) => Err(format!("{host:?} is not a host name or an IPv6 address ('%' names the zone of one)")),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// One rule on each road (T-503): the relay's names, and on the direct
    /// road also the zone of an IPv6 literal; each other character, a blank
    /// and a control character are refused, and a name beyond ASCII is told
    /// its ASCII form.
    #[test]
    fn names_of_each_road_and_their_refusals() {
        for good in ["example.org", "a-b_c.example", "example.org.", "10.0.0.1", "2001:db8::1", "::1"] {
            assert_eq!(check_target(good), Ok(()), "{good}");
            assert_eq!(check_direct_target(good), Ok(()), "{good}, directly");
        }
        for bad in ["a$b", "a!b", "a/b", "a b", " ", "a\tb", "a\u{1b}b", "a;b", "a`b", "a@b", "a%b", "-a", ".a", ""] {
            assert!(check_target(bad).is_err(), "{bad:?}");
            assert!(check_direct_target(bad).is_err(), "{bad:?}, directly");
        }
        assert_eq!(check_direct_target("fe80::1%eth0"), Ok(()));
        assert_eq!(check_direct_target("fe80::1%12"), Ok(()));
        assert!(check_target("fe80::1%eth0").is_err(), "the relay cannot use a zone of this host");
        for bad in ["fe80::1%", "fe80::1%eth 0", "fe80::1%a/b", "fe80::1%eth0%1", "host%eth0"] {
            assert!(check_direct_target(bad).is_err(), "{bad:?}");
        }
        let why = check_target("bücher.example").unwrap_err();
        assert!(why.contains("ASCII form") && why.contains("xn--"), "{why}");
        assert_eq!(check_host("a$b").unwrap_err(), "\"a$b\" is not a host name ('$' is not allowed)");
    }
}
