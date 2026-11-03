//! The hosts of a run that something dials, checked before anything
//! connects (T-503): the first hop by the rule of its road, and each host
//! after it (a later hop of `-J`, then the destination) by the rule of a dial
//! from the SSH server before it. One rule on each road, so that a name that
//! the relay road refuses with 64 is not passed to a proxy or a resolver on
//! the direct road, to fail there with 255. The check of `podssh_ws::dial`
//! stays, for its other callers.

use podssh_ssh::Hop;
use podssh_ws::names::{check_direct_target, check_target};

/// What dials the first hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Road {
    /// The relay hosts, or the servers that take their place: a host name,
    /// an IPv4 or an IPv6 literal, as the relay takes them.
    Relay,
    /// This host, through `HTTPS_PROXY` when one is set (`--direct`): also
    /// an IPv6 literal with the zone of an interface of this host.
    Direct,
    /// A tunnel to the first hop of `-J` (`cf://`, `iap://`, `eice://`),
    /// whose name is the tunnel's own, checked where it was read.
    Tunnel,
}

/// The first hop by `road`'s rule, and each host after it by a dial's from
/// the server before it: `jump` holds the hops of `-J`, and `host` is the
/// destination, each after its `HostName`. The refusal's words are the
/// relay road's, with the road that would have dialed.
pub(super) fn check(road: Road, jump: &[Hop], host: &str) -> Result<(), String> {
    let hosts: Vec<&str> = jump.iter().map(|hop| hop.host.as_str()).chain([host]).collect();
    for (at, name) in hosts.iter().enumerate() {
        let refused = match (at, road) {
            (0, Road::Tunnel) => continue,
            (0, Road::Relay) => check_target(name).map_err(|why| format!("{} through the relay: {why}", reach(name))),
            (0, Road::Direct) => check_direct_target(name).map_err(|why| format!("{} directly: {why}", reach(name))),
            _ => check_direct_target(name)
                .map_err(|why| format!("{} through the jump host {}: {why}", reach(name), shown(hosts[at - 1]))),
        };
        refused?;
    }
    Ok(())
}

/// The refusals of `--direct` before anything connects: `-4` and `-6`,
/// which only the relay's dial takes, then the hosts of [`check`].
pub(super) fn direct(family: Option<u8>, jump: &[Hop], host: &str) -> Result<(), String> {
    if family.is_some() {
        return Err("-4/-6 select the address family the relay dials; with --direct they are not supported yet".into());
    }
    check(Road::Direct, jump, host)
}

/// The head of a refusal: the host that cannot be reached.
fn reach(name: &str) -> String {
    format!("cannot reach {}", shown(name))
}

/// A name as typed when each of its characters prints as itself, else in
/// quotes with its escapes: a blank or a control character is seen, and
/// never reaches the terminal as it is.
fn shown(name: &str) -> String {
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_graphic()) {
        name.to_string()
    } else {
        format!("{name:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(host: &str) -> Hop {
        Hop { user: Some("u".into()), host: host.into(), port: 22, tls: false }
    }

    /// The first hop by its road; each later host by a dial's from the hop
    /// before it, which may name a zone of its own interface.
    #[test]
    fn each_host_is_checked_by_what_dials_it() {
        assert_eq!(check(Road::Relay, &[], "example.org"), Ok(()));
        let why = check(Road::Relay, &[], "a$b").unwrap_err();
        assert_eq!(why, "cannot reach a$b through the relay: \"a$b\" is not a host name ('$' is not allowed)");
        let why = check(Road::Direct, &[], "a b").unwrap_err();
        assert!(why.starts_with("cannot reach \"a b\" directly: "), "{why}");
        assert_eq!(check(Road::Direct, &[], "fe80::1%eth0"), Ok(()));
        assert!(check(Road::Relay, &[], "fe80::1%eth0").is_err());
        // Behind a jump host, the destination is the jump host's dial.
        assert_eq!(check(Road::Relay, &[hop("bastion.example")], "fe80::1%eth0"), Ok(()));
        let why = check(Road::Direct, &[hop("bastion.example")], "a!b").unwrap_err();
        assert!(why.starts_with("cannot reach a!b through the jump host bastion.example: "), "{why}");
        assert!(check(Road::Relay, &[hop("a/b")], "example.org").unwrap_err().contains("through the relay"));
        // A tunnel's name is the tunnel's; the host after it is checked.
        assert_eq!(check(Road::Tunnel, &[hop("cf://tunnel.example")], "example.org"), Ok(()));
        assert!(check(Road::Tunnel, &[hop("cf://tunnel.example")], "a$b").is_err());
        assert!(direct(Some(4), &[], "example.org").unwrap_err().starts_with("-4/-6 "));
    }
}
