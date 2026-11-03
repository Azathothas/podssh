//! The direct road once each relay host failed (T-363), apart from
//! `transport.rs` for its length; and once a relay host opened a session to
//! an IPv6 target and closed it before any byte came, as a relay with no
//! IPv6 route out does (T-253). The dial keeps the family of `-4` or `-6`.

use std::net::SocketAddr;
use std::time::Duration;

use podssh_ssh::{Hop, Log, RelayEnd, RelayStatus};
use podssh_ws::ProxyChoice;
use tokio::net::TcpStream;

use super::{direct, multipath_asked, NotReached, Reached, MPTCP_ENV};
use crate::ssh::resolve::{Resolved, Transport};

/// How long the direct road after the relay hosts waits for the server's
/// version line (T-363): an SSH server sends it at once, and a proxy that
/// takes the CONNECT and carries no SSH sends nothing.
pub(super) const VERSION_WAIT: Duration = Duration::from_secs(10);

/// The direct road once each relay host failed (T-363): one dial of
/// `first`, as `--direct` makes it, of `family` when the run asked for one,
/// then the server's version line within [`VERSION_WAIT`], whose bytes go to
/// the SSH client first. When it fails too, the relay's lines, then one that
/// names both roads with their times; the exit stays the relay's.
pub(super) async fn after_relay(
    first: &Hop,
    family: Option<u8>,
    target: &str,
    relay: NotReached,
    relay_took: Duration,
    log: &Log,
) -> Result<Reached, NotReached> {
    let proxy = proxy_of(first);
    log.info(&announce(relay_took, target, proxy.as_deref()));
    once(first, family, target, relay, relay_took, proxy, log).await
}

/// Whether the relay opened the session of `resolved` to an IPv6 target and
/// then closed it before any byte came, as a relay with no IPv6 route out
/// does (T-253), on a run that may take the direct road: `relay` is the
/// relay leg's status of a try that reached nothing of the destination.
pub(crate) fn ipv6_unreached(resolved: &Resolved, relay: Option<&RelayStatus>) -> bool {
    let Transport::Relay { family, then_direct: true, .. } = &resolved.transport else { return false };
    let opts = &resolved.options;
    let first = opts.jump.first().unwrap_or(&opts.destination);
    let v6 = *family == Some(6) || podssh_relay::relay::is_ipv6_literal(&first.host);
    match relay.and_then(RelayStatus::get) {
        Some(RelayEnd::Closed { code, reason }) => v6 && podssh_relay::relay::unreached_ipv6(code, &reason),
        _ => false,
    }
}

/// The direct road once, after [`ipv6_unreached`], in place of another try
/// of the relay: `relay` holds the relay's lines, and `relay_took` its time.
/// When it fails too, the note names the roads that carry IPv6.
pub(crate) async fn after_ipv6_close(
    resolved: &Resolved,
    relay: NotReached,
    relay_took: Duration,
    log: &Log,
) -> Result<Reached, NotReached> {
    let opts = &resolved.options;
    let first = opts.jump.first().unwrap_or(&opts.destination);
    let family = match &resolved.transport {
        Transport::Relay { family, .. } => *family,
        _ => None,
    };
    let target = podssh_ws::dial::authority(&first.host, first.port);
    let proxy = proxy_of(first);
    log.info(&announce_ipv6(relay_took, &target, proxy.as_deref()));
    once(first, family, &target, relay, relay_took, proxy, log).await.map_err(|mut not| {
        let note = podssh_relay::relay::ipv6_note(true, podssh_relay::relay::NO_IPV6_ROUTE);
        not.lines.extend(note.map(str::to_string));
        not
    })
}

/// The proxy that the direct road's dial of `first` takes, by its place.
fn proxy_of(first: &Hop) -> Option<String> {
    podssh_ws::dial::proxy_from_env(&first.host).ok().flatten().map(|p| p.to_string())
}

/// One dial of `first`, then its version line, for [`after_relay`] and
/// [`after_ipv6_close`].
async fn once(
    first: &Hop,
    family: Option<u8>,
    target: &str,
    relay: NotReached,
    relay_took: Duration,
    proxy: Option<String>,
    log: &Log,
) -> Result<Reached, NotReached> {
    for line in &relay.lines {
        log.verbose(line);
    }
    let started = tokio::time::Instant::now();
    let failed = |why: String| {
        let mut lines = relay.lines.clone();
        lines.push(both_failed(relay_took, target, started.elapsed(), &why));
        NotReached { lines, code: relay.code }
    };
    let tcp = match dial(first, family, target, log).await {
        Ok(tcp) => tcp,
        Err(why) => return Err(failed(why)),
    };
    let _ = tcp.set_nodelay(true);
    let mut stream = podssh_ws::write_limit::WriteLimit::new(tcp, podssh_ws::client::WRITE_TIMEOUT);
    match crate::ssh::banner::read(&mut stream, VERSION_WAIT).await {
        Ok(read) => {
            log.verbose(&format!("the direct road carried the session to {target}"));
            let stream = Box::new(crate::ssh::banner::Prefixed::new(read, stream));
            Ok(Reached { stream, relay: None, direct_proxy: None, layer: None })
        }
        // A proxy that takes the CONNECT and carries no SSH is no road (T-317).
        Err(why) => Err(failed(match &proxy {
            Some(proxy) => format!(
                "the proxy {proxy} took the CONNECT, then {why}: no byte of an SSH server came back, as from a \
                 proxy that expects TLS and carries no SSH"
            ),
            None => format!("the connection opened, then {why}"),
        })),
    }
}

/// The direct road's dial: as `--direct` makes it, or, with `family`, the
/// addresses of that family alone, each in turn, as the relay's `?family`
/// keeps it (T-253); an address is of its own family. A name's addresses go
/// through the proxy that the name takes, as literals, since a proxy can
/// keep no family.
async fn dial(first: &Hop, family: Option<u8>, target: &str, log: &Log) -> Result<TcpStream, String> {
    let literal = first.host.parse::<std::net::IpAddr>().is_ok();
    let Some(family) = family.filter(|_| !literal) else {
        // A bad PODSSH_MPTCP asks for nothing here: the one dial is a plain one.
        let multipath = multipath_asked(std::env::var(MPTCP_ENV).ok().as_deref()).unwrap_or(false);
        return direct(&first.host, first.port, multipath, target, log).await.map_err(|e| e.to_string());
    };
    let deadline = tokio::time::Instant::now() + podssh_relay::open::CONNECT_TIMEOUT;
    let found = podssh_ws::resolve::resolve(&first.host, first.port, deadline)
        .await
        .map_err(|why| format!("could not resolve {}: {why}", first.host))?;
    let wanted: Vec<SocketAddr> = found.into_iter().filter(|a| a.is_ipv6() == (family == 6)).collect();
    if wanted.is_empty() {
        return Err(format!("{} has no IPv{family} address, as -{family} asks", first.host));
    }
    let proxy = match podssh_ws::dial::proxy_from_env(&first.host)? {
        Some(proxy) => ProxyChoice::Via(proxy),
        None => ProxyChoice::Direct,
    };
    let mut last = String::new();
    for address in wanted {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match podssh_ws::dial::dial(&address.ip().to_string(), address.port(), &proxy, left).await {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

/// The line before the direct road's dial: through a proxy, its CONNECT
/// names the target, which the relay's does not.
pub(super) fn announce(relay_took: Duration, target: &str, proxy: Option<&str>) -> String {
    format!(
        "each relay host failed, after {:.1} s; podssh tries {target} directly{} (PODSSH_DIRECT=no turns this \
         off; -v gives the relay's lines)",
        relay_took.as_secs_f32(),
        through(proxy)
    )
}

/// The line before the direct road's dial once the relay reached no IPv6
/// host (T-253).
pub(super) fn announce_ipv6(relay_took: Duration, target: &str, proxy: Option<&str>) -> String {
    format!(
        "the relay opened a session to {target}, then closed it before any byte came, as a relay with no IPv6 \
         route out does, after {:.1} s; podssh tries {target} directly{} (PODSSH_DIRECT=no turns this off; -v \
         gives the relay's lines)",
        relay_took.as_secs_f32(),
        through(proxy)
    )
}

/// The words of the proxy that the dial goes through, if any.
fn through(proxy: Option<&str>) -> String {
    proxy.map(|p| format!(", through the proxy {p}, whose CONNECT names it")).unwrap_or_default()
}

/// The line of both roads, each with its time, when both failed.
pub(super) fn both_failed(relay_took: Duration, target: &str, direct_took: Duration, why: &str) -> String {
    format!(
        "the relay road failed after {:.1} s, and the direct road to {target} after {:.1} s: {why}",
        relay_took.as_secs_f32(),
        direct_took.as_secs_f32()
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{announce, announce_ipv6};

    /// The line of the direct road after the relay reached no IPv6 host
    /// names the target and the switch, as the line after each host failed
    /// does (T-253).
    #[test]
    fn the_line_after_no_ipv6_host_names_the_target_and_the_switch() {
        let said = announce_ipv6(Duration::from_millis(900), "[2001:db8::7]:22", None);
        assert!(said.contains("closed it before any byte came, as a relay with no IPv6 route out does"), "{said}");
        assert!(said.contains("podssh tries [2001:db8::7]:22 directly (PODSSH_DIRECT=no"), "{said}");
        let via = announce_ipv6(Duration::ZERO, "h:22", Some("127.0.0.1:3128"));
        assert!(via.contains("directly, through the proxy 127.0.0.1:3128"), "{via}");
        assert!(announce(Duration::ZERO, "h:22", None).contains("podssh tries h:22 directly (PODSSH_DIRECT=no"));
    }
}
