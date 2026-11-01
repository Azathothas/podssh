//! The direct road once each relay host failed (T-363), apart from
//! `transport.rs` for its length.

use std::time::Duration;

use podssh_ssh::{Hop, Log};

use super::{direct, multipath_asked, NotReached, Reached, MPTCP_ENV};

/// How long the direct road after the relay hosts waits for the server's
/// version line (T-363): an SSH server sends it at once, and a proxy that
/// takes the CONNECT and carries no SSH sends nothing.
pub(super) const VERSION_WAIT: Duration = Duration::from_secs(10);

/// The direct road once each relay host failed (T-363): one dial of
/// `first`, as `--direct` makes it, then the server's version line within
/// [`VERSION_WAIT`], whose bytes go to the SSH client first. When it fails
/// too, the relay's lines, then one that names both roads with their times;
/// the exit stays the relay's.
pub(super) async fn after_relay(
    first: &Hop,
    target: &str,
    relay: NotReached,
    relay_took: Duration,
    log: &Log,
) -> Result<Reached, NotReached> {
    let proxy = podssh_ws::dial::proxy_from_env(&first.host).ok().flatten().map(|p| p.to_string());
    log.info(&announce(relay_took, target, proxy.as_deref()));
    for line in &relay.lines {
        log.verbose(line);
    }
    let started = tokio::time::Instant::now();
    let failed = |why: String| {
        let mut lines = relay.lines.clone();
        lines.push(both_failed(relay_took, target, started.elapsed(), &why));
        NotReached { lines, code: relay.code }
    };
    // A bad PODSSH_MPTCP asks for nothing here: the one dial is a plain one.
    let multipath = multipath_asked(std::env::var(MPTCP_ENV).ok().as_deref()).unwrap_or(false);
    let tcp = match direct(&first.host, first.port, multipath, target, log).await {
        Ok(tcp) => tcp,
        Err(e) => return Err(failed(e.to_string())),
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

/// The line before the direct road's dial: through a proxy, its CONNECT
/// names the target, which the relay's does not.
pub(super) fn announce(relay_took: Duration, target: &str, proxy: Option<&str>) -> String {
    let via = proxy.map(|p| format!(", through the proxy {p}, whose CONNECT names it")).unwrap_or_default();
    format!(
        "each relay host failed, after {:.1} s; podssh tries {target} directly{via} (PODSSH_DIRECT=no turns this \
         off; -v gives the relay's lines)",
        relay_took.as_secs_f32()
    )
}

/// The line of both roads, each with its time, when both failed.
pub(super) fn both_failed(relay_took: Duration, target: &str, direct_took: Duration, why: &str) -> String {
    format!(
        "the relay road failed after {:.1} s, and the direct road to {target} after {:.1} s: {why}",
        relay_took.as_secs_f32(),
        direct_took.as_secs_f32()
    )
}
