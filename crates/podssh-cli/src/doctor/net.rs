//! Egress: the proxy the environment names and what it lets through, and
//! podssh's TLS setup; name resolution is `names.rs`'s.

use std::time::{Duration, Instant};

use podssh_relay::relay::RelayList;
// The variables podssh reads for a proxy, in the order it reads them: the
// dialer's own list, so this report names the one that the dialer takes.
use podssh_ws::dial::{self, HttpProxy, ProxyChoice, PROXY_VARS};
use podssh_ws::{Trust, Verdict};

use super::samples::{sample, Tried};
use super::Report;

/// The bound on each network probe here and in `names.rs`.
pub(super) const PROBE: Duration = Duration::from_secs(8);

/// A host every proxy and resolver can be asked about. Its port 22 tells an
/// egress that lets SSH out from one that allows only HTTPS.
const REFERENCE_HOST: &str = "github.com";

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

pub(super) fn ms(since: Instant) -> u128 {
    since.elapsed().as_millis()
}

/// The proxy as configured, and the address actually reached when that is
/// not the same text (a proxy named by host name).
pub(super) fn proxy_reached(proxy: &HttpProxy, peer: &str) -> String {
    let named = proxy.to_string();
    if named == peer {
        named
    } else {
        format!("{named} ({peer})")
    }
}

/// The checks that open nothing: the proxy setting, the TLS provider and the
/// trust store. `trust_from` names the setting that chose `trust`.
pub(super) fn check_local(report: &mut Report<'_>, relays: &RelayList, trust: &Trust, trust_from: &str) {
    proxy_setting(report, &relays.primary().host);
    match podssh_ws::crypto::suites::self_check() {
        Ok(()) => report.ok("TLS provider", "podssh's own pure-Rust provider passed its self-check"),
        Err(why) => report.fail("TLS provider", why),
    }
    match podssh_ws::tls::roots_for(trust) {
        Ok(roots) => {
            let detail = match trust {
                Trust::File(path) => {
                    format!("{} anchors from {} ({trust_from}); nothing else is trusted", roots.count, path.display())
                }
                // The default store names its counts per source. (No other
                // form gets here: a caller's configuration has no roots to list.)
                _ if roots.source.contains(" + ") => format!("{} anchors: {}", roots.count, roots.source),
                _ => roots.source,
            };
            report.ok("trust store", detail);
        }
        Err(e) => report.fail("trust store", format!("{e} (chosen by {trust_from})")),
    }
    // A file chosen by the user replaces the compiled-in roots and the
    // system's stores.
    if *trust == Trust::Default {
        // Each store of Windows and macOS, with its count or why it gave
        // none (T-340); a system whose roots are files has no line.
        if let Some(stores) = podssh_ws::stores::summary(&podssh_ws::stores::read()) {
            report.ok("system stores", stores);
        }
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        roots_age(report, podssh_ws::tls::ROOTS_PUBLISHED, now);
    }
}

/// How old the compiled-in roots are, at `now` (seconds since the epoch). A
/// binary keeps the roots that it was built with, so a root that Mozilla
/// removed later stays trusted in it; a system bundle adds roots and removes
/// none. Old roots are said, not failed: podssh still works with them, and
/// a FAIL would fail every doctor run of an old binary.
fn roots_age(report: &mut Report<'_>, published: &str, now: i64) {
    let what = format!("the compiled-in roots are webpki-roots {} of {published}", podssh_ws::tls::ROOTS_VERSION);
    let Some(day) = super::clock::parse_day(published) else {
        report.unknown("roots age", format!("{what}, a date that cannot be read"));
        return;
    };
    let days = now.div_euclid(86_400) - day;
    if days < 0 {
        report.unknown("roots age", format!("{what}, and this host's clock is before that day"));
    } else if days > 365 {
        report.ok(
            "roots age",
            format!(
                "{what}, {} months old: older than 12 months. A newer podssh has newer roots; until \
                 then, --ca-file or SSL_CERT_FILE with a current bundle replaces them",
                days / 30
            ),
        );
    } else {
        report.ok("roots age", format!("{what}, {days} days old"));
    }
}

/// Which proxy podssh would use for the relay, named by its variable and
/// shown without credentials.
fn proxy_setting(report: &mut Report<'_>, relay_host: &str) {
    let named = PROXY_VARS.iter().find_map(|n| var(n).map(|v| (*n, v)));
    match (named, dial::proxy_from_env(relay_host)) {
        (named, Err(why)) => {
            let which = named.map(|(n, _)| n).unwrap_or("the proxy variable");
            report.fail("proxy", format!("{which} is set but cannot be used: {why}"));
        }
        (None, Ok(_)) => {
            let plain = if var("http_proxy").or_else(|| var("HTTP_PROXY")).is_some() {
                "; http_proxy is set, but it is for http:// URLs: podssh reads https_proxy, HTTPS_PROXY, \
                 all_proxy and ALL_PROXY"
            } else {
                ""
            };
            report.ok("proxy", format!("none set: podssh connects directly{plain}"));
        }
        (Some((name, _)), Ok(None)) => {
            let why = if dial::is_loopback(relay_host) {
                format!("{relay_host} is this host's own loopback, which never goes through a proxy")
            } else {
                // The entry that matched: a block (10.0.0.0/8) is not plain to see.
                let list = dial::NO_PROXY_VARS.iter().find_map(|n| var(n));
                match list.as_deref().and_then(|l| dial::no_proxy_entry(l, relay_host)) {
                    Some(entry) => format!("NO_PROXY's entry {entry} excludes {relay_host}"),
                    None => format!("NO_PROXY excludes {relay_host}"),
                }
            };
            report.ok("proxy", format!("{name} is set, but {why}, so podssh connects to it directly"));
        }
        (Some((name, raw)), Ok(Some(proxy))) => {
            let credentials = if has_credentials(&raw) { " with credentials (not shown)" } else { "" };
            let kind = match proxy.kind {
                dial::ProxyKind::Http => "",
                dial::ProxyKind::Socks5 => "the SOCKS5 proxy ",
            };
            report.ok(
                "proxy",
                format!(
                    "{name} names {kind}{proxy}{credentials}; podssh asks it to CONNECT by name, so no DNS is needed"
                ),
            );
        }
    }
}

/// Whether a proxy URL carries `user:password@`.
fn has_credentials(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or_default().contains('@')
}

/// The checks that connect: what the proxy lets through, or whether port 22
/// is open straight out, and name resolution.
pub(super) async fn check_network(report: &mut Report<'_>, relays: &RelayList, trust: &Trust) {
    let primary = relays.primary();
    match dial::proxy_from_env(&primary.host) {
        Ok(Some(proxy)) => {
            let names = through_proxy(report, &proxy, &primary.host, primary.port).await;
            // An address too (T-366), and what the two mean.
            let addresses = super::address::through_proxy(report, &proxy, trust).await;
            super::address::case(report, names, addresses, true);
            super::names::with_proxy(report, &primary.host).await;
        }
        Ok(None) => {
            let straight = direct(report).await;
            let (named, by_address) = super::names::direct(report, &primary.host).await;
            super::address::case(report, named, by_address || straight, false);
        }
        Err(_) => report.unknown("egress", "not probed: the proxy setting cannot be used"),
    }
}

/// How long the server of port 22 has to send its banner: an SSH server
/// sends it at once.
const BANNER_WAIT: Duration = Duration::from_secs(5);

/// Why a connection to port 22 that opened carries no SSH, or `None` when
/// the server's banner came. A `200` to CONNECT proves that the proxy took
/// the request, not that the tunnel carries bytes as they are: a proxy that
/// intercepts TLS waits for a ClientHello, and sends nothing or resets. The
/// check is the direct road's too, after the relay hosts (T-363).
pub(super) async fn no_ssh_banner<S: tokio::io::AsyncRead + Unpin>(mut stream: S) -> Option<String> {
    crate::ssh::banner::read(&mut stream, BANNER_WAIT).await.err()
}

/// What the proxy lets through: the relay, and for comparison GitHub on 443
/// and 22, each tried several times (T-324). Each answer is reported as the
/// proxy gave it; on port 22, only the server's banner, read on the first
/// connection that opened, says that plain ssh can leave. Whether the proxy
/// took a name on port 443, the relay's or GitHub's.
async fn through_proxy(report: &mut Report<'_>, proxy: &HttpProxy, relay_host: &str, relay_port: u16) -> bool {
    let mut named = false;
    let via = &ProxyChoice::Via(proxy.clone());
    for (host, port) in [(relay_host, relay_port), (REFERENCE_HOST, 443), (REFERENCE_HOST, 22)] {
        let target = dial::authority(host, port);
        let is_relay = host == relay_host;
        let Tried { samples, first, error } = sample(PROBE, move |bound| dial::dial(host, port, via, bound)).await;
        let summary = samples.summary();
        named |= first.is_some() && port != 22;
        let verdict = match first {
            Some(stream) => {
                let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
                let by = proxy_reached(proxy, &peer);
                let detail = match (port == 22 && !is_relay).then_some(stream) {
                    None => format!("{target}: allowed by {by}; {summary}"),
                    Some(stream) => match no_ssh_banner(stream).await {
                        None => format!("{target}: allowed by {by}; {summary}; plain ssh can leave this way too"),
                        Some(why) => format!(
                            "{target}: {by} took the CONNECT, then {why}: it carries no SSH, and may expect TLS; \
                             plain ssh cannot leave this way, which is what the relay is for; {summary}"
                        ),
                    },
                };
                Verdict::Ok { detail }
            }
            None => {
                let e = error.map(|e| e.to_string()).unwrap_or_default();
                match (is_relay, port) {
                    (true, _) => Verdict::Failed {
                        detail: format!(
                            "{target}: {e}; {summary}; another relay host may be allowed (--relay-host or PODSSH_RELAY)"
                        ),
                    },
                    (false, 22) => Verdict::Ok {
                        detail: format!(
                            "{target}: {e}; {summary}; plain ssh cannot leave this way, which is what the relay is for"
                        ),
                    },
                    (false, _) => Verdict::Ok { detail: format!("{target}: {e}; {summary}") },
                }
            }
        };
        report.sampled("CONNECT", verdict, &samples);
    }
    named
}

/// With no proxy: whether port 22 is open straight out, in which case the
/// relay is a convenience here rather than the only way; and whether the
/// connection to its address opened.
async fn direct(report: &mut Report<'_>) -> bool {
    let target = dial::authority(REFERENCE_HOST, 22);
    let straight = &ProxyChoice::Direct;
    let Tried { samples, first, error } =
        sample(PROBE, move |bound| dial::dial(REFERENCE_HOST, 22, straight, bound)).await;
    let summary = samples.summary();
    let opened = first.is_some();
    let detail = match first {
        Some(stream) => {
            let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
            // A middlebox can take the connection and carry nothing, as a proxy can.
            match no_ssh_banner(stream).await {
                None => format!("{target}: connected to {peer}; {summary}; plain ssh can leave this host too"),
                Some(why) => format!(
                    "{target}: connected to {peer}, then {why}: something between carries no SSH; plain ssh \
                     cannot leave this host, which is what the relay is for; {summary}"
                ),
            }
        }
        None => format!(
            "{}; {summary}; plain ssh cannot leave this host, which is what the relay is for",
            error.map(|e| e.to_string()).unwrap_or_default()
        ),
    };
    report.sampled("direct TCP", Verdict::Ok { detail }, &samples);
    opened
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_detected_and_never_needed_to_name_the_proxy() {
        assert!(has_credentials("http://user:secret@proxy.example:3128"));
        assert!(has_credentials("user:secret@proxy.example:3128"));
        assert!(!has_credentials("http://proxy.example:3128/path@x"));
        assert!(!has_credentials("http://proxy.example:3128"));
        let shown = HttpProxy::parse("http://user:secret@proxy.example:3128").unwrap().to_string();
        assert_eq!(shown, "proxy.example:3128");
    }

    /// The planted dates: the roots of today, of 400 days ago, and of a day
    /// after this host's clock.
    #[test]
    fn roots_age_says_when_they_are_older_than_12_months() {
        let published = "2026-07-18";
        let start = super::super::clock::parse_day(published).unwrap() * 86_400;
        let run = |now: i64| {
            let mut out: Vec<u8> = Vec::new();
            roots_age(&mut Report::new(&mut out), published, now);
            String::from_utf8(out).unwrap()
        };
        let fresh = run(start + 82 * 86_400);
        assert!(fresh.contains("ok") && fresh.contains("82 days old"), "{fresh}");
        assert!(fresh.contains("webpki-roots"), "{fresh}");
        let old = run(start + 400 * 86_400);
        assert!(old.contains("13 months old: older than 12 months"), "{old}");
        assert!(old.contains("--ca-file or SSL_CERT_FILE"), "{old}");
        let early = run(start - 86_400);
        assert!(early.contains("????") && early.contains("clock is before"), "{early}");
    }
}

/// The check of a server's banner (T-317), on streams in memory.
#[cfg(test)]
mod banner_tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, DuplexStream};

    /// The near end of a stream whose far end sent `bytes` and stays open:
    /// a server that waits for the client's banner.
    async fn sent(bytes: &[u8]) -> (DuplexStream, DuplexStream) {
        let (near, mut far) = tokio::io::duplex(1024);
        far.write_all(bytes).await.unwrap();
        (near, far)
    }

    /// A stream that the far end resets.
    struct Reset;

    impl tokio::io::AsyncRead for Reset {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        }
    }

    /// Only a banner says that plain ssh can leave; RFC 4253 lets other
    /// lines come before it.
    #[tokio::test]
    async fn only_the_server_banner_counts() {
        assert_eq!(no_ssh_banner(sent(b"SSH-2.0-stand-in\r\n").await.0).await, None);
        assert_eq!(no_ssh_banner(sent(b"welcome\r\nSSH-2.0-stand-in\r\n").await.0).await, None);
        // A TLS alert, as a proxy that ends TLS may send for the first bytes.
        let why = no_ssh_banner(sent(b"\x15\x03\x03\x00\x02\x02\x28").await.0).await.unwrap();
        assert!(why.contains("not an SSH banner"), "{why}");
        let (near, far) = tokio::io::duplex(64);
        drop(far);
        assert_eq!(no_ssh_banner(near).await.as_deref(), Some("it was closed with nothing sent"));
        assert!(no_ssh_banner(Reset).await.unwrap().starts_with("it broke with nothing sent"));
    }

    /// A proxy that intercepts TLS waits for a ClientHello: nothing comes,
    /// and the wait ends at its bound.
    #[tokio::test(start_paused = true)]
    async fn silence_after_the_connect_is_named_at_its_bound() {
        let (near, _far) = tokio::io::duplex(64);
        let started = tokio::time::Instant::now();
        assert_eq!(no_ssh_banner(near).await, Some(format!("nothing came in {} s", BANNER_WAIT.as_secs())));
        assert_eq!(started.elapsed(), BANNER_WAIT);
    }
}
