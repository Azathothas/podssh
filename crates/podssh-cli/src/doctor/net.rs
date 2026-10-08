//! Egress: the proxy the environment names and what it lets through, name
//! resolution, and podssh's TLS setup.

use std::time::{Duration, Instant};

use podssh_relay::relay::RelayList;
use podssh_ws::dial::{self, HttpProxy, ProxyChoice};
use podssh_ws::Trust;

use super::Report;

/// The bound on each network probe here.
const PROBE: Duration = Duration::from_secs(8);

/// A host every proxy and resolver can be asked about. Its port 22 tells an
/// egress that lets SSH out from one that allows only HTTPS.
const REFERENCE_HOST: &str = "github.com";

/// The variables podssh reads for a proxy, in the order it reads them.
const PROXY_VARS: [&str; 4] = ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"];

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn ms(since: Instant) -> u128 {
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
    // A file chosen by the user replaces the compiled-in roots.
    if *trust == Trust::Default {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
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
                format!("NO_PROXY excludes {relay_host}")
            };
            report.ok("proxy", format!("{name} is set, but {why}, so podssh connects to it directly"));
        }
        (Some((name, raw)), Ok(Some(proxy))) => {
            let credentials = if has_credentials(&raw) { " with credentials (not shown)" } else { "" };
            report.ok(
                "proxy",
                format!("{name} names {proxy}{credentials}; podssh asks it to CONNECT by name, so no DNS is needed"),
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
pub(super) async fn check_network(report: &mut Report<'_>, relays: &RelayList) {
    let primary = relays.primary();
    match dial::proxy_from_env(&primary.host) {
        Ok(Some(proxy)) => {
            through_proxy(report, &proxy, &primary.host, primary.port).await;
            names_with_proxy(report, &primary.host).await;
        }
        Ok(None) => {
            direct(report).await;
            names_direct(report, &primary.host).await;
        }
        Err(_) => report.unknown("egress", "not probed: the proxy setting cannot be used"),
    }
}

/// What the proxy lets through: the relay, and for comparison GitHub on 443
/// and 22. Each answer is reported as the proxy gave it.
async fn through_proxy(report: &mut Report<'_>, proxy: &HttpProxy, relay_host: &str, relay_port: u16) {
    let via = ProxyChoice::Via(proxy.clone());
    for (host, port) in [(relay_host, relay_port), (REFERENCE_HOST, 443), (REFERENCE_HOST, 22)] {
        let target = dial::authority(host, port);
        let is_relay = host == relay_host;
        let started = Instant::now();
        match dial::dial(host, port, &via, PROBE).await {
            Ok(stream) => {
                let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
                let meaning = if port == 22 { "; plain ssh can leave this way too" } else { "" };
                let by = proxy_reached(proxy, &peer);
                report.ok("CONNECT", format!("{target}: allowed by {by}, {} ms{meaning}", ms(started)));
            }
            Err(e) if is_relay => report.fail(
                "CONNECT",
                format!("{target}: {e}; another relay host may be allowed (--relay-host or PODSSH_RELAY)"),
            ),
            Err(e) => {
                let meaning = if port == 22 { "; plain ssh cannot leave this way, which is what the relay is for" } else { "" };
                report.ok("CONNECT", format!("{target}: {e}{meaning}"));
            }
        }
    }
}

/// With no proxy: whether port 22 is open straight out, in which case the
/// relay is a convenience here rather than the only way.
async fn direct(report: &mut Report<'_>) {
    let target = dial::authority(REFERENCE_HOST, 22);
    let started = Instant::now();
    match dial::dial(REFERENCE_HOST, 22, &ProxyChoice::Direct, PROBE).await {
        Ok(stream) => {
            let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
            report.ok(
                "direct TCP",
                format!("{target}: connected to {peer}, {} ms; plain ssh can leave this host too", ms(started)),
            );
        }
        Err(e) => report.ok(
            "direct TCP",
            format!("{e}; plain ssh cannot leave this host, which is what the relay is for"),
        ),
    }
}

/// With a proxy podssh never resolves the relay's name; the system resolver
/// is still asked, so the report says what this host can do on its own.
async fn names_with_proxy(report: &mut Report<'_>, host: &str) {
    let fact = match system_lookup(host).await {
        Ok(ips) => format!("{host} is {ips} here (system resolver)"),
        Err(e) => format!("{host} does not resolve here ({e})"),
    };
    report.ok("DNS", format!("{fact}; not needed: the proxy is given names and resolves them"));
}

/// Without a proxy: pinned addresses, the system resolver, then DNS over
/// HTTPS, the order the dialer uses them in.
async fn names_direct(report: &mut Report<'_>, host: &str) {
    let pinned = podssh_ws::resolve::pinned(host);
    if !pinned.is_empty() {
        let ips: Vec<String> = pinned.iter().map(|ip| ip.to_string()).collect();
        report.ok(
            "pinned",
            format!("{host} is pinned to {} (--relay-addr or PODSSH_RELAY_ADDR); used before any resolver", ips.join(", ")),
        );
    }
    let system = system_lookup(host).await;
    match &system {
        Ok(ips) => report.ok("DNS", format!("{host} is {ips} (system resolver)")),
        Err(e) => report.ok(
            "DNS",
            format!("the system resolver fails for {host} ({e}); podssh falls back to DNS over HTTPS"),
        ),
    }
    doh(report, host, system.is_ok() || !pinned.is_empty()).await;
}

/// The first DNS-over-HTTPS resolver that answers. Missing it is a failure
/// only when nothing else can resolve the relay's name.
async fn doh(report: &mut Report<'_>, host: &str, another_way: bool) {
    let mut failures = Vec::new();
    for &(ip, path) in podssh_ws::resolve::DOH_RESOLVERS {
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + PROBE;
        match podssh_ws::resolve::doh_lookup_with(&[(ip, path)], host, deadline).await {
            Ok(ips) => {
                let ips: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                let before =
                    if failures.is_empty() { String::new() } else { format!("; before it: {}", failures.join("; ")) };
                report.ok(
                    "DNS over HTTPS",
                    format!("{ip} answered: {host} is {}, {} ms{before}", shorten(&ips), ms(started)),
                );
                return;
            }
            // An answer, not a failure: the name does not exist anywhere.
            Err(e) if e.ends_with(podssh_ws::resolve::NXDOMAIN) => {
                let detail = format!("{ip} answered that {host} does not exist (NXDOMAIN)");
                if another_way {
                    report.ok("DNS over HTTPS", detail);
                } else {
                    report.fail(
                        "DNS over HTTPS",
                        format!("{detail}: check the relay's name, or pin its address with --relay-addr HOST=IP"),
                    );
                }
                return;
            }
            Err(e) => failures.push(e),
        }
    }
    let detail = format!("no resolver answered ({})", failures.join("; "));
    if another_way {
        report.ok("DNS over HTTPS", format!("{detail}; only a fallback is missing"));
    } else {
        report.fail(
            "DNS over HTTPS",
            format!("{detail}, and the system resolver fails too: pin the relay's address with --relay-addr HOST=IP"),
        );
    }
}

async fn system_lookup(host: &str) -> Result<String, String> {
    match tokio::time::timeout(PROBE, tokio::net::lookup_host((host, 443))).await {
        Ok(Ok(addrs)) => {
            let mut ips: Vec<String> = Vec::new();
            for ip in addrs.map(|a| a.ip().to_string()) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            if ips.is_empty() {
                Err("no addresses".into())
            } else {
                Ok(shorten(&ips))
            }
        }
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("no answer within {} s", PROBE.as_secs())),
    }
}

/// At most three addresses, then how many more.
fn shorten(ips: &[String]) -> String {
    match ips.len() {
        0..=3 => ips.join(", "),
        n => format!("{} and {} more", ips[..3].join(", "), n - 3),
    }
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

    #[test]
    fn long_address_lists_are_cut_to_three() {
        let ips: Vec<String> = (1..=5).map(|i| format!("192.0.2.{i}")).collect();
        assert_eq!(shorten(&ips), "192.0.2.1, 192.0.2.2, 192.0.2.3 and 2 more");
        assert_eq!(shorten(&ips[..2]), "192.0.2.1, 192.0.2.2");
    }
}
