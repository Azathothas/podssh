//! Name resolution, as the dialer does it: the pins, the system resolver, the
//! addresses that carried a session (T-344), and DNS over HTTPS with the form
//! of each resolver that answered. Through a proxy, only what this host can
//! do on its own.

use std::net::IpAddr;
use std::time::Instant;

use super::net::{ms, PROBE};
use super::Report;

/// With a proxy podssh never resolves the relay's name; the system resolver
/// is still asked, so the report says what this host can do on its own.
pub(super) async fn with_proxy(report: &mut Report<'_>, host: &str) {
    let fact = match system_lookup(host).await {
        Ok(ips) => format!("{host} is {ips} here (system resolver)"),
        Err(e) => format!("{host} does not resolve here ({e})"),
    };
    report.ok("DNS", format!("{fact}; not needed: the proxy is given names and resolves them"));
}

/// Without a proxy: pinned addresses, the system resolver, the addresses
/// that carried a session, then DNS over HTTPS, the order the dialer uses
/// them in.
pub(super) async fn direct(report: &mut Report<'_>, host: &str) {
    let pinned = podssh_ws::resolve::pinned(host);
    if !pinned.is_empty() {
        let ips: Vec<String> = pinned.iter().map(|ip| ip.to_string()).collect();
        report.ok(
            "pinned",
            format!(
                "{host} is pinned to {} (--relay-addr or PODSSH_RELAY_ADDR); used before any resolver",
                ips.join(", ")
            ),
        );
    }
    let system = system_lookup(host).await;
    let remembered = podssh_ws::resolve::remembered(host);
    let (fresh, _) = podssh_ws::resolve::split(&remembered, crate::pairs::now_ms());
    match &system {
        Ok(ips) => report.ok("DNS", format!("{host} is {ips} (system resolver)")),
        Err(e) => {
            let then = if fresh.is_empty() { "DNS over HTTPS" } else { "the cached addresses, then to DNS over HTTPS" };
            report.ok("DNS", format!("the system resolver fails for {host} ({e}); podssh falls back to {then}"))
        }
    }
    cached(report, host, &remembered);
    doh(report, host, system.is_ok() || !pinned.is_empty() || !remembered.is_empty()).await;
}

/// The addresses that carried a session to `host`, as the dialer asks them:
/// the fresh ones after the system resolver fails, before DNS over HTTPS,
/// and an old one after it, last.
fn cached(report: &mut Report<'_>, host: &str, remembered: &[podssh_ws::resolve::Remembered]) {
    let file = podssh_relay::addresses::FILE;
    if remembered.is_empty() {
        let none = format!("no address of {host} is in the cache yet: {file} keeps each one that carries a session");
        report.ok("cached", none);
        return;
    }
    let now = crate::pairs::now_ms();
    let (fresh, old) = podssh_ws::resolve::split(remembered, now);
    let ago = |ip: &IpAddr| remembered.iter().find(|r| r.ip == *ip).map_or(0, |r| now - r.at_ms);
    let list = |ips: &[IpAddr]| ips.iter().map(|ip| format!("{ip} {} ago", age(ago(ip)))).collect::<Vec<_>>();
    let mut said = Vec::new();
    if !fresh.is_empty() {
        said.push(format!(
            "{} carried a session to {host} ({file}); tried after the system resolver fails, before DNS over HTTPS",
            list(&fresh).join(", ")
        ));
    }
    if !old.is_empty() {
        let days = podssh_ws::resolve::FRESH.as_secs() / 86_400;
        said.push(format!("older than {days} days, tried last: {}", list(&old).join(", ")));
    }
    report.ok("cached", said.join("; "));
}

/// A time in its largest whole unit: 40 s, 12 min, 3 h, 9 days.
fn age(ms: i64) -> String {
    let s = ms.max(0) / 1000;
    match s {
        0..=119 => format!("{s} s"),
        120..=7_199 => format!("{} min", s / 60),
        7_200..=172_799 => format!("{} h", s / 3600),
        _ => format!("{} days", s / 86_400),
    }
}

/// The first DNS-over-HTTPS resolver that answers, and in which of its forms.
/// Missing it is a failure only when nothing else can resolve the relay's
/// name.
async fn doh(report: &mut Report<'_>, host: &str, another_way: bool) {
    let mut failures = Vec::new();
    for resolver in podssh_ws::resolve::DOH_RESOLVERS {
        let ip = resolver.ip;
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + PROBE;
        match podssh_ws::resolve::doh_ask(resolver, host, deadline).await {
            Ok((ips, form)) => {
                let ips: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                let before =
                    if failures.is_empty() { String::new() } else { format!("; before it: {}", failures.join("; ")) };
                report.ok(
                    "DNS over HTTPS",
                    format!(
                        "{ip} answered by {}: {host} is {}, {} ms{before}",
                        form.words(),
                        shorten(&ips),
                        ms(started)
                    ),
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
    use podssh_ws::resolve::Remembered;

    #[test]
    fn long_address_lists_are_cut_to_three() {
        let ips: Vec<String> = (1..=5).map(|i| format!("192.0.2.{i}")).collect();
        assert_eq!(shorten(&ips), "192.0.2.1, 192.0.2.2, 192.0.2.3 and 2 more");
        assert_eq!(shorten(&ips[..2]), "192.0.2.1, 192.0.2.2");
    }

    #[test]
    fn an_age_is_said_in_its_largest_unit() {
        assert_eq!(age(40_000), "40 s");
        assert_eq!(age(12 * 60_000), "12 min");
        assert_eq!(age(3 * 3_600_000), "3 h");
        assert_eq!(age(9 * 86_400_000), "9 days");
        assert_eq!(age(-5_000), "0 s", "a time from the future, of a clock that moved");
    }

    /// The cache's line names the file, each address with its age, and where
    /// the dialer asks each: a fresh one before DNS over HTTPS, an old one last.
    #[test]
    fn the_cache_s_line_says_where_each_address_is_tried() {
        fn run(remembered: &[Remembered]) -> String {
            let mut out: Vec<u8> = Vec::new();
            cached(&mut Report::new(&mut out), "relay.example", remembered);
            String::from_utf8(out).unwrap()
        }
        let none = run(&[]);
        assert!(none.contains("cached") && none.contains(podssh_relay::addresses::FILE), "{none}");
        let now = crate::pairs::now_ms();
        let seen = |ip: &str, ago: i64| Remembered { host: "relay.example".into(), ip: ip.parse().unwrap(), at_ms: now - ago };
        let both = run(&[seen("192.0.2.1", 3 * 3_600_000), seen("192.0.2.2", 9 * 86_400_000)]);
        assert!(both.contains("192.0.2.1 3 h ago carried a session to relay.example"), "{both}");
        assert!(both.contains("before DNS over HTTPS"), "{both}");
        assert!(both.contains("older than 7 days, tried last: 192.0.2.2 9 days ago"), "{both}");
    }
}
