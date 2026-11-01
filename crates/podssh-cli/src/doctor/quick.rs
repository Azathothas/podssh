//! The quick tunnel's edge (T-339): the day that the first of cloudflared's
//! roots ends, the roots that `podssh node --quick-tunnel` trusts beside
//! podssh's own for the edge. A binary keeps the roots that it was built
//! with, as it keeps its compiled-in roots (`net.rs`): the day is said, not
//! failed, as podssh works until it comes. And whether UDP reaches the edge,
//! as the node takes QUIC (T-359), and which road over TCP reaches it, as
//! the node takes HTTP/2: directly or through the proxy, else inside WARP's
//! tunnel (T-374).

use std::net::SocketAddr;
use std::time::Duration;

use podssh_relay::quick::{edge, quic};
use podssh_ws::ProxyChoice;

use super::Report;

/// What the node takes where a proxy is set: no proxy carries UDP (T-301).
const BEHIND_A_PROXY: &str =
    "a proxy is set, and no proxy carries UDP, so podssh node --quick-tunnel takes HTTP/2 and sends no UDP";

/// The words of a QUIC handshake with the edge: what answered, and in what
/// time, or why nothing did; each says what the node then takes.
fn handshake_words(answer: &Result<(SocketAddr, Duration), String>) -> String {
    match answer {
        Ok((addr, took)) => format!(
            "QUIC to the quick tunnel's edge at {addr} answered in {} ms, so podssh node --quick-tunnel takes QUIC",
            took.as_millis()
        ),
        Err(why) => format!("{why}, so podssh node --quick-tunnel takes HTTP/2"),
    }
}

/// What a run without `--full` says where no proxy is set: the edge is
/// Cloudflare's, a server that doctor reaches only when asked.
const NOT_PROBED: &str = "not probed: podssh doctor --full makes a QUIC handshake with the quick tunnel's edge, as \
                          podssh node --quick-tunnel tries first where no proxy is set";

/// Whether UDP reaches the quick tunnel's edge: with a proxy set, nothing is
/// sent, as the node then takes HTTP/2; else, with `full`, a QUIC handshake
/// with the edge, as the node's first try makes one, closed at once with
/// nothing registered. Each answer is `ok`, as the node's HTTP/2 is a road
/// that works.
pub(super) async fn udp_out(report: &mut Report<'_>, full: bool) {
    match podssh_ws::dial::proxy_from_env(edge::REGIONS[0]) {
        Ok(Some(_)) => report.ok("UDP out", BEHIND_A_PROXY.to_string()),
        Err(why) => report.unknown("UDP out", format!("the proxy setting cannot be read ({why}), so nothing was sent")),
        Ok(None) if !full => report.unknown("UDP out", NOT_PROBED.to_string()),
        Ok(None) => {
            let tls = match edge::roots().and_then(|roots| quic::tls(&roots)) {
                Ok(tls) => tls,
                Err(why) => return report.unknown("UDP out", format!("the edge's roots: {why}")),
            };
            let found = edge::find(&ProxyChoice::FromEnvironment).await;
            report.ok("UDP out", handshake_words(&quic::handshake(&found, tls).await));
        }
    }
}

/// What a run without `--full` says of the edge's road over TCP.
const EDGE_NOT_PROBED: &str = "not probed: podssh doctor --full opens TLS with the quick tunnel's edge on TCP port \
                               7844, as podssh node --quick-tunnel does over HTTP/2, and inside WARP's tunnel when \
                               that fails";

/// Which road over TCP reaches the quick tunnel's edge, as the node tries
/// them (T-374): TCP port 7844 directly or through the proxy, then inside
/// WARP's tunnel, with the device that the cache keeps; doctor registers no
/// device. TLS with the edge, closed at once, with nothing registered. Each
/// answer is `ok`, as the node is one road of podssh among others.
pub(super) async fn edge_road(report: &mut Report<'_>, full: bool) {
    if !full {
        return report.unknown("edge road", EDGE_NOT_PROBED.to_string());
    }
    let proxy = ProxyChoice::FromEnvironment;
    let found = edge::find(&proxy).await;
    let first = found.regions.first().map(String::as_str).unwrap_or(edge::REGIONS[0]);
    let way = match podssh_ws::dial::proxy_from_env(first) {
        Ok(Some(proxy)) => format!("through the proxy {proxy}"),
        _ => "directly".to_string(),
    };
    let detail = match edge::connect(&proxy, &found).await {
        Ok(_) => format!(
            "TCP port {} of the edge answered TLS {way}, so podssh node --quick-tunnel takes HTTP/2 there",
            found.port
        ),
        Err(why) => inside_warp(&found, why).await,
    };
    report.ok("edge road", detail);
}

/// The edge inside WARP's tunnel, after `why` of TCP: what the node would
/// take.
#[cfg(feature = "warp")]
async fn inside_warp(found: &edge::Edge, why: String) -> String {
    use crate::ssh::cloud::warp::{road, ACCEPT_TERMS_ENV};
    let mut device = match road::kept() {
        Ok(Some(device)) => device,
        Ok(None) => {
            return format!(
                "{why}; no WARP device is kept: podssh node --quick-tunnel registers one where {ACCEPT_TERMS_ENV} \
                 is yes, then tries the edge inside WARP's tunnel"
            )
        }
        Err((line, _)) => return format!("{why}; {line}"),
    };
    // A front door's new key is read from WARP's API and kept, as a run of
    // the road keeps it (T-399), so that doctor does not take it for a proxy.
    let warp = match road::tunnel(&mut device, &crate::pairs::trust(None), &|_: &str| {}).await {
        Ok(warp) => warp,
        Err(fault) => return format!("{why}; WARP's tunnel: {fault}"),
    };
    let trust = match edge::trust() {
        Ok(trust) => trust,
        Err(e) => return format!("{why}; the edge's roots: {e}"),
    };
    match podssh_relay::quick::edge_warp::connect(&warp, found, &trust).await {
        Ok(_) => format!(
            "{why}; inside WARP's tunnel ({}) the edge answered TLS, so podssh node --quick-tunnel takes HTTP/2 \
             inside it",
            warp.via()
        ),
        Err(inside) => format!("{why}; {inside}"),
    }
}

/// In a build without the feature: what such a build would try.
#[cfg(not(feature = "warp"))]
async fn inside_warp(_found: &edge::Edge, why: String) -> String {
    format!("{why}; a build with the feature warp tries the edge inside WARP's tunnel too")
}

/// The day that the first root ends, `end`, at `now` (seconds since the
/// epoch).
pub(super) fn roots_end(report: &mut Report<'_>, end: &str, now: i64) {
    let what = format!("cloudflared's roots for the quick tunnel's edge, the first ending on {end}");
    let Some(day) = super::clock::parse_day(end) else {
        report.unknown("quick tunnel roots", format!("{what}, a date that cannot be read"));
        return;
    };
    let days = day - now.div_euclid(86_400);
    let detail = if days < 0 {
        format!("{what}: it has ended, and the edge's chain to it with it; a newer podssh has newer roots")
    } else if days < 365 {
        format!("{what}, in {days} days: a newer podssh has the roots of a newer cloudflared")
    } else {
        format!("{what}, {days} days ahead")
    };
    report.ok("quick tunnel roots", detail);
}

/// [`roots_end`] for the roots built in, now.
pub(super) fn check(report: &mut Report<'_>) {
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    roots_end(report, edge::ROOTS_FIRST_END, now);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The planted dates: years ahead, within the last year, and past.
    #[test]
    fn the_day_that_the_first_root_ends_is_said_with_how_near_it_is() {
        let end = "2029-08-15";
        let day = super::super::clock::parse_day(end).unwrap() * 86_400;
        let run = |now: i64| {
            let mut out: Vec<u8> = Vec::new();
            roots_end(&mut Report::new(&mut out), end, now);
            String::from_utf8(out).unwrap()
        };
        let far = run(day - 1000 * 86_400);
        assert!(far.contains("ok") && far.contains("1000 days ahead") && far.contains(end), "{far}");
        let near = run(day - 100 * 86_400);
        assert!(near.contains("in 100 days") && near.contains("a newer podssh"), "{near}");
        let past = run(day + 86_400);
        assert!(past.contains("it has ended"), "{past}");
        let unread = {
            let mut out: Vec<u8> = Vec::new();
            roots_end(&mut Report::new(&mut out), "not a day", day);
            String::from_utf8(out).unwrap()
        };
        assert!(unread.contains("????"), "{unread}");
    }

    #[test]
    fn each_answer_of_the_edge_says_what_the_node_takes() {
        let answered = handshake_words(&Ok(("198.41.192.7:7844".parse().unwrap(), Duration::from_millis(31))));
        assert!(answered.contains("answered in 31 ms") && answered.ends_with("takes QUIC"), "{answered}");
        let silent = handshake_words(&Err("no region of the edge answered over QUIC: r1 no answer".into()));
        assert!(silent.starts_with("no region") && silent.ends_with("takes HTTP/2"), "{silent}");
        assert!(BEHIND_A_PROXY.contains("HTTP/2") && BEHIND_A_PROXY.contains("sends no UDP"));
        assert!(NOT_PROBED.contains("--full"), "{NOT_PROBED}");
        assert!(EDGE_NOT_PROBED.contains("--full") && EDGE_NOT_PROBED.contains("WARP"), "{EDGE_NOT_PROBED}");
    }
}
