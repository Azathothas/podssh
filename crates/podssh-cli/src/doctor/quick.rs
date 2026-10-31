//! The quick tunnel's edge (T-339): the day that the first of cloudflared's
//! roots ends, the roots that `podssh node --quick-tunnel` trusts beside
//! podssh's own for the edge. A binary keeps the roots that it was built
//! with, as it keeps its compiled-in roots (`net.rs`): the day is said, not
//! failed, as podssh works until it comes. And whether UDP reaches the edge,
//! as the node takes QUIC (T-359).

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
    }
}
