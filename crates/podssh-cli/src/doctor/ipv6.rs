//! The line `ipv6` (T-253): whether an IPv6 target can be reached through
//! the relay, by what the relay host that answered `/health` says of its own
//! way out in its `/relays.json`, and on the direct road, by this host's own
//! probes, which send nothing: an IPv6 socket made and closed, and the table
//! of routes that the relay role reads too. The default relay says nothing of
//! IPv6 in its `/relays.json`; its egress reached no IPv6 host when it was
//! measured (`docs/relay.md`, "IPv6 targets").

use std::time::Duration;

use podssh_relay::relay::{Relay, DEFAULT_RELAY_HOST};
use podssh_relay::serve::ipv6::Ipv6Out;
use podssh_ws::{dial, http, ProxyChoice, Trust};
use serde_json::Value;

use super::Report;

/// An address of the public internet that names no host: the target whose
/// proxy, if any, a direct road of `-6` takes, as the role asks of its own.
const ANY_PUBLIC: &str = "2000::1";

/// The line, with the relay host that answered `/health`, if one did.
pub(super) async fn check(report: &mut Report<'_>, relay: Option<&Relay>, trust: &Trust, timeout: Duration) {
    let socket = tokio::net::TcpSocket::new_v6().map(drop).map_err(|e| e.to_string());
    let proxy = dial::proxy_from_env(ANY_PUBLIC);
    let direct = direct_words(proxy, socket, Ipv6Out::default().out());
    let Some(relay) = relay else {
        return report
            .unknown("ipv6", format!("through the relay: not attempted, as no relay host answered; {direct}"));
    };
    let body = relays_json(relay, trust, timeout).await;
    match relay_words(&relay.host, default_deployment(&relay.host), body) {
        Ok(words) => report.ok("ipv6", format!("{words}; {direct}")),
        Err(words) => report.unknown("ipv6", format!("{words}; {direct}")),
    }
}

/// Whether `host` is the default relay or a host of its pool, whose
/// deployment was measured with no IPv6 out.
fn default_deployment(host: &str) -> bool {
    host.eq_ignore_ascii_case(DEFAULT_RELAY_HOST) || podssh_relay::pool::same_deployment(DEFAULT_RELAY_HOST, host)
}

/// `GET /relays.json` on `relay`, over the path of its `/health`.
async fn relays_json(relay: &Relay, trust: &Trust, timeout: Duration) -> Result<Vec<u8>, String> {
    let host = &relay.host;
    let proxy = ProxyChoice::FromEnvironment;
    let mut tls =
        podssh_ws::client::open_tls(host, relay.port, host, trust, &proxy, timeout).await.map_err(|e| e.to_string())?;
    let host_header = if relay.port == 443 { host.clone() } else { dial::authority(host, relay.port) };
    let accept = [("Accept", "application/json")];
    let exchange =
        http::exchange(&mut tls, "GET", &host_header, "/relays.json", &accept, b"", podssh_relay::pool::MAX_BODY);
    let response = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| format!("no answer within {} s", timeout.as_secs()))?
        .map_err(|e| e.to_string())?;
    if response.status != 200 {
        return Err(format!("HTTP {}", response.status));
    }
    Ok(response.body)
}

/// The relay's half: what its `/relays.json` says of its host's way out to
/// IPv6. `Err` holds the words of a check that could not run.
fn relay_words(host: &str, default: bool, body: Result<Vec<u8>, String>) -> Result<String, String> {
    let at = format!("through {host}");
    let body = body.map_err(|why| format!("{at}: /relays.json: {why}"))?;
    let doc: Value = serde_json::from_slice(&body).map_err(|_| format!("{at}: /relays.json is not JSON"))?;
    let egress = &doc["egress"];
    let known = egress["known_by"].as_str().map(podssh_ws::text::one_line).unwrap_or_else(|| "it says not how".into());
    Ok(match egress.get("ipv6") {
        Some(Value::Bool(true)) => format!("{at}: yes, the relay says that its host routes IPv6 out ({known})"),
        Some(Value::Bool(false)) => format!(
            "{at}: none, the relay says that its host has no IPv6 route out ({known}), so it refuses an IPv6 \
             target before the upgrade"
        ),
        Some(Value::Null) => format!("{at}: unknown, the relay cannot tell ({known})"),
        // The default relay publishes no word of it: the last measurement.
        _ if default => format!(
            "{at}: none when last measured, on 2026-11-03: each IPv6 target upgraded, then closed with 1011 \
             (its /relays.json says nothing of IPv6)"
        ),
        _ => format!("{at}: unknown, as its /relays.json says nothing of IPv6 (podssh relay serve says it)"),
    })
}

/// The direct road's half: through the proxy of a public IPv6 address, its
/// way out decides; with none, this host's IPv6 socket, then its routes.
fn direct_words(
    proxy: Result<Option<podssh_ws::Proxy>, String>,
    socket: Result<(), String>,
    routes: (Option<bool>, &str),
) -> String {
    match proxy {
        Ok(Some(proxy)) => return format!("direct: through the proxy {proxy}, whose way out decides"),
        Err(why) => return format!("direct: unknown, as the proxy setting cannot be read ({why})"),
        Ok(None) => {}
    }
    if let Err(why) = socket {
        return format!("direct: none, as this host makes no IPv6 socket ({why})");
    }
    match routes {
        (Some(true), by) => format!("direct: yes, by {by}"),
        (Some(false), by) => format!("direct: none, by {by}"),
        (None, _) => "direct: unknown before a dial, as this host gives no table of IPv6 routes".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(egress: &str) -> Result<Vec<u8>, String> {
        Ok(format!(r#"{{"pool": [], "egress": {egress}}}"#).into_bytes())
    }

    /// Each word of a relay of podssh's role, the default relay's silence,
    /// another relay's, and a document that could not be read.
    #[test]
    fn the_relay_s_half_says_what_its_relays_json_says() {
        let at = "r.example";
        let yes = relay_words(at, false, doc(r#"{"ipv6": true, "known_by": "the routes of this host"}"#)).unwrap();
        assert_eq!(
            yes,
            "through r.example: yes, the relay says that its host routes IPv6 out (the routes of this host)"
        );
        let no = relay_words(at, false, doc(r#"{"ipv6": false, "known_by": "a dial that met no route"}"#)).unwrap();
        assert!(no.starts_with("through r.example: none, the relay says that its host has no IPv6 route out"), "{no}");
        assert!(no.contains("(a dial that met no route)") && no.ends_with("before the upgrade"), "{no}");
        let proxied = r#"{"ipv6": null, "known_by": "the proxy of the relay's host decides"}"#;
        let proxied = relay_words(at, false, doc(proxied)).unwrap();
        assert!(
            proxied.ends_with("unknown, the relay cannot tell (the proxy of the relay's host decides)"),
            "{proxied}"
        );
        let silent = Ok(br#"{"pool": [{"host": "tcp-a.ssh.relay.ajam.dev"}]}"#.to_vec());
        let default = relay_words(DEFAULT_RELAY_HOST, true, silent.clone()).unwrap();
        assert!(default.contains("none when last measured, on 2026-11-03") && default.contains("1011"), "{default}");
        let other = relay_words(at, false, silent).unwrap();
        assert!(other.ends_with("unknown, as its /relays.json says nothing of IPv6 (podssh relay serve says it)"));
        let cut = relay_words(at, false, Err("HTTP 404".into())).unwrap_err();
        assert_eq!(cut, "through r.example: /relays.json: HTTP 404");
        assert!(relay_words(at, false, Ok(b"<html>".to_vec())).unwrap_err().ends_with("is not JSON"));
        assert!(default_deployment("TCP-EU-WEST-3.SSH.RELAY.AJAM.DEV") && default_deployment(DEFAULT_RELAY_HOST));
        assert!(!default_deployment("relay.example"));
    }

    /// A proxy decides before this host's probes, and a refused socket
    /// before the table; a proxy is named by its address alone.
    #[test]
    fn the_direct_half_names_the_proxy_the_socket_or_the_routes() {
        let table = "the routes of this host";
        let proxy = podssh_ws::Proxy::parse("http://proxy.invalid:3128").unwrap();
        let words = direct_words(Ok(Some(proxy)), Ok(()), (Some(false), table));
        assert_eq!(words, "direct: through the proxy proxy.invalid:3128, whose way out decides");
        let bad = direct_words(Err("HTTPS_PROXY: no host".into()), Ok(()), (None, ""));
        assert!(bad.starts_with("direct: unknown, as the proxy setting cannot be read"), "{bad}");
        let refused = "Address family not supported by protocol (os error 97)";
        let none = direct_words(Ok(None), Err(refused.into()), (Some(true), table));
        assert_eq!(none, format!("direct: none, as this host makes no IPv6 socket ({refused})"));
        assert_eq!(direct_words(Ok(None), Ok(()), (Some(true), table)), "direct: yes, by the routes of this host");
        assert_eq!(direct_words(Ok(None), Ok(()), (Some(false), table)), "direct: none, by the routes of this host");
        assert!(direct_words(Ok(None), Ok(()), (None, "nothing before a dial")).contains("unknown before a dial"));
    }
}
