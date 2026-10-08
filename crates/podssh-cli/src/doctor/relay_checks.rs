//! The relay: each host's `/health` over verified TLS, a token, a forward
//! session to an SSH server identified by its published host key, and this
//! host's clock against the relay's.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podssh_relay::open::Request;
use podssh_relay::relay::{Relay, RelayList};
use podssh_relay::token::{self, MintContext, Origin};
use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::{http, Trust, Verdict};

use super::clock::{format_http_date, parse_http_date};
use super::Report;

/// The relay version podssh was last measured against (docs/relay.md).
const MEASURED_VERSION: &str = "2026-10-03-r2";

/// The service name the relay gives in `/health`: with a verified
/// certificate for the host, this is how the relay is identified.
const SERVICE: &str = "tcp-ssh-relay";

/// Bound on each request and handshake here.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The forward session's target, and the SHA-256 fingerprints of the host
/// keys GitHub publishes for it (Ed25519, ECDSA, RSA; equal to
/// `api.github.com/meta` on 2026-10-08).
const FORWARD_HOST: &str = "github.com";
const GITHUB_KEYS: [&str; 3] = [
    "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
    "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
    "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
];

/// Skew beyond which this host's clock is called wrong.
const CLOCK_LIMIT: i64 = 3600;

pub(super) async fn check(report: &mut Report<'_>, relays: &RelayList, trust: &Trust) {
    let mut answered: Option<(&Relay, Option<String>)> = None;
    for relay in &relays.hosts {
        match health(relay, trust).await {
            Ok((line, date)) => {
                report.ok("relay", line);
                if answered.is_none() {
                    answered = Some((relay, date));
                }
            }
            Err(line) => report.fail("relay", line),
        }
    }
    let Some((relay, date)) = answered else {
        for name in ["token", "forward", "clock"] {
            report.unknown(name, "not attempted: no relay host answered");
        }
        return;
    };
    if token_check(report, relays, relay, trust).await {
        forward(report, relays, trust).await;
    } else {
        report.unknown("forward", "not attempted: there is no relay token");
    }
    clock(report, date.as_deref());
}

/// `GET /health` on one host, through the same proxy-aware, verified path
/// as a session. Returns the report line and the relay's `Date` header.
async fn health(relay: &Relay, trust: &Trust) -> Result<(String, Option<String>), String> {
    let host = &relay.host;
    let started = Instant::now();
    let mut tls = podssh_ws::client::open_tls(host, relay.port, host, trust, &ProxyChoice::FromEnvironment, TIMEOUT)
        .await
        .map_err(|e| {
            let text = e.to_string();
            format!("{host}: {text}{}", clock_hint(&text))
        })?;
    let (tcp, connection) = tls.get_ref();
    let peer = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_else(|e| format!("an address it cannot name ({e})"));
    let tls_version = connection
        .protocol_version()
        .map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1."))
        .unwrap_or_else(|| "TLS".into());
    let opened = match dial::proxy_from_env(host) {
        Ok(Some(proxy)) => format!(
            "CONNECT {} through {}",
            dial::authority(host, relay.port),
            super::net::proxy_reached(&proxy, &peer)
        ),
        _ => format!("TCP {peer}"),
    };
    let host_header = if relay.port == 443 { host.clone() } else { dial::authority(host, relay.port) };
    let exchange = http::exchange(&mut tls, "GET", &host_header, "/health", &[("Accept", "application/json")], b"", 64 * 1024);
    let response = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| format!("{host}: /health did not answer within {} s (opened {opened})", TIMEOUT.as_secs()))?
        .map_err(|e| format!("{host}: /health: {e} (opened {opened})"))?;
    if response.status != 200 {
        return Err(format!(
            "{host}: /health answered HTTP {} {} (opened {opened})",
            response.status,
            response.body_text(120)
        ));
    }
    let doc: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|_| format!("{host}: /health did not answer with JSON (opened {opened})"))?;
    let text = |v: &serde_json::Value| v.as_str().map(podssh_ws::text::one_line);
    let service = text(&doc["service"]).unwrap_or_default();
    if service != SERVICE {
        return Err(format!(
            "{host}: /health names the service {service:?}, not {SERVICE:?}, so this is not the relay (opened {opened})"
        ));
    }
    let version = text(&doc["version"]).unwrap_or_else(|| "(no version)".into());
    let edge = text(&doc["relay"]["edge_colo"]).map(|c| format!(" at edge {c}")).unwrap_or_default();
    let mut line = format!(
        "{host}: {SERVICE} {version}{edge}, {} ms; {tls_version}, certificate verified for {host}; opened {opened}",
        started.elapsed().as_millis()
    );
    if version != MEASURED_VERSION {
        line.push_str(&format!("; podssh was measured against {MEASURED_VERSION}"));
    }
    Ok((line, response.header("date").map(str::to_string)))
}

/// A certificate that is "expired" or "not valid yet" for every relay host
/// usually means this host's clock is wrong.
fn clock_hint(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("expired") || lower.contains("notvalidyet") || lower.contains("not valid yet") {
        format!("; certificates are checked against this host's clock, which reads {}", format_http_date(now()))
    } else {
        String::new()
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// A token from the environment, the cache or a fresh mint at a host that
/// answered. It is never shown.
async fn token_check(report: &mut Report<'_>, relays: &RelayList, at: &Relay, trust: &Trust) -> bool {
    let proxy = ProxyChoice::FromEnvironment;
    let primary = relays.primary().host.as_str();
    let ctx = MintContext { relay: at, cache_key: primary, trust, proxy: &proxy, timeout: TIMEOUT };
    match token::obtain(&ctx, false).await {
        Ok(token) => {
            let detail = match (token.origin, &token.cache_warning) {
                (Origin::Environment, _) => format!("from {} (not shown)", token::TOKEN_ENV),
                (Origin::Cache, _) => format!("a cached token for {primary} (not shown)"),
                (Origin::Minted, None) => format!("minted at {} and cached (not shown)", at.host),
                (Origin::Minted, Some(why)) => {
                    format!("minted at {} (not shown), but it could not be cached: {why}", at.host)
                }
            };
            drop(token);
            report.ok("token", detail);
            true
        }
        Err(e) => {
            report.fail("token", e.to_string());
            false
        }
    }
}

/// A forward session to GitHub's SSH port. The server must present one of
/// GitHub's published host keys: then the relay path works end to end and
/// nothing in between answered in GitHub's place.
async fn forward(report: &mut Report<'_>, relays: &RelayList, trust: &Trust) {
    let target = dial::authority(FORWARD_HOST, 22);
    let path = match podssh_relay::relay::forward_path(FORWARD_HOST, 22) {
        Ok(p) => p,
        Err(why) => return report.fail("forward", why),
    };
    let request = Request { relays, path: &path, trust, target: &target, rounds: 1 };
    // Its progress notes repeat what the relay lines above already say.
    let opened = match podssh_relay::open(&request, &mut |_: &str| {}).await {
        Ok(opened) => opened,
        Err(failure) => return report.fail("forward", format!("{target}: {}", failure.lines(&target).join("; "))),
    };
    let skipped: Vec<&str> =
        relays.hosts.iter().map(|r| r.host.as_str()).take_while(|h| *h != opened.relay.host).collect();
    let via = if skipped.is_empty() {
        opened.relay.host.clone()
    } else {
        format!("{} (after {} failed)", opened.relay.host, skipped.join(", "))
    };
    let (stream, status) = podssh_ssh::relay_stream::spawn(opened.session);
    let key = match podssh_ssh::probe::host_key(stream, TIMEOUT).await {
        Ok(key) => key,
        Err(why) => {
            let relay = status.get().and_then(|end| end.explain()).map(|e| format!(" ({e})")).unwrap_or_default();
            return report.fail("forward", format!("{target} through {via}: {why}{relay}"));
        }
    };
    let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
    let kind = podssh_ssh::known_hosts::key_type(&key);
    let shown = format!("{target} through {via}: {kind} host key {fingerprint}");
    if GITHUB_KEYS.contains(&fingerprint.as_str()) {
        return report.ok("forward", format!("{shown}, one of GitHub's published keys"));
    }
    // GitHub may have rotated a key since this list was written: ask it,
    // over verified TLS, before calling the answer wrong.
    let current = github_keys(trust).await;
    report.line("forward", judge_unlisted(&shown, &fingerprint, current));
}

/// The verdict on a key that is not in [`GITHUB_KEYS`], given what
/// `api.github.com/meta` says now: equality with a published fingerprint,
/// never anything about the server's banner.
fn judge_unlisted(shown: &str, fingerprint: &str, current: Result<Vec<String>, String>) -> Verdict {
    match current {
        Ok(current) if current.iter().any(|c| c == fingerprint) => Verdict::Ok {
            detail: format!(
                "{shown}, one of the keys api.github.com/meta lists now (podssh's own list is out of date)"
            ),
        },
        Ok(_) => Verdict::Failed {
            detail: format!(
                "{shown}, which is none of GitHub's keys: something in between answered in its place"
            ),
        },
        Err(why) => Verdict::Failed {
            detail: format!(
                "{shown}, which is not in podssh's list of GitHub's keys, and GitHub could not be asked for its \
                 current ones ({why})"
            ),
        },
    }
}

/// The fingerprints `api.github.com/meta` publishes now.
async fn github_keys(trust: &Trust) -> Result<Vec<String>, String> {
    let response =
        podssh_ws::https_get("api.github.com", 443, "/meta", 1024 * 1024, trust, &ProxyChoice::FromEnvironment, TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
    if response.status != 200 {
        return Err(format!("HTTP {}", response.status));
    }
    let doc: serde_json::Value = serde_json::from_slice(&response.body).map_err(|_| "not JSON".to_string())?;
    let prints = doc["ssh_key_fingerprints"].as_object().ok_or("no ssh_key_fingerprints in the answer")?;
    Ok(prints.values().filter_map(|v| v.as_str()).map(|v| format!("SHA256:{v}")).collect())
}

/// This host's clock against the relay's `Date` header (one-second
/// resolution, so a small skew is noise).
fn clock(report: &mut Report<'_>, date: Option<&str>) {
    let Some(relay) = date.and_then(parse_http_date) else {
        return report.unknown("clock", "the relay sent no usable Date header");
    };
    let skew = now() - relay;
    let side = if skew > 0 { "ahead of" } else { "behind" };
    match skew.abs() {
        0..=2 => report.ok("clock", "agrees with the relay's within 2 s"),
        n if n <= CLOCK_LIMIT => report.ok("clock", format!("{n} s {side} the relay's")),
        n => report.fail(
            "clock",
            format!(
                "{n} s {side} the relay's ({}): certificates and cached tokens are checked against this clock",
                format_http_date(relay)
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_validity_error_points_at_the_clock() {
        assert!(clock_hint("invalid peer certificate: Expired").contains("this host's clock"));
        assert!(clock_hint("invalid peer certificate: NotValidYet").contains("this host's clock"));
        assert!(clock_hint("invalid peer certificate: UnknownIssuer").is_empty());
    }

    #[test]
    fn a_key_is_judged_by_equality_with_a_published_fingerprint() {
        let theirs = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU".to_string();
        let planted = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        // A key GitHub lists now passes even when podssh's list is stale.
        let rotated = judge_unlisted("k", &theirs, Ok(vec![theirs.clone()]));
        assert!(matches!(&rotated, Verdict::Ok { detail } if detail.contains("out of date")), "{rotated:?}");
        // A planted key, listed neither here nor there: whatever answered is
        // not GitHub.
        let wrong = judge_unlisted("k", planted, Ok(vec![theirs.clone()]));
        assert!(matches!(&wrong, Verdict::Failed { detail } if detail.contains("none of GitHub's keys")), "{wrong:?}");
        // With no way to ask GitHub, an unlisted key is never passed.
        let unasked = judge_unlisted("k", planted, Err("HTTP 403".into()));
        assert!(matches!(&unasked, Verdict::Failed { detail } if detail.contains("HTTP 403")), "{unasked:?}");
        // The key measured through the relay on 2026-10-08 is in the list.
        assert!(GITHUB_KEYS.contains(&theirs.as_str()));
    }

    #[test]
    fn the_published_keys_are_well_formed_sha256_fingerprints() {
        for key in GITHUB_KEYS {
            let b64 = key.strip_prefix("SHA256:").expect(key);
            assert_eq!(b64.len(), 43, "{key}");
            assert!(b64.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/'), "{key}");
        }
    }
}
