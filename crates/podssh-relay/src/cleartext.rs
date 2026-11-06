//! The cleartext road on the relay's port (T-326, the operator's ruling
//! Q45), tried last by [`crate::open`]: once each relay host failed, one host
//! of each deployment whose TLS failed on the way
//! ([`podssh_ws::cleartext::tls_failed`]) is asked in cleartext, through the
//! same proxy, for a token of one session (`POST /v1/mint?once=1`, signed by
//! this client's key where the relay asks, T-448), and the upgrade goes with
//! it, in cleartext too. No other token goes on this road: not the cache's,
//! not `PODSSH_RELAY_TOKEN`'s. The token of one session is never cached, and
//! a relay whose answer does not say `"once": true`, with an end within
//! [`ONCE_MAX_MS`], gets no upgrade. Each hop reads the target and that
//! token; SSH inside stays end to end. podssh's relay role serves the road
//! (`serve::cleartext`); the default relay's edge serves TLS alone on its
//! port, so its mint is refused there. `PODSSH_CLEARTEXT=no` turns it off.

use std::time::Duration;

use podssh_ws::http::Response;
use podssh_ws::{Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::identity::file;
use crate::open::{OpenError, CONNECT_TIMEOUT, HOST_DEADLINE};
use crate::relay::Relay;
use crate::session::OsEntropy;
use crate::token::{self, TokenError};

/// The variable that turns the cleartext road off, the forwarders' `ws://`
/// form with it.
pub const CLEARTEXT_ENV: &str = "PODSSH_CLEARTEXT";

/// The longest life of a token of one session that podssh sends in
/// cleartext: the relay role's live 5 minutes.
pub const ONCE_MAX_MS: i64 = 10 * 60 * 1000;

/// The mint, and the query that asks it for a token of one session.
const MINT: &str = "/v1/mint";
const ONCE: &str = "?once=1";

/// The largest answer of the mint read.
const MINT_BODY: usize = 64 * 1024;

/// Whether the road is on: unset, empty or yes; no turns it off; another
/// word is refused, with why.
pub fn on_from(value: Option<&str>) -> Result<bool, String> {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("" | "yes" | "on" | "true" | "1") => Ok(true),
        Some("no" | "off" | "false" | "0") => Ok(false),
        Some(_) => Err(format!("{CLEARTEXT_ENV}: yes or no")),
    }
}

/// [`on_from`] of this process's variable.
pub fn on() -> Result<bool, String> {
    on_from(std::env::var(CLEARTEXT_ENV).ok().as_deref())
}

/// Whether a host's failure is one that the cleartext road may pass: TLS
/// itself failed once the connection opened, for the mint or the upgrade.
pub fn may_help(e: &OpenError) -> bool {
    match e {
        OpenError::Connect { error, .. } | OpenError::Token(TokenError::Connect(error)) => {
            podssh_ws::cleartext::tls_failed(error)
        }
        _ => false,
    }
}

/// The hosts of `hosts` that the road tries, in order: those whose TLS
/// failed in `attempts`, the first of each deployment alone, as the hosts
/// of one deployment share their front, and so its answer.
pub fn hosts_for(hosts: &[Relay], attempts: &[(String, OpenError)]) -> Vec<Relay> {
    let mut deployments: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for relay in hosts {
        let failed = attempts.iter().any(|(host, e)| *host == relay.host && may_help(e));
        let deployment = token::token_key(relay);
        if failed && !deployments.contains(&deployment) {
            deployments.push(deployment);
            out.push(relay.clone());
        }
    }
    out
}

/// The road after the TLS road failed with `attempts`: the session of the
/// first of [`hosts_for`] that opens, each within [`HOST_DEADLINE`], one at a
/// time; `notes` hears each step.
pub async fn last(
    hosts: &[Relay],
    attempts: &[(String, OpenError)],
    path: &str,
    notes: &mut dyn FnMut(&str),
) -> Option<(Relay, RelaySession)> {
    over(hosts_for(hosts, attempts), path, notes).await
}

/// The road to `tried`, in order, as [`last`] takes it.
pub async fn over(tried: Vec<Relay>, path: &str, notes: &mut dyn FnMut(&str)) -> Option<(Relay, RelaySession)> {
    if tried.is_empty() {
        return None;
    }
    match on() {
        Ok(true) => {}
        Ok(false) => return None,
        Err(why) => {
            notes(&format!("{why}; the cleartext road is not tried"));
            return None;
        }
    }
    let proxy = ProxyChoice::FromEnvironment;
    for relay in tried {
        let shown = token::relay_name(&relay);
        notes(&format!(
            "each relay host failed, and the TLS of {shown} failed on the way: podssh asks {shown} in cleartext for a \
             token of one session, and opens the session with it; each hop reads the target and that token, and \
             SSH inside stays end to end ({CLEARTEXT_ENV}=no turns this off)"
        ));
        match tokio::time::timeout(HOST_DEADLINE, attempt(&relay, path, &proxy, CONNECT_TIMEOUT)).await {
            Ok(Ok(session)) => {
                notes(&format!("{shown} carries the session in cleartext, with a token of one session"));
                return Some((relay, session));
            }
            Ok(Err(why)) => notes(&format!("{shown} in cleartext: {why}")),
            Err(_) => notes(&format!("{shown} in cleartext: no session within {} s", HOST_DEADLINE.as_secs())),
        }
    }
    None
}

/// One host in cleartext through `proxy`: the mint of a token of one
/// session, then the upgrade at `path` with it, each step within `step`.
pub async fn attempt(relay: &Relay, path: &str, proxy: &ProxyChoice, step: Duration) -> Result<RelaySession, String> {
    let token = mint_once(relay, proxy, step).await?;
    let config = WsClientConfig {
        endpoint: Endpoint { host: relay.host.clone(), port: relay.port, path: path.to_string() },
        // No TLS on this road: neither is read.
        trust: Trust::Default,
        server_name: relay.host.clone(),
        timeout: step,
        idle_timeout: Some(podssh_ws::DEFAULT_IDLE_TIMEOUT),
        proxy: proxy.clone(),
    };
    let opened = podssh_ws::cleartext::connect(&config, &token).await;
    drop(token);
    opened.map_err(|e| e.to_string())
}

/// A token of one session, minted at `relay` in cleartext, once more with
/// this client's key when the relay asks for one.
async fn mint_once(relay: &Relay, proxy: &ProxyChoice, step: Duration) -> Result<Zeroizing<String>, String> {
    let (host, port) = (relay.host.as_str(), relay.port);
    // The `Host` that the request sends, and that a key's proof signs.
    let named = crate::keyed::host_header(host, port);
    let first = post(host, port, &named, b"{}", proxy, step).await?;
    let response = match crate::keyed::challenge_of(&first) {
        None => first,
        Some(challenge) => {
            let key = file::load(&file::client_place(), &mut OsEntropy)
                .map_err(|why| format!("the relay mints for the keys of its list; this client's key: {why}"))?;
            let body = crate::keyed::proof(&key.identity, &named, MINT, &challenge);
            post(host, port, &named, &body, proxy, step).await?
        }
    };
    once_token(&response, crate::pool::now_ms())
}

/// `POST /v1/mint?once=1` with `body`, in cleartext, within `step`.
async fn post(
    host: &str,
    port: u16,
    named: &str,
    body: &[u8],
    proxy: &ProxyChoice,
    step: Duration,
) -> Result<Response, String> {
    let mut tcp = podssh_ws::dial::dial(host, port, proxy, step).await.map_err(|e| e.to_string())?;
    let headers = [("Content-Type", "application/json"), ("Accept", "application/json")];
    let target = format!("{MINT}{ONCE}");
    let asked = podssh_ws::http::exchange(&mut tcp, "POST", named, &target, &headers, body, MINT_BODY);
    match tokio::time::timeout(step, asked).await {
        Err(_) => Err(format!("the mint gave no answer within {} s", step.as_secs())),
        Ok(Err(e)) => {
            let cut = podssh_ws::Cut::of(e.kind()).words();
            Err(format!("the mint gave no answer ({cut}: {e}): a hop may cut cleartext"))
        }
        Ok(Ok(response)) => Ok(response),
    }
}

#[derive(Deserialize)]
struct Minted {
    token: String,
    /// Milliseconds since the epoch.
    expires: i64,
    #[serde(default)]
    once: bool,
}

/// The token of one session of the mint's answer, at `now_ms`: refused when
/// the relay did not say that it is one, or when it lives longer than
/// [`ONCE_MAX_MS`], as no other token goes in cleartext. A body of 2xx is
/// never quoted: it may hold a token.
pub fn once_token(response: &Response, now_ms: i64) -> Result<Zeroizing<String>, String> {
    match response.status {
        200..=299 => {}
        429 => return Err("the mint is braked (429); ask again later".into()),
        503 => return Err("the relay mints no token here (503)".into()),
        status => {
            let body = response.body_text(200);
            let said = if body.is_empty() { String::new() } else { format!(": {body}") };
            return Err(format!("the mint refused a token of one session: HTTP {status}{said}"));
        }
    }
    let minted: Minted =
        serde_json::from_slice(&response.body).map_err(|_| "the mint's answer is not the expected JSON".to_string())?;
    let token = Zeroizing::new(minted.token);
    let lives = minted.expires.saturating_sub(now_ms);
    if !minted.once || lives <= 0 || lives > ONCE_MAX_MS {
        return Err("the relay minted no token of one session (\"once\": true, minutes long), and podssh sends no \
                    other token in cleartext"
            .into());
    }
    if !crate::cache::valid_token(&token) {
        return Err("the mint's answer holds no usable token".into());
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_ws::ConnectError;

    #[test]
    fn the_variable_is_yes_or_no() {
        assert_eq!(on_from(None), Ok(true));
        for yes in ["", " yes ", "On", "1", "true"] {
            assert_eq!(on_from(Some(yes)), Ok(true), "{yes:?}");
        }
        for no in ["no", "OFF", "0", "false"] {
            assert_eq!(on_from(Some(no)), Ok(false), "{no:?}");
        }
        assert_eq!(on_from(Some("maybe")), Err("PODSSH_CLEARTEXT: yes or no".into()));
    }

    fn connect(error: ConnectError) -> OpenError {
        OpenError::Connect { error, origin: token::Origin::Minted }
    }

    /// One host of each deployment whose TLS failed, in the order of the
    /// list; a host that failed otherwise is not tried.
    #[test]
    fn a_host_of_each_deployment_whose_tls_failed_is_tried() {
        let default = crate::relay::default_relay_host();
        let relay = |host: &str| Relay { host: host.into(), port: 443 };
        let pool = "tcp-eu-west-3.ssh.relay.ajam.dev";
        let hosts = [relay(default), relay(pool), relay("a.example"), relay("b.example")];
        let tls = || connect(ConnectError::Tls("invalid peer certificate: UnknownIssuer".into()));
        let mint_tls = || OpenError::Token(TokenError::Connect(ConnectError::Tls("reset".into())));
        let refused = connect(ConnectError::Refused { status: 403, body: "not in the ALLOW list".into() });
        let attempts = vec![
            (default.to_string(), tls()),
            (pool.to_string(), mint_tls()),
            ("a.example".to_string(), refused),
            ("b.example".to_string(), mint_tls()),
        ];
        let tried: Vec<String> = hosts_for(&hosts, &attempts).into_iter().map(|r| r.host).collect();
        assert_eq!(tried, [default, "b.example"], "a host of each deployment, in order");
        assert!(!may_help(&OpenError::Deadline) && !may_help(&OpenError::Token(TokenError::NotIssued)));
        assert!(hosts_for(&hosts, &[]).is_empty(), "no failure, no road");
    }

    fn answer(status: u16, body: &str) -> Response {
        Response {
            status,
            reason: String::new(),
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            url: String::new(),
        }
    }

    /// A token of one session is taken; a token of 72 h, an answer that
    /// does not say once, and a refusal are not, and a 2xx body is never
    /// quoted.
    #[test]
    fn only_a_token_of_one_session_is_taken_from_the_mint() {
        let now = 1_000_000;
        let once = format!(r#"{{"token":"once1.1.n.t","expires":{},"scope":"forward","once":true}}"#, now + 300_000);
        assert_eq!(once_token(&answer(200, &once), now).unwrap().as_str(), "once1.1.n.t");
        let long = format!(r#"{{"token":"SECRET-TOKEN","expires":{},"once":true}}"#, now + 72 * 3_600_000);
        let unsaid = format!(r#"{{"token":"SECRET-TOKEN","expires":{}}}"#, now + 300_000);
        let ended = format!(r#"{{"token":"SECRET-TOKEN","expires":{},"once":true}}"#, now - 1);
        for body in [long, unsaid, ended] {
            let refused = once_token(&answer(200, &body), now).unwrap_err();
            assert!(refused.contains("no token of one session") && !refused.contains("SECRET"), "{refused}");
        }
        let edge = once_token(&answer(400, "The plain HTTP request was sent to HTTPS port"), now).unwrap_err();
        assert!(edge.ends_with("HTTP 400: The plain HTTP request was sent to HTTPS port"), "{edge}");
        assert!(once_token(&answer(503, ""), now).unwrap_err().contains("mints no token"));
        assert!(once_token(&answer(200, "not json"), now).unwrap_err().contains("not the expected JSON"));
    }
}
