//! The relays of the iroh road (T-165): a table of defaults, in order; the
//! flag `--iroh-relay` and the variable [`ENV`], which replace it, the flag
//! first; and the failover: the first relay of the list that answers
//! `/ping`, through the proxy and with podssh's trust store, is the home
//! relay. iroh itself would pick the relay with the least latency, in no
//! order, and could change it during a run, and with it a node's ticket.

use std::time::{Duration, Instant};

use iroh::RelayUrl;
use podssh_ws::{dial, http, ProxyChoice, Trust};

/// The relays when nothing is set, in order: n0's public relays, read in
/// iroh 1.3.0 (`defaults::prod`: North America east and west, Europe, Asia
/// and Pacific). The operator's own relay goes first when it exists
/// (`docs/decisions.md`, 2026-10-08).
pub const DEFAULT: &[&str] = &[
    "https://use1-1.relay.n0.iroh.link.",
    "https://usw1-1.relay.n0.iroh.link.",
    "https://euc1-1.relay.n0.iroh.link.",
    "https://aps1-1.relay.n0.iroh.link.",
];

/// The variable that replaces the table, as `--iroh-relay` does.
pub const ENV: &str = "PODSSH_IROH_RELAY";

/// The bound on each relay's `/ping`, the connection included.
pub const PING_LIMIT: Duration = Duration::from_secs(5);

/// Where a list of relays came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Flag,
    Variable,
    Table,
}

/// The table, as URLs.
pub fn defaults() -> Vec<RelayUrl> {
    DEFAULT.iter().map(|text| parse_url(text).expect("each relay of the table is a relay URL")).collect()
}

/// One relay: `https://HOST[:PORT]`, where HOST is a name or an IPv4
/// address that [`podssh_ws::names::check_host`] takes. User information, a
/// path, a query and a fragment are refused: iroh puts its own path after
/// the origin.
pub fn parse_url(text: &str) -> Result<RelayUrl, String> {
    let url = url::Url::parse(text.trim()).map_err(|e| format!("{text:?} is not a URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("{text:?}: an iroh relay is reached over https:// only"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{text:?}: a relay URL takes no user name or password"));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{text:?}: a relay URL is https://HOST[:PORT], with no path, query or fragment"));
    }
    let host = url.host_str().ok_or_else(|| format!("{text:?} names no host"))?;
    podssh_ws::names::check_host(host).map_err(|why| format!("{text:?}: {why}"))?;
    Ok(RelayUrl::from(url))
}

/// The relays of a list, `URL[,URL...]`, in order and once each.
pub fn parse_list(text: &str) -> Result<Vec<RelayUrl>, String> {
    let mut relays: Vec<RelayUrl> = Vec::new();
    for word in text.split(',').map(str::trim) {
        if word.is_empty() {
            return Err(format!("{text:?}: an empty relay in the list"));
        }
        let relay = parse_url(word)?;
        if !relays.contains(&relay) {
            relays.push(relay);
        }
    }
    Ok(relays)
}

/// The relays to use: the flag's, else the variable's (an empty variable is
/// none), else the table.
pub fn select(flag: Option<&str>, variable: Option<String>) -> Result<(Vec<RelayUrl>, Source), String> {
    if let Some(text) = flag {
        return parse_list(text).map(|list| (list, Source::Flag)).map_err(|why| format!("--iroh-relay: {why}"));
    }
    if let Some(text) = variable.filter(|v| !v.trim().is_empty()) {
        return parse_list(&text).map(|list| (list, Source::Variable)).map_err(|why| format!("{ENV}: {why}"));
    }
    Ok((defaults(), Source::Table))
}

/// [`select`] with the variable of this process.
pub fn from_environment(flag: Option<&str>) -> Result<(Vec<RelayUrl>, Source), String> {
    select(flag, std::env::var(ENV).ok())
}

/// A relay's answer to `/ping`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    pub elapsed: Duration,
    /// How the connection went: `directly`, or the proxy's `CONNECT`.
    pub way: String,
}

/// `GET /ping` on `relay`, through the proxy that podssh chooses for it, with
/// its certificate checked against `trust`, within `limit`.
pub async fn ping(relay: &RelayUrl, trust: &Trust, proxy: &ProxyChoice, limit: Duration) -> Result<Pong, String> {
    let host = relay.host_str().ok_or_else(|| format!("{relay}: no host"))?;
    let port = relay.port_or_known_default().unwrap_or(443);
    let started = Instant::now();
    let way = match proxy {
        ProxyChoice::Direct => "directly".to_string(),
        ProxyChoice::Via(p) => format!("CONNECT {} through {p}", dial::authority(host, port)),
        ProxyChoice::FromEnvironment => match dial::proxy_from_env(host) {
            Ok(Some(p)) => format!("CONNECT {} through {p}", dial::authority(host, port)),
            _ => "directly".to_string(),
        },
    };
    let answer = async {
        let mut tls = podssh_ws::client::open_tls(host, port, host, trust, proxy, limit)
            .await
            .map_err(|e| format!("{host}: {e}"))?;
        let host_header = if port == 443 { host.to_string() } else { dial::authority(host, port) };
        http::exchange(&mut tls, "GET", &host_header, "/ping", &[], b"", 4096)
            .await
            .map_err(|e| format!("{host}: /ping: {e} ({way})"))
    };
    let response = tokio::time::timeout(limit, answer)
        .await
        .map_err(|_| format!("{host}: /ping did not answer within {} s ({way})", limit.as_secs()))??;
    if response.status != 200 {
        return Err(format!("{host}: /ping answered HTTP {} {} ({way})", response.status, response.body_text(120)));
    }
    Ok(Pong { elapsed: started.elapsed(), way })
}

/// The relays to give iroh: the first of `relays` that answers `/ping`
/// alone, as the home relay; else all of them, for iroh's own probes. With
/// the reason of each relay that did not answer before one did.
pub async fn home(relays: &[RelayUrl], trust: &Trust, proxy: &ProxyChoice) -> (Vec<RelayUrl>, Vec<String>) {
    let mut missed = Vec::new();
    for relay in relays {
        match ping(relay, trust, proxy, PING_LIMIT).await {
            Ok(_) => return (vec![relay.clone()], missed),
            Err(why) => missed.push(why),
        }
    }
    (relays.to_vec(), missed)
}
