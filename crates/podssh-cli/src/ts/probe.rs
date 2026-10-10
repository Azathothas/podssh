//! The network check of each mode, before the start (T-102): `tcp` needs a
//! stock DERP server and `relay` needs the relay host, each reached through
//! the proxy by a TLS handshake that podssh's trust store verifies, in 8 s
//! for each step as `podssh doctor` does. The chain reads the verdicts, and a
//! mode that was not checked is not ready: starting in `tcp` and again in
//! `relay` would register twice, and wait for a failure that has no limit.

use std::io::Write;
use std::time::Duration;

use podssh_ts::chain::{select_chain, ChainInputs, Verdict};
use podssh_ts::config::TsMode;
use podssh_ts::wait::Deadline;
use podssh_ws::client::open_tls;
use podssh_ws::dial::authority;
use podssh_ws::{ConnectError, HttpProxy, ProxyChoice, Trust};

/// The bound on each step, as on each probe of `podssh doctor`.
pub const STEP: Duration = Duration::from_secs(8);

/// Where Tailscale publishes its default DERP map; the fork's own tests read
/// it from there.
pub const DERP_MAP_HOST: &str = "login.tailscale.com";
pub const DERP_MAP_PATH: &str = "/derpmap/default";

/// The largest map read. The map of 2026-10-10 is 15 KB.
const MAP_MAX: usize = 1024 * 1024;

/// DERP servers tried, each of another region, before `tcp` fails: one
/// server that is down does not make the stock tailnet unreachable.
pub const DERP_TRIES: usize = 3;

/// The proxy of the checks: `--ts-proxy`, read with the port that the fork
/// gives a URL with none (8080), so the check goes where the node will;
/// else the environment's, for each host, as each other podssh command
/// reads it.
pub fn proxy_choice(flag: Option<&str>) -> Result<ProxyChoice, String> {
    let Some(url) = flag else { return Ok(ProxyChoice::FromEnvironment) };
    let explicit = podssh_ts::config::parse_proxy_url(url).map_err(|_| format!("{url:?} is not an http:// URL"))?;
    HttpProxy::parse(&explicit).map(ProxyChoice::Via)
}

/// Check the modes in chain order until one is ready, and return it; a
/// later mode is not checked. With none ready, each verdict goes to `err`,
/// and the result is the exit: 78, for a route that this host lacks.
pub async fn select(
    modes: &[TsMode],
    proxy: &ProxyChoice,
    deadline: Deadline,
    err: &mut dyn Write,
) -> Result<TsMode, i32> {
    // The key's presence was checked before: a missing flag is 77, not this.
    let mut inputs = ChainInputs { addrs: vec![], socks_endpoint: None, has_key: true, reach: Vec::new() };
    for mode in modes {
        let verdict = reach(mode, proxy, deadline).await;
        inputs.reach.push((mode.clone(), verdict));
        if let Some(selected) = select_chain(modes, &inputs) {
            // A mode passed over is said once: the run then differs from
            // what the order promises.
            for (passed, verdict) in inputs.reach.iter().filter(|(m, _)| *m != selected) {
                let _ = writeln!(err, "podssh ts: mode {} is not ready: {}", name(passed), shown(verdict));
            }
            if inputs.reach.len() > 1 {
                let _ = writeln!(err, "podssh ts: using mode {}.", name(&selected));
            }
            return Ok(selected);
        }
    }
    for mode in modes {
        let _ = writeln!(err, "podssh ts: mode {}: {}", name(mode), shown(&inputs.reached(mode)));
    }
    let _ = writeln!(err, "podssh ts: no mode is ready.");
    Err(crate::exitmap::Fault::Capability.code())
}

/// A mode as the messages name it.
fn name(mode: &TsMode) -> String {
    match mode {
        TsMode::Tcp => "tcp".to_string(),
        TsMode::Relay { host, port } => format!("relay {}", authority(host, *port)),
    }
}

fn shown(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Ok => "ready".to_string(),
        Verdict::Fail(why) => why.clone(),
        Verdict::Unknown => "not checked".to_string(),
    }
}

/// The network check of `mode` through `proxy`, each step in [`STEP`] and
/// never past `deadline`. A failure says why; the mode's name says where.
pub async fn reach(mode: &TsMode, proxy: &ProxyChoice, deadline: Deadline) -> Verdict {
    match mode {
        TsMode::Tcp => stock_derp(proxy, deadline).await,
        TsMode::Relay { host, port } => match handshake(host, *port, proxy, deadline.limit(STEP)).await {
            Ok(()) => Verdict::Ok,
            Err(why) => Verdict::Fail(why),
        },
    }
}

/// `tcp`: the default DERP map, then a handshake with a server of the
/// first regions in it, until one answers.
async fn stock_derp(proxy: &ProxyChoice, deadline: Deadline) -> Verdict {
    let from = format!("the default DERP map from {DERP_MAP_HOST}");
    let limit = deadline.limit(STEP);
    if limit.is_zero() {
        return Verdict::Fail(format!("{from}: not read, the bound had passed"));
    }
    // `https_get` bounds its dial, its handshake and its exchange each; the
    // step bounds all three.
    let fetched = tokio::time::timeout(
        limit,
        podssh_ws::https_get(DERP_MAP_HOST, 443, DERP_MAP_PATH, MAP_MAX, &Trust::Default, proxy, limit),
    )
    .await;
    let map = match fetched {
        Ok(Ok(r)) if r.status == 200 => r.body,
        Ok(Ok(r)) => return Verdict::Fail(format!("{from}: HTTP {}", r.status)),
        Ok(Err(e)) => return Verdict::Fail(format!("{from}: {}", connect_error(&e))),
        Err(_) => return Verdict::Fail(format!("{from}: no answer within {}", seconds(limit))),
    };
    let servers = derp_servers(&map, DERP_TRIES);
    if servers.is_empty() {
        return Verdict::Fail(format!("{from} names no DERP server"));
    }
    let until = tokio::time::Instant::now() + deadline.limit(STEP);
    let mut reasons = Vec::new();
    for (host, port) in &servers {
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        match handshake(host, *port, proxy, left).await {
            Ok(()) => return Verdict::Ok,
            Err(why) => reasons.push(format!("{}: {why}", authority(host, *port))),
        }
    }
    Verdict::Fail(format!("no stock DERP server answered: {}", reasons.join("; ")))
}

/// TCP through the proxy and a verified TLS handshake, all in `limit`.
async fn handshake(host: &str, port: u16, proxy: &ProxyChoice, limit: Duration) -> Result<(), String> {
    if limit.is_zero() {
        return Err("not tried, the bound had passed".to_string());
    }
    // `open_tls` bounds its dial and its handshake each; the step bounds both.
    match tokio::time::timeout(limit, open_tls(host, port, host, &Trust::Default, proxy, limit)).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(e)) => Err(connect_error(&e)),
        Err(_) => Err(format!("no TLS handshake within {}", seconds(limit))),
    }
}

/// A limit as the messages say it, in whole seconds rounded up.
fn seconds(limit: Duration) -> String {
    format!("{} s", limit.as_secs_f32().ceil())
}

/// A connect error, said for any server: its own text names the relay.
fn connect_error(e: &ConnectError) -> String {
    match e {
        ConnectError::Tls(why) => format!("TLS: {why}"),
        other => other.to_string(),
    }
}

/// Up to `most` DERP servers in the text of a DERP map: from the regions in
/// the order of their numbers, one each, the first server of the region
/// that serves DERP (not one for STUN only, nor one for tests), with its
/// DERP port, 443 when the map gives none. A region to avoid is passed over.
pub fn derp_servers(map: &[u8], most: usize) -> Vec<(String, u16)> {
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(map) else { return Vec::new() };
    let Some(regions) = doc.get("Regions").and_then(|r| r.as_object()) else { return Vec::new() };
    let mut numbered: Vec<(u64, &serde_json::Value)> =
        regions.iter().filter_map(|(id, region)| id.parse().ok().map(|id| (id, region))).collect();
    numbered.sort_by_key(|(id, _)| *id);
    let mut out = Vec::new();
    for (_, region) in numbered {
        if out.len() == most {
            break;
        }
        if flag(region, "Avoid") {
            continue;
        }
        let nodes = region.get("Nodes").and_then(|n| n.as_array()).map(Vec::as_slice).unwrap_or(&[]);
        if let Some(server) = nodes.iter().find_map(derp_server) {
            out.push(server);
        }
    }
    out
}

/// One node of a region, when it serves DERP: its host name and port.
fn derp_server(node: &serde_json::Value) -> Option<(String, u16)> {
    if flag(node, "STUNOnly") || flag(node, "InsecureForTests") {
        return None;
    }
    let host = node.get("HostName")?.as_str()?.trim();
    if host.is_empty() {
        return None;
    }
    // Tailscale's own reading: none or 0 is 443, and -1 turns DERP off.
    let port = match node.get("DERPPort").filter(|p| !p.is_null()).map(|p| p.as_i64()) {
        None | Some(Some(0)) => 443,
        Some(Some(p)) => u16::try_from(p).ok().filter(|p| *p != 0)?,
        Some(None) => return None,
    };
    Some((host.to_string(), port))
}

fn flag(value: &serde_json::Value, name: &str) -> bool {
    value.get(name).and_then(|v| v.as_bool()) == Some(true)
}
