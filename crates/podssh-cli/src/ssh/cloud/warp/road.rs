//! The device of WARP's road, in a build with the feature `warp`: read from
//! its record in the cache, else registered once, with the user's
//! acceptance of the Terms, and kept; its tunnel, with a new key of the
//! endpoint that WARP's API gives (T-399), the API's peers and the endpoint
//! that opened (T-561) kept in the record; the run's settings of the
//! endpoint and of the probe (T-560); and the exit code of each fault.

use std::time::SystemTime;

use podssh_warp::register::{self, Api};
use podssh_warp::routes::Route;
use podssh_warp::{Device, Fault, Warp};
use podssh_ws::{ProxyChoice, Trust};

use super::{
    accepted, probe_kept, ACCEPT_TERMS_ENV, API_ENV, DEVICE_FILE, ENDPOINT_ENV, PROBE_ENV, TEAM_TOKEN_FILE_ENV,
};
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_SOFTWARE, EX_UNAVAILABLE};

/// The code of a run that a fault of the road ends: 77 for the device that
/// the edge refused, 70 for this host's part, 69 else, a tunnel that carried
/// nothing too (T-560).
pub fn code(fault: &Fault) -> i32 {
    match fault {
        Fault::Device(_) => EX_NOPERM,
        Fault::Local(_) => EX_SOFTWARE,
        Fault::Unreachable(_) | Fault::Intercepted(_) | Fault::Edge(_) | Fault::Silent(_) => EX_UNAVAILABLE,
    }
}

/// The device of a run: at `PODSSH_WARP_ENDPOINT` when it is set, and with
/// no probe of its tunnel where `PODSSH_WARP_PROBE=no` (T-560); neither goes
/// into the record.
fn for_run(device: Device) -> Result<Device, (String, i32)> {
    let device = match endpoint()? {
        Some(at) => device.at(at),
        None => device,
    };
    Ok(if probe()? { device } else { device.probing(None) })
}

/// `PODSSH_WARP_PROBE`: whether the run probes a tunnel that has just opened.
fn probe() -> Result<bool, (String, i32)> {
    probe_kept(std::env::var(PROBE_ENV).ok().as_deref()).map_err(|why| (why, EX_CONFIG))
}

/// `PODSSH_WARP_ENDPOINT`: another endpoint, as `ADDRESS:PORT`.
fn endpoint() -> Result<Option<std::net::SocketAddr>, (String, i32)> {
    match std::env::var(ENDPOINT_ENV).ok().filter(|v| !v.trim().is_empty()) {
        None => Ok(None),
        Some(text) => text
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| (format!("{ENDPOINT_ENV}={text}: an address and a port, as 162.159.198.2:443"), EX_CONFIG)),
    }
}

/// The team's token of `PODSSH_WARP_TEAM_TOKEN_FILE`, from a private file;
/// the token is never shown.
fn team_token() -> Result<Option<zeroize::Zeroizing<String>>, (String, i32)> {
    let Some(path) = std::env::var_os(TEAM_TOKEN_FILE_ENV) else { return Ok(None) };
    let path = std::path::PathBuf::from(path);
    let text =
        podssh_relay::cache::read_private(&path).map_err(|why| (format!("{TEAM_TOKEN_FILE_ENV}: {why}"), EX_CONFIG))?;
    let token = zeroize::Zeroizing::new(text.trim().to_string());
    if token.is_empty() || token.contains(['\r', '\n']) {
        return Err((format!("{TEAM_TOKEN_FILE_ENV}: {} holds no token on one line", path.display()), EX_CONFIG));
    }
    Ok(Some(token))
}

/// The code of a run that a fault of the registration ends.
fn register_code(fault: &register::Fault) -> i32 {
    match fault {
        register::Fault::Refused { status: 401 | 403, .. } => EX_NOPERM,
        register::Fault::Local(_) => EX_SOFTWARE,
        _ => EX_UNAVAILABLE,
    }
}

/// The device of the record in the cache, as [`for_run`] sets it for the
/// run; `None` with no record. It never registers: `podssh doctor` reads it
/// so (T-374).
pub fn kept() -> Result<Option<Device>, (String, i32)> {
    // A setting that cannot be used is said before the record is read, and
    // before a device is registered.
    endpoint()?;
    probe()?;
    api_route()?;
    let Some(text) = podssh_relay::cache::load_file(DEVICE_FILE) else { return Ok(None) };
    let text = zeroize::Zeroizing::new(text);
    let device = Device::from_json(&text).map_err(|why| {
        let line = format!("the device's record {DEVICE_FILE} in the cache: {why}; remove it to register again");
        (line, EX_CONFIG)
    })?;
    for_run(device).map(Some)
}

/// The device: [`kept`]; else a new one, registered when the user accepted
/// the Terms, whose record is kept. A record that cannot be read is a
/// configuration error that names the file, never one that registers again
/// on its own.
pub async fn device(
    trust: &Trust,
    say: &(dyn Fn(&str) + Sync),
    verbose: &(dyn Fn(&str) + Sync),
) -> Result<Device, (String, i32)> {
    if let Some(device) = kept()? {
        return Ok(device);
    }
    let yes = accepted(std::env::var(ACCEPT_TERMS_ENV).ok().as_deref()).map_err(|why| (why, EX_CONFIG))?;
    if !yes {
        let line = format!(
            "WARP's road needs a device, which podssh registers once with Cloudflare's API under Cloudflare's \
             Terms ({}); {ACCEPT_TERMS_ENV}=yes accepts them, and the device's record is kept in the cache",
            podssh_warp::TERMS_URL
        );
        return Err((line, EX_CONFIG));
    }
    let team = team_token()?;
    say("registering a device with WARP's API, once: its record is kept in the cache");
    let api = api_for(trust, ProxyChoice::FromEnvironment, None);
    let team = team.as_ref().map(|t| t.as_str());
    let device =
        register::register(&api, team, SystemTime::now()).await.map_err(|f| (f.to_string(), register_code(&f)))?;
    if let Some(route) = &device.api {
        verbose(&format!("WARP's API answered at {route}"));
    }
    // A record that is not kept costs a device at each run: said, and the
    // run goes on with this one.
    match podssh_relay::cache::store_file(DEVICE_FILE, device.to_json().as_bytes()) {
        Ok(path) => verbose(&format!("the device's record is in {}", path.display())),
        Err(why) => say(&format!("the device's record was not kept ({why}): the next run registers again")),
    }
    for_run(device)
}

/// `PODSSH_WARP_API`: another route to WARP's API, `https://HOST[:PORT]`,
/// tried first (T-562).
fn api_route() -> Result<Option<Route>, (String, i32)> {
    match std::env::var(API_ENV).ok().filter(|v| !v.trim().is_empty()) {
        None => Ok(None),
        Some(text) => Route::parse_url(&text)
            .map(Some)
            .map_err(|why| (format!("{API_ENV}={text}: {why}, as https://api.cloudflareclient.com"), EX_CONFIG)),
    }
}

/// WARP's API, by its own names in turn, after the route that answered for
/// `kept`'s device before, and after `PODSSH_WARP_API`, which goes first
/// (T-562); [`kept`] said a setting that cannot be used before.
fn api_for(trust: &Trust, proxy: ProxyChoice, kept: Option<&Route>) -> Api {
    let mut api = Api::cloudflare(trust.clone(), proxy, podssh_relay::open::CONNECT_TIMEOUT);
    if let Some(route) = kept {
        api = api.first(route.clone());
    }
    if let Ok(Some(route)) = api_route() {
        api = api.first(route);
    }
    api
}

/// What the road learns of a device in a run, which its record keeps: the
/// endpoint's key that WARP's API gave (T-399), the API's peers and the
/// endpoint that opened (T-561), and the route to the API that answered
/// (T-562).
type Learnt = (Vec<u8>, Vec<std::net::SocketAddr>, Option<std::net::SocketAddr>, Option<Route>);

fn learnt(device: &Device) -> Learnt {
    (device.endpoint_point.clone(), device.peers.clone(), device.reached, device.api.clone())
}

/// The tunnel of `device` through the environment's proxy, at each of its
/// endpoints in turn (T-561): a certificate of another key than the
/// record's sends the road to WARP's API for the device's record again,
/// through the same proxy and with `trust` (T-399). A new key that the API
/// gives, its peers and the endpoint that opened are kept in the record of
/// the cache.
pub async fn tunnel(device: &mut Device, trust: &Trust, verbose: &(dyn Fn(&str) + Sync)) -> Result<Warp, Fault> {
    let limit = podssh_relay::open::CONNECT_TIMEOUT;
    let proxy = ProxyChoice::FromEnvironment;
    let api = api_for(trust, proxy.clone(), device.api.as_ref());
    let before = learnt(device);
    if device.probe.is_none() {
        verbose(&format!("{PROBE_ENV}=no: WARP's tunnel is taken as it opens, with no packet through it proven"));
    }
    let opened = Warp::open_reading(device, &api, &proxy, limit).await;
    if learnt(device) != before {
        keep(device, verbose);
    }
    if let Ok(warp) = &opened {
        verbose(&format!("WARP's tunnel opened at {}", warp.endpoint));
        if let Some(to) = warp.probed {
            verbose(&format!("a packet went inside WARP's tunnel to {to} and its answer came back"));
        }
    }
    opened
}

/// The record in the cache with what the road learnt of `device`: the
/// endpoint's key that WARP's API gave, the API's peers, and the endpoint
/// that opened, or none when none did; the rest of the record stays, its
/// endpoint too, as `PODSSH_WARP_ENDPOINT` changes a run, not the record.
fn keep(device: &Device, verbose: &(dyn Fn(&str) + Sync)) {
    let Some(text) = podssh_relay::cache::load_file(DEVICE_FILE) else { return };
    let text = zeroize::Zeroizing::new(text);
    let Ok(mut record) = Device::from_json(&text) else { return };
    let new_key = record.endpoint_pem != device.endpoint_pem;
    if record.id != device.id || record.rekey(&device.endpoint_pem).is_err() {
        return;
    }
    record.peers = device.peers.clone();
    record.reached = device.reached;
    record.api = device.api.clone();
    match podssh_relay::cache::store_file(DEVICE_FILE, record.to_json().as_bytes()) {
        Ok(_) if new_key => verbose("WARP's API gave its endpoint a new key, which the device's record keeps"),
        Ok(_) => verbose("the device's record keeps WARP's peers, the endpoint that opened and the API's route"),
        Err(why) => verbose(&format!("the device's record was not written again ({why}): the next run asks again")),
    }
}
