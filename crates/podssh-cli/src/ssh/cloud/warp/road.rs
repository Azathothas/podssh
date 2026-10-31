//! The device of WARP's road, in a build with the feature `warp`: read from
//! its record in the cache, else registered once, with the user's
//! acceptance of the Terms, and kept; and the exit code of each fault.

use std::time::SystemTime;

use podssh_warp::register::{self, Api};
use podssh_warp::{Device, Fault};
use podssh_ws::{ProxyChoice, Trust};

use super::{accepted, ACCEPT_TERMS_ENV, DEVICE_FILE, ENDPOINT_ENV, TEAM_TOKEN_FILE_ENV};
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_SOFTWARE, EX_UNAVAILABLE};

/// The code of a run that a fault of the road ends: 77 for the device that
/// the edge refused, 70 for this host's part, 69 else.
pub fn code(fault: &Fault) -> i32 {
    match fault {
        Fault::Device(_) => EX_NOPERM,
        Fault::Local(_) => EX_SOFTWARE,
        Fault::Unreachable(_) | Fault::Intercepted(_) | Fault::Edge(_) => EX_UNAVAILABLE,
    }
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

/// The device of the record in the cache, at `PODSSH_WARP_ENDPOINT` when
/// it is set; `None` with no record. It never registers: `podssh doctor`
/// reads it so (T-374).
pub fn kept() -> Result<Option<Device>, (String, i32)> {
    let at = endpoint()?;
    let Some(text) = podssh_relay::cache::load_file(DEVICE_FILE) else { return Ok(None) };
    let text = zeroize::Zeroizing::new(text);
    let device = Device::from_json(&text).map_err(|why| {
        let line = format!("the device's record {DEVICE_FILE} in the cache: {why}; remove it to register again");
        (line, EX_CONFIG)
    })?;
    Ok(Some(match at {
        Some(at) => device.at(at),
        None => device,
    }))
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
    let at = endpoint()?;
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
    let limit = podssh_relay::open::CONNECT_TIMEOUT;
    let api = Api::cloudflare(trust.clone(), ProxyChoice::FromEnvironment, limit);
    let team = team.as_ref().map(|t| t.as_str());
    let device =
        register::register(&api, team, SystemTime::now()).await.map_err(|f| (f.to_string(), register_code(&f)))?;
    // A record that is not kept costs a device at each run: said, and the
    // run goes on with this one.
    match podssh_relay::cache::store_file(DEVICE_FILE, device.to_json().as_bytes()) {
        Ok(path) => verbose(&format!("the device's record is in {}", path.display())),
        Err(why) => say(&format!("the device's record was not kept ({why}): the next run registers again")),
    }
    Ok(match at {
        Some(at) => device.at(at),
        None => device,
    })
}
