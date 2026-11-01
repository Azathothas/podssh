//! `podssh ssh iap://...` and `podssh ssh eice://...` (T-351): SSH to a VM
//! of the user's through its cloud's own tunnel, a WebSocket on port 443
//! through `HTTPS_PROXY` when one is set, with no relay: GCP's
//! Identity-Aware Proxy for TCP ([`iap`]) and AWS's EC2 Instance Connect
//! Endpoint ([`eice`]). Each needs the user's account, in a file that the
//! user names: a token or a key of Google's ([`google`]), a credential of
//! AWS's ([`aws`]). The VM is then a jump host like any other: `-J` with
//! the tunnel as its first hop reaches the hosts that the VM reaches.
//!
//! `podssh ssh warp://...` (T-352) is a road of the same kind, a provider's
//! own tunnel from this host: WARP's, whose network reaches any host
//! ([`warp`]), in a build with the feature `warp`. So is `tor://...`
//! (T-353), through the Tor network ([`tor`]), with the feature `tor`.

mod aws;
mod eice;
pub mod google;
mod iap;
pub mod proxy;
// The forwarders' road says its end the same way (T-369).
pub(crate) mod told;
pub mod tor;
pub mod warp;

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::Log;
use podssh_ws::Trust;

use super::resolve::{Env, Transport};
use super::transport::{NotReached, Reached};
use crate::relay_settings::Refusal;

pub use aws::{CREDENTIALS_FILE_ENV, DURATION_ENV, PROFILE_ENV, SHARED_ENV};
pub use google::{GOOGLE_ENV, TOKEN_FILE_ENV};

/// A VM behind a cloud's own tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Road {
    /// GCP: the VM's project, zone, name and port.
    Iap(podssh_ws::iap::Target),
    /// AWS: the endpoint, and the instance's address and port.
    Eice { endpoint: podssh_ws::eice::Endpoint, target: podssh_ws::eice::Target },
    /// WARP: any host and port, inside Cloudflare's tunnel (T-352).
    Warp(warp::Target),
    /// Tor: any host and port, through an exit (T-353).
    Tor(tor::Target),
}

/// `iap://[user@]PROJECT/ZONE/INSTANCE[:PORT]` or
/// `eice://[user@]ENDPOINT/ADDRESS[:PORT]` as its user and its road; `None`
/// for each other destination.
pub fn destination(text: &str) -> Result<Option<(Option<String>, Road)>, String> {
    if let Some((user, target)) = iap::destination(text)? {
        return Ok(Some((user, Road::Iap(target))));
    }
    if let Some((user, endpoint, target)) = eice::destination(text)? {
        return Ok(Some((user, Road::Eice { endpoint, target })));
    }
    if let Some((user, target)) = warp::destination(text)? {
        return Ok(Some((user, Road::Warp(target))));
    }
    if let Some((user, target)) = tor::destination(text)? {
        return Ok(Some((user, Road::Tor(target))));
    }
    Ok(None)
}

/// A user's name before `@`, when it comes before the first `/`: a name of
/// the cloud's part holds no `@`.
fn user_of<'a>(text: &str, rest: &'a str) -> Result<(Option<String>, &'a str), String> {
    match rest.split_once('@') {
        Some((user, _)) if user.contains('/') => Ok((None, rest)),
        Some(("", _)) => Err(format!("{text:?}: empty user name")),
        Some((user, rest)) => Ok((Some(user.to_string()), rest)),
        None => Ok((None, rest)),
    }
}

/// A port after the last `:`, or 22.
fn port_of<'a>(text: &str, part: &'a str) -> Result<(&'a str, u16), String> {
    match part.rsplit_once(':') {
        Some((name, port)) => match port.parse::<u16>() {
            Ok(port) if port != 0 => Ok((name, port)),
            _ => Err(format!("{text:?}: {port:?} is not a port")),
        },
        None => Ok((part, 22)),
    }
}

/// `SCHEME[user@]HOST[:PORT]` as its user, host and port (22 when none is
/// given); `None` for another destination. An IPv6 address goes in
/// brackets. The form of `warp://` and of `tor://`.
fn host_destination(text: &str, scheme: &str) -> Result<Option<(Option<String>, String, u16)>, String> {
    let Some(rest) = text.strip_prefix(scheme) else { return Ok(None) };
    let (user, rest) = user_of(text, rest.trim_end_matches('/'))?;
    let (host, port) = match rest.strip_prefix('[') {
        Some(inner) => {
            let (v6, after) = inner.split_once(']').ok_or_else(|| format!("{text:?}: no ] after the address"))?;
            let port = match after.strip_prefix(':') {
                Some(_) => port_of(text, after)?.1,
                None if after.is_empty() => 22,
                None => return Err(format!("{text:?}: {after:?} after the address")),
            };
            v6.parse::<std::net::Ipv6Addr>().map_err(|_| format!("{text:?}: {v6:?} is not an IPv6 address"))?;
            (v6.to_string(), port)
        }
        None if rest.matches(':').count() > 1 => {
            return Err(format!("{text:?}: an IPv6 address goes in brackets, as {scheme}[ADDRESS]:PORT"))
        }
        None => {
            let (name, port) = port_of(text, rest)?;
            (name.to_string(), port)
        }
    };
    let usable = !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._:".contains(&b));
    if !usable {
        return Err(format!("{text:?}: give it as {scheme}[user@]HOST[:PORT]"));
    }
    Ok(Some((user, host, port)))
}

impl Road {
    /// The VM's name in the messages and in the known hosts: `iap://` with
    /// its project, zone and name, or `eice://` with the endpoint's id and
    /// the instance's address.
    pub fn shown(&self) -> String {
        match self {
            Road::Iap(t) => format!("{}{}/{}/{}", iap::SCHEME, t.project, t.zone, t.instance),
            Road::Eice { endpoint, target } => match target.address {
                std::net::IpAddr::V6(v6) => format!("{}{}/[{v6}]", eice::SCHEME, endpoint.id),
                v4 => format!("{}{}/{v4}", eice::SCHEME, endpoint.id),
            },
            Road::Warp(target) => target.shown(),
            Road::Tor(target) => target.shown(),
        }
    }

    /// The name that the blocks of `ssh_config` match: the VM's name, or
    /// the instance's address.
    pub fn host(&self) -> String {
        match self {
            Road::Iap(t) => t.instance.clone(),
            Road::Eice { target, .. } => target.address.to_string(),
            Road::Warp(target) => target.host.clone(),
            Road::Tor(target) => target.host.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Road::Iap(t) => t.port,
            Road::Eice { target, .. } => target.port,
            Road::Warp(target) => target.port,
            Road::Tor(target) => target.port,
        }
    }

    /// The road's word in the session log.
    pub fn word(&self) -> &'static str {
        match self {
            Road::Iap(_) => "iap",
            Road::Eice { .. } => "eice",
            Road::Warp(_) => "warp",
            Road::Tor(_) => "tor",
        }
    }

    /// How long a session of the road may last before a copy opens a new
    /// one: EICE ends each tunnel at its duration, and a copy goes on in a
    /// new one first, as it does before the relay's limits.
    pub fn age_limit(&self) -> Option<Duration> {
        let Road::Eice { target, .. } = self else { return None };
        let life = u64::from(target.max_duration.unwrap_or(podssh_ws::eice::MAX_DURATION));
        let limit = life.saturating_sub((life / 12).max(30));
        (limit > 0).then(|| Duration::from_secs(limit))
    }
}

/// The road of a cloud's tunnel, from this host, to the run's `port`: no
/// `--direct`, no `-J` hop before it, no `HostName`, no `-4` or `-6`.
pub(super) fn transport(road: &Road, r: &super::node::Ask<'_>, env: &Env, port: u16) -> Result<Transport, Refusal> {
    let why = if r.args.direct {
        Some("--direct cannot reach it: its road is the provider's own tunnel")
    } else if r.jumps > 0 {
        Some("a -J hop cannot reach it, as its tunnel opens from this host: make it the first hop of -J")
    } else if r.host_name {
        Some("-o HostName cannot apply: the destination names the VM")
    } else if r.family.is_some() {
        Some("-4 and -6 do not apply: the cloud reaches the VM")
    } else {
        None
    };
    if let Some(why) = why {
        return Err(Refusal::usage(format!("{}: {why}", road.shown())));
    }
    let road = match road.clone() {
        Road::Iap(mut target) => {
            target.port = port;
            Road::Iap(target)
        }
        Road::Eice { endpoint, mut target } => {
            target.port = port;
            target.max_duration = eice::max_duration(std::env::var(DURATION_ENV).ok().as_deref())
                .map_err(|why| Refusal::config(format!("{DURATION_ENV}: {why}")))?;
            Road::Eice { endpoint, target }
        }
        Road::Warp(mut target) => {
            target.port = port;
            Road::Warp(target)
        }
        Road::Tor(mut target) => {
            target.port = port;
            Road::Tor(target)
        }
    };
    let trust = match super::resolve::ca_file(r.args, env) {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    Ok(Transport::Cloud { road, trust })
}

/// The stream to the VM of `road`.
pub(super) async fn reach(road: &Road, trust: &Trust, log: &Arc<Log>) -> Result<Reached, NotReached> {
    if podssh_relay::open::offline() {
        let line = format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Err(NotReached { lines: vec![line], code: crate::exitmap::sysexits::EX_UNAVAILABLE });
    }
    match road {
        Road::Iap(target) => iap::reach(target, trust, log).await,
        Road::Eice { endpoint, target } => eice::reach(endpoint, target, trust, log).await,
        Road::Warp(target) => warp::reach(target, trust, log).await,
        Road::Tor(target) => tor::reach(target, trust, log).await,
    }
}

/// The age limit of a run's road, for a copy's meter.
pub fn age_limit(transport: &Transport) -> Option<Duration> {
    match transport {
        Transport::Cloud { road, .. } => road.age_limit(),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
