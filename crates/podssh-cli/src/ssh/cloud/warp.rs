//! `warp://[user@]HOST[:PORT]` (T-352): a port of any host, 22 by default,
//! inside WARP's tunnel, MASQUE over HTTP/2 to Cloudflare's endpoint on port
//! 443 through `HTTPS_PROXY` when one is set (`podssh_warp`), with no relay:
//! Cloudflare's own network reaches the host. The road is in a build with
//! the feature `warp` only; without it, a `warp://` destination is refused
//! before anything connects, with exit 70.
//!
//! The device is registered once, after the user accepted Cloudflare's
//! Terms ([`ACCEPT_TERMS_ENV`]), and its record kept in the cache
//! ([`DEVICE_FILE`], a private file of T-243's directory), as a
//! registration at each run would spend a device.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::Trust;

use crate::ssh::transport::{Duplex, NotReached, Reached};

/// The form of a destination on this road.
pub const SCHEME: &str = "warp://";
/// The device's record in the cache; the name of `podssh_warp::device`.
pub const DEVICE_FILE: &str = "warp-device.json";
/// The user's acceptance of Cloudflare's Terms, which a registration needs.
pub const ACCEPT_TERMS_ENV: &str = "PODSSH_WARP_ACCEPT_TERMS";
/// The file of a team's token, for a device of a Cloudflare One organization.
pub const TEAM_TOKEN_FILE_ENV: &str = "PODSSH_WARP_TEAM_TOKEN_FILE";
/// Another endpoint of HTTP/2, `ADDRESS:PORT`, in place of 162.159.198.2:443.
pub const ENDPOINT_ENV: &str = "PODSSH_WARP_ENDPOINT";

/// A host and a port inside the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    /// The host as a destination shows it: an IPv6 address in brackets.
    pub fn shown(&self) -> String {
        if self.host.contains(':') {
            format!("{SCHEME}[{}]", self.host)
        } else {
            format!("{SCHEME}{}", self.host)
        }
    }
}

/// `warp://[user@]HOST[:PORT]` as its user and target; `None` for another
/// destination. An IPv6 address goes in brackets.
pub fn destination(text: &str) -> Result<Option<(Option<String>, Target)>, String> {
    let found = super::host_destination(text, SCHEME)?;
    Ok(found.map(|(user, host, port)| (user, Target { host, port })))
}

/// Why this build has no WARP road, for `what` that needs it.
pub fn not_built(what: &str) -> String {
    format!(
        "{what}: WARP's road is not in this build; build podssh with --features warp \
         (cargo build -p podssh-cli --features warp)"
    )
}

/// Whether `destination` names a host on this road.
pub fn is_warp(destination: &str) -> bool {
    destination.starts_with(SCHEME)
}

/// A line of the road, and the code of a run that it ends.
pub type Failed = (String, i32);

/// The stream to `target` inside WARP's tunnel: the device, the tunnel
/// through the environment's proxy, then the stream. `say` tells the user
/// of a registration, and `verbose` the rest.
#[cfg(feature = "warp")]
pub async fn open(
    target: &Target,
    trust: &Trust,
    say: &(dyn Fn(&str) + Sync),
    verbose: &(dyn Fn(&str) + Sync),
) -> Result<Box<dyn Duplex>, Failed> {
    use crate::exitmap::sysexits::EX_UNAVAILABLE;
    let shown = target.shown();
    let device = road::device(trust, say, verbose).await.map_err(|(line, code)| (format!("{shown}: {line}"), code))?;
    let limit = podssh_relay::open::CONNECT_TIMEOUT;
    verbose(&format!("connecting to {shown}, port {}, inside WARP's tunnel ({})", target.port, device.endpoint));
    let warp = podssh_warp::Warp::open(&device, &podssh_ws::ProxyChoice::FromEnvironment, limit)
        .await
        .map_err(|fault| (format!("{shown}: {fault}"), road::code(&fault)))?;
    verbose(&format!("{shown}: the tunnel opened, to {}", warp.via()));
    let stream = warp
        .connect(&target.host, target.port, limit)
        .await
        .map_err(|why| (format!("{shown}: inside WARP's tunnel: {why}"), EX_UNAVAILABLE))?;
    Ok(Box::new(stream))
}

/// In a build without the feature: the refusal, which `podssh ssh` says
/// before anything is resolved; a road that reaches here says it again.
#[cfg(not(feature = "warp"))]
pub async fn open(
    target: &Target,
    _trust: &Trust,
    _say: &(dyn Fn(&str) + Sync),
    _verbose: &(dyn Fn(&str) + Sync),
) -> Result<Box<dyn Duplex>, Failed> {
    Err((not_built(&target.shown()), crate::exit_codes::EXIT_NOT_IMPLEMENTED))
}

/// The stream to `target`, as `podssh ssh` reaches a first hop.
pub(super) async fn reach(target: &Target, trust: &Trust, log: &Arc<Log>) -> Result<Reached, NotReached> {
    let (info, more) = (log.clone(), log.clone());
    let say = move |line: &str| info.info(line);
    let verbose = move |line: &str| more.verbose(line);
    match open(target, trust, &say, &verbose).await {
        Ok(stream) => Ok(Reached { stream, relay: None, direct_proxy: None, layer: None }),
        Err((line, code)) => Err(NotReached { lines: vec![line], code }),
    }
}

#[cfg(feature = "warp")]
pub mod road;

/// Whether `value` of [`ACCEPT_TERMS_ENV`] accepts the Terms: yes, on, true
/// or 1; no, off, false, 0, empty or unset do not; another word is a
/// setting that cannot be used.
pub fn accepted(value: Option<&str>) -> Result<bool, String> {
    let Some(value) = value else { return Ok(false) };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "no" | "off" | "false" | "0" => Ok(false),
        "yes" | "on" | "true" | "1" => Ok(true),
        _ => Err(format!("{ACCEPT_TERMS_ENV}={value}: yes or no")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warp_a_destination_is_read() {
        let (user, target) = destination("warp://me@github.com").unwrap().unwrap();
        assert_eq!((user.as_deref(), target.host.as_str(), target.port), (Some("me"), "github.com", 22));
        assert_eq!(target.shown(), "warp://github.com");
        let (_, target) = destination("warp://[2001:db8::1]:2222").unwrap().unwrap();
        assert_eq!((target.host.as_str(), target.port), ("2001:db8::1", 2222));
        assert_eq!(target.shown(), "warp://[2001:db8::1]");
        let (_, target) = destination("warp://192.0.2.10:443/").unwrap().unwrap();
        assert_eq!((target.host.as_str(), target.port), ("192.0.2.10", 443));
        assert_eq!(destination("github.com").unwrap(), None);
        for bad in [
            "warp://",
            "warp://@host",
            "warp://2001:db8::1",
            "warp://[2001:db8::1",
            "warp://[host]:22",
            "warp://host:0",
            "warp://host/path",
            "warp://ho st",
        ] {
            assert!(destination(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn warp_the_terms_are_accepted_by_a_word() {
        assert_eq!(accepted(None), Ok(false));
        assert_eq!(accepted(Some("yes")), Ok(true));
        assert_eq!(accepted(Some(" ON ")), Ok(true));
        assert_eq!(accepted(Some("no")), Ok(false));
        assert!(accepted(Some("maybe")).is_err());
    }

    /// The name of the record is the library's, in a build that has it.
    #[cfg(feature = "warp")]
    #[test]
    fn warp_the_record_s_name_is_the_library_s() {
        assert_eq!(DEVICE_FILE, podssh_warp::device::FILE);
    }
}
