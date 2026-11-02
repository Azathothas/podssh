//! `--via https://[USER@]HOST[:PORT]` (T-439, the operator's ruling Q66): a
//! forward proxy over TLS that the user runs (Caddy's forwardproxy, squid's
//! `https_port`, h2o) is the road in place of the relay, so that a server
//! of the user's own is a road with no relay. podssh opens TLS to it,
//! through `HTTPS_PROXY` first when one is set, then sends CONNECT inside
//! (`podssh_ws::via`); the tunnel then carries the session as the direct
//! road's TCP does, and SSH's host key protects it, as on each road.
//!
//! The proxy comes from `--via`, else `PODSSH_VIA` where the command line
//! names no other road. Its Basic credentials come from a private file,
//! `--via-auth-file` or `PODSSH_VIA_AUTH_FILE`, never from the URL, where
//! argv would show them. The tunnels of one run, as `each` makes, are
//! streams of one HTTP/2 connection where the proxy speaks HTTP/2
//! ([`client`]).

pub mod pipe;
pub mod reach;

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use podssh_ws::via::{Client, Dial, Offer, Via};
use podssh_ws::{ProxyChoice, Trust};
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Env, Resolved, Transport};

/// The variable of the second proxy, as `--via`.
pub const VIA_ENV: &str = "PODSSH_VIA";
/// The variable of its credentials file, as `--via-auth-file`.
pub const AUTH_ENV: &str = "PODSSH_VIA_AUTH_FILE";
/// The versions of HTTP offered to it: `1.1`, `2`, or both (the default).
pub const HTTP_ENV: &str = "PODSSH_VIA_HTTP";

/// The flags of a command that takes `--via`, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub url: Option<String>,
    pub auth_file: Option<String>,
}

impl Flags {
    pub fn of(args: &SshArgs) -> Flags {
        Flags { url: args.via.clone(), auth_file: args.via_auth_file.clone() }
    }
}

/// The second proxy of a run, the trust of its TLS, and the versions of
/// HTTP that it is offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Road {
    pub via: Via,
    pub trust: Trust,
    pub offer: Offer,
}

impl Road {
    /// The proxy as each line names it: its URL with no user.
    pub fn shown(&self) -> String {
        self.via.shown()
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// The road of the flags, else of the variables; none when neither names a
/// proxy. A bad flag is a usage error (64), a bad variable or credentials
/// file a configuration error (78).
pub fn chosen(flags: &Flags, trust: Trust) -> Result<Option<Road>, Refusal> {
    from(flags, var(VIA_ENV), var(AUTH_ENV), var(HTTP_ENV), trust)
}

/// [`chosen`] with the variables given.
pub fn from(
    flags: &Flags,
    url_env: Option<String>,
    auth_env: Option<String>,
    http_env: Option<String>,
    trust: Trust,
) -> Result<Option<Road>, Refusal> {
    let (url, flag) = match (&flags.url, url_env) {
        (Some(url), _) => (url.clone(), true),
        (None, Some(url)) => (url, false),
        (None, None) if flags.auth_file.is_some() => {
            return Err(Refusal::usage(format!("--via-auth-file is for --via, or {VIA_ENV}")))
        }
        (None, None) => return Ok(None),
    };
    let bad = |why: String| match flag {
        true => Refusal::usage(format!("--via: {why}")),
        false => Refusal::config(format!("{VIA_ENV}: {why}")),
    };
    let via = Via::parse(&url).map_err(bad)?;
    let offer = match http_env {
        Some(value) => Offer::parse(&value).map_err(|why| Refusal::config(format!("{HTTP_ENV}: {why}")))?,
        None => Offer::Both,
    };
    // The flag's file wins over the variable's, as the flag's proxy does.
    let via = match flags.auth_file.clone().or(auth_env) {
        Some(path) => {
            let at = format!("--via-auth-file {path}");
            let text = podssh_relay::cache::read_private(Path::new(&path))
                .map_err(|why| Refusal::config(format!("{at}: {why}")))?;
            let text = Zeroizing::new(text);
            via.with_credentials(&text).map_err(|why| Refusal::config(format!("{at}: {why}")))?
        }
        None if via.names_user() => {
            return Err(bad("it names a user, and no file gives the password: give --via-auth-file FILE".into()))
        }
        None => via,
    };
    Ok(Some(Road { via, trust, offer }))
}

/// The flag of another road on the command line, if one is given.
fn other_road(args: &SshArgs) -> Option<&'static str> {
    let flags = [
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
    ];
    flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag)
}

/// The road of a run that resolved to the relay: the second proxy when
/// `--via` names one, or `PODSSH_VIA` where the command line names no other
/// road, with the relay's trust; else the road as it was. `-4` and `-6`
/// choose the family that the relay dials, and the proxy dials as it
/// chooses.
pub fn or_relay(args: &SshArgs, env: &Env, relay: Transport) -> Result<Transport, Refusal> {
    let Transport::Relay { trust, family, .. } = &relay else { return Ok(relay) };
    let flags = Flags::of(args);
    match (&flags.url, other_road(args)) {
        (Some(_), Some(other)) => {
            return Err(Refusal::usage(format!("--via and {other} name two roads; a run has one")))
        }
        (None, Some(_)) if flags.auth_file.is_none() => return Ok(relay),
        (None, _) if env.relay.is_some() && var(VIA_ENV).is_some() => {
            let relay_env = podssh_relay::relay::RELAY_ENV;
            return Err(Refusal::config(format!("{VIA_ENV} and {relay_env} name two roads; a run has one")));
        }
        (None, None) if var(VIA_ENV).is_some() && var(crate::forwarder::FORWARDER_ENV).is_some() => {
            let forwarders = crate::forwarder::FORWARDER_ENV;
            return Err(Refusal::config(format!("{VIA_ENV} and {forwarders} name two roads; a run has one")));
        }
        _ => {}
    }
    let Some(road) = chosen(&flags, trust.clone())? else { return Ok(relay) };
    if family.is_some() {
        let why = "-4 and -6 choose the family that the relay dials; the proxy of --via dials as it chooses";
        return Err(Refusal::usage(why));
    }
    Ok(Transport::Via { road })
}

/// `--via` beside a road of its own, which [`or_relay`] never took, and
/// `--via-auth-file` with no proxy: a usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    let other = match &resolved.transport {
        Transport::Via { .. } => return Ok(()),
        Transport::Direct => "--direct",
        Transport::Relay { .. } => "the relay",
        Transport::Forwarder { .. } => "the forwarders",
        Transport::Shadowsocks { .. } => "--shadowsocks",
        Transport::Node { .. } => "a node:// destination",
        Transport::Iroh { .. } => "an iroh: destination",
        Transport::Cloudflare { .. } => "a cf://HOST destination or first hop",
        Transport::Cloud { .. } => "an iap://, eice://, warp:// or tor:// destination or first hop",
        Transport::Derp { .. } => "a derp: destination",
        Transport::Wstunnel { .. } => "--wstunnel",
    };
    if args.via.is_some() {
        let why = format!("--via cannot go with {other}, which is a road of its own; a run has one road");
        return Err(Refusal::usage(why));
    }
    if args.via_auth_file.is_some() {
        return Err(Refusal::usage(format!("--via-auth-file is for --via, or {VIA_ENV}, which {other} does not take")));
    }
    Ok(())
}

/// The clients of this process, one for each second proxy, so that the
/// tunnels of a run share HTTP/2's connection.
static CLIENTS: Mutex<Vec<(Road, Arc<Client>)>> = Mutex::new(Vec::new());

/// The client of `road`, made at its first use: TCP through `HTTPS_PROXY`
/// when one is set, each step within the relay's bound of a connection.
pub fn client(road: &Road) -> Arc<Client> {
    let mut clients = CLIENTS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, client)) = clients.iter().find(|(kept, _)| kept == road) {
        return client.clone();
    }
    let dial = Dial {
        trust: road.trust.clone(),
        proxy: ProxyChoice::FromEnvironment,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        offer: road.offer,
    };
    let client = Arc::new(Client::new(road.via.clone(), dial));
    clients.push((road.clone(), client.clone()));
    client
}

/// The trust of the proxy's TLS: `--ca-file`, else `SSL_CERT_FILE` or
/// `CaFile`, else podssh's default stores, as the relay's.
pub fn trust(ca_file: Option<&str>) -> Trust {
    crate::settings::ca_file(ca_file).map_or(Trust::Default, |file| Trust::File(file.into()))
}

#[cfg(test)]
mod tests;
