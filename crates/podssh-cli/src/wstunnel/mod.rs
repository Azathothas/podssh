//! `--wstunnel wss://HOST[:PORT]` (T-441, the operator's ruling Q66): a
//! server of erebe/wstunnel that the user runs (`wstunnel server
//! wss://[::]:443`), which takes the destination from its client, is the
//! road in place of the relay, so that a server of the user's own is a road
//! with no relay. podssh opens the WebSocket to it, through `HTTPS_PROXY`
//! when one is set, and its token names the first hop
//! (`podssh_ws::wstunnel`); SSH's host key protects the session, as on each
//! road.
//!
//! The server comes from `--wstunnel`, else `PODSSH_WSTUNNEL` where the
//! command line names no other road. What it checks of a client, the path
//! prefix that it restricts and the credentials that its restrictions
//! match, comes from a private file, `--wstunnel-secret-file` or
//! `PODSSH_WSTUNNEL_SECRET_FILE`, never from the URL, where argv would show
//! it; with none, podssh is the client of wstunnel's defaults (the prefix
//! `v1`).

pub mod pipe;
pub mod reach;

use std::path::Path;

use podssh_ws::wstunnel::{Secret, Server};
use podssh_ws::Trust;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Env, Resolved, Transport};

/// The variable of the server, as `--wstunnel`.
pub const WSTUNNEL_ENV: &str = "PODSSH_WSTUNNEL";
/// The variable of its secret file, as `--wstunnel-secret-file`.
pub const SECRET_ENV: &str = "PODSSH_WSTUNNEL_SECRET_FILE";

/// The flags of a command that takes `--wstunnel`, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub url: Option<String>,
    pub secret_file: Option<String>,
}

impl Flags {
    pub fn of(args: &SshArgs) -> Flags {
        Flags { url: args.wstunnel.clone(), secret_file: args.wstunnel_secret_file.clone() }
    }
}

/// The server of a run, what it checks of a client, and the trust of its
/// TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Road {
    pub server: Server,
    pub secret: Secret,
    pub trust: Trust,
}

impl Road {
    /// The server as each line names it: its URL, which holds no secret.
    pub fn shown(&self) -> String {
        self.server.shown()
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// The road of the flags, else of the variables; none when neither names a
/// server. A bad flag is a usage error (64), a bad variable or secret file
/// a configuration error (78).
pub fn chosen(flags: &Flags, trust: Trust) -> Result<Option<Road>, Refusal> {
    from(flags, var(WSTUNNEL_ENV), var(SECRET_ENV), trust)
}

/// [`chosen`] with the variables given.
pub fn from(
    flags: &Flags,
    url_env: Option<String>,
    secret_env: Option<String>,
    trust: Trust,
) -> Result<Option<Road>, Refusal> {
    let (url, flag) = match (&flags.url, url_env) {
        (Some(url), _) => (url.clone(), true),
        (None, Some(url)) => (url, false),
        (None, None) if flags.secret_file.is_some() => {
            return Err(Refusal::usage(format!("--wstunnel-secret-file is for --wstunnel, or {WSTUNNEL_ENV}")))
        }
        (None, None) => return Ok(None),
    };
    let bad = |why: String| match flag {
        true => Refusal::usage(format!("--wstunnel: {why}")),
        false => Refusal::config(format!("{WSTUNNEL_ENV}: {why}")),
    };
    let server = Server::parse(&url).map_err(bad)?;
    // The flag's file wins over the variable's, as the flag's server does.
    let secret = match flags.secret_file.clone().or(secret_env) {
        Some(path) => {
            let at = format!("--wstunnel-secret-file {path}");
            let text = podssh_relay::cache::read_private(Path::new(&path))
                .map_err(|why| Refusal::config(format!("{at}: {why}")))?;
            let text = Zeroizing::new(text);
            Secret::parse(&text).map_err(|why| Refusal::config(format!("{at}: {why}")))?
        }
        None => Secret::default(),
    };
    podssh_ws::wstunnel::check(&server, &secret).map_err(bad)?;
    Ok(Some(Road { server, secret, trust }))
}

/// The flag of another road on the command line, if one is given.
fn other_road(args: &SshArgs) -> Option<&'static str> {
    let flags = [
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
        ("--via", args.via.is_some()),
        ("--vless", args.vless.is_some()),
    ];
    flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag)
}

/// The variable of another road beside `PODSSH_WSTUNNEL`, if one is set.
fn other_variable(env: &Env) -> Option<&'static str> {
    if env.relay.is_some() {
        return Some(podssh_relay::relay::RELAY_ENV);
    }
    [crate::forwarder::FORWARDER_ENV, crate::via::VIA_ENV].into_iter().find(|name| var(name).is_some())
}

/// The road of a run that resolved to the relay: the wstunnel server when
/// `--wstunnel` names one, or `PODSSH_WSTUNNEL` where neither the command
/// line nor another variable names another road, with the relay's trust;
/// else the road as it was. It runs before the other roads that take the
/// relay's place, so that its flag wins over their variables.
pub fn or_relay(args: &SshArgs, env: &Env, relay: Transport) -> Result<Transport, Refusal> {
    let Transport::Relay { trust, family, .. } = &relay else { return Ok(relay) };
    let flags = Flags::of(args);
    match (&flags.url, other_road(args)) {
        (Some(_), Some(other)) => {
            return Err(Refusal::usage(format!("--wstunnel and {other} name two roads; a run has one")))
        }
        (None, Some(_)) if flags.secret_file.is_none() => return Ok(relay),
        (None, None) if var(WSTUNNEL_ENV).is_some() => {
            if let Some(other) = other_variable(env) {
                return Err(Refusal::config(format!("{WSTUNNEL_ENV} and {other} name two roads; a run has one")));
            }
        }
        _ => {}
    }
    let Some(road) = chosen(&flags, trust.clone())? else { return Ok(relay) };
    if family.is_some() {
        let why = "-4 and -6 choose the family that the relay dials; the wstunnel server dials as it chooses";
        return Err(Refusal::usage(why));
    }
    Ok(Transport::Wstunnel { road })
}

/// `--wstunnel` beside a road of its own, which [`or_relay`] never took, and
/// `--wstunnel-secret-file` with no server: a usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    let other = match &resolved.transport {
        Transport::Wstunnel { .. } => return Ok(()),
        Transport::Direct => "--direct",
        Transport::Relay { .. } => "the relay",
        Transport::Forwarder { .. } => "the forwarders",
        Transport::Shadowsocks { .. } => "--shadowsocks",
        Transport::Via { .. } => "--via",
        Transport::Vless { .. } => "--vless",
        Transport::Node { .. } => "a node:// destination",
        Transport::Iroh { .. } => "an iroh: destination",
        Transport::Cloudflare { .. } => "a cf://HOST destination or first hop",
        Transport::Cloud { .. } => "an iap://, eice://, warp:// or tor:// destination or first hop",
        Transport::Derp { .. } => "a derp: destination",
        Transport::Chisel { .. } => "--chisel",
    };
    if args.wstunnel.is_some() {
        let why = format!("--wstunnel cannot go with {other}, which is a road of its own; a run has one road");
        return Err(Refusal::usage(why));
    }
    if args.wstunnel_secret_file.is_some() {
        let why = format!("--wstunnel-secret-file is for --wstunnel, or {WSTUNNEL_ENV}, which {other} does not take");
        return Err(Refusal::usage(why));
    }
    Ok(())
}

/// The trust of the server's TLS: `--ca-file`, else `SSL_CERT_FILE` or
/// `CaFile`, else podssh's default stores, as the relay's.
pub fn trust(ca_file: Option<&str>) -> Trust {
    crate::via::trust(ca_file)
}

#[cfg(test)]
mod tests;
