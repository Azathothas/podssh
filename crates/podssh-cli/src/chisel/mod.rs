//! `--chisel URL` (T-490, the operator's ruling Q66): a server of
//! jpillora/chisel that the user runs (`chisel server --port 443 --auth
//! user:pass`), which takes the destination from its client, is the road in
//! place of the relay. podssh opens the WebSocket to it, through
//! `HTTPS_PROXY` when one is set (`podssh_ws::chisel`), speaks SSH inside it
//! as chisel's client does ([`link`]), and opens one channel `chisel` for
//! each session, its target the first hop; SSH's host key of the first hop
//! protects the session, as on each road, and the server's own key is
//! checked by its fingerprint when the file names one.
//!
//! The server comes from `--chisel`, else `PODSSH_CHISEL` where the command
//! line names no other road. Its user and password, and the fingerprint of
//! its key, come from a private file, `--chisel-auth-file` or
//! `PODSSH_CHISEL_AUTH_FILE`, never from the URL or argv ([`Secret`]).

pub mod link;
pub mod pipe;
pub mod reach;

use std::path::Path;

use podssh_ws::chisel::Server;
use podssh_ws::Trust;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Env, Resolved, Transport};

/// The variable of the server, as `--chisel`.
pub const CHISEL_ENV: &str = "PODSSH_CHISEL";
/// The variable of its credentials file, as `--chisel-auth-file`.
pub const AUTH_ENV: &str = "PODSSH_CHISEL_AUTH_FILE";

/// The flags of a command that takes `--chisel`, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub url: Option<String>,
    pub auth_file: Option<String>,
}

impl Flags {
    pub fn of(args: &SshArgs) -> Flags {
        Flags { url: args.chisel.clone(), auth_file: args.chisel_auth_file.clone() }
    }
}

/// What the client gives the server, and what it checks of it: the user and
/// password of chisel's `--auth`, and the fingerprint of the server's key,
/// as chisel's `--fingerprint` (SHA-256 in base64, 44 characters). Never
/// shown.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret {
    pub user: String,
    pub password: Zeroizing<String>,
    pub fingerprint: Option<String>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret").field("fingerprint", &self.fingerprint).finish_non_exhaustive()
    }
}

impl Secret {
    /// The secret of a file's text: lines `auth USER:PASSWORD`, as chisel's
    /// `--auth` and its authfile's keys, and `fingerprint BASE64`, each once;
    /// `#` starts a comment line. A refusal names a line by its number, never
    /// its text.
    pub fn parse(text: &str) -> Result<Secret, String> {
        let mut secret = Secret::default();
        let (mut auth, mut seen_any) = (false, false);
        for (n, line) in text.lines().enumerate().map(|(n, l)| (n + 1, l.trim())) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            seen_any = true;
            let (word, value) = line.split_once(char::is_whitespace).map_or((line, ""), |(w, v)| (w, v.trim()));
            if value.is_empty() {
                return Err(format!("line {n}: {word} has no value"));
            }
            match word {
                "auth" if auth => return Err(format!("line {n}: a second auth")),
                "auth" => {
                    let Some((user, password)) = value.split_once(':') else {
                        return Err(format!("line {n}: auth takes USER:PASSWORD, as chisel's --auth"));
                    };
                    if user.is_empty() {
                        return Err(format!("line {n}: auth names no user"));
                    }
                    (secret.user, secret.password, auth) =
                        (user.to_string(), Zeroizing::new(password.to_string()), true);
                }
                "fingerprint" if secret.fingerprint.is_some() => return Err(format!("line {n}: a second fingerprint")),
                "fingerprint" => {
                    secret.fingerprint = Some(fingerprint(value).map_err(|why| format!("line {n}: {why}"))?)
                }
                _ => return Err(format!("line {n}: it takes auth USER:PASSWORD and fingerprint BASE64")),
            }
        }
        match seen_any {
            true => Ok(secret),
            false => Err("it has no line: give auth USER:PASSWORD, fingerprint BASE64, or both".into()),
        }
    }
}

/// A fingerprint as chisel prints it: SHA-256 of the key in base64 with its
/// padding, 44 characters. chisel's deprecated MD5 form is refused.
pub fn fingerprint(text: &str) -> Result<String, String> {
    use base64::Engine as _;
    let text = text.trim();
    let raw = base64::engine::general_purpose::STANDARD.decode(text).ok().filter(|b| b.len() == 32);
    match raw {
        Some(_) if text.len() == 44 => Ok(text.to_string()),
        _ if text.contains(':') => {
            Err("an MD5 fingerprint with colons, which chisel deprecated: give the SHA-256 one \
                                         that chisel server prints (44 characters, base64)"
                .into())
        }
        _ => Err("a fingerprint is SHA-256 in base64, 44 characters, as chisel server prints it".into()),
    }
}

/// The server of a run, what it gives and checks, and the trust of its TLS.
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
/// server. A bad flag is a usage error (64), a bad variable or file a
/// configuration error (78).
pub fn chosen(flags: &Flags, trust: Trust) -> Result<Option<Road>, Refusal> {
    from(flags, var(CHISEL_ENV), var(AUTH_ENV), trust)
}

/// [`chosen`] with the variables given.
pub fn from(
    flags: &Flags,
    url_env: Option<String>,
    auth_env: Option<String>,
    trust: Trust,
) -> Result<Option<Road>, Refusal> {
    let (url, flag) = match (&flags.url, url_env) {
        (Some(url), _) => (url.clone(), true),
        (None, Some(url)) => (url, false),
        (None, None) if flags.auth_file.is_some() => {
            return Err(Refusal::usage(format!("--chisel-auth-file is for --chisel, or {CHISEL_ENV}")))
        }
        (None, None) => return Ok(None),
    };
    let bad = |why: String| match flag {
        true => Refusal::usage(format!("--chisel: {why}")),
        false => Refusal::config(format!("{CHISEL_ENV}: {why}")),
    };
    if url.contains('@') {
        return Err(bad("the URL names a user: the user and password go in a file (--chisel-auth-file)".into()));
    }
    let server = Server::parse(&url).map_err(bad)?;
    // The flag's file wins over the variable's, as the flag's server does.
    let secret = match flags.auth_file.clone().or(auth_env) {
        Some(path) => {
            let at = format!("--chisel-auth-file {path}");
            let text = podssh_relay::cache::read_private(Path::new(&path))
                .map_err(|why| Refusal::config(format!("{at}: {why}")))?;
            let text = Zeroizing::new(text);
            Secret::parse(&text).map_err(|why| Refusal::config(format!("{at}: {why}")))?
        }
        None => Secret::default(),
    };
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
        ("--wstunnel", args.wstunnel.is_some()),
    ];
    flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag)
}

/// The variable of another road beside `PODSSH_CHISEL`, if one is set.
fn other_variable(env: &Env) -> Option<&'static str> {
    if env.relay.is_some() {
        return Some(podssh_relay::relay::RELAY_ENV);
    }
    [crate::forwarder::FORWARDER_ENV, crate::via::VIA_ENV, crate::wstunnel::WSTUNNEL_ENV]
        .into_iter()
        .find(|name| var(name).is_some())
}

/// The road of a run that resolved to the relay: the chisel server when
/// `--chisel` names one, or `PODSSH_CHISEL` where neither the command line
/// nor another variable names another road, with the relay's trust; else
/// the road as it was. It runs first of the roads that take the relay's
/// place, so that its flag wins over their variables.
pub fn or_relay(args: &SshArgs, env: &Env, relay: Transport) -> Result<Transport, Refusal> {
    let Transport::Relay { trust, family, .. } = &relay else { return Ok(relay) };
    let flags = Flags::of(args);
    match (&flags.url, other_road(args)) {
        (Some(_), Some(other)) => {
            return Err(Refusal::usage(format!("--chisel and {other} name two roads; a run has one")))
        }
        (None, Some(_)) if flags.auth_file.is_none() => return Ok(relay),
        (None, None) if var(CHISEL_ENV).is_some() => {
            if let Some(other) = other_variable(env) {
                return Err(Refusal::config(format!("{CHISEL_ENV} and {other} name two roads; a run has one")));
            }
        }
        _ => {}
    }
    let Some(road) = chosen(&flags, trust.clone())? else { return Ok(relay) };
    if family.is_some() {
        let why = "-4 and -6 choose the family that the relay dials; the chisel server dials as it chooses";
        return Err(Refusal::usage(why));
    }
    Ok(Transport::Chisel { road })
}

/// `--chisel` beside a road of its own, which [`or_relay`] never took, and
/// `--chisel-auth-file` with no server: a usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    let other = match &resolved.transport {
        Transport::Chisel { .. } => return Ok(()),
        other => crate::ssh::servers::road_name(other),
    };
    if args.chisel.is_some() {
        let why = format!("--chisel cannot go with {other}, which is a road of its own; a run has one road");
        return Err(Refusal::usage(why));
    }
    if args.chisel_auth_file.is_some() {
        let why = format!("--chisel-auth-file is for --chisel, or {CHISEL_ENV}, which {other} does not take");
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
