//! `podssh ssh cf://[user@]HOST` (T-264): SSH to a service that Cloudflare's
//! `cloudflared` publishes under HOST, the name of a tunnel's `ssh://` or
//! `tcp://` rule, over the WebSocket that `cloudflared access tcp` opens, with
//! no program of Cloudflare's, through `HTTPS_PROXY` when one is set
//! (`podssh_ws::cloudflare`). A name behind Cloudflare Access needs a service
//! token, or a token of a user made on another host
//! (`cloudflared access token -app=https://HOST`): the browser login of
//! Access cannot run in a cage. Each credential comes from the environment or
//! a file, never from the command line. The host key is recorded under HOST,
//! as with OpenSSH's `ProxyCommand cloudflared access ssh --hostname %h`.

use std::io::Read;

use podssh_ssh::Log;
use podssh_ws::client::{ConnectError, DEFAULT_IDLE_TIMEOUT};
use podssh_ws::cloudflare::{self, Access};
use podssh_ws::{ProxyChoice, Trust};
use zeroize::Zeroizing;

use super::resolve::{Env, Transport};
use super::transport::{NotReached, Reached};
use crate::exitmap::sysexits;

/// The form of a destination on this road.
pub const SCHEME: &str = "cf://";
/// A service token of Cloudflare Access: its id and its secret.
pub const CLIENT_ID_ENV: &str = "PODSSH_CF_ACCESS_CLIENT_ID";
pub const CLIENT_SECRET_ENV: &str = "PODSSH_CF_ACCESS_CLIENT_SECRET";
/// A token of a user (`cloudflared access token -app=https://HOST`), or the
/// file that holds one.
pub const TOKEN_ENV: &str = "PODSSH_CF_ACCESS_TOKEN";
pub const TOKEN_FILE_ENV: &str = "PODSSH_CF_ACCESS_TOKEN_FILE";
/// The longest credential: a token of Access is about 1 KiB.
const MAX_VALUE: usize = 8192;

/// `cf://[user@]HOST` as the user and HOST, in lower case; `None` for each
/// other destination.
pub fn destination(text: &str) -> Result<Option<(Option<String>, String)>, String> {
    let Some(rest) = text.strip_prefix(SCHEME) else { return Ok(None) };
    let rest = rest.trim_end_matches('/');
    let (user, host) = match rest.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() => (Some(user.to_string()), host),
        Some(_) => return Err(format!("{text:?}: empty user name")),
        None => (None, rest),
    };
    if host.is_empty() {
        return Err(format!("{text:?}: no HOST after {SCHEME}"));
    }
    if host.contains(':') {
        return Err(format!("{text:?}: a tunnel has no port here: its rule names the service"));
    }
    let named = host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if !named || host.starts_with(['.', '-']) || !host.contains('.') {
        return Err(format!("{text:?}: HOST is the DNS name of the tunnel's rule"));
    }
    Ok(Some((user, host.to_ascii_lowercase())))
}

/// The road of `cf://HOST`: the WebSocket alone, from this host, so no
/// `--direct`, `-J`, port, `HostName` or address family applies.
pub(super) fn transport(r: &super::node::Ask<'_>, env: &Env) -> Result<Transport, String> {
    let why = if r.args.direct {
        Some("--direct cannot reach a Cloudflare tunnel: its road is the WebSocket")
    } else if r.jumps > 0 {
        Some("a Cloudflare tunnel cannot be reached through a -J hop yet")
    } else if r.port {
        Some("a tunnel has no port here: its rule names the service")
    } else if r.host_name {
        Some("-o HostName cannot apply to a Cloudflare tunnel")
    } else if r.family.is_some() {
        Some("-4 and -6 do not apply: Cloudflare's edge dials the service")
    } else {
        None
    };
    if let Some(why) = why {
        return Err(format!("{SCHEME}{}: {why}", r.label));
    }
    let trust = match super::resolve::ca_file(r.args, env) {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    Ok(Transport::Cloudflare { host: r.label.to_string(), trust })
}

/// The credentials of Cloudflare Access, as `read` gives each variable: a
/// refusal names the variable, never the value.
pub fn access_from(read: &dyn Fn(&str) -> Option<String>) -> Result<Access, String> {
    let value = |name: &str| -> Result<Option<Zeroizing<String>>, String> {
        let Some(raw) = read(name).map(Zeroizing::new) else { return Ok(None) };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        check(name, trimmed)?;
        Ok(Some(Zeroizing::new(trimmed.to_string())))
    };
    let client_id = value(CLIENT_ID_ENV)?;
    let client_secret = value(CLIENT_SECRET_ENV)?;
    if client_id.is_some() != client_secret.is_some() {
        return Err(format!(
            "{CLIENT_ID_ENV} and {CLIENT_SECRET_ENV} go together: a service token of Cloudflare Access is both"
        ));
    }
    let token = match value(TOKEN_ENV)? {
        Some(token) => Some(token),
        None => read(TOKEN_FILE_ENV).filter(|p| !p.trim().is_empty()).map(|p| token_file(p.trim())).transpose()?,
    };
    Ok(Access { client_id, client_secret, token })
}

fn check(name: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_VALUE || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(format!(
            "{name} is not a credential of Cloudflare Access: 1 to {MAX_VALUE} printable characters, with no space"
        ));
    }
    Ok(())
}

/// The token in the file of `path`, trimmed.
fn token_file(path: &str) -> Result<Zeroizing<String>, String> {
    let mut text = Zeroizing::new(String::new());
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_VALUE as u64 + 1).read_to_string(&mut text))
        .map_err(|e| format!("{TOKEN_FILE_ENV}: {path}: {e}"))?;
    let token = text.trim();
    if token.is_empty() {
        return Err(format!("{TOKEN_FILE_ENV}: {path} holds no token"));
    }
    check(TOKEN_FILE_ENV, token)?;
    Ok(Zeroizing::new(token.to_string()))
}

/// Why the tunnel of `host` did not take the session, and the code of a
/// command that says so: 77 for a refusal of Cloudflare Access, 69 else.
pub fn refusal(host: &str, e: &ConnectError) -> (String, i32) {
    match e {
        ConnectError::Refused { status, body } if cloudflare::refused_by_access(*status, body) => {
            let said = if body.is_empty() { String::new() } else { format!(", {body}") };
            (
                format!(
                    "{SCHEME}{host}: Cloudflare Access refused the session (HTTP {status}{said}): give a service \
                     token in {CLIENT_ID_ENV} and {CLIENT_SECRET_ENV}, or a token of \
                     `cloudflared access token -app=https://{host}` in {TOKEN_ENV} or the file of {TOKEN_FILE_ENV}"
                ),
                sysexits::EX_NOPERM,
            )
        }
        ConnectError::Refused { status, body } => {
            let said = if body.is_empty() { String::new() } else { format!(": {body}") };
            (
                format!("{SCHEME}{host}: the tunnel did not take the session: HTTP {status}{said}"),
                sysexits::EX_UNAVAILABLE,
            )
        }
        other => (format!("{SCHEME}{host}: {other}"), sysexits::EX_UNAVAILABLE),
    }
}

/// The stream to the service of `host`'s tunnel.
pub(super) async fn reach(host: &str, trust: &Trust, log: &Log) -> Result<Reached, NotReached> {
    if podssh_relay::open::offline() {
        let line = format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Err(NotReached { lines: vec![line], code: sysexits::EX_UNAVAILABLE });
    }
    let access = access_from(&|name| std::env::var(name).ok())
        .map_err(|why| NotReached { lines: vec![why], code: sysexits::EX_CONFIG })?;
    log.verbose(&format!("connecting to {SCHEME}{host} over its Cloudflare tunnel"));
    let timeout = podssh_relay::open::CONNECT_TIMEOUT;
    match cloudflare::connect(host, &access, trust, &ProxyChoice::FromEnvironment, timeout, Some(DEFAULT_IDLE_TIMEOUT))
        .await
    {
        Ok(session) => {
            log.verbose(&format!("the tunnel of {host} took the session"));
            let (stream, _) = podssh_ssh::relay_stream::spawn(session);
            Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None })
        }
        Err(e) => {
            let (line, code) = refusal(host, &e);
            Err(NotReached { lines: vec![line], code })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_destination_is_a_dns_name_with_no_port() {
        assert_eq!(destination("cf://ssh.example.org").unwrap(), Some((None, "ssh.example.org".into())));
        assert_eq!(
            destination("cf://me@SSH.Example.org/").unwrap(),
            Some((Some("me".into()), "ssh.example.org".into()))
        );
        assert_eq!(destination("ssh.example.org").unwrap(), None);
        for bad in
            ["cf://", "cf://@h.example", "cf://h.example:22", "cf://h.example/x", "cf://localhost", "cf://-h.example"]
        {
            assert!(destination(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cloudflare_credentials_name_their_variable_and_never_the_value() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
        };
        let none = access_from(&env(&[])).unwrap();
        assert!(none.client_id.is_none() && none.token.is_none());
        let service =
            access_from(&env(&[(CLIENT_ID_ENV, " id.access "), (CLIENT_SECRET_ENV, "secret-value")])).unwrap();
        assert_eq!(service.client_id.as_deref().map(String::as_str), Some("id.access"));
        let half = access_from(&env(&[(CLIENT_ID_ENV, "id.access")])).unwrap_err();
        assert!(half.contains(CLIENT_ID_ENV) && half.contains(CLIENT_SECRET_ENV), "{half}");
        let spaced = access_from(&env(&[(TOKEN_ENV, "a token with spaces")])).unwrap_err();
        assert!(spaced.contains(TOKEN_ENV) && !spaced.contains("with spaces"), "{spaced}");
        let missing = access_from(&env(&[(TOKEN_FILE_ENV, "no-such-file-of-this-test")])).unwrap_err();
        assert!(missing.contains(TOKEN_FILE_ENV), "{missing}");
    }

    #[test]
    fn cloudflare_token_comes_from_its_file_and_the_variable_wins() {
        let file = std::env::temp_dir().join(format!("podssh-cf-token-{}", std::process::id()));
        std::fs::write(&file, "token.from.the-file\n").unwrap();
        let path = file.to_string_lossy().into_owned();
        let read = |var: Option<&'static str>| {
            let path = path.clone();
            move |name: &str| match name {
                TOKEN_FILE_ENV => Some(path.clone()),
                TOKEN_ENV => var.map(str::to_string),
                _ => None,
            }
        };
        let from_file = access_from(&read(None)).unwrap();
        assert_eq!(from_file.token.as_deref().map(String::as_str), Some("token.from.the-file"));
        let from_var = access_from(&read(Some("token.of-the.variable"))).unwrap();
        assert_eq!(from_var.token.as_deref().map(String::as_str), Some("token.of-the.variable"));
        let _ = std::fs::remove_file(&file);
    }
}
