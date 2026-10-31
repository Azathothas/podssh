//! `eice://[user@]ENDPOINT/ADDRESS[:PORT]` (T-351): a port of an EC2
//! instance by its private address, through an EC2 Instance Connect
//! Endpoint by its DNS name (`podssh_ws::eice`), as `aws ec2-instance-connect
//! open-tunnel --instance-connect-endpoint-dns-name` reaches it; no call to
//! EC2's API. Each connection signs a new URL with the credential of
//! [`super::aws`]; the endpoint ends a tunnel at its duration, an hour at
//! most, and `podssh cp` goes on in a new one before it.

use std::net::IpAddr;
use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ssh::RelayEnd;
use podssh_ws::client::ConnectError;
use podssh_ws::eice::{self, Credentials, Endpoint, Target};
use podssh_ws::{ProxyChoice, Trust};

use super::told::Told;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::ssh::transport::{NotReached, Reached};

/// The form of a destination on this road.
pub const SCHEME: &str = "eice://";

/// `eice://[user@]ENDPOINT/ADDRESS[:PORT]`, an IPv6 address in brackets.
pub fn destination(text: &str) -> Result<Option<(Option<String>, Endpoint, Target)>, String> {
    let Some(rest) = text.strip_prefix(SCHEME) else { return Ok(None) };
    let (user, rest) = super::user_of(text, rest.trim_end_matches('/'))?;
    let usage = || {
        format!(
            "{text:?}: give it as {SCHEME}ENDPOINT/ADDRESS[:PORT], the endpoint's DNS name and the instance's \
             private address"
        )
    };
    let (dns, address) = rest.split_once('/').ok_or_else(usage)?;
    let (address, port) = match address.strip_prefix('[') {
        Some(inside) => {
            let (v6, after) = inside.split_once(']').ok_or_else(usage)?;
            let port = match after.strip_prefix(':') {
                Some(port) => super::port_of(text, &format!("x:{port}"))?.1,
                None if after.is_empty() => 22,
                None => return Err(usage()),
            };
            (v6.to_string(), port)
        }
        None => {
            let (address, port) = super::port_of(text, address)?;
            (address.to_string(), port)
        }
    };
    let address: IpAddr = address.parse().map_err(|_| format!("{text:?}: {address:?} is not an IP address"))?;
    let endpoint = Endpoint::parse(dns).map_err(|why| format!("{text:?}: {why}"))?;
    Ok(Some((user, endpoint, Target { address, port, max_duration: None })))
}

/// The tunnel's longest life, of `PODSSH_EICE_MAX_TUNNEL_DURATION`: whole
/// seconds from 1 to 3600, or none, which leaves the endpoint's own.
pub fn max_duration(value: Option<&str>) -> Result<Option<u32>, String> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else { return Ok(None) };
    match value.parse::<u32>() {
        Ok(secs) if (1..=eice::MAX_DURATION).contains(&secs) => Ok(Some(secs)),
        _ => Err(format!("{value:?}: whole seconds from 1 to {}", eice::MAX_DURATION)),
    }
}

/// The stream to `target` through `endpoint`.
pub(super) async fn reach(
    endpoint: &Endpoint,
    target: &Target,
    trust: &Trust,
    log: &Arc<Log>,
) -> Result<Reached, NotReached> {
    let shown = super::Road::Eice { endpoint: endpoint.clone(), target: target.clone() }.shown();
    let credentials = super::aws::credentials()
        .map_err(|why| NotReached { lines: vec![format!("{shown}: the credential: {why}")], code: EX_CONFIG })?;
    let life = target.max_duration.unwrap_or(eice::MAX_DURATION);
    let (port, dns) = (target.port, &endpoint.dns);
    log.verbose(&format!("connecting to {shown}, port {port}, through {dns}: its tunnel lasts {life} s at most"));
    let (line, code) = match open(endpoint, target, &credentials, trust).await {
        Ok(session) => {
            let (stream, status) = podssh_ssh::relay_stream::spawn(session);
            let said = shown.clone();
            let why = move || status.get().and_then(|end| ended(&said, &end));
            let stream = Box::new(Told::new(stream, why, log.clone()));
            return Ok(Reached { stream, relay: None, direct_proxy: None, layer: None });
        }
        Err(e) => refusal(&shown, endpoint, &e),
    };
    Err(NotReached { lines: vec![line], code })
}

/// A new tunnel, its URL signed for it alone.
pub async fn open(
    endpoint: &Endpoint,
    target: &Target,
    credentials: &Credentials,
    trust: &Trust,
) -> Result<podssh_ws::RelaySession, ConnectError> {
    let timeout = podssh_relay::open::CONNECT_TIMEOUT;
    eice::connect(endpoint, target, credentials, trust, &ProxyChoice::FromEnvironment, timeout).await
}

/// Why the endpoint took no tunnel, and the code of a command that says
/// so: 77 for a refusal of the credential, 78 for one that cannot be used,
/// 69 else. A presigned URL is checked against AWS's clock, so a refusal
/// gives this host's.
pub fn refusal(shown: &str, endpoint: &Endpoint, e: &ConnectError) -> (String, i32) {
    match e {
        ConnectError::Refused { status: status @ (401 | 403), body } => {
            let said = if body.is_empty() { String::new() } else { format!(": {body}") };
            let clock = podssh_ws::clock::http_date(now());
            let line = format!(
                "{shown}: the endpoint {} refused the tunnel (HTTP {status}{said}): the credential needs \
                 ec2-instance-connect:OpenTunnel on it, for this address and port; a URL is signed for 60 s, \
                 and this host's clock reads {clock}",
                endpoint.id
            );
            (line, EX_NOPERM)
        }
        ConnectError::Refused { status, body } => {
            let said = if body.is_empty() { String::new() } else { format!(": {body}") };
            (format!("{shown}: the endpoint refused the tunnel: HTTP {status}{said}"), EX_UNAVAILABLE)
        }
        ConnectError::Config(why) => (format!("{shown}: {why}"), EX_CONFIG),
        other => (format!("{shown}: {other}"), EX_UNAVAILABLE),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// The line of a tunnel that the endpoint ended, said once before SSH sees
/// the end of its stream; `None` for an ordinary end.
pub fn ended(shown: &str, end: &RelayEnd) -> Option<String> {
    match end {
        RelayEnd::Closed { code: None | Some(1000), .. } => None,
        RelayEnd::Closed { code: Some(code), reason } if reason.is_empty() => {
            Some(format!("{shown}: the endpoint ended the tunnel (close {code})"))
        }
        RelayEnd::Closed { code: Some(code), reason } => {
            Some(format!("{shown}: the endpoint ended the tunnel (close {code}): {reason}"))
        }
        RelayEnd::Failed(why) => Some(format!("{shown}: the tunnel failed: {why}")),
    }
}
