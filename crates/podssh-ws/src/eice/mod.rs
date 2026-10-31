//! The road of AWS's EC2 Instance Connect Endpoint (T-351): a WebSocket to
//! `wss://DNS/openTunnel`, DNS the endpoint's own name, through
//! `HTTPS_PROXY` when one is set. Its URL is presigned with SigV4
//! ([`sigv4`]) for 60 s, as aws-cli presigns it, and so carries the
//! credential: the one exception to "credentials never in URLs", by the
//! operator's ruling Q51. podssh makes a new URL for each connection, just
//! before its upgrade, keeps it in memory that is wiped, and never shows
//! it. Then the stream goes in binary messages as they are.
//!
//! Read in aws/aws-cli at v2 (`awscli/customizations/ec2instanceconnect/`:
//! `eicesigner.py`, `websocket.py`, `opentunnel.py`) and in AWS's documents,
//! on 2026-10-31: the upgrade is awscrt's (`Host`, `Upgrade`, `Connection`,
//! the key, the version) with aws-cli's `User-Agent` and no subprotocol; a
//! tunnel lasts an hour at most, `maxTunnelDuration` shortens it, an
//! endpoint takes 20 tunnels at once, and a high volume is throttled.

pub mod sigv4;

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::client::{self, ConnectError, WRITE_TIMEOUT};
use crate::dial::ProxyChoice;
use crate::handshake;
use crate::session::RelaySession;
use crate::tls::Trust;

pub const PORT: u16 = 443;
pub const PATH: &str = "/openTunnel";
/// The name of the service in the signature.
pub const SERVICE: &str = "ec2-instance-connect";
/// How long a presigned URL is good for, as aws-cli signs it.
pub const EXPIRES: u32 = 60;
/// The longest tunnel, and the default of `maxTunnelDuration`.
pub const MAX_DURATION: u32 = 3600;
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));
/// The largest frame taken from the endpoint, which documents none; aws-cli
/// sends frames of 65000 bytes.
pub const MAX_FRAME: usize = 1024 * 1024;
/// The longest value of a credential: a session token is about 1 KiB.
const MAX_VALUE: usize = 4096;

/// An endpoint, by its DNS name as `aws ec2
/// describe-instance-connect-endpoints` gives it: its id is the first
/// label, and its region the label after `ec2-instance-connect-endpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub dns: String,
    pub id: String,
    pub region: String,
}

impl Endpoint {
    /// `eice-ID.HASH.[fips.]ec2-instance-connect-endpoint.REGION.amazonaws.com`.
    pub fn parse(dns: &str) -> Result<Endpoint, String> {
        let dns = dns.trim_end_matches('.').to_ascii_lowercase();
        let label = |l: &str| {
            let named = l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && named
        };
        if dns.len() > 253 || !dns.split('.').all(label) {
            return Err(format!("{dns:?} is not a DNS name"));
        }
        let labels: Vec<&str> = dns.split('.').collect();
        let not_one = || {
            format!(
                "{dns:?} is not the DNS name of an EC2 Instance Connect Endpoint, as \
                 eice-ID.HASH.ec2-instance-connect-endpoint.REGION.amazonaws.com is one"
            )
        };
        let id = labels[0];
        if !id.starts_with("eice-") || id.len() < 6 {
            return Err(not_one());
        }
        let at = labels.iter().position(|l| *l == "ec2-instance-connect-endpoint").ok_or_else(not_one)?;
        let region = labels.get(at + 1).filter(|r| r.contains('-') && at + 2 < labels.len()).ok_or_else(not_one)?;
        Ok(Endpoint { id: id.to_string(), region: region.to_string(), dns: dns.clone() })
    }
}

/// What a tunnel reaches: the instance's private address and port, and the
/// tunnel's longest life when one is asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub address: IpAddr,
    pub port: u16,
    pub max_duration: Option<u32>,
}

/// A credential of AWS that signs the URL: an access key, and the token of
/// a temporary one. Kept in memory that is wiped; never shown.
#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: Zeroizing<String>,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials").field("temporary", &self.session_token.is_some()).finish_non_exhaustive()
    }
}

impl Credentials {
    /// Whether each value can go in a URL: 1 to 4096 printable characters.
    /// A refusal names the part, never its value.
    pub fn check(&self) -> Result<(), String> {
        let parts = [
            ("access key id", Some(&self.access_key_id)),
            ("secret access key", Some(&self.secret_access_key)),
            ("session token", self.session_token.as_ref()),
        ];
        for (name, value) in parts {
            let Some(value) = value else { continue };
            if value.is_empty() || value.len() > MAX_VALUE || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                return Err(format!(
                    "the {name} is not one of AWS's: 1 to {MAX_VALUE} printable characters, with no space"
                ));
            }
        }
        Ok(())
    }

    /// `text` with no part of the credential and no part of the presigned
    /// URL, which an answer may quote, whole or cut short: from its query,
    /// or from each of its `X-Amz-` parameters, to the next space.
    fn hide(&self, text: &str) -> String {
        let mut out = text.to_string();
        for marker in ["openTunnel?", "X-Amz-"] {
            let mut from = 0;
            while let Some(at) = out[from..].find(marker).map(|at| from + at + marker.len()) {
                let end = out[at..].find(char::is_whitespace).map_or(out.len(), |e| at + e);
                out.replace_range(at..end, "<not shown>");
                from = at + "<not shown>".len();
            }
        }
        let token = self.session_token.as_deref().map(String::as_str);
        let escaped = token.map(sigv4::escape);
        let parts = [Some(&**self.access_key_id), Some(&**self.secret_access_key), token, escaped.as_deref()];
        for secret in parts.into_iter().flatten().filter(|s| s.len() >= 4) {
            out = out.replace(secret, "<not shown>");
        }
        out
    }
}

/// The path and query of an openTunnel to `target` through `endpoint`,
/// presigned at `now`, seconds since the Unix epoch, for [`EXPIRES`]: the
/// parameters of aws-cli's URL, in its order.
pub fn presigned_path(endpoint: &Endpoint, target: &Target, credentials: &Credentials, now: i64) -> Zeroizing<String> {
    let mut params = vec![
        ("instanceConnectEndpointId", endpoint.id.clone()),
        ("remotePort", target.port.to_string()),
        ("privateIpAddress", target.address.to_string()),
    ];
    if let Some(duration) = target.max_duration {
        params.push(("maxTunnelDuration", duration.to_string()));
    }
    let amz_date = sigv4::amz_date(now);
    let presign = sigv4::Presign {
        access_key_id: &credentials.access_key_id,
        secret_access_key: &credentials.secret_access_key,
        session_token: credentials.session_token.as_deref().map(String::as_str),
        region: &endpoint.region,
        service: SERVICE,
        host: &endpoint.dns,
        path: PATH,
        params: &params,
        amz_date: &amz_date,
        expires: EXPIRES,
    };
    let query = presign.query();
    let mut path = Zeroizing::new(String::with_capacity(PATH.len() + 1 + query.len()));
    path.push_str(PATH);
    path.push('?');
    path.push_str(&query);
    path
}

/// The upgrade to `path` at `host`, with `key`, as awscrt writes it, with
/// `user_agent` as aws-cli adds one. Sized once, so that no copy of the
/// presigned URL is left in a freed buffer.
pub fn request(host: &str, path: &str, key: &str, user_agent: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if host.is_empty() || host.contains(|c: char| c.is_control() || c.is_whitespace() || "/?#@".contains(c)) {
        return Err(format!("{host:?} is not a host name"));
    }
    if !path.starts_with('/') || path.contains(|c: char| c.is_control() || c.is_whitespace()) {
        return Err("the path of the upgrade holds a space or a control character".into());
    }
    let lines = [
        ("Host", host),
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Key", key),
        ("Sec-WebSocket-Version", "13"),
        ("User-Agent", user_agent),
    ];
    if let Some((name, _)) = lines.iter().find(|(_, value)| value.contains(|c: char| c.is_control())) {
        return Err(format!("the value of {name} holds a control character"));
    }
    let size = 32 + path.len() + lines.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>();
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(b"GET ");
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in lines {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// The seconds since the Unix epoch, for a signature.
fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// A tunnel to `target` through `endpoint`, through `proxy`, its URL signed
/// with `credentials` once TLS is up, as late as can be. Each step is
/// bounded by `timeout`.
pub async fn connect(
    endpoint: &Endpoint,
    target: &Target,
    credentials: &Credentials,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<RelaySession, ConnectError> {
    credentials.check().map_err(ConnectError::Config)?;
    let tls = client::open_tls(&endpoint.dns, PORT, &endpoint.dns, trust, proxy, timeout).await?;
    let path = presigned_path(endpoint, target, credentials, now());
    let (tls, pending) = upgrade(tls, &endpoint.dns, &path, credentials, timeout).await?;
    Ok(session(tls, pending))
}

/// The upgrade over `stream`; a refusal's body shows no credential and no
/// part of the URL.
async fn upgrade<S>(
    stream: S,
    host: &str,
    path: &str,
    credentials: &Credentials,
    timeout: Duration,
) -> Result<(S, Vec<u8>), ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = handshake::generate_key().map_err(|e| ConnectError::Upgrade(e.to_string()))?;
    let request = request(host, path, &key, USER_AGENT).map_err(ConnectError::Config)?;
    match tokio::time::timeout(timeout, client::upgrade_with(stream, &request, &key)).await {
        Err(_) => Err(ConnectError::Timeout { step: "the WebSocket upgrade", after: timeout }),
        Ok(Err(ConnectError::Refused { status, body })) => {
            Err(ConnectError::Refused { status, body: credentials.hide(&body) })
        }
        Ok(answer) => answer,
    }
}

/// A tunnel: no bound on a read, as SSH's keepalives find a dead link; the
/// relay stream's Pings find one sooner where the endpoint answers them.
fn session<S>(stream: S, pending: Vec<u8>) -> RelaySession<S>
where
    S: AsyncRead + AsyncWrite,
{
    let session = RelaySession::new(stream, pending, None, WRITE_TIMEOUT);
    session.set_receive_cap(MAX_FRAME);
    session
}

#[cfg(test)]
mod tests;
