//! The request for a quick tunnel (T-300): `POST
//! https://api.trycloudflare.com/tunnel` with an empty body, as cloudflared
//! 2026.10.6 sends it (`cmd/cloudflared/tunnel/quick_tunnel.go`), but
//! through `HTTPS_PROXY` when it is set, with podssh's TLS (measured, T-299:
//! the API took the request through a CONNECT proxy, with a User-Agent that
//! was not cloudflared's). The reply names the tunnel and gives its
//! credentials; the secret stays in memory that is wiped, and is never
//! shown, as a token is not.

use std::borrow::Cow;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use zeroize::Zeroizing;

pub const HOST: &str = "api.trycloudflare.com";
pub const PATH: &str = "/tunnel";
/// cloudflared waits 15 s for the reply.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// A quick tunnel: its name and its credentials.
pub struct Tunnel {
    pub id: [u8; 16],
    /// `NAME.trycloudflare.com`.
    pub hostname: String,
    pub account_tag: String,
    pub secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel").field("hostname", &self.hostname).field("secret", &"(not shown)").finish()
    }
}

/// Why no tunnel came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The API answered with this status, and this text.
    Status { status: u16, detail: String },
    /// The API named its errors.
    Errors(String),
    /// The reply did not read as a tunnel.
    Malformed(&'static str),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Status { status, detail } => write!(f, "{HOST} answered {status}{detail}"),
            Refused::Errors(errors) => write!(f, "{HOST} made no tunnel: {errors}"),
            Refused::Malformed(why) => write!(f, "{HOST} gave a reply that is not a tunnel: {why}"),
        }
    }
}

#[derive(Deserialize)]
struct Reply<'a> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    #[serde(borrow)]
    result: Option<Created<'a>>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Created<'a> {
    #[serde(borrow)]
    id: Cow<'a, str>,
    #[serde(borrow)]
    hostname: Cow<'a, str>,
    #[serde(borrow)]
    account_tag: Cow<'a, str>,
    #[serde(borrow)]
    secret: Cow<'a, str>,
}

/// The tunnel in the reply of `status` with `body`. The body of a reply
/// that succeeded is never quoted: it holds the secret.
pub fn read_reply(status: u16, body: &[u8]) -> Result<Tunnel, Refused> {
    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(body);
        let text: String = text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(200).collect();
        return Err(Refused::Status {
            status,
            detail: if text.is_empty() { String::new() } else { format!(": {text}") },
        });
    }
    let reply: Reply<'_> = serde_json::from_slice(body).map_err(|_| Refused::Malformed("not the expected JSON"))?;
    if !reply.errors.is_empty() {
        let errors: Vec<String> = reply.errors.iter().map(|e| format!("[{}] {}", e.code, e.message)).collect();
        return Err(Refused::Errors(errors.join("; ")));
    }
    let created = match (reply.success, reply.result) {
        (true, Some(created)) => created,
        _ => return Err(Refused::Errors("the reply did not say success".into())),
    };
    let id = uuid_bytes(&created.id).ok_or(Refused::Malformed("an id that is not a UUID"))?;
    let hostname = created.hostname.to_ascii_lowercase();
    let label =
        hostname.strip_suffix(".trycloudflare.com").ok_or(Refused::Malformed("a name not under trycloudflare.com"))?;
    if label.is_empty() || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(Refused::Malformed("a name that is not one label"));
    }
    let secret = Zeroizing::new(
        STANDARD.decode(created.secret.as_bytes()).map_err(|_| Refused::Malformed("a secret that is not base64"))?,
    );
    if secret.is_empty() || created.account_tag.is_empty() {
        return Err(Refused::Malformed("no credentials"));
    }
    Ok(Tunnel { id, hostname, account_tag: created.account_tag.into_owned(), secret })
}

/// The 16 bytes of a UUID written with its hyphens.
pub fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
    if text.len() != 36 || hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (k, pair) in hex.chunks(2).enumerate() {
        out[k] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Ask for a tunnel, through `proxy` when there is one, with `trust`.
pub async fn request(trust: &podssh_ws::Trust, proxy: &podssh_ws::ProxyChoice) -> Result<Tunnel, String> {
    let response = podssh_ws::client::https_post_json(HOST, 443, PATH, b"", trust, proxy, TIMEOUT)
        .await
        .map_err(|e| format!("the request for a quick tunnel to {HOST} failed: {e}"))?;
    // The reply holds the secret: its bytes are wiped once read.
    let body = Zeroizing::new(response.body);
    read_reply(response.status, &body).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply of the shape that T-299 measured: 36 characters of id, 32 of
    /// account tag, and the base64 of 32 bytes of secret (made up here).
    fn reply(hostname: &str) -> String {
        let secret = STANDARD.encode([7u8; 32]);
        format!(
            r#"{{"success":true,"errors":[],"result":{{"id":"8e9d2f0c-4b1a-4f6e-9c3d-5a7b2e1f0d4c","name":"qt-x","hostname":"{hostname}","account_tag":"0123456789abcdef0123456789abcdef","secret":"{secret}"}}}}"#
        )
    }

    #[test]
    fn a_reply_gives_the_tunnel_s_name_and_credentials() {
        let tunnel = read_reply(200, reply("four-words-in-a.trycloudflare.com").as_bytes()).unwrap();
        assert_eq!(tunnel.hostname, "four-words-in-a.trycloudflare.com");
        assert_eq!(
            tunnel.id,
            [0x8e, 0x9d, 0x2f, 0x0c, 0x4b, 0x1a, 0x4f, 0x6e, 0x9c, 0x3d, 0x5a, 0x7b, 0x2e, 0x1f, 0x0d, 0x4c]
        );
        assert_eq!(tunnel.secret.as_slice(), [7u8; 32]);
        assert!(!format!("{tunnel:?}").contains("BwcH"), "the secret is never shown");
    }

    #[test]
    fn a_refusal_names_its_errors_and_never_quotes_a_reply_that_succeeded() {
        let errors = r#"{"success":false,"errors":[{"code":1003,"message":"too many tunnels"}],"result":null}"#;
        assert_eq!(read_reply(200, errors.as_bytes()).unwrap_err(), Refused::Errors("[1003] too many tunnels".into()));
        let status = read_reply(429, b"Too Many Requests\n").unwrap_err();
        assert_eq!(status.to_string(), "api.trycloudflare.com answered 429: Too Many Requests");
        let bad = read_reply(200, b"{\"success\":true,\"result\":{\"secret\":\"s3cr3t\"}}").unwrap_err();
        assert!(!bad.to_string().contains("s3cr3t"), "{bad}");
        assert_eq!(
            read_reply(200, reply("x.example.com").as_bytes()).unwrap_err(),
            Refused::Malformed("a name not under trycloudflare.com")
        );
        assert_eq!(
            read_reply(200, reply("a.b.trycloudflare.com").as_bytes()).unwrap_err(),
            Refused::Malformed("a name that is not one label")
        );
    }

    #[test]
    fn a_uuid_reads_as_its_16_bytes() {
        assert_eq!(uuid_bytes("00000000-0000-0000-0000-0000000000ff").unwrap()[15], 0xff);
        assert_eq!(uuid_bytes("00000000000000000000000000000000"), None, "no hyphens");
        assert_eq!(uuid_bytes("zz000000-0000-0000-0000-000000000000"), None);
    }
}
