//! The token of a tunnel (T-441): a JWT whose claims name the tunnel's id,
//! its protocol, its host and its port, as wstunnel's client writes them
//! (`erebe/wstunnel:wstunnel/src/tunnel/transport/jwt.rs`, its
//! `JwtTunnelConfig`, read at v11.1.0): serde's form of that struct, its
//! fields in their order, `{"id":ID,"p":{"Tcp":{"proxy_protocol":false}},
//! "r":HOST,"rp":PORT}`. The protocol `Tcp` took its field in 9.1, so a
//! server of 9.0 or before cannot read it.
//!
//! The signature is HS256 with [`KEY`]: wstunnel 9.1 to 10.0 sign and check
//! with it, and 10.1 and later sign with a key of each process and check no
//! signature (its commit 1522882, "Randomize jwt secret signature",
//! 2024-08-26), so this one token serves each version from 9.1.

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// The key of wstunnel 9.1 to 10.0 (`JWT_SECRET` of
/// `erebe/wstunnel:src/tunnel/transport/jwt.rs` at v10.0.1): a constant of
/// its public source, which each of their clients sends. It guards nothing,
/// and is no credential.
pub const KEY: &[u8] = b"champignonfrais";

/// The token's place in `Sec-WebSocket-Protocol`, after the subprotocol
/// `v1` (`JWT_HEADER_PREFIX`).
pub const PREFIX: &str = "authorization.bearer.";

/// The header of each token, as jsonwebtoken writes `Header::new(HS256)`:
/// `typ`, then `alg`.
const HEADER: &str = r#"{"typ":"JWT","alg":"HS256"}"#;

/// The claim `r` of `host`: a name or an IPv4 address as it is, an IPv6 one
/// in brackets, as the url crate's `Host` writes it and `Host::parse`, which
/// the server calls, reads it.
pub fn host_claim(host: &str) -> String {
    match host.contains(':') && !host.starts_with('[') {
        true => format!("[{host}]"),
        false => host.to_string(),
    }
}

/// The claims of a tunnel to `host:port` with the id `id`; each string is
/// JSON's, escaped as serde_json escapes it.
pub fn claims(id: &str, host: &str, port: u16) -> String {
    let text = |s: &str| serde_json::Value::String(s.to_string()).to_string();
    format!(
        r#"{{"id":{},"p":{{"Tcp":{{"proxy_protocol":false}}}},"r":{},"rp":{port}}}"#,
        text(id),
        text(&host_claim(host))
    )
}

/// The JWT of `claims` (RFC 7519): the header and the claims in base64url
/// with no padding, and HS256 of both with [`KEY`].
pub fn sign(claims: &str) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let input = format!("{}.{}", b64.encode(HEADER), b64.encode(claims));
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).expect("HMAC takes a key of any length");
    mac.update(input.as_bytes());
    format!("{input}.{}", b64.encode(mac.finalize().into_bytes()))
}

/// The id of a tunnel: a UUID of version 4 (RFC 9562), as wstunnel's client
/// makes one, from the system's source; the server only logs it.
pub fn tunnel_id() -> Result<String, String> {
    let mut b = [0u8; 16];
    use rustls::crypto::SecureRandom as _;
    crate::crypto::random::OsRandom.fill(&mut b).map_err(|_| "no bytes from the system's random source".to_string())?;
    Ok(uuid_text(b))
}

/// `b` as a UUID of version 4 and RFC 9562's variant, in its text form.
pub fn uuid_text(mut b: [u8; 16]) -> String {
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// The token of a tunnel to `host:port`, with a fresh id.
pub fn for_target(host: &str, port: u16) -> Result<String, String> {
    Ok(sign(&claims(&tunnel_id()?, host, port)))
}
