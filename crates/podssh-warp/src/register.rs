//! The registration of a device, with the API that Cloudflare's app uses
//! (read in usque's `api/cloudflare.go`, `internal/consts.go` and
//! `models/`, 2026-10-31): `POST /VERSION/reg` with a random key of
//! WireGuard's form and a random serial, as the Android app registers, then
//! `PATCH /VERSION/reg/ID` with the device's P-256 key and the tunnel type
//! `masque`, whose answer gives the endpoint's key and the device's
//! addresses. Each request is one HTTPS connection of podssh-ws, through the
//! proxy, with the headers of "WARP for Android", which the API takes and
//! the open clients send (the operator's ruling Q52 allowed the road with
//! them; T-352's Decision). A team's token (a Cloudflare One organization)
//! goes in `CF-Access-Jwt-Assertion`, as usque sends it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use podssh_ws::{ProxyChoice, Trust};
use rustls::crypto::SecureRandom as _;
use serde::Serialize;
use tokio::io::AsyncWriteExt as _;

use crate::device::Device;
use crate::key::DeviceKey;

/// The API (usque's `ApiUrl`, `ApiVersion`).
pub const API_HOST: &str = "api.cloudflareclient.com";
pub const API_VERSION: &str = "v0a4471";
/// The headers of the app (usque's `Headers`), but `Connection`: each
/// request here has its own connection.
pub const USER_AGENT: &str = "WARP for Android";
pub const CLIENT_VERSION: &str = "a-6.35-4471";
pub const CONTENT_TYPE: &str = "application/json; charset=UTF-8";
/// The device's model and locale (usque's defaults), and the key's types.
pub const MODEL: &str = "PC";
pub const LOCALE: &str = "en_US";
pub const KEY_TYPE: &str = "secp256r1";
pub const TUNNEL_TYPE: &str = "masque";
/// The longest answer read: a device's record is a few KiB.
const MAX_ANSWER: usize = 64 * 1024;

/// Where the API is, and how it is reached.
#[derive(Debug, Clone)]
pub struct Api {
    pub host: String,
    pub port: u16,
    pub trust: Trust,
    pub proxy: ProxyChoice,
    pub limit: Duration,
}

impl Api {
    /// Cloudflare's, on port 443.
    pub fn cloudflare(trust: Trust, proxy: ProxyChoice, limit: Duration) -> Api {
        Api { host: API_HOST.to_string(), port: 443, trust, proxy, limit }
    }
}

/// Why a registration did not end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// The API was not reached: the proxy, DNS, TLS.
    Unreachable(String),
    /// It answered with this status, and these words of its body.
    Refused { status: u16, said: String },
    /// It answered with something that podssh does not read.
    Answer(String),
    /// This host cannot make a key.
    Local(String),
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::Unreachable(why) => write!(f, "WARP's API ({API_HOST}) was not reached: {why}"),
            Fault::Refused { status, said } => write!(f, "WARP's API refused the device (HTTP {status}): {said}"),
            Fault::Answer(why) => write!(f, "WARP's API answered with no device that podssh reads: {why}"),
            Fault::Local(why) => write!(f, "the device's key: {why}"),
        }
    }
}

/// The body of `POST /reg`, its fields in usque's order.
#[derive(Serialize)]
struct Registration<'a> {
    key: String,
    install_id: &'a str,
    fcm_token: &'a str,
    tos: &'a str,
    model: &'a str,
    serial_number: String,
    os_version: &'a str,
    key_type: &'a str,
    tunnel_type: &'a str,
    locale: &'a str,
}

/// The body of `POST /reg`: a key of WireGuard's form that is never used,
/// as usque sends one, a serial of 8 random bytes in hex, and the time at
/// which the Terms were accepted.
pub fn registration_body(wg_key: &[u8; 32], serial: &[u8; 8], tos: &str) -> String {
    let body = Registration {
        key: base64::engine::general_purpose::STANDARD.encode(wg_key),
        install_id: "",
        fcm_token: "",
        tos,
        model: MODEL,
        serial_number: serial.iter().map(|b| format!("{b:02x}")).collect(),
        os_version: "",
        key_type: "curve25519",
        tunnel_type: "wireguard",
        locale: LOCALE,
    };
    serde_json::to_string(&body).unwrap_or_default()
}

/// The body of `PATCH /reg/ID`: the device's key, base64 of its
/// SubjectPublicKeyInfo, and the tunnel type of MASQUE.
pub fn enrolment_body(spki: &[u8]) -> String {
    serde_json::json!({
        "key": base64::engine::general_purpose::STANDARD.encode(spki),
        "key_type": KEY_TYPE,
        "tunnel_type": TUNNEL_TYPE,
    })
    .to_string()
}

/// A time as usque writes the time of the Terms (Go's
/// `2006-01-02T15:04:05.000-07:00`), in UTC.
pub fn terms_time(now: SystemTime) -> String {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() as i64;
    let (y, m, d) = podssh_ws::clock::civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    let millis = since.subsec_millis();
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}+00:00", rest / 3600, rest % 3600 / 60, rest % 60)
}

/// One request of HTTP/1.1 to the API. A value with a line break is
/// refused, so that no header can be added through one.
pub fn request(
    method: &str,
    host: &str,
    path: &str,
    bearer: Option<&str>,
    team: Option<&str>,
    body: &str,
) -> Result<Vec<u8>, String> {
    let parts = [Some(method), Some(host), Some(path), bearer, team];
    if parts.iter().flatten().any(|p| p.contains(['\r', '\n'])) {
        return Err("a request line or a header holds a line break".into());
    }
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n\
         CF-Client-Version: {CLIENT_VERSION}\r\nContent-Type: {CONTENT_TYPE}\r\nAccept: application/json\r\n\
         Connection: close\r\n"
    );
    if let Some(token) = bearer {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(team) = team {
        head.push_str(&format!("CF-Access-Jwt-Assertion: {team}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    Ok([head.as_bytes(), body.as_bytes()].concat())
}

/// What a device's answer holds, of what podssh keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub id: String,
    /// Only the answer of `POST /reg` holds it.
    pub token: Option<String>,
    /// The endpoint's key, PEM, once the device has a key of MASQUE.
    pub endpoint_key: Option<String>,
    pub address_v4: Option<String>,
    pub address_v6: Option<String>,
}

/// The parts of a device's answer (usque's `models.AccountData`).
pub fn read_answer(body: &[u8]) -> Result<Answer, String> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| "its answer is not JSON".to_string())?;
    let text = |v: &serde_json::Value| v.as_str().filter(|s| !s.is_empty()).map(str::to_string);
    let id = text(&value["id"]).ok_or("its answer has no device id")?;
    // The id goes into a path: a UUID's characters only.
    if !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("its device id is not one that a path can hold".into());
    }
    let peer = &value["config"]["peers"][0];
    let addresses = &value["config"]["interface"]["addresses"];
    Ok(Answer {
        id,
        token: text(&value["token"]),
        endpoint_key: text(&peer["public_key"]),
        address_v4: text(&addresses["v4"]),
        address_v6: text(&addresses["v6"]),
    })
}

/// One request and its answer, on a connection of its own.
async fn exchange(
    api: &Api,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    team: Option<&str>,
    body: &str,
) -> Result<Answer, Fault> {
    let host = if api.port == 443 { api.host.clone() } else { podssh_ws::dial::authority(&api.host, api.port) };
    let request = request(method, &host, path, bearer, team, body).map_err(Fault::Local)?;
    let mut tls = podssh_ws::client::open_tls(&api.host, api.port, &api.host, &api.trust, &api.proxy, api.limit)
        .await
        .map_err(|e| Fault::Unreachable(e.to_string()))?;
    let asked = async {
        tls.write_all(&request).await?;
        tls.flush().await?;
        podssh_ws::http::read_response(&mut tls, Vec::new(), MAX_ANSWER).await
    };
    let response = tokio::time::timeout(api.limit, asked)
        .await
        .map_err(|_| Fault::Unreachable(format!("no answer within {} s", api.limit.as_secs())))?
        .map_err(|e| Fault::Unreachable(e.to_string()))?;
    if !(200..300).contains(&response.status) {
        return Err(Fault::Refused { status: response.status, said: response.body_text(200) });
    }
    read_answer(&response.body).map_err(Fault::Answer)
}

/// Register a new device with `api`, and give it a key of MASQUE; `team` is
/// the token of a Cloudflare One organization, when the user gives one. The
/// caller has the user's acceptance of the Terms ([`crate::TERMS_URL`]).
pub async fn register(api: &Api, team: Option<&str>, now: SystemTime) -> Result<Device, Fault> {
    let random = podssh_ws::crypto::random::OsRandom;
    let (mut wg_key, mut serial) = ([0u8; 32], [0u8; 8]);
    let drawn = random.fill(&mut wg_key).and_then(|()| random.fill(&mut serial));
    drawn.map_err(|_| Fault::Local("this host's random source gave no bytes".into()))?;
    let tos = terms_time(now);
    let body = registration_body(&wg_key, &serial, &tos);
    let mut made = exchange(api, "POST", &format!("/{API_VERSION}/reg"), None, team, &body).await?;
    let token = made.token.take().ok_or_else(|| Fault::Answer("its answer has no token".into()))?;
    let token = zeroize::Zeroizing::new(token);
    let key = DeviceKey::generate().map_err(Fault::Local)?;
    let path = format!("/{API_VERSION}/reg/{}", made.id);
    let enrolled = exchange(api, "PATCH", &path, Some(token.as_str()), None, &enrolment_body(&key.spki())).await?;
    let pem = enrolled.endpoint_key.ok_or_else(|| Fault::Answer("its answer has no endpoint key".into()))?;
    let endpoint = crate::ENDPOINT_H2.parse().map_err(|_| Fault::Local("the endpoint of HTTP/2".into()))?;
    let v4 = enrolled.address_v4.and_then(|t| t.parse::<std::net::Ipv4Addr>().ok());
    let v6 = enrolled.address_v6.and_then(|t| t.parse::<std::net::Ipv6Addr>().ok());
    Device::new(made.id, token.to_string(), key, &pem, endpoint, v4, v6, tos, team.is_some()).map_err(Fault::Answer)
}

/// The device's record as WARP's API holds it now: `GET /reg/ID` with the
/// device's token, as cfrs reads a device again (T-399). The answer must be
/// of the same device.
pub async fn read_record(api: &Api, device: &Device) -> Result<Answer, Fault> {
    // The id goes into a path: a UUID's characters only, as a registration
    // takes it.
    if device.id.is_empty() || !device.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(Fault::Answer("the device's id in its record is not one that a path can hold".into()));
    }
    let path = format!("/{API_VERSION}/reg/{}", device.id);
    let answer = exchange(api, "GET", &path, Some(device.token()), None, "").await?;
    if answer.id != device.id {
        return Err(Fault::Answer("its answer is of another device".into()));
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body of `POST /reg` as usque's `models.Registration` writes it,
    /// in the order of its fields.
    #[test]
    fn the_registration_is_usque_s() {
        let serial = [0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3];
        let body = registration_body(&[0u8; 32], &serial, "2026-10-31T12:00:00.000+00:00");
        assert_eq!(
            body,
            "{\"key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"install_id\":\"\",\"fcm_token\":\"\",\
             \"tos\":\"2026-10-31T12:00:00.000+00:00\",\"model\":\"PC\",\"serial_number\":\"deadbeef00010203\",\
             \"os_version\":\"\",\"key_type\":\"curve25519\",\"tunnel_type\":\"wireguard\",\"locale\":\"en_US\"}"
        );
    }

    /// The enrolment's key is base64 of the SPKI, with the key type and the
    /// tunnel type of MASQUE.
    #[test]
    fn the_enrolment_names_masque() {
        let body: serde_json::Value = serde_json::from_str(&enrolment_body(&[1, 2, 3])).unwrap();
        assert_eq!(body["key"], "AQID");
        assert_eq!(body["key_type"], "secp256r1");
        assert_eq!(body["tunnel_type"], "masque");
    }

    /// The time of the Terms in Go's form, as usque writes it.
    #[test]
    fn the_time_of_the_terms_is_go_s_form() {
        let now = UNIX_EPOCH + Duration::from_millis(1_791_440_989_042);
        assert_eq!(terms_time(now), "2026-10-08T06:29:49.042+00:00");
    }

    /// The headers of the app, the token in its header alone, and no header
    /// added through a line break.
    #[test]
    fn a_request_has_the_app_s_headers() {
        let bytes = request("PATCH", API_HOST, "/v0a4471/reg/abc", Some("tok"), None, "{}").unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("PATCH /v0a4471/reg/abc HTTP/1.1\r\nHost: api.cloudflareclient.com\r\n"), "{text}");
        for line in [
            "User-Agent: WARP for Android",
            "CF-Client-Version: a-6.35-4471",
            "Authorization: Bearer tok",
            "Content-Length: 2",
        ] {
            assert!(text.contains(&format!("{line}\r\n")), "{line}: {text}");
        }
        assert!(text.ends_with("\r\n\r\n{}"));
        assert!(!text.contains("CF-Access-Jwt-Assertion"));
        assert!(request("POST", API_HOST, "/", None, Some("a\r\nX: y"), "").is_err());
    }

    /// The parts of an answer of usque's form; an id that a path cannot hold
    /// is refused.
    #[test]
    fn an_answer_gives_its_device() {
        let body = br#"{"id":"0d2a-11","token":"t","config":{"peers":[{"public_key":"PEM","endpoint":
            {"v4":"162.159.198.1:0"}}],"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700::1"}}}}"#;
        let answer = read_answer(body).unwrap();
        assert_eq!(answer.id, "0d2a-11");
        assert_eq!(answer.token.as_deref(), Some("t"));
        assert_eq!(answer.endpoint_key.as_deref(), Some("PEM"));
        assert_eq!(answer.address_v4.as_deref(), Some("172.16.0.2"));
        assert_eq!(answer.address_v6.as_deref(), Some("2606:4700::1"));
        assert!(read_answer(br#"{"id":"../x"}"#).is_err());
        assert!(read_answer(b"not json").is_err());
    }
}
