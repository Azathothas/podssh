//! The headers between a quick tunnel's connector and the edge, over HTTP/2
//! (T-300), as cloudflared 2026.10.6 writes them (`connection/http2.go`,
//! `connection/header.go`). The kind of each request of the edge is in one
//! header; the origin's answer goes in another, each name and value in
//! base64 with no padding, as `name:value` pairs joined by `;`, so that the
//! rules of HTTP/2 do not apply to headers of HTTP/1; and a third says who
//! answered.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;

/// The header of a request that names its kind, and its values.
pub const UPGRADE: &str = "cf-cloudflared-proxy-connection-upgrade";
pub const CONTROL_STREAM: &str = "control-stream";
pub const WEBSOCKET: &str = "websocket";
pub const CONFIGURATION_UPDATE: &str = "update-configuration";
/// The header that marks a request for raw TCP (WARP's routing).
pub const TCP_SOURCE: &str = "cf-cloudflared-proxy-src";

/// The header of an answer that holds the origin's headers.
pub const RESPONSE_HEADERS: &str = "cf-cloudflared-response-headers";
/// The header of an answer that says who answered, and its two values.
pub const RESPONSE_META: &str = "cf-cloudflared-response-meta";
pub const META_ORIGIN: &str = r#"{"src":"origin"}"#;
pub const META_CONNECTOR: &str = r#"{"src":"cloudflared"}"#;

/// The kind of a request of the edge, read in cloudflared's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The stream of the registration's RPC.
    Control,
    /// A new configuration of a tunnel that is managed remotely.
    Configuration,
    /// A visitor's WebSocket.
    WebSocket,
    /// Raw TCP, from WARP's routing.
    Tcp,
    /// Any other request of a visitor.
    Http,
}

/// The kind of a request whose headers `get` reads, by name in lower case.
pub fn kind<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Kind {
    let upgrade = get(UPGRADE);
    if upgrade == Some(CONFIGURATION_UPDATE) {
        Kind::Configuration
    } else if upgrade == Some(WEBSOCKET) {
        Kind::WebSocket
    } else if get(TCP_SOURCE).is_some_and(|v| !v.is_empty()) {
        Kind::Tcp
    } else if upgrade == Some(CONTROL_STREAM) {
        Kind::Control
    } else {
        Kind::Http
    }
}

/// The value of [`RESPONSE_HEADERS`] for `headers`.
pub fn serialize(headers: &[(&str, &str)]) -> String {
    let pairs: Vec<String> = headers
        .iter()
        .map(|(name, value)| format!("{}:{}", STANDARD_NO_PAD.encode(name), STANDARD_NO_PAD.encode(value)))
        .collect();
    pairs.join(";")
}

/// The headers in a value of [`RESPONSE_HEADERS`]; `None` for a value that
/// does not read, as cloudflared's `DeserializeHeaders` refuses it.
pub fn deserialize(value: &str) -> Option<Vec<(String, String)>> {
    let text = |part: &str| String::from_utf8(STANDARD_NO_PAD.decode(part).ok()?).ok();
    value
        .split(';')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut parts = pair.split(':');
            let (name, value) = (parts.next()?, parts.next()?);
            if parts.next().is_some() {
                return None;
            }
            Some((text(name)?, text(value)?))
        })
        .collect()
}

/// The origin's headers of the answer to a visitor's WebSocket whose key is
/// `key`: those of a 101, which HTTP/2 sends as 200 (cloudflared's
/// `websocket.NewResponseHeader`).
pub fn websocket_answer(key: &str) -> String {
    let accept = podssh_ws::handshake::accept_key(key);
    serialize(&[("Connection", "Upgrade"), ("Sec-Websocket-Accept", &accept), ("Upgrade", "websocket")])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_s_kind_is_read_in_cloudflared_s_order() {
        let headers = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
        };
        assert_eq!(kind(headers(&[(UPGRADE, CONTROL_STREAM)])), Kind::Control);
        assert_eq!(kind(headers(&[(UPGRADE, WEBSOCKET)])), Kind::WebSocket);
        assert_eq!(kind(headers(&[(UPGRADE, CONFIGURATION_UPDATE)])), Kind::Configuration);
        assert_eq!(kind(headers(&[(TCP_SOURCE, "203.0.113.7")])), Kind::Tcp);
        assert_eq!(kind(headers(&[(TCP_SOURCE, ""), (UPGRADE, "something")])), Kind::Http);
        // A raw TCP stream is read before the control stream, as cloudflared does.
        assert_eq!(kind(headers(&[(UPGRADE, CONTROL_STREAM), (TCP_SOURCE, "x")])), Kind::Tcp);
    }

    /// A header of cloudflared's `connection/header_test.go` at 2026.10.6,
    /// whose base64 with no padding is Python's `base64.b64encode` with the
    /// `=` taken off.
    #[test]
    fn headers_serialize_as_cloudflared_s_and_read_back() {
        assert_eq!(
            serialize(&[("Mock-Header-One", "Mock header one value")]),
            "TW9jay1IZWFkZXItT25l:TW9jayBoZWFkZXIgb25lIHZhbHVl"
        );
        let both = serialize(&[("A", "b"), ("Content-Type", "text/plain; charset=utf-8")]);
        assert_eq!(
            deserialize(&both).unwrap(),
            vec![("A".into(), "b".into()), ("Content-Type".into(), "text/plain; charset=utf-8".into())]
        );
        assert_eq!(deserialize(""), Some(vec![]));
        assert_eq!(deserialize("QQ:Yg:Yw"), None, "three parts");
        assert_eq!(deserialize("!!:Yg"), None, "not base64");
    }

    #[test]
    fn the_answer_to_a_websocket_holds_the_accept_of_rfc_6455() {
        // RFC 6455, section 1.3: the key and its accept.
        let headers = deserialize(&websocket_answer("dGhlIHNhbXBsZSBub25jZQ==")).unwrap();
        assert!(headers.contains(&("Sec-Websocket-Accept".into(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".into())));
        assert!(headers.contains(&("Upgrade".into(), "websocket".into())));
        assert!(headers.contains(&("Connection".into(), "Upgrade".into())));
    }
}
