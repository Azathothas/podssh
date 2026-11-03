//! What a bridge carries (anomalyco/opentunnel:docs/protocol.md at v0.6.1,
//! "Bridge"): JSON control messages in text frames, and each connection's
//! bytes in binary frames of a big-endian `u32` connection id and at most
//! 32 KiB. A message of a type that this end does not know is ignored, as
//! the protocol asks, and so is a field; a known message with a field
//! missing or out of range is refused. The routes: `@`, the tunnel's own
//! name, or one DNS label, which a visitor's SNI picks.

use std::time::Duration;

use serde_json::{json, Value};

/// The subprotocol of a bridge: version 1.
pub const SUBPROTOCOL: &str = "opentunnel";
/// The largest payload of a data frame.
pub const MAX_PAYLOAD: usize = 32 * 1024;
/// The connections that a bridge carries at once, at most: what OpenTunnel's
/// own clients advertise, and the server's own bound.
pub const MAX_CONNS: u32 = 256;
/// The route of the tunnel's own name.
pub const ROOT_ROUTE: &str = "@";
/// The server closes a bridge that sends no `attach` within this.
pub const ATTACH_WITHIN: Duration = Duration::from_secs(10);

/// The codes of `attach_error` and `reset` that this end names or sends.
pub mod codes {
    pub const BAD_TOKEN: &str = "bad_token";
    pub const CERT_NOT_READY: &str = "cert_not_ready";
    pub const ROUTE_CONFLICT: &str = "route_conflict";
    pub const TOO_MANY_ROUTES: &str = "too_many_routes";
    pub const UNKNOWN_ROUTE: &str = "unknown_route";
    pub const TOO_MANY_CONNECTIONS: &str = "too_many_connections";
    pub const UPSTREAM_CONNECT_FAILED: &str = "upstream_connect_failed";
    pub const UPSTREAM_IO_ERROR: &str = "upstream_io_error";
}

/// Whether an `attach_error` will be the same on each try: the token is not
/// the tunnel's, or its certificate is not ready.
pub fn fatal(code: &str) -> bool {
    matches!(code, codes::BAD_TOKEN | codes::CERT_NOT_READY)
}

/// The words of an `attach_error`, for the user.
pub fn attach_words(code: &str) -> String {
    let code = podssh_ws::text::one_line(code);
    match code.as_str() {
        codes::BAD_TOKEN => {
            "OpenTunnel refused the tunnel's token (bad_token): the tunnel is gone, or its token is not \
                             the one kept"
                .into()
        }
        codes::CERT_NOT_READY => "OpenTunnel has no certificate ready for the tunnel (cert_not_ready)".into(),
        codes::ROUTE_CONFLICT => {
            "another bridge of the tunnel holds its route (route_conflict): an earlier run of this \
                                  node, until the service lets it go"
                .into()
        }
        codes::TOO_MANY_ROUTES => "the tunnel's bridges claim too many routes (too_many_routes)".into(),
        other => format!("OpenTunnel refused the bridge ({other})"),
    }
}

/// The words of a Close of a bridge that the server sent.
pub fn close_words(code: Option<u16>, reason: &str) -> String {
    let reason = podssh_ws::text::one_line(reason);
    let what = match code {
        Some(1008) => "the service closed the bridge as no attach came in time (1008)".to_string(),
        Some(1009) => "the service closed the bridge for a message too large (1009)".to_string(),
        Some(1001) => "the service took the bridge for gone (1001)".to_string(),
        Some(1012) => "the service restarts (1012)".to_string(),
        Some(code) => format!("the service closed the bridge ({code})"),
        None => "the service closed the bridge".to_string(),
    };
    if reason.is_empty() {
        what
    } else {
        format!("{what}: {reason}")
    }
}

/// A message of this end, the client of the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Up<'a> {
    Attach { token: &'a str, routes: &'a [String] },
    Ping { time_sent: u64 },
    Pong { time_sent: u64 },
    End { conn: u32 },
    Reset { conn: u32, code: &'a str },
}

impl Up<'_> {
    /// The message's text frame.
    pub fn text(&self) -> String {
        let value = match self {
            Up::Attach { token, routes } => json!({
                "type": "attach",
                "token": token,
                "transport": "ws",
                "routes": routes,
                "client": { "version": concat!("podssh/", env!("CARGO_PKG_VERSION")), "max_conns": MAX_CONNS },
            }),
            Up::Ping { time_sent } => json!({ "type": "ping", "time_sent": time_sent }),
            Up::Pong { time_sent } => json!({ "type": "pong", "time_sent": time_sent }),
            Up::End { conn } => json!({ "type": "end", "conn": conn }),
            Up::Reset { conn, code } => json!({ "type": "reset", "conn": conn, "code": code }),
        };
        value.to_string()
    }
}

/// A message of the server's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Down {
    Attached { session: String, routes: Vec<String>, heartbeat_ms: u64, idle_timeout_ms: u64 },
    AttachError { code: String },
    Open { conn: u32, peer: String, sni: String, alpn: String },
    Ping { time_sent: u64 },
    Pong { time_sent: u64 },
    Drain { reason: String },
    End { conn: u32 },
    Reset { conn: u32, code: String },
}

/// The server's message in `text`: none for a type that this end does not
/// know, which the protocol has it ignore; an error for text that is no
/// message, or a known message that is not whole.
pub fn decode(text: &str) -> Result<Option<Down>, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("a control message that is no JSON: {e}"))?;
    let Some(kind) = value.get("type").and_then(Value::as_str) else {
        return Err("a control message with no type".into());
    };
    let text = |name: &str| -> Result<String, String> {
        value.get(name).and_then(Value::as_str).map(str::to_string).ok_or_else(|| format!("{kind}: no {name}"))
    };
    // A field that a known message may leave out is empty.
    let text_or_empty = |name: &str| value.get(name).and_then(Value::as_str).unwrap_or_default().to_string();
    let number = |name: &str| value.get(name).and_then(Value::as_u64).ok_or_else(|| format!("{kind}: no {name}"));
    let conn = || -> Result<u32, String> {
        let conn = number("conn")?;
        u32::try_from(conn).map_err(|_| format!("{kind}: the connection id {conn} is past u32"))
    };
    let down = match kind {
        "attached" => {
            let routes = match value.get("routes") {
                None => Vec::new(),
                Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(str::to_string).collect(),
                Some(_) => return Err("attached: routes is not a list".into()),
            };
            Down::Attached {
                session: text("session")?,
                routes,
                heartbeat_ms: number("heartbeat_ms")?,
                idle_timeout_ms: number("idle_timeout_ms")?,
            }
        }
        "attach_error" => Down::AttachError { code: text("code")? },
        "open" => {
            Down::Open { conn: conn()?, peer: text_or_empty("peer"), sni: text("sni")?, alpn: text_or_empty("alpn") }
        }
        "ping" => Down::Ping { time_sent: number("time_sent")? },
        "pong" => Down::Pong { time_sent: number("time_sent")? },
        "drain" => Down::Drain { reason: text_or_empty("reason") },
        "end" => Down::End { conn: conn()? },
        "reset" => Down::Reset { conn: conn()?, code: text_or_empty("code") },
        _ => return Ok(None),
    };
    Ok(Some(down))
}

/// A data frame: the connection's id, big-endian, then the payload.
pub fn data_frame(conn: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&conn.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// A data frame's connection id and payload; none for one of fewer than 4
/// bytes.
pub fn split_frame(frame: &[u8]) -> Option<(u32, &[u8])> {
    let (head, payload) = frame.split_at_checked(4)?;
    Some((u32::from_be_bytes(head.try_into().ok()?), payload))
}

/// One DNS label of `[a-z0-9-]`, 63 at most, with no `-` at either end.
fn is_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    match bytes {
        [] => false,
        [only] => edge(only),
        [first, middle @ .., last] => {
            bytes.len() <= 63 && edge(first) && edge(last) && middle.iter().all(|b| edge(b) || *b == b'-')
        }
    }
}

/// Whether `value` is a route: `@`, or one label.
pub fn is_route(value: &str) -> bool {
    value == ROOT_ROUTE || is_label(value)
}

/// The route that a visitor's SNI picks on the tunnel `hostname`: `@` for
/// the name itself, the label for a name one deeper; none for each other
/// name. Case does not matter.
pub fn route_for_sni(sni: &str, hostname: &str) -> Option<String> {
    let (sni, hostname) = (sni.to_ascii_lowercase(), hostname.to_ascii_lowercase());
    if sni == hostname {
        return Some(ROOT_ROUTE.to_string());
    }
    let label = sni.strip_suffix(&hostname)?.strip_suffix('.')?;
    is_label(label).then(|| label.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors of `anomalyco/opentunnel:spec/vectors/control.json` at v0.6.1.
    #[test]
    fn the_server_s_messages_of_the_protocol_s_vectors_are_read_and_the_bad_ones_refused() {
        let attached = r#"{ "type": "attached", "session": "sess_1", "routes": ["api"], "heartbeat_ms": 15000, "idle_timeout_ms": 45000 }"#;
        let want = Down::Attached {
            session: "sess_1".into(),
            routes: vec!["api".into()],
            heartbeat_ms: 15000,
            idle_timeout_ms: 45000,
        };
        assert_eq!(decode(attached), Ok(Some(want)));
        assert_eq!(
            decode(r#"{ "type": "attach_error", "code": "bad_token" }"#),
            Ok(Some(Down::AttachError { code: "bad_token".into() }))
        );
        let open = r#"{ "type": "open", "conn": 1, "peer": "203.0.113.9", "sni": "api.demo.opentunnel.xyz", "alpn": "h2,http/1.1" }"#;
        let want = Down::Open {
            conn: 1,
            peer: "203.0.113.9".into(),
            sni: "api.demo.opentunnel.xyz".into(),
            alpn: "h2,http/1.1".into(),
        };
        assert_eq!(decode(open), Ok(Some(want)));
        assert_eq!(
            decode(r#"{ "type": "ping", "time_sent": 1700000000000 }"#),
            Ok(Some(Down::Ping { time_sent: 1_700_000_000_000 }))
        );
        assert_eq!(
            decode(r#"{ "type": "drain", "reason": "deploy" }"#),
            Ok(Some(Down::Drain { reason: "deploy".into() }))
        );
        assert_eq!(decode(r#"{ "type": "end", "conn": 1 }"#), Ok(Some(Down::End { conn: 1 })));
        let reset = r#"{ "type": "reset", "conn": 1, "code": "client_io_error" }"#;
        assert_eq!(decode(reset), Ok(Some(Down::Reset { conn: 1, code: "client_io_error".into() })));
        assert_eq!(decode(r#"{ "type": "future_message", "anything": true }"#), Ok(None), "an unknown type is ignored");
        for invalid in [
            r#"{ "type": "open", "conn": -1, "peer": "x", "sni": "x", "alpn": "" }"#,
            r#"{ "type": "open", "conn": 4294967296, "peer": "x", "sni": "x", "alpn": "" }"#,
            r#"{ "type": "end" }"#,
            r#"{ "type": "attached", "session": "s" }"#,
            r#"{ "conn": 1 }"#,
            "not json",
        ] {
            assert!(decode(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn this_end_s_messages_hold_the_fields_of_the_protocol() {
        let routes = vec!["@".to_string(), "api".to_string()];
        let attach: Value = serde_json::from_str(&Up::Attach { token: "tok_123", routes: &routes }.text()).unwrap();
        assert_eq!(attach["type"], "attach");
        assert_eq!(attach["token"], "tok_123");
        assert_eq!(attach["transport"], "ws");
        assert_eq!(attach["routes"], json!(["@", "api"]));
        assert_eq!(attach["client"]["max_conns"], 256);
        assert!(attach["client"]["version"].as_str().unwrap().starts_with("podssh/"));
        let reset: Value =
            serde_json::from_str(&Up::Reset { conn: u32::MAX, code: codes::UNKNOWN_ROUTE }.text()).unwrap();
        assert_eq!(reset, json!({ "type": "reset", "conn": 4294967295u64, "code": "unknown_route" }));
        let pong: Value = serde_json::from_str(&Up::Pong { time_sent: 1_700_000_000_000 }.text()).unwrap();
        assert_eq!(pong, json!({ "type": "pong", "time_sent": 1700000000000u64 }));
    }

    /// `anomalyco/opentunnel:spec/vectors/frames.json` at v0.6.1.
    #[test]
    fn a_data_frame_is_the_connection_s_id_big_endian_then_its_bytes() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(&data_frame(0, b"")), "00000000");
        assert_eq!(hex(&data_frame(1, b"hello")), "0000000168656c6c6f");
        assert_eq!(hex(&data_frame(4_294_967_295, &[0xff, 0x00])), "ffffffffff00");
        assert_eq!(hex(&data_frame(305_419_896, &[0x16, 0x03, 0x01, 0x00])), "1234567816030100");
        assert_eq!(split_frame(&data_frame(7, b"abc")), Some((7, &b"abc"[..])));
        assert_eq!(split_frame(&[0, 0, 1]), None);
    }

    /// `anomalyco/opentunnel:spec/vectors/names.json` and `routes.json` at v0.6.1.
    #[test]
    fn routes_are_one_label_or_at_and_a_visitor_s_sni_picks_one() {
        for ok in ["@", "api", "a", "my-app2", &"a".repeat(63)] {
            assert!(is_route(ok), "{ok}");
        }
        for bad in ["-api", "api-", "Api", "a.b", "", &"a".repeat(64)] {
            assert!(!is_route(bad), "{bad}");
        }
        let host = "demo.opentunnel.xyz";
        assert_eq!(route_for_sni("demo.opentunnel.xyz", host).as_deref(), Some("@"));
        assert_eq!(route_for_sni("api.demo.opentunnel.xyz", host).as_deref(), Some("api"));
        assert_eq!(route_for_sni("API.Demo.OpenTunnel.xyz", host).as_deref(), Some("api"));
        for none in
            ["a.b.demo.opentunnel.xyz", "other.opentunnel.xyz", "xdemo.opentunnel.xyz", ".demo.opentunnel.xyz", ""]
        {
            assert_eq!(route_for_sni(none, host), None, "{none}");
        }
    }

    #[test]
    fn the_refusals_are_named_and_two_of_them_are_final() {
        assert!(fatal("bad_token") && fatal("cert_not_ready"));
        assert!(!fatal("route_conflict") && !fatal("too_many_routes"));
        assert!(attach_words("bad_token").contains("token"));
        assert!(attach_words("route_conflict").contains("route_conflict"));
        assert!(close_words(Some(1008), "").contains("1008"));
        assert!(close_words(Some(1009), "too big").ends_with("1009): too big"));
    }
}
