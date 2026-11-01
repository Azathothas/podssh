//! A push of configuration (T-404), sans-IO: the edge's request whose kind
//! is `update-configuration`, with the body `{"version":N,"config":{...}}`,
//! sent to a connector of a tunnel that is managed remotely. cloudflared
//! 2026.10.6 applies its ingress rules and answers
//! `{"lastAppliedVersion":N,"err":null}`, or 502 to a body that does not
//! read (`connection/http2.go`, `handleConfigurationUpdate`, and its test
//! `TestHTTP2ConfigurationSet`). podssh serves the one TARGET of its own
//! command line, so it keeps nothing of a push, and answers as cloudflared
//! does when it took one: a refusal could read as a connector that failed,
//! at a later change of the edge.

use std::time::Duration;

use serde_json::{Map, Value};

/// The most bytes of a push that the node reads: a quick tunnel's rules are
/// no one's to push, so a larger body is not taken for one.
pub const MAX_PUSH: usize = 1024 * 1024;
/// How long the edge has to send a push's body.
pub const PUSH_WAIT: Duration = Duration::from_secs(10);

/// The answer to a push whose body is `body`: its version, taken, as
/// cloudflared's answer reads; `None` for a body that does not read as Go's
/// decoder reads it into cloudflared's `ConfigurationUpdateBody`, which gets
/// 502. The rules, `config`, are not looked at.
pub fn answer(body: &[u8]) -> Option<String> {
    let push: Map<String, Value> = serde_json::from_slice(body).ok()?;
    let version = match push.get("version") {
        // Go leaves its zero where the field is missing or null.
        None | Some(Value::Null) => 0,
        Some(number) => i32::try_from(number.as_i64()?).ok()?,
    };
    Some(format!(r#"{{"lastAppliedVersion":{version},"err":null}}"#))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body of cloudflared's `TestHTTP2ConfigurationSet` at 2026.10.6,
    /// byte for byte, and the answer that the test expects.
    const PUSH: &[u8] = br#"{
"version": 2,
"config": {"warp-routing": {"enabled": true},  "originRequest" : {"connectTimeout": 10}, "ingress" : [ {"hostname": "test", "service": "https://localhost:8000" } , {"service": "http_status:404"} ]}}
"#;

    #[test]
    fn a_push_is_answered_as_cloudflared_s_own_test_expects() {
        assert_eq!(answer(PUSH).as_deref(), Some(r#"{"lastAppliedVersion":2,"err":null}"#));
    }

    #[test]
    fn the_version_is_the_push_s_and_a_body_that_does_not_read_gets_none() {
        assert_eq!(answer(br#"{"version":7}"#).as_deref(), Some(r#"{"lastAppliedVersion":7,"err":null}"#));
        assert_eq!(
            answer(br#"{"version":-1,"config":null}"#).as_deref(),
            Some(r#"{"lastAppliedVersion":-1,"err":null}"#)
        );
        assert_eq!(answer(b"{}").as_deref(), Some(r#"{"lastAppliedVersion":0,"err":null}"#), "Go's zero");
        assert_eq!(answer(br#"{"version":null}"#).as_deref(), Some(r#"{"lastAppliedVersion":0,"err":null}"#));
        for bad in [&b""[..], b"not json", br#"{"version":"2"}"#, br#"{"version":3000000000}"#, b"[2]", b"2.5"] {
            assert_eq!(answer(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }
}
