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
//!
//! Over QUIC the same push is a call of `updateConfiguration`, with the
//! version and the rules as its parameters, on an RPC stream of the edge
//! (T-411, `rpc_stream`): its results say the same, in Cap'n Proto
//! (`tunnelrpc/proto/tunnelrpc.capnp`, the interface `ConfigurationManager`;
//! `tunnelrpc/pogs/configuration_manager.go`).

use std::time::Duration;

use serde_json::{Map, Value};

use super::capnp::{At, Builder, Struct};

/// The most bytes of a push that the node reads: a quick tunnel's rules are
/// no one's to push, so a larger body is not taken for one.
pub const MAX_PUSH: usize = 1024 * 1024;
/// How long the edge has to send a push's body.
pub const PUSH_WAIT: Duration = Duration::from_secs(10);

/// `ConfigurationManager`, and its one method (T-411).
pub const CONFIGURATION_MANAGER: u64 = 0xb48e_dfbd_aa25_db04;
pub const UPDATE_CONFIGURATION: u16 = 0;
/// The sizes of its results, `result`, and of that `UpdateConfigurationResponse`:
/// `latestAppliedVersion` (data bytes 0 to 3) and `err` (pointer 0).
pub const RESULTS: (u16, u16) = (0, 1);
const RESPONSE: (u16, u16) = (1, 1);

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

/// The results of a push over QUIC whose parameters are `params` (T-411),
/// written in `at`, a struct of [`RESULTS`]: as [`answer`] over HTTP/2, the
/// push's version (`version`, data bytes 0 to 3, an Int32), taken, and no
/// `err`, as cloudflared writes a push that it took. Parameters that are
/// not set read as Go's zero; the rules, `config`, are not looked at.
pub fn results(params: Option<Struct<'_>>, b: &mut Builder, at: At) {
    let version = params.map_or(0, |params| params.u32(0));
    let response = b.init_struct(at, 0, RESPONSE.0, RESPONSE.1);
    b.set_u32(response, 0, version);
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
