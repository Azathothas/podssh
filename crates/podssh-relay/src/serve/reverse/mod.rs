//! The relay role's reverse road (T-427): `POST /v1/pair`, the node's socket
//! at `/v1/node/<name>`, the operator's at `/v1/connect/<name>`,
//! `GET /v1/status/<name>` and `POST /v1/stop/<name>`, as the contract
//! `2026-10-03-r2` gives them (`docs/relay.md`, "The reverse path"), so that
//! `podssh node`, `podssh operator` and `podssh ssh node://` work against
//! `podssh relay serve` with no other relay. What the default deployment does
//! not do, the role does: a bound of 1 MiB for a slow receiver (T-336), a
//! frame in flight for a session just closed dropped, not the node's socket
//! (T-421), and `1012` to each socket before a planned stop (T-255).
//!
//! The frames are read and written with the codecs of podssh's own node
//! (`crate::reverse::framing`, `crate::reverse::control`), so that the two
//! sides cannot drift apart; `scripts/fake_reverse.py` stays the second
//! reading of the contract.

pub mod node;
pub mod operator;
pub mod outbox;
pub mod pairs;

pub use pairs::Pairs;

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request::{self, Request};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};

use self::pairs::{NotMade, Role};
use super::{answer, docs, Config, Mint};
use crate::reverse::framing::SessionId;

/// The role pings each reverse socket this often, and drops one that answers
/// nothing for so many intervals: a dead node's socket would else hold its
/// name, and the node that comes back would meet `409` for ever. The default
/// relay sends no keepalive; a Ping is no payload, and a peer answers it.
pub const PING_EVERY: Duration = Duration::from_secs(20);
pub const PINGS_ALLOWED: u32 = 3;
/// How long a socket that the role closed waits for the peer's Close.
pub const CLOSE_WAIT: Duration = Duration::from_secs(5);
/// The contract's wait for a `ready`: `1013 node open timeout` after it.
pub const OPEN_WAIT: Duration = Duration::from_secs(15);
/// The contract's cap of one session, both ways together.
pub const SESSION_BYTES: u64 = 64 << 20;
/// The sessions of one node, as `hello` says them.
pub const MAX_SESSIONS: usize = 64;
/// The largest body of `/v1/pair` and `/v1/stop`, which the contract sends
/// as `{}`.
const BODY_MAX: usize = 4096;

/// Whether `path` is one of the reverse road's.
pub fn serves(path: &str) -> bool {
    path == "/v1/pair" || ["/v1/node/", "/v1/connect/", "/v1/status/", "/v1/stop/"].iter().any(|p| path.starts_with(p))
}

/// Serve one request of the reverse road on `stream`.
pub async fn request<S>(mut stream: S, head: Request, pending: Vec<u8>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    // A request that is no upgrade has its body read first, `{}` at most: a
    // byte left unread would make the end of the connection a reset, which
    // can lose the answer.
    let (pending, sent) = if head.has_token("upgrade", "websocket") {
        (pending, Vec::new())
    } else {
        match super::body(&mut stream, &head, pending, BODY_MAX, &path).await {
            Ok(sent) => (Vec::new(), sent),
            Err(refusal) => return answer(&mut stream, refusal).await,
        }
    };
    if path == "/v1/pair" {
        return pair(&mut stream, &head, &sent, &cfg).await;
    }
    let mut parts = path.trim_start_matches('/').splitn(3, '/');
    let (Some("v1"), Some(kind), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
        return answer(&mut stream, request::refusal(404, &format!("{path}: not found"), &[])).await;
    };
    let role = match kind {
        "node" => Role::Node,
        "connect" | "status" => Role::Connect,
        _ => Role::Stop,
    };
    let now = super::tokens::now_ms();
    let found = crate::relay::check_node_name(name)
        .ok()
        .and_then(|()| cfg.pairs.find(name, role, token_of(&head).as_deref(), now));
    // Each failed authentication looks the same, as on the default relay.
    let Some(pair) = found else {
        return answer(&mut stream, request::refusal(403, "reverse: forbidden", &[])).await;
    };
    let method = head.method.clone();
    match (kind, method.as_str()) {
        ("status", "GET") => {
            let (online, sessions) = {
                let state = pair.lock();
                (state.node_outbox().is_some(), state.sessions.len())
            };
            answer(&mut stream, docs::json(&json!({ "online": online, "sessions": sessions }))).await
        }
        ("stop", "POST") => {
            let (stopped, sessions) = cfg.pairs.end(name, 1001, "operator stopped reverse relay").unwrap_or((false, 0));
            cfg.event("reverse stop");
            answer(&mut stream, docs::json(&json!({ "stopped": stopped, "sessions": sessions }))).await
        }
        ("node", _) => node::join(stream, head, pending, pair, cfg).await,
        ("connect", _) => operator::join(stream, head, pending, pair, cfg).await,
        (_, method) => {
            let allow = if kind == "stop" { "POST" } else { "GET" };
            let why = format!("{path}: not {method}, but {allow}");
            answer(&mut stream, request::refusal(405, &why, &[("Allow", allow)])).await
        }
    }
}

/// `POST /v1/pair`: `{name, node_token, connect_token, stop_token, expires}`,
/// for whom the role mints tokens.
async fn pair<S>(stream: &mut S, head: &Request, body: &[u8], cfg: &Config)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if head.method != "POST" {
        let why = format!("/v1/pair: not {}, but POST", head.method);
        return answer(stream, request::refusal(405, &why, &[("Allow", "POST")])).await;
    }
    if cfg.mint == Mint::Nobody {
        let why = "/v1/pair: this relay makes no pair, as it mints no token; its owner gives them";
        return answer(stream, request::refusal(503, why, &[])).await;
    }
    let empty = body.iter().all(u8::is_ascii_whitespace);
    if !empty && !serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|v| v.is_object()) {
        return answer(stream, request::refusal(400, "/v1/pair: the body is {} or nothing", &[])).await;
    }
    let made = match cfg.pairs.make(super::tokens::now_ms()) {
        Ok(made) => made,
        Err(NotMade::NameInUse) => {
            return answer(stream, request::refusal(409, "/v1/pair: the name drawn is in use; pair again", &[])).await
        }
        Err(NotMade::Full) => {
            let why = format!("/v1/pair: this relay keeps {} pairs already", pairs::MAX_PAIRS);
            return answer(stream, request::refusal(429, &why, &[("Retry-After", "60")])).await;
        }
        Err(NotMade::Failed(why)) => {
            return answer(stream, request::refusal(503, &format!("/v1/pair: {why}"), &[])).await;
        }
    };
    cfg.event("reverse pair");
    let body = json!({
        "name": made.name, "node_token": made.node, "connect_token": made.connect,
        "stop_token": made.stop, "expires": made.expires_ms,
    });
    answer(stream, docs::json(&body)).await;
}

/// The token of a reverse request: its `X-Relay-Token`, else its `?token=`,
/// the two places that the contract names.
fn token_of(head: &Request) -> Option<String> {
    if let Some(token) = head.header("x-relay-token") {
        return Some(token.to_string());
    }
    let query = head.target.split_once('?').map(|(_, q)| q)?;
    query.split('&').find_map(|p| p.strip_prefix("token=")).map(str::to_string)
}

/// A new session's id: 32 lowercase hex characters, as the contract gives.
fn new_id() -> Option<SessionId> {
    let bytes = pairs::random(16).ok()?;
    SessionId::parse(pairs::hex(&bytes).as_bytes()).ok()
}

/// The node's first frame, as the default relay sends it (measured
/// 2026-10-09).
fn hello() -> String {
    json!({ "type": "hello", "version": 1, "maxFrameBytes": 65536, "maxSessions": MAX_SESSIONS }).to_string()
}

/// `open {id}` to the node.
fn open(id: &SessionId) -> String {
    json!({ "type": "open", "id": id.as_str() }).to_string()
}

/// `close {id}` to the node, with the relay's reason when it ended the
/// session itself; with none when the operator left, as the default relay.
fn close(id: &SessionId, why: Option<&str>) -> String {
    match why {
        Some(why) => json!({ "type": "close", "id": id.as_str(), "reason": why }).to_string(),
        None => json!({ "type": "close", "id": id.as_str() }).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reverse::control::{self, NodeInbound, NodeLimits};

    fn head(target: &str, token: Option<&str>) -> Request {
        let header = token.map(|t| format!("X-Relay-Token: {t}\r\n")).unwrap_or_default();
        let text = format!("GET {target} HTTP/1.1\r\nHost: relay-a.test\r\n{header}\r\n");
        request::parse_request(text.as_bytes()).unwrap()
    }

    #[test]
    fn the_paths_of_the_reverse_road_are_its_own() {
        for path in ["/v1/pair", "/v1/node/p-a", "/v1/connect/p-a", "/v1/status/p-a", "/v1/stop/p-a"] {
            assert!(serves(path), "{path}");
        }
        for path in ["/v1/mint", "/v1/pairs", "/connect/h/22", "/health", "/v1/nodes/p-a"] {
            assert!(!serves(path), "{path}");
        }
    }

    #[test]
    fn a_token_comes_from_its_header_first_then_from_the_query() {
        assert_eq!(token_of(&head("/v1/status/p-a", Some("aaaa"))).as_deref(), Some("aaaa"));
        assert_eq!(token_of(&head("/v1/status/p-a?x=1&token=bbbb", None)).as_deref(), Some("bbbb"));
        assert_eq!(token_of(&head("/v1/status/p-a?token=bbbb", Some("aaaa"))).as_deref(), Some("aaaa"));
        assert_eq!(token_of(&head("/v1/status/p-a", None)), None);
    }

    #[test]
    fn podssh_s_node_reads_each_frame_that_the_role_sends_it() {
        let mut limits = NodeLimits::conservative();
        match control::parse_inbound(hello().as_bytes()).unwrap() {
            NodeInbound::Hello(hello) => limits.apply(&hello),
            other => panic!("{other:?}"),
        }
        assert_eq!(limits, NodeLimits { max_sessions: 64, max_frame_bytes: 65536 });
        let id = new_id().unwrap();
        assert!(
            matches!(control::parse_inbound(open(&id).as_bytes()).unwrap(), NodeInbound::Open { id: i } if i == id.as_str())
        );
        let closed = control::parse_inbound(close(&id, Some("relay backpressure")).as_bytes()).unwrap();
        assert!(matches!(closed, NodeInbound::Close { reason: Some(r), .. } if r == "relay backpressure"));
        assert!(matches!(
            control::parse_inbound(close(&id, None).as_bytes()).unwrap(),
            NodeInbound::Close { reason: None, .. }
        ));
        assert_ne!(new_id().unwrap(), id, "each id is drawn");
    }
}
