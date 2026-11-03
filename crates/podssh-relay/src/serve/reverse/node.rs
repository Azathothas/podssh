//! The node's socket at `/v1/node/<name>` (T-427): one for each pair, a
//! second one refused with `409` before the upgrade, so that the node that
//! holds the name and its sessions go on. The role sends `hello`, then
//! `open {id}` and `close {id}`, and reads the node's `ready`, `reject` and
//! `close` and its binary frames, each the session's 32 hex characters and
//! the payload; a fault of the node's bytes closes its socket with the row of
//! the contract's close table, and its operators hear that cause. A
//! carrier's node (T-595) has the same socket with no upgrade before it.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::frame;
use podssh_ws::http::request::Request;
use podssh_ws::server;
use podssh_ws::session::RelaySession;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::outbox::{frames_of, Outbox};
use super::pairs::{Answer, NodeLink, Pair};
use super::{close, hello, CLOSE_WAIT, PINGS_ALLOWED, PING_EVERY};
use crate::reverse::control;
use crate::reverse::framing::legs::decode_node_frame;
use crate::reverse::framing::{CodecError, SessionId, CONTROL_FRAME_MAX};
use crate::serve::{answer, tokens, Config};

/// A fault of the node's bytes: the code and the reason of the table's row.
type Fault = (u16, &'static str);

/// Join the node of `pair` on `stream`, and serve its socket until it ends.
pub async fn join<S>(mut stream: S, head: Request, pending: Vec<u8>, pair: Arc<Pair>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let key = match server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => return answer(&mut stream, refused.answer()).await,
    };
    let serial = cfg.pairs.serial();
    let held = {
        let mut state = pair.lock();
        let held = state.node.is_some();
        if !held {
            state.node = Some(NodeLink { serial, outbox: None });
        }
        held
    };
    if held {
        let why = "reverse: a node holds this name";
        return answer(&mut stream, podssh_ws::http::request::refusal(409, why, &[])).await;
    }
    if stream.write_all(&server::switching(&key)).await.is_err() {
        detach(&pair, serial, None);
        return;
    }
    let session = Arc::new(server::session(stream, pending, None));
    let outbox = Outbox::start(session.clone(), cfg.pairs.writers.clone());
    if !joined(&pair, serial, &outbox) {
        // Stopped or expired while the upgrade was answered.
        outbox.close(1001, "pair expired");
        return;
    }
    socket(session, outbox, pair, cfg, serial).await
}

/// A node's socket that is a WebSocket from its first byte, with no upgrade
/// before it: a carrier's (T-595), in the process of the carrier's client.
/// It holds `pair` at once, or is refused while a node holds it; then a task
/// serves it as [`join`] serves one.
pub fn carried<S>(session: Arc<RelaySession<S>>, pair: Arc<Pair>, cfg: Arc<Config>) -> Result<JoinHandle<()>, String>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let serial = cfg.pairs.serial();
    {
        let mut state = pair.lock();
        if state.ended || state.node.is_some() {
            return Err("a node holds the carrier's role".into());
        }
        state.node = Some(NodeLink { serial, outbox: None });
    }
    let outbox = Outbox::start(session.clone(), cfg.pairs.writers.clone());
    if !joined(&pair, serial, &outbox) {
        outbox.close(1001, "the carrier's role ended");
        return Err("the carrier's role ended".into());
    }
    Ok(tokio::spawn(socket(session, outbox, pair, cfg, serial)))
}

/// Give the node's socket under `serial` its writer, unless the pair ended,
/// or another socket took its place, meanwhile.
fn joined(pair: &Pair, serial: u64, outbox: &Outbox) -> bool {
    let mut guard = pair.lock();
    let state = &mut *guard;
    match state.node.as_mut() {
        Some(link) if link.serial == serial && !state.ended => {
            link.outbox = Some(outbox.clone());
            true
        }
        _ => false,
    }
}

/// Serve the node's socket of `pair`, joined under `serial` with its writer
/// `outbox`, until it ends.
async fn socket<S>(session: Arc<RelaySession<S>>, outbox: Outbox, pair: Arc<Pair>, cfg: Arc<Config>, serial: u64)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    // Until the node answered a Close: a planned stop waits for it (T-255).
    let _live = cfg.pairs.live.counted();
    outbox.text(hello());
    cfg.event("reverse node");

    let (mut frames, reader) = frames_of(session.clone());
    let liveness = session.watch_liveness(PING_EVERY, PINGS_ALLOWED);
    tokio::pin!(liveness);
    let left = Duration::from_millis(pair.expires_ms().saturating_sub(tokens::now_ms()));
    let expiry = tokio::time::sleep(left);
    tokio::pin!(expiry);
    let (mut expired, mut cause): (bool, Option<Fault>) = (false, None);
    let mut closing: Option<Instant> = None;
    loop {
        let give_up = closing.map(|at| at + CLOSE_WAIT);
        tokio::select! {
            read = frames.recv() => match read {
                Some(Ok(f)) if cause.is_none() => {
                    let fault = match f.opcode {
                        frame::OPCODE_TEXT => control_frame(&pair, &f.payload, &cfg),
                        frame::OPCODE_BINARY => data(&pair, &outbox, &f.payload, &cfg),
                        frame::OPCODE_CLOSE => break,
                        _ => Ok(()),
                    };
                    if let Err((code, why)) = fault {
                        cfg.event(&format!("reverse node closed {code} {why}"));
                        // Before what waits: a node whose bytes broke the
                        // contract hears why at once.
                        outbox.abort(code, why);
                        cause = Some((code, why));
                        closing.get_or_insert_with(Instant::now);
                    }
                }
                Some(Ok(f)) if f.opcode == frame::OPCODE_CLOSE => break,
                Some(Ok(_)) => {}
                _ => break,
            },
            _ = &mut liveness => break,
            () = &mut expiry, if !expired => {
                // A renewal (T-592) moved the end: its new time is waited for.
                match renewed(&pair) {
                    Some(at) => expiry.as_mut().reset(at),
                    None => {
                        expired = true;
                        cfg.pairs.end(&pair.name, 1001, "pair expired");
                        cfg.event("reverse expired");
                    }
                }
            }
            () = outbox.ended(), if closing.is_none() => closing = Some(Instant::now()),
            () = sleep_until(give_up), if give_up.is_some() => break,
        }
    }
    reader.abort();
    detach(&pair, serial, cause);
    outbox.abort(1011, "socket error");
    cfg.event("reverse node gone");
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// When the timer of `pair`'s expiry fires: the instant of its new end, when
/// a renewal moved it (T-592); `None` when it ends now. Read by the node's
/// socket and by each operator's leg.
pub(super) fn renewed(pair: &Pair) -> Option<Instant> {
    let left = pair.expires_ms().saturating_sub(tokens::now_ms());
    (left > 0).then(|| Instant::now() + Duration::from_millis(left))
}

/// The node's socket ended: its sessions end with it, each operator hearing
/// the cause when the role closed the node for one, else `1011 node
/// disconnected`, after what waits for it.
fn detach(pair: &Pair, serial: u64, cause: Option<Fault>) {
    let sessions = {
        let mut state = pair.lock();
        if !state.node.as_ref().is_some_and(|n| n.serial == serial) {
            return;
        }
        state.node = None;
        let ids: Vec<SessionId> = state.sessions.keys().copied().collect();
        ids.iter().filter_map(|id| state.forget(id)).collect::<Vec<_>>()
    };
    let (code, why) = cause.unwrap_or((1011, "node disconnected"));
    for session in sessions {
        session.operator.close(code, why);
    }
}

/// A text frame of the node: `ready`, `reject` or `close`, each with a
/// session's id.
fn control_frame(pair: &Pair, text: &[u8], cfg: &Config) -> Result<(), Fault> {
    if text.len() > CONTROL_FRAME_MAX {
        return Err((1009, "control frame byte cap"));
    }
    let message: Value = serde_json::from_slice(text).map_err(|_| (1003, "invalid control json"))?;
    let kind = message.get("type").and_then(Value::as_str).unwrap_or_default();
    if !matches!(kind, "ready" | "reject" | "close") {
        return Err((1003, "unknown control type"));
    }
    let id = message.get("id").and_then(Value::as_str).map(|id| SessionId::parse(id.as_bytes()));
    let Some(Ok(id)) = id else { return Err((1003, "invalid session id")) };
    // The node's own words; the literal type when it sent none.
    let reason = message.get("reason").and_then(Value::as_str).filter(|r| !r.is_empty()).unwrap_or(kind).to_string();
    let mut state = pair.lock();
    if kind == "ready" {
        if !state.sessions.contains_key(&id) {
            // A `ready` that crossed the relay's close of its session.
            return match state.in_flight(&id) {
                Some(first) => {
                    in_flight(first, 0, cfg);
                    Ok(())
                }
                None => Err((1003, "unknown session id")),
            };
        }
        let Some(session) = state.sessions.get_mut(&id) else { return Ok(()) };
        if !session.ready {
            session.ready = true;
            // On the operator's socket before any byte of the session.
            if let Ok(ready) = control::ready(&id) {
                session.operator.text(String::from_utf8_lossy(&ready).into_owned());
            }
            if let Some(answer) = session.answer.take() {
                let _ = answer.send(Answer::Ready);
            }
        }
        return Ok(());
    }
    // A `reject` or a `close` of an id that the relay forgot is the race of
    // a teardown, and only that.
    let Some(session) = state.forget(&id) else { return Ok(()) };
    drop(state);
    let shown = control::truncate_reason(&reason);
    if kind == "reject" {
        // The `reject` frame keeps the whole reason; the Close, its cut.
        if let Ok(reject) = control::reject(&id, &reason) {
            session.operator.text(String::from_utf8_lossy(&reject).into_owned());
        }
        session.operator.close(1011, &shown);
    } else {
        session.operator.close(1000, &shown);
    }
    Ok(())
}

/// A binary frame of the node: the session's id, then its payload, for the
/// session's operator.
fn data(pair: &Pair, node: &Outbox, wire: &[u8], cfg: &Config) -> Result<(), Fault> {
    let (id, payload) = decode_node_frame(wire).map_err(|e| match e {
        CodecError::FrameTooShort { .. } | CodecError::FrameTooLong { .. } => (1009, "bad multiplex frame"),
        _ => (1003, "bad multiplex id"),
    })?;
    let mut state = pair.lock();
    if !state.sessions.contains_key(&id) {
        return match state.in_flight(&id) {
            // On its way before the node heard of the close (T-421).
            Some(first) => {
                in_flight(first, payload.len(), cfg);
                Ok(())
            }
            None => Err((1003, "unknown session id")),
        };
    }
    let Some(session) = state.sessions.get_mut(&id) else { return Ok(()) };
    if !session.ready {
        return Err((1003, "data before ready"));
    }
    if payload.is_empty() {
        return Ok(());
    }
    session.bytes += payload.len() as u64;
    if session.bytes > pair.session_bytes {
        let session = state.forget(&id);
        drop(state);
        if let Some(session) = session {
            session.operator.close(1009, "session byte cap");
        }
        node.text(close(&id, Some("session byte cap")));
        return Ok(());
    }
    if session.operator.binary_or_full(payload.to_vec()).is_err() {
        // The operator reads too slowly: its session ends, the frame is
        // dropped, and the node's socket, which carries each other session,
        // goes on.
        let session = state.forget(&id);
        drop(state);
        if let Some(session) = session {
            session.operator.abort(1011, "relay backpressure");
        }
        node.text(close(&id, Some("relay backpressure")));
        cfg.event("reverse backpressure");
    }
    Ok(())
}

/// A frame of a session closed in the last seconds: said once.
fn in_flight(first: bool, bytes: usize, cfg: &Config) {
    if first {
        cfg.event(&format!("reverse in flight: a frame of a closed session dropped ({bytes} bytes)"));
    }
}
