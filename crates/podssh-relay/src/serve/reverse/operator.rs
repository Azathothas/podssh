//! An operator's socket at `/v1/connect/<name>` (T-427): one session to the
//! pair's node. The role gives the session its id, sends the node `open`,
//! and the operator `ready` once the node readied it; after that the
//! operator's binary frames are the payload alone, with no framing, and the
//! role puts the id before each for the node. A text frame of the operator
//! closes its socket with `1003`. A carrier's operator (T-595) has the same
//! socket, a pipe in its own process, with no upgrade before it.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::frame;
use podssh_ws::http::request::Request;
use podssh_ws::server;
use podssh_ws::session::RelaySession;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::Instant;

use super::outbox::{frames_of, Outbox};
use super::pairs::{Pair, Session};
use super::{close, new_id, open, CLOSE_WAIT, MAX_SESSIONS, OPEN_WAIT, PINGS_ALLOWED, PING_EVERY};
use crate::reverse::framing::legs::encode_node_frame;
use crate::reverse::framing::{SessionId, OPERATOR_PAYLOAD_MAX};
use crate::serve::{answer, tokens, Config};

/// Where a session stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// `open` went to the node, which has not answered.
    Opening,
    Ready,
    /// The role or the node closed it: what waits goes out, then the Close.
    Closing,
}

/// Join an operator of `pair` on `stream`, and carry its session until it
/// ends.
pub async fn join<S>(mut stream: S, head: Request, pending: Vec<u8>, pair: Arc<Pair>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let key = match server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => return answer(&mut stream, refused.answer()).await,
    };
    if stream.write_all(&server::switching(&key)).await.is_err() {
        return;
    }
    leg(Arc::new(server::session(stream, pending, None)), pair, cfg).await
}

/// An operator's socket that is a WebSocket already, carried until its
/// session ends: the role's after the upgrade, and a carrier's leg (T-595).
pub async fn leg<S>(session: Arc<RelaySession<S>>, pair: Arc<Pair>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let outbox = Outbox::start(session.clone(), cfg.pairs.writers.clone());
    let Some(id) = new_id() else {
        outbox.close(1011, "socket error");
        return;
    };
    let (told, answered) = oneshot::channel();
    let node = {
        let mut state = pair.lock();
        match state.node_outbox() {
            Some(node) if state.sessions.len() < MAX_SESSIONS && !state.ended => {
                let entry = Session { operator: outbox.clone(), ready: false, answer: Some(told), bytes: 0 };
                state.sessions.insert(id, entry);
                Some(node)
            }
            _ => None,
        }
    };
    let Some(node) = node else {
        // No node, or no room on it: the `open` could not be queued.
        outbox.close(1011, "node unavailable");
        let _ = tokio::time::timeout(CLOSE_WAIT, outbox.ended()).await;
        return;
    };
    node.text(open(&id));
    cfg.event("reverse open");

    let (mut frames, reader) = frames_of(session.clone());
    let liveness = session.watch_liveness(PING_EVERY, PINGS_ALLOWED);
    tokio::pin!(liveness);
    let left = Duration::from_millis(pair.expires_ms.saturating_sub(tokens::now_ms()));
    let expiry = tokio::time::sleep(left);
    tokio::pin!(expiry);
    let open_by = tokio::time::sleep(OPEN_WAIT);
    tokio::pin!(open_by);
    tokio::pin!(answered);
    let mut phase = Phase::Opening;
    let mut closing: Option<Instant> = None;
    let mut expired = false;
    loop {
        let give_up = closing.map(|at| at + CLOSE_WAIT);
        tokio::select! {
            read = frames.recv() => match read {
                Some(Ok(f)) if f.opcode == frame::OPCODE_CLOSE => break,
                Some(Ok(_)) if phase == Phase::Closing => {}
                Some(Ok(f)) if f.opcode == frame::OPCODE_TEXT => {
                    // The operator's leg is binary alone.
                    end(&pair, &id, &outbox, (1003, "binary frames required"));
                    phase = Phase::Closing;
                }
                Some(Ok(f)) if f.opcode == frame::OPCODE_BINARY && phase == Phase::Opening => {
                    if !f.payload.is_empty() {
                        end(&pair, &id, &outbox, (1008, "wait for ready"));
                        phase = Phase::Closing;
                    }
                }
                Some(Ok(f)) if f.opcode == frame::OPCODE_BINARY => {
                    if let Err(why) = carry(&pair, &id, &f.payload).await {
                        end(&pair, &id, &outbox, why);
                        phase = Phase::Closing;
                    }
                }
                Some(Ok(_)) => {}
                // The link was lost, not closed.
                _ => break,
            },
            answer = &mut answered, if phase == Phase::Opening => {
                // `Ok`: the node readied it, and the operator heard `ready`
                // first; `Err`: the node refused it, or went away, and the
                // operator hears why.
                phase = if answer.is_ok() { Phase::Ready } else { Phase::Closing };
            }
            () = &mut open_by, if phase == Phase::Opening => {
                end(&pair, &id, &outbox, (1013, "node open timeout"));
                phase = Phase::Closing;
            }
            _ = &mut liveness => break,
            () = &mut expiry, if !expired => {
                expired = true;
                cfg.pairs.end(&pair.name, 1001, "pair expired");
                phase = Phase::Closing;
            }
            () = outbox.ended(), if closing.is_none() => {
                closing = Some(Instant::now());
                phase = Phase::Closing;
            }
            () = sleep_until(give_up), if give_up.is_some() => break,
        }
    }
    reader.abort();
    // The node hears of the end at once, unless the session ended there.
    let (gone, node) = {
        let mut state = pair.lock();
        (state.forget(&id).is_some(), state.node_outbox())
    };
    if let (true, Some(node)) = (gone, node) {
        node.text(close(&id, None));
    }
    outbox.abort(1011, "socket error");
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// End the session for `why`: the node hears `close {id}` with the reason,
/// and the operator the Close.
fn end(pair: &Pair, id: &SessionId, operator: &Outbox, why: (u16, &str)) {
    let (session, node) = {
        let mut state = pair.lock();
        (state.forget(id), state.node_outbox())
    };
    if let (Some(_), Some(node)) = (session, node) {
        node.text(close(id, Some(why.1)));
    }
    operator.close(why.0, why.1);
}

/// One frame of the operator's payload, to the node with the session's id.
/// The node is the receiver of each session, so the role waits for room in
/// its queue rather than lose a session's bytes: a slow node slows its
/// operators, and no queue for it passes the bound.
async fn carry(pair: &Pair, id: &SessionId, payload: &[u8]) -> Result<(), (u16, &'static str)> {
    if payload.is_empty() {
        return Ok(());
    }
    if payload.len() > OPERATOR_PAYLOAD_MAX {
        return Err((1009, "frame byte cap"));
    }
    let node = {
        let mut guard = pair.lock();
        let state = &mut *guard;
        let Some(session) = state.sessions.get_mut(id) else {
            // The node or the role ended it already: its Close is on its way.
            return Ok(());
        };
        session.bytes += payload.len() as u64;
        if session.bytes > pair.session_bytes {
            return Err((1009, "session byte cap"));
        }
        state.node_outbox()
    };
    let Some(node) = node else { return Err((1011, "node offline")) };
    let frame = encode_node_frame(id, payload).map_err(|_| (1009, "frame byte cap"))?;
    // A node gone in the wait closes this session with its cause.
    let _ = node.binary_waiting(frame).await;
    Ok(())
}
