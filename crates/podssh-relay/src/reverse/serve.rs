//! One node socket: the sessions on it, until the socket ends.
//!
//! One task, the writer, owns the write half and the state of each session,
//! so no frame goes out without its id, before its `ready`, or after its
//! `close` (`docs/reverse.md`, "Node"). The reader routes data by id to the
//! local side of each session, and never waits for one: a local side that
//! reads no more ends its own session. An opener task per `open` asks the
//! handler, and only its answer queues `ready` or `reject`. A role that
//! registers tokens of one leg says so in its `hello`, and the handler sends
//! its registrations through the writer too (T-615, `crate::e2e::legs`).
//! The sessions' bytes wait in a line each, a turn each (T-648, `super::fair`).

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::frame;
use podssh_ws::session::{close_code_and_reason, RelaySession};
use podssh_ws::SessionError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use super::closes::RelayClose;
use super::control::{self, NodeInbound, NodeLimits};
use super::fair::Fair;
use super::framing::legs::{chunk_for_node, decode_node_frame, CHUNK_BYTES};
use super::framing::SessionId;
use super::node::Handler;
use super::sessions::Sessions;

/// How one socket ended.
#[derive(Debug)]
pub enum End {
    /// The relay closed the socket, with its code and reason.
    Closed(RelayClose),
    /// The socket failed with no Close: a broken link, or unanswered pings.
    Failed(SessionError),
    /// The caller stopped the node: each session got `close`, the socket a
    /// Close 1000.
    Stopped,
}

/// What a node needs for one socket, and how long it connects again after
/// it lost one.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// How long the handler may take to open the local side: under the 15 s
    /// after which the relay ends the session itself.
    pub open_limit: Duration,
    /// How often to ping the relay, and how many silent intervals mean the
    /// socket is dead. The relay answers a Ping on a node socket (measured
    /// 2026-10-09).
    pub ping_every: Duration,
    pub pings_allowed: u32,
    /// How long a node that lost its socket connects again when the relay
    /// answers `409`: the relay can still hold the old socket, and the
    /// sessions that the resumable layer keeps wait as long (T-261).
    pub rejoin: Duration,
    /// How long a node connects again when the relay answers `409` at its
    /// first registration: the relay can still hold the socket of the node
    /// that ran just before this one, as at a restart (T-416). Zero exits at
    /// the first `409`.
    pub first_conflict: Duration,
}

/// The default of [`Settings::first_conflict`].
pub const FIRST_CONFLICT: Duration = Duration::from_secs(30);

impl Default for Settings {
    fn default() -> Self {
        Settings {
            open_limit: Duration::from_secs(10),
            ping_every: podssh_ws::LIVENESS_EVERY,
            pings_allowed: podssh_ws::LIVENESS_ALLOWED,
            rejoin: crate::session::resume::RESUME_DEADLINE,
            first_conflict: FIRST_CONFLICT,
        }
    }
}

/// A request to the writer, the only task that writes to the socket.
enum Out {
    Opened(SessionId),
    Ready(SessionId),
    Reject(SessionId, String),
    Data(SessionId, Vec<u8>),
    /// The relay closed the session.
    Closed(SessionId),
    /// The local side ended: the relay is told with `close {id}`.
    LocalEnd(SessionId),
    /// The local side reads no more: `close {id}`, with the reason.
    Stalled(SessionId),
    /// A text frame of the node's own: a token of one leg (T-615).
    Text(String),
    Stop,
}

/// Why a node ends a session whose local side reads no more.
const STALLED: &str = "the node's local side does not read";

/// The writer's two queues. Control goes first: a `ready`, a refusal, or
/// the relay's close of a session never waits behind megabytes of another
/// session's bytes, as the relay ends a session that the node does not
/// answer within 15 s, and a `ready` that comes later ends the whole socket
/// with `1003 unknown session id` (T-410); the relay's close drops the
/// session's queued bytes before they go out for an id that it forgot. A
/// session's bytes, and the `close` after its last ones, keep their order.
/// Data waits in a line for each session, a turn each (T-648): an
/// interactive session's echo waits for one read of each other session, not
/// for a bulk copy's backlog.
#[derive(Clone)]
struct Outbox {
    control: mpsc::Sender<Out>,
    data: Fair<SessionId, Out>,
}

/// The reads of a session's local side that may wait for the socket, and of
/// all its sessions: the one queue's 256 of before, shared out, so that a
/// node's memory stays as it was. A read is `CHUNK_BYTES` at most.
const SESSION_READS: usize = 4;
const SOCKET_READS: usize = 256;

impl Outbox {
    async fn send(&self, out: Out) -> Result<(), ()> {
        match out {
            Out::Data(id, _) => self.data.push(id, out, 1).await.map_err(|_| ()),
            // After the session's last bytes, with no wait for their room.
            Out::LocalEnd(id) => self.data.push_last(id, out).map_err(|_| ()),
            other => self.control.send(other).await.map_err(|_| ()),
        }
    }
}

/// The local side of a session: where its data goes, the bytes that wait for
/// it and how many may, and its two copies, which stop at once when it
/// stalls.
struct Route {
    data: mpsc::UnboundedSender<Vec<u8>>,
    waiting: Arc<AtomicUsize>,
    limit: usize,
    copies: [tokio::task::AbortHandle; 2],
}

/// The local side of each session that has one, by id.
type Routes = Arc<Mutex<HashMap<SessionId, Route>>>;

/// Serve the sessions of `session` until the socket ends or `stop` fires.
pub async fn serve<S, H, F>(session: RelaySession<S>, handler: Arc<H>, settings: Settings, stop: &mut F) -> End
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    H: Handler,
    F: Future<Output = ()> + Unpin,
{
    let session = Arc::new(session);
    let ((control, control_rx), data) = (mpsc::channel(1024), Fair::new(SESSION_READS, SOCKET_READS));
    let tx = Outbox { control, data: data.clone() };
    let mut writer = Writer(tokio::spawn(write(session.clone(), control_rx, data)));
    let routes: Routes = Arc::default();
    let opening = Arc::new(AtomicUsize::new(0));
    let mut limits = NodeLimits::conservative();
    let liveness = session.watch_liveness(settings.ping_every, settings.pings_allowed);
    tokio::pin!(liveness);
    let end = loop {
        let frame = tokio::select! {
            frame = session.read_frame() => frame,
            dead = &mut liveness => break End::Failed(dead),
            () = &mut *stop => {
                let _ = tx.send(Out::Stop).await;
                break End::Stopped;
            }
        };
        match frame {
            Ok(f) if f.opcode == frame::OPCODE_TEXT => match control::parse_inbound(&f.payload) {
                Ok(NodeInbound::Hello(hello)) => {
                    limits.apply(&hello);
                    // A role that registers tokens of one leg (T-615): the
                    // handler registers them on this socket from now on.
                    super::legs::heard(&hello);
                    if crate::e2e::legs::offered(&hello.extra) {
                        handler.attach(Some(frames(&tx)));
                    }
                }
                Ok(NodeInbound::Open { id }) => {
                    let Ok(id) = SessionId::parse(id.as_bytes()) else { continue };
                    let live = routes_len(&routes) + opening.load(Ordering::SeqCst);
                    if live >= limits.max_sessions as usize {
                        let reason = format!("the node has its {} sessions", limits.max_sessions);
                        let _ = tx.send(Out::Reject(id, reason)).await;
                        continue;
                    }
                    let _ = tx.send(Out::Opened(id)).await;
                    opening.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(open(
                        id,
                        handler.clone(),
                        settings.open_limit,
                        tx.clone(),
                        routes.clone(),
                        opening.clone(),
                    ));
                }
                Ok(NodeInbound::Close { id, .. }) => {
                    let Ok(id) = SessionId::parse(id.as_bytes()) else { continue };
                    // Dropping the route ends the local writer, which shuts the
                    // local side; its late bytes find no session and are dropped.
                    routes.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                    let _ = tx.send(Out::Closed(id)).await;
                }
                // The role took a token of one leg for an operator (T-615).
                Ok(NodeInbound::Spent { digest }) => handler.spent(&digest),
                // Not a message that a node answers.
                Ok(NodeInbound::Unknown) | Err(_) => {}
            },
            Ok(f) if f.opcode == frame::OPCODE_BINARY => {
                let Ok((id, payload)) = decode_node_frame(&f.payload) else { continue };
                // Data for no live session (a late frame of a closed one) is
                // dropped; the socket and the other sessions go on.
                if offer(&routes, id, payload) {
                    let _ = tx.send(Out::Stalled(id)).await;
                }
            }
            Ok(f) if f.opcode == frame::OPCODE_CLOSE => {
                let (code, reason) = close_code_and_reason(&f.payload);
                break End::Closed(RelayClose { code: code.unwrap_or(1005), reason, clean: true });
            }
            Ok(_) => {}
            Err(e) => break End::Failed(e),
        }
    };
    // The tokens of one leg wait for the next socket (T-615).
    handler.attach(None);
    routes.lock().unwrap_or_else(|e| e.into_inner()).clear();
    // No session's bytes join the queue now; a sender that waits for room
    // hears it, as it heard the end of the one queue before.
    tx.data.shut();
    drop(tx);
    // A stop's last frames (each session's `close`, the Close) go out
    // first. A socket that the relay closed, or that broke, takes nothing
    // more, so the node goes on at once (T-255).
    if matches!(end, End::Stopped) {
        let _ = tokio::time::timeout(Duration::from_secs(5), &mut writer.0).await;
    }
    end
}

/// The writer's task, which ends with `serve`: a `serve` that is dropped,
/// as its task's abort drops it, takes the socket with it. The writer holds
/// the socket, and lived on while a session's tasks held the outbox, so the
/// far side never saw the node go (T-601).
struct Writer(tokio::task::JoinHandle<Result<(), SessionError>>);

impl Drop for Writer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The text frames of the handler's registrations, from a caller that holds
/// a lock and cannot wait (T-615): a frame that finds the control queue full
/// is dropped, and a leg that needed it takes the pair's token.
fn frames(tx: &Outbox) -> crate::e2e::legs::Frames {
    let control = tx.control.clone();
    Arc::new(move |text: String| {
        let _ = control.try_send(Out::Text(text));
    })
}

fn routes_len(routes: &Routes) -> usize {
    routes.lock().unwrap_or_else(|e| e.into_inner()).len()
}

/// Give a frame's payload to its session without waiting. A queue that holds
/// its handler's bytes already means that the local side reads no more;
/// waiting for it would stop every session of the socket, as the relay has
/// no flow control for one session. So that session ends here: true when it
/// did.
fn offer(routes: &Routes, id: SessionId, payload: &[u8]) -> bool {
    let mut routes = routes.lock().unwrap_or_else(|e| e.into_inner());
    let Some(route) = routes.get(&id) else { return false };
    if route.waiting.load(Ordering::SeqCst) + payload.len() > route.limit {
        if let Some(route) = routes.remove(&id) {
            for copy in route.copies {
                copy.abort();
            }
        }
        return true;
    }
    route.waiting.fetch_add(payload.len(), Ordering::SeqCst);
    // Sent; or the local writer is gone, and the session's own end tells the
    // relay.
    let _ = route.data.send(payload.to_vec());
    false
}

/// Open the local side of `id`, and only then queue `ready`; on a refusal or
/// after `limit`, `reject` with the reason. Then copy between the local side
/// and the socket until either ends.
async fn open<H: Handler>(
    id: SessionId,
    handler: Arc<H>,
    limit: Duration,
    tx: Outbox,
    routes: Routes,
    opening: Arc<AtomicUsize>,
) {
    let opened = tokio::time::timeout(limit, handler.open(id)).await;
    let stream = match opened {
        Ok(Ok(stream)) => stream,
        Ok(Err(reason)) => {
            opening.fetch_sub(1, Ordering::SeqCst);
            let _ = tx.send(Out::Reject(id, reason)).await;
            return;
        }
        Err(_) => {
            opening.fetch_sub(1, Ordering::SeqCst);
            let reason = format!("the local side did not open within {} s", limit.as_secs());
            let _ = tx.send(Out::Reject(id, reason)).await;
            return;
        }
    };
    let (mut local_read, mut local_write) = tokio::io::split(stream);
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (waiting, limit) = (Arc::new(AtomicUsize::new(0)), handler.queue_bytes());
    let to_local = tokio::spawn({
        let waiting = waiting.clone();
        async move {
            while let Some(bytes) = in_rx.recv().await {
                if local_write.write_all(&bytes).await.is_err() {
                    break;
                }
                // Written: the bytes wait no more.
                waiting.fetch_sub(bytes.len(), Ordering::SeqCst);
            }
            let _ = local_write.shutdown().await;
        }
    });
    // The local reader starts once `ready` is queued: the writer drops data
    // of a session that is not readied.
    let (go, readied) = oneshot::channel::<()>();
    let from_local = tokio::spawn({
        let (tx, routes) = (tx.clone(), routes.clone());
        async move {
            if readied.await.is_err() {
                return;
            }
            let mut buf = vec![0u8; CHUNK_BYTES];
            loop {
                match local_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(Out::Data(id, buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                }
            }
            routes.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            let _ = tx.send(Out::LocalEnd(id)).await;
        }
    });
    // The route exists before `ready`, so the first bytes after it find it.
    let route = Route { data: in_tx, waiting, limit, copies: [to_local.abort_handle(), from_local.abort_handle()] };
    routes.lock().unwrap_or_else(|e| e.into_inner()).insert(id, route);
    opening.fetch_sub(1, Ordering::SeqCst);
    let _ = tx.send(Out::Ready(id)).await;
    let _ = go.send(());
}

/// The writer: the one task that writes to the socket. It owns the state of
/// each session, so a frame for an id that is not readied, or is closed,
/// never goes out: it is dropped here.
async fn write<S>(
    session: Arc<RelaySession<S>>,
    mut control: mpsc::Receiver<Out>,
    data: Fair<SessionId, Out>,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let mut sessions = Sessions::new();
    loop {
        // Control first (`Outbox`), then one session's turn; the loop ends
        // once both queues closed. A read keeps its room until it went out.
        let (out, _room) = tokio::select! {
            biased;
            Some(out) = control.recv() => (out, None),
            Some(turn) = data.next() => (turn.piece, Some(turn.slot)),
            else => break,
        };
        match out {
            Out::Opened(id) => sessions.opened(id),
            Out::Ready(id) => {
                if sessions.may_send_ready(&id).is_ok() {
                    if let Some(text) = json(control::ready(&id)) {
                        session.send_text(&text).await?;
                        sessions.readied(id);
                    }
                }
            }
            Out::Reject(id, reason) => {
                // A refusal over the session limit answers an id the writer
                // was never told of; the relay waits for an answer to it.
                if let Some(text) = json(control::reject(&id, &reason)) {
                    session.send_text(&text).await?;
                }
                sessions.closed(&id);
            }
            Out::Data(id, bytes) => {
                if sessions.may_send_data(&id).is_err() {
                    continue;
                }
                let Ok(frames) = chunk_for_node(&id, &bytes) else { continue };
                for frame in frames {
                    session.send_binary(&frame).await?;
                }
            }
            Out::Closed(id) => {
                sessions.closed(&id);
                // Its queued bytes are for an id that the relay forgot.
                data.drop_line(&id);
            }
            Out::LocalEnd(id) => {
                if sessions.state(&id).is_some() {
                    if let Some(text) = json(control::close(&id, None)) {
                        session.send_text(&text).await?;
                    }
                    sessions.closed(&id);
                }
            }
            Out::Stalled(id) => {
                if sessions.state(&id).is_some() {
                    if let Some(text) = json(control::close(&id, Some(STALLED))) {
                        session.send_text(&text).await?;
                    }
                    sessions.closed(&id);
                }
                data.drop_line(&id);
            }
            Out::Text(text) => session.send_text(&text).await?,
            Out::Stop => {
                let live: Vec<SessionId> = sessions.live().map(|(id, _)| *id).collect();
                for id in live {
                    if let Some(text) = json(control::close(&id, Some("the node is stopping"))) {
                        let _ = session.send_text(&text).await;
                    }
                }
                let _ = session.send_close(1000, "").await;
                return Ok(());
            }
        }
    }
    Ok(())
}

/// A control message as the text of a frame, or `None` when the codec could
/// not build it: nothing goes out then, because a frame that the relay
/// refuses closes the whole socket.
fn json(built: Result<Vec<u8>, control::ControlError>) -> Option<String> {
    built.ok().and_then(|bytes| String::from_utf8(bytes).ok())
}
