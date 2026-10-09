//! The operator of a pair: one WebSocket to `/v1/connect/<name>`, for one
//! session to the node's local side. The relay readies it with a text
//! `ready`; after that, binary frames carry the bytes with no framing, and
//! the operator never sends a text frame (`docs/reverse.md`, "Operator").

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::client::{ConnectError, Endpoint, WsClientConfig};
use podssh_ws::frame;
use podssh_ws::session::{close_code_and_reason, RelaySession};
use podssh_ws::{ProxyChoice, SessionError, Trust};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::control::{self, NodeOutbound};
use super::framing::legs::chunk_for_bare;
use super::wire::{self, Socket, Wire};
use crate::relay::Relay;

/// The most input kept before `ready`; more fails the session.
pub const QUEUE_BEFORE_READY: usize = 1024 * 1024;
/// The largest payload of an operator frame (spec line 184).
const FRAME_PAYLOAD: usize = 65536;

/// The limits of one operator session.
#[derive(Debug, Clone, Copy)]
pub struct OperatorLimits {
    /// How long to wait for `ready`: more than the relay's 15 s, after which
    /// it ends a session that the node did not answer.
    pub ready_limit: Duration,
    /// How long to wait for the relay's answer to the Close sent at the end
    /// of the input, so the last bytes arrive.
    pub close_limit: Duration,
    /// The relay answers a Ping on the operator's socket (measured
    /// 2026-10-09): ping every so often, and give up after so many silent
    /// intervals.
    pub ping_every: Duration,
    pub pings_allowed: u32,
}

impl Default for OperatorLimits {
    fn default() -> Self {
        OperatorLimits {
            ready_limit: Duration::from_secs(20),
            close_limit: Duration::from_secs(10),
            ping_every: podssh_ws::LIVENESS_EVERY,
            pings_allowed: podssh_ws::LIVENESS_ALLOWED,
        }
    }
}

/// Where an operator connects, and how.
pub struct OperatorConfig<'a> {
    pub relay: &'a Relay,
    pub name: &'a str,
    pub connect_token: &'a str,
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// Bound on connecting.
    pub timeout: Duration,
    pub limits: OperatorLimits,
    /// TLS, except in the tests of an embedder.
    pub wire: Wire,
}

/// How an operator session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The node never readied the session; `reason` is a `reject`'s whole
    /// reason when one came. Always a failure.
    NeverReady { code: Option<u16>, reason: String },
    /// The relay ended the session after `ready`. `1000` is a success; each
    /// other code is a failure that names the code and the reason.
    Ended { code: u16, reason: String },
    /// The input ended, and the relay answered the Close.
    LocalEnd,
}

impl Outcome {
    /// Whether the session did what it was opened for.
    pub fn is_success(&self) -> bool {
        matches!(self, Outcome::Ended { code: 1000, .. } | Outcome::LocalEnd)
    }
}

/// Connect to the pair's name and carry `io` until the session ends.
pub async fn run<IO>(config: &OperatorConfig<'_>, io: IO) -> Result<Outcome, ConnectError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    Ok(match wire::open(config.wire, &socket_config(config)?, config.connect_token).await? {
        Socket::Tls(session) => exchange(session, io, config.limits).await,
        #[cfg(feature = "plain-ws")]
        Socket::Plain(session) => exchange(session, io, config.limits).await,
    })
}

/// Connect, then carry `io` in a task of its own: a connection that fails is
/// known before anything uses `io` (an SSH client over it, for one), and the
/// task gives the outcome. Inside a tokio runtime.
pub async fn start<IO>(config: &OperatorConfig<'_>, io: IO) -> Result<JoinHandle<Outcome>, ConnectError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let limits = config.limits;
    Ok(match wire::open(config.wire, &socket_config(config)?, config.connect_token).await? {
        Socket::Tls(session) => tokio::spawn(exchange(session, io, limits)),
        #[cfg(feature = "plain-ws")]
        Socket::Plain(session) => tokio::spawn(exchange(session, io, limits)),
    })
}

/// The socket to `/v1/connect/<name>`.
fn socket_config(config: &OperatorConfig<'_>) -> Result<WsClientConfig, ConnectError> {
    let path = crate::relay::operator_path(config.name).map_err(ConnectError::Config)?;
    Ok(WsClientConfig {
        endpoint: Endpoint { host: config.relay.host.clone(), port: config.relay.port, path },
        trust: config.trust.clone(),
        server_name: config.relay.host.clone(),
        timeout: config.timeout,
        // The relay sends no keepalives on a reverse socket; pings find a
        // dead one instead of an idle read limit.
        idle_timeout: None,
        proxy: config.proxy.clone(),
    })
}

/// Carry `io` over a connected operator socket (any stream, for tests). At
/// each end, the write side of `io` is shut, so its reader sees the end, and
/// the tasks that read stop.
pub async fn exchange<S, IO>(session: RelaySession<S>, io: IO, limits: OperatorLimits) -> Outcome
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let session = Arc::new(session);
    let (local_read, mut local_write) = tokio::io::split(io);
    let (frames, frames_task) = frames_of(session.clone());
    let (input, input_task) = input_of(local_read);
    let outcome = carry(&session, frames, input, &mut local_write, limits).await;
    input_task.abort();
    frames_task.abort();
    let _ = local_write.shutdown().await;
    outcome
}

/// The session from the first frame to its end.
async fn carry<S, IO>(
    session: &RelaySession<S>,
    mut frames: mpsc::Receiver<Result<frame::Frame, SessionError>>,
    mut input: mpsc::Receiver<Vec<u8>>,
    local_write: &mut WriteHalf<IO>,
    limits: OperatorLimits,
) -> Outcome
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    IO: AsyncRead + AsyncWrite,
{
    let liveness = session.watch_liveness(limits.ping_every, limits.pings_allowed);
    tokio::pin!(liveness);

    // Before `ready`: keep the input, send nothing.
    let mut queue: Vec<u8> = Vec::new();
    let mut input_open = true;
    let mut rejected: Option<String> = None;
    let deadline = Instant::now() + limits.ready_limit;
    loop {
        tokio::select! {
            frame = frames.recv() => match frame {
                Some(Ok(f)) if f.opcode == frame::OPCODE_TEXT => match control::parse_operator_control(&f.payload) {
                    Ok(NodeOutbound::Ready { .. }) => break,
                    Ok(NodeOutbound::Reject { reason, .. }) => rejected = Some(reason),
                    Ok(NodeOutbound::Close { reason, .. }) => rejected = rejected.or(reason),
                    Err(_) => {}
                },
                Some(Ok(f)) if f.opcode == frame::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    return Outcome::NeverReady { code, reason: rejected.unwrap_or(reason) };
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Outcome::NeverReady { code: None, reason: rejected.unwrap_or_else(|| e.to_string()) },
                None => return Outcome::NeverReady { code: None, reason: rejected.unwrap_or_else(|| "the relay ended the session".into()) },
            },
            bytes = input.recv(), if input_open => match bytes {
                Some(bytes) => {
                    queue.extend_from_slice(&bytes);
                    if queue.len() > QUEUE_BEFORE_READY {
                        let _ = session.send_close(1000, "").await;
                        return Outcome::NeverReady {
                            code: None,
                            reason: format!("more than {QUEUE_BEFORE_READY} bytes of input came before the node was ready"),
                        };
                    }
                }
                None => input_open = false,
            },
            () = tokio::time::sleep_until(deadline) => {
                let _ = session.send_close(1000, "").await;
                return Outcome::NeverReady {
                    code: None,
                    reason: format!("the node did not answer within {} s", limits.ready_limit.as_secs()),
                };
            }
            dead = &mut liveness => return Outcome::NeverReady { code: None, reason: dead.to_string() },
        }
    }

    // `ready`: the queue first, in order, then both ways.
    if send_bytes(session, &queue).await.is_err() {
        return Outcome::Ended { code: 1006, reason: "the relay connection broke".into() };
    }
    drop(queue);
    let mut closing: Option<Instant> = None;
    if !input_open {
        let _ = session.send_close(1000, "").await;
        closing = Some(Instant::now() + limits.close_limit);
    }
    let mut text_reason: Option<String> = None;
    loop {
        let close_deadline = closing.unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
        tokio::select! {
            frame = frames.recv() => match frame {
                Some(Ok(f)) if f.opcode == frame::OPCODE_BINARY => {
                    // An empty frame carries nothing.
                    if !f.payload.is_empty() && local_write.write_all(&f.payload).await.is_err() {
                        // The local side is gone: there is nobody to give bytes to.
                        let _ = session.send_close(1000, "").await;
                        closing.get_or_insert(Instant::now() + limits.close_limit);
                    }
                }
                Some(Ok(f)) if f.opcode == frame::OPCODE_TEXT => {
                    if let Ok(NodeOutbound::Close { reason: Some(reason), .. }) = control::parse_operator_control(&f.payload) {
                        text_reason = Some(reason);
                    }
                }
                Some(Ok(f)) if f.opcode == frame::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    // The answer to this side's Close echoes 1000; another code
                    // crossed it, and names a failure.
                    if closing.is_some() && matches!(code, None | Some(1000)) {
                        return Outcome::LocalEnd;
                    }
                    return Outcome::Ended { code: code.unwrap_or(1005), reason: text_reason.unwrap_or(reason) };
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Outcome::Ended { code: 1006, reason: e.to_string() },
                None => return Outcome::Ended { code: 1006, reason: "the relay ended the session with no Close".into() },
            },
            bytes = input.recv(), if closing.is_none() => match bytes {
                Some(bytes) => {
                    if send_bytes(session, &bytes).await.is_err() {
                        return Outcome::Ended { code: 1006, reason: "the relay connection broke".into() };
                    }
                }
                None => {
                    let _ = session.send_close(1000, "").await;
                    closing = Some(Instant::now() + limits.close_limit);
                }
            },
            () = tokio::time::sleep_until(close_deadline), if closing.is_some() => return Outcome::LocalEnd,
            dead = &mut liveness => return Outcome::Ended { code: 1006, reason: dead.to_string() },
        }
    }
}

/// Send `bytes` in frames of at most 64 KiB, bare: the operator adds no id.
async fn send_bytes<S>(session: &RelaySession<S>, bytes: &[u8]) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    if bytes.is_empty() {
        return Ok(());
    }
    let Ok(chunks) = chunk_for_bare(bytes, FRAME_PAYLOAD) else { return Ok(()) };
    for chunk in chunks {
        session.send_binary(&chunk).await?;
    }
    Ok(())
}

/// The socket's frames, read by their own task, so that waiting for one
/// never stands in the way of the input.
fn frames_of<S>(session: Arc<RelaySession<S>>) -> (mpsc::Receiver<Result<frame::Frame, SessionError>>, JoinHandle<()>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (tx, rx) = mpsc::channel(32);
    let task = tokio::spawn(async move {
        loop {
            let frame = session.read_frame().await;
            let last = !matches!(&frame, Ok(f) if f.opcode != frame::OPCODE_CLOSE);
            if tx.send(frame).await.is_err() || last {
                return;
            }
        }
    });
    (rx, task)
}

/// The local input, read by its own task; `None` at its end.
fn input_of<IO>(mut local: ReadHalf<IO>) -> (mpsc::Receiver<Vec<u8>>, JoinHandle<()>)
where
    IO: AsyncRead + Send + 'static,
{
    let (tx, rx) = mpsc::channel(32);
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; FRAME_PAYLOAD];
        loop {
            match local.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    (rx, task)
}
