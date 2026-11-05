//! A published name's connection on the reverse road (T-649, GitHub #147):
//! the listener found a name of `relay serve --publish NAME=PAIR` in its
//! ClientHello, and the connection, each byte untouched from its first, is
//! one session of that pair's node. The role is the session's operator in its
//! own process: a pipe whose far end [`super::operator::leg`] carries as it
//! carries an operator's socket, as a carrier's leg is (T-595), so that the
//! node hears `open`, its `ready` comes before any byte, and each byte after
//! it keeps the order and the bounds of an operator's leg, one code for both.
//! The node's own TLS ends the visitor's; the role reads the name, which
//! routed it, and never a byte of the session, which it only carries.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::client::WRITE_TIMEOUT;
use podssh_ws::frame::{self, Frame};
use podssh_ws::server;
use podssh_ws::session::{close_code_and_reason, RelaySession};
use podssh_ws::SessionError;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;

use super::outbox::frames_of;
use super::{operator, OPEN_WAIT};
use crate::reverse::control::{self, NodeOutbound};
use crate::serve::published::Routed;
use crate::serve::{tokens, Config};

/// Each direction of the pipe of the session's leg.
const LEG_PIPE: usize = 256 * 1024;
/// The most bytes of the visitor in one frame to the node: under the
/// operator's cap of a frame, 64 KiB.
const CHUNK: usize = 16 * 1024;
/// The node's answer to the session's `open`: the contract's wait for a
/// `ready`, after which the leg closes `1013` itself, and a margin.
const ANSWER_WAIT: Duration = Duration::from_secs(OPEN_WAIT.as_secs() + 5);

/// Carry `visitor`, whose ClientHello `routed` names, to the node of its
/// pair, until either side ended; a line on the role's stdout at its start
/// and its end names the visitor's address and the name, never a byte.
pub async fn carry(mut visitor: TcpStream, routed: Routed, cfg: Arc<Config>) {
    let from = visitor.peer_addr().map(|at| at.ip().to_string()).unwrap_or_else(|_| "a visitor".into());
    let shown = match routed.acme {
        true => format!("a CA's validation of {}", routed.name),
        false => routed.name.clone(),
    };
    // A pair that ended, or none of that name: no TLS of the role's answers
    // for a name that it publishes, so the connection closes.
    let now = tokens::now_ms();
    let pair = cfg.pairs.named(&routed.pair).filter(|pair| !pair.lock().ended && pair.expires_ms() > now);
    let Some(pair) = pair.filter(|_| !cfg.pairs.stopping()) else {
        let why = format!("its pair {} is not one of this relay's, or ended, or the relay stops", routed.pair);
        return cfg.event(&format!("publish {shown} from {from}: {why}; the connection closes"));
    };
    // A TLS record goes on at once, as the visitor's own socket sends it.
    let _ = visitor.set_nodelay(true);
    let (near, far) = tokio::io::duplex(LEG_PIPE);
    tokio::spawn(operator::leg(Arc::new(server::session(far, Vec::new(), None)), pair, cfg.clone()));
    let leg = Arc::new(RelaySession::new(near, Vec::new(), None, WRITE_TIMEOUT).naming("a published name's leg"));
    let (mut frames, reader) = frames_of(leg.clone());
    let started = Instant::now();
    match tokio::time::timeout(ANSWER_WAIT, answered(&mut frames)).await {
        Ok(Ok(())) => cfg.event(&format!("publish {shown} from {from}: to the node of {}", routed.pair)),
        Ok(Err(why)) => {
            reader.abort();
            return cfg.event(&format!("publish {shown} from {from}: {why}; the connection closes"));
        }
        Err(_) => {
            reader.abort();
            let _ = leg.send_close(1000, "").await;
            let why = format!("the node did not answer within {} s", ANSWER_WAIT.as_secs());
            return cfg.event(&format!("publish {shown} from {from}: {why}; the connection closes"));
        }
    }
    let ended = pump(&mut visitor, &leg, &mut frames, cfg.limits.half_closed).await;
    reader.abort();
    let _ = leg.send_close(1000, "").await;
    let _ = visitor.shutdown().await;
    let (up, down, why) = ended;
    let secs = started.elapsed().as_secs();
    cfg.event(&format!("publish {shown} from {from} ended after {secs} s, {up} bytes up and {down} down: {why}"));
}

/// The node's answer to the session's `open`: `Ok` at its `ready`, which
/// the leg sends before any byte of the session; else the words of the
/// node's refusal, or of the leg's end.
async fn answered(frames: &mut Receiver<Result<Frame, SessionError>>) -> Result<(), String> {
    loop {
        match frames.recv().await {
            Some(Ok(f)) if f.opcode == frame::OPCODE_TEXT => match control::parse_operator_control(&f.payload) {
                Ok(NodeOutbound::Ready { .. }) => return Ok(()),
                Ok(NodeOutbound::Reject { reason, .. }) => {
                    return Err(format!("the node refused it: {}", podssh_ws::text::one_line(&reason)))
                }
                Ok(NodeOutbound::Close { .. }) => return Err("the node closed it".into()),
                // Not a frame of the contract's: the Close that follows says why.
                Err(_) => {}
            },
            Some(Ok(f)) if f.opcode == frame::OPCODE_CLOSE => return Err(closed(&f.payload)),
            Some(Ok(_)) => {}
            _ => return Err("its leg ended".into()),
        }
    }
}

/// The words of the leg's Close: `node unavailable`, a halt of the pair's
/// owner, or the contract's other rows.
fn closed(payload: &[u8]) -> String {
    let (code, reason) = close_code_and_reason(payload);
    format!("the relay closed it ({} {})", code.unwrap_or(1005), podssh_ws::text::one_line(&reason))
}

/// Copy both ways between `visitor` and the session's `leg` until one side
/// ended: the visitor's bytes up as binary frames, the node's down as they
/// came. After the visitor's end of its input, the node's bytes still go to
/// it until the node ends the session or is silent for `half_closed`, as
/// the forward road keeps a target's (T-671). The bytes each way, and why it
/// ended.
async fn pump(
    visitor: &mut TcpStream,
    leg: &RelaySession<tokio::io::DuplexStream>,
    frames: &mut Receiver<Result<Frame, SessionError>>,
    half_closed: Duration,
) -> (u64, u64, String) {
    let (mut from, mut to) = visitor.split();
    let mut buf = vec![0u8; CHUNK];
    let (mut up, mut down) = (0u64, 0u64);
    // Since when the node was silent, once the visitor's input ended.
    let mut quiet: Option<Instant> = None;
    let why = loop {
        let silence = quiet.map(|since| since + half_closed);
        tokio::select! {
            read = from.read(&mut buf), if quiet.is_none() => match read {
                Ok(n) if n > 0 => {
                    if leg.send_binary(&buf[..n]).await.is_err() {
                        break "its leg ended".to_string();
                    }
                    up += n as u64;
                }
                // The visitor's input ended: the node may still answer.
                _ => quiet = Some(Instant::now()),
            },
            got = frames.recv() => match got {
                Some(Ok(f)) if f.opcode == frame::OPCODE_BINARY => {
                    if to.write_all(&f.payload).await.is_err() {
                        break "the visitor went away".to_string();
                    }
                    down += f.payload.len() as u64;
                    if quiet.is_some() {
                        quiet = Some(Instant::now());
                    }
                }
                Some(Ok(f)) if f.opcode == frame::OPCODE_CLOSE => break closed(&f.payload),
                // A `reject` or a `close` of the node: its Close follows.
                Some(Ok(_)) => {}
                _ => break "its leg ended".to_string(),
            },
            () = sleep_until(silence), if silence.is_some() => {
                break format!("the visitor's input ended, and the node was silent {} s", half_closed.as_secs());
            }
        }
    };
    (up, down, why)
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
