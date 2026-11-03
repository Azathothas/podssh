//! A bridge (anomalyco/opentunnel:docs/protocol.md at v0.6.1, "Session"):
//! one WebSocket at `/api/tunnel/ID/connect` on the API's host, offering the
//! subprotocol `opentunnel`, through `HTTPS_PROXY` as the API is reached;
//! `attach` with the token and the node's routes at once, well within the
//! service's 10 s, and `attached` with the heartbeat and the idle bound, or
//! `attach_error`. Then each `open` of a route of the node's is a
//! [`Visitor`], given to the node; `end` and `reset` reach their connection;
//! a `ping` is answered; this end sends its own each `heartbeat_ms`, and
//! ends a bridge that sent nothing for `idle_timeout_ms`. The reader never
//! waits on the writer, so a service that stops reading for a while never
//! stops this end reading: control messages go ahead of the data frames.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::session::close_code_and_reason;
use podssh_ws::{frame, Frame, RelaySession, SessionError};
use tokio::sync::mpsc;

use super::api::Api;
use super::conn::{self, Held, Inbound, Outbox, Visitor};
use super::dial::BoxIo;
use super::wire::{self, codes, Down, Up};
use super::Service;

/// The bound of the upgrade, and of the answer to `attach`, each.
pub const ANSWER_LIMIT: Duration = Duration::from_secs(20);
/// The bound of each read: well past the service's heartbeat, which the
/// idle bound of `attached` checks first.
pub const READ_IDLE: Duration = Duration::from_secs(120);
/// The bound of each write: the service's own write bound is 30 s.
pub const WRITE_LIMIT: Duration = Duration::from_secs(30);
/// The data frames that wait for the writer: 2 MiB.
pub const DATA_QUEUE: usize = 64;
/// The heartbeat and the idle bound, at least, whatever `attached` says.
const MIN_HEARTBEAT: Duration = Duration::from_secs(1);
const MIN_IDLE: Duration = Duration::from_secs(5);

/// What `attached` said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attached {
    pub session: String,
    pub heartbeat: Duration,
    pub idle: Duration,
}

/// Why no bridge attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// The same on each try: the token, or a tunnel that the service does
    /// not know.
    Fatal(String),
    /// `cert_not_ready`, which the protocol calls final: a node whose
    /// certificate was ready tries again, after a long wait.
    NotReady(String),
    /// Worth another try, after a wait.
    Again(String),
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failed::Fatal(why) | Failed::NotReady(why) | Failed::Again(why) => f.write_str(why),
        }
    }
}

/// The upgrade request of the bridge of the tunnel `id`, with `key` as its
/// `Sec-WebSocket-Key`. No token: it goes in `attach`, inside the socket.
pub fn request(service: &Service, id: &str, key: &str) -> Vec<u8> {
    let mut out = String::with_capacity(256);
    out.push_str(&format!("GET /api/tunnel/{id}/connect HTTP/1.1\r\n"));
    out.push_str(&format!("Host: {}\r\n", service.authority()));
    out.push_str(&format!("User-Agent: podssh/{}\r\n", env!("CARGO_PKG_VERSION")));
    out.push_str("Upgrade: websocket\r\n");
    out.push_str("Connection: Upgrade\r\n");
    out.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    out.push_str("Sec-WebSocket-Version: 13\r\n");
    out.push_str(&format!("Sec-WebSocket-Protocol: {}\r\n", wire::SUBPROTOCOL));
    out.push_str("\r\n");
    out.into_bytes()
}

/// A bridge of the tunnel `id`, attached with `token` for `routes`.
pub async fn attach(
    api: &Api,
    id: &str,
    token: &str,
    routes: &[String],
) -> Result<(RelaySession<BoxIo>, Attached), Failed> {
    let service = api.service();
    let io = match tokio::time::timeout(ANSWER_LIMIT, (api.dial())(service)).await {
        Err(_) => return Err(Failed::Again(format!("{service}: no connection within {} s", ANSWER_LIMIT.as_secs()))),
        Ok(Err(why)) => return Err(Failed::Again(why)),
        Ok(Ok(io)) => io,
    };
    let key = podssh_ws::handshake::generate_key().map_err(|e| Failed::Again(e.to_string()))?;
    let asked = podssh_ws::client::upgrade_with(io, &request(service, id, &key), &key);
    let (io, pending) = match tokio::time::timeout(ANSWER_LIMIT, asked).await {
        Err(_) => return Err(Failed::Again(format!("{service} did not answer the bridge's upgrade"))),
        Ok(Err(podssh_ws::ConnectError::Refused { status: 404, .. })) => {
            return Err(Failed::Fatal(format!("{service} knows no tunnel {id} (HTTP 404)")));
        }
        Ok(Err(e)) => return Err(Failed::Again(format!("{service} refused the bridge's upgrade: {e}"))),
        Ok(Ok(upgraded)) => upgraded,
    };
    let session = RelaySession::new(io, pending, Some(READ_IDLE), WRITE_LIMIT).naming("OpenTunnel");
    let sent = session.send_text(&Up::Attach { token, routes }.text()).await;
    sent.map_err(|e| Failed::Again(format!("the attach of the bridge was not sent: {e}")))?;
    match tokio::time::timeout(ANSWER_LIMIT, answer(&session)).await {
        Err(_) => {
            Err(Failed::Again(format!("{service} did not answer the attach within {} s", ANSWER_LIMIT.as_secs())))
        }
        Ok(Ok(attached)) => Ok((session, attached)),
        Ok(Err(failed)) => Err(failed),
    }
}

/// The service's answer to `attach`.
async fn answer(session: &RelaySession<BoxIo>) -> Result<Attached, Failed> {
    loop {
        let f = session.read_frame().await.map_err(|e| Failed::Again(format!("the bridge, before its attach: {e}")))?;
        match f.opcode {
            frame::OPCODE_TEXT => match wire::decode(&String::from_utf8_lossy(&f.payload)) {
                Ok(Some(Down::Attached { session, heartbeat_ms, idle_timeout_ms, .. })) => {
                    let heartbeat = Duration::from_millis(heartbeat_ms).max(MIN_HEARTBEAT);
                    let idle = Duration::from_millis(idle_timeout_ms).max(MIN_IDLE);
                    return Ok(Attached { session, heartbeat, idle });
                }
                Ok(Some(Down::AttachError { code })) if code == codes::CERT_NOT_READY => {
                    return Err(Failed::NotReady(wire::attach_words(&code)));
                }
                Ok(Some(Down::AttachError { code })) if wire::fatal(&code) => {
                    return Err(Failed::Fatal(wire::attach_words(&code)));
                }
                Ok(Some(Down::AttachError { code })) => return Err(Failed::Again(wire::attach_words(&code))),
                _ => {}
            },
            frame::OPCODE_CLOSE => {
                let (code, reason) = close_code_and_reason(&f.payload);
                return Err(Failed::Again(wire::close_words(code, &reason)));
            }
            _ => {}
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Serve the bridge `session`, attached as `attached`, of the tunnel
/// `hostname` for `routes`, until it ends: each new connection of a route
/// of `routes` goes to `opened`. Why it ended.
pub async fn serve<F>(
    session: RelaySession<BoxIo>,
    attached: &Attached,
    hostname: &str,
    routes: &[String],
    opened: F,
) -> String
where
    F: Fn(Visitor) + Send + Sync,
{
    let session = Arc::new(session);
    let (outbox, mut outgoing) = Outbox::new(DATA_QUEUE);
    // The writer: control first.
    let mut writer = {
        let session = session.clone();
        tokio::spawn(async move {
            loop {
                let sent = tokio::select! {
                    biased;
                    Some(text) = outgoing.control.recv() => session.send_text(&text).await,
                    Some(frame) = outgoing.data.recv() => session.send_binary(&frame).await,
                    else => return String::new(),
                };
                if let Err(e) = sent {
                    return format!("sending on the bridge to OpenTunnel failed: {e}");
                }
            }
        })
    };
    // The reader, in a task of its own, so that no wait of this loop drops
    // a read half-way.
    let (frames, mut frames_rx) = mpsc::channel::<Result<Frame, SessionError>>(4);
    let reader = {
        let session = session.clone();
        tokio::spawn(async move {
            loop {
                let read = session.read_frame().await;
                let last = read.is_err();
                if frames.send(read).await.is_err() || last {
                    return;
                }
            }
        })
    };
    let (gone, mut gone_rx) = mpsc::unbounded_channel::<u32>();
    let mut conns: HashMap<u32, Held> = HashMap::new();
    let mut beat = tokio::time::interval(attached.heartbeat);
    beat.tick().await;
    let why = loop {
        tokio::select! {
            read = frames_rx.recv() => {
                let f = match read {
                    Some(Ok(f)) => f,
                    Some(Err(e)) => break format!("the bridge to OpenTunnel failed: {e}"),
                    None => break "the bridge to OpenTunnel ended".to_string(),
                };
                match f.opcode {
                    frame::OPCODE_BINARY => {
                        let Some((conn, payload)) = wire::split_frame(&f.payload) else { continue };
                        let Some(held) = conns.get(&conn) else { continue };
                        if !held.deliver(Inbound::Data(payload.to_vec())).await {
                            stalled(&mut conns, conn, &outbox);
                        }
                    }
                    frame::OPCODE_TEXT => {
                        let text = String::from_utf8_lossy(&f.payload);
                        // An invalid message is ignored, as an unknown one.
                        let Ok(Some(down)) = wire::decode(&text) else { continue };
                        match down {
                            Down::Open { conn, peer, sni, .. } => {
                                let route = wire::route_for_sni(&sni, hostname);
                                if conns.contains_key(&conn) {
                                    // A second `open` of a connection that is open is
                                    // the service's error: the first goes on.
                                } else if !route.as_ref().is_some_and(|route| routes.contains(route)) {
                                    outbox.control(&Up::Reset { conn, code: codes::UNKNOWN_ROUTE });
                                } else if conns.len() >= wire::MAX_CONNS as usize {
                                    outbox.control(&Up::Reset { conn, code: codes::TOO_MANY_CONNECTIONS });
                                } else {
                                    let (visitor, held) = conn::open(conn, peer, sni, outbox.clone(), gone.clone());
                                    conns.insert(conn, held);
                                    opened(visitor);
                                }
                            }
                            Down::End { conn } => {
                                if let Some(held) = conns.get(&conn) {
                                    if !held.deliver(Inbound::End).await {
                                        stalled(&mut conns, conn, &outbox);
                                    }
                                }
                            }
                            Down::Reset { conn, code } => {
                                if let Some(held) = conns.remove(&conn) {
                                    let code = podssh_ws::text::one_line(&code);
                                    held.reset(format!("OpenTunnel reset the connection ({code})"));
                                }
                            }
                            Down::Ping { time_sent } => {
                                outbox.control(&Up::Pong { time_sent });
                            }
                            Down::Drain { reason } => {
                                let reason = podssh_ws::text::one_line(&reason);
                                break format!("OpenTunnel drains the bridge ({reason})");
                            }
                            Down::Pong { .. } | Down::Attached { .. } | Down::AttachError { .. } => {}
                        }
                    }
                    frame::OPCODE_CLOSE => {
                        let (code, reason) = close_code_and_reason(&f.payload);
                        break wire::close_words(code, &reason);
                    }
                    _ => {}
                }
            }
            Some(conn) = gone_rx.recv() => {
                conns.remove(&conn);
            }
            _ = beat.tick() => {
                let silent = session.last_heard().elapsed();
                if silent > attached.idle {
                    break format!("nothing from OpenTunnel on the bridge for {} s", silent.as_secs());
                }
                outbox.control(&Up::Ping { time_sent: now_ms() });
            }
            ended = &mut writer => {
                break ended.unwrap_or_else(|e| format!("the bridge's writer ended: {e}"));
            }
        }
    };
    for (_, held) in conns.drain() {
        held.reset(format!("the bridge to OpenTunnel was lost: {why}"));
    }
    reader.abort();
    writer.abort();
    let _ = session.send_close(1000, "").await;
    why
}

/// Reset a connection whose reader did not take its bytes in time: it would
/// hold each connection of the bridge.
fn stalled(conns: &mut HashMap<u32, Held>, conn: u32, outbox: &Outbox) {
    if let Some(held) = conns.remove(&conn) {
        held.reset("the connection did not read for 5 s".into());
        outbox.control(&Up::Reset { conn, code: codes::UPSTREAM_IO_ERROR });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upgrade_asks_for_the_subprotocol_at_the_tunnel_s_path_and_names_no_token() {
        let text = String::from_utf8(request(&Service::hosted(), "abcdefghijkl", "dGhlIHNhbXBsZSBub25jZQ==")).unwrap();
        assert!(
            text.starts_with("GET /api/tunnel/abcdefghijkl/connect HTTP/1.1\r\nHost: opentunnel.xyz\r\n"),
            "{text}"
        );
        assert!(text.contains("\r\nSec-WebSocket-Protocol: opentunnel\r\n"));
        assert!(text.contains("\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(!text.to_ascii_lowercase().contains("authorization") && !text.contains("token"));
        assert!(text.ends_with("\r\n\r\n"));
    }
}
