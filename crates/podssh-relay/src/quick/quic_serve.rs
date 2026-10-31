//! A quick tunnel's connection over QUIC, served (T-301): the control stream
//! is the first stream, which the node opens (`connection/quic_connection.go`),
//! and on it the node registers as over HTTP/2. Each stream that the edge
//! opens is a request, whose first bytes say what it is (`connect.rs`): a
//! visitor's WebSocket goes to `visit`; any other request gets 404; an RPC
//! stream of the edge is refused, as podssh takes no configuration from it.

use std::future::Future;
use std::io::Cursor;
use std::time::Duration;

use noq::{Connection, ConnectionError, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::capnp;
use super::connect::{self, Kind, Stream};
use super::control::{Control, Event, Failure};
use super::register::Registered;
use super::register::Registration;
use super::serve::{Ended, Step, CLOSE_GRACE, UNREGISTER_WAIT};
use super::visitor;

/// The most bytes of a request's message, its headers with room.
const MAX_REQUEST: usize = 64 * 1024;
/// How long the edge has for a request's first bytes.
const REQUEST_WAIT: Duration = Duration::from_secs(10);

/// Serve `connection` to the edge: register it with `registration`, give
/// each visitor's WebSocket to `visit`, and say each step to `steps`. When
/// `stop` ends, unregister, close and return `Ok`; an end that comes first is
/// an error, as over HTTP/2.
pub async fn serve<V, F>(
    connection: Connection,
    registration: &Registration<'_>,
    mut visit: V,
    steps: mpsc::UnboundedSender<Step>,
    stop: impl Future<Output = ()>,
) -> Result<(), Ended>
where
    V: FnMut(DuplexStream) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    tokio::pin!(stop);
    let (send, recv) = tokio::select! {
        opened = connection.open_bi() => opened.map_err(ended)?,
        () = &mut stop => return Ok(()),
    };
    let (control, first) = Control::register(registration);
    let (said, mut heard) = mpsc::unbounded_channel::<Result<Event, Failure>>();
    let (unregister, asked) = mpsc::unbounded_channel::<()>();
    tokio::spawn(run_control(control, first, recv, send, said, asked));
    // The visitors, from the tasks that read each stream's request.
    let (arrived, mut visitors) = mpsc::unbounded_channel::<DuplexStream>();
    // Whether the end was asked for, and the deadline of its phase: the
    // unregistration, then the grace of the streams still open.
    let (mut stopping, mut closing, mut deadline) = (false, false, None::<Instant>);
    loop {
        tokio::select! {
            accepted = connection.accept_bi() => match accepted {
                Ok((send, recv)) => {
                    tokio::spawn(request(send, recv, arrived.clone()));
                }
                Err(_) if stopping => return Ok(()),
                Err(e) => return Err(ended(e)),
            },
            Some(stream) = visitors.recv() => {
                let _ = steps.send(Step::Visitor);
                tokio::spawn(visit(stream));
            },
            Some(event) = heard.recv() => match event {
                Ok(Event::Registered(Registered::Details { location, .. })) => {
                    let _ = steps.send(Step::Registered { location });
                }
                Ok(Event::Registered(Registered::Refused { cause, retry, after })) => {
                    connection.close(VarInt::from_u32(0), b"");
                    return Err(Ended::Refused { cause, retry, after });
                }
                Ok(Event::Unregistered) => {
                    let _ = steps.send(Step::Unregistered);
                    (closing, deadline) = (true, Some(Instant::now() + CLOSE_GRACE));
                }
                // A control stream that fails in the end: close anyway.
                Err(_) if stopping => (closing, deadline) = (true, Some(Instant::now() + CLOSE_GRACE)),
                // The connection's own end, a close or a silence, can reach
                // the control stream before `accept_bi`: its reason is then
                // the end, not the stream's.
                Err(_) if connection.close_reason().is_some() => {
                    return Err(connection.close_reason().map(ended).unwrap_or(Ended::Closed));
                }
                Err(e) => {
                    connection.close(VarInt::from_u32(0), b"");
                    return Err(Ended::Control(e));
                }
            },
            () = &mut stop, if !stopping => {
                stopping = true;
                deadline = Some(Instant::now() + UNREGISTER_WAIT);
                // A control stream that ended has nothing to unregister.
                if unregister.send(()).is_err() {
                    (closing, deadline) = (true, Some(Instant::now() + CLOSE_GRACE));
                }
            },
            () = sleep_until(deadline), if deadline.is_some() => {
                if !closing {
                    // The edge did not take the end in time: the grace, then the close.
                    (closing, deadline) = (true, Some(Instant::now() + CLOSE_GRACE));
                    continue;
                }
                connection.close(VarInt::from_u32(0), b"");
                // The edge's own end of the registration, with no end asked
                // for: the node connects again.
                return if stopping { Ok(()) } else { Err(Ended::Closed) };
            },
        }
    }
}

/// Why a connection ended, in the words of HTTP/2's ends where they match.
fn ended(e: ConnectionError) -> Ended {
    match e {
        ConnectionError::TimedOut => Ended::Silent,
        ConnectionError::ApplicationClosed(_) | ConnectionError::ConnectionClosed(_) | ConnectionError::Reset => {
            Ended::Closed
        }
        other => Ended::Quic(other.to_string()),
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// The control stream: the registration's bytes out, the edge's in, each
/// event to `said`; at the word of `asked`, the end.
async fn run_control(
    mut control: Control,
    first: Vec<u8>,
    mut recv: RecvStream,
    mut send: SendStream,
    said: mpsc::UnboundedSender<Result<Event, Failure>>,
    mut asked: mpsc::UnboundedReceiver<()>,
) {
    if send.write_all(&first).await.is_err() {
        let _ = said.send(Err(Failure::Ended));
        return;
    }
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            read = recv.read(&mut chunk) => {
                // The edge ended or reset the stream: the connection is no
                // longer registered.
                let Ok(Some(n)) = read else {
                    let _ = said.send(Err(Failure::Ended));
                    return;
                };
                match control.feed(&chunk[..n]) {
                    Ok((events, out)) => {
                        if !out.is_empty() && send.write_all(&out).await.is_err() {
                            let _ = said.send(Err(Failure::Ended));
                            return;
                        }
                        let done = events.contains(&Event::Unregistered);
                        for event in events {
                            let _ = said.send(Ok(event));
                        }
                        if done {
                            let _ = send.finish();
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = said.send(Err(e));
                        return;
                    }
                }
            }
            Some(()) = asked.recv() => {
                let bytes = control.unregister();
                if send.write_all(&bytes).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// One stream of the edge: its preamble and its request, then the answer. A
/// visitor's WebSocket goes to `visitors`, with the bytes that came after
/// its request.
async fn request(mut send: SendStream, mut recv: RecvStream, visitors: mpsc::UnboundedSender<DuplexStream>) {
    let read = tokio::time::timeout(REQUEST_WAIT, read_request(&mut recv)).await;
    let Ok(Some((request, rest))) = read else {
        // An RPC stream, another signature, or a request that does not read.
        let _ = recv.stop(VarInt::from_u32(0));
        let _ = send.reset(VarInt::from_u32(0));
        return;
    };
    let key = request.header("sec-websocket-key").map(str::to_string);
    match (request.kind, key) {
        (Kind::WebSocket, Some(key)) => {
            if send.write_all(&connect::preamble()).await.is_err()
                || send.write_all(&connect::websocket_answer(&key)).await.is_err()
            {
                return;
            }
            let from_edge = AsyncReadExt::chain(Cursor::new(rest), recv);
            let _ = visitors.send(visitor::websocket(from_edge, send));
        }
        _ => {
            let _ = send.write_all(&connect::preamble()).await;
            let _ = send.write_all(&connect::refusal()).await;
            let _ = send.finish();
            let _ = recv.stop(VarInt::from_u32(0));
        }
    }
}

/// The preamble of a data stream, then its request: the request, and the
/// bytes read past it. Nothing for any other stream.
async fn read_request(recv: &mut RecvStream) -> Option<(connect::ConnectRequest, Vec<u8>)> {
    let mut preamble = [0u8; connect::PREAMBLE];
    recv.read_exact(&mut preamble).await.ok()?;
    let signature: [u8; 6] = preamble[..6].try_into().ok()?;
    if connect::stream(&signature) != Stream::Data || preamble[6..] != connect::VERSION {
        return None;
    }
    let (mut message, mut chunk) = (Vec::new(), vec![0u8; 4096]);
    let len = loop {
        if let Some(len) = capnp::frame_len(&message).ok()? {
            if len > MAX_REQUEST {
                return None;
            }
            if message.len() >= len {
                break len;
            }
        }
        if message.len() > MAX_REQUEST {
            return None;
        }
        let n = recv.read(&mut chunk).await.ok()??;
        message.extend_from_slice(&chunk[..n]);
    };
    let request = connect::read_request(&message[..len]).ok()?;
    Some((request, message[len..].to_vec()))
}
