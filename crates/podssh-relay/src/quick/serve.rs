//! A quick tunnel's connection, served (T-300): podssh dialed the edge, and
//! the edge is the client of HTTP/2 on that connection, as it is for
//! cloudflared (`connection/http2.go`; measured, T-299: the edge sends the
//! client's preface). The edge's first request is the control stream, on
//! which podssh registers the connection; each later request with the
//! upgrade `websocket` is a visitor, whose WebSocket goes to `visit`; a push
//! of configuration gets cloudflared's answer and is kept nowhere (T-404);
//! any other request gets 404 with no body, as podssh serves nothing else.
//!
//! Nothing listens: the connection is the one that podssh dialed. The
//! WebSocket's frames pass the edge unchanged, so podssh is the WebSocket's
//! server here, and its frames go unmasked (RFC 6455, section 5.1).

use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{Request, Response, StatusCode};
use podssh_ws::frame::{self, Frame, Role};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use super::configuration;
use super::control::{Control, Event, Failure};
use super::goaway;
use super::headers::{self, Kind};
use super::register::{Registered, Registration};

/// The most streams at once: a quick tunnel takes 200 requests in flight.
const MAX_STREAMS: u32 = 256;
/// The buffer of each bridge between a stream and its user.
const PIPE: usize = 64 * 1024;
/// Each stream's window, and the connection's: as many as the streams, so
/// that streams whose users read slowly never hold the window of the
/// others, or of the control stream.
const STREAM_WINDOW: u32 = 64 * 1024;
const CONNECTION_WINDOW: u32 = MAX_STREAMS * STREAM_WINDOW;
/// How long the edge has for HTTP/2's handshake.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(30);
/// How often the node asks whether the edge is there (an HTTP/2 PING), and
/// how long its answer may take: an edge that answers none is gone, though
/// nothing closed the connection.
pub const PING_EVERY: Duration = Duration::from_secs(30);
pub const PONG_WAIT: Duration = Duration::from_secs(30);
/// How long the end waits for the edge to take the unregistration.
pub const UNREGISTER_WAIT: Duration = Duration::from_secs(5);
/// How long the streams still open may take, once the connection closes.
pub const CLOSE_GRACE: Duration = Duration::from_secs(2);
/// How long the visitors of a connection go on after the edge's GOAWAY,
/// while the node's next connection takes the new ones (T-402).
pub const DRAIN: Duration = Duration::from_secs(90);

/// What happens on the connection, as it happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The edge took the registration: where the connection landed.
    Registered { location: String },
    /// A visitor's WebSocket came.
    Visitor,
    /// The edge took the end of the connection.
    Unregistered,
    /// The edge sent GOAWAY: no new visitor comes on this connection, and
    /// those on it go on until they end, for [`DRAIN`] at most.
    GoingAway,
}

/// Why a connection ended before its end was asked for.
#[derive(Debug)]
pub enum Ended {
    /// HTTP/2 failed, or the edge closed the connection.
    Http2(h2::Error),
    /// The control stream failed.
    Control(Failure),
    /// The edge refused the registration: why, and whether to try again
    /// after `after`.
    Refused { cause: String, retry: bool, after: Duration },
    /// The edge closed the connection.
    Closed,
    /// The edge answered neither the handshake nor a PING in time.
    Silent,
    /// The edge sent GOAWAY: it opens no new stream on this connection.
    GoingAway,
    /// QUIC to the edge failed (T-301).
    Quic(String),
}

impl Ended {
    /// Whether the end may come of a change of cloudflared's protocol, which
    /// podssh speaks as one release: a refusal, or an answer of the edge
    /// that podssh does not read or that is an error (T-339).
    pub fn may_be_the_protocol(&self) -> bool {
        matches!(
            self,
            Ended::Refused { .. }
                | Ended::Control(Failure::Malformed(_) | Failure::Exception { .. } | Failure::Aborted(_))
        )
    }
}

impl std::fmt::Display for Ended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ended::Http2(e) => write!(f, "HTTP/2 to the edge failed: {e}"),
            Ended::Control(e) => write!(f, "{e}"),
            Ended::Refused { cause, .. } => write!(f, "the edge refused the connection: {cause}"),
            Ended::Closed => write!(f, "the edge closed the connection"),
            Ended::Silent => write!(f, "the edge stopped answering"),
            Ended::GoingAway => write!(f, "the edge takes no new visitor on this connection (GOAWAY)"),
            Ended::Quic(e) => write!(f, "QUIC to the edge failed: {e}"),
        }
    }
}

/// Serve the connection `io` to the edge: register it with `registration`,
/// give each visitor's WebSocket to `visit` as a stream of its bytes, and
/// say each step to `steps`. When `stop` ends, unregister, close and return
/// `Ok`; an end that comes first is an error.
pub async fn serve<IO, V, F>(
    io: IO,
    registration: &Registration<'_>,
    mut visit: V,
    steps: mpsc::UnboundedSender<Step>,
    stop: impl Future<Output = ()>,
) -> Result<(), Ended>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    V: FnMut(DuplexStream) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    tokio::pin!(stop);
    let (io, mut going) = goaway::watched(io);
    let handshake = h2::server::Builder::new()
        .max_concurrent_streams(MAX_STREAMS)
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .handshake::<_, Bytes>(io);
    let mut conn = tokio::select! {
        shaken = tokio::time::timeout(HANDSHAKE_WAIT, handshake) => match shaken {
            Ok(shaken) => shaken.map_err(Ended::Http2)?,
            Err(_) => return Err(Ended::Silent),
        },
        // Nothing was registered yet: nothing to undo.
        () = &mut stop => return Ok(()),
    };
    // The PING that waits for its answer, and when the next one goes.
    let mut pinger = conn.ping_pong();
    let (mut ping_at, mut pong_by) = (Some(Instant::now() + PING_EVERY), None::<Instant>);
    let (control, first) = Control::register(registration);
    let mut control = Some((control, first));
    // The control task's word: the registration's answer, then the end.
    let (said, mut heard) = mpsc::unbounded_channel::<Result<Event, Failure>>();
    let (unregister, asked) = mpsc::unbounded_channel::<()>();
    let mut asked = Some(asked);
    // Whether the end was asked for, and the deadline of its phase: the
    // unregistration, then the close.
    let (mut stopping, mut deadline) = (false, None);
    // Whether the connection closes, and when its drain ends after a GOAWAY.
    let (mut closing, mut draining) = (false, None::<Instant>);
    loop {
        tokio::select! {
            accepted = conn.accept() => match accepted {
                Some(Ok((request, respond))) => match headers::kind(|name| header(&request, name)) {
                    Kind::Control => match (control.take(), asked.take()) {
                        (Some((control, first)), Some(asked)) => {
                            let said = said.clone();
                            let (recv, send) = (request.into_body(), respond_200(respond, &[])?);
                            tokio::spawn(run_control(control, first, recv, send, said, asked));
                        }
                        _ => refuse(respond, StatusCode::BAD_REQUEST),
                    },
                    Kind::WebSocket => {
                        let key = header(&request, "sec-websocket-key").unwrap_or_default().to_string();
                        let answer = headers::websocket_answer(&key);
                        let pairs = [(headers::RESPONSE_HEADERS, answer.as_str()), (headers::RESPONSE_META, headers::META_ORIGIN)];
                        // A visitor that the edge reset before the answer
                        // ends with its stream, not the connection.
                        if let Ok(send) = respond_200(respond, &pairs) {
                            let _ = steps.send(Step::Visitor);
                            tokio::spawn(visit(websocket(request.into_body(), send)));
                        }
                    }
                    Kind::Configuration => {
                        tokio::spawn(answer_push(request.into_body(), respond));
                    }
                    Kind::Http | Kind::Tcp => refuse(respond, StatusCode::NOT_FOUND),
                },
                // The end was asked for: the edge's close, or a pipe that
                // breaks under it, is that end.
                Some(Err(_)) | None if stopping => return Ok(()),
                // The edge's close after its GOAWAY is the drain's end.
                Some(Err(_)) | None if draining.is_some() => return Err(Ended::GoingAway),
                Some(Err(e)) => return Err(Ended::Http2(e)),
                None => return Err(Ended::Closed),
            },
            Some(event) = heard.recv() => match event {
                Ok(Event::Registered(Registered::Details { location, .. })) => {
                    let _ = steps.send(Step::Registered { location });
                }
                Ok(Event::Registered(Registered::Refused { cause, retry, after })) => {
                    return Err(Ended::Refused { cause, retry, after });
                }
                Ok(Event::Unregistered) => {
                    let _ = steps.send(Step::Unregistered);
                    close(&mut conn, &mut closing, &mut deadline);
                }
                // A control stream that fails in the end: close anyway.
                Err(_) if stopping => close(&mut conn, &mut closing, &mut deadline),
                // The edge that went away may end it first: the drain goes on.
                Err(_) if draining.is_some() => {}
                Err(e) => return Err(Ended::Control(e)),
            },
            () = &mut stop, if !stopping => {
                stopping = true;
                // No control stream yet, or one that ended: nothing to
                // unregister.
                if asked.is_some() || unregister.send(()).is_err() {
                    close(&mut conn, &mut closing, &mut deadline);
                } else {
                    deadline = Some(tokio::time::Instant::now() + UNREGISTER_WAIT);
                }
            },
            () = sleep_until(ping_at), if ping_at.is_some() && pinger.is_some() => {
                ping_at = None;
                if pinger.as_mut().is_some_and(|p| p.send_ping(h2::Ping::opaque()).is_ok()) {
                    pong_by = Some(Instant::now() + PONG_WAIT);
                } else if !stopping {
                    return Err(Ended::Silent);
                }
            },
            pong = pong(&mut pinger), if pong_by.is_some() => match pong {
                Ok(()) => (pong_by, ping_at) = (None, Some(Instant::now() + PING_EVERY)),
                Err(_) if stopping => pong_by = None,
                Err(e) => return Err(Ended::Http2(e)),
            },
            () = sleep_until(pong_by), if pong_by.is_some() => {
                pong_by = None;
                if !stopping {
                    return Err(Ended::Silent);
                }
            },
            // Once the edge went away, the node's next connection takes the
            // new visitors, and those here go on for the drain; a session cut
            // at its end resumes there (T-402).
            Ok(_) = going.wait_for(|went| *went), if !stopping && draining.is_none() => {
                let _ = steps.send(Step::GoingAway);
                draining = Some(Instant::now() + DRAIN);
            },
            () = sleep_until(draining), if draining.is_some() && !stopping => return Err(Ended::GoingAway),
            () = sleep_until(deadline), if deadline.is_some() => {
                // The edge did not take the end in time, or streams stay
                // open past the grace: close, then end.
                if closing {
                    return Ok(());
                }
                close(&mut conn, &mut closing, &mut deadline);
            },
        }
    }
}

/// Close the connection: a GOAWAY, and the grace of the streams still open.
fn close<IO: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut h2::server::Connection<IO, Bytes>,
    closing: &mut bool,
    deadline: &mut Option<tokio::time::Instant>,
) {
    if !*closing {
        *closing = true;
        conn.graceful_shutdown();
        *deadline = Some(tokio::time::Instant::now() + CLOSE_GRACE);
    }
}

/// Until the edge answers the PING that waits; for ever with none.
async fn pong(pinger: &mut Option<h2::PingPong>) -> Result<(), h2::Error> {
    match pinger {
        Some(pinger) => std::future::poll_fn(|cx| pinger.poll_pong(cx)).await.map(|_| ()),
        None => std::future::pending().await,
    }
}

async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

fn header<'a>(request: &'a Request<RecvStream>, name: &str) -> Option<&'a str> {
    request.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Answer 200 with `pairs`, the body to follow.
fn respond_200(mut respond: SendResponse<Bytes>, pairs: &[(&str, &str)]) -> Result<SendStream<Bytes>, Ended> {
    let mut answer = Response::builder().status(StatusCode::OK);
    for (name, value) in pairs {
        answer = answer.header(*name, *value);
    }
    let answer = answer.body(()).expect("a valid answer");
    respond.send_response(answer, false).map_err(Ended::Http2)
}

/// Answer `status` with no body.
fn refuse(mut respond: SendResponse<Bytes>, status: StatusCode) {
    let answer = Response::builder().status(status).body(()).expect("a valid answer");
    let _ = respond.send_response(answer, true);
}

/// A push of configuration: its body, within its limits, answered as
/// cloudflared answers it, and nothing of it kept (`configuration`); a body
/// that does not read gets 502 from the connector, as cloudflared's does.
async fn answer_push(mut body: RecvStream, mut respond: SendResponse<Bytes>) {
    let mut push = Vec::new();
    let read = async {
        while let Some(chunk) = body.data().await {
            let chunk = chunk.ok()?;
            let _ = body.flow_control().release_capacity(chunk.len());
            if push.len() + chunk.len() > configuration::MAX_PUSH {
                return None;
            }
            push.extend_from_slice(&chunk);
        }
        Some(())
    };
    let read = tokio::time::timeout(configuration::PUSH_WAIT, read).await.ok().flatten();
    let Some(answer) = read.and_then(|()| configuration::answer(&push)) else {
        let failed =
            Response::builder().status(StatusCode::BAD_GATEWAY).header(headers::RESPONSE_META, headers::META_CONNECTOR);
        let _ = respond.send_response(failed.body(()).expect("a valid answer"), true);
        return;
    };
    if let Ok(mut send) = respond_200(respond, &[]) {
        if send_all(&mut send, answer.as_bytes()).await.is_ok() {
            let _ = send.send_data(Bytes::new(), true);
        }
    }
}

/// The control stream: the registration's bytes out, the edge's in, each
/// event to `said`; at the word of `asked`, the end.
async fn run_control(
    mut control: Control,
    first: Vec<u8>,
    mut recv: RecvStream,
    mut send: SendStream<Bytes>,
    said: mpsc::UnboundedSender<Result<Event, Failure>>,
    mut asked: mpsc::UnboundedReceiver<()>,
) {
    if send_all(&mut send, &first).await.is_err() {
        let _ = said.send(Err(Failure::Ended));
        return;
    }
    loop {
        tokio::select! {
            chunk = recv.data() => {
                // The edge ended or reset the stream: the connection is no
                // longer registered, and the node connects again.
                let Some(Ok(chunk)) = chunk else {
                    let _ = said.send(Err(Failure::Ended));
                    return;
                };
                let _ = recv.flow_control().release_capacity(chunk.len());
                match control.feed(&chunk) {
                    Ok((events, out)) => {
                        if !out.is_empty() && send_all(&mut send, &out).await.is_err() {
                            let _ = said.send(Err(Failure::Ended));
                            return;
                        }
                        let done = events.contains(&Event::Unregistered);
                        for event in events {
                            let _ = said.send(Ok(event));
                        }
                        // Unregistered: this side of the stream ends.
                        if done {
                            let _ = send.send_data(Bytes::new(), true);
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
                if send_all(&mut send, &bytes).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Send `bytes` on `send` as the edge's window lets them go.
async fn send_all(send: &mut SendStream<Bytes>, mut bytes: &[u8]) -> Result<(), h2::Error> {
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len());
        let room = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(room)) => room,
            Some(Err(e)) => return Err(e),
            None => return Err(h2::Error::from(h2::Reason::CANCEL)),
        };
        let take = room.min(bytes.len());
        if take == 0 {
            continue;
        }
        send.send_data(Bytes::copy_from_slice(&bytes[..take]), false)?;
        bytes = &bytes[take..];
    }
    Ok(())
}

/// A visitor's WebSocket on a stream: the bytes of its messages, both ways,
/// as one end of a pipe. Pings get their pongs; a close, or the end of the
/// stream, ends the pipe.
fn websocket(mut recv: RecvStream, mut send: SendStream<Bytes>) -> DuplexStream {
    let (user, ours) = tokio::io::duplex(PIPE);
    let (mut from_user, mut to_user) = tokio::io::split(ours);
    // The latest ping's payload only: RFC 6455, section 5.5.3, lets an end
    // answer the most recent of the pings that wait, so a visitor that
    // pings while the writer waits for the edge's window holds one payload.
    let (pongs, mut pongs_due) = watch::channel::<Option<Vec<u8>>>(None);
    // The visitor's frames, masked as a client writes them, to the user.
    tokio::spawn(async move {
        let mut inbox = Vec::new();
        while let Some(Ok(chunk)) = recv.data().await {
            let _ = recv.flow_control().release_capacity(chunk.len());
            inbox.extend_from_slice(&chunk);
            loop {
                match frame::decode(&inbox, Role::Client) {
                    Ok(Some((frame, used))) => {
                        inbox.drain(..used);
                        match frame.opcode {
                            // A continuation, a text or a binary message.
                            0x0..=0x2 => {
                                if to_user.write_all(&frame.payload).await.is_err() {
                                    return;
                                }
                            }
                            0x9 => {
                                pongs.send_replace(Some(frame.payload));
                            }
                            0x8 => {
                                let _ = to_user.shutdown().await;
                                return;
                            }
                            _ => {}
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
        }
        let _ = to_user.shutdown().await;
    });
    // The user's bytes, as binary messages unmasked, to the visitor.
    tokio::spawn(async move {
        let mut buf = vec![0u8; PIPE];
        loop {
            tokio::select! {
                n = from_user.read(&mut buf) => {
                    let n = match n {
                        Ok(0) | Err(_) => {
                            let close = Frame { fin: true, opcode: 0x8, payload: 1000u16.to_be_bytes().to_vec() };
                            let _ = send_all(&mut send, &frame::encode(&close, Role::Server, [0; 4])).await;
                            let _ = send.send_data(Bytes::new(), true);
                            return;
                        }
                        Ok(n) => n,
                    };
                    let message = Frame { fin: true, opcode: 0x2, payload: buf[..n].to_vec() };
                    if send_all(&mut send, &frame::encode(&message, Role::Server, [0; 4])).await.is_err() {
                        return;
                    }
                }
                Ok(()) = pongs_due.changed() => {
                    let Some(payload) = pongs_due.borrow_and_update().clone() else { continue };
                    let pong = Frame { fin: true, opcode: 0xA, payload };
                    if send_all(&mut send, &frame::encode(&pong, Role::Server, [0; 4])).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    user
}
