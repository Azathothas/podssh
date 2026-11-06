//! A request of the edge for the node's origin, over HTTP/2 (T-428): its
//! head and its body to the origin as HTTP/1.1 ([`super::origin`]), and the
//! origin's answer back as cloudflared answers over HTTP/2
//! (`connection/http2.go` at 2026.10.6): a 101 as 200, as HTTP/2 has no 101,
//! the origin's headers serialized in [`headers::RESPONSE_HEADERS`] with
//! `content-length` beside them, then the body, or after a 101 the
//! WebSocket's frames as they are, both ways. A request that the node cannot
//! give to the origin is answered by the node itself, as cloudflared's own
//! answers are ([`headers::META_CONNECTOR`]).

use std::sync::Arc;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

use super::h2_stream::send_all;
use super::headers;
use super::origin::{self, Answer, Asked, Origin};

/// Serve `request` of the edge with `server`, its answer on `respond`.
pub async fn serve(
    server: Arc<dyn Origin>,
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    websocket: bool,
) {
    let (parts, mut recv) = request.into_parts();
    let asked = asked(&parts, websocket);
    // A funnel's TARGET takes the body as it comes, of any size (T-180).
    if !websocket && server.streams() {
        let length = super::origin_stream::length_h2(&parts.headers, &recv);
        return super::origin_stream::h2(server, asked, length, recv, respond).await;
    }
    // The body of a request that is no upgrade comes whole before the origin
    // reads it, and the edge's end of the stream ends it.
    let body = match websocket {
        true => Vec::new(),
        false => match tokio::time::timeout(origin::BODY_WAIT, read_body(&mut recv)).await {
            Ok(Ok(body)) => body,
            Ok(Err(status)) => return refuse(respond, status),
            Err(_) => return refuse(respond, StatusCode::REQUEST_TIMEOUT),
        },
    };
    let Ok(head) = asked.head(body.len()) else { return refuse(respond, StatusCode::BAD_REQUEST) };
    let visitor = origin::visitor_of(asked.headers.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    let mut conn = server.connect(visitor);
    let answered = async {
        conn.write_all(&head).await.map_err(|e| e.to_string())?;
        conn.write_all(&body).await.map_err(|e| e.to_string())?;
        origin::read_answer(&mut conn).await
    };
    // An origin that gives no answer: 502, as cloudflared's for its origin.
    let Ok(Ok((answer, rest))) = tokio::time::timeout(origin::ANSWER_WAIT, answered).await else {
        return refuse(respond, StatusCode::BAD_GATEWAY);
    };
    let Some(reply) = edge_answer(&answer) else { return refuse(respond, StatusCode::BAD_GATEWAY) };
    // A visitor that the edge reset before the answer ends with its stream.
    let Ok(mut send) = respond.send_response(reply, false) else { return };
    let (from_origin, to_origin) = tokio::io::split(conn);
    if answer.switched() {
        both_ways(recv, send, rest, from_origin, to_origin).await;
    } else {
        drop(recv);
        body_to_edge(&mut send, rest, from_origin).await;
    }
}

/// The request as the origin takes it: the visitor's Host is HTTP/2's
/// authority, else its `host`.
fn asked(parts: &http::request::Parts, websocket: bool) -> Asked {
    let target = parts.uri.path_and_query().map_or("/", |p| p.as_str()).to_string();
    let named = parts.headers.get("host").and_then(|v| v.to_str().ok());
    let host = parts.uri.authority().map(|a| a.as_str()).or(named).unwrap_or_default().to_string();
    let fields = parts.headers.iter();
    let fields = fields.map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()));
    Asked { method: parts.method.as_str().to_string(), target, host, headers: fields.collect(), websocket }
}

/// The body of `recv`, [`origin::BODY_MAX`] at most; `Err` holds the status
/// that refuses it.
async fn read_body(recv: &mut RecvStream) -> Result<Vec<u8>, StatusCode> {
    let mut body = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        let _ = recv.flow_control().release_capacity(chunk.len());
        if body.len() + chunk.len() > origin::BODY_MAX {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The answer to the edge for the origin's `answer`; `None` for a status or
/// a length that HTTP/2 cannot carry.
pub(super) fn edge_answer(answer: &Answer) -> Option<Response<()>> {
    let status = if answer.switched() { 200 } else { answer.status };
    let mut reply = Response::builder()
        .status(StatusCode::from_u16(status).ok()?)
        .header(headers::RESPONSE_HEADERS, headers::serialize(&answer.passed()))
        .header(headers::RESPONSE_META, headers::META_ORIGIN);
    // The length means something to HTTP/2 too, so cloudflared sends it
    // beside the others.
    if let Some(length) = answer.length().filter(|_| !answer.switched()) {
        reply = reply.header("content-length", length);
    }
    reply.body(()).ok()
}

/// The node's own answer `status`, with no body.
pub(super) fn refuse(mut respond: SendResponse<Bytes>, status: StatusCode) {
    let answer = Response::builder().status(status).header(headers::RESPONSE_META, headers::META_CONNECTOR);
    let _ = respond.send_response(answer.body(()).expect("a valid answer"), true);
}

/// The origin's body to the edge, until the origin closes; an origin that
/// stalls past [`origin::ANSWER_WAIT`] resets the stream.
pub(super) async fn body_to_edge(send: &mut SendStream<Bytes>, rest: Vec<u8>, mut from_origin: ReadHalf<DuplexStream>) {
    if send_all(send, &rest).await.is_err() {
        return;
    }
    let mut buf = vec![0u8; origin::PIPE];
    loop {
        match tokio::time::timeout(origin::ANSWER_WAIT, from_origin.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if send_all(send, &buf[..n]).await.is_err() {
                    return;
                }
            }
            _ => return send.send_reset(h2::Reason::INTERNAL_ERROR),
        }
    }
    let _ = send.send_data(Bytes::new(), true);
}

/// After a 101: the visitor's frames to the origin, and the origin's to the
/// visitor, until the origin ends; once the visitor's side ended, the
/// origin's last frames have [`origin::END_WAIT`].
async fn both_ways(
    mut recv: RecvStream,
    mut send: SendStream<Bytes>,
    rest: Vec<u8>,
    mut from_origin: ReadHalf<DuplexStream>,
    mut to_origin: WriteHalf<DuplexStream>,
) {
    let up = async move {
        // Each chunk's window goes back once the origin took it, so a slow
        // origin slows the visitor.
        while let Some(Ok(chunk)) = recv.data().await {
            let taken = to_origin.write_all(&chunk).await.is_ok();
            let _ = recv.flow_control().release_capacity(chunk.len());
            if !taken {
                break;
            }
        }
        let _ = to_origin.shutdown().await;
    };
    let down = async move {
        if send_all(&mut send, &rest).await.is_err() {
            return;
        }
        let mut buf = vec![0u8; origin::PIPE];
        loop {
            match from_origin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send_all(&mut send, &buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    };
    tokio::pin!(up, down);
    tokio::select! {
        () = &mut down => {}
        () = &mut up => {
            let _ = tokio::time::timeout(origin::END_WAIT, down).await;
        }
    }
}
