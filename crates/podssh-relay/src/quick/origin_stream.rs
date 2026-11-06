//! A request for an origin that takes its body as it comes (T-180,
//! [`Origin::streams`]): a funnel's TARGET, a web application, which may take
//! an upload of any size. The head goes first, with the visitor's length, or
//! in chunks where the visitor named none; the body follows as the edge
//! gives it, while the origin's answer is read beside it, so that an origin
//! that answers before the body's end (a refusal, a redirect) answers at
//! once. Over HTTP/2 ([`h2`]) and over QUIC ([`quic`]), the answer as
//! `origin_h2` and `origin_quic` give an answer.

use std::sync::Arc;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use http::StatusCode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, WriteHalf};
use tokio::task::JoinHandle;

use super::chunks;
use super::connect::ConnectRequest;
use super::origin::{self, Answer, Asked, BodyHead, Origin};

/// The body's length that the head of an HTTP/2 request names: none when
/// the edge ended the stream with the head, its `content-length`, else in
/// chunks.
pub fn length_h2(headers: &http::HeaderMap, recv: &RecvStream) -> BodyHead {
    if recv.is_end_stream() {
        return BodyHead::Length(0);
    }
    let named = headers.get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok());
    named.map_or(BodyHead::Chunked, BodyHead::Length)
}

/// The body's length of a request over QUIC, as cloudflared reads one: its
/// `Content-Length`, or in chunks the rest of the stream, else none. `None`
/// for a length that does not read.
pub fn length_quic(request: &ConnectRequest) -> Option<BodyHead> {
    match request.header("content-length") {
        Some(text) => text.trim().parse().map(BodyHead::Length).ok(),
        None if request.header("transfer-encoding").is_some() => Some(BodyHead::Chunked),
        None => Some(BodyHead::Length(0)),
    }
}

/// Serve an HTTP/2 request of the edge with `server`, its body streamed.
pub async fn h2(
    server: Arc<dyn Origin>,
    asked: Asked,
    length: BodyHead,
    mut recv: RecvStream,
    mut respond: SendResponse<Bytes>,
) {
    let Ok(head) = asked.head_with(length) else { return super::origin_h2::refuse(respond, StatusCode::BAD_REQUEST) };
    let visitor = origin::visitor_of(asked.headers.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    let (mut from_origin, to_origin) = tokio::io::split(server.connect(visitor));
    let chunked = length == BodyHead::Chunked;
    let up = tokio::spawn(async move {
        let mut to_origin = to_origin;
        if to_origin.write_all(&head).await.is_err() {
            return;
        }
        // Each chunk's window goes back once the origin took it, so a slow
        // origin slows the visitor.
        while let Some(Ok(chunk)) = recv.data().await {
            let taken = put(&mut to_origin, &chunk, chunked).await;
            let _ = recv.flow_control().release_capacity(chunk.len());
            if !taken {
                return;
            }
        }
        end(&mut to_origin, chunked).await;
    });
    let Some((answer, rest)) = answered(&mut from_origin, up).await else {
        return super::origin_h2::refuse(respond, StatusCode::BAD_GATEWAY);
    };
    let Some(reply) = super::origin_h2::edge_answer(&answer) else {
        return super::origin_h2::refuse(respond, StatusCode::BAD_GATEWAY);
    };
    let Ok(mut send) = respond.send_response(reply, false) else { return };
    super::origin_h2::body_to_edge(&mut send, rest, from_origin).await;
}

/// Serve a QUIC request of the edge with `server`, its body streamed from
/// `from_edge`.
pub async fn quic<R, W>(server: Arc<dyn Origin>, asked: Asked, length: BodyHead, from_edge: R, mut to_edge: W)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let Ok(head) = asked.head_with(length) else { return super::origin_quic::refuse(&mut to_edge, 400).await };
    let visitor = origin::visitor_of(asked.headers.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    let (mut from_origin, to_origin) = tokio::io::split(server.connect(visitor));
    let up = tokio::spawn(async move {
        let mut to_origin = to_origin;
        if to_origin.write_all(&head).await.is_err() {
            return;
        }
        let (chunked, mut left) = match length {
            BodyHead::Length(n) => (false, Some(n as u64)),
            BodyHead::Chunked => (true, None),
        };
        let mut from_edge = from_edge;
        let mut buf = vec![0u8; origin::PIPE];
        while left != Some(0) {
            let room = left.map_or(buf.len(), |n| n.min(buf.len() as u64) as usize);
            let n = match from_edge.read(&mut buf[..room]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            left = left.map(|l| l - n as u64);
            if !put(&mut to_origin, &buf[..n], chunked).await {
                return;
            }
        }
        end(&mut to_origin, chunked).await;
    });
    let Some((answer, rest)) = answered(&mut from_origin, up).await else {
        return super::origin_quic::refuse(&mut to_edge, 502).await;
    };
    if to_edge.write_all(&super::origin_quic::answer_frame(&answer)).await.is_err() {
        return;
    }
    super::origin_quic::body_to_edge(to_edge, rest, from_origin).await;
}

/// `data` to the origin, as one chunk where the body is chunked; whether the
/// origin took it.
async fn put(to_origin: &mut WriteHalf<DuplexStream>, data: &[u8], chunked: bool) -> bool {
    match chunked {
        true => to_origin.write_all(&chunks::encode(data)).await.is_ok(),
        false => to_origin.write_all(data).await.is_ok(),
    }
}

/// The end of the body: the last chunk where it is chunked. The origin's
/// side stays open for its answer.
async fn end(to_origin: &mut WriteHalf<DuplexStream>, chunked: bool) {
    if chunked {
        let _ = to_origin.write_all(chunks::LAST).await;
    }
    let _ = to_origin.flush().await;
}

/// The head of the origin's answer: with no bound while the body still goes
/// up (an upload takes as long as it takes), then within
/// [`origin::ANSWER_WAIT`]; `None` for no answer. The upload goes on beside
/// an early answer, until the edge's side ends.
async fn answered<R: AsyncRead + Unpin>(from_origin: &mut R, mut up: JoinHandle<()>) -> Option<(Answer, Vec<u8>)> {
    let reading = origin::read_answer(from_origin);
    tokio::pin!(reading);
    let read = tokio::select! {
        read = &mut reading => read,
        _ = &mut up => match tokio::time::timeout(origin::ANSWER_WAIT, &mut reading).await {
            Ok(read) => read,
            Err(_) => return None,
        },
    };
    read.ok()
}
