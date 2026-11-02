//! XHTTP's packet-up (Xray-core, `transport/internet/splithttp/`): a GET of
//! `PATH/SESSION` whose answer streams the target's bytes, and for each
//! chunk up a POST of `PATH/SESSION/SEQ` with a body of that chunk, numbered
//! from 0 (`upload_queue.go`, `nextSeq`). The first POST is VLESS's request.
//! POSTs go one at a time, each after the 200 of the last, so they come in
//! order and the server's queue of 30 (`GetNormalizedScMaxBufferedPosts`)
//! never fills; what waits meanwhile goes in the next, up to the link's
//! largest POST (1,000,000 bytes by default, `GetNormalizedScMaxEachPostBytes`).
//! Plain requests with whole bodies: the mode that passes a proxy or a front
//! end that refuses the upgrade and holds a streamed body. It has no
//! half-close: the end of this side's bytes ends the POSTs, and the session
//! ends with the GET.

use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use tokio::io::{AsyncReadExt, DuplexStream};

use super::link::Server;
use super::split::{Failed, Halves};
use super::xhttp::{answer, at, request, send, send_all, session_id};
use super::VlessError;
use crate::via::Stream;

/// The pipe in memory to the task of the POSTs: a write waits while a POST
/// of this much waits for its 200.
const PIPE: usize = 1 << 20;

pub(super) async fn open(
    server: &Server,
    sender: SendRequest<Bytes>,
    first: Vec<u8>,
    limit: Duration,
) -> Result<Halves<Stream, DuplexStream>, VlessError> {
    let id = session_id()?;
    let get = request(server, http::Method::GET, &at(server, &id), false)?;
    let (down, closed) = send(&sender, get, true, limit).await?;
    let down = answer(down, limit, "the GET of packet-up").await?;
    let read = Stream::from_parts(closed, down.into_body());
    post(server, &sender, &id, 0, Bytes::from(first), limit).await?;
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let failed = Failed::default();
    tokio::spawn(uploads(server.clone(), sender, id, theirs, limit, failed.clone()));
    Ok(Halves { read, write: ours, failed })
}

/// One POST of packet-up, its body whole, and its 200.
async fn post(
    server: &Server,
    sender: &SendRequest<Bytes>,
    id: &str,
    seq: u64,
    body: Bytes,
    limit: Duration,
) -> Result<(), VlessError> {
    let mut post = request(server, http::Method::POST, &at(server, &format!("{id}/{seq}")), false)?;
    post.headers_mut().insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
    let (answered, mut up) = send(sender, post, false, limit).await?;
    send_all(&mut up, body, true).await.map_err(VlessError::Carry)?;
    answer(answered, limit, "a POST of packet-up").await.map(drop)
}

/// The POSTs after the first, until this side's bytes end or one fails;
/// a failure is kept, so that the next write says it.
async fn uploads(
    server: Server,
    sender: SendRequest<Bytes>,
    id: String,
    mut from: DuplexStream,
    limit: Duration,
    failed: Failed,
) {
    let mut buf = vec![0u8; server.extra.max_post];
    for seq in 1u64.. {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if let Err(e) = post(&server, &sender, &id, seq, Bytes::copy_from_slice(&buf[..n]), limit).await {
            let shown = server.shown();
            *failed.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.line(&shown, "the target"));
            return;
        }
    }
}
