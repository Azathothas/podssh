//! XHTTP over HTTP/1.1, on two connections (Q67): where the server, or a
//! front end that ends TLS on the way, refused HTTP/2. HTTP/1.1 carries one
//! request at a time on a connection, so the download and the upload of a
//! session need one each, as Xray-core's client opens them: the GET of
//! `PATH/SESSION` on the first, its body the target's bytes as they come;
//! the upload on a second connection to the same server.
//!
//! - packet-up: a POST of `PATH/SESSION/SEQ` for each chunk up, with its
//!   length, each after the answer of the last, on the kept connection; a
//!   server that closes it after an answer gets a new one for the next.
//! - stream-up: one POST of `PATH/SESSION`, its body in chunks as they come.
//! - stream-one stays refused: Go's server reads a request's whole body
//!   before it answers on HTTP/1.1, and the session's body never ends.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::h1::{self, Again, Conn, Framing};
use super::link::{Mode, Server};
use super::split::{Failed, Halves};
use super::xhttp::{at, session_id};
use super::{Dial, VlessError};
use crate::via::Duplex;

/// The pipe in memory to each task: a write waits while this much waits.
const PIPE: usize = 1 << 20;

/// Why stream-one does not go on HTTP/1.1.
pub(super) const STREAM_ONE: &str = "it did not choose HTTP/2 by ALPN (h2), and stream-one cannot go over HTTP/1.1: \
                                     Go's server reads a request's whole body before it answers, and a session's \
                                     body never ends; use mode=packet-up or stream-up, serve h2, or type=ws";

/// The session in `mode` over HTTP/1.1, `first` the first connection, which
/// the server already took: the stream and what carried it.
pub(super) async fn open(
    server: &Server,
    mode: Mode,
    first: Vec<u8>,
    dial: &Dial<'_>,
    conn: Conn,
) -> Result<(Box<dyn Duplex>, String), VlessError> {
    let again = Again::of(server, dial);
    let how = format!("XHTTP {} over HTTP/1.1 on two connections", mode.name());
    let stream: Box<dyn Duplex> = match mode {
        Mode::StreamOne => return Err(VlessError::Http1(STREAM_ONE.into())),
        Mode::StreamUp => Box::new(stream_up(again, conn, first).await?),
        Mode::PacketUp | Mode::Auto => Box::new(packet_up(again, conn, first).await?),
    };
    Ok((stream, how))
}

/// A request's head on `conn`, within the bound.
async fn send_head(conn: &mut Conn, head: &[u8], limit: Duration, what: &str) -> Result<(), VlessError> {
    let write = async {
        conn.get_mut().write_all(head).await?;
        conn.get_mut().flush().await
    };
    tokio::time::timeout(limit, write)
        .await
        .map_err(|_| VlessError::Carry(format!("{what}: not sent within {} s", limit.as_secs())))?
        .map_err(|e| VlessError::Carry(format!("{what}: HTTP/1.1: {e}")))
}

/// The GET of `PATH/SESSION` on `conn`, and its 200: the target's bytes, as
/// they come, from the other end of the pipe that this returns.
async fn download(again: &Again, mut conn: Conn, id: &str, what: &'static str) -> Result<DuplexStream, VlessError> {
    let (server, limit) = (&again.server, again.timeout);
    let head = h1::head(server, http::Method::GET, &at(server, id), Framing::None)?;
    send_head(&mut conn, &head, limit, what).await?;
    let answer = h1::answer(&mut conn, limit, what).await?;
    let (ours, mut theirs) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        // The end of the GET's body, or of its connection, ends the read side.
        let _ = h1::body(&mut conn, answer.body, &mut theirs).await;
        let _ = theirs.shutdown().await;
    });
    Ok(ours)
}

async fn packet_up(again: Again, conn: Conn, first: Vec<u8>) -> Result<Halves<DuplexStream, DuplexStream>, VlessError> {
    let id = session_id()?;
    let read = download(&again, conn, &id, "the GET of packet-up").await?;
    // The second connection: the upload's, as HTTP/1.1 carries one request
    // at a time and the GET's lasts as long as the session.
    let mut up = Some(again.connect().await?);
    post(&again, &mut up, &id, 0, &first).await?;
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let failed = Failed::default();
    tokio::spawn(uploads(again, up, id, theirs, failed.clone()));
    Ok(Halves { read, write: ours, failed })
}

/// One POST of packet-up with its length, and its 200, its body read so
/// that the next request starts clean; a closed connection is dialed again
/// once for it, as a server may close a kept one at any answer.
async fn post(again: &Again, up: &mut Option<Conn>, id: &str, seq: u64, body: &[u8]) -> Result<(), VlessError> {
    let server = &again.server;
    let path = at(server, &format!("{id}/{seq}"));
    let head = h1::head(server, http::Method::POST, &path, Framing::Length(body.len() as u64))?;
    let what = "a POST of packet-up";
    for attempt in 0..2 {
        let mut conn = match up.take() {
            Some(conn) => conn,
            None => again.connect().await?,
        };
        let sent = async {
            send_head(&mut conn, &head, again.timeout, what).await?;
            tokio::time::timeout(again.timeout, async {
                conn.get_mut().write_all(body).await?;
                conn.get_mut().flush().await
            })
            .await
            .map_err(|_| VlessError::Carry(format!("{what}: its body not sent within {} s", again.timeout.as_secs())))?
            .map_err(|e| VlessError::Carry(format!("{what}: HTTP/1.1: {e}")))?;
            let answer = h1::answer(&mut conn, again.timeout, what).await?;
            h1::body(&mut conn, answer.body, &mut tokio::io::sink())
                .await
                .map_err(|e| VlessError::Carry(format!("{what}: HTTP/1.1: {e}")))?;
            Ok::<_, VlessError>(answer.close)
        };
        match sent.await {
            Ok(close) => {
                if !close {
                    *up = Some(conn);
                }
                return Ok(());
            }
            // A kept connection that the server had closed: the next try
            // dials a new one. A refusal is the server's word, not tried again.
            Err(VlessError::Carry(_)) if attempt == 0 => continue,
            Err(e) => return Err(e),
        }
    }
    Err(VlessError::Carry(format!("{what}: no connection took it")))
}

/// The POSTs after the first, until this side's bytes end or one fails; a
/// failure is kept, so that the next write says it.
async fn uploads(again: Again, mut up: Option<Conn>, id: String, mut from: DuplexStream, failed: Failed) {
    let mut buf = vec![0u8; again.server.extra.max_post];
    for seq in 1u64.. {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if let Err(e) = post(&again, &mut up, &id, seq, &buf[..n]).await {
            let shown = again.server.shown();
            *failed.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.line(&shown, "the target"));
            return;
        }
    }
}

async fn stream_up(again: Again, conn: Conn, first: Vec<u8>) -> Result<Halves<DuplexStream, DuplexStream>, VlessError> {
    let id = session_id()?;
    let read = download(&again, conn, &id, "the GET of stream-up").await?;
    let mut up = again.connect().await?;
    let what = "the POST of stream-up";
    let head = h1::head(&again.server, http::Method::POST, &at(&again.server, &id), Framing::Chunked)?;
    send_head(&mut up, &head, again.timeout, what).await?;
    h1::chunk(up.get_mut(), &first).await.map_err(|e| VlessError::Carry(format!("{what}: HTTP/1.1: {e}")))?;
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let failed = Failed::default();
    tokio::spawn(streamed(again, up, theirs, failed.clone()));
    Ok(Halves { read, write: ours, failed })
}

/// stream-up's body: each read of this side's bytes a chunk, flushed, and the
/// last chunk at their end; then the POST's answer, whose refusal is kept
/// for the next write. The server may answer before the body ends: the
/// answer is read only after it, as HTTP/1.1 reads in order.
async fn streamed(again: Again, mut up: Conn, mut from: DuplexStream, failed: Failed) {
    let what = "the POST of stream-up";
    let keep = |why: String| *failed.lock().unwrap_or_else(|p| p.into_inner()) = Some(why);
    let shown = again.server.shown();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => 0,
            Ok(n) => n,
        };
        if let Err(e) = h1::chunk(up.get_mut(), &buf[..n]).await {
            keep(VlessError::Carry(format!("{what}: HTTP/1.1: {e}")).line(&shown, "the target"));
            return;
        }
        if n == 0 {
            break;
        }
    }
    if let Err(e) = h1::answer(&mut up, again.timeout, what).await {
        keep(e.line(&shown, "the target"));
    }
}
