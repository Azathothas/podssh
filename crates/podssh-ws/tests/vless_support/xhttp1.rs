//! The XHTTP stand-in of HTTP/1.1 (T-456), as Xray-core's `hub.go` routes
//! the same requests when its server speaks HTTP/1.1: the GET of
//! `PATH/SESSION` holds its connection and streams the download in chunks;
//! a POST of `PATH/SESSION/SEQ` with its length is a packet, answered with an
//! empty 200 on a kept connection; a POST of `PATH/SESSION` in chunks is
//! stream-up's upload; a POST to the path with no session (stream-one) is
//! refused, as Go reads a whole body first. After `CLOSE_AFTER` packets a
//! connection is closed with `Connection: close`, as a server may close a kept
//! one, so that the client must dial again. Each connection is counted.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use super::xhttp::{padding_of, upsert, Sessions};
use super::{dial, parse_request, Seen};

/// The packets that a kept connection takes before the stand-in closes it.
pub const CLOSE_AFTER: usize = 3;

/// A request's line and head: method, path, and each field by its lower name.
async fn head<R: AsyncRead + Unpin>(io: &mut BufReader<R>) -> Option<(String, String, HashMap<String, String>)> {
    let mut first = String::new();
    if io.read_line(&mut first).await.ok()? == 0 {
        return None;
    }
    let mut words = first.split_whitespace();
    let (method, path) = (words.next()?.to_string(), words.next()?.to_string());
    let mut fields = HashMap::new();
    loop {
        let mut line = String::new();
        if io.read_line(&mut line).await.ok()? == 0 {
            return None;
        }
        let line = line.trim_end();
        if line.is_empty() {
            return Some((method, path, fields));
        }
        if let Some((name, value)) = line.split_once(':') {
            fields.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
}

async fn answer<W: AsyncWrite + Unpin>(io: &mut W, code: u16, close: bool) -> bool {
    let close = if close { "Connection: close\r\n" } else { "" };
    let text = format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\n{close}\r\n");
    io.write_all(text.as_bytes()).await.is_ok() && io.flush().await.is_ok()
}

/// Each request of one connection, in order, until it ends or is closed.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: S, seen: Arc<Seen>, sessions: Sessions) {
    seen.connections.fetch_add(1, Ordering::SeqCst);
    let mut io = BufReader::new(io);
    let mut packets = 0;
    while let Some((method, path, fields)) = head(&mut io).await {
        let field = |name: &str| fields.get(name).cloned().unwrap_or_default();
        let pad = padding_of(&field("referer"));
        seen.requests.lock().unwrap().push((method.clone(), path.clone(), field("host"), pad));
        if !(100..=1000).contains(&pad) {
            let _ = answer(io.get_mut(), 400, true).await;
            return;
        }
        let Some(rest) = path.split('?').next().unwrap_or_default().strip_prefix("/xh/").map(String::from) else {
            let _ = answer(io.get_mut(), 404, true).await;
            return;
        };
        let parts: Vec<String> = rest.split('/').filter(|p| !p.is_empty()).map(String::from).collect();
        match (method.as_str(), parts.as_slice()) {
            ("GET", [id]) => {
                let Some(rx) = upsert(&mut sessions.lock().unwrap(), id).rx.take() else {
                    let _ = answer(io.get_mut(), 409, true).await;
                    return;
                };
                let open = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\n\r\n";
                if io.get_mut().write_all(open).await.is_err() || io.get_mut().flush().await.is_err() {
                    return;
                }
                vless(rx, io.into_inner(), seen).await;
                return;
            }
            ("POST", [id, seq]) => {
                let len: usize = field("content-length").parse().unwrap_or(0);
                let mut whole = vec![0u8; len];
                if io.read_exact(&mut whole).await.is_err() {
                    return;
                }
                let seq: u64 = seq.parse().unwrap_or(u64::MAX);
                {
                    let mut map = sessions.lock().unwrap();
                    let upload = upsert(&mut map, id);
                    upload.held.insert(seq, whole);
                    while let Some(bytes) = upload.held.remove(&upload.next) {
                        let _ = upload.tx.send(bytes);
                        upload.next += 1;
                    }
                }
                packets += 1;
                let close = packets >= CLOSE_AFTER;
                if !answer(io.get_mut(), 200, close).await || close {
                    return;
                }
            }
            ("POST", [id]) => {
                let tx = upsert(&mut sessions.lock().unwrap(), id).tx.clone();
                while let Some(chunk) = chunk(&mut io).await {
                    if chunk.is_empty() || tx.send(chunk).is_err() {
                        break;
                    }
                }
                let _ = answer(io.get_mut(), 200, true).await;
                return;
            }
            _ => {
                let _ = answer(io.get_mut(), 400, true).await;
                return;
            }
        }
    }
}

/// One chunk of a request's body; empty for the last.
async fn chunk<R: AsyncRead + Unpin>(io: &mut BufReader<R>) -> Option<Vec<u8>> {
    let mut size = String::new();
    io.read_line(&mut size).await.ok()?;
    let n = usize::from_str_radix(size.trim().split(';').next()?, 16).ok()?;
    let mut data = vec![0u8; n];
    io.read_exact(&mut data).await.ok()?;
    let mut end = String::new();
    io.read_line(&mut end).await.ok()?;
    if n == 0 {
        // The trailer's empty line was the one just read.
        return Some(Vec::new());
    }
    Some(data)
}

/// VLESS's request from the upload, then the target both ways, the download
/// in chunks of HTTP/1.1; another ID ends the download with no answer.
async fn vless<W: AsyncWrite + Unpin + Send>(mut up: mpsc::UnboundedReceiver<Vec<u8>>, mut down: W, seen: Arc<Seen>) {
    let mut got = Vec::new();
    let (id, target, used) = loop {
        let Some(chunk) = up.recv().await else { return };
        got.extend_from_slice(&chunk);
        if let Some(request) = parse_request(&got) {
            break request;
        }
    };
    let Some(tcp) = dial(id, &target, &seen).await else {
        let _ = down.write_all(b"0\r\n\r\n").await;
        return;
    };
    let (mut rd, mut wr) = tcp.into_split();
    let _ = wr.write_all(&got[used..]).await;
    let upward = async move {
        while let Some(chunk) = up.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    };
    let downward = async move {
        let (mut buf, mut answer) = (vec![0u8; 16 * 1024], vec![0u8, 0u8]);
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            answer.extend_from_slice(&buf[..n]);
            let size = format!("{:x}\r\n", answer.len());
            let framed = [size.as_bytes(), answer.as_slice(), b"\r\n".as_slice()].concat();
            answer.clear();
            if down.write_all(&framed).await.is_err() || down.flush().await.is_err() {
                return;
            }
        }
        let _ = down.write_all(b"0\r\n\r\n").await;
        let _ = down.flush().await;
    };
    tokio::join!(upward, downward);
}
