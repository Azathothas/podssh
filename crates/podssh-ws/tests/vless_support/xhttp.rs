//! The XHTTP stand-in's answer to each request, as Xray-core's `hub.go`
//! routes them: a POST to the path with no session is stream-one; a GET of
//! `PATH/SESSION` is the download of packet-up or stream-up; a POST of
//! `PATH/SESSION` is stream-up's upload, and one of `PATH/SESSION/SEQ` a packet,
//! put in order by its number. The padding of `Referer` is checked first.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::{dial, parse_request, Seen};

/// The upload of a session of packet-up or stream-up.
pub struct Upload {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    next: u64,
    held: BTreeMap<u64, Vec<u8>>,
}

/// The uploads by each session's id.
pub type Sessions = Arc<Mutex<HashMap<String, Upload>>>;

/// The length of `x_padding` in `Referer`'s query.
fn padding(request: &http::Request<RecvStream>) -> usize {
    let referer = request.headers().get("referer").and_then(|v| v.to_str().ok()).unwrap_or_default();
    referer.split_once("x_padding=").map_or(0, |(_, x)| x.split('&').next().unwrap_or_default().len())
}

fn status(respond: &mut SendResponse<Bytes>, code: u16, end: bool) -> Option<SendStream<Bytes>> {
    let answer = http::Response::builder().status(code).body(()).unwrap();
    respond.send_response(answer, end).ok()
}

pub async fn handle(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    seen: Arc<Seen>,
    sessions: Sessions,
) {
    let (method, path) = (request.method().to_string(), request.uri().path().to_string());
    let host = request.uri().authority().map(|a| a.to_string()).unwrap_or_default();
    let pad = padding(&request);
    seen.requests.lock().unwrap().push((method.clone(), path.clone(), host, pad));
    if !(100..=1000).contains(&pad) {
        status(&mut respond, 400, true);
        return;
    }
    let Some(rest) = path.strip_prefix("/xh/") else {
        status(&mut respond, 404, true);
        return;
    };
    let parts: Vec<String> = rest.split('/').filter(|p| !p.is_empty()).map(String::from).collect();
    let mut body = request.into_body();
    match (method.as_str(), parts.as_slice()) {
        ("POST", []) => {
            let Some(down) = status(&mut respond, 200, false) else { return };
            let (tx, rx) = mpsc::unbounded_channel();
            tokio::spawn(forward(body, tx));
            vless(rx, down, seen).await;
        }
        ("GET", [id]) => {
            let (tx, rx) = mpsc::unbounded_channel();
            sessions.lock().unwrap().insert(id.clone(), Upload { tx, next: 0, held: BTreeMap::new() });
            let Some(down) = status(&mut respond, 200, false) else { return };
            vless(rx, down, seen).await;
        }
        ("POST", [id]) => {
            let tx = sessions.lock().unwrap().get(id).map(|u| u.tx.clone());
            let Some(tx) = tx else {
                status(&mut respond, 404, true);
                return;
            };
            let Some(mut answer) = status(&mut respond, 200, false) else { return };
            forward(body, tx).await;
            let _ = answer.send_data(Bytes::new(), true);
        }
        ("POST", [id, seq]) => {
            let mut whole = Vec::new();
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
                whole.extend_from_slice(&chunk);
            }
            let seq: u64 = seq.parse().unwrap_or(u64::MAX);
            let known = {
                let mut map = sessions.lock().unwrap();
                match map.get_mut(id) {
                    Some(upload) => {
                        upload.held.insert(seq, whole);
                        while let Some(bytes) = upload.held.remove(&upload.next) {
                            let _ = upload.tx.send(bytes);
                            upload.next += 1;
                        }
                        true
                    }
                    None => false,
                }
            };
            status(&mut respond, if known { 200 } else { 500 }, true);
        }
        _ => {
            status(&mut respond, 404, true);
        }
    }
}

/// A request's body into the channel of its session.
async fn forward(mut body: RecvStream, tx: mpsc::UnboundedSender<Vec<u8>>) {
    while let Some(Ok(chunk)) = body.data().await {
        let _ = body.flow_control().release_capacity(chunk.len());
        if tx.send(chunk.to_vec()).is_err() {
            return;
        }
    }
}

/// VLESS's request from the upload, then the target both ways, its first
/// bytes after the answer; another ID ends the download with no answer.
async fn vless(mut up: mpsc::UnboundedReceiver<Vec<u8>>, mut down: SendStream<Bytes>, seen: Arc<Seen>) {
    let mut got = Vec::new();
    let (id, target, used) = loop {
        let Some(chunk) = up.recv().await else { return };
        got.extend_from_slice(&chunk);
        if let Some(request) = parse_request(&got) {
            break request;
        }
    };
    let Some(tcp) = dial(id, &target, &seen).await else {
        let _ = down.send_data(Bytes::new(), true);
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
            if !send_all(&mut down, std::mem::take(&mut answer)).await {
                return;
            }
        }
        let _ = down.send_data(Bytes::new(), true);
    };
    tokio::join!(upward, downward);
}

/// `data` on `send` as the windows let it go.
async fn send_all(send: &mut SendStream<Bytes>, data: Vec<u8>) -> bool {
    let mut rest = Bytes::from(data);
    while !rest.is_empty() {
        send.reserve_capacity(rest.len());
        match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(0)) => continue,
            Some(Ok(room)) => {
                let chunk = rest.split_to(room.min(rest.len()));
                if send.send_data(chunk, false).is_err() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}
