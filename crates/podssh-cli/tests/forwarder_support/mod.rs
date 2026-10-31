//! Stand-ins of WebSocket forwarders (T-369, T-370), behind the proxy of
//! `cloud_support`, which re-terminates TLS with the test's own CA for each
//! name: podssh reaches them by `https_proxy` and `--ca-file` alone, as it
//! would reach the forwarders themselves. Each one dials the test's SSH
//! server, whatever target it was asked for, and keeps what it saw: the
//! request, the target, and the first frame of the frame form. A name of
//! no stand-in, such as a relay host, gets 503.

#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use podssh_ws::{frame, RelaySession};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::cloud_support::{Handler, Stream};

/// The names of the stand-ins that take the target from the query, as
/// Mudlet's Worker and its older copy do.
pub const QUERY_HOSTS: &[&str] = &["fwd-query.test", "web-proxy.mudlet.org", "mudix.delwing.workers.dev"];
/// The names of those that take it from a first frame, as ssheasy does.
pub const FRAME_HOSTS: &[&str] = &["fwd-frame.test", "ssheasy.com"];
/// The name of one that closes at once with 1011, as a Worker that cannot
/// reach the target.
pub const CLOSE_HOST: &str = "fwd-close.test";

/// One upgrade that a stand-in took.
#[derive(Debug, Clone)]
pub struct Seen {
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub target: (String, u16),
    pub first_frame: Option<String>,
}

/// The stand-ins: where they dial, what they saw, and the names that close
/// instead of carrying.
pub struct Stands {
    sshd: u16,
    pub seen: Mutex<Vec<Seen>>,
    pub closing: Mutex<HashSet<String>>,
}

impl Stands {
    pub fn new(sshd: u16) -> Arc<Stands> {
        Arc::new(Stands { sshd, seen: Mutex::default(), closing: Mutex::default() })
    }

    /// The handler of the proxy.
    pub fn handler(self: &Arc<Self>) -> Handler {
        let stands = self.clone();
        Arc::new(move |host: String, stream: Stream| {
            let stands = stands.clone();
            Box::pin(async move { stands.serve(host, stream).await })
        })
    }

    /// Each name that a stand-in saw an upgrade for, in order.
    pub fn hosts(&self) -> Vec<String> {
        self.seen.lock().unwrap().iter().map(|s| s.host.clone()).collect()
    }

    async fn serve(&self, host: String, mut tls: Stream) {
        // The request first, read whole, so that the answer is not lost to
        // a reset of unread bytes.
        let Ok((head, pending)) = podssh_ws::http::read_request(&mut tls, Vec::new()).await else { return };
        let query = QUERY_HOSTS.contains(&host.as_str()) || host == CLOSE_HOST;
        if !query && !FRAME_HOSTS.contains(&host.as_str()) {
            let _ = tls.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n").await;
            let _ = tls.shutdown().await;
            return;
        }
        let Ok(key) = podssh_ws::server::check_upgrade(&head) else {
            let _ = tls.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
            return;
        };
        if tls.write_all(&podssh_ws::server::switching(&key)).await.is_err() {
            return;
        }
        let session = Arc::new(podssh_ws::server::session(tls, pending, None));
        let (target, first_frame) = if query {
            (query_target(&head.target), None)
        } else {
            let Ok(first) = session.read_frame().await else { return };
            let text = String::from_utf8_lossy(&first.payload).into_owned();
            let doc: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            let host = doc["Host"].as_str().unwrap_or_default().to_string();
            ((host, doc["Port"].as_u64().unwrap_or(0) as u16), Some(text))
        };
        let path = head.target.clone();
        let seen = Seen { host: host.clone(), path, headers: head.headers.clone(), target: target.clone(), first_frame };
        self.seen.lock().unwrap().push(seen);
        // The guard ends with the statement: none is held across an await.
        let closing = host == CLOSE_HOST || self.closing.lock().unwrap().contains(&host);
        if closing {
            let reason = format!("Proxy: connect to {}:{} failed: refused", target.0, target.1);
            let _ = session.send_close(1011, &reason).await;
            let _ = session.read_frame().await;
            return;
        }
        let Ok(sshd) = TcpStream::connect(("127.0.0.1", self.sshd)).await else { return };
        if query {
            // The Worker's word once its socket is open, a text frame.
            let _ = session.send_text(r#"{"type":"game.connected"}"#).await;
        } else {
            // ssheasy's answer, in a binary frame.
            let _ = session.send_binary(br#"{"status":"ok"}"#).await;
        }
        pump(session, sshd).await;
    }
}

/// `%XX` back to its byte.
fn decoded(text: &str) -> String {
    let (bytes, mut out, mut i) = (text.as_bytes(), Vec::new(), 0);
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap_or(b'?'));
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `?host=H&port=P`, as the Worker reads it.
fn query_target(target: &str) -> (String, u16) {
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let get = |name: &str| {
        query.split('&').find_map(|pair| pair.strip_prefix(&format!("{name}="))).map(decoded).unwrap_or_default()
    };
    (get("host"), get("port").parse().unwrap_or(23))
}

/// The copy of a stand-in, both ways: binary frames to the server, its
/// bytes in binary frames, and a Close 1000 when it closes, as the Worker's.
async fn pump(session: Arc<RelaySession<Stream>>, server: TcpStream) {
    let (mut rd, mut wr) = server.into_split();
    let s = session.clone();
    let up = tokio::spawn(async move {
        while let Ok(f) = s.read_frame().await {
            match f.opcode {
                frame::OPCODE_BINARY => {
                    if wr.write_all(&f.payload).await.is_err() {
                        break;
                    }
                }
                frame::OPCODE_CLOSE => break,
                _ => {}
            }
        }
        let _ = wr.shutdown().await;
    });
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if session.send_binary(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = session.send_close(1000, "TCP connection closed").await;
    let _ = up.await;
}
