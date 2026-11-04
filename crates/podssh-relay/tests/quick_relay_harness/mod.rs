//! The relay role behind a quick tunnel (T-428), as its tests run it: the
//! node served on one end of a pipe, with the role as its origin, and the
//! stand-in edge of T-300 on the other end, which registers it; and the
//! edge's front, a port of the loopback that takes HTTP/1.1 from a client as
//! Cloudflare's edge takes a visitor's, and sends each request to the node
//! over the HTTP/2 of the registered connection with cloudflared's headers
//! (`connection/http2.go` at 2026.10.6): the upgrade of a WebSocket in
//! `cf-cloudflared-proxy-connection-upgrade`, the visitor's other headers as
//! HTTP/2's, its Host as the authority. The node's answer goes back as
//! HTTP/1.1: a 200 to an upgrade as its 101, with the origin's headers of
//! `cf-cloudflared-response-headers`. A client of the contract reaches the
//! role through the front as it reaches a relay host.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::Request;
use podssh_relay::quick::headers;
use podssh_relay::quick::origin::{Origin, Visitors};
use podssh_relay::quick::serve::{serve, Step};
use podssh_relay::serve::behind::Behind;
use podssh_relay::serve::{self as role, Config, Limits, Mint};
use podssh_ws::http::request::read_request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use super::quick_harness::{echo, register, registration};

pub const LIMIT: Duration = Duration::from_secs(20);
/// The tunnel's name, as the API gives one.
pub const NAME: &str = "podssh-test.trycloudflare.com";
/// A version line of the form of GitHub's SSH port's (babeld), the first
/// bytes of the test's target.
pub const BANNER: &[u8] = b"SSH-2.0-babeld-5c1f8e2a\r\n";

/// The headers that HTTP/2 does not carry (RFC 9113, section 8.2.2), and
/// the Host, which it carries as the authority.
const ONE_HOP: &[&str] =
    &["host", "connection", "upgrade", "keep-alive", "proxy-connection", "transfer-encoding", "te"];

/// A node registered at the stand-in edge, with the role behind its tunnel,
/// and the front's port.
pub struct Tunnel {
    pub port: u16,
    pub cfg: Arc<Config>,
    pub events: Arc<Mutex<Vec<String>>>,
    pub steps: mpsc::UnboundedReceiver<Step>,
    /// The control stream's ends and the node's stop, kept for the test.
    kept: (SendStream<Bytes>, RecvStream, oneshot::Sender<()>),
}

impl Tunnel {
    /// The node, with the role of `mint` behind it, for each path when
    /// `every` (a node with no TARGET), and its visitors echoed.
    pub async fn start(mint: Mint, every: bool) -> Tunnel {
        let events = Arc::new(Mutex::new(Vec::new()));
        let said = events.clone();
        let say: role::Events = Box::new(move |line: &str| said.lock().unwrap().push(line.to_string()));
        let cfg = Arc::new(Config {
            version: "podssh test".into(),
            mint,
            tokens: role::tokens::Tokens::new([7; 32]),
            // The test's target is on the loopback.
            policy: role::policy::Policy { private: true, ..Default::default() },
            egress: Default::default(),
            limits: Limits::default(),
            pairs: Default::default(),
            resumes: Default::default(),
            answered: Default::default(),
            events: Some(say),
            brake: Default::default(),
        });
        let origin: Arc<dyn Origin> = Arc::new(Behind::new(cfg.clone(), NAME, every));
        let visitors = Visitors { visit: echo, origin: Some(origin) };
        let (node_io, edge_io) = tokio::io::duplex(1 << 20);
        let (steps_tx, mut steps) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let stop = async {
                let _ = stopped.await;
            };
            serve(node_io, &registration(), visitors, steps_tx, stop).await
        });
        let (mut edge, conn) = h2::client::handshake(edge_io).await.unwrap();
        tokio::spawn(conn);
        let (to_node, from_node) = register(&mut edge, &mut steps).await;
        let port = front(edge).await;
        Tunnel { port, cfg, events, steps, kept: (to_node, from_node, stop) }
    }

    /// Whether the role said a line that holds `text`.
    pub fn said(&self, text: &str) -> bool {
        self.events.lock().unwrap().iter().any(|line| line.contains(text))
    }
}

/// The front: each connection of a client, a request to the node.
async fn front(edge: SendRequest<Bytes>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(visitor(tcp, edge.clone()));
        }
    });
    port
}

/// One client of the front: its request to the node, as the edge sends a
/// visitor's, and the node's answer back to it.
async fn visitor(mut tcp: TcpStream, edge: SendRequest<Bytes>) {
    let Ok((head, mut pending)) = read_request(&mut tcp, Vec::new()).await else { return };
    let websocket = head.has_token("upgrade", "websocket");
    let host = head.header("host").unwrap_or_default().to_string();
    let mut request = Request::builder().method(head.method.as_str()).uri(format!("https://{host}{}", head.target));
    if websocket {
        request = request.header(headers::UPGRADE, headers::WEBSOCKET);
    }
    for (name, value) in head.headers.iter().filter(|(name, _)| !ONE_HOP.contains(&name.as_str())) {
        request = request.header(name.as_str(), value.as_str());
    }
    let length: usize = head.header("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
    let Ok(mut edge) = edge.ready().await else { return };
    let ends = !websocket && length == 0;
    let Ok((answer, mut to_node)) = edge.send_request(request.body(()).unwrap(), ends) else { return };
    if !websocket && length > 0 {
        let mut chunk = vec![0u8; 4096];
        while pending.len() < length {
            match tcp.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
            }
        }
        pending.truncate(length);
        if send_all(&mut to_node, &std::mem::take(&mut pending)).await.is_err() {
            return;
        }
        let _ = to_node.send_data(Bytes::new(), true);
    }
    let Ok(answer) = answer.await else { return };
    let status = answer.status().as_u16();
    let serialized = answer.headers().get(headers::RESPONSE_HEADERS).and_then(|v| v.to_str().ok());
    let origin = serialized.and_then(headers::deserialize).unwrap_or_default();
    // A 200 to an upgrade is its 101 (cloudflared's `http2RespWriter`).
    let switched = websocket && status == 200;
    let mut out = match switched {
        true => "HTTP/1.1 101 Switching Protocols\r\n".to_string(),
        false => format!("HTTP/1.1 {status} Answer\r\nConnection: close\r\n"),
    };
    for (name, value) in &origin {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    if tcp.write_all(out.as_bytes()).await.is_err() {
        return;
    }
    let mut from_node = answer.into_body();
    let (mut tcp_in, mut tcp_out) = tcp.into_split();
    let down = async move {
        while let Some(Ok(chunk)) = from_node.data().await {
            let _ = from_node.flow_control().release_capacity(chunk.len());
            if tcp_out.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = tcp_out.shutdown().await;
    };
    if !switched {
        return down.await;
    }
    let up = async move {
        if send_all(&mut to_node, &pending).await.is_err() {
            return;
        }
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match tcp_in.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send_all(&mut to_node, &buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = to_node.send_data(Bytes::new(), true);
    };
    tokio::join!(up, down);
}

/// Send `bytes` as the node's window lets them go.
async fn send_all(send: &mut SendStream<Bytes>, mut bytes: &[u8]) -> Result<(), h2::Error> {
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len());
        let room = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(room)) => room,
            Some(Err(e)) => return Err(e),
            None => return Err(h2::Error::from(h2::Reason::CANCEL)),
        };
        let take = room.min(bytes.len());
        if take > 0 {
            send.send_data(Bytes::copy_from_slice(&bytes[..take]), false)?;
            bytes = &bytes[take..];
        }
    }
    Ok(())
}

/// One request of HTTP/1.1 through the front, with `Host: host`: its status
/// and its body.
pub async fn http(port: u16, method: &str, path: &str, host: &str, body: &[u8]) -> (u16, String) {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let length = body.len();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {length}\r\n\r\n");
    tcp.write_all(head.as_bytes()).await.unwrap();
    tcp.write_all(body).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await.expect("an answer in time").unwrap();
    let text = String::from_utf8_lossy(&answer).into_owned();
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

/// A target on the loopback that sends [`BANNER`], then echoes.
pub async fn banner_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                if tcp.write_all(BANNER).await.is_ok() {
                    let (mut r, mut w) = tcp.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                }
            });
        }
    });
    port
}

/// A list's file in a scratch directory of the test's own, which goes when
/// the test ends, pass or fail: the gate counts what tests leave.
pub struct List {
    dir: std::path::PathBuf,
    /// The file, which the role reads at each proof while the test runs.
    pub path: std::path::PathBuf,
}

impl Drop for List {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A list of the key of `seed` alone, in the format of `podssh node
/// --allow`, in a scratch directory of this test's own.
pub fn list_of(seed: u8, tag: &str) -> List {
    let dir = std::env::temp_dir().join(format!("podssh-quick-relay-{tag}-{}", std::process::id()));
    podssh_relay::cache::private_dir(&dir).unwrap();
    let path = dir.join("allow");
    let fingerprint = podssh_relay::identity::Identity::from_seed(&[seed; 32]).public().fingerprint();
    std::fs::write(&path, format!("{fingerprint} the test's key\n")).unwrap();
    List { dir, path }
}
