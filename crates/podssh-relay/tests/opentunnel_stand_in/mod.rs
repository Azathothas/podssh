//! A stand-in OpenTunnel server for the tests of the OpenTunnel road (T-530),
//! as anomalyco/opentunnel:docs/protocol.md and docs/server.md at v0.6.1 tell
//! it, over pipes in memory or the loopback's TCP: no listener but the
//! loopback's. Its API in plain HTTP/1.1, as the server's `HTTP_MODE=serve`:
//! `POST /api/tunnel` gives a tunnel of 12 letters under `opentunnel.test`
//! and its token; the bind of a CSR checks it as the service does (its key,
//! its common name, and its names, the tunnel's and its wildcard alone),
//! counts each new CSR, and issues a leaf of its own CA after one poll, as
//! `ISSUER=local` does; the bridge's upgrade needs the subprotocol
//! `opentunnel`, then `attach` within 10 s (else a Close 1008), with the
//! tunnel's token and a certificate ready, a route held by one bridge at a
//! time. A visitor's connection is routed by the SNI of its ClientHello to
//! the bridge of its route, as `open` and then its bytes from the ClientHello
//! on; a visitor of a route that no bridge holds is closed. Its messages are
//! written here, apart from the library's.

#![allow(dead_code)]

#[path = "keys.rs"]
pub mod keys;
#[path = "parse.rs"]
pub mod parse;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::opentunnel::dial::{BoxIo, Dial, Dialing, Visit};
use podssh_relay::opentunnel::Service;
use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE, OPCODE_TEXT};
use podssh_ws::RelaySession;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};

/// The domain of the stand-in's tunnels and of its API.
pub const DOMAIN: &str = "opentunnel.test";
const PIPE: usize = 1 << 20;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// A stream that a dial gives.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

struct Tunnel {
    token: String,
    hostname: String,
    csr: Option<String>,
    leaf: Option<String>,
    failed: Option<String>,
    /// The polls of the certificate before it is ready.
    polls: u32,
    new_csrs: usize,
}

/// What goes to a bridge's client.
enum Out {
    Text(String),
    Binary(Vec<u8>),
}

/// What goes to a visitor.
enum ToVisitor {
    Data(Vec<u8>),
    End,
}

struct Bridge {
    out: mpsc::UnboundedSender<Out>,
    conns: Mutex<HashMap<u32, mpsc::UnboundedSender<ToVisitor>>>,
    cut: Notify,
}

pub struct StandIn {
    pub ca: keys::Ca,
    tunnels: Mutex<HashMap<String, Tunnel>>,
    /// The bridge that holds each (tunnel, route).
    routes: Mutex<HashMap<(String, String), Arc<Bridge>>>,
    next_conn: AtomicU32,
    pub heartbeat_ms: u64,
    pub idle_timeout_ms: u64,
    /// Each `POST /api/tunnel` is refused with 429 and a long Retry-After.
    pub refuse_creates: AtomicBool,
    pub created: AtomicUsize,
    pub new_csrs: AtomicUsize,
    pub same_csrs: AtomicUsize,
    pub attaches: AtomicUsize,
    pub opens: AtomicUsize,
    pub visitors_closed: AtomicUsize,
}

impl StandIn {
    pub fn new() -> Arc<StandIn> {
        StandIn::with_heartbeat(15_000, 45_000)
    }

    pub fn with_heartbeat(heartbeat_ms: u64, idle_timeout_ms: u64) -> Arc<StandIn> {
        Arc::new(StandIn {
            ca: keys::Ca::new(),
            tunnels: Mutex::default(),
            routes: Mutex::default(),
            next_conn: AtomicU32::new(1),
            heartbeat_ms,
            idle_timeout_ms,
            refuse_creates: AtomicBool::new(false),
            created: AtomicUsize::new(0),
            new_csrs: AtomicUsize::new(0),
            same_csrs: AtomicUsize::new(0),
            attaches: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            visitors_closed: AtomicUsize::new(0),
        })
    }

    /// The service as the library names it.
    pub fn service() -> Service {
        Service { host: DOMAIN.into(), port: 443 }
    }

    /// A dial of the API that reaches the stand-in, over a pipe.
    pub fn api(self: &Arc<Self>) -> Dial {
        let me = self.clone();
        Arc::new(move |_: &Service| -> Dialing {
            let (ours, theirs) = tokio::io::duplex(PIPE);
            tokio::spawn(me.clone().serve_api(theirs));
            Box::pin(async move { Ok(Box::new(ours) as BoxIo) })
        })
    }

    /// A visit of a name that reaches the stand-in's port 443, over a pipe.
    pub fn visit(self: &Arc<Self>) -> Visit {
        let me = self.clone();
        Arc::new(move |_: &str| -> Dialing {
            let (ours, theirs) = tokio::io::duplex(PIPE);
            tokio::spawn(me.clone().serve_visitor(theirs));
            Box::pin(async move { Ok(Box::new(ours) as BoxIo) })
        })
    }

    /// The hostname of each tunnel made.
    pub fn hostnames(&self) -> Vec<String> {
        lock(&self.tunnels).values().map(|t| t.hostname.clone()).collect()
    }

    /// Each bridge ends with a Close 1012, as at a restart of the service.
    pub fn cut_bridges(&self) {
        for bridge in lock(&self.routes).values() {
            bridge.cut.notify_one();
        }
    }

    /// The bridges that hold a route now.
    pub fn bridges(&self) -> usize {
        lock(&self.routes).len()
    }

    /// The API, on one connection: one request, one answer.
    pub async fn serve_api<S: Io>(self: Arc<Self>, mut io: S) {
        let Ok((request, rest)) = podssh_ws::http::read_request(&mut io, Vec::new()).await else { return };
        let target = request.target.split('?').next().unwrap_or_default().to_string();
        let path: Vec<&str> = target.split('/').collect();
        if let ("GET", ["", "api", "tunnel", id, "connect"]) = (request.method.as_str(), &path[..]) {
            if request.has_token("connection", "upgrade") {
                let id = id.to_string();
                return self.bridge(io, &request, &id, rest).await;
            }
        }
        let body = read_body(&mut io, &request, rest).await;
        let bearer = request.header("authorization").and_then(|v| v.strip_prefix("Bearer ")).map(str::to_string);
        let (status, answer) = match (request.method.as_str(), &path[..]) {
            ("GET", ["", "health"]) => (200, json!({ "ok": true })),
            ("POST", ["", "api", "tunnel"]) => self.create(),
            ("POST", ["", "api", "tunnel", id, "certificate"]) => self.bind_csr(id, bearer.as_deref(), &body),
            ("GET", ["", "api", "tunnel", id, "certificate"]) => self.certificate(id, bearer.as_deref()),
            _ => (404, json!({ "_tag": "NotFoundError", "message": "no such route" })),
        };
        let mut head = format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nConnection: close\r\n");
        if status == 429 {
            head.push_str("Retry-After: 1800\r\n");
        }
        let text = answer.to_string();
        head.push_str(&format!("Content-Length: {}\r\n\r\n{text}", text.len()));
        let _ = io.write_all(head.as_bytes()).await;
        let _ = io.shutdown().await;
    }

    fn create(&self) -> (u16, Value) {
        if self.refuse_creates.load(Ordering::SeqCst) {
            let message = "Too many tunnels created from this address; try again in 30 minutes";
            return (429, json!({ "_tag": "RateLimitedError", "message": message }));
        }
        let id: String = (0..12).map(|_| (b'a' + rand::random::<u8>() % 26) as char).collect();
        let token = format!("tok_{}", (0..24).map(|_| (b'a' + rand::random::<u8>() % 26) as char).collect::<String>());
        let hostname = format!("{id}.{DOMAIN}");
        let tunnel = Tunnel {
            token: token.clone(),
            hostname: hostname.clone(),
            csr: None,
            leaf: None,
            failed: None,
            polls: 0,
            new_csrs: 0,
        };
        lock(&self.tunnels).insert(id.clone(), tunnel);
        self.created.fetch_add(1, Ordering::SeqCst);
        (201, json!({ "tunnel": { "id": id, "hostname": hostname, "state": "offline" }, "token": token }))
    }

    fn bind_csr(&self, id: &str, bearer: Option<&str>, body: &[u8]) -> (u16, Value) {
        let mut tunnels = lock(&self.tunnels);
        let Some(tunnel) = tunnels.get_mut(id) else { return not_found() };
        if bearer != Some(tunnel.token.as_str()) {
            return unauthorized();
        }
        let csr = serde_json::from_slice::<Value>(body).ok().and_then(|v| v["csr"].as_str().map(str::to_string));
        let Some(csr) = csr else { return (400, json!({ "_tag": "BadRequest", "message": "no csr" })) };
        if tunnel.csr.as_deref() == Some(csr.as_str()) {
            self.same_csrs.fetch_add(1, Ordering::SeqCst);
        } else {
            self.new_csrs.fetch_add(1, Ordering::SeqCst);
            tunnel.new_csrs += 1;
            if tunnel.new_csrs > 5 {
                return (
                    429,
                    json!({ "_tag": "RateLimitedError", "message": "Too many new certificates for this tunnel" }),
                );
            }
            (tunnel.csr, tunnel.leaf, tunnel.failed, tunnel.polls) = (Some(csr), None, None, 1);
        }
        (202, state(id, tunnel))
    }

    fn certificate(&self, id: &str, bearer: Option<&str>) -> (u16, Value) {
        let mut tunnels = lock(&self.tunnels);
        let Some(tunnel) = tunnels.get_mut(id) else { return not_found() };
        if bearer != Some(tunnel.token.as_str()) {
            return unauthorized();
        }
        if tunnel.leaf.is_none() && tunnel.failed.is_none() && tunnel.csr.is_some() {
            if tunnel.polls > 0 {
                tunnel.polls -= 1;
            } else {
                self.issue(tunnel);
            }
        }
        (200, state(id, tunnel))
    }

    /// The leaf of the tunnel's CSR, when it asks for the tunnel's names
    /// alone, as the service checks before each order.
    fn issue(&self, tunnel: &mut Tunnel) {
        let csr =
            tunnel.csr.as_deref().and_then(|pem| keys::der(pem, "CERTIFICATE REQUEST")).and_then(|d| parse::csr(&d));
        let Some(csr) = csr else {
            tunnel.failed = Some("the CSR could not be read".into());
            return;
        };
        let want = vec![tunnel.hostname.clone(), format!("*.{}", tunnel.hostname)];
        let mut names = csr.names.clone();
        names.sort();
        let mut wanted = want.clone();
        wanted.sort();
        if csr.common_name.as_deref() != Some(tunnel.hostname.as_str()) || names != wanted {
            tunnel.failed = Some("the CSR names other names than the tunnel's".into());
            return;
        }
        tunnel.leaf = Some(self.ca.leaf(&want, &csr.point));
    }

    async fn bridge<S: Io>(self: Arc<Self>, mut io: S, request: &podssh_ws::http::Request, id: &str, rest: Vec<u8>) {
        if !request.has_token("sec-websocket-protocol", "opentunnel") {
            let _ = io.write_all(&podssh_ws::http::request::refusal(400, "the subprotocol opentunnel", &[])).await;
            return;
        }
        let Some(key) = request.header("sec-websocket-key") else { return };
        let accept = podssh_ws::handshake::accept_key(key);
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: opentunnel\r\n\r\n"
        );
        if io.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let session = Arc::new(RelaySession::new(io, rest, None, Duration::from_secs(30)).as_server());
        let attach = match tokio::time::timeout(Duration::from_secs(10), session.read_frame()).await {
            Err(_) => {
                let _ = session.send_close(1008, "no attach").await;
                return;
            }
            Ok(Err(_)) => return,
            Ok(Ok(f)) if f.opcode == OPCODE_TEXT => serde_json::from_slice::<Value>(&f.payload).unwrap_or_default(),
            Ok(Ok(_)) => return,
        };
        let refused = |code: &str| json!({ "type": "attach_error", "code": code }).to_string();
        let routes: Vec<String> = attach["routes"]
            .as_array()
            .map(|r| r.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default();
        let answer = {
            let tunnels = lock(&self.tunnels);
            match tunnels.get(id) {
                None => Err(refused("bad_token")),
                Some(t) if attach["type"] != "attach" || attach["token"].as_str() != Some(t.token.as_str()) => {
                    Err(refused("bad_token"))
                }
                Some(t) if t.leaf.is_none() => Err(refused("cert_not_ready")),
                Some(_) if routes.is_empty() || routes.len() > 128 => Err(refused("too_many_routes")),
                Some(_) => Ok(()),
            }
        };
        if let Err(text) = answer {
            let _ = session.send_text(&text).await;
            let _ = session.send_close(1000, "").await;
            return;
        }
        let (out, mut out_rx) = mpsc::unbounded_channel();
        let bridge = Arc::new(Bridge { out, conns: Mutex::default(), cut: Notify::new() });
        // A route belongs to one bridge at a time; no lock is held over a wait.
        let conflict = {
            let mut held = lock(&self.routes);
            let conflict = routes.iter().any(|route| held.contains_key(&(id.to_string(), route.clone())));
            if !conflict {
                for route in &routes {
                    held.insert((id.to_string(), route.clone()), bridge.clone());
                }
            }
            conflict
        };
        if conflict {
            let _ = session.send_text(&refused("route_conflict")).await;
            let _ = session.send_close(1000, "").await;
            return;
        }
        self.attaches.fetch_add(1, Ordering::SeqCst);
        let attached = json!({ "type": "attached", "session": format!("sess_{}", self.attaches.load(Ordering::SeqCst)), "routes": routes,
            "heartbeat_ms": self.heartbeat_ms, "idle_timeout_ms": self.idle_timeout_ms });
        let _ = session.send_text(&attached.to_string()).await;
        let writer = {
            let session = session.clone();
            tokio::spawn(async move {
                while let Some(out) = out_rx.recv().await {
                    let sent = match out {
                        Out::Text(text) => session.send_text(&text).await,
                        Out::Binary(bytes) => session.send_binary(&bytes).await,
                    };
                    if sent.is_err() {
                        return;
                    }
                }
            })
        };
        loop {
            let f = tokio::select! {
                read = session.read_frame() => match read { Ok(f) => f, Err(_) => break },
                () = bridge.cut.notified() => {
                    let _ = session.send_close(1012, "restart").await;
                    break;
                }
            };
            match f.opcode {
                OPCODE_TEXT => {
                    let message: Value = serde_json::from_slice(&f.payload).unwrap_or_default();
                    let conn = message["conn"].as_u64().map(|c| c as u32);
                    match (message["type"].as_str(), conn) {
                        (Some("ping"), _) => {
                            let _ = bridge.out.send(Out::Text(
                                json!({ "type": "pong", "time_sent": message["time_sent"] }).to_string(),
                            ));
                        }
                        (Some("end"), Some(conn)) => {
                            if let Some(to) = lock(&bridge.conns).get(&conn) {
                                let _ = to.send(ToVisitor::End);
                            }
                        }
                        (Some("reset"), Some(conn)) => {
                            lock(&bridge.conns).remove(&conn);
                        }
                        _ => {}
                    }
                }
                OPCODE_BINARY if f.payload.len() >= 4 => {
                    let conn = u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]);
                    if let Some(to) = lock(&bridge.conns).get(&conn) {
                        let _ = to.send(ToVisitor::Data(f.payload[4..].to_vec()));
                    }
                }
                OPCODE_CLOSE => break,
                _ => {}
            }
        }
        // The routes go free, and each visitor of the bridge ends.
        lock(&self.routes).retain(|_, held| !Arc::ptr_eq(held, &bridge));
        lock(&bridge.conns).clear();
        writer.abort();
    }

    /// A visitor's connection to port 443: its ClientHello's SNI picks the
    /// bridge, which gets `open` and the bytes from the ClientHello on.
    pub async fn serve_visitor<S: Io>(self: Arc<Self>, mut io: S) {
        let mut hello = Vec::new();
        let read = async {
            let mut chunk = [0u8; 4096];
            while parse::record_len(&hello).is_none_or(|len| hello.len() < len) && hello.len() < 64 * 1024 {
                let n = io.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return false;
                }
                hello.extend_from_slice(&chunk[..n]);
            }
            true
        };
        let whole = tokio::time::timeout(Duration::from_secs(10), read).await.unwrap_or(false);
        let picked = parse::sni(&hello).and_then(|sni| Some((sni.clone(), parse::tunnel_and_route(&sni, DOMAIN)?)));
        let bridge = picked.as_ref().and_then(|(_, key)| lock(&self.routes).get(key).cloned());
        let (Some((sni, _)), Some(bridge), true) = (picked, bridge, whole) else {
            self.visitors_closed.fetch_add(1, Ordering::SeqCst);
            return;
        };
        self.opens.fetch_add(1, Ordering::SeqCst);
        let conn = self.next_conn.fetch_add(1, Ordering::SeqCst);
        let (to, mut from_bridge) = mpsc::unbounded_channel();
        lock(&bridge.conns).insert(conn, to);
        let open = json!({ "type": "open", "conn": conn, "peer": "203.0.113.9:4242", "sni": sni, "alpn": "" });
        let _ = bridge.out.send(Out::Text(open.to_string()));
        let frame = |payload: &[u8]| [&conn.to_be_bytes()[..], payload].concat();
        for piece in hello.chunks(32 * 1024) {
            let _ = bridge.out.send(Out::Binary(frame(piece)));
        }
        let (mut reader, mut writer) = tokio::io::split(io);
        let up = async {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let n = reader.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    let _ = bridge.out.send(Out::Text(json!({ "type": "end", "conn": conn }).to_string()));
                    return;
                }
                let _ = bridge.out.send(Out::Binary(frame(&buf[..n])));
            }
        };
        let down = async {
            while let Some(item) = from_bridge.recv().await {
                match item {
                    ToVisitor::Data(bytes) => {
                        if writer.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    ToVisitor::End => break,
                }
            }
            let _ = writer.shutdown().await;
        };
        // The connection ends once both of its ways ended.
        tokio::join!(up, down);
        lock(&bridge.conns).remove(&conn);
    }
}

/// The bytes of a request's body, by its `Content-Length`.
async fn read_body<S: Io>(io: &mut S, request: &podssh_ws::http::Request, mut rest: Vec<u8>) -> Vec<u8> {
    let want = request.header("content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0).min(1 << 20);
    let mut chunk = [0u8; 4096];
    while rest.len() < want {
        match io.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => rest.extend_from_slice(&chunk[..n]),
        }
    }
    rest.truncate(want);
    rest
}

fn not_found() -> (u16, Value) {
    (404, json!({ "_tag": "NotFoundError", "message": "Tunnel not found" }))
}

fn unauthorized() -> (u16, Value) {
    (401, json!({ "_tag": "UnauthorizedError", "message": "Invalid token" }))
}

fn state(id: &str, tunnel: &Tunnel) -> Value {
    let state = match (&tunnel.leaf, &tunnel.failed) {
        (Some(leaf), _) => {
            json!({ "type": "ready", "certificate": leaf, "chain": "", "expiry": "2099-01-01T00:00:00.000Z" })
        }
        (None, Some(reason)) => json!({ "type": "failed", "reason": reason }),
        (None, None) => json!({ "type": "issuing" }),
    };
    json!({ "id": format!("cert_{id}"), "state": state })
}
