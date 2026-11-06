//! A stand-in of frps for the tests of the frp road (T-498), written here
//! from frp's source at v0.71.1 (`server/service.go`, `server/control.go`,
//! `server/visitor/visitor.go`, `pkg/auth/token.go`) and hashicorp's yamux
//! specification: frp's TCP with TLS (the byte 0x17, then TLS), yamux as the
//! server, a login in clear, the control stream in AES-128-CFB after it, an
//! STCP service, work connections and visitors. Its refusals are frps's own
//! words with `detailedErrorsToClient` on, frps's default. The yamux frames
//! and the messages' framing are written by hand here; the key of the
//! control stream and the auth keys are podssh-ws's, which its own tests
//! check against vectors of Python's hashlib and cryptography.

mod mux;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::frp::cfb::{self, Cfb};
use podssh_ws::frp::msg::auth_key;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// frps's token, made up for the tests.
pub const TOKEN: &str = "a-token-of-the-frp-test";
/// The STCP service's secret, made up for the tests.
pub const SECRET: &str = "a-secret-of-the-frp-test";

/// One STCP service: its secret, the control's asks, and its work
/// connections as the node opens them.
struct Service {
    sk: String,
    ask: mpsc::UnboundedSender<()>,
    work: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<DuplexStream>>>,
}

/// The stand-in and what it saw.
#[derive(Default)]
pub struct Frps {
    services: Mutex<HashMap<String, Service>>,
    /// Each run's queue of work connections, by its run id.
    runs: Mutex<HashMap<String, mpsc::UnboundedSender<DuplexStream>>>,
    pub logins: AtomicUsize,
    pub visits: AtomicUsize,
    pub refused: Mutex<Vec<String>>,
}

impl Frps {
    /// Serve frp's TCP with TLS by `acceptor` on a port of the loopback.
    pub async fn listen(self: &Arc<Frps>, acceptor: podssh_ws::tls_server::TlsAcceptor) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let frps = self.clone();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let (frps, acceptor) = (frps.clone(), acceptor.clone());
                tokio::spawn(async move {
                    // frp's TLS starts with one byte, 0x17, that frps reads first.
                    let mut first = [0u8; 1];
                    if tcp.read_exact(&mut first).await.is_err() || first[0] != 0x17 {
                        return;
                    }
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    let frps2 = frps.clone();
                    mux::serve(tls, move |stream| {
                        let frps = frps2.clone();
                        tokio::spawn(async move { frps.stream(stream).await });
                    })
                    .await;
                });
            }
        });
        port
    }

    fn refuse(&self, words: &str) -> String {
        self.refused.lock().unwrap().push(words.to_string());
        words.to_string()
    }

    /// A stream's first message, in clear, says what it is.
    async fn stream(self: Arc<Frps>, mut s: DuplexStream) {
        let Some((kind, m)) = read_msg(&mut s).await else { return };
        match kind {
            b'o' => self.control(s, m).await,
            b'w' => self.work(s, m).await,
            b'v' => self.visitor(s, m).await,
            _ => {}
        }
    }

    async fn control(self: Arc<Frps>, mut s: DuplexStream, login: Value) {
        let ts = login["timestamp"].as_i64().unwrap_or(0);
        if login["privilege_key"].as_str() != Some(auth_key(TOKEN, ts).as_str()) {
            let words = self.refuse("token in login doesn't match token from configuration");
            write_msg(&mut s, b'1', &json!({ "version": "0.71.1", "error": words })).await;
            return;
        }
        let n = self.logins.fetch_add(1, Ordering::SeqCst);
        let run_id = format!("run-{n}");
        write_msg(&mut s, b'1', &json!({ "version": "0.71.1", "run_id": run_id, "error": "" })).await;
        let (work_tx, work_rx) = mpsc::unbounded_channel();
        self.runs.lock().unwrap().insert(run_id.clone(), work_tx);
        let work_rx = Arc::new(tokio::sync::Mutex::new(work_rx));
        // From here, each side's bytes are AES-128-CFB, after its own IV.
        let key = cfb::key(TOKEN.as_bytes());
        let (mut r, mut w) = tokio::io::split(s);
        let mut iv = [0u8; 16];
        if r.read_exact(&mut iv).await.is_err() {
            return;
        }
        let mut dec = Cfb::decrypter(&key, &iv);
        let ours: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let mut enc = Cfb::encrypter(&key, &ours);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(u8, Value)>();
        tokio::spawn(async move {
            if w.write_all(&ours).await.is_err() {
                return;
            }
            while let Some((kind, body)) = out_rx.recv().await {
                let mut bytes = frame(kind, &body);
                enc.apply(&mut bytes);
                if w.write_all(&bytes).await.is_err() {
                    return;
                }
            }
        });
        let mut plain = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            while let Some((kind, body, used)) = parse(&plain) {
                plain.drain(..used);
                match kind {
                    b'p' => {
                        let name = body["proxy_name"].as_str().unwrap_or("").to_string();
                        let sk = body["sk"].as_str().unwrap_or("").to_string();
                        let (ask, mut asks) = mpsc::unbounded_channel();
                        let service = Service { sk, ask, work: work_rx.clone() };
                        let taken = self.services.lock().unwrap().insert(name.clone(), service).is_some();
                        let error = if taken { format!("proxy [{name}] is already in use") } else { String::new() };
                        let _ = out_tx.send((b'2', json!({ "proxy_name": name, "remote_addr": "", "error": error })));
                        let out = out_tx.clone();
                        tokio::spawn(async move {
                            while asks.recv().await.is_some() {
                                let _ = out.send((b'r', json!({})));
                            }
                        });
                    }
                    b'h' => {
                        let ts = body["timestamp"].as_i64().unwrap_or(0);
                        let ok = body["privilege_key"].as_str() == Some(auth_key(TOKEN, ts).as_str());
                        let error = if ok { "" } else { "token in heartbeat doesn't match token from configuration" };
                        let _ = out_tx.send((b'4', json!({ "error": error })));
                    }
                    _ => {}
                }
            }
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let mut piece = buf[..n].to_vec();
                    dec.apply(&mut piece);
                    plain.extend_from_slice(&piece);
                }
            }
        }
    }

    async fn work(self: Arc<Frps>, mut s: DuplexStream, m: Value) {
        let ts = m["timestamp"].as_i64().unwrap_or(0);
        if m["privilege_key"].as_str() != Some(auth_key(TOKEN, ts).as_str()) {
            let words = self.refuse("token in NewWorkConn doesn't match token from configuration");
            write_msg(&mut s, b's', &json!({ "error": words })).await;
            return;
        }
        let run = self.runs.lock().unwrap().get(m["run_id"].as_str().unwrap_or("")).cloned();
        if let Some(run) = run {
            let _ = run.send(s);
        }
    }

    async fn visitor(self: Arc<Frps>, mut s: DuplexStream, m: Value) {
        let name = m["proxy_name"].as_str().unwrap_or("").to_string();
        let ts = m["timestamp"].as_i64().unwrap_or(0);
        let found = {
            let services = self.services.lock().unwrap();
            services.get(&name).map(|sv| (sv.sk.clone(), sv.ask.clone(), sv.work.clone()))
        };
        let Some((sk, ask, work)) = found else {
            let words = self.refuse(&format!("custom listener for [{name}] doesn't exist"));
            write_msg(&mut s, b'3', &json!({ "proxy_name": name, "error": words })).await;
            return;
        };
        if m["sign_key"].as_str() != Some(auth_key(&sk, ts).as_str()) {
            let words = self.refuse(&format!("visitor connection of [{name}] auth failed"));
            write_msg(&mut s, b'3', &json!({ "proxy_name": name, "error": words })).await;
            return;
        }
        self.visits.fetch_add(1, Ordering::SeqCst);
        write_msg(&mut s, b'3', &json!({ "proxy_name": name, "error": "" })).await;
        let _ = ask.send(());
        let got = tokio::time::timeout(Duration::from_secs(10), async { work.lock().await.recv().await }).await;
        let Ok(Some(mut w)) = got else { return };
        let start = json!({ "proxy_name": name, "src_addr": "", "dst_addr": "", "src_port": 0, "error": "" });
        write_msg(&mut w, b's', &start).await;
        let _ = tokio::io::copy_bidirectional(&mut s, &mut w).await;
    }
}

/// A message of frp's wire v1: its type, the length as an i64 of eight
/// bytes big-endian, and its JSON.
fn frame(kind: u8, body: &Value) -> Vec<u8> {
    let json = body.to_string().into_bytes();
    let mut out = vec![kind];
    out.extend_from_slice(&(json.len() as i64).to_be_bytes());
    out.extend_from_slice(&json);
    out
}

fn parse(buf: &[u8]) -> Option<(u8, Value, usize)> {
    if buf.len() < 9 {
        return None;
    }
    let len = i64::from_be_bytes(buf[1..9].try_into().unwrap()) as usize;
    if buf.len() < 9 + len {
        return None;
    }
    let body = serde_json::from_slice(&buf[9..9 + len]).ok()?;
    Some((buf[0], body, 9 + len))
}

async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Option<(u8, Value)> {
    let mut head = [0u8; 9];
    r.read_exact(&mut head).await.ok()?;
    let len = i64::from_be_bytes(head[1..9].try_into().unwrap());
    if !(0..=10_240).contains(&len) {
        return None;
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await.ok()?;
    Some((head[0], serde_json::from_slice(&body).ok()?))
}

async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, kind: u8, body: &Value) {
    let _ = w.write_all(&frame(kind, body)).await;
    let _ = w.flush().await;
}
