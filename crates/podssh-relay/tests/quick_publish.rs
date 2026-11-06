//! A funnel through the stand-in edge of T-300 (T-180): the node of `podssh
//! funnel` registered on one end of a pipe, its origin TARGET for each path,
//! and the test as the edge, which sends each visitor's request over the
//! HTTP/2 of the registered connection with cloudflared's headers. TARGET is
//! Python's `http.server`, software that podssh did not write, over TCP and
//! over a Unix socket: a GET whose answer comes in chunks, decoded as it
//! comes; a POST of 100 KiB with no length, which goes to TARGET in chunks as
//! it comes, with `Connection: close`; and a WebSocket's upgrade, which a
//! WebSocket echo answers, its frames back untouched. Each says "did not
//! run" with no Python here. Planted: an origin that takes each body whole
//! first (`Origin::streams` false), and the POST gets a 413.
#![cfg(feature = "quick")]

mod quick_harness;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use h2::SendStream;
use http::Request;
use podssh_relay::quick::funnel::{Dial, Dialed, Funnel, Stream, TLS_LINE};
use podssh_relay::quick::headers;
use podssh_relay::quick::origin::{Origin, Visitors};
use podssh_relay::quick::serve::serve;
use podssh_ws::frame::{self, Frame, Role};
use quick_harness::{echo, register, registration, LIMIT};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

/// The tunnel's name, as the API gives one.
const NAME: &str = "podssh-funnel.trycloudflare.com";

/// TARGET's server: a GET answered in three chunks; a POST, with a length
/// or in chunks, answered with its body's SHA-256 and the Connection header
/// that it came with.
const SERVER: &str = r#"
import hashlib, http.server, socketserver, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args): pass
    def address_string(self): return "test"
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for part in (b"hello ", b"from ", b"python"):
            self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
        self.wfile.write(b"0\r\n\r\n")
        self.close_connection = True
    def do_POST(self):
        body = b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        out = (hashlib.sha256(body).hexdigest() + " " + self.headers.get("Connection", "-")).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
        self.close_connection = True

mode, where, ready = sys.argv[1], sys.argv[2], sys.argv[3]
if mode == "tcp":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    open(ready + ".tmp", "w").write(str(server.server_address[1]))
else:
    class U(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
    server = U(where, H)
    open(ready + ".tmp", "w").write("ready")
import os
os.rename(ready + ".tmp", ready)
server.serve_forever()
"#;

/// Python's server in a scratch directory of its own, which goes with it.
struct Python {
    child: Child,
    dir: PathBuf,
}

impl Drop for Python {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The server over `mode`, `tcp` or `unix`: it and its port, or its
/// socket's path; `None` with no Python here.
fn python(mode: &str) -> Option<(Python, String)> {
    let program = ["python3", "python"].into_iter().find(|p| {
        Command::new(p).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
    })?;
    let dir = std::env::temp_dir().join(format!("podssh-funnel-{mode}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (script, socket, ready) = (dir.join("server.py"), dir.join("app.sock"), dir.join("ready"));
    std::fs::write(&script, SERVER).unwrap();
    let child = Command::new(program)
        .arg("-I")
        .arg(&script)
        .args([mode, &socket.display().to_string(), &ready.display().to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let server = Python { child, dir };
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "Python's server did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let at = match mode {
        "tcp" => std::fs::read_to_string(&ready).unwrap(),
        _ => socket.display().to_string(),
    };
    Some((server, at))
}

/// A dial of TCP to `port` on the loopback, for each request.
fn tcp(port: u16) -> Dial {
    Arc::new(move || {
        Box::pin(async move {
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
            Ok(Box::new(tcp) as Box<dyn Stream>)
        }) as Dialed
    })
}

/// A dial of the Unix socket at `path`, for each request.
#[cfg(unix)]
fn unix(path: String) -> Dial {
    Arc::new(move || {
        let path = path.clone();
        Box::pin(async move {
            let unix = tokio::net::UnixStream::connect(&path).await.map_err(|e| e.to_string())?;
            Ok(Box::new(unix) as Box<dyn Stream>)
        }) as Dialed
    })
}

/// The funnel's node, registered at the stand-in edge: the edge's sender.
async fn funnel(dial: Dial) -> (SendRequest<Bytes>, oneshot::Sender<()>) {
    let origin: Arc<dyn Origin> = Arc::new(Funnel::new(dial, Arc::new(|line| eprintln!("funnel: {line}"))));
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
    // The control stream stays open for the test.
    std::mem::forget((to_node, from_node));
    (edge, stop)
}

/// Send `bytes` as the node's window lets them go.
async fn send_all(send: &mut SendStream<Bytes>, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len());
        let room = std::future::poll_fn(|cx| send.poll_capacity(cx)).await.unwrap().unwrap();
        let take = room.min(bytes.len());
        if take > 0 {
            send.send_data(Bytes::copy_from_slice(&bytes[..take]), false).unwrap();
            bytes = &bytes[take..];
        }
    }
}

/// One visitor's request, as the edge sends it, `body` in pieces with no
/// length: the status, the origin's headers, and the body.
async fn ask(
    edge: &SendRequest<Bytes>,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let request = Request::builder().method(method).uri(format!("https://{NAME}{path}")).body(()).unwrap();
    let mut edge = edge.clone().ready().await.unwrap();
    let (answer, mut send) = edge.send_request(request, body.is_none()).unwrap();
    if let Some(body) = body {
        for piece in body.chunks(8 * 1024) {
            send_all(&mut send, piece).await;
        }
        send.send_data(Bytes::new(), true).unwrap();
    }
    let answer = tokio::time::timeout(LIMIT, answer).await.expect("an answer in time").unwrap();
    let status = answer.status().as_u16();
    let serialized = answer.headers().get(headers::RESPONSE_HEADERS).and_then(|v| v.to_str().ok());
    let origin = serialized.and_then(headers::deserialize).unwrap_or_default();
    let mut recv = answer.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = tokio::time::timeout(LIMIT, recv.data()).await.expect("the body in time") {
        let chunk = chunk.unwrap();
        let _ = recv.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
    (status, origin, got)
}

/// The GET and the POST of one TARGET.
async fn get_and_post(dial: Dial) {
    let (edge, _stop) = funnel(dial).await;
    let (status, origin, body) = ask(&edge, "GET", "/hello", None).await;
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8(body).unwrap(), "hello from python", "the chunks decoded");
    assert!(!origin.iter().any(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding")), "{origin:?}");
    let upload: Vec<u8> = (0..100 * 1024u32).map(|i| (i % 251) as u8).collect();
    let want: String = Sha256::digest(&upload).iter().map(|b| format!("{b:02x}")).collect();
    let (status, _, body) = ask(&edge, "POST", "/sum", Some(&upload)).await;
    assert_eq!(status, 200, "a body of 100 KiB with no length: {}", String::from_utf8_lossy(&body));
    assert_eq!(String::from_utf8(body).unwrap(), format!("{want} close"), "the body whole, Connection: close");
}

#[tokio::test]
async fn a_funnel_serves_python_over_tcp_a_get_in_chunks_and_a_post_with_no_length() {
    let Some((_python, port)) = python("tcp") else {
        eprintln!("did not run: no Python here");
        return;
    };
    get_and_post(tcp(port.trim().parse().unwrap())).await;
}

#[cfg(unix)]
#[tokio::test]
async fn a_funnel_serves_python_over_a_unix_socket() {
    let Some((_python, path)) = python("unix") else {
        eprintln!("did not run: no Python here");
        return;
    };
    get_and_post(unix(path)).await;
}

/// A WebSocket echo on the loopback: one upgrade, then each message back.
async fn websocket_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if tcp.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let key = text
                    .lines()
                    .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-key")))
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default();
                let accept = podssh_ws::handshake::accept_key(&key);
                let answer = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                tcp.write_all(answer.as_bytes()).await.unwrap();
                let (mut inbox, mut chunk) = (Vec::new(), vec![0u8; 4096]);
                loop {
                    let n = tcp.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    inbox.extend_from_slice(&chunk[..n]);
                    while let Ok(Some((frame, used))) = frame::decode(&inbox, Role::Client) {
                        inbox.drain(..used);
                        let back = Frame { fin: true, opcode: frame.opcode, payload: frame.payload };
                        tcp.write_all(&frame::encode(&back, Role::Server, [0; 4])).await.unwrap();
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn a_websocket_passes_through_the_funnel_to_target_and_back() {
    let (edge, _stop) = funnel(tcp(websocket_echo().await)).await;
    let request = Request::builder()
        .method("GET")
        .uri(format!("https://{NAME}/ws"))
        .header(headers::UPGRADE, headers::WEBSOCKET)
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .unwrap();
    let mut ready = edge.ready().await.unwrap();
    let (answer, mut send) = ready.send_request(request, false).unwrap();
    let answer = tokio::time::timeout(LIMIT, answer).await.expect("an answer in time").unwrap();
    assert_eq!(answer.status().as_u16(), 200, "a 101 over HTTP/2");
    let serialized = answer.headers().get(headers::RESPONSE_HEADERS).and_then(|v| v.to_str().ok()).unwrap();
    let origin = headers::deserialize(serialized).unwrap();
    assert!(origin
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("sec-websocket-accept") && v == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    let message = Frame { fin: true, opcode: 0x1, payload: b"through the funnel".to_vec() };
    send_all(&mut send, &frame::encode(&message, Role::Client, [1, 2, 3, 4])).await;
    let mut recv = answer.into_body();
    let mut inbox = Vec::new();
    let back = loop {
        if let Ok(Some((frame, _))) = frame::decode(&inbox, Role::Server) {
            break frame;
        }
        let chunk = tokio::time::timeout(LIMIT, recv.data()).await.expect("the echo in time").unwrap().unwrap();
        let _ = recv.flow_control().release_capacity(chunk.len());
        inbox.extend_from_slice(&chunk);
    };
    assert_eq!(back.payload, b"through the funnel");
}

#[test]
fn the_funnel_s_line_says_who_reads_its_traffic() {
    assert_eq!(TLS_LINE, "TLS ends at Cloudflare's edge; Cloudflare can read this traffic.");
}
