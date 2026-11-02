//! What the tests of the Piping Server road run against: nwtgck's own
//! servers, started on the loopback by the command that a variable names
//! (`PODSSH_TEST_PIPING_JS` for nwtgck/piping-server, as `npm install -g
//! piping-server@1.12.9` gives it, the server of `ppng.io`;
//! `PODSSH_TEST_PIPING_RUST` for nwtgck/piping-server-rust's binary); a dial
//! of the loopback in place of TLS; and a stand-in of a proxy that ends TLS,
//! as a cloud container's does: it refuses each request that asks for an
//! upgrade, and holds each request's body until its end.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpStream as StdStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::piping::dial::{BoxIo, Dial, Dialing, Proto};
use podssh_relay::piping::http1::{Framing, Reader};
use podssh_relay::piping::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;

/// How long a server may take to answer `/version`.
const READY_LIMIT: Duration = Duration::from_secs(30);

/// Which of nwtgck's servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// nwtgck/piping-server, in Node: HTTP/1.1 on its plain port.
    Js,
    /// nwtgck/piping-server-rust: HTTP/1.1, and HTTP/2 by prior knowledge.
    Rust,
}

impl Kind {
    fn variable(self) -> &'static str {
        match self {
            Kind::Js => "PODSSH_TEST_PIPING_JS",
            Kind::Rust => "PODSSH_TEST_PIPING_RUST",
        }
    }
}

/// A server on the loopback, stopped when it is dropped.
pub struct Running {
    pub port: u16,
    pub kind: Kind,
    child: Child,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The server of `kind` on a free port of the loopback; else why it cannot
/// run here, for a line of "did not run".
pub fn start(kind: Kind) -> Result<Running, String> {
    let command = std::env::var(kind.variable())
        .ok()
        .filter(|command| !command.trim().is_empty())
        .ok_or_else(|| format!("{} names no command of the server", kind.variable()))?;
    let mut words = command.split_whitespace();
    let program = words.next().unwrap_or_default();
    let free = std::net::TcpListener::bind("127.0.0.1:0").and_then(|listener| listener.local_addr());
    let port = free.map_err(|e| format!("no free port of the loopback: {e}"))?.port();
    let child = Command::new(program)
        .args(words)
        .args(["--host", "127.0.0.1", "--http-port", &port.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{command}: {e}"))?;
    let running = Running { port, kind, child };
    let deadline = Instant::now() + READY_LIMIT;
    while !answers(port) {
        if Instant::now() > deadline {
            return Err(format!("{command} did not answer /version within {} s", READY_LIMIT.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(running)
}

/// Whether the server on `port` answers `GET /version` with 200.
fn answers(port: u16) -> bool {
    let Ok(mut stream) = StdStream::connect(("127.0.0.1", port)) else { return false };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if stream.write_all(b"GET /version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").is_err() {
        return false;
    }
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    answer.starts_with(b"HTTP/1.1 200") || answer.starts_with(b"HTTP/1.0 200")
}

/// The server's name in each request: the loopback.
pub fn server() -> Server {
    Server::parse("https://127.0.0.1").expect("a server")
}

/// TCP to the loopback's `port`, speaking `proto`, in place of TLS.
pub fn dial(port: u16, proto: Proto) -> Dial {
    Arc::new(move |_: &Server| -> Dialing {
        Box::pin(async move {
            let tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
            let _ = tcp.set_nodelay(true);
            Ok((Box::new(tcp) as BoxIo, proto))
        })
    })
}

/// A stand-in of a proxy that ends TLS: one request for each connection,
/// sent on to the server of `upstream` once its body ended; a request that
/// asks for an upgrade gets 403 and the proxy's own words.
pub struct Holding {
    pub port: u16,
    task: AbortHandle,
}

impl Drop for Holding {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The words of the stand-in's refusal of an upgrade.
pub const REFUSAL: &str = "WebSocket upgrades are not allowed by this proxy";

impl Holding {
    pub async fn start(upstream: u16) -> Holding {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
        let port = listener.local_addr().expect("its address").port();
        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(hold(client, upstream));
            }
        });
        Holding { port, task: task.abort_handle() }
    }
}

async fn hold(mut client: TcpStream, upstream: u16) {
    let mut buf = Vec::new();
    let end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let mut chunk = [0u8; 4096];
        match client.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let rest = buf.split_off(end);
    let lines: Vec<&str> = head.split("\r\n").filter(|line| !line.is_empty()).collect();
    let header = |name: &str| {
        lines.iter().skip(1).find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_ascii_lowercase())
        })
    };
    if header("upgrade").is_some() {
        let length = REFUSAL.len();
        let top = format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n");
        let answer = format!("{top}{REFUSAL}");
        let _ = client.write_all(answer.as_bytes()).await;
        return;
    }
    // The whole body, held: of its length, or to its last chunk.
    let framing = if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        Framing::Chunked
    } else {
        Framing::Length(header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0))
    };
    let (read, mut write) = client.split();
    let Ok(body) = Reader::new(read, rest, framing).all(16 << 20).await else { return };
    let mut forward = format!("{}\r\n", lines[0]);
    for line in &lines[1..] {
        let name = line.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        if !matches!(name.as_str(), "transfer-encoding" | "content-length" | "connection") {
            forward.push_str(&format!("{line}\r\n"));
        }
    }
    forward.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    let Ok(mut server) = TcpStream::connect(("127.0.0.1", upstream)).await else { return };
    if server.write_all(forward.as_bytes()).await.is_err() || server.write_all(&body).await.is_err() {
        return;
    }
    let _ = tokio::io::copy(&mut server, &mut write).await;
    let _ = write.shutdown().await;
}
