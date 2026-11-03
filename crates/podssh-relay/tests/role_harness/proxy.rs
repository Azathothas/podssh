//! A stand-in HTTP CONNECT proxy on the loopback, as the host's proxy of the
//! relay role (T-457): it keeps the head of each request, answers each with
//! the status line that it was given, and after a `2xx` carries the bytes to
//! the test's target, whatever host the CONNECT named, as a proxy that
//! reaches it would. And a target that greets each connection with a line.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::LIMIT;

/// The proxy, where it listens, and the heads that it took.
pub struct StandIn {
    pub port: u16,
    heads: Arc<Mutex<Vec<String>>>,
}

impl StandIn {
    /// A proxy that answers `status` (`200 Connection Established`, `403
    /// Forbidden`), then, for a `2xx`, carries the tunnel to `127.0.0.1:target`.
    pub async fn start(status: &'static str, target: u16) -> StandIn {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
        let port = listener.local_addr().unwrap().port();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let kept = heads.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(tunnel(tcp, status, target, kept.clone()));
            }
        });
        StandIn { port, heads }
    }

    /// The proxy's URL, with `userinfo` (`user:password@`) when one is given.
    pub fn url(&self, userinfo: &str) -> String {
        format!("http://{userinfo}127.0.0.1:{}", self.port)
    }

    /// The first line of each request that it took, in order.
    pub fn asked(&self) -> Vec<String> {
        let heads = self.heads.lock().unwrap();
        heads.iter().map(|head| head.lines().next().unwrap_or_default().to_string()).collect()
    }

    /// Each head that it took, whole.
    pub fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

async fn tunnel(mut tcp: TcpStream, status: &'static str, target: u16, kept: Arc<Mutex<Vec<String>>>) {
    let Some(head) = head_of(&mut tcp).await else { return };
    kept.lock().unwrap().push(head);
    let answer = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
    if tcp.write_all(answer.as_bytes()).await.is_err() || !status.starts_with('2') {
        return;
    }
    let Ok(mut far) = TcpStream::connect(("127.0.0.1", target)).await else { return };
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut far).await;
}

/// A request's head, byte by byte, so that nothing of the tunnel is read.
async fn head_of(tcp: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(LIMIT, tcp.read(&mut byte)).await {
            Ok(Ok(1)) if head.len() < 16 * 1024 => head.push(byte[0]),
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// A target on the loopback that sends `line` to each connection, then
/// reads until its end.
pub async fn greeting(line: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = tcp.write_all(line.as_bytes()).await;
                let mut sink = vec![0u8; 4096];
                while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
            });
        }
    });
    port
}
