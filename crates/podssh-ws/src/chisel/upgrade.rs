//! The upgrade to a chisel server (T-490): the request, as chisel's client
//! sends it (gorilla's dialer with the subprotocol `chisel-v3`), and the
//! server's answer. A chisel server answers with a 101 that names no
//! subprotocol; an upgrade that it does not take, or a server that is not
//! chisel's, gets its reverse proxy's answer or a 404 "Not found"
//! (`server/server_handler.go` at v1.13.0).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ChiselError, SUBPROTOCOL};
use crate::client::{ConnectError, UPGRADE_HEAD};
use crate::{handshake, http, text};

/// The upgrade request: `GET TARGET` with the subprotocol. It holds no
/// secret: the password goes inside the SSH that follows.
pub fn request(host_header: &str, target: &str, key: &str) -> String {
    format!(
        "GET {target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n",
        crate::url::USER_AGENT
    )
}

/// Send `request` on `stream` and read the answer: the stream and the bytes
/// after the head on a 101, else why not.
pub async fn upgrade<S>(mut stream: S, request: &[u8], key: &str) -> Result<(S, Vec<u8>), ChiselError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io = |e: std::io::Error| ChiselError::Connect(ConnectError::Upgrade(e.to_string()));
    stream.write_all(request).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        if buf.len() > UPGRADE_HEAD {
            let why = "its answer's head did not end within 16 KiB".to_string();
            return Err(ChiselError::Connect(ConnectError::Upgrade(why)));
        }
        let n = stream.read(&mut chunk).await.map_err(io)?;
        if n == 0 {
            let why = "it closed the connection before it answered the upgrade".to_string();
            return Err(ChiselError::Connect(ConnectError::Upgrade(why)));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let not_http = |why: String| {
        ChiselError::Connect(ConnectError::Upgrade(format!("its answer is no HTTP: {}", text::one_line(&why))))
    };
    let (status, reason, _headers) = http::parse_head(&head).map_err(not_http)?;
    if status == 101 {
        let not_ws = |e: crate::error::WsError| {
            ChiselError::Connect(ConnectError::Upgrade(format!("its 101 is no WebSocket's: {e}")))
        };
        handshake::check_response(&head, key).map_err(not_ws)?;
        return Ok((stream, buf.split_off(end)));
    }
    // A short, bounded read of the body, which holds the server's words.
    let body = tokio::time::timeout(Duration::from_secs(3), http::read_response(&mut stream, buf, 4096))
        .await
        .ok()
        .and_then(Result::ok)
        .map(|r| r.body_text(200))
        .unwrap_or_default();
    Err(ChiselError::Refused { status, words: words(status, &reason, &body) })
}

/// The words of a refusal: the server's own, then what they mean.
pub fn words(status: u16, reason: &str, body: &str) -> String {
    let said = text::one_line(if body.trim().is_empty() { reason } else { body });
    let meaning = match (status, said.trim()) {
        (404, "Not found") => format!(
            "the words of a chisel server that did not take the upgrade, as one older than the subprotocol \
             {SUBPROTOCOL} (chisel 1.7 and before speak another), or of another server on that path"
        ),
        _ => "not the answer of a chisel server, which takes each upgrade with the subprotocol: a server in front \
              of it, or another server, answered"
            .to_string(),
    };
    match said.is_empty() {
        true => meaning,
        false => format!("{said}; {meaning}"),
    }
}
