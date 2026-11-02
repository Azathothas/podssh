//! The upgrade of a tunnel (T-441): the request, as wstunnel's client sends
//! it, and the server's answer, said in the words of the version that sends
//! them. A wstunnel server answers a tunnel with 101 and the subprotocol `v1`
//! once the target is dialed, or refuses it with a 400 whose body names no
//! cause: "Invalid request" from 10 on (`bad_request` of
//! `erebe/wstunnel:wstunnel/src/tunnel/server/utils.rs` at v11.1.0, and at
//! v10.0.1), "Invalid upgrade request" before (`src/tunnel/server.rs` at
//! v9.7.4). The server's log names the cause.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::{Secret, WstunnelError};
use crate::client::{ConnectError, UPGRADE_HEAD};
use crate::{handshake, http, text};

/// The subprotocol of the request and of the server's 101, since 7.
pub const SUBPROTOCOL: &str = "v1";

/// The versions whose protocol podssh speaks, as a line names them.
pub const VERSIONS: &str = "wstunnel 9.1 to 11";

/// The refusal of wstunnel 10 and later, for each cause.
pub const REFUSED_10: &str = "Invalid request";

/// The refusal of wstunnel 9 and before, for each cause.
pub const REFUSED_9: &str = "Invalid upgrade request";

/// The upgrade request of a tunnel: `GET /PREFIX/events`, the token after
/// the subprotocol `v1`, and the `Authorization` of the secret when it has
/// one. It holds the secret, so it is wiped when dropped.
pub fn request(host_header: &str, secret: &Secret, token: &str, key: &str) -> Zeroizing<String> {
    // Room for all of it: a String that grows leaves a copy of the secret.
    let room = 512 + host_header.len() + token.len() + secret.prefix().len();
    let mut r = Zeroizing::new(String::with_capacity(room + secret.authorization().map_or(0, str::len)));
    // Pieces, not format!, so that no other copy of the secret is made.
    r.push_str("GET /");
    r.push_str(secret.prefix());
    r.push_str("/events HTTP/1.1\r\n");
    r.push_str(&format!("Host: {host_header}\r\nUser-Agent: {}\r\n", crate::url::USER_AGENT));
    r.push_str("Upgrade: websocket\r\nConnection: Upgrade\r\n");
    r.push_str(&format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"));
    r.push_str(&format!("Sec-WebSocket-Protocol: {SUBPROTOCOL}, {}{token}\r\n", super::PREFIX));
    if let Some(value) = secret.authorization() {
        r.push_str("Authorization: ");
        r.push_str(value);
        r.push_str("\r\n");
    }
    r.push_str("\r\n");
    r
}

/// Send `request` on `stream` and read the answer: the stream and the bytes
/// after the head on a 101 of wstunnel's, else why not.
pub async fn upgrade<S>(mut stream: S, request: &[u8], key: &str) -> Result<(S, Vec<u8>), WstunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io = |e: std::io::Error| WstunnelError::Connect(ConnectError::Upgrade(e.to_string()));
    stream.write_all(request).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        if buf.len() > UPGRADE_HEAD {
            return Err(WstunnelError::NotWstunnel("its answer's head did not end within 16 KiB".into()));
        }
        let n = stream.read(&mut chunk).await.map_err(io)?;
        if n == 0 {
            let why = "it closed the connection before it answered the upgrade".to_string();
            return Err(WstunnelError::Connect(ConnectError::Upgrade(why)));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let not_http = |why: String| WstunnelError::NotWstunnel(format!("its answer is no HTTP: {}", text::one_line(&why)));
    let (status, reason, headers) = http::parse_head(&head).map_err(not_http)?;
    if status == 101 {
        let not_ws = |e: crate::error::WsError| WstunnelError::NotWstunnel(format!("its 101 is no WebSocket's: {e}"));
        handshake::check_response(&head, key).map_err(not_ws)?;
        let chosen = headers.iter().find(|(name, _)| name == "sec-websocket-protocol").map(|(_, v)| v.as_str());
        if chosen != Some(SUBPROTOCOL) {
            return Err(WstunnelError::NotWstunnel(no_subprotocol(chosen)));
        }
        return Ok((stream, buf.split_off(end)));
    }
    // A short, bounded read of the body, which holds the server's words.
    let body = tokio::time::timeout(Duration::from_secs(3), http::read_response(&mut stream, buf, 4096))
        .await
        .ok()
        .and_then(Result::ok)
        .map(|r| r.body_text(200))
        .unwrap_or_default();
    Err(WstunnelError::Refused { status, words: words(status, &reason, &body) })
}

/// Why a 101 is not a tunnel of wstunnel's: each server of 7 and later
/// names the subprotocol `v1`.
fn no_subprotocol(chosen: Option<&str>) -> String {
    let gave = match chosen {
        Some(other) => format!("it named the subprotocol {:?}", text::one_line(other)),
        None => "it named no subprotocol".to_string(),
    };
    format!(
        "its 101 lacks wstunnel's subprotocol v1 ({gave}): another server answered, or a wstunnel whose protocol \
         podssh does not speak; podssh speaks that of {VERSIONS}"
    )
}

/// The words of a refusal: the server's own, then what they mean in the
/// version that says them.
pub fn words(status: u16, reason: &str, body: &str) -> String {
    let said = text::one_line(if body.trim().is_empty() { reason } else { body });
    let meaning = match (status, said.as_str()) {
        (400, REFUSED_10) => "the words of wstunnel 10 and later for each refusal: a path prefix or an Authorization \
                              that it does not take, a target that its restrictions do not allow, or one that it \
                              could not reach; its log names which"
            .to_string(),
        (400, w) if w.starts_with(REFUSED_9) => format!(
            "the words of wstunnel 9 and before for each refusal: a path prefix that it does not take, a target that \
             its restrictions do not allow or that it could not reach, or a server of 9.0 or before, which cannot \
             read the token of {VERSIONS}; its log names which"
        ),
        _ => "not the answer of a wstunnel server, which refuses with 400: a server in front of it, or another \
              server, answered"
            .to_string(),
    };
    match said.is_empty() {
        true => meaning,
        false => format!("{said}; {meaning}"),
    }
}
