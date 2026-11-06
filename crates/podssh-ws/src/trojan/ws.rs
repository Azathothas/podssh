//! Trojan over a WebSocket over TLS (trojan-go's `websocket`, Xray-core's
//! `ws`): the upgrade goes to the link's path with the link's `host`, which
//! the server checks whole (another path is its fallback's or a 404), then
//! each binary message is a piece of the stream, both ways, as VLESS's
//! WebSocket carries its own (`crate::vless::ws`, whose pump this road
//! shares). The request rides the first message; no early data goes in a
//! header.

use tokio::io::DuplexStream;

use super::link::Server;
use super::TrojanError;
use crate::client::{self, ConnectError};
use crate::session::RelaySession;
use crate::vless::Dial;
use crate::{handshake, url};

/// The largest message taken.
const RECEIVE_CAP: usize = 1024 * 1024;

/// The upgrade, then Trojan's request in the first binary message.
pub(super) async fn open(server: &Server, first: Vec<u8>, dial: &Dial<'_>) -> Result<DuplexStream, TrojanError> {
    let key = handshake::generate_key().map_err(|e| TrojanError::Carry(e.to_string()))?;
    let request = request(server, &key);
    let tls = client::open_tls(&server.host, server.port, &server.sni, dial.trust, dial.proxy, dial.timeout)
        .await
        .map_err(|e| failed(e, &server.path))?;
    let stream = url::Stream::Tls(Box::new(tls));
    let upgraded = tokio::time::timeout(dial.timeout, client::upgrade_with(stream, &request, &key))
        .await
        .map_err(|_| TrojanError::Carry(format!("no answer to the upgrade within {} s", dial.timeout.as_secs())))?;
    let (stream, pending) = upgraded.map_err(|e| failed(e, &server.path))?;
    let idle = Some(client::DEFAULT_IDLE_TIMEOUT);
    let session = RelaySession::new(stream, pending, idle, client::WRITE_TIMEOUT).naming("the Trojan server");
    session.set_receive_cap(RECEIVE_CAP);
    session
        .send_binary(&first)
        .await
        .map_err(|e| TrojanError::Carry(format!("sending Trojan's request failed: {e}")))?;
    Ok(crate::vless::ws::spawn(session, dial.close_at_end))
}

/// The upgrade request: the link's path and `Host`, no subprotocol and no
/// `Origin`, as Xray-core's and trojan-go's clients send it.
fn request(server: &Server, key: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        server.path,
        server.authority,
        url::USER_AGENT
    )
    .into_bytes()
}

/// A failure of the dial or the upgrade, in this road's words.
pub(super) fn failed(e: ConnectError, path: &str) -> TrojanError {
    let path = path.split('?').next().unwrap_or("/");
    match e {
        ConnectError::Dial(e) => TrojanError::Dial(e),
        ConnectError::Refused { status, body } => {
            let said = if body.is_empty() { String::new() } else { format!(" ({body})") };
            let why = format!(
                "the WebSocket upgrade at {path}{said}; a path that it does not serve, or a proxy or a front end \
                 that does not pass the upgrade, answers so: type=tcp is Trojan in TLS alone"
            );
            TrojanError::Refused { status, why }
        }
        ConnectError::Tls(why) => TrojanError::Carry(format!("TLS: {why}")),
        ConnectError::Upgrade(why) => TrojanError::Carry(format!("the WebSocket upgrade: {why}")),
        other => TrojanError::Carry(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upgrade_names_the_link_s_path_and_host_and_no_subprotocol() {
        let link =
            ["trojan://", "s3cr3t", "@203.0.113.9:443?type=ws&sni=t.example&host=cdn.example&path=%2Ftr"].concat();
        let server = Server::parse(&link).unwrap();
        let text = String::from_utf8(request(&server, "dGhlIHNhbXBsZSBub25jZQ==")).unwrap();
        assert!(text.starts_with("GET /tr HTTP/1.1\r\nHost: cdn.example\r\n"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("sec-websocket-protocol"), "{text}");
        let refused = failed(ConnectError::Refused { status: 404, body: String::new() }, "/tr?x=1");
        let line = refused.line("trojan://203.0.113.9:443/tr", "h:22");
        assert!(line.contains("refused the WebSocket upgrade at /tr;") && line.ends_with("HTTP 404"), "{line}");
    }
}
