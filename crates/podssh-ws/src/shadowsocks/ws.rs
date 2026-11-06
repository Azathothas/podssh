//! Shadowsocks in a WebSocket (T-493), as Outline's servers serve it:
//! outline-ss-server's listener `websocket-stream` (since 1.9.0) on a path
//! of a web server that a TLS front covers, and the Outline SDK's client,
//! which writes the AEAD stream in binary messages and reads only binary
//! ones back (`x/websocket/endpoint.go`, `gorillaConn`). The WebSocket
//! here is podssh's own, dialed as each road dials (TLS checked for the
//! URL's host, through the proxy of the environment), and its messages are
//! the stream's bytes; the Shadowsocks stream above it is the one of raw
//! TCP, byte for byte.

use std::time::Duration;

use tokio::io::DuplexStream;

use crate::client::ConnectError;
use crate::dial::ProxyChoice;
use crate::forwarder::{carry, Form, Note};
use crate::tls::Trust;
use crate::url::WsUrl;

/// The largest message taken from the server: outline-ss-server writes
/// what a read of its target gave, far under it.
const RECEIVE_CAP: usize = 1024 * 1024;

/// The other end, in the words of a failure of the WebSocket.
const PEER: &str = "the Shadowsocks server's WebSocket";

/// Why the WebSocket to a server did not open: its URL shown with no path,
/// as the path is often the server's secret.
pub fn failure(url: &WsUrl, e: &ConnectError) -> String {
    let shown = format!("{}://{}/...", if url.tls { "wss" } else { "ws" }, url.host_header());
    match e {
        // outline-ss-server's web server answers a path that it does not
        // serve with 404, and an upgrade that it refuses with its status.
        ConnectError::Refused { status: 404, .. } => {
            format!("{shown} has no WebSocket at the key's path (HTTP 404): the path is not the server's")
        }
        ConnectError::Refused { status, body } if body.is_empty() => {
            format!("{shown} refused the upgrade: HTTP {status}")
        }
        ConnectError::Refused { status, body } => format!("{shown} refused the upgrade: HTTP {status}: {body}"),
        ConnectError::Tls(why) => format!("TLS with {} failed: {why}", url.host),
        ConnectError::Upgrade(why) => format!("the WebSocket upgrade with {shown} failed: {why}"),
        other => format!("{shown}: {other}"),
    }
}

/// The WebSocket at `url` as a stream of bytes: each write a binary message,
/// each binary message read back as bytes. The end of this side's bytes
/// waits for the server's end, as the target may still answer (a pipe's).
pub async fn open(url: &WsUrl, trust: &Trust, proxy: &ProxyChoice, timeout: Duration) -> Result<DuplexStream, String> {
    let session = crate::url::dial(url, trust, proxy, timeout, None).await.map_err(|e| failure(url, &e))?;
    let session = session.naming(PEER);
    session.set_receive_cap(RECEIVE_CAP);
    // A text message is no part of the stream: Outline's server sends none.
    let note: Note = std::sync::Arc::new(|_: &str| {});
    let (carried, _first) = carry::spawn(session, Form::Query, false, note, PEER);
    // The copying tasks run on when the handle goes; the stream's end is
    // theirs, and the Shadowsocks stream above it reads it.
    Ok(carried.stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_shows_the_host_and_never_the_path() {
        let url = WsUrl::parse("wss://ss.example/SECRET/tcp").unwrap();
        let lost = failure(&url, &ConnectError::Refused { status: 404, body: "Not Found".into() });
        assert!(lost.contains("wss://ss.example/...") && lost.contains("not the server's"), "{lost}");
        assert!(!lost.contains("SECRET"), "{lost}");
        let refused = failure(&url, &ConnectError::Refused { status: 403, body: String::new() });
        assert_eq!(refused, "wss://ss.example/... refused the upgrade: HTTP 403");
    }
}
