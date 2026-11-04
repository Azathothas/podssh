//! Whether a relay host offers the resumable layer on its forward road: the
//! field `forward.layer` of its `/relays.json`, `true` (T-173). A relay of the
//! contract has no such field, and a document that cannot be read offers
//! nothing, so a client asks for the layer only where a host said so.

use std::time::Duration;

use podssh_ws::client::open_tls;
use podssh_ws::{dial, http, ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::relay::Relay;

/// Whether the `/relays.json` body `body` offers the layer.
pub fn offered(body: &[u8]) -> bool {
    let doc: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    doc.get("forward").and_then(|forward| forward.get("layer")) == Some(&serde_json::Value::Bool(true))
}

/// Ask `relay`, over TLS through `proxy`, within `timeout` for each step:
/// whether it offers the layer. `Err` says why its document was not read.
pub async fn ask(relay: &Relay, trust: &Trust, proxy: &ProxyChoice, timeout: Duration) -> Result<bool, String> {
    if crate::open::offline() {
        return Err(format!("{} is set, so podssh does not connect anywhere", crate::open::OFFLINE_ENV));
    }
    let mut tls =
        open_tls(&relay.host, relay.port, &relay.host, trust, proxy, timeout).await.map_err(|e| e.to_string())?;
    let host_header = if relay.port == 443 { relay.host.clone() } else { dial::authority(&relay.host, relay.port) };
    tokio::time::timeout(timeout, over(&mut tls, &host_header))
        .await
        .map_err(|_| format!("/relays.json took more than {} s", timeout.as_secs()))?
}

/// Ask over `stream`, a connection to the host: its `/relays.json`, read up
/// to the pool's bound on the body. A status that is not 2xx is a relay with
/// no such document, which offers nothing.
pub async fn over<S>(stream: &mut S, host_header: &str) -> Result<bool, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let accept = [("Accept", "application/json")];
    let response = http::exchange(stream, "GET", host_header, "/relays.json", &accept, b"", crate::pool::MAX_BODY)
        .await
        .map_err(|e| format!("/relays.json: {e}"))?;
    Ok((200..300).contains(&response.status) && offered(&response.body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_true_of_forward_layer_is_an_offer() {
        assert!(offered(br#"{"service":"tcp-ssh-relay","forward":{"layer":true}}"#));
        for body in [
            &br#"{"service":"tcp-ssh-relay","pool":[]}"#[..],
            br#"{"forward":{"layer":"yes"}}"#,
            br#"{"forward":{"layer":false}}"#,
            br#"{"forward":true}"#,
            br#"{"layer":true}"#,
            b"not json",
            b"",
        ] {
            assert!(!offered(body), "{}", String::from_utf8_lossy(body));
        }
    }
}
