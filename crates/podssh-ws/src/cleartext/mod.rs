//! The cleartext road on the relay's port (T-326, the operator's ruling
//! Q45): the upgrade of [`crate::connect`] over the stream that the dial
//! gave, with no TLS, for a proxy that tunnels CONNECT but cuts TLS that it
//! does not know, by its SNI or its certificate. Each hop reads what crosses
//! it, the token's header among them, so the caller gives a token of one
//! session alone and tries this road last, once its TLS failed on the way
//! ([`tls_failed`]); SSH inside stays end to end. [`probe`] asks a host in
//! cleartext with nothing secret, as GitHub #56 asks, and names what came
//! back.

mod probe;

pub use probe::{probe, Heard, PLAIN_TO_TLS, PROBE_PATH};

use crate::client::{upgrade, ConnectError, WsClientConfig};
use crate::dial;
use crate::session::RelaySession;

/// The step of the upgrade in a bound's words.
const UPGRADE_STEP: &str = "the WebSocket upgrade in cleartext";

/// Whether the TLS road failed in TLS itself, once its connection opened: a
/// certificate that is not the relay's (a proxy that answers with its own),
/// a reset or a close in the handshake, or its bound. The cleartext road may
/// pass where TLS failed so; not where the dial failed, as its CONNECT is
/// the same, nor where the relay answered, as TLS passed there.
pub fn tls_failed(e: &ConnectError) -> bool {
    matches!(e, ConnectError::Tls(_) | ConnectError::Timeout { step: "the TLS handshake", .. })
}

/// Dial `config`'s endpoint through its proxy, and upgrade at its path with
/// `token` in the `X-Relay-Token` header, as [`crate::connect`] does, with
/// no TLS; its trust and its server name are not used. Each hop reads the
/// token, so the caller gives a token of one session alone.
pub async fn connect(config: &WsClientConfig, token: &str) -> Result<RelaySession, ConnectError> {
    // The rules of a path and a token are those of `connect`.
    config.validate().map_err(ConnectError::Config)?;
    if token.contains(['\r', '\n']) {
        return Err(ConnectError::Config("the relay token contains a line break".into()));
    }
    let at = &config.endpoint;
    let tcp = dial::dial(&at.host, at.port, &config.proxy, config.timeout).await.map_err(ConnectError::Dial)?;
    let host_header = dial::authority(&at.host, at.port);
    let (tcp, pending) = tokio::time::timeout(config.timeout, upgrade(tcp, &host_header, &at.path, token))
        .await
        .map_err(|_| ConnectError::Timeout { step: UPGRADE_STEP, after: config.timeout })??;
    Ok(RelaySession::over_cleartext(tcp, pending, config.idle_timeout))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::cut::TlsFailure;

    /// TLS's own failures and its bound may pass in cleartext; a dial, the
    /// relay's answer and another bound may not.
    #[test]
    fn only_a_failure_of_tls_itself_is_one_that_cleartext_may_pass() {
        let after = Duration::from_secs(20);
        assert!(tls_failed(&ConnectError::Tls(TlsFailure::from("invalid peer certificate: UnknownIssuer"))));
        assert!(tls_failed(&ConnectError::Timeout { step: "the TLS handshake", after }));
        let unreached = crate::DialError::Connect { target: "r:443".into(), detail: "refused".into(), cut: None };
        for other in [
            ConnectError::Dial(unreached),
            ConnectError::Refused { status: 403, body: "forward: missing or wrong token".into() },
            ConnectError::Timeout { step: "the WebSocket upgrade", after },
            ConnectError::Upgrade("no 101".into()),
            ConnectError::Config("a path".into()),
        ] {
            assert!(!tls_failed(&other), "{other:?}");
        }
    }
}
