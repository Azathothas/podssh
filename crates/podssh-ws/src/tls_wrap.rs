//! A verified TLS handshake over a stream that is open already: the relay's
//! TCP connection, or an SSH channel that reaches a hop inside TLS
//! (`ssh+tls://`, T-372). Each road takes the same configuration and the
//! same messages of failure.

use std::time::Duration;

use crate::client::ConnectError;
use crate::tls::{self, Trust};

/// A verified TLS handshake for `server_name` over `stream`, within
/// `timeout`.
pub async fn tls_over<S>(
    stream: S,
    server_name: &str,
    trust: &Trust,
    timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<S>, ConnectError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let tls_config = tls::config_for(trust).map_err(|e| ConnectError::Config(e.to_string()))?;
    let name = rustls_pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| ConnectError::Config(format!("{server_name:?} is not a valid server name: {e}")))?;
    // The connector gets its config explicitly, never a process default.
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .map_err(|_| ConnectError::Timeout { step: "the TLS handshake", after: timeout })?
        // rustls's text distinguishes an unknown issuer from a name mismatch,
        // and an unknown issuer gets what to do (T-340).
        .map_err(|e| ConnectError::Tls(crate::tls::handshake_failure(&e)))
}
