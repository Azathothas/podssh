//! A verified TLS handshake over a stream that is open already: the relay's
//! TCP connection, or an SSH channel that reaches a hop inside TLS
//! (`ssh+tls://`, T-372). Each road takes the same configuration and the
//! same messages of failure: `pod-tls`'s, in the process's context.

use std::time::Duration;

use crate::client::ConnectError;
use crate::tls::{self, Trust};

/// A verified TLS handshake for `server_name` over `stream`, within
/// `timeout`. rustls's text distinguishes an unknown issuer from a name
/// mismatch, and an unknown issuer gets what to do (T-340); the kind of a cut
/// is kept beside it (T-487).
pub async fn tls_over<S>(
    stream: S,
    server_name: &str,
    trust: &Trust,
    timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<S>, ConnectError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tls::context().tls_over(stream, server_name, trust, timeout).await.map_err(|e| tls::connect_error(e, timeout))
}
