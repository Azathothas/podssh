//! RFC 8484 over HTTP/2, for a resolver that serves no HTTP/1.1: Quad9
//! answered a GET of HTTP/1.1 with `505`, and the same GET over HTTP/2 with
//! its answer (2026-10-31, from GitHub's runners and through a proxy). RFC
//! 8484 asks for HTTP/2 at least (section 5.2); the other resolvers serve
//! HTTP/1.1 too, which podssh's own client speaks.

use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::dial::{self, ProxyChoice};
use crate::http::Response;

/// `config` offering `h2` alone, so that a server that chose another
/// protocol is refused before a byte of HTTP is sent.
pub fn config_h2(config: &Arc<ClientConfig>) -> Arc<ClientConfig> {
    let mut config = (**config).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// TLS for `name` (a resolver's address, or its name through a proxy) with
/// ALPN `h2` over `stream`, then one GET of `target`.
pub async fn get_over<S>(
    config: &Arc<ClientConfig>,
    stream: S,
    name: &str,
    target: &str,
    accept: &str,
    max: usize,
) -> Result<Response, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server = rustls_pki_types::ServerName::try_from(name.to_string()).map_err(|e| e.to_string())?;
    let tls = tokio_rustls::TlsConnector::from(config_h2(config))
        .connect(server, stream)
        .await
        .map_err(|e| format!("TLS: {}", crate::tls::handshake_failure(&e)))?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err("the resolver did not take HTTP/2".into());
    }
    get(tls, name, target, accept, max).await
}

/// The same through `proxy` when one is set: the proxy is asked for `host`,
/// the resolver's name or its address (T-405), and TLS checks the same.
pub(super) async fn get_via(
    config: &Arc<ClientConfig>,
    host: &str,
    target: &str,
    accept: &str,
    max: usize,
    proxy: &ProxyChoice,
    limit: Duration,
) -> Result<Response, String> {
    let ask = async {
        let stream = dial::dial(host, 443, proxy, limit).await.map_err(|e| e.to_string())?;
        get_over(config, stream, host, target, accept, max).await
    };
    tokio::time::timeout(limit, ask).await.map_err(|_| format!("no answer within {} s", limit.as_secs()))?
}

/// One GET over an HTTP/2 connection of its own. The connection is driven in
/// a task that ends with this call.
async fn get<S>(stream: S, name: &str, target: &str, accept: &str, max: usize) -> Result<Response, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client, connection) = h2::client::handshake(stream).await.map_err(|e| format!("HTTP/2: {e}"))?;
    let mut driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let answer = ask(client, name, target, accept, max).await;
    // With the request's handles gone, h2 ends the connection itself: GOAWAY,
    // then TLS's close_notify, which a resolver reads as an end and not as a
    // torn socket. In the background, so that the answer waits for nothing
    // and no caller's bound can lose it; bounded, for a server that takes
    // no more bytes, and dropped with the runtime at worst.
    tokio::spawn(async move {
        if tokio::time::timeout(CLOSE, &mut driver).await.is_err() {
            driver.abort();
        }
    });
    answer
}

/// The bound of the connection's own end, after the answer.
const CLOSE: Duration = Duration::from_secs(2);

async fn ask(
    client: h2::client::SendRequest<bytes::Bytes>,
    name: &str,
    target: &str,
    accept: &str,
    max: usize,
) -> Result<Response, String> {
    let mut client = client.ready().await.map_err(|e| format!("HTTP/2: {e}"))?;
    let request = ::http::Request::get(format!("https://{name}{target}"))
        .header("accept", accept)
        .body(())
        .map_err(|e| format!("HTTP/2: {e}"))?;
    let (response, _) = client.send_request(request, true).map_err(|e| format!("HTTP/2: {e}"))?;
    let response = response.await.map_err(|e| format!("HTTP/2: {e}"))?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| format!("HTTP/2: {e}"))?;
        let _ = body.flow_control().release_capacity(chunk.len());
        if out.len() + chunk.len() > max {
            return Err(format!("an answer over {max} bytes"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Response { status, reason: String::new(), headers: Vec::new(), body: out })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration offers `h2` alone, and the caller's is unchanged.
    #[test]
    fn only_h2_is_offered() {
        let config = crate::tls::config_for(&crate::Trust::Default).unwrap();
        let h2 = config_h2(&config);
        assert_eq!(h2.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(config.alpn_protocols.is_empty());
    }
}
