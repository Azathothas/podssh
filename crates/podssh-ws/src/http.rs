//! The little HTTP/1.1 podssh needs besides the WebSocket upgrade: `pod-proxy`'s
//! (one request and one response over an already-open stream, with bounded
//! sizes, and a server's reading of a request, [`request`]), with podssh's
//! user agent.

pub use pod_proxy::http::*;

use tokio::io::{AsyncRead, AsyncWrite};

/// Send one request and read the response, closing nothing, with
/// `User-Agent: podssh/VERSION`. `extra_headers` must not contain CR or LF
/// (they are refused). The response body is capped at `max_body` bytes.
pub async fn exchange<S>(
    stream: &mut S,
    method: &str,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    max_body: usize,
) -> std::io::Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let user_agent = crate::dial::user_agent();
    pod_proxy::http::exchange(stream, &user_agent, method, host, path, extra_headers, body, max_body).await
}
