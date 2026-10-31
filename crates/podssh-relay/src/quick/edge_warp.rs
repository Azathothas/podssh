//! The quick tunnel's edge inside WARP's tunnel (T-374), feature `warp`: a
//! node whose cage allows ports 443, 80 and 8443 alone reaches the edge's
//! TCP port 7844 as any target of WARP's road (T-352), over HTTP/2 to
//! Cloudflare's endpoint on 443. Each region of the edge is a TCP stream
//! inside the tunnel, its name asked inside it, then the edge's TLS of
//! [`super::edge`] over that stream, and the client of T-300 on it as it is.
//! The request for a tunnel to `api.trycloudflare.com` goes as before,
//! through the proxy.

use podssh_ws::Trust;
use tokio::io::{AsyncRead, AsyncWrite};

use super::edge::{Edge, DIAL_LIMIT, SERVER_NAME};

/// The road's words, as the node says how it registered.
pub const ROAD: &str = "HTTP/2 inside WARP's tunnel";

/// The edge's TLS on either road, as the node serves it.
pub trait EdgeIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> EdgeIo for T {}

/// A TLS connection to `edge` inside `warp`'s tunnel, trusted as `trust`
/// says (the node's: [`super::edge::trust`]): each region in turn; the
/// failure of each when none answers. It holds the tunnel while it lasts.
pub async fn connect(warp: &podssh_warp::Warp, edge: &Edge, trust: &Trust) -> Result<Box<dyn EdgeIo>, String> {
    let (mut failed, port) = (Vec::new(), edge.port);
    for region in &edge.regions {
        let stream = match warp.connect(region, port, DIAL_LIMIT).await {
            Ok(stream) => stream,
            Err(e) => {
                failed.push(format!("{region}:{port}: {e}"));
                continue;
            }
        };
        match podssh_ws::tls::connect_over(stream, SERVER_NAME, trust, DIAL_LIMIT).await {
            Ok(tls) => return Ok(Box::new(tls)),
            Err(e) => failed.push(format!("{region}:{port}: {e}")),
        }
    }
    Err(format!("no region of the edge answered inside WARP's tunnel: {}", failed.join("; ")))
}
