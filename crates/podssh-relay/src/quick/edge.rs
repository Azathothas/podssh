//! The edge of a quick tunnel (T-300): where it is, and its TLS. The two
//! names that Cloudflare's documents give, which the SRV record
//! `_v2-origintunneld._tcp.argotunnel.com` named in that order (measured,
//! T-299); TCP port 7844, directly or through a CONNECT proxy that allows
//! it; TLS with the name `h2.cftunnel.com` and no ALPN, and cloudflared's
//! three roots beside podssh's (measured: the edge's certificate chains to
//! the first of them, and to no root of the system).

use std::time::Duration;

use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};

pub const REGIONS: [&str; 2] = ["region1.v2.argotunnel.com", "region2.v2.argotunnel.com"];
pub const PORT: u16 = 7844;
/// The name of the edge's certificate for HTTP/2 (cloudflared's
/// `connection/protocol.go`).
pub const SERVER_NAME: &str = "h2.cftunnel.com";
/// How long each TCP connection and each TLS handshake may take.
pub const DIAL_LIMIT: Duration = Duration::from_secs(10);

const CLOUDFLARE_ROOTS: &str = include_str!("cloudflare-roots.pem");

/// The roots of the edge's TLS, over either transport: podssh's, and
/// cloudflared's three.
pub fn roots() -> Result<podssh_ws::tls::TlsRoots, String> {
    let mut roots = podssh_ws::tls::default_roots();
    let certs = podssh_ws::bundle::pem_certificates(CLOUDFLARE_ROOTS.as_bytes())?;
    let (added, invalid) = roots.roots.add_parsable_certificates(certs);
    if added != 3 || invalid != 0 {
        return Err(format!("cloudflared's roots gave {added} anchors and {invalid} that do not parse, not 3"));
    }
    Ok(roots)
}

/// The trust of the edge's TLS over HTTP/2.
pub fn trust() -> Result<Trust, String> {
    let config = podssh_ws::tls::client_config(&roots()?).map_err(|e| e.to_string())?;
    Trust::caller(config).map_err(|e| e.to_string())
}

/// A TLS connection to the edge: each region in turn, through `proxy` when
/// there is one; the failure of each when none answers.
pub async fn connect(proxy: &ProxyChoice) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send, String> {
    let trust = trust()?;
    let mut failed = Vec::new();
    for region in REGIONS {
        let tcp = match podssh_ws::dial::dial(region, PORT, proxy, DIAL_LIMIT).await {
            Ok(tcp) => tcp,
            Err(e) => {
                failed.push(format!("{region}:{PORT}: {e}"));
                continue;
            }
        };
        match podssh_ws::tls::connect_over(tcp, SERVER_NAME, &trust, DIAL_LIMIT).await {
            Ok(tls) => return Ok(tls),
            Err(e) => failed.push(format!("{region}:{PORT}: {e}")),
        }
    }
    Err(format!("no region of the edge answered: {}", failed.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflared_s_three_roots_parse_and_join_podssh_s() {
        assert!(trust().is_ok());
        let certs = podssh_ws::bundle::pem_certificates(CLOUDFLARE_ROOTS.as_bytes()).unwrap();
        assert_eq!(certs.len(), 3);
    }
}
