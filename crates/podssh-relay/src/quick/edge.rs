//! The edge of a quick tunnel (T-300): where it is, and its TLS. The SRV
//! record `_v2-origintunneld._tcp.argotunnel.com`, which cloudflared asks
//! for, read by DNS over HTTPS through the proxy (T-339); when it does not
//! name two regions under `argotunnel.com`, the two names that Cloudflare's
//! documents give, which it named in that order (measured, T-299), and TCP
//! port 7844, directly or through a CONNECT proxy that allows it. TLS with
//! the name `h2.cftunnel.com` and no ALPN, and cloudflared's roots beside
//! podssh's (measured: the edge's certificate chains to the first of them,
//! and to no root of the system).

use std::time::Duration;

use podssh_ws::resolve::Srv;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

/// The record whose targets are the edge's regions (cloudflared's
/// `edgediscovery/allregions/discovery.go`).
pub const SRV_NAME: &str = "_v2-origintunneld._tcp.argotunnel.com";
/// The regions and the port when the record names none.
pub const REGIONS: [&str; 2] = ["region1.v2.argotunnel.com", "region2.v2.argotunnel.com"];
pub const PORT: u16 = 7844;
/// The day that the first of cloudflared's roots ends, which doctor names
/// (a test reads it off the certificates).
pub const ROOTS_FIRST_END: &str = "2029-08-15";
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
    // Three or more: a later release of cloudflared may add one (T-339).
    if added < 3 || invalid != 0 {
        return Err(format!("cloudflared's roots gave {added} anchors and {invalid} that do not parse, not 3 or more"));
    }
    Ok(roots)
}

/// Where the edge is: its regions, its port, and why the fixed names stand
/// in, when they do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub regions: Vec<String>,
    pub port: u16,
    pub fixed: Option<String>,
}

impl Edge {
    /// The names of Cloudflare's documents, and port 7844, for `why`.
    pub fn fixed(why: String) -> Edge {
        Edge { regions: REGIONS.iter().map(|r| r.to_string()).collect(), port: PORT, fixed: Some(why) }
    }
}

/// The regions and the port of an SRV answer, by priority: two targets
/// under `argotunnel.com` on one port, as the record names them; else none,
/// as an answer of another shape is not one that podssh knows.
pub fn choose(records: &[Srv]) -> Option<(Vec<String>, u16)> {
    let mut sorted = records.to_vec();
    sorted.sort_by_key(|r| (r.priority, std::cmp::Reverse(r.weight)));
    let regions: Vec<String> = sorted.iter().map(|r| r.target.clone()).collect();
    let port = sorted.first()?.port;
    let shaped = regions.len() == 2 && regions[0] != regions[1] && sorted.iter().all(|r| r.port == port);
    (shaped && regions.iter().all(|r| r.ends_with(".argotunnel.com"))).then_some((regions, port))
}

/// The edge, by its SRV record through `proxy` within the dial's limit; the
/// fixed names when the record is not read, or names no edge that podssh
/// knows.
pub async fn find(proxy: &ProxyChoice) -> Edge {
    match podssh_ws::resolve::doh_srv(SRV_NAME, proxy, Instant::now() + DIAL_LIMIT).await {
        Ok(records) => match choose(&records) {
            Some((regions, port)) => Edge { regions, port, fixed: None },
            None => Edge::fixed(format!(
                "the edge's SRV record named {} target(s), not two under argotunnel.com on one port",
                records.len()
            )),
        },
        Err(why) => Edge::fixed(format!("the edge's SRV record was not read: {why}")),
    }
}

/// The trust of the edge's TLS over HTTP/2.
pub fn trust() -> Result<Trust, String> {
    let config = podssh_ws::tls::client_config(&roots()?).map_err(|e| e.to_string())?;
    Trust::caller(config).map_err(|e| e.to_string())
}

/// A TLS connection to `edge`: each region in turn, through `proxy` when
/// there is one; the failure of each when none answers.
pub async fn connect(proxy: &ProxyChoice, edge: &Edge) -> Result<Box<dyn EdgeIo>, String> {
    let trust = trust()?;
    let (mut failed, port) = (Vec::new(), edge.port);
    for region in &edge.regions {
        let tcp = match podssh_ws::dial::dial(region, port, proxy, DIAL_LIMIT).await {
            Ok(tcp) => tcp,
            Err(e) => {
                failed.push(format!("{region}:{port}: {e}"));
                continue;
            }
        };
        match podssh_ws::tls::connect_over(tcp, SERVER_NAME, &trust, DIAL_LIMIT).await {
            Ok(tls) => return Ok(Box::new(tls)),
            Err(e) => failed.push(format!("{region}:{port}: {e}")),
        }
    }
    Err(format!("no region of the edge answered: {}", failed.join("; ")))
}

/// The edge's TLS on a road of HTTP/2, as the node serves it: boxed, so that
/// each road gives one type, and owned, so that a task of its own serves it
/// (T-400).
pub trait EdgeIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> EdgeIo for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflared_s_three_roots_parse_and_join_podssh_s() {
        assert!(trust().is_ok());
        let certs = podssh_ws::bundle::pem_certificates(CLOUDFLARE_ROOTS.as_bytes()).unwrap();
        assert_eq!(certs.len(), 3);
    }

    /// A DER element at the start of `der`: its tag, its contents, and the
    /// rest.
    fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, rest) = der.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = match first {
            0..0x80 => (first as usize, rest),
            _ => {
                let n = (first & 0x7f) as usize;
                if n == 0 || n > 4 || rest.len() < n {
                    return None;
                }
                (rest[..n].iter().fold(0usize, |len, byte| (len << 8) | *byte as usize), &rest[n..])
            }
        };
        (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
    }

    /// A certificate's notAfter as `YYYY-MM-DD` (RFC 5280, 4.1): the
    /// TBSCertificate, past its version, serial, signature and issuer, to
    /// the second time of its validity.
    fn not_after(cert: &[u8]) -> Option<String> {
        let (_, certificate, _) = element(cert)?;
        let (_, mut tbs, _) = element(certificate)?;
        if element(tbs)?.0 == 0xA0 {
            tbs = element(tbs)?.2;
        }
        for _ in 0..3 {
            tbs = element(tbs)?.2;
        }
        let (_, validity, _) = element(tbs)?;
        let (tag, time, _) = element(element(validity)?.2)?;
        let text = std::str::from_utf8(time).ok()?;
        match tag {
            // UTCTime, YYMMDDHHMMSSZ: 50 to 99 are of the 1900s.
            0x17 => {
                let yy: u32 = text.get(0..2)?.parse().ok()?;
                let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
                Some(format!("{year}-{}-{}", text.get(2..4)?, text.get(4..6)?))
            }
            0x18 => Some(format!("{}-{}-{}", text.get(0..4)?, text.get(4..6)?, text.get(6..8)?)),
            _ => None,
        }
    }

    #[test]
    fn the_first_end_of_cloudflared_s_roots_is_the_day_that_doctor_names() {
        let certs = podssh_ws::bundle::pem_certificates(CLOUDFLARE_ROOTS.as_bytes()).unwrap();
        let ends: Vec<String> = certs.iter().map(|c| not_after(c.as_ref()).expect("a notAfter")).collect();
        // The file's comments, read off each certificate by OpenSSL.
        assert_eq!(ends, ["2029-08-15", "2029-08-15", "2029-11-01"]);
        assert_eq!(ends.iter().min().map(String::as_str), Some(ROOTS_FIRST_END));
    }

    fn srv(priority: u16, port: u16, target: &str) -> Srv {
        Srv { priority, weight: 1, port, target: target.to_string() }
    }

    #[test]
    fn two_targets_under_argotunnel_com_are_the_edge_and_others_are_not() {
        let (r1, r2) = ("region1.v2.argotunnel.com", "region2.v2.argotunnel.com");
        // The answer measured in T-299, in either order: by priority.
        let two = choose(&[srv(2, 7844, r2), srv(1, 7844, r1)]);
        assert_eq!(two, Some((vec![r1.to_string(), r2.to_string()], 7844)));
        assert_eq!(choose(&[srv(1, 7845, r1), srv(2, 7845, r2)]).map(|(_, port)| port), Some(7845));
        // One, none, a name elsewhere, two ports, or one target twice.
        for odd in [
            vec![srv(1, 7844, r1)],
            vec![],
            vec![srv(1, 7844, r1), srv(2, 7844, "region2.example.com")],
            vec![srv(1, 7844, r1), srv(2, 7845, r2)],
            vec![srv(1, 7844, r1), srv(2, 7844, r1)],
            vec![srv(1, 7844, r1), srv(2, 7844, r2), srv(3, 7844, "region3.v2.argotunnel.com")],
        ] {
            assert_eq!(choose(&odd), None, "{odd:?}");
        }
        let fixed = Edge::fixed("why".into());
        assert_eq!((fixed.regions.len(), fixed.port, fixed.fixed.as_deref()), (2, PORT, Some("why")));
    }
}
