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

/// The edge of Cloudflare's tunnels: the service `cloudflare-tunnel-edge` of
/// `pod-services`, which holds its record, its regions, its names and its
/// roots.
pub fn service() -> &'static pod_services::Service {
    pod_services::get("cloudflare-tunnel-edge").expect("pod-services holds the service cloudflare-tunnel-edge")
}

/// The record whose targets are the edge's regions (cloudflared's
/// `edgediscovery/allregions/discovery.go`): the fact `srv-name`.
pub fn srv_name() -> &'static str {
    service().text("srv-name").expect("cloudflare-tunnel-edge of pod-services holds the fact srv-name")
}

/// The regions when the record names none: the endpoints of the role `h2`.
pub fn regions() -> Vec<&'static str> {
    service().endpoints_of("h2").map(|e| e.host()).collect()
}

/// The port when the record names none: the port of the role `h2`.
pub fn port() -> u16 {
    service().endpoints_of("h2").next().map_or(7844, |e| e.port())
}

/// The day that the first of cloudflared's roots ends, which doctor names:
/// the fact `roots-first-end` (`pod-services` reads it off the certificates).
pub fn roots_first_end() -> String {
    service().date("roots-first-end").map(|d| d.to_string()).unwrap_or_default()
}

/// The name of the edge's certificate for HTTP/2 (cloudflared's
/// `connection/protocol.go`): the SNI of the role `h2`.
pub fn server_name() -> &'static str {
    service().endpoints_of("h2").next().map(|e| e.server_name()).expect("cloudflare-tunnel-edge has the role h2")
}

/// How long each TCP connection and each TLS handshake may take.
pub const DIAL_LIMIT: Duration = Duration::from_secs(10);

/// cloudflared's three roots: the fact `roots`.
fn cloudflare_roots() -> &'static str {
    service().text("roots").expect("cloudflare-tunnel-edge of pod-services holds the fact roots")
}

/// The roots of the edge's TLS, over either transport: podssh's, and
/// cloudflared's three.
pub fn roots() -> Result<podssh_ws::tls::TlsRoots, String> {
    let mut roots = podssh_ws::tls::default_roots();
    let certs = podssh_ws::bundle::pem_certificates(cloudflare_roots().as_bytes())?;
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
        Edge { regions: regions().into_iter().map(str::to_string).collect(), port: port(), fixed: Some(why) }
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
    match podssh_ws::resolve::doh_srv(srv_name(), proxy, Instant::now() + DIAL_LIMIT).await {
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
        match podssh_ws::tls::connect_over(tcp, server_name(), &trust, DIAL_LIMIT).await {
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

impl Edge {
    /// The edge as the connection `conn_index` dials it: its regions turned
    /// by the index, so that the node's second connection (1, and 3 after a
    /// GOAWAY) starts at the second region, and a region in trouble leaves
    /// one connection standing (T-402); the other region stays, in turn.
    pub fn for_connection(&self, conn_index: u8) -> Edge {
        let mut regions = self.regions.clone();
        let count = regions.len();
        if count > 0 {
            regions.rotate_left(usize::from(conn_index) % count);
        }
        Edge { regions, ..self.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflared_s_three_roots_parse_and_join_podssh_s() {
        assert!(trust().is_ok());
        let certs = podssh_ws::bundle::pem_certificates(cloudflare_roots().as_bytes()).unwrap();
        assert_eq!(certs.len(), 3);
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
        assert_eq!((fixed.regions.len(), fixed.port, fixed.fixed.as_deref()), (2, port(), Some("why")));
    }

    #[test]
    fn each_connection_starts_at_its_own_region() {
        let found = Edge::fixed("why".into());
        assert_eq!(found.for_connection(0).regions, [regions()[0], regions()[1]]);
        assert_eq!(found.for_connection(1).regions, [regions()[1], regions()[0]]);
        // The connections that replace them after a GOAWAY, 2 and 3.
        assert_eq!(found.for_connection(2), found.for_connection(0));
        assert_eq!(found.for_connection(3), found.for_connection(1));
        assert_eq!((found.for_connection(1).port, found.for_connection(1).fixed), (port(), Some("why".into())));
        let one = Edge { regions: vec!["only.argotunnel.com".into()], port: port(), fixed: None };
        assert_eq!(one.for_connection(1).regions, ["only.argotunnel.com"]);
        let none = Edge { regions: Vec::new(), port: port(), fixed: None };
        assert!(none.for_connection(1).regions.is_empty());
    }
}
