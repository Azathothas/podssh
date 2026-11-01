//! The road as one call: [`Warp::open`] opens the tunnel of a device and
//! its stack; [`Warp::connect`] opens a TCP stream to `HOST:PORT` inside it,
//! a name asked of the resolver inside the tunnel first.
//!
//! The probe (T-352's Approach, step 2) is the opening itself: the CONNECT
//! to the endpoint's address through the proxy, then TLS against the
//! pinned key. A proxy that allows listed names alone refuses the first,
//! or cuts the second. A certificate of another key is a proxy's that
//! re-terminates TLS, or the front door's own new key (T-399):
//! [`Warp::open_reading`] asks WARP's API for the device's record again,
//! and tries a new key that the API gives; else the proxy is named, and the
//! road is not tried again in the run.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use podssh_ws::dial::{self, DialError, ProxyChoice};

use crate::device::Device;
use crate::register::{self, Api};
use crate::stack::{Link, Stack};
use crate::stream::Stream;
use crate::tunnel::{self, Opening};

/// The issuer of the certificate that a proxy which re-terminates TLS
/// showed, for each proxy and endpoint where the road met one in this run.
type Met = (Option<String>, SocketAddr, String);
static INTERCEPTED: Mutex<Vec<Met>> = Mutex::new(Vec::new());

/// How long the road waits before its last try with the key that WARP's
/// API gave: a new connection may reach another server of the front door.
pub const RETRY_AFTER: Duration = Duration::from_secs(1);

/// Why the road did not open, in a line for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// The way out does not reach the endpoint: the proxy refused it, the
    /// network did not carry it.
    Unreachable(String),
    /// A proxy re-terminates TLS, and the road cannot pass it.
    Intercepted(String),
    /// The edge refused this device: it is not enrolled, or it is gone.
    Device(String),
    /// The edge failed or answered as podssh does not read.
    Edge(String),
    /// This host's part.
    Local(String),
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::Unreachable(line)
            | Fault::Intercepted(line)
            | Fault::Device(line)
            | Fault::Edge(line)
            | Fault::Local(line) => f.write_str(line),
        }
    }
}

/// The proxy that carries a connection to `ip`, as `proxy` chooses one.
fn proxy_for(ip: &str, proxy: &ProxyChoice) -> Option<String> {
    match proxy {
        ProxyChoice::Direct => None,
        ProxyChoice::Via(p) => Some(p.to_string()),
        ProxyChoice::FromEnvironment => dial::proxy_from_env(ip).ok().flatten().map(|p| p.to_string()),
    }
}

/// The line of a failed opening, through `proxied` when a proxy carried it.
pub fn fault(opening: Opening, endpoint: SocketAddr, proxied: Option<&str>) -> Fault {
    let at = endpoint.to_string();
    match opening {
        Opening::Dial(DialError::ProxyRefused { proxy, status, reason, .. }) => Fault::Unreachable(format!(
            "the proxy {proxy} refused CONNECT {at} ({status} {reason}): WARP's road asks for an address, which a \
             proxy that allows listed names alone refuses (podssh doctor's line egress takes says which)"
        )),
        Opening::Dial(e) => Fault::Unreachable(format!("WARP's endpoint {at} was not reached: {e}")),
        Opening::Intercepted { issuer } => Fault::Intercepted(format!(
            "a proxy re-terminates TLS: the endpoint {at} showed a certificate of {issuer}, not of WARP's key, \
             so the road cannot pass it{}",
            proxied.map(|p| format!(" ({p})")).unwrap_or_default()
        )),
        Opening::NotEnrolled(why) => Fault::Device(format!(
            "WARP's endpoint {at} took no certificate of this device ({why}): its key is not enrolled, or the \
             device is gone; remove its record to register a new one"
        )),
        Opening::Tls(why) => match proxied {
            Some(proxy) if cut(&why) => Fault::Unreachable(format!(
                "the proxy {proxy} took the CONNECT to {at}, and the TLS through it was cut ({why}): it may allow \
                 listed names alone (podssh doctor's line egress takes says which)"
            )),
            _ => Fault::Edge(format!("TLS with WARP's endpoint {at}: {why}")),
        },
        Opening::Http2(why) => Fault::Edge(format!("HTTP/2 with WARP's endpoint {at}: {why}")),
        Opening::Refused { status } => match status {
            401 | 403 => {
                Fault::Device(format!("WARP's endpoint {at} refused the tunnel of this device (HTTP {status})"))
            }
            _ => Fault::Edge(format!("WARP's endpoint {at} refused the tunnel (HTTP {status})")),
        },
        Opening::Timeout(step) => Fault::Unreachable(format!("{step} ({at}) did not end in time")),
        Opening::Local(why) => Fault::Local(why),
    }
}

/// Whether a failure of TLS reads as a connection that was cut.
fn cut(why: &str) -> bool {
    let lower = why.to_ascii_lowercase();
    ["reset", "eof", "closed", "broken pipe", "unexpected end"].iter().any(|w| lower.contains(w))
}

/// The issuer that a proxy which re-terminates TLS showed on the way to
/// `endpoint` through `proxy` (none: directly), in this run.
pub fn intercepted(proxy: Option<&str>, endpoint: SocketAddr) -> Option<String> {
    let met = INTERCEPTED.lock().unwrap_or_else(PoisonError::into_inner);
    met.iter().find(|(p, e, _)| p.as_deref() == proxy && *e == endpoint).map(|(_, _, issuer)| issuer.clone())
}

/// The refusal of a road that met a proxy which re-terminates TLS earlier
/// in this run.
fn tried_before(proxied: Option<&str>, endpoint: SocketAddr) -> Result<(), Fault> {
    match intercepted(proxied, endpoint) {
        Some(issuer) => Err(Fault::Intercepted(format!(
            "a proxy re-terminated TLS with {endpoint} earlier in this run (a certificate of {issuer}): \
             WARP's road is not tried again"
        ))),
        None => Ok(()),
    }
}

/// A certificate of `issuer` taken for a proxy's: remembered for the run,
/// and its line, with `note` when the road learnt more.
fn intercepted_now(issuer: String, endpoint: SocketAddr, proxied: Option<String>, note: Option<&str>) -> Fault {
    let line = fault(Opening::Intercepted { issuer: issuer.clone() }, endpoint, proxied.as_deref()).to_string();
    INTERCEPTED.lock().unwrap_or_else(PoisonError::into_inner).push((proxied, endpoint, issuer));
    Fault::Intercepted(match note {
        Some(note) => format!("{line}; {note}"),
        None => line,
    })
}

/// The tunnel of one device, and its stack.
#[derive(Debug, Clone)]
pub struct Warp {
    stack: Stack,
    /// The endpoint, and the proxy that carries the tunnel, if any.
    pub endpoint: SocketAddr,
    pub proxy: Option<String>,
}

impl Warp {
    /// Open the tunnel of `device` through `proxy`, each step within
    /// `limit`; a certificate of another key than the pinned one is taken
    /// for a proxy's.
    pub async fn open(device: &Device, proxy: &ProxyChoice, limit: Duration) -> Result<Warp, Fault> {
        let endpoint = device.endpoint;
        let proxied = proxy_for(&endpoint.ip().to_string(), proxy);
        tried_before(proxied.as_deref(), endpoint)?;
        match tunnel::open(device, proxy, limit).await {
            Ok(link) => Warp::over(device, link, proxied),
            Err(Opening::Intercepted { issuer }) => Err(intercepted_now(issuer, endpoint, proxied, None)),
            Err(opening) => Err(fault(opening, endpoint, proxied.as_deref())),
        }
    }

    /// [`Warp::open`], where a certificate of another key than the pinned
    /// one sends the road to `api` for the device's record again (T-399):
    /// WARP's front door showed a new device another key than its record's
    /// until the record was read again (cfrs #32). A key that the API gives
    /// in its place goes into `device`, whose file the caller writes, and is
    /// tried, and once more after [`RETRY_AFTER`]. A key that the API never
    /// gave is never taken: the certificate is then a proxy's that
    /// re-terminates TLS, as it is when the API gives the same key, or
    /// cannot be read.
    pub async fn open_reading(
        device: &mut Device,
        api: &Api,
        proxy: &ProxyChoice,
        limit: Duration,
    ) -> Result<Warp, Fault> {
        let endpoint = device.endpoint;
        let proxied = proxy_for(&endpoint.ip().to_string(), proxy);
        tried_before(proxied.as_deref(), endpoint)?;
        let issuer = match tunnel::open(device, proxy, limit).await {
            Ok(link) => return Warp::over(device, link, proxied),
            Err(Opening::Intercepted { issuer }) => issuer,
            Err(opening) => return Err(fault(opening, endpoint, proxied.as_deref())),
        };
        let given = match register::read_record(api, device).await {
            Ok(record) => record.endpoint_key,
            Err(why) => {
                let note = format!("the device's record was not read again: {why}");
                return Err(intercepted_now(issuer, endpoint, proxied, Some(note.as_str())));
            }
        };
        let point = given.as_deref().map(crate::device::endpoint_point);
        let pem = match (given, point) {
            (Some(pem), Some(Ok(point))) if point != device.endpoint_point => pem,
            (_, Some(Ok(_))) => {
                let note = "WARP's API, asked again, gives the same key";
                return Err(intercepted_now(issuer, endpoint, proxied, Some(note)));
            }
            _ => {
                let note = "WARP's API, asked again, gives no endpoint key that podssh reads";
                return Err(intercepted_now(issuer, endpoint, proxied, Some(note)));
            }
        };
        device.rekey(&pem).map_err(Fault::Edge)?;
        let mut shown = issuer;
        for attempt in 0..2 {
            if attempt > 0 {
                tokio::time::sleep(RETRY_AFTER).await;
            }
            match tunnel::open(device, proxy, limit).await {
                Ok(link) => return Warp::over(device, link, proxied),
                Err(Opening::Intercepted { issuer }) => shown = issuer,
                Err(opening) => return Err(fault(opening, endpoint, proxied.as_deref())),
            }
        }
        let note = "nor did it show, in two tries, the key that WARP's API gives now";
        Err(intercepted_now(shown, endpoint, proxied, Some(note)))
    }

    /// The stack of `device` over its open tunnel.
    fn over(device: &Device, link: Link, proxy: Option<String>) -> Result<Warp, Fault> {
        let stack = Stack::start(&device.addresses(), link).map_err(Fault::Local)?;
        Ok(Warp { stack, endpoint: device.endpoint, proxy })
    }

    /// The road's words for `-v` and doctor: the endpoint, and its proxy.
    pub fn via(&self) -> String {
        match &self.proxy {
            Some(proxy) => format!("WARP's endpoint {} through the proxy {proxy}", self.endpoint),
            None => format!("WARP's endpoint {}", self.endpoint),
        }
    }

    /// The stack inside the tunnel.
    pub fn stack(&self) -> &Stack {
        &self.stack
    }

    /// Why the tunnel ended, once it has.
    pub fn ended(&self) -> Option<String> {
        self.stack.ended()
    }

    /// The addresses of `host`: itself, when it is one; else the resolver
    /// inside the tunnel's; else podssh's own resolver, which asks the
    /// system and DNS over HTTPS.
    pub async fn resolve(&self, host: &str, limit: Duration) -> Result<Vec<IpAddr>, String> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let inside = crate::dns::lookup(&self.stack, &crate::dns::RESOLVERS, host, limit).await;
        match inside {
            Ok(ips) => Ok(ips),
            Err(e) if e.ends_with(podssh_ws::resolve::NXDOMAIN) => Err(format!("{host}: {e}")),
            Err(inside) => {
                let deadline = tokio::time::Instant::now() + limit;
                match podssh_ws::resolve::resolve(host, 0, deadline).await {
                    Ok(addrs) => Ok(addrs.into_iter().map(|a| a.ip()).collect()),
                    Err(own) => Err(format!("{host}: inside the tunnel: {inside}; on this host: {own}")),
                }
            }
        }
    }

    /// A TCP stream to `host:port` inside the tunnel: each address of
    /// `host` of a family that the device has, in turn.
    pub async fn connect(&self, host: &str, port: u16, limit: Duration) -> Result<Stream, String> {
        let ips = self.resolve(host, limit).await?;
        let families: Vec<bool> = self.stack.addresses().iter().map(IpAddr::is_ipv4).collect();
        let mut reasons = Vec::new();
        for ip in ips.iter().filter(|ip| families.contains(&ip.is_ipv4())) {
            match self.stack.connect(SocketAddr::new(*ip, port), limit).await {
                Ok(stream) => return Ok(stream),
                Err(e) => reasons.push(e),
            }
        }
        if reasons.is_empty() {
            return Err(format!("{host}: no address of a family that WARP gave this device ({ips:?})"));
        }
        Err(reasons.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> SocketAddr {
        crate::ENDPOINT_H2.parse().unwrap()
    }

    /// A proxy's refusal of the address names the case of the doctor's line.
    #[test]
    fn a_refused_address_names_the_proxy_and_the_case() {
        let refused = DialError::ProxyRefused {
            proxy: "http://proxy:3128".into(),
            target: "162.159.198.2:443".into(),
            status: 403,
            reason: "Forbidden".into(),
        };
        let line = fault(Opening::Dial(refused), at(), Some("http://proxy:3128")).to_string();
        assert!(line.contains("refused CONNECT 162.159.198.2:443 (403 Forbidden)"), "{line}");
        assert!(line.contains("egress takes"), "{line}");
    }

    /// A cut TLS through a proxy is the proxy's; without one, the edge's.
    #[test]
    fn a_cut_handshake_through_a_proxy_is_the_proxy_s() {
        let cut = Opening::Tls("connection reset by peer".into());
        assert!(matches!(fault(cut.clone(), at(), Some("http://p:1")), Fault::Unreachable(_)));
        assert!(matches!(fault(cut, at(), None), Fault::Edge(_)));
    }

    /// An interception names its issuer; a refusal of 403 is the device's.
    #[test]
    fn the_faults_name_their_cause() {
        let line = fault(Opening::Intercepted { issuer: "CN=Corp Proxy CA".into() }, at(), None).to_string();
        assert!(line.contains("re-terminates TLS") && line.contains("CN=Corp Proxy CA"), "{line}");
        assert!(matches!(fault(Opening::Refused { status: 403 }, at(), None), Fault::Device(_)));
        assert!(matches!(fault(Opening::Refused { status: 502 }, at(), None), Fault::Edge(_)));
    }
}
