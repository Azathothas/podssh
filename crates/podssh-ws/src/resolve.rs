//! Turning a host name into addresses without trusting that this host's
//! resolver works. In order:
//!
//! 1. an IP literal is its own address;
//! 2. addresses pinned for the name ([`set_pins`]: podssh's `--relay-addr` and
//!    `PODSSH_RELAY_ADDR`), for hosts with no DNS at all;
//! 3. the system resolver;
//! 4. DNS over HTTPS to public resolvers reached by IP literal, whose
//!    certificates are verified against those IPs like any other — for hosts
//!    whose resolver is broken but whose TCP egress works.
//!
//! With an HTTP proxy none of this runs for the target: the proxy is given the
//! name and resolves it. TLS to the target always checks the target's name, so
//! a wrong pinned or resolved address fails the handshake instead of
//! connecting somewhere else.

use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::http;
use crate::tls::{self, Trust};

/// Public DNS-over-HTTPS resolvers, by IP literal (a resolver needs no
/// resolver), with the JSON API path each one serves. Two operators, two
/// addresses each.
pub const DOH_RESOLVERS: &[(&str, &str)] =
    &[("1.1.1.1", "/dns-query"), ("8.8.8.8", "/resolve"), ("1.0.0.1", "/dns-query"), ("8.8.4.4", "/resolve")];

/// The bound on one resolver's answer, inside the caller's overall deadline.
const DOH_EACH: Duration = Duration::from_secs(5);

/// A resolver's answer that the name does not exist (DNS status 3). It holds
/// for every record type and every resolver, so the lookup stops there.
pub const NXDOMAIN: &str = "no such name (NXDOMAIN)";

static PINS: RwLock<Vec<(String, IpAddr)>> = RwLock::new(Vec::new());

/// `HOST=IP[,HOST=IP...]`; a host may appear more than once. IPv6 addresses
/// may be bracketed.
pub fn parse_pins(text: &str) -> Result<Vec<(String, IpAddr)>, String> {
    let mut pins = Vec::new();
    for item in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (host, ip) = item.split_once('=').ok_or_else(|| format!("{item:?} is not HOST=IP"))?;
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || !dns_safe(&host) {
            return Err(format!("{item:?}: not a host name"));
        }
        let ip: IpAddr = ip
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| format!("{item:?}: not an IP address"))?;
        pins.push((host, ip));
    }
    Ok(pins)
}

/// Replace the process-wide pins.
pub fn set_pins(pins: Vec<(String, IpAddr)>) {
    *PINS.write().unwrap_or_else(|e| e.into_inner()) = pins;
}

/// The addresses pinned for `host`, in the order given.
pub fn pinned(host: &str) -> Vec<IpAddr> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    PINS.read().unwrap_or_else(|e| e.into_inner()).iter().filter(|(h, _)| *h == host).map(|(_, ip)| *ip).collect()
}

/// The addresses to try for `host:port`, by the order in the module comment.
/// The error names every source that was tried.
pub async fn resolve(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let pins = pinned(host);
    if !pins.is_empty() {
        return Ok(pins.into_iter().map(|ip| SocketAddr::new(ip, port)).collect());
    }
    let system = match tokio::time::timeout_at(deadline, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addrs)) => {
            let addrs: Vec<SocketAddr> = addrs.collect();
            if !addrs.is_empty() {
                return Ok(addrs);
            }
            "no addresses".to_string()
        }
        Ok(Err(e)) => e.to_string(),
        Err(_) => "timed out".to_string(),
    };
    // The caller names the host ("could not resolve HOST: ..."), so these
    // say only what each source answered.
    if !dns_safe(host) {
        return Err(system);
    }
    match doh_lookup(host, deadline).await {
        Ok(ips) => Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()),
        Err(doh) => Err(format!("{system}; DNS over HTTPS: {doh}")),
    }
}

/// Ask the [`DOH_RESOLVERS`] in turn for A, then AAAA records; the first
/// resolver that answers with addresses wins, and the first that says the
/// name does not exist ends the lookup.
pub async fn doh_lookup(host: &str, deadline: Instant) -> Result<Vec<IpAddr>, String> {
    doh_lookup_with(DOH_RESOLVERS, host, deadline).await
}

/// [`doh_lookup`] over a given list of `(ip, path)` resolvers.
pub async fn doh_lookup_with(resolvers: &[(&str, &str)], host: &str, deadline: Instant) -> Result<Vec<IpAddr>, String> {
    let mut reasons = Vec::new();
    for (ip, path) in resolvers {
        if Instant::now() >= deadline {
            reasons.push("out of time".to_string());
            break;
        }
        let each = (Instant::now() + DOH_EACH).min(deadline);
        let mut found = Vec::new();
        for kind in ["A", "AAAA"] {
            match tokio::time::timeout_at(each, query(ip, path, host, kind)).await {
                Ok(Ok(mut ips)) => found.append(&mut ips),
                Ok(Err(e)) if e == NXDOMAIN => return Err(format!("{ip}: {e}")),
                Ok(Err(e)) => reasons.push(format!("{ip}: {e}")),
                Err(_) => reasons.push(format!("{ip}: timed out")),
            }
            if kind == "A" && !found.is_empty() {
                break;
            }
        }
        if !found.is_empty() {
            return Ok(found);
        }
    }
    Err(if reasons.is_empty() { "no resolver answered".into() } else { reasons.join("; ") })
}

/// One JSON-API query (`?name=...&type=...`) to the resolver at `ip`.
async fn query(ip: &str, path: &str, host: &str, kind: &str) -> Result<Vec<IpAddr>, String> {
    let roots = tls::roots_for(&Trust::Default).map_err(|e| e.to_string())?;
    let config = tls::client_config(&roots).map_err(|e| e.to_string())?;
    let name = rustls_pki_types::ServerName::try_from(ip.to_string()).map_err(|e| e.to_string())?;
    let addr: IpAddr = ip.parse().map_err(|_| format!("{ip} is not an IP"))?;
    let tcp = TcpStream::connect(SocketAddr::new(addr, 443)).await.map_err(|e| e.to_string())?;
    let mut stream =
        tokio_rustls::TlsConnector::from(config).connect(name, tcp).await.map_err(|e| format!("TLS: {e}"))?;
    let target = format!("{path}?name={host}&type={kind}");
    let response =
        http::exchange(&mut stream, "GET", ip, &target, &[("Accept", "application/dns-json")], b"", 64 * 1024)
            .await
            .map_err(|e| e.to_string())?;
    if response.status != 200 {
        return Err(format!("HTTP {}", response.status));
    }
    parse_answer(&response.body, kind)
}

/// The addresses in a DNS JSON answer (`Answer[].data` of type 1 or 28).
pub fn parse_answer(body: &[u8], kind: &str) -> Result<Vec<IpAddr>, String> {
    let want: u64 = if kind == "AAAA" { 28 } else { 1 };
    let doc: serde_json::Value = serde_json::from_slice(body).map_err(|_| "not a DNS JSON answer".to_string())?;
    match doc.get("Status").and_then(|s| s.as_u64()) {
        Some(0) => {}
        Some(3) => return Err(NXDOMAIN.to_string()),
        other => {
            return Err(format!("DNS status {}", other.map(|s| s.to_string()).unwrap_or_else(|| "missing".into())))
        }
    }
    Ok(doc
        .get("Answer")
        .and_then(|a| a.as_array())
        .map(|answers| {
            answers
                .iter()
                .filter(|a| a.get("type").and_then(|t| t.as_u64()) == Some(want))
                .filter_map(|a| a.get("data").and_then(|d| d.as_str()).and_then(|d| d.parse().ok()))
                .collect()
        })
        .unwrap_or_default())
}

/// Letters, digits, `.`, `-` and `_` only: safe in a query string and in DNS.
fn dns_safe(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_parse_and_reject_garbage() {
        let pins = parse_pins("tcp.ssh.relay.ajam.dev=104.21.39.2, Relay.Example.=[2001:db8::1],x=1.2.3.4").unwrap();
        assert_eq!(pins[0], ("tcp.ssh.relay.ajam.dev".into(), "104.21.39.2".parse().unwrap()));
        assert_eq!(pins[1], ("relay.example".into(), "2001:db8::1".parse().unwrap()));
        assert_eq!(pins.len(), 3);
        for bad in ["noequals", "=1.2.3.4", "host=not-an-ip", "bad host=1.2.3.4", "h=1.2.3.4.5"] {
            assert!(parse_pins(bad).is_err(), "{bad}");
        }
        assert!(parse_pins("").unwrap().is_empty());
    }

    #[test]
    fn dns_json_answers_parse_by_type() {
        let body = br#"{"Status":0,"Answer":[
            {"name":"a.example.","type":5,"data":"b.example."},
            {"name":"b.example.","type":1,"data":"192.0.2.7"},
            {"name":"b.example.","type":28,"data":"2001:db8::7"}]}"#;
        assert_eq!(parse_answer(body, "A").unwrap(), vec!["192.0.2.7".parse::<IpAddr>().unwrap()]);
        assert_eq!(parse_answer(body, "AAAA").unwrap(), vec!["2001:db8::7".parse::<IpAddr>().unwrap()]);
        assert_eq!(parse_answer(br#"{"Status":3}"#, "A").unwrap_err(), NXDOMAIN);
        assert_eq!(parse_answer(br#"{"Status":2}"#, "A").unwrap_err(), "DNS status 2");
        assert_eq!(parse_answer(br#"{"Answer":[]}"#, "A").unwrap_err(), "DNS status missing");
        assert!(parse_answer(b"nope", "A").is_err());
        assert!(parse_answer(br#"{"Status":0}"#, "A").unwrap().is_empty());
    }

    #[tokio::test]
    async fn literals_and_pins_need_no_resolver() {
        let soon = Instant::now() + Duration::from_secs(1);
        assert_eq!(resolve("192.0.2.1", 443, soon).await.unwrap(), vec!["192.0.2.1:443".parse().unwrap()]);
        assert_eq!(resolve("[2001:db8::1]", 22, soon).await.unwrap(), vec!["[2001:db8::1]:22".parse().unwrap()]);
        set_pins(parse_pins("pinned.invalid=192.0.2.9").unwrap());
        assert_eq!(resolve("PINNED.invalid", 443, soon).await.unwrap(), vec!["192.0.2.9:443".parse().unwrap()]);
        set_pins(Vec::new());
    }
}
