//! The control server of `--ts-control-url` (T-334): its URL, checked before
//! the network; the relay of `--ts-relay`, read the same way; and the check
//! of `tcp` against that server, in place of Tailscale's default map.
//!
//! headscale publishes no DERP map where Tailscale does
//! (`/derpmap/default`): a node reads its DERP servers in its own map
//! response, once it has registered. So the check asks the control server
//! for its key first, as the node does, and for its map only when it
//! publishes one.

use std::net::Ipv6Addr;

use podssh_ts::chain::Verdict;
use podssh_ts::wait::Deadline;
use podssh_ws::dial::authority;
use podssh_ws::{ProxyChoice, Trust};

use super::probe::{connect_error, seconds, try_servers, DERP_MAP_PATH, MAP_MAX, STEP};

/// The variable of a test's CA file, which the node's fork adds to its roots
/// (patch 0027 of `vendor/patches/`): a stand-in control server of a test's
/// own CA is then reached with TLS checked. Only a test sets it.
pub const TEST_CA_VAR: &str = "PODSSH_TS_TEST_CA_FILE";

/// The largest answer to `/key`: a JSON object of two keys.
const KEY_MAX: usize = 4096;

/// A server as `podssh ts` dials it: a name or an address, an IPv6 one with
/// no brackets, and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub host: String,
    pub port: u16,
}

impl Server {
    /// `host:port`, an IPv6 address in brackets, as the messages say it.
    pub fn authority(&self) -> String {
        authority(&self.host, self.port)
    }
}

/// `https://HOST[:PORT]`, with `/` at most after it: the control server.
/// The fork asks for `/key` and `/ts2021` at the root of the host, whatever
/// path the URL has, so a path is refused rather than ignored; so is a user
/// or a password, which the list of processes shows; and so is `http://`,
/// over which anyone on the path could give the node a control key of
/// theirs. No message quotes the URL.
pub fn control_url(text: &str) -> Result<Server, String> {
    let Some((scheme, rest)) = text.trim().split_once("://") else {
        return Err("it is not a URL; give https://HOST[:PORT]".to_string());
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return Err("the scheme is not https://; the control key comes over checked TLS alone".to_string());
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (place, tail) = rest.split_at(end);
    if !(tail.is_empty() || tail == "/") {
        return Err("a path, a query or a fragment is not taken: the node asks at the root of the host".to_string());
    }
    if place.contains('@') {
        return Err("a user or a password is not taken: the list of processes shows the command line".to_string());
    }
    host_port(place, 443)
}

/// The URL that the fork takes for `server`: `https://HOST:PORT`.
pub fn url_of(server: &Server) -> String {
    format!("https://{}", server.authority())
}

/// `HOST[:PORT]`, an IPv6 address in brackets, `port` when none is given:
/// a relay of `--ts-relay`, and the place of a control URL.
pub fn host_port(text: &str, port: u16) -> Result<Server, String> {
    let (host, given) = match text.strip_prefix('[') {
        Some(inner) => {
            let Some((host, after)) = inner.split_once(']') else {
                return Err("an IPv6 address has no closing ]".to_string());
            };
            if host.parse::<Ipv6Addr>().is_err() {
                return Err(format!("[{host}] is not an IPv6 address"));
            }
            match after {
                "" => (host, None),
                _ => match after.strip_prefix(':') {
                    Some(p) => (host, Some(p)),
                    None => return Err("text after the ] of the address is not a :PORT".to_string()),
                },
            }
        }
        None => match text.split_once(':') {
            Some((_, rest)) if rest.contains(':') => {
                return Err("an IPv6 address goes in brackets, as [ADDRESS]:PORT".to_string());
            }
            Some((host, p)) => (host, Some(p)),
            None => (text, None),
        },
    };
    if host.is_empty() {
        return Err("no host is given".to_string());
    }
    // A name or an IPv4 address: letters, digits, dots, hyphens and
    // underscores; anything else would break a request line.
    if !text.starts_with('[') && !host.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)) {
        return Err(format!("{host:?} is not a host name or an address"));
    }
    let port = match given {
        None => port,
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n != 0 => n,
            _ => return Err(format!("the port {p:?} is not a number from 1 to 65535")),
        },
    };
    Ok(Server { host: host.to_string(), port })
}

/// The check of `tcp` with the control server `control`, its steps each in
/// [`STEP`] and never past `deadline`, through `proxy`, each TLS handshake
/// checked against `trust`: its key, as the node asks for it first; then its
/// DERP map, when it publishes one where Tailscale does, and a handshake with
/// up to three of its servers. A server that publishes none (404, as
/// headscale) passes on its key: the node reads its DERP servers in its map.
pub async fn reach(control: &Server, trust: &Trust, proxy: &ProxyChoice, deadline: Deadline) -> Verdict {
    let at = control.authority();
    let key = format!("the control key from {at}");
    let limit = deadline.limit(STEP);
    if limit.is_zero() {
        return Verdict::Fail(format!("{key}: not read, the bound had passed"));
    }
    match get(control, &podssh_ts::control::key_path(), KEY_MAX, trust, proxy, limit).await {
        Ok(r) if r.status == 200 && names_a_key(&r.body) => {}
        Ok(r) if r.status == 200 => return Verdict::Fail(format!("{key}: the answer names no publicKey")),
        Ok(r) => return Verdict::Fail(format!("{key}: HTTP {}", r.status)),
        Err(why) => return Verdict::Fail(format!("{key}: {why}")),
    }
    let from = format!("the DERP map of {at}");
    let limit = deadline.limit(STEP);
    if limit.is_zero() {
        return Verdict::Fail(format!("{from}: not read, the bound had passed"));
    }
    match get(control, DERP_MAP_PATH, MAP_MAX, trust, proxy, limit).await {
        Ok(r) if r.status == 200 => {
            try_servers(&from, &format!("DERP server of {at}"), &r.body, trust, proxy, deadline).await
        }
        Ok(r) if r.status == 404 => Verdict::Ok,
        Ok(r) => Verdict::Fail(format!("{from}: HTTP {}", r.status)),
        Err(why) => Verdict::Fail(format!("{from}: {why}")),
    }
}

/// A GET of `path` from `control`, all of it within `limit`.
async fn get(
    control: &Server,
    path: &str,
    max: usize,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: std::time::Duration,
) -> Result<podssh_ws::http::Response, String> {
    // `https_get` bounds its dial, its handshake and its exchange each; the
    // step bounds all three.
    let fetched = podssh_ws::https_get(&control.host, control.port, path, max, trust, proxy, limit);
    match tokio::time::timeout(limit, fetched).await {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => Err(connect_error(&e)),
        Err(_) => Err(format!("no answer within {}", seconds(limit))),
    }
}

/// Whether an answer to `/key` names the key of the Noise protocol, as the
/// node reads it: `publicKey`, a machine key.
pub fn names_a_key(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("publicKey").and_then(|k| k.as_str()).map(|k| k.starts_with("mkey:")))
        .unwrap_or(false)
}

/// The line that says a test's CA is on: an extra root, which a host where
/// nobody meant one should hear of. The file is named, never read here.
pub fn test_ca_notice(var: impl Fn(&str) -> Option<String>) -> Option<String> {
    let file = var(TEST_CA_VAR).filter(|v| !v.trim().is_empty())?;
    Some(format!(
        "podssh ts: {TEST_CA_VAR} adds the CA certificates of {file} to the node's roots: a setting for tests."
    ))
}
