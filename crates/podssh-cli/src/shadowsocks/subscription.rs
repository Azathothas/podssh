//! A subscription: a list of servers that a provider serves at a URL, which
//! changes as its servers do. It is fetched through the proxy of the
//! environment over TLS, checked with podssh's trust, at most [`MAX_LIST`]
//! bytes, and kept in the cache (T-243) as a private file of mode 0600 with
//! the time it came. A kept list is read for a day; it is fetched again
//! after that, and when each of its servers failed ([`super::order`]). The
//! URL's path and query may hold the provider's token: a line shows the
//! host alone.

use std::fmt;
use std::time::Duration;

use podssh_ws::shadowsocks::{self, Node};
use podssh_ws::{ConnectError, ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The largest list fetched.
pub const MAX_LIST: usize = 1 << 20;
/// How long a kept list is read before it is fetched again.
pub const KEEP: Duration = Duration::from_secs(24 * 60 * 60);
/// Bound on the fetch, its TLS and its answer.
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
/// The redirects followed, each to another `https://` URL.
const REDIRECTS: usize = 3;
/// The largest kept file: what the cache reads (`podssh_relay::cache`),
/// less room for the time and the brackets.
const MAX_KEPT: usize = 60 * 1024;

/// A subscription's URL: `https://HOST[:PORT]/PATH?QUERY`.
#[derive(Clone, PartialEq, Eq)]
pub struct Subscription {
    pub host: String,
    pub port: u16,
    /// The path and its query, as the request line carries them.
    target: Zeroizing<String>,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription").field("host", &self.host).field("port", &self.port).finish_non_exhaustive()
    }
}

impl Subscription {
    /// An `https://` URL; `http://` is refused, as the list holds passwords,
    /// and so is a user in the URL.
    pub fn parse(url: &str) -> Result<Subscription, String> {
        let lower = url.get(..8).unwrap_or(url).to_ascii_lowercase();
        let rest = match url.get(8..) {
            Some(rest) if lower == "https://" => rest,
            _ if lower.starts_with("http://") => {
                return Err("a subscription is fetched over TLS: give its https:// URL".into())
            }
            _ => return Err("a subscription is an https:// URL".into()),
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err("a subscription's URL takes no user and no password".into());
        }
        let (host, port) = host_port(authority)?;
        let tail = tail.split('#').next().unwrap_or_default();
        let target = if tail.starts_with('/') { tail.to_string() } else { format!("/{tail}") };
        if target.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err("a subscription's URL holds a space or a control character; write it %20".into());
        }
        // A byte that is not ASCII goes percent-encoded, as a browser sends it.
        let target: String =
            target.bytes().map(|b| if b < 0x80 { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
        Ok(Subscription { host, port, target: Zeroizing::new(target) })
    }

    /// The URL with its host alone: `https://HOST/...`.
    pub fn shown(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match self.port {
            443 => format!("https://{host}/..."),
            port => format!("https://{host}:{port}/..."),
        }
    }

    /// The kept list's name in the cache: of the whole URL, so that two
    /// lists of one host are two files, and no part of it shows.
    pub fn file_name(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(format!("{}:{}", self.host, self.port).as_bytes());
        hash.update(self.target.as_bytes());
        let digest = hash.finalize();
        let short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        format!("shadowsocks-{short}.json")
    }
}

/// `HOST`, `HOST:PORT`, `[IPV6]` or `[IPV6]:PORT`; 443 with no port.
fn host_port(authority: &str) -> Result<(String, u16), String> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']').ok_or("a subscription's host has a [ and no ]")?;
            match after {
                "" => (host, None),
                _ => (host, Some(after.strip_prefix(':').ok_or("a subscription's URL has text after ]")?)),
            }
        }
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    podssh_ws::names::check_target(host).map_err(|why| format!("a subscription's host: {why}"))?;
    let port = match port {
        None => 443,
        Some(text) => text.parse::<u16>().ok().filter(|p| *p != 0).ok_or("a subscription's port is not a port")?,
    };
    Ok((host.to_string(), port))
}

/// A list in the cache, and whether it is younger than [`KEEP`].
pub struct Kept {
    pub nodes: Vec<Node>,
    pub fresh: bool,
}

/// The kept list of `list`, if the cache has one that reads.
pub fn kept(list: &Subscription) -> Option<Kept> {
    let text = Zeroizing::new(podssh_relay::cache::load_file(&list.file_name())?);
    let doc: serde_json::Value = serde_json::from_str(&text).ok()?;
    let fetched = doc.get("fetched").and_then(|f| f.as_i64())?;
    let lines = doc.get("nodes").and_then(|n| n.as_array())?;
    let nodes: Vec<Node> = lines.iter().filter_map(|l| l.as_str()).filter_map(|l| Node::parse(l).ok()).collect();
    let age = crate::pairs::now_ms() / 1000 - fetched;
    // A time ahead of the clock by more than a minute is not trusted.
    let fresh = (-60..KEEP.as_secs() as i64).contains(&age);
    Some(Kept { nodes, fresh })
}

/// A list as it came, and what to say of it.
pub struct Fetched {
    pub nodes: Vec<Node>,
    /// One line of what was left out, or of the cache, when there is any.
    pub notes: Vec<String>,
}

/// Fetch `list` through the proxy over TLS, read it, and keep it.
pub async fn fetch(list: &Subscription, trust: &Trust) -> Result<Fetched, String> {
    let shown = list.shown();
    let body = get(list, trust).await.map_err(|why| format!("the subscription {shown}: {why}"))?;
    let listed = shadowsocks::subscription(&body).map_err(|why| format!("the subscription {shown}: {why}"))?;
    let mut notes = Vec::new();
    if !listed.refused.is_empty() {
        notes.push(format!("the subscription {shown}: left out, {}", listed.refused.join("; ")));
    }
    if listed.nodes.is_empty() {
        let others = match listed.others {
            0 => String::new(),
            n => format!(" ({n} of other kinds, which podssh does not speak)"),
        };
        return Err(format!("the subscription {shown} holds no Shadowsocks server that podssh can use{others}"));
    }
    if let Some(note) = keep(list, &listed.nodes) {
        notes.push(format!("the subscription {shown}: {note}"));
    }
    Ok(Fetched { nodes: listed.nodes, notes })
}

/// The body at `list`, after at most [`REDIRECTS`] redirects.
async fn get(list: &Subscription, trust: &Trust) -> Result<Vec<u8>, String> {
    let mut at = list.clone();
    for _ in 0..=REDIRECTS {
        let response = podssh_ws::client::https_get_accepting(
            &at.host,
            at.port,
            &at.target,
            "*/*",
            MAX_LIST,
            trust,
            &ProxyChoice::FromEnvironment,
            FETCH_TIMEOUT,
        )
        .await
        .map_err(|e| failed(&e, &at.host))?;
        match response.status {
            200 => return Ok(response.body),
            301 | 302 | 303 | 307 | 308 => {
                let to = response.header("location").ok_or("a redirect with no Location")?;
                at = match to.strip_prefix('/') {
                    Some(_) if !to.starts_with("//") => {
                        let path = Subscription::parse(&format!("https://{}{to}", at_authority(&at)))?;
                        Subscription { target: path.target, ..at }
                    }
                    _ => Subscription::parse(to).map_err(|why| format!("a redirect: {why}"))?,
                };
            }
            status => return Err(format!("HTTP {status} {}", response.reason)),
        }
    }
    Err(format!("more than {REDIRECTS} redirects"))
}

/// `HOST:PORT` of a URL, an IPv6 one in brackets.
fn at_authority(list: &Subscription) -> String {
    podssh_ws::dial::authority(&list.host, list.port)
}

/// A fetch's failure, its host named and never its path.
fn failed(e: &ConnectError, host: &str) -> String {
    match e {
        ConnectError::Tls(why) => format!("TLS with {host} failed: {why}"),
        ConnectError::Http(why) => format!("the HTTPS request to {host} failed: {why}"),
        other => other.to_string(),
    }
}

/// Keep `nodes` as the list of `list`, with the time; what to say when the
/// cache took less than all, or none.
fn keep(list: &Subscription, nodes: &[Node]) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut size = 0;
    for node in nodes {
        let uri = node.to_uri();
        if size + uri.len() + 4 > MAX_KEPT {
            break;
        }
        size += uri.len() + 4;
        lines.push(uri.as_str().to_string());
    }
    let doc = serde_json::json!({ "fetched": crate::pairs::now_ms() / 1000, "nodes": lines });
    let body = Zeroizing::new(doc.to_string());
    let left = nodes.len() - lines.len();
    // The lines held passwords; their copies go with the body.
    for line in &mut lines {
        zeroize::Zeroize::zeroize(line);
    }
    match podssh_relay::cache::store_file(&list.file_name(), body.as_bytes()) {
        Ok(_) if left == 0 => None,
        Ok(_) => Some(format!("{left} servers past the cache's size were not kept")),
        Err(why) => Some(format!("the list could not be kept, so it is fetched at each run: {why}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscription_is_https_and_shows_its_host_alone() {
        let list = Subscription::parse("https://sub.example/link/SECRET?flag=ss").unwrap();
        assert_eq!((list.host.as_str(), list.port), ("sub.example", 443));
        assert_eq!(list.shown(), "https://sub.example/...");
        assert_eq!(list.target.as_str(), "/link/SECRET?flag=ss");
        assert!(!format!("{list:?}").contains("SECRET"));
        assert!(!list.file_name().contains("SECRET") && list.file_name().starts_with("shadowsocks-"));
        let other = Subscription::parse("https://sub.example/link/OTHER").unwrap();
        assert_ne!(list.file_name(), other.file_name(), "two lists of one host are two files");
        let v6 = Subscription::parse("HTTPS://[2001:db8::2]:8443").unwrap();
        assert_eq!((v6.shown(), v6.target.as_str()), ("https://[2001:db8::2]:8443/...".to_string(), "/"));
        assert!(Subscription::parse("http://sub.example/x").unwrap_err().contains("over TLS"));
        let with_user = ["https://user", ":pw", "@sub.example/x"].concat();
        assert!(Subscription::parse(&with_user).unwrap_err().contains("no user"));
        assert!(Subscription::parse("ftp://sub.example/x").is_err());
    }
}
