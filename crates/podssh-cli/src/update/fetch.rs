//! One file of a release over HTTPS (T-375), through the proxy as each
//! connection of podssh goes, with the TLS of podssh-ws: a GET, its
//! redirects followed to at most [`REDIRECTS`] hops and on HTTPS alone, its
//! body bounded in size and time. GitHub sends an asset to a signed URL of
//! another host; that URL carries a credential of the moment in its query,
//! so no message names more of a URL than its host and its path.

use podssh_ws::client::open_tls;
use podssh_ws::http;
use podssh_ws::{ProxyChoice, Trust};
use std::time::Duration;

/// The most redirects that one file follows: GitHub's asset takes one.
pub const REDIRECTS: usize = 5;

/// Where and how a release's files are fetched.
#[derive(Debug, Clone)]
pub struct Fetcher {
    pub trust: Trust,
    pub proxy: ProxyChoice,
    /// The limit of the connection and of each answer's head.
    pub timeout: Duration,
}

/// Why a file did not come.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The server answered 404: no such release or file.
    NotFound(String),
    /// Anything else: TCP, the proxy, TLS, a status, a size, a time.
    Failed(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::NotFound(why) | FetchError::Failed(why) => f.write_str(why),
        }
    }
}

/// An `https://` URL, read: its host, its port, and its path with the query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(text: &str) -> Result<Url, String> {
        let rest = text.strip_prefix("https://").ok_or("not an https:// URL")?;
        let rest = rest.split('#').next().unwrap_or_default();
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.contains('@') {
            return Err("a URL with a user in it".into());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => {
                (host, port.parse::<u16>().map_err(|_| format!("the port {port:?} is no port"))?)
            }
            _ => (authority, 443),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err("a URL with no host".into());
        }
        let path = if path.is_empty() {
            "/".to_string()
        } else if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_string()
        };
        if path.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err("a URL with a space in its path".into());
        }
        Ok(Url { host: host.to_string(), port, path })
    }

    /// The host and the path, without the query: what a message may say.
    pub fn shown(&self) -> String {
        let path = self.path.split('?').next().unwrap_or_default();
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match self.port {
            443 => format!("https://{host}{path}"),
            port => format!("https://{host}:{port}{path}"),
        }
    }

    /// Where `location`, a redirect's header, sends from this URL: a whole
    /// URL, or a path of this host.
    fn join(&self, location: &str) -> Result<Url, String> {
        if location.starts_with("https://") {
            return Url::parse(location);
        }
        if location.starts_with("//") || location.contains("://") {
            return Err("a redirect to another scheme than https".into());
        }
        if !location.starts_with('/') {
            return Err("a redirect to a relative path".into());
        }
        Ok(Url { host: self.host.clone(), port: self.port, path: location.to_string() })
    }
}

impl Fetcher {
    /// The body of `url`, of `max` bytes at most, within `limit` for the
    /// whole of it, redirects included.
    pub async fn get(&self, url: &str, accept: &str, max: usize, limit: Duration) -> Result<Vec<u8>, FetchError> {
        let first = Url::parse(url).map_err(|why| FetchError::Failed(format!("{url}: {why}")))?;
        let shown = first.shown();
        match tokio::time::timeout(limit, self.follow(first, accept, max)).await {
            Ok(result) => result,
            Err(_) => Err(FetchError::Failed(format!("{shown}: no whole answer within {} s", limit.as_secs()))),
        }
    }

    async fn follow(&self, mut url: Url, accept: &str, max: usize) -> Result<Vec<u8>, FetchError> {
        for _ in 0..=REDIRECTS {
            let shown = url.shown();
            let failed = |why: String| FetchError::Failed(format!("{shown}: {why}"));
            let mut tls = open_tls(&url.host, url.port, &url.host, &self.trust, &self.proxy, self.timeout)
                .await
                .map_err(|e| failed(e.to_string()))?;
            let host_header = match url.port {
                443 => url.host.clone(),
                port => podssh_ws::dial::authority(&url.host, port),
            };
            let response = http::exchange(&mut tls, "GET", &host_header, &url.path, &[("Accept", accept)], b"", max)
                .await
                .map_err(|e| failed(e.to_string()))?;
            match response.status {
                200 => return Ok(response.body),
                301 | 302 | 303 | 307 | 308 => {
                    let location =
                        response.header("location").ok_or_else(|| failed("a redirect with no Location".into()))?;
                    url = url.join(location).map_err(failed)?;
                }
                404 => return Err(FetchError::NotFound(format!("{shown}: not found (HTTP 404)"))),
                status => {
                    return Err(failed(format!("HTTP {status} {}: {}", response.reason, response.body_text(120))));
                }
            }
        }
        Err(FetchError::Failed(format!("{}: more than {REDIRECTS} redirects", url.shown())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_gives_its_host_port_and_path() {
        let url = Url::parse("https://github.com/Azathothas/podssh/releases.atom").unwrap();
        assert_eq!(
            (url.host.as_str(), url.port, url.path.as_str()),
            ("github.com", 443, "/Azathothas/podssh/releases.atom")
        );
        let url = Url::parse("https://127.0.0.1:8443?x=1#y").unwrap();
        assert_eq!((url.host.as_str(), url.port, url.path.as_str()), ("127.0.0.1", 8443, "/?x=1"));
        let url = Url::parse("https://[::1]:8443/a").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("::1", 8443));
        assert_eq!(url.shown(), "https://[::1]:8443/a");
        for wrong in ["http://github.com/", "https://", "https://user@github.com/", "https://a:b/", "https://a/b c"] {
            assert!(Url::parse(wrong).is_err(), "{wrong}");
        }
    }

    /// A signed URL's query is a credential of the moment: no message holds
    /// it.
    #[test]
    fn what_a_message_shows_holds_no_query() {
        let url = Url::parse("https://release-assets.githubusercontent.com/a/b?sig=SECRET&exp=1").unwrap();
        assert_eq!(url.shown(), "https://release-assets.githubusercontent.com/a/b");
    }

    #[test]
    fn a_redirect_goes_to_https_or_to_a_path_of_the_same_host() {
        let from = Url::parse("https://github.com/o/r/releases/download/v1/x").unwrap();
        let to = from.join("https://release-assets.githubusercontent.com/x?sig=1").unwrap();
        assert_eq!(to.host, "release-assets.githubusercontent.com");
        assert_eq!(from.join("/o/r/x").unwrap().path, "/o/r/x");
        for wrong in ["http://example.org/x", "//example.org/x", "x", "ftp://example.org/x"] {
            assert!(from.join(wrong).is_err(), "{wrong}");
        }
    }
}
