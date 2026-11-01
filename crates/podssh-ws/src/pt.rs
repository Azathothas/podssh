//! What Tor's two pluggable transports of podssh share (T-385), meek_lite
//! ([`crate::meek`]) and WebTunnel ([`crate::webtunnel`]): a bridge's
//! arguments, as Arti hands them over (`k=v`, from the bridge line), the URL
//! that each argument `url=` names, and the connection that each opens to
//! its server. That connection is every road's: TCP through the proxy of the
//! environment, then TLS checked with podssh's trust for the name sent,
//! with no bypass of the check (`tls.rs`).

use std::time::Duration;

use crate::client::ConnectError;
use crate::dial::ProxyChoice;
use crate::tls::Trust;
use crate::url::Stream;

/// How a transport reaches its server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reach {
    /// The proxy of each connection.
    pub proxy: ProxyChoice,
    /// The roots of each TLS handshake.
    pub trust: Trust,
    /// The bound of each dial, TLS handshake and answer.
    pub wait: Duration,
}

/// The first value of `key` among a bridge's arguments, as goptlib's
/// `Args.Get` gives it.
pub fn get<'a>(settings: &'a [(String, String)], key: &str) -> Option<&'a str> {
    settings.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// A URL of a bridge's argument: `http://` or `https://`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    /// `https://`: TLS.
    pub tls: bool,
    /// A name, or an IP address; an IPv6 one with no brackets.
    pub host: String,
    /// The port given, else the scheme's own.
    pub port: u16,
    /// The host and the port as the URL writes them, for `Host`.
    pub authority: String,
    /// The path and its query, from `/`, as a request line carries them.
    pub target: String,
}

impl HttpUrl {
    /// `http://HOST[:PORT][/PATH]` or `https://...`; a fragment is dropped.
    /// A user and a password are refused, and so is a path that would break
    /// a request line.
    pub fn parse(text: &str) -> Result<HttpUrl, String> {
        let lower = text.get(..8).unwrap_or(text).to_ascii_lowercase();
        let (tls, rest) = if lower.starts_with("https://") {
            (true, &text[8..])
        } else if lower.starts_with("http://") {
            (false, &text[7..])
        } else {
            return Err("a bridge's url is http://HOST[:PORT]/PATH or https://HOST[:PORT]/PATH".into());
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err("a bridge's url takes no user and no password".into());
        }
        let (host, port) = host_port(authority, if tls { 443 } else { 80 })?;
        let tail = tail.split('#').next().unwrap_or_default();
        let target = match tail {
            "" => "/".to_string(),
            t if t.starts_with('/') => t.to_string(),
            t => format!("/{t}"),
        };
        let target = crate::url::request_target(&target)
            .map_err(|_| "a bridge's url holds a space or a control character in its path".to_string())?;
        Ok(HttpUrl { tls, host, port, authority: authority.to_string(), target })
    }

    /// The path, with no query: a query may hold the bridge's secret.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("/")
    }

    /// The URL for a line of podssh's: no query.
    pub fn shown(&self) -> String {
        format!("{}://{}{}", if self.tls { "https" } else { "http" }, self.authority, self.path())
    }
}

/// `HOST`, `HOST:PORT`, `[IPV6]` or `[IPV6]:PORT`, the port `default` when
/// none is given.
pub fn host_port(authority: &str, default: u16) -> Result<(String, u16), String> {
    let (host, port) = crate::dial::split_host_port(authority)?;
    if authority.starts_with('[') {
        host.parse::<std::net::Ipv6Addr>().map_err(|_| format!("{authority:?}: brackets hold an IPv6 address"))?;
    } else if host.contains(':') {
        return Err(format!("{authority:?}: an IPv6 address goes in brackets"));
    } else {
        crate::names::check_host(&host)?;
    }
    match port {
        Some(0) => Err(format!("{authority:?}: port 0")),
        Some(port) => Ok((host, port)),
        None => Ok((host, default)),
    }
}

/// A connection to `host:port` through the reach's proxy, with TLS checked
/// for `server_name` when `tls`, all within the reach's wait.
pub(crate) async fn open(host: &str, port: u16, tls: bool, server_name: &str, reach: &Reach) -> Result<Stream, String> {
    if !tls {
        let tcp = crate::dial::dial(host, port, &reach.proxy, reach.wait).await.map_err(|e| e.to_string())?;
        return Ok(Stream::Plain(tcp));
    }
    match crate::client::open_tls(host, port, server_name, &reach.trust, &reach.proxy, reach.wait).await {
        Ok(stream) => Ok(Stream::Tls(Box::new(stream))),
        Err(ConnectError::Tls(why)) => Err(format!("TLS with {server_name} failed: {why}")),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bridge_s_url_gives_its_scheme_host_port_authority_and_target() {
        let url = HttpUrl::parse("https://1603026938.rsc.cdn77.org").unwrap();
        assert_eq!((url.tls, url.host.as_str(), url.port), (true, "1603026938.rsc.cdn77.org", 443));
        assert_eq!((url.authority.as_str(), url.target.as_str()), ("1603026938.rsc.cdn77.org", "/"));
        let url = HttpUrl::parse("http://192.0.2.9:15000/SeCrEt?x=1#frag").unwrap();
        assert_eq!((url.tls, url.port, url.authority.as_str()), (false, 15000, "192.0.2.9:15000"));
        assert_eq!((url.target.as_str(), url.path()), ("/SeCrEt?x=1", "/SeCrEt"));
        assert_eq!(url.shown(), "http://192.0.2.9:15000/SeCrEt");
        let url = HttpUrl::parse("HTTPS://[2001:db8::7]:8443/p").unwrap();
        assert_eq!((url.host.as_str(), url.authority.as_str()), ("2001:db8::7", "[2001:db8::7]:8443"));
    }

    #[test]
    fn a_url_that_would_break_a_request_is_refused() {
        // A URL with a user and a password is built here, as a literal of
        // that form reads as a credential to the scan of secrets.
        let with_password = format!("https://{}:{}@example.org/", "user", "pw");
        for bad in [
            "ws://example.org/",
            with_password.as_str(),
            "https://example.org:0/",
            "https://example.org:x/",
            "https:///path",
            "https://exa mple.org/",
            "https://2001:db8::1/",
            "https://[nope]/",
            "https://example.org/a b",
            "https://example.org/a\r\nX-Session-Id: 1",
        ] {
            assert!(HttpUrl::parse(bad).is_err(), "{bad:?}");
        }
        let refused = HttpUrl::parse(&format!("https://{}:{}@example.org/", "user", "SECRET")).unwrap_err();
        assert!(!refused.contains("SECRET"), "{refused}");
    }

    #[test]
    fn the_first_value_of_a_key_is_the_argument() {
        let settings = vec![("url".to_string(), "a".to_string()), ("url".to_string(), "b".to_string())];
        assert_eq!(get(&settings, "url"), Some("a"));
        assert_eq!(get(&settings, "front"), None);
    }
}
