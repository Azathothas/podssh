//! The proxy that a URL names (T-070): HTTP `CONNECT` (`http://`, or a bare
//! `host:port`) or SOCKS5 (`socks5://`, `socks5h://`), with the user and the
//! password that it carries, which no message shows.

use crate::dial::{authority, split_host_port};

/// How a proxy tunnels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    /// HTTP `CONNECT`: `http://`, or a bare `host:port`.
    Http,
    /// SOCKS5 (RFC 1928): `socks5://` and `socks5h://` alike. Both send the
    /// host name, so that a host with no DNS needs none (T-070).
    Socks5,
}

impl ProxyKind {
    /// The scheme of a URL that names a proxy of this kind.
    pub fn scheme(self) -> &'static str {
        match self {
            ProxyKind::Http => "http",
            ProxyKind::Socks5 => "socks5h",
        }
    }

    /// The kind as a word of a report: `http` or `socks5`.
    pub fn name(self) -> &'static str {
        match self {
            ProxyKind::Http => "http",
            ProxyKind::Socks5 => "socks5",
        }
    }

    /// The request that opens the tunnel, as a line that says how a
    /// connection was opened names it.
    pub fn request(self) -> &'static str {
        match self {
            ProxyKind::Http => "CONNECT",
            ProxyKind::Socks5 => "SOCKS5 CONNECT",
        }
    }
}

/// A proxy that tunnels: HTTP `CONNECT`, or SOCKS5 `CONNECT`.
#[derive(Clone, PartialEq, Eq)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    pub kind: ProxyKind,
    /// The user and the password, each percent-decoded: HTTP Basic, or the
    /// user and password of RFC 1929. Never displayed.
    credentials: Option<(String, String)>,
}

/// The name of [`Proxy`] before SOCKS5 (T-070), kept for the crates and the
/// projects that name it.
pub type HttpProxy = Proxy;

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("kind", &self.kind)
            .field("credentials", &self.credentials.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl std::fmt::Display for Proxy {
    /// `host:port` only: the credentials never appear in a message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", authority(&self.host, self.port))
    }
}

impl Proxy {
    /// Parse `http://[user:pass@]host[:port][/]` or a bare `host:port` (port
    /// 80, as for any `http://` URL), or `socks5://` or `socks5h://` with the
    /// same parts (port 1080). SOCKS4 is refused by name: it has no
    /// authentication, and its first form no host names.
    pub fn parse(url: &str) -> Result<Proxy, String> {
        let url = url.trim();
        let (kind, rest) = match url.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => (ProxyKind::Http, rest),
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("socks5") || scheme.eq_ignore_ascii_case("socks5h") => {
                (ProxyKind::Socks5, rest)
            }
            Some((scheme, _)) if scheme.eq_ignore_ascii_case("socks4") || scheme.eq_ignore_ascii_case("socks4a") => {
                return Err(format!(
                    "proxy scheme {scheme}:// is not supported: SOCKS4 has no authentication; podssh speaks SOCKS5 \
                     to a socks5:// or socks5h:// proxy, and HTTP CONNECT to an http:// one"
                ))
            }
            Some((scheme, _)) => {
                return Err(format!(
                    "proxy scheme {scheme}:// is not supported; podssh speaks HTTP CONNECT to an http:// proxy, and \
                     SOCKS5 to a socks5:// or socks5h:// one"
                ))
            }
            None => (ProxyKind::Http, url),
        };
        let rest = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let (credentials, hostport) = match rest.rsplit_once('@') {
            // Split before decoding: a `:` escaped in the user is the user's.
            Some((userinfo, hostport)) => {
                let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                (Some((percent_decode(user)?, percent_decode(password)?)), hostport)
            }
            None => (None, rest),
        };
        let (host, port) = split_host_port(hostport)?;
        let port = port.unwrap_or(match kind {
            ProxyKind::Http => 80,
            ProxyKind::Socks5 => 1080,
        });
        if host.is_empty() {
            return Err("the proxy URL names no host".into());
        }
        if let (ProxyKind::Socks5, Some((user, password))) = (kind, &credentials) {
            // RFC 1929 gives each one a length byte, and 0 is no length.
            for (what, value) in [("user", user), ("password", password)] {
                if value.is_empty() || value.len() > 255 {
                    return Err(format!("the SOCKS5 {what} has {} bytes; RFC 1929 takes 1 to 255", value.len()));
                }
            }
        }
        Ok(Proxy { host, port, kind, credentials })
    }

    /// The user and the password, for the exchange with the proxy.
    pub(crate) fn credentials(&self) -> Option<(&str, &str)> {
        self.credentials.as_ref().map(|(user, password)| (user.as_str(), password.as_str()))
    }

    /// The proxy as a URL at `addr`, its resolved address, with its
    /// credentials escaped again: for a library that takes a URL, as the
    /// iroh road's relay dial does. Never for a message.
    pub fn url_at(&self, addr: std::net::SocketAddr) -> String {
        format!("{}://{}{addr}", self.kind.scheme(), self.userinfo())
    }

    /// The proxy as a URL by its name, with its port always written and its
    /// credentials escaped again: for a library that dials the proxy itself
    /// and reads a missing port its own way, as the tailnet fork does
    /// (8080). Never for a message.
    pub fn url(&self) -> String {
        format!("{}://{}{}", self.kind.scheme(), self.userinfo(), authority(&self.host, self.port))
    }

    /// `user:password@`, escaped, or nothing.
    fn userinfo(&self) -> String {
        match &self.credentials {
            Some((user, password)) => format!("{}:{}@", percent_encode(user), percent_encode(password)),
            None => String::new(),
        }
    }
}

/// Each byte but the unreserved ones of RFC 3986 as a `%` escape.
fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Decode `%XX` escapes in proxy credentials.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3).ok_or("a % escape is cut short in the proxy credentials")?;
            let value = u8::from_str_radix(hex, 16)
                .map_err(|_| "a % escape in the proxy credentials is not hex".to_string())?;
            out.push(value);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "the proxy credentials are not UTF-8".to_string())
}
