//! The routes to WARP's API (T-562): the registration was the one step of
//! the road with no other way, one name of the API, so a host where that
//! name does not resolve, or is not allowed, had no device and no road, and
//! its line said that the API did not answer, not which name. A route is a
//! name, or an address, and a port; [`crate::register::Api`] holds them in
//! the order that they are tried, and the line of a failure names each.

use std::fmt;

/// One route to the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub host: String,
    pub port: u16,
}

impl Route {
    /// A route of `host` on port 443.
    pub fn https(host: &str) -> Route {
        Route { host: host.to_string(), port: 443 }
    }

    /// The route of `https://HOST[:PORT]`, as `PODSSH_WARP_API` names one:
    /// a path of `/` at most, and no user, query or fragment, as the
    /// requests' paths are the API's own.
    pub fn parse_url(text: &str) -> Result<Route, String> {
        let rest = text.trim().strip_prefix("https://").ok_or("not a URL of https://HOST[:PORT]")?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#', '@']) {
            return Err("a URL of HOST[:PORT] alone, with no path, user or query".into());
        }
        Route::parse_authority(rest)
    }

    /// The route of `HOST`, `HOST:PORT`, `[IPV6]` or `[IPV6]:PORT`, as the
    /// device's record and the lines write one; 443 when no port is given.
    pub fn parse_authority(text: &str) -> Result<Route, String> {
        let (host, port) = match text.strip_prefix('[') {
            Some(inner) => {
                let (host, after) = inner.split_once(']').ok_or("an IPv6 address with no closing bracket")?;
                let port = match after {
                    "" => None,
                    _ => Some(after.strip_prefix(':').ok_or("a port after the IPv6 address with no colon")?),
                };
                if host.parse::<std::net::Ipv6Addr>().is_err() {
                    return Err("not an IPv6 address in the brackets".into());
                }
                (host, port)
            }
            None => match text.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (text, None),
            },
        };
        let port = match port {
            None => 443,
            Some(port) => port.parse::<u16>().ok().filter(|p| *p > 0).ok_or("a port from 1 to 65535")?,
        };
        let name = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':');
        if host.is_empty() || !host.chars().all(name) {
            return Err("a host of letters, digits, dots and hyphens".into());
        }
        Ok(Route { host: host.to_string(), port })
    }
}

impl fmt::Display for Route {
    /// `HOST` on port 443, else `HOST:PORT`; an IPv6 address in brackets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v6 = self.host.contains(':');
        match (self.port, v6) {
            (443, false) => f.write_str(&self.host),
            (443, true) => write!(f, "[{}]", self.host),
            _ => f.write_str(&podssh_ws::dial::authority(&self.host, self.port)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The forms of a URL and of an authority, and the text that each
    /// route writes, which reads back as the same route.
    #[test]
    fn a_route_reads_from_its_url_and_back() {
        let cases = [
            ("https://api.example", "api.example", 443, "api.example"),
            ("https://api.example/", "api.example", 443, "api.example"),
            ("https://127.0.0.1:8443", "127.0.0.1", 8443, "127.0.0.1:8443"),
            ("https://[2001:db8::1]", "2001:db8::1", 443, "[2001:db8::1]"),
            ("https://[2001:db8::1]:9443", "2001:db8::1", 9443, "[2001:db8::1]:9443"),
        ];
        for (url, host, port, shown) in cases {
            let route = Route::parse_url(url).unwrap();
            assert_eq!((route.host.as_str(), route.port), (host, port), "{url}");
            assert_eq!(route.to_string(), shown);
            assert_eq!(Route::parse_authority(shown).unwrap(), route, "{shown}");
        }
        assert_eq!(Route::https("api.example").to_string(), "api.example");
    }

    /// A URL that is not of HTTPS, or holds a path, a user, a query or a
    /// port out of range, is refused, as is a host of other characters.
    #[test]
    fn a_url_of_another_shape_is_refused() {
        for bad in [
            "http://api.example",
            "api.example",
            "https://",
            "https://api.example/v0a4471/reg",
            "https://user@api.example",
            "https://api.example?x=1",
            "https://api.example:0",
            "https://api.example:70000",
            "https://[2001:db8::1",
            "https://[not-v6]:443",
            "https://api example",
            "https://api.example:443:1",
        ] {
            assert!(Route::parse_url(bad).is_err(), "{bad}");
        }
    }
}
