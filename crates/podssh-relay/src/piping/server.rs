//! The Piping Server of the road: `https://ppng.io`, which its author
//! (nwtgck) runs and which needs no account, unless the user names another
//! as `https://HOST[:PORT][/PREFIX]`: a server of the user's own, maybe
//! behind a prefix of a reverse proxy. No `http://`: the paths are the
//! road's meeting point, and a proxy on the way would read them.

use std::fmt;

/// The server of the road when the user names none.
pub const DEFAULT_HOST: &str = "ppng.io";
/// The port of a server that names none.
pub const PORT: u16 = 443;

/// A Piping Server: the name that its certificate holds, its HTTPS port, and
/// the prefix of its paths, empty or `/` and words with no `/` at its end.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub prefix: String,
}

impl Default for Server {
    fn default() -> Server {
        Server { host: DEFAULT_HOST.to_string(), port: PORT, prefix: String::new() }
    }
}

impl Server {
    /// `https://HOST[:PORT][/PREFIX]`, with or without a `/` at its end. A
    /// user, a query or a fragment is refused: a Piping Server reads the
    /// path alone, and a `?n=` would change who meets.
    pub fn parse(text: &str) -> Result<Server, String> {
        let shown = podssh_ws::text::one_line(text.trim());
        let rest = text.trim().strip_prefix("https://").ok_or_else(|| format!("{shown:?} is not an https:// URL"))?;
        if rest.contains(['?', '#', '@', '%', '\\']) || rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!("{shown:?}: a Piping Server's URL has no user, query, fragment or escape"));
        }
        let (authority, prefix) = match rest.find('/') {
            Some(at) => (&rest[..at], rest[at..].trim_end_matches('/')),
            None => (rest, ""),
        };
        if prefix.contains("//") || prefix.split('/').any(|word| word == "." || word == "..") {
            return Err(format!("{shown:?}: the prefix is not a plain path"));
        }
        let (host, port) = split_port(authority).map_err(|why| format!("{shown:?}: {why}"))?;
        // A name, an IPv4 address, or an IPv6 one with no zone.
        podssh_ws::names::check_target(host).map_err(|why| format!("{shown:?}: {why}"))?;
        Ok(Server { host: host.to_ascii_lowercase(), port, prefix: prefix.to_string() })
    }

    /// `HOST`, or `HOST:PORT` off port 443, as `Host` and `:authority` name
    /// the server; an IPv6 address in brackets.
    pub fn authority(&self) -> String {
        match (self.port, self.host.contains(':')) {
            (PORT, false) => self.host.clone(),
            (PORT, true) => format!("[{}]", self.host),
            (port, _) => podssh_ws::dial::authority(&self.host, port),
        }
    }

    /// The path of `word` on this server.
    pub fn path(&self, word: &str) -> String {
        format!("{}/{word}", self.prefix)
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}{}", self.authority(), self.prefix)
    }
}

/// `HOST`, `HOST:PORT`, `[V6]` or `[V6]:PORT`.
fn split_port(authority: &str) -> Result<(&str, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or("an IPv6 address with no ']'")?;
        return match after {
            "" => Ok((host, PORT)),
            _ => Ok((host, port_of(after.strip_prefix(':').ok_or("no ':' before the port")?)?)),
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Ok((host, port_of(port)?)),
        None => Ok((authority, PORT)),
    }
}

fn port_of(text: &str) -> Result<u16, String> {
    match text.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("{text:?} is not a port")),
        Ok(port) => Ok(port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_ppng_io_on_443_with_no_prefix() {
        let server = Server::default();
        assert_eq!(server.to_string(), "https://ppng.io");
        assert_eq!(Server::parse("https://ppng.io/"), Ok(server.clone()));
        assert_eq!(server.authority(), "ppng.io");
        assert_eq!(server.path("abc"), "/abc");
    }

    #[test]
    fn a_port_and_a_prefix_are_kept_and_the_host_is_in_lower_case() {
        let server = Server::parse("https://Pipe.Example:8443/relay/piping/").unwrap();
        assert_eq!((server.host.as_str(), server.port), ("pipe.example", 8443));
        assert_eq!(server.prefix, "/relay/piping");
        assert_eq!(server.authority(), "pipe.example:8443");
        assert_eq!(server.path("abc"), "/relay/piping/abc");
        assert_eq!(server.to_string(), "https://pipe.example:8443/relay/piping");
        let v6 = Server::parse("https://[::1]:8080").unwrap();
        assert_eq!((v6.host.as_str(), v6.port, v6.authority()), ("::1", 8080, "[::1]:8080".to_string()));
    }

    #[test]
    fn a_url_that_is_not_one_server_s_https_is_refused() {
        for bad in [
            "http://ppng.io",
            "ppng.io",
            "https://",
            "https://ppng.io:0",
            "https://ppng.io:http",
            "https://user@ppng.io",
            "https://ppng.io/?n=2",
            "https://ppng.io/#x",
            "https://ppng.io/a/../b",
            "https://ppng.io/a%2f",
            "https://ppng.io/a b",
            "https://ppng.io\r\nX: y",
        ] {
            assert!(Server::parse(bad).is_err(), "{bad:?}");
        }
    }
}
