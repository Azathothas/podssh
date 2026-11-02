//! What an operator asks of a node, as the word of its proof names it: no
//! word, the node's target with no route; a route's name (T-089); or a
//! target of the operator's own, which an exit node dials (T-431). An
//! exit's word is `HOST:PORT`, an IPv6 address in brackets, and its ':' tells
//! it from each route's name, which never holds one. The word travels
//! encrypted, so the relay never sees which. A node of before T-431 takes
//! no word with a ':', and refuses the proof whole.

use std::fmt;

/// The most bytes of a word: its length is one byte of the proof.
pub const MAX_WORD: usize = 255;

/// What an operator asks of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// The node's target with no route.
    Target,
    /// A route of the node (T-089).
    Route(String),
    /// A target that the operator names, for an exit node to dial (T-431).
    Exit { host: String, port: u16 },
}

impl Ask {
    /// The ask of a route's name, or of none.
    pub fn of_route(route: Option<&str>) -> Ask {
        route.map_or(Ask::Target, |name| Ask::Route(name.to_string()))
    }

    /// The ask of a proof's word; `None` for a word of neither form, which
    /// the proof is refused for.
    pub fn read(word: Option<&str>) -> Option<Ask> {
        let Some(word) = word else { return Some(Ask::Target) };
        if word.is_empty() || word.len() > MAX_WORD {
            return None;
        }
        if !word.contains(':') {
            return podssh_ws::names::check_node_name(word).is_ok().then(|| Ask::Route(word.to_string()));
        }
        let (host, port) = target_of(word)?;
        Some(Ask::Exit { host, port })
    }

    /// The word of the proof: none for the target with no route.
    pub fn word(&self) -> Option<String> {
        match self {
            Ask::Target => None,
            Ask::Route(name) => Some(name.clone()),
            Ask::Exit { host, port } => Some(exit_word(host, *port)),
        }
    }

    /// The route's name, when a route is asked.
    pub fn route(&self) -> Option<&str> {
        match self {
            Ask::Route(name) => Some(name),
            _ => None,
        }
    }

    /// The host and the port of an exit's target, when one is asked.
    pub fn exit(&self) -> Option<(&str, u16)> {
        match self {
            Ask::Exit { host, port } => Some((host, *port)),
            _ => None,
        }
    }
}

/// What a node's line says after "came in": nothing for its target with no
/// route.
impl fmt::Display for Ask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ask::Target => Ok(()),
            Ask::Route(name) => write!(f, " to the route {name}"),
            Ask::Exit { host, port } => write!(f, " to {} through the exit", exit_word(host, *port)),
        }
    }
}

/// `HOST:PORT`, an IPv6 address in brackets: the word of an exit's target.
pub fn exit_word(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The host and the port of an exit's word: a name or an IPv4 address, or
/// an IPv6 address in brackets, and a port from 1, each checked as a target
/// of a road is.
fn target_of(word: &str) -> Option<(String, u16)> {
    let (host, port) = match word.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']')?;
            host.parse::<std::net::Ipv6Addr>().ok()?;
            (host, after.strip_prefix(':')?)
        }
        None => {
            let (host, port) = word.rsplit_once(':')?;
            // A bare IPv6 address would read as a host and a port.
            if host.contains(':') {
                return None;
            }
            (host, port)
        }
    };
    // Digits alone: `u16`'s parser takes a sign too.
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    podssh_ws::names::check_target(host).ok()?;
    Some((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(host: &str, port: u16) -> Ask {
        Ask::Exit { host: host.into(), port }
    }

    #[test]
    fn each_ask_reads_back_from_its_word() {
        for ask in [Ask::Target, Ask::Route("web".into()), exit("github.com", 22), exit("2606:4700::1111", 443)] {
            assert_eq!(Ask::read(ask.word().as_deref()), Some(ask.clone()), "{ask:?}");
        }
        assert_eq!(exit("2606:4700::1111", 443).word().as_deref(), Some("[2606:4700::1111]:443"));
        assert_eq!(Ask::read(Some("140.82.112.3:22")), Some(exit("140.82.112.3", 22)));
    }

    #[test]
    fn a_route_is_never_an_exit_and_a_bad_word_is_neither() {
        // Each route's name of T-089 stays a route: it holds no ':'.
        for name in ["web", "db.main", "a_b-c", "8080"] {
            assert_eq!(Ask::read(Some(name)), Some(Ask::Route(name.into())), "{name}");
        }
        for bad in [
            "",
            ":22",
            "host:",
            "host:0",
            "host:65536",
            "host:+22",
            "host:22x",
            "2001:db8::1:22",
            "[2001:db8::1]",
            "[host]:22",
            "[2001:db8::1]22",
            "a b:22",
            "a/b:22",
            "-x",
            ".x",
        ] {
            assert_eq!(Ask::read(Some(bad)), None, "{bad:?}");
        }
        assert_eq!(Ask::read(Some(&format!("{}:22", "a".repeat(MAX_WORD)))), None, "longer than a proof holds");
    }

    #[test]
    fn a_node_s_line_names_what_was_asked() {
        assert_eq!(Ask::Target.to_string(), "");
        assert_eq!(Ask::Route("web".into()).to_string(), " to the route web");
        assert_eq!(exit("github.com", 22).to_string(), " to github.com:22 through the exit");
        let (route, target) = (Ask::Route("web".into()), exit("a.example", 1));
        assert_eq!((route.route(), target.exit(), Ask::Target.route()), (Some("web"), Some(("a.example", 1)), None));
    }
}
