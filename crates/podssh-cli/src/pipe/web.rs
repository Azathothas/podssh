//! The addresses of `podssh pipe` that speak HTTP (T-367): `http-listen:`,
//! an HTTP CONNECT proxy on a port as `tcp-listen:` takes it or on a socket
//! as `unix-listen:` takes it, and the template of its other side, a road
//! whose target each request names as `%h:%p`, as `ProxyCommand` names the
//! host and the port in OpenSSH. And those of a WebSocket (T-368): `ws://`
//! and `wss://` by the URL that a user copies, and `ws-listen:`, a server
//! on a port or a socket by the same rules.

use super::address::{self, Address};
use crate::relay_settings::Refusal;

/// The target of each request, in a template.
pub const TARGET: &str = "%h:%p";

/// The forms of the other side of `http-listen:`, for its lines.
const FORMS: &str = "relay:%h:%p, tcp:%h:%p or ssh:[USER@]HOP[,HOP...],%h:%p";

/// `http-listen:[ADDR:]PORT`, or `http-listen:PATH` for a socket.
pub fn http_proxy(rest: &str) -> Result<Address, Refusal> {
    listening_at("http-listen", rest).map(|at| Address::HttpListen(Box::new(at)))
}

/// Where a listener of `kind` listens: a socket when REST is a path (it holds
/// a `/`, or on Windows a `\`, or it is `@NAME`), else a TCP port.
pub(super) fn listening_at(kind: &str, rest: &str) -> Result<Address, Refusal> {
    let path = rest.contains('/') || rest.starts_with('@') || (cfg!(windows) && rest.contains('\\'));
    if path {
        return address::socket_name(kind, rest).map(Address::UnixListen);
    }
    if !rest.contains(':') && rest.parse::<u16>().is_err() {
        return Err(Refusal::usage(format!(
            "{kind}:{rest}: a PORT is a number from 0 to 65535, and a socket's PATH holds a /, as ./{rest}"
        )));
    }
    address::tcp_port(kind, rest)
}

/// `ws://HOST[:PORT]/PATH` or `wss://...`, as `podssh_ws::url` reads it.
/// The form `wss:HOST:PORT/PATH` is refused with the URL's; a line shows the
/// address without its query, which may hold a secret.
pub fn ws_url(text: &str) -> Result<Address, Refusal> {
    let shown = text.split(['?', '#']).next().unwrap_or_default();
    podssh_ws::url::WsUrl::parse(text).map(Address::Ws).map_err(|why| Refusal::usage(format!("{shown}: {why}")))
}

/// `ws-listen:[ADDR:]PORT`, or `ws-listen:PATH` for a socket.
pub fn ws_server(rest: &str) -> Result<Address, Refusal> {
    listening_at("ws-listen", rest).map(|at| Address::WsListen(Box::new(at)))
}

/// The road of the other side of `http-listen:`, whose target each request
/// fills in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Template {
    /// `relay:%h:%p`: through the relay.
    Relay,
    /// `tcp:%h:%p`: from this host, through `HTTPS_PROXY` when it is set.
    Tcp,
    /// `ssh:HOPS,%h:%p`: from the last of these hops.
    Ssh(Vec<String>),
}

/// The other side of `http-listen:`: `%h:%p` once, as the target, and last;
/// or a road with no target, which takes it at its end (`with_target`).
pub fn template(given: &str) -> Result<Address, Refusal> {
    if let Some(what) = takes_no_target(given) {
        return Err(Refusal::usage(format!(
            "{given} cannot be the other side of http-listen:: each CONNECT names its own target, which {what} \
             does not take; give {FORMS}"
        )));
    }
    let full = with_target(given).map(|(full, _)| full);
    let text = full.as_deref().unwrap_or(given);
    let head = text.strip_suffix(TARGET).filter(|head| !head.contains("%h") && !head.contains("%p"));
    let Some(head) = head else {
        return Err(Refusal::usage(format!(
            "{text}: the other side of http-listen: names its target %h:%p, once and last: {FORMS}"
        )));
    };
    let template = match head {
        "relay:" => Template::Relay,
        "tcp:" => Template::Tcp,
        _ => match head.strip_prefix("ssh:").and_then(|hops| hops.strip_suffix(',')) {
            Some(hops) => Template::Ssh(hops.split(',').map(|hop| hop.trim().to_string()).collect()),
            None => return Err(Refusal::usage(format!("{text}: http-listen: takes {FORMS}"))),
        },
    };
    // Checked now with a target, as each request's target will be.
    template.fill("example.org", 443)?;
    Ok(Address::Template(template))
}

/// A road that a proxy reads with its target at its end, when the text has
/// no `%h` and no `%p`: `ssh:HOP[,HOP...]` takes `,%h:%p`, and `relay` and
/// `tcp`, with a colon or none, take `:%h:%p`. The full template, and where
/// each CONNECT's target is reached from. Each word of `ssh:` is a hop, as a
/// proxy has no fixed target.
fn with_target(text: &str) -> Option<(String, &'static str)> {
    if text.contains("%h") || text.contains("%p") {
        return None;
    }
    match text.strip_suffix(':').unwrap_or(text) {
        "relay" => return Some((format!("relay:{TARGET}"), "through the relay")),
        "tcp" => return Some((format!("tcp:{TARGET}"), "from this host")),
        _ => {}
    }
    let hops = text.strip_prefix("ssh:")?.trim_end_matches(',');
    if hops.trim().is_empty() {
        return None;
    }
    Some((format!("ssh:{hops},{TARGET}"), "from the last hop"))
}

/// What an address of a kind that never takes a target is, for the refusal
/// that says why it cannot be the other side of a proxy; `None` for the
/// roads, whose own form is checked.
fn takes_no_target(text: &str) -> Option<&'static str> {
    if text == "-" || text == "stdio" {
        return Some("stdio");
    }
    let kind = text.split_once(':').map_or(text, |(kind, _)| kind);
    Some(match kind {
        "exec" => "a command",
        "fd" => "a descriptor",
        "node" | "udp" | "iroh" => "a node, with its one TARGET,",
        "unix-connect" => "a socket",
        "serial" => "a serial line",
        "ws" | "wss" => "a WebSocket",
        "unix-listen" | "tcp-listen" | "http-listen" | "ws-listen" => "a listener",
        _ => return None,
    })
}

/// The line that says how the other side of a proxy is read when it named no
/// target, said before the proxy listens; `None` when it named its target,
/// or when neither side is a proxy.
pub fn reading(a: &str, b: &str) -> Option<String> {
    let other = match (a.starts_with("http-listen:"), b.starts_with("http-listen:")) {
        (true, false) => b,
        (false, true) => a,
        _ => return None,
    };
    let (full, from) = with_target(other)?;
    Some(format!("http-listen: {other} is read as {full}: each CONNECT's target is reached {from}"))
}

impl Template {
    /// The road to `host:port`, checked as the address of its text is.
    pub fn fill(&self, host: &str, port: u16) -> Result<Address, Refusal> {
        let target = podssh_ws::dial::authority(host, port);
        let text = match self {
            Template::Relay => format!("relay:{target}"),
            Template::Tcp => format!("tcp:{target}"),
            Template::Ssh(hops) => format!("ssh:{},{target}", hops.join(",")),
        };
        address::parse(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(a: &str, b: &str) -> i32 {
        address::both(Some(a), Some(b)).expect_err(&format!("{a} {b}")).code
    }

    #[test]
    fn http_listen_takes_a_port_as_tcp_listen_does_or_a_socket_s_path() {
        let tcp = |host: &str, port| Address::HttpListen(Box::new(Address::TcpListen { host: host.into(), port }));
        assert_eq!(address::parse("http-listen:8080").unwrap(), tcp("127.0.0.1", 8080));
        assert_eq!(address::parse("http-listen:localhost:0").unwrap(), tcp("127.0.0.1", 0));
        assert_eq!(address::parse("http-listen:[::1]:3128").unwrap(), tcp("::1", 3128));
        assert_eq!(address::parse("http-listen:0.0.0.0:3128").unwrap(), tcp("0.0.0.0", 3128));
        let socket = address::parse("http-listen:/tmp/proxy.sock").unwrap();
        assert_eq!(socket, Address::HttpListen(Box::new(Address::UnixListen("/tmp/proxy.sock".into()))));
        assert!(socket.listens());
        assert_eq!(socket.bound(), &Address::UnixListen("/tmp/proxy.sock".into()));
        for bad in ["http-listen:", "http-listen:proxy.sock", "http-listen:70000", "http-listen:example.org:80"] {
            assert_eq!(address::parse(bad).unwrap_err().code, 64, "{bad}");
        }
        assert!(address::parse("http-listen:proxy.sock").unwrap_err().message.contains("./proxy.sock"));
    }

    #[test]
    fn the_other_side_of_a_proxy_names_its_target_as_a_template() {
        let (a, b) = address::both(Some("http-listen:3128"), Some("relay:%h:%p")).unwrap();
        assert!(a.listens());
        assert_eq!(b, Address::Template(Template::Relay));
        let (a, b) = address::both(Some("tcp:%h:%p"), Some("http-listen:3128")).unwrap();
        assert_eq!((a, b.listens()), (Address::Template(Template::Tcp), true));
        let (_, b) = address::both(Some("http-listen:3128"), Some("ssh:me@bastion, you@inner,%h:%p")).unwrap();
        assert_eq!(b, Address::Template(Template::Ssh(vec!["me@bastion".into(), "you@inner".into()])));
        for other in ["stdio", "exec:cat", "relay:example.org:443", "relay:%h:443", "ssh:%h:%p", "node:%h:%p"] {
            assert_eq!(code("http-listen:3128", other), 64, "{other}");
        }
        for other in ["relay:%h:%p%p", "tcp:%h:%p:%h:%p", "ssh:me@%h,%h:%p", "tcp-listen:%h:%p"] {
            assert_eq!(code("http-listen:3128", other), 64, "{other}");
        }
        // A template is for the other side of a proxy alone.
        let refusal = address::both(Some("stdio"), Some("relay:%h:%p")).unwrap_err();
        assert!(refusal.message.contains("http-listen:"), "{}", refusal.message);
        assert_eq!(code("http-listen:1", "http-listen:2"), 64);
    }

    /// A road with no target takes `%h:%p` at its end, and the line says
    /// the reading; each word of `ssh:` is a hop (T-483).
    #[test]
    fn a_road_with_no_target_takes_each_request_s_target_at_its_end() {
        let template = |b: &str| address::both(Some("http-listen:3128"), Some(b)).map(|(_, b)| b);
        let ssh = |hops: &[&str]| Address::Template(Template::Ssh(hops.iter().map(|h| h.to_string()).collect()));
        assert_eq!(template("ssh:me@bastion").unwrap(), ssh(&["me@bastion"]));
        assert_eq!(template("ssh:a,b").unwrap(), ssh(&["a", "b"]));
        assert_eq!(template("ssh:me@bastion,").unwrap(), ssh(&["me@bastion"]));
        for (given, want) in [("relay", Template::Relay), ("relay:", Template::Relay), ("tcp", Template::Tcp)] {
            assert_eq!(template(given).unwrap(), Address::Template(want), "{given}");
        }
        assert_eq!(template("tcp:").unwrap(), Address::Template(Template::Tcp));
        for bad in ["ssh:me@%h", "relay:%h:443", "ssh:", "ssh:,", "relay:example.org:443"] {
            assert_eq!(code("http-listen:3128", bad), 64, "{bad}");
        }
        let line = reading("http-listen:3128", "ssh:me@bastion").unwrap();
        let want = "http-listen: ssh:me@bastion is read as ssh:me@bastion,%h:%p: each CONNECT's target is reached \
                    from the last hop";
        assert_eq!(line, want);
        let line = reading("tcp", "http-listen:/tmp/proxy.sock").unwrap();
        assert!(line.ends_with("is read as tcp:%h:%p: each CONNECT's target is reached from this host"), "{line}");
        assert_eq!(reading("http-listen:3128", "relay:%h:%p"), None, "a target named says nothing");
        assert_eq!(reading("stdio", "relay"), None, "no proxy");
    }

    /// Another kind of address says first why it cannot be a proxy's other
    /// side, then the forms (T-483).
    #[test]
    fn a_kind_that_takes_no_target_is_refused_with_why_first() {
        for (other, what) in [
            ("exec:cat", "a command"),
            ("stdio", "stdio"),
            ("node:lab", "a node"),
            ("unix-connect:/tmp/s.sock", "a socket"),
            ("tcp-listen:%h:%p", "a listener"),
        ] {
            let refusal = address::both(Some("http-listen:3128"), Some(other)).unwrap_err();
            assert_eq!(refusal.code, 64, "{other}");
            let head = format!("{other} cannot be the other side of http-listen:: each CONNECT names its own target");
            assert!(refusal.message.starts_with(&head), "{}", refusal.message);
            assert!(refusal.message.contains(&format!("which {what}")) && refusal.message.contains(FORMS), "{other}");
        }
    }

    #[test]
    fn each_request_s_target_fills_the_template_and_is_checked_as_each_target() {
        let relay = Template::Relay.fill("example.org", 443).unwrap();
        assert_eq!(relay, Address::Relay { host: "example.org".into(), port: 443 });
        let v6 = Template::Tcp.fill("2001:db8::1", 22).unwrap();
        assert_eq!(v6, Address::Tcp { host: "2001:db8::1".into(), port: 22 });
        let ssh = Template::Ssh(vec!["me@bastion".into()]).fill("db.internal", 5432).unwrap();
        let hops = vec!["me@bastion".to_string()];
        assert_eq!(ssh, Address::Ssh { hops, host: "db.internal".into(), port: 5432 });
        assert_eq!(Template::Relay.fill("a/b", 443).unwrap_err().code, 64);
    }

    #[test]
    fn a_websocket_is_its_url_and_ws_listen_a_port_or_a_socket() {
        let Address::Ws(url) = address::parse("wss://example.org/socket?k=v").unwrap() else { panic!("not ws") };
        assert_eq!((url.tls, url.port, url.target.as_str()), (true, 443, "/socket?k=v"));
        let refusal = address::parse("wss:example.org:443/socket?token=SECRET").unwrap_err();
        assert_eq!(refusal.code, 64);
        assert!(refusal.message.contains("wss://HOST") && !refusal.message.contains("SECRET"), "{}", refusal.message);
        let server = address::parse("ws-listen:8080").unwrap();
        assert_eq!(server.bound(), &Address::TcpListen { host: "127.0.0.1".into(), port: 8080 });
        assert!(server.listens() && address::parse("ws-listen:/tmp/ws.sock").unwrap().listens());
        assert!(!address::parse("ws://example.org/").unwrap().listens());
        assert_eq!(code("ws-listen:1", "tcp-listen:2"), 64);
        assert_eq!(code("ws-listen:x.sock", "stdio"), 64);
        assert!(address::both(Some("ws-listen:1"), Some("wss://example.org/")).is_ok());
    }
}
