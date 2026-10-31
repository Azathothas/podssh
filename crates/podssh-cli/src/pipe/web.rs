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

/// The other side of `http-listen:`: `%h:%p` once, as the target, and last.
pub fn template(text: &str) -> Result<Address, Refusal> {
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
