//! The addresses of `podssh pipe A B` (T-174, T-175): `KIND:REST`, both
//! checked before anything starts. `-` is `stdio`. The local kinds are
//! `stdio`, `fd:N` (Unix) and `exec:CMD`; the remote ones `relay:HOST:PORT`,
//! `tcp:HOST:PORT`, `ssh:[USER@]HOP[,HOP...],HOST:PORT`, `node:NAME` and
//! `iroh:TICKET`; a local socket `unix-connect:PATH` (T-176); the
//! listeners `unix-listen:PATH` and `tcp-listen:[ADDR:]PORT` (T-177), one
//! side at most; UDP through a node, `udp:node:NAME` (T-168); a serial
//! line `serial:PATH[,BAUD]` (T-181), on Unix; an HTTP CONNECT proxy,
//! `http-listen:`, whose other side names each request's target as `%h:%p`
//! (T-367, `web`); and a WebSocket, `ws://` and `wss://` by its URL, or
//! `ws-listen:` (T-368).

use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::relay_settings::Refusal;

/// One side of a pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// stdin and stdout.
    Stdio,
    /// A descriptor that podssh inherited, 3 or more (Unix).
    Fd(i32),
    /// A program and its words, started with no shell.
    Exec(Vec<String>),
    /// TCP to HOST:PORT through the relay.
    Relay { host: String, port: u16 },
    /// TCP to HOST:PORT from this host, through `HTTPS_PROXY` when it is set.
    Tcp { host: String, port: u16 },
    /// TCP to HOST:PORT that the last of the SSH hops opens, as `-W` asks;
    /// each hop as `-J` reads it.
    Ssh { hops: Vec<String>, host: String, port: u16 },
    /// The TARGET of the node of the pair under this label.
    Node(String),
    /// The TARGET of a node of the iroh road, by its ticket.
    Iroh(String),
    /// UDP through the node of the pair under this label, whose TARGET is
    /// `udp:HOST:PORT`: each datagram after its 16-bit length.
    UdpNode(String),
    /// A local socket: a path, `@NAME` in Linux's abstract namespace, or on
    /// Windows a named pipe.
    Unix(String),
    /// A local socket that podssh listens on, by the same names.
    UnixListen(String),
    /// A TCP port that podssh listens on: 127.0.0.1, or the address given.
    TcpListen { host: String, port: u16 },
    /// An HTTP CONNECT proxy on the `TcpListen` or `UnixListen` within it.
    HttpListen(Box<Address>),
    /// A WebSocket by its URL, with no token.
    Ws(podssh_ws::url::WsUrl),
    /// A WebSocket server on the `TcpListen` or `UnixListen` within it.
    WsListen(Box<Address>),
    /// The other side of `http-listen:`: a road whose target each request
    /// names, `%h:%p`.
    Template(super::web::Template),
    /// A serial device of this host, at a speed of [`BAUDS`] (Unix).
    Serial { path: String, baud: u32 },
}

impl Address {
    /// Whether this side waits for a client to connect.
    pub fn listens(&self) -> bool {
        matches!(self.bound(), Address::UnixListen(_) | Address::TcpListen { .. })
    }

    /// What this side binds: itself, or the port or the socket of a proxy or
    /// of a WebSocket server.
    pub fn bound(&self) -> &Address {
        match self {
            Address::HttpListen(at) | Address::WsListen(at) => &**at,
            other => other,
        }
    }
}

/// The kinds that an unknown kind lists.
pub const KINDS: &[&str] = &[
    "-",
    "stdio",
    "fd:N",
    "exec:CMD",
    "relay:HOST:PORT",
    "tcp:HOST:PORT",
    "ssh:[USER@]HOP[,HOP...],HOST:PORT",
    "node:NAME",
    "udp:node:NAME",
    "iroh:TICKET",
    "unix-connect:PATH",
    "unix-listen:PATH",
    "tcp-listen:[ADDR:]PORT",
    "http-listen:[ADDR:]PORT",
    "http-listen:PATH",
    "ws://HOST[:PORT]/PATH",
    "wss://HOST[:PORT]/PATH",
    "ws-listen:[ADDR:]PORT",
    "ws-listen:PATH",
    "serial:PATH[,BAUD]",
];

/// The speeds of `serial:`, in baud: those that Linux names.
pub const BAUDS: &[u32] = &[
    1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 500000, 576000, 921600, 1000000,
    1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000,
];
/// The speed of `serial:` with no BAUD.
pub const DEFAULT_BAUD: u32 = 115200;

/// A and B, each checked: no side starts before both are good.
pub fn both(a: Option<&str>, b: Option<&str>) -> Result<(Address, Address), Refusal> {
    let a = a.ok_or("missing A and B: the two addresses to join, such as stdio exec:CMD")?;
    let b = b.ok_or("missing B: the second address")?;
    // The other side of a proxy names no target: each request gives one.
    let proxy = |text: &str| text.starts_with("http-listen:");
    let (a, b) = match (proxy(a), proxy(b)) {
        (true, false) => (parse(a)?, super::web::template(b)?),
        (false, true) => (super::web::template(a)?, parse(b)?),
        _ => (parse(a)?, parse(b)?),
    };
    if a == Address::Stdio && b == Address::Stdio {
        return Err(Refusal::usage("stdio on both sides joins stdin to stdout; name another address"));
    }
    if a.listens() && b.listens() {
        return Err(Refusal::usage("one side may listen; the other names where its bytes go"));
    }
    Ok((a, b))
}

/// One address.
pub fn parse(text: &str) -> Result<Address, Refusal> {
    if text == "-" || text == "stdio" {
        return Ok(Address::Stdio);
    }
    let kinds = KINDS.join(", ");
    let Some((kind, rest)) = text.split_once(':') else {
        return Err(Refusal::usage(format!("{text}: not an address; the kinds are {kinds}")));
    };
    match kind {
        "fd" => fd(rest).map(Address::Fd),
        "exec" => words(rest).map(Address::Exec).map_err(|why| Refusal::usage(format!("exec:{rest}: {why}"))),
        "relay" => {
            let (host, port) = target(kind, rest)?;
            // The path that the relay takes must be one that it can carry.
            podssh_relay::relay::forward_path(&host, port)
                .map_err(|why| Refusal::usage(format!("relay:{rest}: {why}")))?;
            Ok(Address::Relay { host, port })
        }
        "tcp" => target(kind, rest).map(|(host, port)| Address::Tcp { host, port }),
        "ssh" => ssh(rest),
        "node" => node_label("node", rest).map(Address::Node),
        "udp" => udp(rest),
        "iroh" => iroh(rest),
        "unix-connect" => socket_name(kind, rest).map(Address::Unix),
        "unix-listen" => socket_name(kind, rest).map(Address::UnixListen),
        "tcp-listen" => tcp_port(kind, rest),
        "http-listen" => super::web::http_proxy(rest),
        "ws" | "wss" => super::web::ws_url(text),
        "ws-listen" => super::web::ws_server(rest),
        "serial" => serial(rest),
        "stdio" => Err(Refusal::usage("stdio takes nothing after it")),
        other => Err(Refusal::usage(format!("{other}: no such kind of address; the kinds are {kinds}"))),
    }
}

/// The label of `node:NAME`, the pair of the node.
fn node_label(kind: &str, rest: &str) -> Result<String, Refusal> {
    if rest.contains(',') {
        return Err(Refusal::usage(format!("{kind}:{rest}: a node serves one TARGET; name the node alone")));
    }
    crate::pairs::check_label(rest)?;
    Ok(rest.to_string())
}

/// `udp:node:NAME`: datagrams through a node that sends them as UDP. This
/// host sends none, and the relay carries TCP only, so a target of UDP is
/// named on the node's command line: `podssh node NAME udp:HOST:PORT`.
fn udp(rest: &str) -> Result<Address, Refusal> {
    let Some(label) = rest.strip_prefix("node:") else {
        let kinds = KINDS.join(", ");
        return Err(Refusal::usage(format!(
            "udp:{rest}: this host sends no UDP, and the relay carries TCP only: run podssh node NAME \
             udp:HOST:PORT where UDP is allowed, and name udp:node:NAME here; the kinds are {kinds}"
        )));
    };
    node_label("udp:node", label).map(Address::UdpNode)
}

/// `[USER@]HOP[,HOP...],HOST:PORT`: the last item is the target, each other
/// item a hop, as `-J` reads one.
fn ssh(rest: &str) -> Result<Address, Refusal> {
    let items: Vec<&str> = rest.split(',').map(str::trim).collect();
    let Some((last, hops)) = items.split_last().filter(|(_, hops)| !hops.is_empty()) else {
        return Err(Refusal::usage(format!("ssh:{rest}: name a host to log in to, then HOST:PORT")));
    };
    for hop in hops {
        crate::ssh::resolve::parse_hop(hop).map_err(|why| Refusal::usage(format!("ssh:{rest}: {why}")))?;
    }
    let (host, port) = target("ssh", last)?;
    Ok(Address::Ssh { hops: hops.iter().map(|h| h.to_string()).collect(), host, port })
}

/// The PATH of `unix-connect:` and `unix-listen:`: a name that fits a
/// socket's address, checked before the call; `@NAME` on Linux alone. A
/// named pipe of Windows has room for more.
pub(super) fn socket_name(kind: &str, rest: &str) -> Result<String, Refusal> {
    if rest.is_empty() {
        return Err(Refusal::usage(format!("{kind}: names no socket")));
    }
    if rest.starts_with('@') && !cfg!(target_os = "linux") {
        return Err(Refusal::usage(format!("{kind}:{rest}: the abstract namespace is Linux's")));
    }
    let pipe = rest.to_ascii_lowercase().replace('/', "\\").starts_with(r"\\.\pipe\");
    // The name's NUL, or the abstract name's leading one.
    let room = super::unix::SUN_PATH - 1;
    if !(cfg!(windows) && pipe) && rest.len() > room {
        let has = rest.len();
        return Err(Refusal::usage(format!("{kind}:{rest}: a socket's name holds {room} bytes, and this has {has}")));
    }
    Ok(rest.to_string())
}

/// `tcp-listen:PORT` on 127.0.0.1, or `tcp-listen:ADDR:PORT` on an address
/// of this host: an IP literal (an IPv6 one in brackets) or `localhost`.
/// Port 0 asks the system for a free one, and podssh says which. `kind` is
/// the address's, for its lines: `http-listen:` takes a port so too.
pub(super) fn tcp_port(kind: &str, rest: &str) -> Result<Address, Refusal> {
    let bad = |why: &str| Refusal::usage(format!("{kind}:{rest}: {why}"));
    let (host, port) = match rest.rsplit_once(':') {
        None => ("127.0.0.1", rest),
        Some((host, port)) => (host, port),
    };
    let port: u16 = port.parse().map_err(|_| bad("PORT is a number from 0 to 65535"))?;
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<std::net::Ipv6Addr>().map_err(|_| bad("not an IPv6 address"))?.to_string(),
        None if host.eq_ignore_ascii_case("localhost") => "127.0.0.1".to_string(),
        None if host.contains(':') => return Err(bad("an IPv6 address goes in brackets: [ADDR]:PORT")),
        None => host
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| bad("ADDR is an address of this host, as 127.0.0.1, [::1] or localhost; no name is resolved"))?
            .to_string(),
    };
    Ok(Address::TcpListen { host, port })
}

/// `serial:PATH[,BAUD]`: a device of this host, on Unix; BAUD from
/// [`BAUDS`], [`DEFAULT_BAUD`] when none is given. The text after the last
/// comma is BAUD, so a PATH with a comma takes a BAUD after it.
fn serial(rest: &str) -> Result<Address, Refusal> {
    if cfg!(windows) {
        return Err(Refusal::usage(format!(
            "serial:{rest}: a serial line is opened on Unix only; a COM port of Windows is not built yet"
        )));
    }
    let (path, baud) = match rest.rsplit_once(',') {
        None => (rest, DEFAULT_BAUD),
        Some((path, baud)) => match baud.trim().parse::<u32>() {
            Ok(baud) if BAUDS.contains(&baud) => (path, baud),
            _ => {
                let bauds: Vec<String> = BAUDS.iter().map(u32::to_string).collect();
                return Err(Refusal::usage(format!("serial:{rest}: BAUD is one of {}", bauds.join(", "))));
            }
        },
    };
    if path.is_empty() {
        return Err(Refusal::usage(format!("serial:{rest}: names no device, such as serial:/dev/ttyUSB0")));
    }
    Ok(Address::Serial { path: path.to_string(), baud })
}

/// `iroh:TICKET`, in a build with the feature `iroh`.
fn iroh(rest: &str) -> Result<Address, Refusal> {
    if !cfg!(feature = "iroh") {
        return Err(Refusal { message: crate::ssh::iroh::not_built("iroh:"), code: EXIT_NOT_IMPLEMENTED });
    }
    if rest.is_empty() {
        return Err(Refusal::usage("iroh: names no ticket"));
    }
    Ok(Address::Iroh(format!("iroh:{rest}")))
}

/// `HOST:PORT` or `[IPV6]:PORT`, as `podssh proxy` reads its one word.
fn target(kind: &str, rest: &str) -> Result<(String, u16), Refusal> {
    if rest.contains("%h") || rest.contains("%p") {
        let why = "%h:%p is a target that each request of http-listen: fills in, on its other side";
        return Err(Refusal::usage(format!("{kind}:{rest}: {why}")));
    }
    crate::proxy::parse_target(Some(rest), None).map_err(|why| Refusal::usage(format!("{kind}:{rest}: {why}")))
}

fn fd(rest: &str) -> Result<i32, Refusal> {
    if !cfg!(unix) {
        return Err(Refusal::usage(format!("fd:{rest}: descriptors are passed on Unix only")));
    }
    let n: i32 = rest.parse().map_err(|_| Refusal::usage(format!("fd:{rest}: N is a number")))?;
    if n < 3 {
        return Err(Refusal::usage(format!("fd:{n}: 0, 1 and 2 are stdio; name stdio")));
    }
    Ok(n)
}

/// The words of `exec:CMD`, as a shell splits them with its quotes only: no
/// variables, globs or backslash escapes, so a Windows path keeps its `\`.
/// podssh starts no shell, as it assumes none (`exec:sh -c 'CMD'` names one).
pub fn words(cmd: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    // A word that has begun, even an empty one in quotes.
    let mut begun = false;
    let mut quote: Option<char> = None;
    for c in cmd.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => word.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                begun = true;
            }
            None if c.is_whitespace() => {
                if begun {
                    words.push(std::mem::take(&mut word));
                    begun = false;
                }
            }
            None => {
                word.push(c);
                begun = true;
            }
        }
    }
    if let Some(q) = quote {
        return Err(format!("a {q} that does not close"));
    }
    if begun {
        words.push(word);
    }
    if words.is_empty() {
        return Err("names no program".into());
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(text: &str) -> i32 {
        parse(text).expect_err(text).code
    }

    #[test]
    fn the_local_kinds_parse_and_a_dash_is_stdio() {
        assert_eq!(parse("-").unwrap(), Address::Stdio);
        assert_eq!(parse("stdio").unwrap(), Address::Stdio);
        assert_eq!(parse("exec:cat").unwrap(), Address::Exec(vec!["cat".into()]));
        if cfg!(unix) {
            assert_eq!(parse("fd:3").unwrap(), Address::Fd(3));
        }
    }

    #[test]
    fn an_unknown_kind_is_a_usage_error_that_lists_the_kinds() {
        let refusal = parse("sctp:example.org:80").unwrap_err();
        assert_eq!(refusal.code, 64);
        assert!(refusal.message.contains("exec:CMD"), "{}", refusal.message);
        assert!(refusal.message.contains("serial:PATH[,BAUD]"), "{}", refusal.message);
        assert_eq!(code("example.org"), 64);
        assert_eq!(code("stdio:x"), 64);
    }

    #[test]
    fn a_serial_line_takes_a_speed_of_the_table_and_is_unix_s() {
        if cfg!(windows) {
            assert_eq!(code("serial:COM3"), 64);
            assert_eq!(code("serial:COM3,9600"), 64);
            return;
        }
        let serial = |path: &str, baud| Address::Serial { path: path.into(), baud };
        assert_eq!(parse("serial:/dev/ttyUSB0").unwrap(), serial("/dev/ttyUSB0", 115200));
        assert_eq!(parse("serial:/dev/ttyS0,9600").unwrap(), serial("/dev/ttyS0", 9600));
        assert_eq!(parse("serial:/dev/odd,name,4000000").unwrap(), serial("/dev/odd,name", 4000000));
        assert!(!parse("serial:/dev/ttyS0").unwrap().listens());
        for bad in ["serial:", "serial:,9600", "serial:/dev/ttyS0,", "serial:/dev/ttyS0,9601", "serial:/dev/x,fast"] {
            assert_eq!(code(bad), 64, "{bad}");
        }
        assert_eq!(code("serial:/dev/ttyS0,8000000"), 64);
    }

    #[test]
    fn a_listener_is_a_socket_or_a_port_of_this_host_and_one_side_at_most() {
        let tcp = |host: &str, port| Address::TcpListen { host: host.into(), port };
        assert_eq!(parse("tcp-listen:2222").unwrap(), tcp("127.0.0.1", 2222));
        assert_eq!(parse("tcp-listen:0").unwrap(), tcp("127.0.0.1", 0));
        assert_eq!(parse("tcp-listen:localhost:80").unwrap(), tcp("127.0.0.1", 80));
        assert_eq!(parse("tcp-listen:[::1]:22").unwrap(), tcp("::1", 22));
        assert_eq!(parse("tcp-listen:0.0.0.0:8080").unwrap(), tcp("0.0.0.0", 8080));
        for bad in ["tcp-listen:", "tcp-listen:x", "tcp-listen:70000", "tcp-listen:example.org:80", "tcp-listen:::1:22"]
        {
            assert_eq!(code(bad), 64, "{bad}");
        }
        assert_eq!(code("tcp-listen:[x]:22"), 64);
        assert_eq!(parse("unix-listen:/tmp/s.sock").unwrap(), Address::UnixListen("/tmp/s.sock".into()));
        assert_eq!(code("unix-listen:"), 64);
        assert_eq!(code(&format!("unix-listen:/{}", "x".repeat(200))), 64);
        assert!(parse("tcp-listen:1").unwrap().listens());
        assert!(!parse("unix-connect:/tmp/s").unwrap().listens());
        assert_eq!(both(Some("unix-listen:/tmp/a"), Some("tcp-listen:1")).unwrap_err().code, 64);
        assert!(both(Some("tcp-listen:1"), Some("stdio")).is_ok());
    }

    #[test]
    fn a_remote_target_is_host_and_port_or_an_ipv6_address_in_brackets() {
        let relay = |host: &str, port| Address::Relay { host: host.into(), port };
        assert_eq!(parse("relay:example.org:80").unwrap(), relay("example.org", 80));
        assert_eq!(parse("relay:[2001:db8::1]:22").unwrap(), relay("2001:db8::1", 22));
        assert_eq!(parse("tcp:127.0.0.1:8080").unwrap(), Address::Tcp { host: "127.0.0.1".into(), port: 8080 });
        for bad in ["relay:example.org", "tcp:example.org:0", "relay:2001:db8::1:22", "tcp::80"] {
            assert_eq!(code(bad), 64, "{bad}");
        }
    }

    #[test]
    fn ssh_names_its_hops_then_the_target_and_node_names_a_pair() {
        let ssh = parse("ssh:me@bastion,db.internal:5432").unwrap();
        assert_eq!(ssh, Address::Ssh { hops: vec!["me@bastion".into()], host: "db.internal".into(), port: 5432 });
        let two = parse("ssh:a@h1:2222, b@h2 ,[2001:db8::1]:22").unwrap();
        let Address::Ssh { hops, host, .. } = two else { panic!() };
        assert_eq!((hops, host), (vec!["a@h1:2222".to_string(), "b@h2".to_string()], "2001:db8::1".to_string()));
        for bad in ["ssh:db:5432", "ssh:,db:5432", "ssh:@h,db:5432", "ssh:h,db", "node:lab,22", "node:../x"] {
            assert_eq!(code(bad), 64, "{bad}");
        }
        assert_eq!(parse("node:lab").unwrap(), Address::Node("lab".into()));
        assert_eq!(parse("udp:node:lab").unwrap(), Address::UdpNode("lab".into()));
        // UDP leaves through a node: a target of UDP is the node's to name.
        let refusal = parse("udp:example.org:53").unwrap_err();
        assert_eq!(refusal.code, 64);
        assert!(refusal.message.contains("podssh node NAME udp:HOST:PORT"), "{}", refusal.message);
        for bad in ["udp:node:", "udp:node:lab,53", "udp:node:../x", "udp:lab"] {
            assert_eq!(code(bad), 64, "{bad}");
        }
        if !cfg!(feature = "iroh") {
            assert_eq!(code("iroh:endpointabc"), 70);
        }
    }

    #[test]
    fn a_socket_s_name_must_fit_its_address() {
        assert_eq!(parse("unix-connect:/run/podman.sock").unwrap(), Address::Unix("/run/podman.sock".into()));
        assert_eq!(code(&format!("unix-connect:/{}", "x".repeat(200))), 64);
        assert_eq!(code("unix-connect:"), 64);
        if cfg!(target_os = "linux") {
            assert_eq!(parse("unix-connect:@podssh").unwrap(), Address::Unix("@podssh".into()));
        } else {
            assert_eq!(code("unix-connect:@podssh"), 64);
        }
        if cfg!(windows) {
            let long = format!(r"\\.\pipe\{}", "p".repeat(150));
            assert!(parse(&format!("unix-connect:{long}")).is_ok(), "a named pipe has room for more");
        }
    }

    #[test]
    fn a_descriptor_is_a_number_from_3_and_only_on_unix() {
        assert_eq!(code("fd:x"), 64);
        assert_eq!(code("fd:0"), 64);
        assert_eq!(code("fd:2"), 64);
        if !cfg!(unix) {
            assert_eq!(code("fd:3"), 64);
        }
    }

    #[test]
    fn stdio_on_both_sides_is_refused_before_anything_starts() {
        let refusal = both(Some("-"), Some("stdio")).unwrap_err();
        assert_eq!(refusal.code, 64);
        assert!(both(Some("stdio"), Some("exec:cat")).is_ok());
        assert_eq!(both(None, None).unwrap_err().code, 64);
        assert_eq!(both(Some("stdio"), None).unwrap_err().code, 64);
        assert_eq!(both(Some("nonsense"), Some("exec:cat")).unwrap_err().code, 64);
    }

    #[test]
    fn words_split_at_blanks_and_keep_what_quotes_hold() {
        let split = |cmd: &str| words(cmd).unwrap();
        assert_eq!(split("sh -c 'exit 7'"), ["sh", "-c", "exit 7"]);
        assert_eq!(split(r#"printf "%s\n" a"#), ["printf", r"%s\n", "a"]);
        assert_eq!(split(r"C:\Tools\nc.exe -v"), [r"C:\Tools\nc.exe", "-v"]);
        assert_eq!(split("echo '' x"), ["echo", "", "x"]);
        assert_eq!(split("  a  b  "), ["a", "b"]);
        assert_eq!(split("a'b c'd"), ["ab cd"]);
        assert_eq!(split("echo $HOME *"), ["echo", "$HOME", "*"], "no variable and no glob");
        assert!(words("sh -c 'exit").is_err());
        assert!(words("   ").is_err());
        assert!(words("").is_err());
    }
}
