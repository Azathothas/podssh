//! The addresses of `podssh pipe A B` (T-174, T-175): `KIND:REST`, both
//! checked before anything starts. `-` is `stdio`. The local kinds are
//! `stdio`, `fd:N` (Unix) and `exec:CMD`; the remote ones `relay:HOST:PORT`,
//! `tcp:HOST:PORT`, `ssh:[USER@]HOP[,HOP...],HOST:PORT`, `node:NAME` and
//! `iroh:TICKET`. The kinds of later entries are known, and refused as not
//! built yet, so that a script gets 70 and not a usage error.

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
    "iroh:TICKET",
];

/// The kinds of later entries: a local socket (T-176), listeners (T-177)
/// and a serial line (T-181).
const LATER: &[&str] = &["unix-connect", "unix-listen", "tcp-listen", "serial"];

/// A and B, each checked: no side starts before both are good.
pub fn both(a: Option<&str>, b: Option<&str>) -> Result<(Address, Address), Refusal> {
    let a = parse(a.ok_or("missing A and B: the two addresses to join, such as stdio exec:CMD")?)?;
    let b = parse(b.ok_or("missing B: the second address")?)?;
    if a == Address::Stdio && b == Address::Stdio {
        return Err(Refusal::usage("stdio on both sides joins stdin to stdout; name another address"));
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
        "node" => {
            if rest.contains(',') {
                return Err(Refusal::usage(format!("node:{rest}: a node serves one TARGET; name the node alone")));
            }
            crate::pairs::check_label(rest)?;
            Ok(Address::Node(rest.to_string()))
        }
        "iroh" => iroh(rest),
        "stdio" => Err(Refusal::usage("stdio takes nothing after it")),
        later if LATER.contains(&later) => Err(Refusal {
            message: format!("{later}: addresses are not built yet; the kinds are {kinds}"),
            code: EXIT_NOT_IMPLEMENTED,
        }),
        other => Err(Refusal::usage(format!("{other}: no such kind of address; the kinds are {kinds}"))),
    }
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
    fn an_unknown_kind_is_a_usage_error_that_lists_the_kinds_and_a_later_kind_is_not_built() {
        let refusal = parse("udp:example.org:80").unwrap_err();
        assert_eq!(refusal.code, 64);
        assert!(refusal.message.contains("exec:CMD"), "{}", refusal.message);
        assert_eq!(code("example.org"), 64);
        assert_eq!(code("stdio:x"), 64);
        for later in ["unix-connect:/run/x.sock", "tcp-listen:2222", "serial:/dev/ttyS0"] {
            assert_eq!(code(later), 70, "{later}");
        }
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
        if !cfg!(feature = "iroh") {
            assert_eq!(code("iroh:endpointabc"), 70);
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
