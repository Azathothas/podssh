//! `-R` and `-o RemoteForward`: the server listens, on a port or a socket
//! path, and podssh connects each connection that it takes to the spec's
//! target, a host and a port, a socket on this host, or the SOCKS proxy that
//! podssh serves (T-035, T-365). The specs are OpenSSH's, read with the
//! reader of `-L` (`local_spec`), so that brackets, a backslash and a field
//! with a `/` mean one thing in each direction.

use podssh_ssh::local::Target;
use podssh_ssh::{RemoteForward, RemoteListen, RemoteTarget};

use super::local_spec::{forms, Listen, Side};

/// One `-R` spec, in OpenSSH's six forms: `[bind_address:]port:host:hostport`,
/// `remote_socket:host:hostport`, `[bind_address:]port:local_socket`,
/// `remote_socket:local_socket`, and the SOCKS proxy, `[bind_address:]port`
/// or `remote_socket` alone.
pub fn parse_remote(spec: &str) -> Result<RemoteForward, String> {
    parse(spec).map_err(|why| format!("-R {spec}: {why}"))
}

/// `-o RemoteForward=LISTEN [TARGET]`: the keyword's arguments, as
/// `ssh_config` writes them; one alone is the SOCKS form.
pub fn parse_remote_keyword(value: &str) -> Result<RemoteForward, String> {
    let mut words = value.split_whitespace();
    let parsed = match (words.next(), words.next(), words.next()) {
        (Some(listen), Some(target), None) => parse(&format!("{listen}:{target}")),
        (Some(listen), None, None) => parse(listen),
        _ => Err("not LISTEN TARGET, or LISTEN alone for SOCKS".into()),
    };
    parsed.map_err(|why| format!("-o RemoteForward={value}: {why}"))
}

/// The forwards of a run: each `-R`, then each `RemoteForward`, as OpenSSH
/// keeps both.
pub fn remote_forwards(command_line: &[String], keyword: &[RemoteForward]) -> Result<Vec<RemoteForward>, String> {
    let mut forwards = command_line.iter().map(|spec| parse_remote(spec)).collect::<Result<Vec<_>, _>>()?;
    // One given twice is asked for once, as OpenSSH keeps it (T-045).
    for forward in keyword {
        if !forwards.contains(forward) {
            forwards.push(forward.clone());
        }
    }
    Ok(forwards)
}

fn parse(spec: &str) -> Result<RemoteForward, String> {
    let (listen, target) = forms(spec, Side::Remote)?;
    let listen = match listen {
        Listen::Port { bind, port } => RemoteListen::Port { bind, port },
        Listen::Path(path) => RemoteListen::Path(path),
    };
    let target = match target {
        Target::Tcp { host, port } => RemoteTarget::Tcp { host, port },
        Target::Socket(path) => RemoteTarget::Socket(path),
        Target::Socks => RemoteTarget::Socks,
    };
    Ok(RemoteForward { listen, target })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward(bind: Option<&str>, port: u16, host: &str, host_port: u16) -> RemoteForward {
        RemoteForward::tcp(bind.map(str::to_string), port, host, host_port)
    }

    #[test]
    fn the_specs_of_openssh_parse() {
        assert_eq!(parse_remote("8080:localhost:80"), Ok(forward(None, 8080, "localhost", 80)));
        assert_eq!(parse_remote("0.0.0.0:8080:web:80"), Ok(forward(Some("0.0.0.0"), 8080, "web", 80)));
        assert_eq!(parse_remote(":8080:web:80"), Ok(forward(Some(""), 8080, "web", 80)));
        assert_eq!(parse_remote("*:8080:web:80"), Ok(forward(Some("*"), 8080, "web", 80)));
        assert_eq!(parse_remote("0:web:80"), Ok(forward(None, 0, "web", 80)));
        assert_eq!(parse_remote("[::1]:8080:[fd00::2]:443"), Ok(forward(Some("::1"), 8080, "fd00::2", 443)));
        assert_eq!(parse_remote_keyword("8080 localhost:80"), Ok(forward(None, 8080, "localhost", 80)));
        assert_eq!(parse_remote_keyword("[::1]:8080  web:80"), Ok(forward(Some("::1"), 8080, "web", 80)));
        // What goes to the server, as OpenSSH sends it.
        let wire = |spec: &str| parse_remote(spec).unwrap().sent_address().to_string();
        assert_eq!(
            [wire("8080:a:1"), wire(":8080:a:1"), wire("*:8080:a:1"), wire("10.1.2.3:8080:a:1")],
            ["localhost", "", "", "10.1.2.3"]
        );
    }

    /// The forms of a socket path on either side, and of SOCKS (T-365), as
    /// OpenSSH 9.6p1's `-G` read them.
    #[test]
    fn the_socket_and_socks_forms_parse() {
        let path = |p: &str| RemoteListen::Path(p.into());
        let port = |bind: Option<&str>, port| RemoteListen::Port { bind: bind.map(str::to_string), port };
        let cases = [
            ("/tmp/r.sock:127.0.0.1:22", path("/tmp/r.sock"), RemoteTarget::Tcp { host: "127.0.0.1".into(), port: 22 }),
            ("8080:/tmp/local.sock", port(None, 8080), RemoteTarget::Socket("/tmp/local.sock".into())),
            ("/tmp/r.sock:/tmp/local.sock", path("/tmp/r.sock"), RemoteTarget::Socket("/tmp/local.sock".into())),
            ("1080", port(None, 1080), RemoteTarget::Socks),
            ("0", port(None, 0), RemoteTarget::Socks),
            ("127.0.0.1:1080", port(Some("127.0.0.1"), 1080), RemoteTarget::Socks),
            ("/tmp/x.sock", path("/tmp/x.sock"), RemoteTarget::Socks),
        ];
        for (spec, listen, target) in cases {
            assert_eq!(parse_remote(spec), Ok(RemoteForward { listen, target }), "{spec}");
        }
        assert_eq!(parse_remote_keyword("8080").map(|f| f.target), Ok(RemoteTarget::Socks));
        assert_eq!(
            parse_remote_keyword("/tmp/r.sock /tmp/local.sock").map(|f| f.target),
            Ok(RemoteTarget::Socket("/tmp/local.sock".into()))
        );
    }

    #[test]
    fn a_spec_of_no_form_is_refused_with_why() {
        for (spec, says) in [
            ("8080:web:http", "not a port"),
            ("8080:web:0", "not allowed"),
            ("x:8080:web:80:9", "more than four fields"),
            ("[::1:8080:web:80", "bracket"),
            ("8080::80", "no host"),
        ] {
            let err = parse_remote(spec).expect_err(spec);
            assert!(err.contains(says), "{spec}: {err}");
        }
        assert!(parse_remote_keyword("a b c").is_err());
    }
}
