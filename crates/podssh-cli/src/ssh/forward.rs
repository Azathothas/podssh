//! `-R` and `-o RemoteForward`: the server listens, and podssh connects each
//! connection that it takes to the spec's target, with one more outbound
//! connection through the proxy (T-035). The specs are OpenSSH's; the forms
//! that podssh does not carry yet are refused by name.

use podssh_ssh::options::RemoteForward;

/// One `-R` spec: `[bind_address:]port:host:hostport`, an IPv6 address in
/// brackets. A socket path, on either side, and the server's SOCKS proxy
/// (`[bind_address:]port` alone) are refused by name.
pub fn parse_remote(spec: &str) -> Result<RemoteForward, String> {
    parse(spec).map_err(|why| format!("-R {spec}: {why}"))
}

/// `-o RemoteForward=[bind_address:]port host:hostport`: the keyword's two
/// arguments, as `ssh_config` writes them.
pub fn parse_remote_keyword(value: &str) -> Result<RemoteForward, String> {
    let mut words = value.split_whitespace();
    let parsed = match (words.next(), words.next(), words.next()) {
        (Some(listen), Some(target), None) => parse(&format!("{listen}:{target}")),
        (Some(listen), None, None) => parse(listen),
        _ => Err("not [bind_address:]port host:hostport".into()),
    };
    parsed.map_err(|why| format!("-o RemoteForward={value}: {why}"))
}

/// The forwards of a run: each `-R`, then each `RemoteForward`, as OpenSSH
/// keeps both.
pub fn remote_forwards(command_line: &[String], keyword: &[RemoteForward]) -> Result<Vec<RemoteForward>, String> {
    let mut forwards = command_line.iter().map(|spec| parse_remote(spec)).collect::<Result<Vec<_>, _>>()?;
    forwards.extend(keyword.iter().cloned());
    Ok(forwards)
}

fn parse(spec: &str) -> Result<RemoteForward, String> {
    let fields = split(spec).ok_or("a bracket is not closed")?;
    if fields.iter().any(|f| f.starts_with('/')) {
        return Err("a Unix socket is not carried yet; forward to a HOST:PORT".into());
    }
    let (bind, port, host, host_port) = match fields.as_slice() {
        [port, host, host_port] => (None, port, host, host_port),
        [bind, port, host, host_port] => (Some(bind.as_str()), port, host, host_port),
        [_] | [_, _] => {
            return Err("the server's SOCKS proxy (-R [bind_address:]port) is not carried yet; \
                        give [bind_address:]port:host:hostport"
                .into())
        }
        _ => return Err("not [bind_address:]port:host:hostport".into()),
    };
    let port: u16 = port.parse().map_err(|_| format!("{port:?} is not a port"))?;
    let host_port: u16 = match host_port.parse() {
        Ok(p) if p > 0 => p,
        _ => return Err(format!("{host_port:?} is not a port to connect to")),
    };
    if host.is_empty() {
        return Err("no host to connect to".into());
    }
    Ok(RemoteForward { bind: bind.map(str::to_string), port, host: host.clone(), host_port })
}

/// The fields between colons, with the brackets of an IPv6 address taken
/// off; `None` for a bracket that is not closed.
fn split(spec: &str) -> Option<Vec<String>> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = spec.chars();
    while let Some(c) = chars.next() {
        match c {
            '[' if field.is_empty() => {
                let mut inner = String::new();
                loop {
                    match chars.next()? {
                        ']' => break,
                        c => inner.push(c),
                    }
                }
                field.push_str(&inner);
            }
            ':' => fields.push(std::mem::take(&mut field)),
            c => field.push(c),
        }
    }
    fields.push(field);
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward(bind: Option<&str>, port: u16, host: &str, host_port: u16) -> RemoteForward {
        RemoteForward { bind: bind.map(str::to_string), port, host: host.into(), host_port }
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

    #[test]
    fn the_forms_not_carried_yet_are_refused_by_name() {
        for (spec, says) in [
            ("8080", "SOCKS"),
            ("0.0.0.0:8080", "SOCKS"),
            ("8080:/tmp/sock", "Unix socket"),
            ("/tmp/remote:web:80", "Unix socket"),
            ("8080:web:http", "not a port"),
            ("8080:web:0", "not a port"),
            ("x:8080:web:80:9", "not [bind_address:]port:host:hostport"),
            ("[::1:8080:web:80", "bracket"),
            ("8080::80", "no host"),
        ] {
            let err = parse_remote(spec).expect_err(spec);
            assert!(err.contains(says), "{spec}: {err}");
        }
        assert!(parse_remote_keyword("8080").unwrap_err().contains("SOCKS"));
        assert!(parse_remote_keyword("a b c").is_err());
    }
}
