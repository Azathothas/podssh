//! An operand of `cp`: a local path, or `[user@]host:path` on a server.
//!
//! As scp reads one (OpenSSH's `colon()`): a `:` before any `/` makes the
//! operand remote, so `./a:b` is a local file named `a:b`, and a leading `:`
//! is part of a local name. An IPv6 address goes in brackets,
//! `[2001:db8::1]:path`. On Windows a drive letter, as in `C:\x`, is local.
//!
//! A URI, `scp://[user@]host[:port][/path]` or the same with `sftp://`, is
//! read as OpenSSH's `parse_uri` reads it: the path after the first `/` is
//! relative to the login directory (`//` makes it absolute), the user and the
//! path are percent-decoded, and the port is the operand's own.

/// One side of a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// A path on this host, as typed.
    Local(String),
    /// A path on a server.
    Remote(Remote),
}

/// A path on a server, and the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    /// The user before `@`, if one is given.
    pub user: Option<String>,
    /// The host, without brackets.
    pub host: String,
    /// The port that a URI named; `None` takes `-P` or the configuration.
    pub port: Option<u16>,
    /// The path on the server; empty for the login directory.
    pub path: String,
}

impl Remote {
    /// The server as `ssh` takes it: `[user@]host`, an IPv6 address in
    /// brackets.
    pub fn destination(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match &self.user {
            Some(user) => format!("{user}@{host}"),
            None => host,
        }
    }

    /// Whether `other` names the same login on the same server.
    pub fn same_server(&self, other: &Remote) -> bool {
        self.user == other.user && self.host.eq_ignore_ascii_case(&other.host) && self.port == other.port
    }
}

/// The byte where the host part ends, when `text` names a server.
fn colon(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.first() == Some(&b':') {
        return None;
    }
    let mut bracket = bytes.first() == Some(&b'[');
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'@' if bytes.get(i + 1) == Some(&b'[') => bracket = true,
            b']' if bracket && bytes.get(i + 1) == Some(&b':') => return Some(i + 1),
            b':' if !bracket => return Some(i),
            b'/' => return None,
            _ => {}
        }
    }
    None
}

/// Whether `text` starts with a drive letter, as Windows names a local path.
fn drive(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Read one operand. `windows` makes a drive letter local.
pub fn parse(text: &str, windows: bool) -> Result<Operand, String> {
    if let Some(rest) = text.strip_prefix("scp://").or_else(|| text.strip_prefix("sftp://")) {
        return uri(text, rest).map(Operand::Remote);
    }
    if windows && drive(text) {
        return Ok(Operand::Local(text.to_string()));
    }
    let Some(at) = colon(text) else { return Ok(Operand::Local(text.to_string())) };
    let (login, path) = (&text[..at], &text[at + 1..]);
    let (user, host) = match login.rfind('@') {
        Some(i) => (Some(&login[..i]), &login[i + 1..]),
        None => (None, login),
    };
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if host.is_empty() {
        return Err(format!("{text:?} names no host before ':'; a local name with ':' starts with ./"));
    }
    if user == Some("") {
        return Err(format!("{text:?} has an empty user before '@'"));
    }
    Ok(Operand::Remote(Remote {
        user: user.map(str::to_string),
        host: host.to_string(),
        port: None,
        path: path.to_string(),
    }))
}

/// `[user@]host[:port][/path]` after the scheme of `text`.
fn uri(text: &str, rest: &str) -> Result<Remote, String> {
    // The user ends at the last `@` before the first `/`; `;` starts
    // parameters of the user, which OpenSSH ignores too.
    let slash = rest.find('/').unwrap_or(rest.len());
    let (user, hostpart) = match rest[..slash].rfind('@') {
        Some(i) => (Some(&rest[..i]), &rest[i + 1..]),
        None => (None, rest),
    };
    let user = user.map(|u| u.split(';').next().unwrap_or(u)).map(decode).transpose()?;
    if user.as_deref() == Some("") {
        return Err(format!("{text:?} has an empty user before '@'"));
    }
    let (host, after) = match hostpart.strip_prefix('[') {
        Some(inside) => {
            let end = inside.find(']').ok_or_else(|| format!("{text:?} has no ']' after its address"))?;
            (&inside[..end], &inside[end + 1..])
        }
        None => {
            let end = hostpart.find([':', '/']).unwrap_or(hostpart.len());
            (&hostpart[..end], &hostpart[end..])
        }
    };
    // As OpenSSH's `valid_domain`: a name or an address, nothing else.
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || "-._:".contains(c)) {
        return Err(format!("{text:?} names no host that podssh can use"));
    }
    let (port, after) = match after.strip_prefix(':') {
        Some(rest) => {
            let end = rest.find('/').unwrap_or(rest.len());
            let port = rest[..end]
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or_else(|| format!("{text:?} has no port from 1 to 65535 after ':'"))?;
            (Some(port), &rest[end..])
        }
        None => (None, after),
    };
    // The `/` after the host ends it; what follows is relative to the login
    // directory, and a second `/` makes it absolute.
    let path = match after.strip_prefix('/') {
        Some(path) => decode(path)?,
        None if after.is_empty() => String::new(),
        None => return Err(format!("{text:?} has {after:?} after its host")),
    };
    Ok(Remote { user, host: host.to_string(), port, path })
}

/// Percent-decoding, as OpenSSH's `urldecode`: `%XX` and `+` for a space; a
/// bad escape, `%00`, or bytes that are not UTF-8 are refused.
fn decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = text.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(b) if b != 0 => out.push(b),
                    _ => return Err(format!("{text:?} has a bad % escape")),
                }
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).map_err(|_| format!("{text:?} decodes to bytes that are not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(user: Option<&str>, host: &str, path: &str) -> Operand {
        Operand::Remote(Remote { user: user.map(str::to_string), host: host.into(), port: None, path: path.into() })
    }

    #[test]
    fn a_colon_before_a_slash_names_a_server() {
        assert_eq!(parse("host:a", false), Ok(remote(None, "host", "a")));
        assert_eq!(parse("u@host:/srv/a", false), Ok(remote(Some("u"), "host", "/srv/a")));
        assert_eq!(parse("host:", false), Ok(remote(None, "host", "")));
        assert_eq!(parse("u@x@host:a", false), Ok(remote(Some("u@x"), "host", "a")), "the last @ ends the user");
    }

    #[test]
    fn a_slash_first_or_a_leading_colon_is_local() {
        for local in ["./a:b", "/tmp/a:b", ":a", "a", "dir/x:y", "[::1]"] {
            assert_eq!(parse(local, false), Ok(Operand::Local(local.into())), "{local}");
        }
    }

    #[test]
    fn an_ipv6_host_goes_in_brackets() {
        assert_eq!(parse("[2001:db8::1]:a", false), Ok(remote(None, "2001:db8::1", "a")));
        assert_eq!(parse("u@[::1]:/x", false), Ok(remote(Some("u"), "::1", "/x")));
        let r = Remote { user: Some("u".into()), host: "::1".into(), port: None, path: String::new() };
        assert_eq!(r.destination(), "u@[::1]");
    }

    #[test]
    fn a_drive_letter_is_local_on_windows_only() {
        assert_eq!(parse(r"C:\x", true), Ok(Operand::Local(r"C:\x".into())));
        assert_eq!(parse("c:/x", true), Ok(Operand::Local("c:/x".into())));
        assert_eq!(parse(r"C:\x", false), Ok(remote(None, "C", r"\x")));
        assert_eq!(parse("host:a", true), Ok(remote(None, "host", "a")), "a longer name is a host on Windows too");
    }

    #[test]
    fn a_uri_names_its_port_and_a_path_under_the_login_directory() {
        let at = |user: Option<&str>, host: &str, port: Option<u16>, path: &str| {
            Ok(Operand::Remote(Remote { user: user.map(str::to_string), host: host.into(), port, path: path.into() }))
        };
        assert_eq!(parse("scp://host", false), at(None, "host", None, ""));
        assert_eq!(parse("scp://u@host:2222/dir/f", false), at(Some("u"), "host", Some(2222), "dir/f"));
        assert_eq!(parse("sftp://host//srv/f", false), at(None, "host", None, "/srv/f"), "// is absolute");
        assert_eq!(parse("scp://[2001:db8::1]:22/x", false), at(None, "2001:db8::1", Some(22), "x"));
        assert_eq!(parse("scp://a%40b;fp=x@host/a%20b+c", false), at(Some("a@b"), "host", None, "a b c"));
        for bad in [
            "scp://",
            "scp://u@:22/x",
            "scp://host:0/x",
            "scp://host:99999",
            "scp://host:x/",
            "scp://host/%zz",
            "scp://host/%00",
            "scp://@host/x",
            "scp://[::1/x",
            "scp://host?x",
        ] {
            assert!(parse(bad, false).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn a_port_makes_another_server() {
        let a = Remote { user: None, host: "h".into(), port: Some(22), path: String::new() };
        let b = Remote { port: Some(2222), ..a.clone() };
        assert!(!a.same_server(&b) && a.same_server(&a.clone()));
    }

    #[test]
    fn no_host_or_an_empty_user_is_refused() {
        assert!(parse("@host:a", false).is_err());
        assert!(parse("u@:a", false).is_err());
        assert!(parse("[]:a", false).is_err());
    }
}
