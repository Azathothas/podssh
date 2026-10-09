//! An operand of `cp`: a local path, or `[user@]host:path` on a server.
//!
//! As scp reads one (OpenSSH's `colon()`): a `:` before any `/` makes the
//! operand remote, so `./a:b` is a local file named `a:b`, and a leading `:`
//! is part of a local name. An IPv6 address goes in brackets,
//! `[2001:db8::1]:path`. On Windows a drive letter, as in `C:\x`, is local.

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
        self.user == other.user && self.host.eq_ignore_ascii_case(&other.host)
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
    Ok(Operand::Remote(Remote { user: user.map(str::to_string), host: host.to_string(), path: path.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(user: Option<&str>, host: &str, path: &str) -> Operand {
        Operand::Remote(Remote { user: user.map(str::to_string), host: host.into(), path: path.into() })
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
        let r = Remote { user: Some("u".into()), host: "::1".into(), path: String::new() };
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
    fn no_host_or_an_empty_user_is_refused() {
        assert!(parse("@host:a", false).is_err());
        assert!(parse("u@:a", false).is_err());
        assert!(parse("[]:a", false).is_err());
    }
}
