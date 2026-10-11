//! The hosts that `ssh_exec` may reach: the patterns of `--allow-host`, which
//! the user gives when `podssh mcp` starts, never the agent. A pattern is
//! `[USER@]HOST` with `*` and `?`, as a `Host` line of `ssh_config` has them,
//! and `!` before one excludes what it matches.

/// One pattern of `--allow-host`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    negated: bool,
    /// The user that the destination must name, as a pattern.
    user: Option<String>,
    /// The host, as a pattern, in lowercase: names are matched with no
    /// regard to case, as OpenSSH lowercases the host before `Host` lines.
    host: String,
}

/// The patterns of a run, in the order given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allow {
    patterns: Vec<Pattern>,
    /// The patterns as given, for the description of `ssh_exec`.
    shown: Vec<String>,
}

/// A destination of `ssh_exec`: `[user@]host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub user: Option<String>,
    pub host: String,
}

impl Allow {
    /// The patterns of `values`, each one checked: a word with no space and
    /// no control character, at most one `@`, a user and a host that are
    /// not empty.
    pub fn new(values: &[String]) -> Result<Allow, String> {
        let mut allow = Allow::default();
        for value in values {
            let bad = |why: &str| format!("--allow-host {value:?}: {why}");
            let (negated, body) = match value.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, value.as_str()),
            };
            if body.is_empty() {
                return Err(bad("no pattern"));
            }
            if body.chars().any(|c| c.is_whitespace() || c.is_control() || c == ',') {
                return Err(bad("one pattern for each flag, with no space and no comma"));
            }
            let (user, host) = match body.split_once('@') {
                Some((user, host)) if user.is_empty() || host.is_empty() || host.contains('@') => {
                    return Err(bad("expected [USER@]HOST"));
                }
                Some((user, host)) => (Some(user.to_string()), host),
                None => (None, body),
            };
            allow.patterns.push(Pattern { negated, user, host: host.to_ascii_lowercase() });
            allow.shown.push(value.clone());
        }
        Ok(allow)
    }

    /// Whether no pattern lets a host in: `ssh_exec` is then not offered.
    pub fn is_empty(&self) -> bool {
        !self.patterns.iter().any(|p| !p.negated)
    }

    /// The patterns as given, joined for a sentence.
    pub fn shown(&self) -> String {
        self.shown.join(", ")
    }

    /// `destination`, when a pattern lets it in and none excludes it.
    pub fn check(&self, destination: &str) -> Result<Destination, String> {
        let dest = parse(destination)?;
        let host = dest.host.to_ascii_lowercase();
        let user_matches = |p: &Pattern, unnamed: bool| match (&p.user, &dest.user) {
            (None, _) => true,
            (Some(pattern), Some(user)) => wildcard(pattern, user),
            // A pattern of a user and a destination that names none: the
            // user comes from the configuration, which is not read here.
            (Some(_), None) => unnamed,
        };
        // An exclusion of a user holds when the destination names no user,
        // and a pattern of a user lets in only a destination that names one.
        let excluded = self.patterns.iter().any(|p| p.negated && wildcard(&p.host, &host) && user_matches(p, true));
        let allowed = self.patterns.iter().any(|p| !p.negated && wildcard(&p.host, &host) && user_matches(p, false));
        if allowed && !excluded {
            return Ok(dest);
        }
        Err(if self.is_empty() {
            "no host is allowed: podssh mcp was started with no --allow-host".to_string()
        } else {
            format!("{destination} is not allowed: this server allows {} (--allow-host)", self.shown())
        })
    }
}

/// `[user@]host`: a host with no port, no path and no scheme, and neither
/// part starting with `-`; the port and the rest come from the user's
/// configuration.
pub fn parse(destination: &str) -> Result<Destination, String> {
    let bad = |why: &str| Err(format!("destination {destination:?}: {why}"));
    if destination.is_empty() || destination.len() > 255 {
        return bad("expected [user@]host");
    }
    if destination.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return bad("a space or a control character");
    }
    let (user, host) = match destination.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, destination),
    };
    if user.is_some_and(|u| u.is_empty() || u.starts_with('-')) {
        return bad("expected [user@]host");
    }
    if host.is_empty() || host.starts_with('-') {
        return bad("expected [user@]host");
    }
    if host.contains([':', '/', '[', ']', '\\']) {
        return bad("the host alone: the port and the rest come from the configuration (-F)");
    }
    Ok(Destination { user: user.map(str::to_string), host: host.to_string() })
}

fn wildcard(pattern: &str, text: &str) -> bool {
    podssh_ssh::known_hosts::wildcard(pattern.as_bytes(), text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(patterns: &[&str]) -> Allow {
        Allow::new(&patterns.iter().map(|p| p.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn a_host_is_let_in_by_a_pattern_and_kept_out_by_an_exclusion() {
        let a = allow(&["web*.example.org", "!web9.example.org", "127.0.0.1"]);
        assert!(a.check("web1.example.org").is_ok());
        assert!(a.check("deploy@WEB2.Example.org").is_ok());
        assert!(a.check("web9.example.org").is_err());
        assert!(a.check("db.example.org").is_err());
        assert!(a.check("127.0.0.1").is_ok());
        assert!(a.check("127.0.0.2").is_err());
        let err = a.check("db.example.org").unwrap_err();
        assert!(err.contains("web*.example.org, !web9.example.org, 127.0.0.1"), "{err}");
    }

    #[test]
    fn a_pattern_of_a_user_needs_a_named_user() {
        let a = allow(&["deploy@*.example.org", "*.lab", "!root@*"]);
        assert!(a.check("deploy@web.example.org").is_ok());
        assert!(a.check("web.example.org").is_err());
        assert!(a.check("admin@web.example.org").is_err());
        assert!(a.check("pi@node.lab").is_ok());
        // Excluded, as root, or as a user that the configuration names.
        assert!(a.check("root@node.lab").is_err());
        assert!(a.check("node.lab").is_err());
    }

    #[test]
    fn a_destination_is_a_user_and_a_host_alone() {
        let a = allow(&["*"]);
        for bad in ["", "-oProxyCommand=x", "u@-h", "@h", "h:22", "ssh://h", "[::1]", "a b", "h\n", "u@h/x"] {
            assert!(a.check(bad).is_err(), "{bad:?}");
        }
        assert_eq!(a.check("u@h").unwrap(), Destination { user: Some("u".into()), host: "h".into() });
        assert_eq!(a.check("a@b@h").unwrap().user.as_deref(), Some("a@b"));
    }

    #[test]
    fn a_bad_pattern_is_refused_and_none_allows_nothing() {
        for bad in ["", "!", "a b", "a,b", "@h", "u@", "u@h@x"] {
            assert!(Allow::new(&[bad.to_string()]).is_err(), "{bad:?}");
        }
        assert!(allow(&[]).is_empty());
        assert!(allow(&["!web"]).is_empty());
        assert!(allow(&[]).check("h").unwrap_err().contains("no --allow-host"));
    }
}
