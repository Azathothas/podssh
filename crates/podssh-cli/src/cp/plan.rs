//! What a `cp` command line asks for: which way the bytes go, the server, and
//! each source. Each refusal here is a usage error, before anything connects.

use super::operand::{parse, Operand, Remote};

/// Which way the bytes go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From this host to the server.
    Up,
    /// From the server to this host.
    Down,
    /// From one server to another, or within one, through this host.
    Across,
}

/// One copy command, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub direction: Direction,
    /// The sources, in order: local paths for `Up`, remote ones else.
    pub sources: Vec<Operand>,
    /// The destination.
    pub destination: Operand,
}

impl Plan {
    /// The server of a copy up or down: the one that each remote operand
    /// names.
    pub fn server(&self) -> Option<&Remote> {
        match (&self.destination, self.sources.first()) {
            (Operand::Remote(r), _) => Some(r),
            (_, Some(Operand::Remote(r))) => Some(r),
            _ => None,
        }
    }
}

/// Read `paths` (SRC... DST); `windows` makes a drive letter local.
pub fn plan(paths: &[String], windows: bool) -> Result<Plan, String> {
    if paths.len() < 2 {
        return Err("give a source and a destination: SRC... DST, one of them [user@]host:path".into());
    }
    let mut operands = Vec::with_capacity(paths.len());
    for path in paths {
        operands.push(parse(path, windows)?);
    }
    let destination = operands.pop().expect("two operands at least");
    let sources = operands;
    let remote_sources = sources.iter().filter(|o| matches!(o, Operand::Remote(_))).count();
    if remote_sources != 0 && remote_sources != sources.len() {
        return Err("give the sources from one side: each local, or each [user@]host:path".into());
    }
    let direction = match (remote_sources > 0, &destination) {
        (false, Operand::Local(_)) => {
            return Err("both sides are local paths; podssh cp copies to or from a server ([user@]host:path)".into())
        }
        (false, Operand::Remote(_)) => Direction::Up,
        (true, Operand::Local(_)) => Direction::Down,
        (true, Operand::Remote(_)) => Direction::Across,
    };
    // One connection at a time: the remote sources come from one server.
    let mut servers = sources.iter().filter_map(|o| match o {
        Operand::Remote(r) => Some(r),
        Operand::Local(_) => None,
    });
    if let Some(first) = servers.next() {
        if servers.any(|r| !r.same_server(first)) {
            return Err("the remote sources name more than one server; give one server at a time".into());
        }
    }
    if direction == Direction::Across && sources.len() > 1 {
        return Err("a copy from server to server takes one source at a time".into());
    }
    Ok(Plan { direction, sources, destination })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(words: &[&str]) -> Result<Plan, String> {
        plan(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>(), false)
    }

    #[test]
    fn up_down_and_across() {
        assert_eq!(p(&["a", "h:b"]).map(|p| p.direction), Ok(Direction::Up));
        assert_eq!(p(&["a", "c", "h:dir/"]).map(|p| p.direction), Ok(Direction::Up));
        assert_eq!(p(&["h:a", "."]).map(|p| p.direction), Ok(Direction::Down));
        assert_eq!(p(&["h:a", "h:b", "."]).map(|p| p.direction), Ok(Direction::Down));
        assert_eq!(p(&["h:a", "g:b"]).map(|p| p.direction), Ok(Direction::Across));
        assert_eq!(p(&["a", "u@h:b"]).ok().and_then(|p| p.server().map(|r| r.destination())), Some("u@h".into()));
    }

    #[test]
    fn each_refusal_is_a_usage_error() {
        for words in [
            &[][..],
            &["a"][..],
            &["a", "b"][..],
            &["a", "h:b", "c"][..],
            &["h:a", "b", "c"][..],
            &["h:a", "g:b", "."][..],
            &["h:a", "h:b", "g:c"][..],
            &["u@:a", "b"][..],
        ] {
            assert!(p(words).is_err(), "{words:?} must be refused");
        }
    }
}
