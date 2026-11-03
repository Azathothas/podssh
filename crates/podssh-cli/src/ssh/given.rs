//! Where the value of a keyword was given: `-o` on the command line, or a
//! line of an `ssh_config` file. A note and a refusal name that place
//! (T-502, T-505), so that a user finds the line that asked for it.

/// The place of one value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Place {
    /// `-o` on the command line, or a flag of podssh's that gives a keyword.
    #[default]
    CommandLine,
    /// `FILE:LINE`, as the refusals of a file name it; `system` for the
    /// system's file and each file that it includes, which a distribution
    /// writes for each program, not the user.
    Line { at: String, system: bool },
}

impl Place {
    /// The line `line` of `file`.
    pub fn line(file: &str, line: usize, system: bool) -> Place {
        Place::Line { at: format!("{file}:{line}"), system }
    }

    /// How a note names it: `-o`, or `FILE:LINE`.
    pub fn shown(&self) -> &str {
        match self {
            Place::CommandLine => "-o",
            Place::Line { at, .. } => at,
        }
    }

    /// The user's own: the command line, the file of `-F` or of
    /// `PODSSH_SSH_CONFIG`, `~/.ssh/config`, and the files that they include.
    pub fn users(&self) -> bool {
        !matches!(self, Place::Line { system: true, .. })
    }
}

/// A value as it was given: its keyword as written, the value, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Given {
    pub name: String,
    pub value: String,
    pub place: Place,
}

impl Given {
    pub fn new(name: &str, value: &str, place: &Place) -> Given {
        Given { name: name.to_string(), value: value.to_string(), place: place.clone() }
    }
}

/// Keep `given` in `list` when no value of its keyword is there yet: the
/// first one holds, as in OpenSSH, and its place is the one a note names.
pub fn keep_first(list: &mut Vec<Given>, given: Given) {
    if !list.iter().any(|g| g.name.eq_ignore_ascii_case(&given.name)) {
        list.push(given);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_place_is_named_as_the_refusals_name_it_and_the_system_file_is_not_the_users() {
        assert_eq!(Place::CommandLine.shown(), "-o");
        let line = Place::line("/home/u/.ssh/config", 4, false);
        assert_eq!(line.shown(), "/home/u/.ssh/config:4");
        assert!(line.users() && Place::CommandLine.users());
        assert!(!Place::line("/etc/ssh/ssh_config", 22, true).users());
        let mut list = Vec::new();
        keep_first(&mut list, Given::new("HashKnownHosts", "yes", &line));
        keep_first(&mut list, Given::new("hashknownhosts", "no", &Place::CommandLine));
        assert_eq!(list, [Given::new("HashKnownHosts", "yes", &line)], "the first one holds");
    }
}
