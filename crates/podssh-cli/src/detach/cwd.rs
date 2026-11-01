//! The working directory of a run in the background (T-397). The run held
//! the caller's, which an unmount then refuses, and which Windows will not
//! let be removed. At ready it goes to the root (on Windows the system
//! drive's), unless a word of the run may still need that directory: a
//! relative path of this host, or a command that runs here, whose own
//! working directory it is. In doubt it stays: a run that loses a file it
//! reads again (a key at a reconnect, an allowlist at each session) would
//! lock its server out, and a directory held does not.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::flags::FlagRow;

/// Set by a run that found a relative path in its settings, which no word
/// shows (an `IdentityFile` of `ssh_config`).
static STAY: AtomicBool = AtomicBool::new(false);

/// The run reads a relative path again later: it keeps the working
/// directory at ready.
pub fn stay_here() {
    STAY.store(true, Ordering::SeqCst);
}

/// The metavariables of a flag whose value is a path of this host.
const PATH_VALUES: &[&str] = &["FILE", "PATH", "CONFIG", "LOGFILE"];
/// The `-o` keywords, in lower case, whose value is a path of this host.
const PATH_KEYWORDS: &[&str] = &[
    "identityfile",
    "certificatefile",
    "userknownhostsfile",
    "globalknownhostsfile",
    "controlpath",
    "identityagent",
    "revokedhostkeys",
    "securitykeyprovider",
    "xauthlocation",
    "include",
];
/// The `-o` keywords of a command that runs here.
const COMMAND_KEYWORDS: &[&str] = &["localcommand", "permitlocalcommand", "proxycommand", "knownhostscommand"];

/// What a supervisor's run adds to its line of ready when it left the
/// working directory: the supervisor, which reads none of the run's
/// settings, then leaves it too, and stays where the run stayed (or where
/// an older binary, which says nothing, runs).
pub(super) const LEFT: &str = ", left its directory";

/// Whether the run leaves the working directory at ready: no word of it
/// (`words`, its verb first) and none of its settings needs it.
pub(super) fn leaves(words: &[OsString]) -> bool {
    !STAY.load(Ordering::SeqCst) && !needs_here(words)
}

/// The root as the working directory; where the change fails, it stays.
pub(super) fn to_root() {
    if let Some(root) = root() {
        let _ = std::env::set_current_dir(root);
    }
}

fn root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let mut root = std::env::var_os("SystemDrive")?;
        root.push("\\");
        Some(PathBuf::from(root))
    }
    #[cfg(not(windows))]
    {
        Some(PathBuf::from("/"))
    }
}

/// What a word is, by the one before it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Word,
    /// The value of a flag that takes a path.
    Path,
    /// The value of `-o`.
    Option,
}

/// Whether a word of the run may need the working directory.
pub(super) fn needs_here(words: &[OsString]) -> bool {
    let words: Vec<String> = words.iter().map(|w| w.to_string_lossy().into_owned()).collect();
    let Some((verb, rest)) = words.split_first() else { return false };
    let rows = crate::flags::verb_for(verb).map_or(&[][..], |v| v.flags);
    let mut next = Next::Word;
    for word in rest {
        let here = match next {
            Next::Path => !absolute(word),
            Next::Option => option_needs_here(word),
            Next::Word => word_needs_here(word, rows),
        };
        if here {
            return true;
        }
        next = if next == Next::Word { follows(word, rows) } else { Next::Word };
    }
    false
}

/// What the word after `word` is: the value of a flag of `rows` that takes
/// a path, the value of `-o`, or a word.
fn follows(word: &str, rows: &[FlagRow]) -> Next {
    let row = match word.strip_prefix("--") {
        Some(long) => rows.iter().find(|r| r.long == long),
        None => {
            let mut chars = word.strip_prefix('-').unwrap_or_default().chars();
            match (chars.next(), chars.next()) {
                (Some(short), None) => rows.iter().find(|r| r.short == Some(short)),
                _ => None,
            }
        }
    };
    match row {
        Some(r) if r.long == "option" => Next::Option,
        Some(r) if r.arg.is_some_and(|meta| PATH_VALUES.contains(&meta)) => Next::Path,
        _ => Next::Word,
    }
}

/// A word by itself: a flag joined to its value (`--ca-file=x`, `-ikey`,
/// `-oName=value`), or a positional.
fn word_needs_here(word: &str, rows: &[FlagRow]) -> bool {
    if let Some(long) = word.strip_prefix("--") {
        return long
            .split_once('=')
            .is_some_and(|(flag, value)| value_needs_here(follows(&format!("--{flag}"), rows), value));
    }
    if let Some(rest) = word.strip_prefix('-') {
        let mut chars = rest.chars();
        if let Some(short) = chars.next() {
            let value = chars.as_str();
            if !value.is_empty() {
                return value_needs_here(follows(&format!("-{short}"), rows), value);
            }
        }
        return false;
    }
    looks_here(word)
}

fn value_needs_here(what: Next, value: &str) -> bool {
    match what {
        Next::Path => !absolute(value),
        Next::Option => option_needs_here(value),
        Next::Word => looks_here(value),
    }
}

/// A positional or a value: a command of `pipe` that runs here, or a
/// relative path, the word itself or the part after a `:` (`unix-listen:x`,
/// `PORT:PATH`). A URL is none.
fn looks_here(word: &str) -> bool {
    if word.starts_with("exec:") {
        return true;
    }
    if word.contains("://") {
        return false;
    }
    std::iter::once(word).chain(word.split(':').skip(1)).any(relative)
}

/// A relative path: one with a separator, one that starts with `.`, or a
/// name of a file that is here.
fn relative(part: &str) -> bool {
    !part.is_empty()
        && !absolute(part)
        && (part.contains('/')
            || part.contains(std::path::MAIN_SEPARATOR)
            || part.starts_with('.')
            || Path::new(part).exists())
}

/// A path that is not of the working directory: absolute, of the home
/// directory (`~`), or `none`, which names no file (`-F none`,
/// `ControlPath=none`).
fn absolute(path: &str) -> bool {
    path == "none" || path.starts_with('~') || Path::new(path).is_absolute()
}

/// The value of `-o`, `Name=value` or `Name value`.
fn option_needs_here(option: &str) -> bool {
    let (name, value) = option.split_once(['=', ' ']).unwrap_or((option, ""));
    let name = name.trim().to_ascii_lowercase();
    COMMAND_KEYWORDS.contains(&name.as_str()) || PATH_KEYWORDS.contains(&name.as_str()) && !absolute(value.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    /// A run that names no path of here and runs no command here leaves
    /// the directory: hosts, forwards of ports, addresses, URLs and paths
    /// that are absolute or of the home directory.
    #[test]
    fn a_run_of_hosts_and_absolute_paths_leaves_the_directory() {
        let abs = std::env::temp_dir().join("k").display().to_string();
        let ca = format!("--ca-file={abs}");
        for run in [
            vec!["ssh", "-f", "-N", "-R", "8022:localhost:22", "user@example.invalid"],
            vec!["ssh", "-f", "-N", "-i", abs.as_str(), "-o", "IdentityFile=~/.ssh/id", "user@example.invalid"],
            vec!["ssh", "-f", "-N", ca.as_str(), "-L", "8080:127.0.0.1:80", "user@example.invalid"],
            vec!["pipe", "--detach", "tcp-listen:127.0.0.1:8080", "wss://ws.example.invalid/x"],
            vec!["node", "lab-invalid", "127.0.0.1:22", "--detach", "--relay-addr", "relay-a.test=127.0.0.1"],
        ] {
            assert!(!needs_here(&words(&run)), "{run:?}");
        }
    }

    /// A relative path, by a separator, a leading `.`, or as the value of a
    /// flag that takes a file, joined or not; a command that runs here.
    #[test]
    fn a_relative_path_or_a_command_here_keeps_the_directory() {
        for run in [
            vec!["ssh", "-f", "-N", "-i", "./key", "user@example.invalid"],
            vec!["ssh", "-f", "-N", "-ikey-invalid", "user@example.invalid"],
            vec!["ssh", "-f", "-N", "--result-file", "out-invalid.json", "user@example.invalid"],
            vec!["ssh", "-f", "-N", "-o", "UserKnownHostsFile=kh-invalid", "user@example.invalid"],
            vec!["ssh", "-f", "-N", "-oProxyCommand=nc %h %p", "user@example.invalid"],
            vec!["pipe", "--detach", "unix-listen:sock/s", "tcp:127.0.0.1:22"],
            vec!["pipe", "--detach", "tcp-listen:8080", "exec:cat"],
            vec!["node", "lab-invalid", "127.0.0.1:22", "--detach", "--allow", "allow-invalid.txt"],
        ] {
            assert!(needs_here(&words(&run)), "{run:?}");
        }
    }
}
