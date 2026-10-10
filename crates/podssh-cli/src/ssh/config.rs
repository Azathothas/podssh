//! `ssh_config` (T-043): `~/.ssh/config`, or the file of `-F` or of
//! `PODSSH_SSH_CONFIG`, read as OpenSSH 10.3p1 reads it. Each line is a
//! keyword and its arguments; a `Host` line starts a block that applies when
//! one of its patterns matches the host as typed, case and all, and none of
//! its negated ones does; the first value obtained wins, and the command
//! line beats the file. `Match`, and `Include` until T-044, are refused by
//! name with FILE:LINE: `Match` can change the host that podssh connects to,
//! so a skipped one would be a silent change of the destination.

use std::path::{Path, PathBuf};

use super::options::Settings;

/// Where the configuration comes from: `-F FILE`, else `PODSSH_SSH_CONFIG`,
/// else `~/.ssh/config`; `none` (and `/dev/null`, `NUL`) reads nothing.
pub fn file(flag: Option<&str>, variable: Option<&str>, home: Option<&Path>) -> Source {
    match flag.or(variable) {
        Some("none") | Some("/dev/null") | Some("NUL") => Source::None,
        Some(path) => Source::Given(super::tokens::tilde(path, home)),
        None => home.map_or(Source::None, |h| Source::Default(h.join(".ssh").join("config"))),
    }
}

/// A configuration file to read, and whether its absence is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Nothing to read.
    None,
    /// `-F` or `PODSSH_SSH_CONFIG`: a missing file is an error, as in
    /// OpenSSH.
    Given(PathBuf),
    /// `~/.ssh/config`: a missing file is no error.
    Default(PathBuf),
}

/// The settings of the blocks of `source` that apply to `host`.
/// `ignore_unknown` is the command line's `IgnoreUnknown`, which holds for
/// the file too and beats the file's own.
pub fn read(source: &Source, host: &str, ignore_unknown: Option<String>) -> Result<Settings, String> {
    // A named file is the user's choice; OpenSSH checks only its own default.
    let (path, named) = match source {
        Source::None => return Ok(Settings::default()),
        Source::Given(path) => (path, true),
        Source::Default(path) => (path, false),
    };
    match read_file(path, !named)? {
        Some(text) => settings(&path.display().to_string(), &text, host, ignore_unknown),
        None if named => Err(format!("{}: no such file", path.display())),
        None => Ok(Settings::default()),
    }
}

/// The largest file read: far above any configuration, and a bound on a
/// device or a pipe that never ends.
const MAX_FILE: u64 = 4 << 20;

/// The text of `path`, or `None` when there is none. As OpenSSH 10.3p1 reads
/// it: a symbolic link is followed (a store of dotfiles links the file), a
/// pipe is read, and with `checked` the opened file must be the user's or
/// root's, and no one else may change it, else it is refused.
fn read_file(path: &Path, checked: bool) -> Result<Option<String>, String> {
    let shown = path.display();
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => {
            return Ok(None)
        }
        Err(e) => return Err(format!("{shown}: {e}")),
    };
    let meta = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if meta.is_dir() {
        return Err(format!("{shown} is a directory, not an ssh_config file"));
    }
    if checked && !owner_alone_writes(&meta) {
        return Err(format!(
            "{shown}: bad owner or permissions; it must be yours or root's, and no one else may change it (chmod go-w)"
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, MAX_FILE + 1), &mut bytes)
        .map_err(|e| format!("{shown}: {e}"))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(format!("{shown} is larger than {} MiB, which no ssh_config is", MAX_FILE >> 20));
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

#[cfg(unix)]
fn owner_alone_writes(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (meta.uid() == 0 || Some(meta.uid()) == super::tokens::local_uid()) && meta.mode() & 0o022 == 0
}

// Windows keeps the owner and the writers in an access list, which podssh
// does not read yet, as for the files of its cache.
#[cfg(not(unix))]
fn owner_alone_writes(_meta: &std::fs::Metadata) -> bool {
    true
}

const MATCH_REFUSED: &str = "Match is not read yet; podssh refuses it rather than skip it, as it can change the host";

/// The settings of `text` for `host`: each line of a block that applies,
/// through the same parser as `-o`, its errors named with FILE:LINE. A line
/// of a block that does not apply is not read: OpenSSH would check it, but
/// podssh refuses some keywords that OpenSSH runs, and a block for another
/// host must not stop each connection.
pub fn settings(file: &str, text: &str, host: &str, ignore_unknown: Option<String>) -> Result<Settings, String> {
    let mut out = Settings { ignore_unknown, ..Settings::default() };
    // Lines before the first `Host` apply to each host.
    let mut applies = true;
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (keyword, value) = split(line);
        let value = uncomment(value).trim_end();
        match keyword.to_ascii_lowercase().as_str() {
            "host" => applies = host_matches(value, host),
            "match" => return Err(format!("{file}:{n}: {MATCH_REFUSED}")),
            "include" if applies => return Err(format!("{file}:{n}: Include is not read yet")),
            _ if applies => out.apply(&format!("{keyword}={value}")).map_err(|why| {
                // The parser speaks of `-o`; here the place is the line.
                format!("{file}:{n}: {}", why.strip_prefix("-o ").unwrap_or(&why))
            })?,
            _ => {}
        }
    }
    Ok(out)
}

/// A keyword and its arguments: `Keyword value` or `Keyword=value`.
fn split(line: &str) -> (&str, &str) {
    let at = line.find(|c: char| c == '=' || c.is_whitespace()).unwrap_or(line.len());
    let (keyword, rest) = line.split_at(at);
    (keyword, rest.trim_start().trim_start_matches('=').trim())
}

/// The arguments up to a `#` that starts a word outside double quotes:
/// OpenSSH reads that as a comment, also after a value.
fn uncomment(value: &str) -> &str {
    let (mut quoted, mut word_start) = (false, true);
    for (i, c) in value.char_indices() {
        if c == '#' && word_start && !quoted {
            return &value[..i];
        }
        if c == '"' {
            quoted = !quoted;
        }
        word_start = !quoted && c.is_whitespace();
    }
    value
}

/// A `Host` line's patterns against the host as typed, as OpenSSH matches
/// them, with case: one that matches, and no negated one that matches, which
/// excludes the host from this block only.
fn host_matches(patterns: &str, host: &str) -> bool {
    let mut matched = false;
    for pattern in patterns.split_whitespace() {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        if podssh_ssh::known_hosts::wildcard(pattern.as_bytes(), host.as_bytes()) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_comment_starts_a_word_outside_quotes() {
        assert_eq!(uncomment("2222 # the port"), "2222 ");
        assert_eq!(uncomment("# all of it"), "");
        assert_eq!(uncomment("a#b"), "a#b");
        assert_eq!(uncomment("\"/k/a #b\" #c"), "\"/k/a #b\" ");
    }

    #[test]
    fn host_patterns_match_with_case_and_negation() {
        assert!(host_matches("MyHost", "MyHost"));
        assert!(!host_matches("myhost", "MyHost"));
        assert!(host_matches("* !alias", "other"));
        assert!(!host_matches("* !alias", "alias"));
        assert!(host_matches("db? web*", "web.example.org"));
        assert!(!host_matches("!alias", "other"), "a negated pattern alone matches nothing");
    }
}
