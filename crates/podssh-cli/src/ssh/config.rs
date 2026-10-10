//! `ssh_config` (T-043, T-044): `~/.ssh/config` and then the system's file,
//! or only the file of `-F` or of `PODSSH_SSH_CONFIG`, read as OpenSSH
//! 10.3p1 reads them. Each line is a keyword and its arguments; a `Host`
//! line starts a block that applies when one of its patterns matches the
//! host as typed, case and all, and none of its negated ones does; the first
//! value obtained wins, and the command line beats the files. `Include` is
//! read where it stands. `Match all` applies where it stands and `Match
//! final all` after the last line; each other `Match` is refused by name
//! with FILE:LINE until T-045, as it can change the host that podssh
//! connects to, so a skipped one would be a silent change of the
//! destination.

mod glob;

use std::path::{Path, PathBuf};

use super::options::Settings;
use super::tokens::Tokens;

/// Where the configuration comes from: `-F FILE`, else `PODSSH_SSH_CONFIG`,
/// else `~/.ssh/config` and the system's file; `none` (and `/dev/null`,
/// `NUL`) reads nothing.
pub fn file(flag: Option<&str>, variable: Option<&str>, home: Option<&Path>) -> Source {
    match flag.or(variable) {
        Some("none") | Some("/dev/null") | Some("NUL") => Source::None,
        Some(path) => Source::Given(super::tokens::tilde(path, home)),
        None => Source::Default(home.map(|h| h.join(".ssh").join("config"))),
    }
}

/// The configuration files to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Nothing to read.
    None,
    /// `-F` or `PODSSH_SSH_CONFIG`, alone: a missing file is an error, as
    /// in OpenSSH.
    Given(PathBuf),
    /// `~/.ssh/config` when the home is known, then the system's file: a
    /// missing one is no error.
    Default(Option<PathBuf>),
}

/// The system's file, as OpenSSH reads it: `/etc/ssh/ssh_config`, and
/// `%ProgramData%\ssh\ssh_config` with OpenSSH for Windows.
pub fn system_file() -> PathBuf {
    if cfg!(windows) {
        let data = std::env::var_os("ProgramData").map(PathBuf::from);
        data.unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("ssh").join("ssh_config")
    } else {
        PathBuf::from("/etc/ssh/ssh_config")
    }
}

/// What a reading needs besides its files.
pub struct Context<'a> {
    /// The host as typed, for `Host` and `%n`.
    pub host: &'a str,
    /// For `~`, and for a relative `Include` of a user's file (`~/.ssh`).
    pub home: Option<&'a Path>,
    /// The system's file, read after `~/.ssh/config`; `None` reads none.
    pub system: Option<&'a Path>,
    /// The `%` tokens of an `Include`, with the values of the moment: the
    /// command line's, and those of the lines read so far.
    pub tokens: &'a dyn Fn(&Settings) -> Tokens,
}

/// A chain of includes stops here, as in OpenSSH (`READCONF_MAX_DEPTH`).
const MAX_DEPTH: usize = 16;

/// The settings of the blocks of `source` that apply. `ignore_unknown` is
/// the command line's `IgnoreUnknown`, which holds for the files too and
/// beats theirs.
pub fn read(source: &Source, ctx: &Context, ignore_unknown: Option<String>) -> Result<Settings, String> {
    // A named file is the user's choice; OpenSSH checks only its default,
    // and each file that an `Include` reads.
    let files: Vec<(&Path, Kind)> = match source {
        Source::None => return Ok(Settings::default()),
        Source::Given(path) => vec![(path.as_path(), Kind::Given)],
        Source::Default(user) => {
            let mut files: Vec<(&Path, Kind)> = user.iter().map(|p| (p.as_path(), Kind::User)).collect();
            files.extend(ctx.system.map(|p| (p, Kind::System)));
            files
        }
    };
    let mut reader = Reader {
        ctx,
        out: Settings { ignore_unknown, ..Settings::default() },
        pass: Pass::First,
        saw_final: false,
        chain: Vec::new(),
    };
    for pass in [Pass::First, Pass::Final] {
        if pass == Pass::Final && !reader.saw_final {
            break;
        }
        reader.pass = pass;
        for (path, kind) in &files {
            reader.file(path, *kind, Block::First)?;
        }
    }
    Ok(reader.out)
}

/// Where a file comes from: whether it is checked, and where a relative
/// `Include` in it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    User,
    Given,
    System,
    Included { system: bool },
}

/// The first pass reads each block that applies; the second, only when a
/// `Match final all` was met, reads those blocks, so that they fill only
/// what is still unset, as OpenSSH's final pass does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    First,
    Final,
}

/// The block that a line is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Block {
    /// A `Host` that does not apply.
    Off,
    /// The top of a file, a `Host` that applies, or `Match all`.
    First,
    /// `Match final all`.
    Final,
}

struct Reader<'a> {
    ctx: &'a Context<'a>,
    out: Settings,
    pass: Pass,
    saw_final: bool,
    /// The files being read, for the message of a loop.
    chain: Vec<String>,
}

impl Reader<'_> {
    /// Read `path` in `block`, the block of the line that names it: a `Host`
    /// line in it holds to its end only.
    fn file(&mut self, path: &Path, kind: Kind, block: Block) -> Result<(), String> {
        let shown = path.display().to_string();
        let checked = matches!(kind, Kind::User | Kind::Included { .. });
        let Some(text) = read_file(path, checked)? else {
            return match kind {
                Kind::Given => Err(format!("{shown}: no such file")),
                _ => Ok(()),
            };
        };
        if self.chain.len() > MAX_DEPTH {
            return Err(format!("{shown}: more than {MAX_DEPTH} nested includes: {}", self.chain.join(" -> ")));
        }
        self.chain.push(shown.clone());
        let system = matches!(kind, Kind::System | Kind::Included { system: true });
        let read = self.lines(&shown, &text, system, block);
        self.chain.pop();
        read
    }

    fn lines(&mut self, file: &str, text: &str, system: bool, mut block: Block) -> Result<(), String> {
        for (i, raw) in text.lines().enumerate() {
            let n = i + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (keyword, value) = split(line);
            let value = uncomment(value).trim_end();
            let at = |why: &str| format!("{file}:{n}: {}", why.strip_prefix("-o ").unwrap_or(why));
            match keyword.to_ascii_lowercase().as_str() {
                "host" => block = if host_matches(value, self.ctx.host) { Block::First } else { Block::Off },
                "match" => block = self.matched(value).map_err(|why| at(&why))?,
                // An `Include` of a block read in neither pass is not read:
                // a block for another host must not stop each connection.
                "include" if block == Block::First || (self.pass == Pass::Final && block == Block::Final) => {
                    self.include(value, system, block).map_err(|why| at(&why))?
                }
                "include" => {}
                _ if self.applies(block) => self.out.apply(&format!("{keyword}={value}")).map_err(|why| at(&why))?,
                _ => {}
            }
        }
        Ok(())
    }

    fn applies(&self, block: Block) -> bool {
        match self.pass {
            Pass::First => block == Block::First,
            Pass::Final => block == Block::Final,
        }
    }

    fn matched(&mut self, value: &str) -> Result<Block, String> {
        let words: Vec<String> = value.split_whitespace().map(str::to_ascii_lowercase).collect();
        match words.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            ["all"] => Ok(Block::First),
            ["final", "all"] => {
                self.saw_final = true;
                Ok(Block::Final)
            }
            _ => Err(MATCH_REFUSED.to_string()),
        }
    }

    /// Each file that an `Include` names, in order: its `%` tokens and `~`
    /// expanded, a relative path from `~/.ssh`, or from the system's
    /// directory for a system file, and a glob's names sorted.
    fn include(&mut self, value: &str, system: bool, block: Block) -> Result<(), String> {
        let names = super::options::words(value);
        if names.is_empty() {
            return Err("Include needs a file".into());
        }
        let tokens = (self.ctx.tokens)(&self.out);
        for name in names {
            let path = super::tokens::tilde(&tokens.text("Include ", &name, &[])?, self.ctx.home);
            let path = if path.is_absolute() || path.has_root() {
                path
            } else if system {
                let base =
                    self.ctx.system.and_then(Path::parent).ok_or("a relative Include needs the system's directory")?;
                base.join(path)
            } else {
                let home = self.ctx.home.ok_or("a relative Include starts from ~/.ssh, and the home is unknown")?;
                home.join(".ssh").join(path)
            };
            for found in glob::expand(&path) {
                // A directory that a glob names is skipped, as OpenSSH skips it.
                if found.is_dir() {
                    continue;
                }
                self.file(&found, Kind::Included { system }, block)?;
            }
        }
        Ok(())
    }
}

const MATCH_REFUSED: &str =
    "Match is not read yet, but for Match all and Match final all; podssh refuses it rather than skip it, as it can \
     change the host";

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
// does not read yet, as for the files of its cache (T-274).
#[cfg(not(unix))]
fn owner_alone_writes(_meta: &std::fs::Metadata) -> bool {
    true
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
