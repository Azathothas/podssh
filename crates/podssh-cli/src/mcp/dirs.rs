//! The directories of this host that the copies of `podssh mcp` may read and
//! write (T-488): those of `--allow-dir`, which the user gives when the
//! server starts, never the agent. `--allow-host` lets an agent reach a
//! host, not read the files of this one, so the local side of a copy has a
//! gate of its own. A path of a call is resolved, its links followed, and
//! held inside one of the directories before any child runs. A directory
//! that holds this user's keys (`~/.ssh`, podssh's cache), or lies inside
//! one, and the root of the file system, are refused as the server starts:
//! a copy from them would hand those keys to the agent.

use std::path::{Component, Path, PathBuf};

use crate::exitmap::sysexits::{EX_CONFIG, EX_USAGE};

/// The directories of a run, resolved, and as the user gave them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dirs {
    allowed: Vec<PathBuf>,
    shown: Vec<String>,
}

impl Dirs {
    /// The directories of `values`, each resolved and checked against the
    /// directories of keys `keys`: the refusal's exit code and words, 78 for
    /// a directory that is not there, as `-F`'s file, and 64 for one of keys.
    pub fn new(values: &[String], keys: &[PathBuf]) -> Result<Dirs, (i32, String)> {
        let mut dirs = Dirs::default();
        for value in values {
            let resolved = std::fs::canonicalize(value)
                .ok()
                .filter(|p| p.is_dir())
                .ok_or((EX_CONFIG, format!("--allow-dir {value}: no such directory")))?;
            if resolved.parent().is_none() {
                return Err((EX_USAGE, format!("--allow-dir {value}: the root of the file system holds each file")));
            }
            for key in keys {
                if key.starts_with(&resolved) {
                    let why = format!("{} is inside it, and a copy would hand its keys to the agent", key.display());
                    return Err((EX_USAGE, format!("--allow-dir {value}: {why}; name a directory that holds no keys")));
                }
                if resolved.starts_with(key) {
                    let why = format!("it is inside {}, which holds keys", key.display());
                    return Err((EX_USAGE, format!("--allow-dir {value}: {why}")));
                }
            }
            dirs.allowed.push(resolved);
            dirs.shown.push(value.clone());
        }
        Ok(dirs)
    }

    /// Whether no directory is allowed: the copies are then not offered.
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// The directories as given, joined for a sentence.
    pub fn shown(&self) -> String {
        self.shown.join(", ")
    }

    /// The path of a call: a relative one is under the first directory.
    fn given(&self, path: &str) -> Result<PathBuf, String> {
        let first =
            self.allowed.first().ok_or("no directory is allowed: podssh mcp was started with no --allow-dir")?;
        if path.is_empty() || path.contains('\0') {
            return Err("local_path: a path, not empty, with no NUL".into());
        }
        let path = Path::new(path);
        Ok(if path.is_absolute() { path.to_path_buf() } else { first.join(path) })
    }

    /// Whether `resolved` lies in an allowed directory.
    fn holds(&self, resolved: &Path, given: &str) -> Result<(), String> {
        if self.allowed.iter().any(|dir| resolved.starts_with(dir)) {
            return Ok(());
        }
        let shown = resolved.display();
        Err(format!("local_path {given}: {shown} is outside the directories of --allow-dir ({})", self.shown()))
    }

    /// What a copy reads: a path that is there and, its links followed, lies
    /// in an allowed directory.
    pub fn source(&self, path: &str) -> Result<PathBuf, String> {
        let joined = self.given(path)?;
        let resolved = std::fs::canonicalize(&joined).map_err(|e| format!("local_path {path}: {e}"))?;
        self.holds(&resolved, path)?;
        Ok(resolved)
    }

    /// Where a copy writes: a path that is there, its links followed, or a
    /// new name in a directory that is there, each in an allowed directory.
    /// `new_only`, for a tree: the path must not be there, so that each path
    /// below it is one that the copy makes, and none a link made before it.
    pub fn target(&self, path: &str, new_only: bool) -> Result<PathBuf, String> {
        let joined = self.given(path)?;
        if let Ok(resolved) = std::fs::canonicalize(&joined) {
            if new_only {
                return Err(format!("local_path {path}: is there; a tree goes into a new path"));
            }
            self.holds(&resolved, path)?;
            return Ok(resolved);
        }
        // A link that names nothing would take the copy where it names.
        if std::fs::symlink_metadata(&joined).is_ok() {
            return Err(format!("local_path {path}: a link that names nothing here"));
        }
        let name = match joined.components().next_back() {
            Some(Component::Normal(name)) => name.to_os_string(),
            _ => return Err(format!("local_path {path}: name the file or the directory to make")),
        };
        let parent = joined.parent().ok_or(format!("local_path {path}: name the file to make"))?;
        let resolved = std::fs::canonicalize(parent)
            .ok()
            .filter(|p| p.is_dir())
            .ok_or(format!("local_path {path}: its directory is not there"))?;
        self.holds(&resolved, path)?;
        Ok(resolved.join(name))
    }
}

/// The directories of this user's keys that a copy must never reach: `.ssh`
/// of the home, there or not, and each directory of podssh's cache that is
/// there, resolved.
pub fn key_dirs() -> Vec<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute());
    let ssh = home.map(|h| std::fs::canonicalize(&h).unwrap_or(h).join(".ssh"));
    let mut keys: Vec<PathBuf> = ssh.into_iter().collect();
    keys.extend(podssh_relay::cache::candidate_dirs().iter().filter_map(|dir| std::fs::canonicalize(dir).ok()));
    keys
}

/// A path as an operand of `podssh cp`: on Windows with no `\\?\`, which a
/// resolved path has and a command line does not.
pub fn operand(path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return rest.to_string();
        }
    }
    text
}

#[cfg(test)]
#[path = "dirs_tests.rs"]
mod tests;
