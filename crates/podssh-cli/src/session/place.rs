//! Where a session's socket is (T-186): `NAME.sock` in the directory
//! `sessions` of the first directory of the cache that podssh can make
//! private (mode 0700; on Windows an access list of this user's), or the
//! path of `--socket`. A client looks for NAME in each directory of the
//! cache, in its order, as the cache finds its token.

use std::path::{Path, PathBuf};

use crate::relay_settings::Refusal;

/// The directory of the sessions, in each directory of the cache.
const DIR: &str = "sessions";

/// The directories of the sockets, in the cache's order.
fn dirs() -> Vec<PathBuf> {
    podssh_relay::cache::candidate_dirs().into_iter().map(|dir| dir.join(DIR)).collect()
}

/// The file of the session `name` in `dir`.
fn file(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.sock"))
}

/// The socket of the session `name`, as a client finds it: `--socket`,
/// else the first directory that holds its file.
pub fn find(name: &str, socket: Option<&str>) -> Option<String> {
    if let Some(path) = socket {
        return Some(path.to_string());
    }
    dirs().iter().map(|dir| file(dir, name)).find(|path| path.symlink_metadata().is_ok()).map(|p| shown(&p))
}

/// Where a new session `name` listens: `--socket`, else its file in the
/// first directory that podssh can make private, and whose path fits the
/// address of a socket.
pub fn new(name: &str, socket: Option<&str>) -> Result<String, Refusal> {
    if let Some(path) = socket {
        return Ok(path.to_string());
    }
    let dirs = dirs();
    if dirs.is_empty() {
        return Err(Refusal::config(format!(
            "{} is none, so podssh keeps no file between runs: give --socket PATH",
            podssh_relay::cache::DIR_ENV
        )));
    }
    new_in(&dirs, name).map_err(|why| Refusal::config(format!("no directory takes the session's socket: {why}")))
}

/// [`new`] in `dirs`: the first that fits, or why none did.
pub(super) fn new_in(dirs: &[PathBuf], name: &str) -> Result<String, String> {
    let mut why = Vec::new();
    for dir in dirs {
        let path = file(dir, name);
        // The address holds the path and its NUL.
        if path.as_os_str().len() >= crate::pipe::unix::SUN_PATH {
            why.push(format!("{}: too long for the address of a socket", path.display()));
            continue;
        }
        match podssh_relay::cache::private_dir(dir) {
            Ok(()) => return Ok(shown(&path)),
            Err(e) => why.push(format!("{}: {e}", dir.display())),
        }
    }
    Err(format!("{}; give --socket PATH", why.join("; ")))
}

/// What a look in the cache's directories found (T-506).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// Each session by name: its name and its socket, once each name,
    /// sorted.
    pub sessions: Vec<(String, String)>,
    /// Each directory of the sessions, in the cache's order.
    pub looked: Vec<String>,
    /// Those that are there and were read.
    pub read: Vec<String>,
    /// Those that are there and could not be read, each with why.
    pub unreadable: Vec<(String, String)>,
}

/// Each session of the cache's directories. A directory that is not there
/// holds none, as no session started there yet.
pub fn all() -> Found {
    all_in(&dirs())
}

/// [`all`] in `dirs`.
pub(super) fn all_in(dirs: &[PathBuf]) -> Found {
    let mut found = Found { looked: dirs.iter().map(|d| shown(d)).collect(), ..Found::default() };
    for dir in dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                found.unreadable.push((shown(dir), e.to_string()));
                continue;
            }
        };
        found.read.push(shown(dir));
        for entry in entries.flatten() {
            let Ok(file) = entry.file_name().into_string() else { continue };
            let Some(name) = file.strip_suffix(".sock") else { continue };
            if super::check_name(name).is_ok() && !found.sessions.iter().any(|(n, _)| n == name) {
                found.sessions.push((name.to_string(), shown(&entry.path())));
            }
        }
    }
    found.sessions.sort();
    found
}

fn shown(path: &Path) -> String {
    path.display().to_string()
}
