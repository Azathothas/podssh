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

/// Each session of the cache's directories, by name: its name and its
/// socket, once each name, sorted.
pub fn all() -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for dir in dirs() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(file) = entry.file_name().into_string() else { continue };
            let Some(name) = file.strip_suffix(".sock") else { continue };
            if super::check_name(name).is_ok() && !found.iter().any(|(n, _)| n == name) {
                found.push((name.to_string(), shown(&entry.path())));
            }
        }
    }
    found.sort();
    found
}

fn shown(path: &Path) -> String {
    path.display().to_string()
}
