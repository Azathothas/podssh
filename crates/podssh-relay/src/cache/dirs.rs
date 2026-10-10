//! Where the cache lives (T-243): the directory that `PODSSH_CACHE_DIR`
//! names, the user's cache directory, the user's runtime directory, the
//! temporary directory, and the working directory, each from the
//! environment; `none` gives no directory. Only the temporary directory's
//! fixed places of Unix are written here, and tried last (the operator,
//! 2026-10-08).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The variable that names the cache's directory, or `none` for no cache
/// (T-243).
pub const DIR_ENV: &str = "PODSSH_CACHE_DIR";

/// The temporary directory's fixed places on Unix, tried only when no
/// variable names it, and last (the operator, 2026-10-08).
#[cfg(unix)]
const FIXED_TEMPORARY: &[&str] = &["/tmp", "/dev/shm"];

/// What `PODSSH_CACHE_DIR` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chosen {
    /// Not set, or empty: the usual places.
    Unset,
    /// `none`: podssh keeps no file between runs.
    Nothing,
    /// An absolute directory, tried first.
    Dir(PathBuf),
    /// A relative path, refused: its place would follow the working
    /// directory of each run.
    Relative(String),
}

/// What `PODSSH_CACHE_DIR` says in this process's environment.
pub fn chosen() -> Chosen {
    chosen_from(&|name| std::env::var_os(name))
}

/// [`chosen`] with the environment given (for tests).
pub fn chosen_from(var: &dyn Fn(&str) -> Option<OsString>) -> Chosen {
    match var(DIR_ENV) {
        None => Chosen::Unset,
        Some(value) if value.is_empty() => Chosen::Unset,
        Some(value) if value.eq_ignore_ascii_case("none") => Chosen::Nothing,
        Some(value) if Path::new(&value).is_absolute() => Chosen::Dir(PathBuf::from(value)),
        Some(value) => Chosen::Relative(value.to_string_lossy().into_owned()),
    }
}

/// The directories tried, in order: the one of `PODSSH_CACHE_DIR`, the
/// user's cache directory, the user's runtime directory, the temporary
/// directory, the working directory. `none` gives no directory.
pub fn candidate_dirs() -> Vec<PathBuf> {
    candidate_dirs_from(&|name| std::env::var_os(name), std::env::current_dir().ok())
}

/// [`candidate_dirs`] with the environment and the working directory given
/// (for tests).
pub fn candidate_dirs_from(var: &dyn Fn(&str) -> Option<OsString>, cwd: Option<PathBuf>) -> Vec<PathBuf> {
    let absolute = |name: &str| var(name).map(PathBuf::from).filter(|p| p.is_absolute());
    let mut dirs = Vec::new();
    match chosen_from(var) {
        Chosen::Nothing => return dirs,
        Chosen::Dir(dir) => dirs.push(dir),
        Chosen::Unset | Chosen::Relative(_) => {}
    }
    let user_cache = if cfg!(windows) {
        absolute("LOCALAPPDATA")
    } else {
        absolute("XDG_CACHE_HOME").or_else(|| absolute("HOME").map(|home| home.join(".cache")))
    };
    if let Some(dir) = user_cache {
        dirs.push(dir.join("podssh"));
    }
    // Made for each user by the login session, where there is one.
    if let Some(dir) = absolute("XDG_RUNTIME_DIR") {
        dirs.push(dir.join("podssh"));
    }
    let tag = user_tag_from(var);
    for dir in temporary_dirs(var) {
        dirs.push(dir.join(format!("podssh-{tag}")));
    }
    if let Some(cwd) = cwd {
        dirs.push(cwd.join(".podssh"));
    }
    dirs
}

/// The temporary directory: the first absolute one of `TMPDIR`, `TMP` and
/// `TEMP` (Windows reads `TMP` and `TEMP`, then its own, at run time), and on
/// Unix the fixed places only when no variable names one.
fn temporary_dirs(var: &dyn Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    let named =
        ["TMPDIR", "TMP", "TEMP"].iter().find_map(|name| var(name).map(PathBuf::from).filter(|p| p.is_absolute()));
    if let Some(dir) = named {
        return vec![dir];
    }
    #[cfg(unix)]
    {
        FIXED_TEMPORARY.iter().map(PathBuf::from).collect()
    }
    #[cfg(not(unix))]
    {
        vec![std::env::temp_dir()]
    }
}

/// A per-user tag for shared directories such as the temporary one: the
/// effective uid on Unix, the user's name on Windows.
fn user_tag_from(var: &dyn Fn(&str) -> Option<OsString>) -> String {
    #[cfg(unix)]
    {
        let _ = var;
        super::euid().to_string()
    }
    #[cfg(not(unix))]
    {
        var("USERNAME")
            .map(|u| u.to_string_lossy().chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "user".to_string())
    }
}
