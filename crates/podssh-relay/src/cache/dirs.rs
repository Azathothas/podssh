//! Where the cache lives (T-243): the directory that `PODSSH_CACHE_DIR`
//! names, the user's cache directory, the user's runtime directory, the
//! temporary directory, and the working directory, each from the
//! environment; `none` gives no directory. Only the temporary directory's
//! fixed places of Unix are written here, and tried last (the operator,
//! 2026-10-08).
//!
//! On Unix the user's cache and runtime directories count only in a tree of
//! the effective uid or of root (T-593): one in another user's tree is passed
//! over, and still read for what podssh kept there before, and the home of
//! the uid's entry in the user database gives the user's cache in its place.

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

/// The cache's places (T-593): the directories that podssh writes in, in
/// order, and each usual place that it passed over, with why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Places {
    /// The directories tried for a new file, in order.
    pub dirs: Vec<PathBuf>,
    /// The user's cache directory among them, where there is one.
    pub user: Option<PathBuf>,
    /// Each usual place in another user's tree.
    pub passed: Vec<Passed>,
}

/// A usual place of the cache that is in another user's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passed {
    /// The cache's directory that it would be, `DIR/podssh`.
    pub dir: PathBuf,
    /// Why: the directory on the way and its owner.
    pub why: String,
}

impl Places {
    /// Where a kept file is looked for: the directories that podssh writes
    /// in, then each place passed over, so that a key, a pin, a pair or a
    /// token kept there before is still found, and a newer copy in this
    /// user's own cache wins.
    pub fn read(&self) -> Vec<PathBuf> {
        self.dirs.iter().chain(self.passed.iter().map(|p| &p.dir)).cloned().collect()
    }

    /// The place passed over that holds the file `path`, if any.
    pub fn passed_for(&self, path: &Path) -> Option<&Passed> {
        self.passed.iter().find(|p| path.parent() == Some(p.dir.as_path()))
    }

    /// What a run says once of a file at `path` that is in a place passed
    /// over: where it is, why, and where to move it to keep it; podssh moves
    /// nothing.
    pub fn kept_note(&self, path: &Path) -> Option<String> {
        let passed = self.passed_for(path)?;
        let to = match (&self.user, path.file_name()) {
            (Some(dir), Some(name)) => {
                format!("move it to {} to keep it in this user's own cache", dir.join(name).display())
            }
            _ => format!("move it to a directory of this user's that lasts, and name that directory in {DIR_ENV}"),
        };
        Some(format!(
            "{} is in another user's tree ({}): podssh reads it there and writes nothing more there; {to}",
            path.display(),
            passed.why
        ))
    }
}

/// The cache's places in this process's environment, on this host.
pub fn places() -> Places {
    places_from(&|name| std::env::var_os(name), std::env::current_dir().ok())
}

/// [`places`] with the environment and the working directory given; the
/// owners and the user database are this host's.
pub fn places_from(var: &dyn Fn(&str) -> Option<OsString>, cwd: Option<PathBuf>) -> Places {
    #[cfg(unix)]
    {
        places_with(var, cwd, &super::owner::Host::this())
    }
    #[cfg(not(unix))]
    {
        // No owner is read: a profile of another user is no report there.
        collect(var, cwd, &|_, _| None, &|| None)
    }
}

/// [`places`] with the environment, the working directory, the owners and
/// the user database given (for tests, which then run as any user).
#[cfg(unix)]
pub fn places_with(
    var: &dyn Fn(&str) -> Option<OsString>,
    cwd: Option<PathBuf>,
    host: &super::owner::Host,
) -> Places {
    let foreign = |dir: &Path, top: Option<&Path>| super::owner::foreign(dir, top, host);
    collect(var, cwd, &foreign, &|| (host.home_of)(host.uid))
}

/// The directories tried, in order: the one of `PODSSH_CACHE_DIR`, the
/// user's cache directory, the user's runtime directory, the temporary
/// directory, the working directory. `none` gives no directory.
pub fn candidate_dirs() -> Vec<PathBuf> {
    places().dirs
}

/// [`candidate_dirs`] with the environment and the working directory given
/// (for tests).
pub fn candidate_dirs_from(var: &dyn Fn(&str) -> Option<OsString>, cwd: Option<PathBuf>) -> Vec<PathBuf> {
    places_from(var, cwd).dirs
}

/// Where a kept file is looked for in this process's environment: see
/// [`Places::read`].
pub fn read_dirs() -> Vec<PathBuf> {
    places().read()
}

/// What a run says once of a file found at `path`: see [`Places::kept_note`].
pub fn kept_note(path: &Path) -> Option<String> {
    places().kept_note(path)
}

/// The list, with `foreign` saying why a directory is in another user's tree
/// (`top` is its home), and `entry` giving the home of the uid's entry in the
/// user database.
fn collect(
    var: &dyn Fn(&str) -> Option<OsString>,
    cwd: Option<PathBuf>,
    foreign: &dyn Fn(&Path, Option<&Path>) -> Option<String>,
    entry: &dyn Fn() -> Option<PathBuf>,
) -> Places {
    let absolute = |name: &str| var(name).map(PathBuf::from).filter(|p| p.is_absolute());
    let mut places = Places::default();
    match chosen_from(var) {
        Chosen::Nothing => return places,
        Chosen::Dir(dir) => places.dirs.push(dir),
        Chosen::Unset | Chosen::Relative(_) => {}
    }
    if let Some(dir) = user_cache(&absolute, foreign, entry, &mut places.passed) {
        places.user = Some(dir.clone());
        places.dirs.push(dir);
    }
    // Made for each user by the login session, where there is one, and the
    // user's own by the XDG spec.
    if let Some(dir) = absolute("XDG_RUNTIME_DIR") {
        match foreign(&dir, None) {
            None => places.dirs.push(dir.join("podssh")),
            Some(why) => places.passed.push(Passed { dir: dir.join("podssh"), why }),
        }
    }
    let tag = user_tag_from(var);
    for dir in temporary_dirs(var) {
        places.dirs.push(dir.join(format!("podssh-{tag}")));
    }
    if let Some(cwd) = cwd {
        places.dirs.push(cwd.join(".podssh"));
    }
    places
}

/// The user's cache directory, `DIR/podssh`: on Windows `LOCALAPPDATA`; else
/// the first of `XDG_CACHE_HOME` and `HOME/.cache` that is in this user's
/// tree, else, once one was passed over, the `.cache` of the home of the
/// uid's entry in the user database. Each place passed over goes to `passed`.
fn user_cache(
    absolute: &dyn Fn(&str) -> Option<PathBuf>,
    foreign: &dyn Fn(&Path, Option<&Path>) -> Option<String>,
    entry: &dyn Fn() -> Option<PathBuf>,
    passed: &mut Vec<Passed>,
) -> Option<PathBuf> {
    if cfg!(windows) {
        return absolute("LOCALAPPDATA").map(|dir| dir.join("podssh"));
    }
    let home = absolute("HOME");
    let offered = absolute("XDG_CACHE_HOME")
        .map(|dir| (dir, home.clone()))
        .into_iter()
        .chain(home.clone().map(|home| (home.join(".cache"), Some(home))));
    for (dir, top) in offered {
        if passed.iter().any(|p| p.dir == dir.join("podssh")) {
            continue;
        }
        match foreign(&dir, top.as_deref()) {
            None => return Some(dir.join("podssh")),
            Some(why) => passed.push(Passed { dir: dir.join("podssh"), why }),
        }
    }
    // With no variable that names a place, none is guessed.
    if passed.is_empty() {
        return None;
    }
    let home = entry()?;
    let dir = home.join(".cache");
    if passed.iter().any(|p| p.dir == dir.join("podssh")) {
        return None;
    }
    match foreign(&dir, Some(&home)) {
        None => Some(dir.join("podssh")),
        Some(why) => {
            passed.push(Passed { dir: dir.join("podssh"), why });
            None
        }
    }
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
