//! Small private files podssh keeps between runs: a minted relay token, and
//! the relay's pool of hosts.
//!
//! Operator decision (2026-10-01): the cache lives in the first usable of the
//! user's cache directory, the temporary directory, `/dev/shm`, and the
//! working directory. Each file is readable by its owner only. A cached file
//! that is a symlink, belongs to another user, or is readable by anyone else
//! is ignored rather than trusted. Nothing here ever prints a token.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A cached token is reused only while it has at least this long left.
pub const MIN_REMAINING_MS: i64 = 10 * 60 * 1000;

/// The largest cache file read (a pool of a few hundred host names fits).
const MAX_FILE: u64 = 64 * 1024;

#[derive(Serialize, Deserialize)]
struct Entry {
    token: String,
    /// Expiry in milliseconds since the epoch, as the relay reports it.
    expires: i64,
    /// The relay that minted the token: `host`, or `host:port`. An entry
    /// written before podssh recorded it has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minted_at: Option<String>,
}

/// A token found in the cache. Its `Debug` never shows the token.
pub struct Cached {
    pub token: String,
    pub expires_ms: i64,
    pub path: PathBuf,
    /// The relay that minted it, when the entry says so.
    pub minted_at: Option<String>,
}

impl std::fmt::Debug for Cached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cached")
            .field("token", &"<redacted>")
            .field("expires_ms", &self.expires_ms)
            .field("path", &self.path)
            .field("minted_at", &self.minted_at)
            .finish()
    }
}

/// Whether a string has the shape of a relay token: 8 to 4096 printable ASCII
/// characters and no whitespace (it goes into an HTTP header).
pub fn valid_token(token: &str) -> bool {
    (8..=4096).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic())
}

/// The directories tried, in order.
pub fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = user_cache_dir() {
        dirs.push(dir.join("podssh"));
    }
    let tag = user_tag();
    dirs.push(std::env::temp_dir().join(format!("podssh-{tag}")));
    if cfg!(unix) {
        dirs.push(PathBuf::from(format!("/dev/shm/podssh-{tag}")));
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join(".podssh"));
    }
    dirs
}

/// The cached token for `relay_host` with at least [`MIN_REMAINING_MS`] left
/// at `now_ms`, from the first directory that has one.
pub fn load(relay_host: &str, now_ms: i64) -> Option<Cached> {
    load_from(&candidate_dirs(), relay_host, now_ms)
}

/// [`load`] over explicit directories (for tests).
pub fn load_from(dirs: &[PathBuf], relay_host: &str, now_ms: i64) -> Option<Cached> {
    let name = file_name(relay_host);
    dirs.iter().find_map(|dir| {
        let path = dir.join(&name);
        let entry: Entry = serde_json::from_str(&read_trusted(&path)?).ok()?;
        (entry.expires.saturating_sub(now_ms) >= MIN_REMAINING_MS && valid_token(&entry.token))
            .then(|| Cached { token: entry.token, expires_ms: entry.expires, path, minted_at: entry.minted_at })
    })
}

/// What the cache holds for `relay_host`, without the token: when it
/// expires, the file, and the relay that minted it. The token field is never
/// read into memory, so `podssh status` cannot hold or show a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peek {
    pub expires_ms: i64,
    pub path: PathBuf,
    pub minted_at: Option<String>,
}

/// An entry with each field but the token.
#[derive(Deserialize)]
struct Meta {
    expires: i64,
    #[serde(default)]
    minted_at: Option<String>,
}

/// The entry for `relay_host` in the first directory that has a trusted one,
/// expired or not, as a [`Peek`].
pub fn peek(relay_host: &str) -> Option<Peek> {
    peek_from(&candidate_dirs(), relay_host)
}

/// [`peek`] over explicit directories (for tests).
pub fn peek_from(dirs: &[PathBuf], relay_host: &str) -> Option<Peek> {
    let name = file_name(relay_host);
    dirs.iter().find_map(|dir| {
        let path = dir.join(&name);
        let meta: Meta = serde_json::from_str(&read_trusted(&path)?).ok()?;
        Some(Peek { expires_ms: meta.expires, path, minted_at: meta.minted_at })
    })
}

/// The contents of the private file `name`, from the first directory that has
/// a trusted one.
pub fn load_file(name: &str) -> Option<String> {
    load_file_from(&candidate_dirs(), name)
}

/// [`load_file`] over explicit directories (for tests).
pub fn load_file_from(dirs: &[PathBuf], name: &str) -> Option<String> {
    dirs.iter().find_map(|dir| read_trusted(&dir.join(name)))
}

/// Save `body` as the private file `name` in the first directory that accepts
/// it.
pub fn store_file(name: &str, body: &[u8]) -> Result<PathBuf, String> {
    store_file_in_first(&candidate_dirs(), name, body)
}

/// [`store_file`] over explicit directories (for tests).
pub fn store_file_in_first(dirs: &[PathBuf], name: &str, body: &[u8]) -> Result<PathBuf, String> {
    let mut reasons = Vec::new();
    for dir in dirs {
        match write_private(dir, name, body) {
            Ok(path) => return Ok(path),
            Err(e) => reasons.push(format!("{}: {e}", dir.display())),
        }
    }
    Err(format!("no directory would take {name} ({})", reasons.join("; ")))
}

/// Save a token under `key` (see `token::token_key`), with the relay that
/// minted it, in the first directory that accepts it. Returns where it went,
/// or every directory's reason for refusing.
pub fn store(key: &str, token: &str, expires_ms: i64, minted_at: &str) -> Result<PathBuf, String> {
    store_in_first(&candidate_dirs(), key, token, expires_ms, minted_at)
}

/// [`store`] over explicit directories (for tests).
pub fn store_in_first(
    dirs: &[PathBuf],
    key: &str,
    token: &str,
    expires_ms: i64,
    minted_at: &str,
) -> Result<PathBuf, String> {
    if !valid_token(token) {
        return Err("refusing to cache something that is not a relay token".into());
    }
    let entry = Entry { token: token.to_string(), expires: expires_ms, minted_at: Some(minted_at.to_string()) };
    let body = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
    store_file_in_first(dirs, &file_name(key), &body)
}

/// Forget the cached token for `relay_host` everywhere it is ours to delete.
pub fn remove(relay_host: &str) {
    remove_from(&candidate_dirs(), relay_host);
}

/// [`remove`] over explicit directories (for tests).
pub fn remove_from(dirs: &[PathBuf], relay_host: &str) {
    remove_named_from(dirs, &file_name(relay_host));
}

/// Delete the private file `name` from each directory where it is ours: a
/// file that another user owns, or that others can read, is not touched.
pub fn remove_named_from(dirs: &[PathBuf], name: &str) {
    for dir in dirs {
        let path = dir.join(name);
        if read_trusted(&path).is_some() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// `relay-token-<host>.json`, with anything but `[a-z0-9.-]` replaced.
pub fn file_name(relay_host: &str) -> String {
    format!("relay-token-{}.json", safe_name(relay_host))
}

/// `host` lower-cased, with anything but `[a-z0-9.-]` replaced, for file names.
pub fn safe_name(host: &str) -> String {
    host.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// Read a cache file only if it is a regular file of ours that nobody else can
/// read. On Unix the checks are made on the opened file, so a symlink swapped
/// in between the check and the read cannot be followed.
fn read_trusted(path: &Path) -> Option<String> {
    let file = open_no_follow(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE || !owned_and_private(&meta) {
        return None;
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut &file, &mut text).ok()?;
    Some(text)
}

/// Write `body` to `dir/name` via a private temporary file and a rename, so a
/// reader never sees a half-written token and the file is never readable by
/// others, not even for a moment.
fn write_private(dir: &Path, name: &str, body: &[u8]) -> std::io::Result<PathBuf> {
    make_private_dir(dir)?;
    let final_path = dir.join(name);
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let result = (|| {
        let mut file = create_new_private(&tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &final_path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map(|()| final_path)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "a symlink"));
    }
    std::fs::File::open(path)
}

#[cfg(unix)]
/// A new file that only its owner can read (mode 0600), never one that exists
/// and never through a symlink.
pub fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// A new file; on Windows the access control list of the profile directory
/// keeps it private (`SECURITY.md`).
#[cfg(not(unix))]
pub fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
}

/// Create `dir` (mode 0700) if needed and make sure it is a real directory of
/// ours that nobody else can write to.
#[cfg(unix)]
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != euid() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the directory is a symlink or belongs to another user",
        ));
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(unix)]
fn owned_and_private(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.uid() == euid() && meta.mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn owned_and_private(_meta: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// A per-user tag for shared directories such as `/tmp`.
fn user_tag() -> String {
    #[cfg(unix)]
    {
        euid().to_string()
    }
    #[cfg(not(unix))]
    {
        std::env::var("USERNAME")
            .ok()
            .map(|u| u.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "user".to_string())
    }
}

/// The per-user cache directory: `%LOCALAPPDATA%` on Windows, else
/// `$XDG_CACHE_HOME` or `$HOME/.cache`. Only absolute paths count.
fn user_cache_dir() -> Option<PathBuf> {
    let absolute = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if cfg!(windows) {
        absolute("LOCALAPPDATA")
    } else {
        absolute("XDG_CACHE_HOME").or_else(|| absolute("HOME").map(|h| h.join(".cache")))
    }
}
