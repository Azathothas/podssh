//! Whose tree a directory of the cache is in (T-593, GitHub #118). A process
//! that runs with the `HOME` of another user, as root in a container or a
//! notebook often does, must neither keep its files there, a node's key
//! among them, nor make a missing `.cache` there that would then be its own
//! and closed to the home's owner. Each owner is read on the running host,
//! and the home of the effective uid's entry in the user database comes in
//! place of a home that is another user's.

use std::path::{Path, PathBuf};

/// The user database, read as a file, as T-500 reads it: a static binary has
/// no NSS, and the file is what each C library reads first.
const PASSWD: &str = "/etc/passwd";

/// The most of that file that is read: a file synced from a directory can be
/// large, and an entry past this is not looked for.
const PASSWD_MOST: u64 = 16 << 20;

/// The uid whose directories each user may hold the cache under.
const ROOT: u32 = 0;

/// What the list of the cache reads of its host, given by the tests so that
/// they run as any user.
pub struct Host<'a> {
    /// The effective uid.
    pub uid: u32,
    /// The owner of a directory, `Ok(None)` when there is none.
    pub owner: &'a dyn Fn(&Path) -> Result<Option<u32>, String>,
    /// The home of a uid's entry in the user database.
    pub home_of: &'a dyn Fn(u32) -> Option<PathBuf>,
}

impl Host<'static> {
    /// This host: the effective uid, the owners on its file systems, and its
    /// user database.
    pub fn this() -> Host<'static> {
        Host { uid: super::euid(), owner: &owner_of, home_of: &entry_home }
    }
}

/// Why the directory `at` is neither the uid's nor root's: its owner, or why
/// it cannot be read. `None` when it is, and when it is missing.
fn not_ours(at: &Path, host: &Host) -> Option<String> {
    match (host.owner)(at) {
        Ok(None) => None,
        Ok(Some(uid)) if uid == host.uid || uid == ROOT => None,
        Ok(Some(uid)) => Some(format!("uid {uid} owns {}", at.display())),
        Err(why) => Some(why),
    }
}

/// Why `dir` is in another user's tree; `None` when it is this user's. Each
/// directory of it that exists, from `dir` up to `top` when `dir` is in it
/// (its home), else up to the root, must be the uid's or root's, as OpenSSH's
/// StrictModes walks a key's path up to the home. The walk goes past the
/// nearest one, so that a `.cache` that an earlier run made in another's home
/// still reads as theirs.
pub fn foreign(dir: &Path, top: Option<&Path>, host: &Host) -> Option<String> {
    let top = top.filter(|top| dir.starts_with(top));
    for at in dir.ancestors().filter(|at| !at.as_os_str().is_empty()) {
        if let Some(why) = not_ours(at, host) {
            return Some(why);
        }
        if Some(at) == top {
            break;
        }
    }
    None
}

/// Make `dir` and each missing directory above it, mode 0700: one above it
/// only in a directory of the uid or of root, and `dir` itself, the cache's
/// own, in any that lets the uid in. The directories made, the highest first.
pub fn make_dirs(dir: &Path, host: &Host) -> std::io::Result<Vec<PathBuf>> {
    use std::os::unix::fs::DirBuilderExt;
    let mut missing = Vec::new();
    for at in dir.ancestors().filter(|at| !at.as_os_str().is_empty()) {
        match std::fs::symlink_metadata(at) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing.push(at),
            Err(e) => return Err(e),
        }
    }
    let mut made = Vec::new();
    for at in missing.into_iter().rev() {
        if at != dir {
            let parent = at.parent().unwrap_or(at);
            if let Some(why) = not_ours(parent, host) {
                let why = format!("{why}, and podssh makes no directory there but the cache's own");
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, why));
            }
        }
        match std::fs::DirBuilder::new().mode(0o700).create(at) {
            Ok(()) => made.push(at.to_path_buf()),
            // Another run made it first.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Ok(made)
}

/// The owner of `path` on this host: `Ok(None)` when there is nothing there.
/// A symbolic link counts as its own owner's when that is neither root nor
/// its target's owner, so that another user's link to a directory of this
/// user's is not this user's tree.
fn owner_of(path: &Path) -> Result<Option<u32>, String> {
    use std::os::unix::fs::MetadataExt;
    let shown = path.display();
    let link = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{shown}: {e}")),
    };
    if !link.file_type().is_symlink() {
        return Ok(Some(link.uid()));
    }
    match std::fs::metadata(path) {
        Ok(target) if link.uid() != ROOT && link.uid() != target.uid() => Ok(Some(link.uid())),
        Ok(target) => Ok(Some(target.uid())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!("{shown} is a symbolic link to nothing")),
        Err(e) => Err(format!("{shown}: {e}")),
    }
}

/// The home of `uid`'s first entry in the text of a passwd file, whose lines
/// are `name:password:uid:gid:gecos:home:shell`, when it is absolute. A
/// comment, a line of NIS (`+` or `-`), a line with too few fields and a name
/// with a blank or a control character are passed over, as T-500 and the C
/// library pass them over.
pub fn passwd_home(text: &str, uid: u32) -> Option<PathBuf> {
    let entry = text.lines().filter(|line| !line.starts_with(['#', '+', '-'])).find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        let name = fields[0];
        let usable = fields.len() >= 7
            && !name.is_empty()
            && !name.chars().any(|c| c.is_whitespace() || c.is_control() || c == char::REPLACEMENT_CHARACTER);
        (usable && fields[2].parse::<u32>().is_ok_and(|u| u == uid)).then(|| PathBuf::from(fields[5]))
    });
    entry.filter(|home| home.is_absolute())
}

/// The home of `uid`'s entry in the file of the user database: a file that is
/// missing or unreadable, or that has no such entry, gives none, and the
/// list of the cache goes on without it.
fn file_home(uid: u32) -> Option<PathBuf> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(PASSWD).ok()?.take(PASSWD_MOST).read_to_end(&mut bytes).ok()?;
    passwd_home(&String::from_utf8_lossy(&bytes), uid)
}

/// The home of `uid`'s entry: on Linux and the BSDs the file alone.
#[cfg(not(target_os = "macos"))]
fn entry_home(uid: u32) -> Option<PathBuf> {
    file_home(uid)
}

/// On macOS the users are in the system's directory, which `getpwuid_r`
/// reads, as T-500 reads the login name; the file, which holds the system's
/// own accounts and root's, is the fallback.
#[cfg(target_os = "macos")]
fn entry_home(uid: u32) -> Option<PathBuf> {
    directory_home(uid).or_else(|| file_home(uid))
}

/// The home of `uid`'s entry as macOS's directory gives it.
#[cfg(target_os = "macos")]
fn directory_home(uid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        // SAFETY: an all-zero passwd is valid (null pointers).
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: getpwuid_r writes only within `buf`, whose length it is
        // given, and into `pwd` and `found`, which outlive the call.
        let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success the home is NUL-terminated inside `buf`.
        let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
        let home = PathBuf::from(std::ffi::OsStr::from_bytes(home.to_bytes()));
        return home.is_absolute().then_some(home);
    }
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;
