//! A private file that the user names, or that podssh keeps for good, such
//! as a key: read with each refusal's reason, where the cache ignores a file
//! that it can make again; and made whole, never over another file.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{create_new_private, make_private_dir, open_no_follow, owned_and_private, MAX_FILE};

/// What users other than the owner may do with a file that [`read_own`]
/// reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Others {
    /// Nothing: the file holds a secret, such as a key.
    NoAccess,
    /// Read it, and not change it: the file holds nothing secret, such as an
    /// allowlist of public keys, as sshd reads `authorized_keys`.
    Read,
}

/// A file of this user, read with no symbolic link followed: `Ok(None)` when
/// there is none. A symbolic link, a file that is not a regular one or is
/// too large, another user's file, and one open to others beyond `others`
/// are refused with the reason. On Unix the checks are made on the opened
/// file, so a link swapped in between the check and the read cannot be
/// followed.
pub fn read_own(path: &Path, others: Others) -> Result<Option<String>, String> {
    let shown = path.display();
    match std::fs::symlink_metadata(path) {
        // None, and none can be where a part of the path is not a directory
        // (Linux says so; Windows says that the path is not found).
        Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => {
            return Ok(None)
        }
        Err(e) => return Err(format!("{shown}: {e}")),
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!("{shown} is a symbolic link, which podssh does not follow here"))
        }
        Ok(_) => {}
    }
    let file = open_no_follow(path).map_err(|e| format!("{shown}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    if meta.len() > MAX_FILE {
        return Err(format!("{shown} is larger than a file of the cache can be"));
    }
    match others {
        Others::NoAccess if !owned_and_private(&meta) => {
            return Err(format!("{shown} is another user's, or others can read it; make it private (chmod 600)"))
        }
        Others::Read if !owned_and_unwritable(&meta) => {
            return Err(format!("{shown} is another user's, or others can change it; chmod go-w"))
        }
        _ => {}
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut &file, &mut text).map_err(|e| format!("{shown}: {e}"))?;
    Ok(Some(text))
}

/// Save `body` as the new private file `path`, whole or not at all, and never
/// over a file or a link that is there: `Ok(false)` then. The body goes to a
/// private temporary file first, which a hard link then names, so a reader
/// never sees half of it, and of two callers at once one makes the file.
/// Where the file system has no hard links, the file is made in place. The
/// directory must exist; its mode is not changed.
pub fn create_private(path: &Path, body: &[u8]) -> std::io::Result<bool> {
    // One name for each call, also for two threads of one process.
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not the path of a file"));
    };
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{}.{}.{unique}.tmp", name.to_string_lossy(), std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let written = (|| {
        let mut file = create_new_private(&tmp)?;
        file.write_all(body)?;
        file.sync_all()
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(_) => create_in_place(path, body),
    }
}

/// [`create_private`] with no hard link: a reader could see the file half
/// written for a moment, and a write that fails takes the file away again.
fn create_in_place(path: &Path, body: &[u8]) -> std::io::Result<bool> {
    let mut file = match create_new_private(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e),
    };
    let written = file.write_all(body).and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(true)
}

/// Make the private file `name` in the first of `dirs` that takes it, never
/// over a file that is there: its path, and whether this call made it
/// (`false`: a file of the name was there first). When none takes it, each
/// directory's reason.
pub fn create_file_in_first(dirs: &[PathBuf], name: &str, body: &[u8]) -> Result<(PathBuf, bool), String> {
    let mut reasons = Vec::new();
    for dir in dirs {
        let path = dir.join(name);
        match make_private_dir(dir).and_then(|()| create_private(&path, body)) {
            Ok(made) => return Ok((path, made)),
            Err(e) => reasons.push(format!("{}: {e}", dir.display())),
        }
    }
    Err(format!("no directory would take {name} ({})", reasons.join("; ")))
}

#[cfg(unix)]
fn owned_and_unwritable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.uid() == super::euid() && meta.mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn owned_and_unwritable(_meta: &std::fs::Metadata) -> bool {
    true
}
