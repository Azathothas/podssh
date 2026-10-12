//! `--inplace` (T-147): the bytes go into the destination itself, not to a
//! temporary name that a rename then puts in its place. The destination keeps
//! its inode, so its other hard links and each program that holds it open see
//! the new bytes; no second copy needs room, and no name is added to its
//! directory. The file is opened with no truncation, written, and cut to the
//! source's size at the end; the digests are compared as for each copy.
//!
//! **A failure leaves the destination damaged**, and says so: podssh says it
//! once before the first byte, and each failure after the first write names
//! the destination as damaged, never as it was. A destination that is a
//! symbolic link is refused (64): the bytes would go through the link.

use std::fs::File;
use std::path::{Path, PathBuf};

use podssh_ssh::sftp::{FileAttributes, FileHandle, OpenFlags, Sftp};

use super::resume::Progress;
use super::transfer::{self, Failed, Side};
use crate::exitmap::Fault;

/// What podssh says on stderr before the first byte of a run with `--inplace`.
pub const NOTICE: &str =
    "--inplace writes into each destination itself: a copy that fails leaves its destination damaged";

/// The refusal of a destination that is a link, or a directory.
fn refused(target: &str, what: &str) -> Failed {
    Failed::new(Fault::Usage, format!("{target}: {what}; --inplace writes into a file, never through a link"))
}

/// A failure after the first write: the destination is damaged. A message
/// that says the destination was not changed says so no more.
pub fn damaged(mut failed: Failed, target: &str) -> Failed {
    if let Some(at) = failed.message.find("; the destination was not changed") {
        failed.message.truncate(at);
    }
    failed.message.push_str(&format!("; {target} is damaged: --inplace wrote into it"));
    failed
}

/// The far destination `target` may take the bytes: it is not a link, nor a
/// directory.
pub async fn check_far(sftp: &Sftp, target: &str) -> Result<(), Failed> {
    match sftp.lstat(target).await {
        Ok(attrs) if attrs.is_symlink() => Err(refused(target, "a symbolic link")),
        Ok(attrs) if attrs.is_dir() => Err(refused(target, "a directory")),
        _ => Ok(()),
    }
}

/// The far destination itself, opened to write with no truncation; a new
/// file has mode 0600 until the copy gives it the source's.
pub async fn open_far(sftp: &Sftp, target: &str) -> Result<FileHandle, Failed> {
    let attrs = FileAttributes { permissions: Some(0o600), ..FileAttributes::default() };
    let flags = OpenFlags::CREATE | OpenFlags::WRITE;
    sftp.open_file(target, flags, attrs).await.map_err(|e| transfer::from_sftp(e, Side::Destination))
}

/// The local destination `target` may take the bytes: it is not a link, nor
/// a directory.
pub fn check_local(target: &Path) -> Result<(), Failed> {
    let shown = target.display().to_string();
    match std::fs::symlink_metadata(target) {
        Ok(meta) if meta.file_type().is_symlink() => Err(refused(&shown, "a symbolic link")),
        Ok(meta) if meta.is_dir() => Err(refused(&shown, "a directory")),
        _ => Ok(()),
    }
}

/// The local destination itself, opened with no truncation, and where the
/// copy starts: at the offset of an earlier attempt when its record names
/// this file and the file holds that many bytes, else at the first byte. The
/// caller reads the part before the offset for the digest.
pub fn open_local(target: &Path, progress: &mut Progress) -> Result<(PathBuf, File, u64), Failed> {
    let shown = target.display().to_string();
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(target).map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if progress.temp.as_deref() == Some(shown.as_str()) && progress.offset <= len {
        return Ok((target.to_path_buf(), file, progress.offset));
    }
    progress.begin(&shown, &shown);
    Ok((target.to_path_buf(), file, 0))
}

/// Before a copy down connects: a local destination that is a link or a
/// directory is refused, so that nothing is attempted. `name` is the far
/// source's last name.
pub fn check_before(dest: &str, name: &str, many: bool) -> Result<(), String> {
    match transfer::local_target(dest, name, many) {
        Ok(target) => check_local(&target).map_err(|f| f.message),
        Err(_) => Ok(()),
    }
}
