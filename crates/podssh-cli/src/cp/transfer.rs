//! The parts of a copy that both roads share: what a file done and a failure
//! are, the temporary name beside the destination, the digests compared,
//! and the rename onto the destination; and the copy within one server by
//! `copy-data`. The SFTP road's up and down are in [`super::bysftp`].
//!
//! **The destination's name never holds a file that was not verified.** The
//! bytes go to `.NAME.podssh-RANDOM.part` in the destination's directory,
//! created anew with mode 0600; after the digests agree, the file gets the
//! source's permission bits and is renamed onto the destination, at once
//! where the server has `posix-rename@openssh.com`. A failure removes the
//! temporary file.

use std::path::{Path, PathBuf};

use podssh_ssh::sftp::{FileAttributes, OpenFlags, Sftp, SftpError};
use podssh_ssh::{Connection, Log};

use super::digest::{self, Sum};
use crate::exitmap::Fault;

/// One file copied and verified, or moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub source: String,
    pub destination: String,
    pub bytes: u64,
    /// The SHA-256 of what was sent; none for a move that the server made
    /// by a rename, as no byte moved.
    pub sum: Option<Sum>,
    /// How the far digest was taken: a tool's name, "read again", or
    /// "rename".
    pub verified_by: String,
    /// An existing destination was removed before the rename: the server has
    /// no `posix-rename@openssh.com`.
    pub not_atomic: bool,
    /// For `mv`: whether the source is gone. `None` for `cp`.
    pub removed: Option<bool>,
}

/// What a failure leaves the copy able to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cause {
    /// An answer: a status of the server, a local error, a refusal.
    #[default]
    Answer,
    /// The connection broke under the step: a new one can continue the copy
    /// (T-136).
    Broke,
    /// The relay session is near its limits: a new one goes on at once
    /// (T-137).
    Spent,
    /// The digests differ.
    Digests,
}

/// A failure, and the fault that sets the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub fault: Fault,
    pub message: String,
    pub cause: Cause,
}

impl Failed {
    /// A failure that is an answer.
    pub fn new(fault: Fault, message: String) -> Failed {
        Failed { fault, message, cause: Cause::Answer }
    }
}

fn failed(fault: Fault, message: String) -> Failed {
    Failed::new(fault, message)
}

/// Which side a failure is on: a source that cannot be read, or a
/// destination that cannot be written.
#[derive(Clone, Copy)]
pub(super) enum Side {
    Source,
    Destination,
}

/// The failure of an SFTP step: a status on a path names the side; a step
/// with no answer, or a session that broke, is a fault of the session.
pub(super) fn from_sftp(e: SftpError, side: Side) -> Failed {
    let fault = match (&e, side) {
        (SftpError::Status { .. }, Side::Source) => Fault::NoInput,
        (SftpError::Status { .. }, Side::Destination) => Fault::CantCreate,
        (SftpError::NoSftp, _) => Fault::RelayUnreachable,
        _ => Fault::SessionFault,
    };
    // No reply, or a closed channel: the connection broke, and a new one
    // can go on.
    let cause = match e {
        SftpError::Closed(_) | SftpError::Timeout { .. } => Cause::Broke,
        _ => Cause::Answer,
    };
    Failed { fault, message: e.to_string(), cause }
}

/// `.NAME.podssh-RANDOM.part`: hidden, unique, and named for what it holds.
pub(super) fn temp_name(name: &str) -> String {
    format!(".{name}.podssh-{:016x}.part", rand::random::<u64>())
}

/// The far digest: by a command when the server can, else by a second read.
pub(super) async fn far_digest(
    handle: &Connection,
    sftp: &Sftp,
    path: &str,
    size: u64,
    side: Side,
) -> Result<(Sum, String), Failed> {
    if let Ok(absolute) = sftp.realpath(path).await {
        if let Some(found) = digest::by_command(handle, &absolute, size).await {
            return Ok(found);
        }
    }
    let sum = digest::by_reading(sftp, path).await.map_err(|e| from_sftp(e, side))?;
    Ok((sum, digest::READ_AGAIN.to_string()))
}

/// Compare the digests; a difference names both.
pub(super) fn compare(sent: &Sum, far: &Sum, how: &str, what: &str) -> Result<(), Failed> {
    if sent == far {
        return Ok(());
    }
    let message = format!(
        "{what}: the digests differ: SHA-256 {} sent, {} on the far side ({how}); the destination was not changed",
        digest::hex(sent),
        digest::hex(far)
    );
    Err(Failed { fault: Fault::SessionFault, message, cause: Cause::Digests })
}

/// Where a file named `name` goes on the server, for the destination
/// `dest`: into it when it is a directory (or is empty, the login
/// directory), else onto it.
pub(super) async fn remote_target(sftp: &Sftp, dest: &str, name: &str, many: bool) -> Result<String, Failed> {
    if dest.is_empty() {
        return Ok(name.to_string());
    }
    if dest.ends_with('/') {
        return Ok(format!("{dest}{name}"));
    }
    match sftp.stat(dest).await {
        Ok(attrs) if attrs.is_dir() => Ok(format!("{dest}/{name}")),
        Ok(_) if many => {
            Err(failed(Fault::CantCreate, format!("{dest} is not a directory, and there are several sources")))
        }
        Ok(_) => Ok(dest.to_string()),
        Err(e) if e.is_missing() && !many => Ok(dest.to_string()),
        Err(e) => Err(from_sftp(e, Side::Destination)),
    }
}

/// `path` split into its directory, with its last `/`, and its name.
pub(super) fn split_remote(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    }
}

/// The permission bits of a local file, for its copy.
pub(super) fn local_mode(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        if meta.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

/// Rename the verified file onto its name. Without
/// `posix-rename@openssh.com` the rename of version 3 refuses an existing
/// name: it is removed first, which is said. Whether it was.
pub(super) async fn rename_onto(sftp: &Sftp, temp: &str, target: &str, log: &Log) -> Result<bool, Failed> {
    rename_raw(sftp, temp, target, log).await.map_err(|e| from_sftp(e, Side::Destination))
}

/// [`rename_onto`] with the server's own error, for `mv` to read its code.
pub(super) async fn rename_raw(sftp: &Sftp, from: &str, target: &str, log: &Log) -> Result<bool, SftpError> {
    let first = match sftp.rename(from, target).await {
        Ok(()) => return Ok(false),
        Err(e) => e,
    };
    if sftp.has("posix-rename@openssh.com") || sftp.stat(target).await.is_err() {
        return Err(first);
    }
    log.info(&format!(
        "{target}: the server has no posix-rename, so the old file is removed first; the replace is not atomic"
    ));
    sftp.remove(target).await?;
    sftp.rename(from, target).await?;
    Ok(true)
}

/// Copy `source` to `dest` on one server with `copy-data`: no byte comes
/// through here, and both digests are taken there.
pub async fn within(sftp: &Sftp, handle: &Connection, source: &str, dest: &str, log: &Log) -> Result<Done, Failed> {
    let attrs = sftp.stat(source).await.map_err(|e| from_sftp(e, Side::Source))?;
    if !attrs.is_regular() {
        return Err(failed(Fault::NoInput, format!("{source}: not a regular file; podssh cp copies files")));
    }
    let size = attrs.size.unwrap_or(0);
    let (_, name) = split_remote(source.trim_end_matches('/'));
    let target = remote_target(sftp, dest, name, false).await?;
    let (dir, leaf) = split_remote(&target);
    let temp = format!("{dir}{}", temp_name(leaf));
    let from = sftp
        .open_file(source, OpenFlags::READ, FileAttributes::default())
        .await
        .map_err(|e| from_sftp(e, Side::Source))?;
    let new = FileAttributes { permissions: Some(0o600), ..FileAttributes::default() };
    let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE;
    let to = match sftp.open_file(&temp, flags, new).await {
        Ok(to) => to,
        Err(e) => {
            let _ = sftp.close(&from).await;
            return Err(from_sftp(e, Side::Destination));
        }
    };
    log.verbose(&format!("{source}: copy-data to {temp} on the server"));
    let copied = async {
        // A copy on the server's disk: 60 s, and 1 s more for each 16 MiB.
        let limit = podssh_ssh::sftp::DATA_WAIT + std::time::Duration::from_secs(size / (16 << 20));
        sftp.copy_data(&from, &to, limit).await.map_err(|e| from_sftp(e, Side::Destination))?;
        sftp.close(&to).await.map_err(|e| from_sftp(e, Side::Destination))?;
        let (sum, how) = far_digest(handle, sftp, source, size, Side::Source).await?;
        let (copy, _) = far_digest(handle, sftp, &temp, size, Side::Destination).await?;
        compare(&sum, &copy, &how, source)?;
        let mode = FileAttributes { permissions: attrs.permissions.map(|p| p & 0o777), ..FileAttributes::default() };
        sftp.setstat(&temp, mode).await.map_err(|e| from_sftp(e, Side::Destination))?;
        let not_atomic = rename_onto(sftp, &temp, &target, log).await?;
        Ok(Done {
            source: source.into(),
            destination: target.clone(),
            bytes: size,
            sum: Some(sum),
            verified_by: how,
            not_atomic,
            removed: None,
        })
    }
    .await;
    let _ = sftp.close(&from).await;
    if copied.is_err() {
        let _ = sftp.close(&to).await;
        let _ = sftp.remove(&temp).await;
    }
    copied
}

/// Where a file named `name` goes here, for the destination `dest`.
pub(super) fn local_target(dest: &str, name: &str, many: bool) -> Result<PathBuf, Failed> {
    let path = PathBuf::from(dest);
    if path.is_dir() {
        return Ok(path.join(name));
    }
    if many {
        return Err(failed(Fault::CantCreate, format!("{dest} is not a directory, and there are several sources")));
    }
    Ok(path)
}

/// A new local file, readable by its owner only.
pub(super) fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// The server's permission bits on the local copy, where the system has
/// them.
pub(super) fn set_local_mode(path: &Path, permissions: Option<u32>) {
    #[cfg(unix)]
    if let Some(bits) = permissions {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits & 0o777));
    }
    #[cfg(not(unix))]
    let _ = (path, permissions);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remote_path_splits_at_its_last_slash() {
        assert_eq!(split_remote("/srv/a/b.txt"), ("/srv/a/", "b.txt"));
        assert_eq!(split_remote("b.txt"), ("", "b.txt"));
        assert_eq!(split_remote("dir/"), ("dir/", ""));
    }

    #[test]
    fn a_temporary_name_is_hidden_and_unique() {
        let (a, b) = (temp_name("x.bin"), temp_name("x.bin"));
        assert!(a.starts_with(".x.bin.podssh-") && a.ends_with(".part"), "{a}");
        assert_ne!(a, b);
    }

    #[test]
    fn a_status_names_its_side_and_the_rest_is_the_session() {
        let missing = SftpError::Status { what: "stat a".into(), code: 2, message: String::new() };
        assert_eq!(from_sftp(missing.clone(), Side::Source).fault, Fault::NoInput);
        assert_eq!(from_sftp(missing, Side::Destination).fault, Fault::CantCreate);
        assert_eq!(from_sftp(SftpError::Closed("gone".into()), Side::Source).fault, Fault::SessionFault);
        assert_eq!(from_sftp(SftpError::NoSftp, Side::Destination).fault, Fault::RelayUnreachable);
    }
}
