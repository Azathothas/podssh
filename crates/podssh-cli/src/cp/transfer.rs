//! One file up or down: a temporary name beside the destination, the digests
//! compared, then a rename onto the destination.
//!
//! **The destination's name never holds a file that was not verified.** The
//! bytes go to `.NAME.podssh-RANDOM.part` in the destination's directory,
//! created anew with mode 0600; after the digests agree, the file gets the
//! source's permission bits and is renamed onto the destination, at once
//! where the server has `posix-rename@openssh.com`. A failure removes the
//! temporary file.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use podssh_ssh::sftp::{FileAttributes, OpenFlags, Sftp, SftpError};
use podssh_ssh::{Connection, Log};
use sha2::{Digest, Sha256};

use super::digest::{self, Sum};
use crate::exitmap::Fault;

/// One file copied and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub source: String,
    pub destination: String,
    pub bytes: u64,
    pub sum: Sum,
    /// How the far digest was taken: a tool's name, or "read again".
    pub verified_by: String,
    /// An existing destination was removed before the rename: the server has
    /// no `posix-rename@openssh.com`.
    pub not_atomic: bool,
}

/// A failure, and the fault that sets the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub fault: Fault,
    pub message: String,
}

fn failed(fault: Fault, message: String) -> Failed {
    Failed { fault, message }
}

/// Which side a failure is on: a source that cannot be read, or a
/// destination that cannot be written.
#[derive(Clone, Copy)]
enum Side {
    Source,
    Destination,
}

/// The failure of an SFTP step: a status on a path names the side; a step
/// with no answer, or a session that broke, is a fault of the session.
fn from_sftp(e: SftpError, side: Side) -> Failed {
    let fault = match (&e, side) {
        (SftpError::Status { .. }, Side::Source) => Fault::NoInput,
        (SftpError::Status { .. }, Side::Destination) => Fault::CantCreate,
        (SftpError::NoSftp, _) => Fault::RelayUnreachable,
        _ => Fault::SessionFault,
    };
    failed(fault, e.to_string())
}

/// `.NAME.podssh-RANDOM.part`: hidden, unique, and named for what it holds.
pub(super) fn temp_name(name: &str) -> String {
    format!(".{name}.podssh-{:016x}.part", rand::random::<u64>())
}

/// The far digest: by a command when the server can, else by a second read.
async fn far_digest(
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
    Err(failed(
        Fault::SessionFault,
        format!(
            "{what}: the digests differ: SHA-256 {} sent, {} on the far side ({how}); the destination was not changed",
            digest::hex(sent),
            digest::hex(far)
        ),
    ))
}

/// Where a file named `name` goes on the server, for the destination
/// `dest`: into it when it is a directory (or is empty, the login
/// directory), else onto it.
async fn remote_target(sftp: &Sftp, dest: &str, name: &str, many: bool) -> Result<String, Failed> {
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

/// Copy the local file `source` to `dest` on the server.
pub async fn up(
    sftp: &Sftp,
    handle: &Connection,
    source: &str,
    dest: &str,
    many: bool,
    log: &Log,
) -> Result<Done, Failed> {
    let local = Path::new(source);
    let before = std::fs::metadata(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
    if !before.is_file() {
        return Err(failed(Fault::NoInput, format!("{source}: not a regular file; podssh cp copies files")));
    }
    let name = local.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        failed(Fault::NoInput, format!("{source}: the name is not UTF-8, and SFTP names are text here"))
    })?;
    let target = remote_target(sftp, dest, name, many).await?;
    let (dir, leaf) = split_remote(&target);
    let temp = format!("{dir}{}", temp_name(leaf));
    let attrs = FileAttributes { permissions: Some(0o600), ..FileAttributes::default() };
    let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE;
    let file = sftp.open_file(&temp, flags, attrs).await.map_err(|e| from_sftp(e, Side::Destination))?;
    log.verbose(&format!("{source}: writing {temp}"));
    let copied = async {
        let mut reader = std::fs::File::open(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; sftp.write_len() as usize];
        let mut offset = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            sftp.write(&file, offset, &buf[..n]).await.map_err(|e| from_sftp(e, Side::Destination))?;
            offset += n as u64;
        }
        sftp.fsync(&file).await.map_err(|e| from_sftp(e, Side::Destination))?;
        sftp.close(&file).await.map_err(|e| from_sftp(e, Side::Destination))?;
        let after = std::fs::metadata(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        if after.len() != before.len() || after.modified().ok() != before.modified().ok() || after.len() != offset {
            return Err(failed(Fault::NoInput, format!("{source}: the file changed while it was read")));
        }
        let sum: Sum = hasher.finalize().into();
        let (far, how) = far_digest(handle, sftp, &temp, offset, Side::Destination).await?;
        compare(&sum, &far, &how, source)?;
        let mode = FileAttributes { permissions: Some(local_mode(&before)), ..FileAttributes::default() };
        sftp.setstat(&temp, mode).await.map_err(|e| from_sftp(e, Side::Destination))?;
        let not_atomic = rename_onto(sftp, &temp, &target, log).await?;
        Ok(Done {
            source: source.into(),
            destination: target.clone(),
            bytes: offset,
            sum,
            verified_by: how,
            not_atomic,
        })
    }
    .await;
    if copied.is_err() {
        let _ = sftp.close(&file).await;
        let _ = sftp.remove(&temp).await;
    }
    copied
}

/// Rename the verified file onto its name. Without
/// `posix-rename@openssh.com` the rename of version 3 refuses an existing
/// name: it is removed first, which is said. Whether it was.
async fn rename_onto(sftp: &Sftp, temp: &str, target: &str, log: &Log) -> Result<bool, Failed> {
    let first = match sftp.rename(temp, target).await {
        Ok(()) => return Ok(false),
        Err(e) => e,
    };
    if sftp.has("posix-rename@openssh.com") || sftp.stat(target).await.is_err() {
        return Err(from_sftp(first, Side::Destination));
    }
    log.info(&format!(
        "{target}: the server has no posix-rename, so the old file is removed first; the replace is not atomic"
    ));
    sftp.remove(target).await.map_err(|e| from_sftp(e, Side::Destination))?;
    sftp.rename(temp, target).await.map_err(|e| from_sftp(e, Side::Destination))?;
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
        Ok(Done { source: source.into(), destination: target.clone(), bytes: size, sum, verified_by: how, not_atomic })
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

/// Copy `source` on the server to the local `dest`.
pub async fn down(
    sftp: &Sftp,
    handle: &Connection,
    source: &str,
    dest: &str,
    many: bool,
    log: &Log,
) -> Result<Done, Failed> {
    let attrs = sftp.stat(source).await.map_err(|e| from_sftp(e, Side::Source))?;
    if !attrs.is_regular() {
        return Err(failed(Fault::NoInput, format!("{source}: not a regular file; podssh cp copies files")));
    }
    let (_, name) = split_remote(source.trim_end_matches('/'));
    if name.is_empty() || name == "." || name == ".." {
        return Err(failed(Fault::NoInput, format!("{source}: names no file")));
    }
    let target = local_target(dest, name, many)?;
    let leaf = target.file_name().and_then(|n| n.to_str()).unwrap_or(name).to_string();
    let temp = target.with_file_name(temp_name(&leaf));
    // An Option, so that the file is closed before it is read back and
    // renamed: Windows renames no open file.
    let mut out =
        Some(create_private(&temp).map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", temp.display())))?);
    log.verbose(&format!("{source}: writing {}", temp.display()));
    let copied = async {
        let file = sftp
            .open_file(source, OpenFlags::READ, FileAttributes::default())
            .await
            .map_err(|e| from_sftp(e, Side::Source))?;
        let mut hasher = Sha256::new();
        let mut offset = 0u64;
        let read = loop {
            match sftp.read(&file, offset, sftp.read_len()).await {
                Ok(Some(data)) if !data.is_empty() => {
                    hasher.update(&data);
                    if let Err(e) = out.as_mut().map_or(Ok(()), |f| f.write_all(&data)) {
                        break Err(failed(Fault::CantCreate, format!("{}: {e}", temp.display())));
                    }
                    offset += data.len() as u64;
                }
                Ok(_) => break Ok(()),
                Err(e) => break Err(from_sftp(e, Side::Source)),
            }
        };
        let _ = sftp.close(&file).await;
        read?;
        if let Some(f) = out.take() {
            f.sync_all().map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", temp.display())))?;
        }
        let sum: Sum = hasher.finalize().into();
        let on_disk =
            digest::of_file(&temp).map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", temp.display())))?;
        compare(&sum, &on_disk, "this disk", &temp.display().to_string())?;
        let (far, how) = far_digest(handle, sftp, source, offset, Side::Source).await?;
        compare(&sum, &far, &how, source)?;
        set_local_mode(&temp, attrs.permissions);
        std::fs::rename(&temp, &target).map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", target.display())))?;
        Ok(Done {
            source: source.into(),
            destination: target.display().to_string(),
            bytes: offset,
            sum,
            verified_by: how,
            not_atomic: false,
        })
    }
    .await;
    if copied.is_err() {
        drop(out);
        let _ = std::fs::remove_file(&temp);
    }
    copied
}

/// The server's permission bits on the local copy, where the system has
/// them.
fn set_local_mode(path: &Path, permissions: Option<u32>) {
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
