//! The SFTP road's copy of one file, up or down, and its continuation after a
//! broken connection (T-136): the temporary file stays, and the next attempt
//! writes on at the offset below which each byte is in it. The digest covers
//! the whole file, the bytes of each attempt.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use podssh_ssh::sftp::{FileAttributes, OpenFlags, Sftp};
use podssh_ssh::{Connection, Log};
use sha2::{Digest, Sha256};

use super::digest::{self, Sum};
use super::resume::{self, Progress};
use super::transfer::{self, Cause, Done, Failed, Side};
use crate::exitmap::Fault;

fn failed(fault: Fault, message: String) -> Failed {
    Failed::new(fault, message)
}

/// Copy the local file `source` to `dest` on the server, or write on in the
/// copy that `progress` holds.
pub async fn up(
    sftp: &Sftp,
    handle: &Connection,
    source: &str,
    dest: &str,
    many: bool,
    log: &Log,
    progress: &mut Progress,
) -> Result<Done, Failed> {
    let local = Path::new(source);
    let before = std::fs::metadata(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
    if !before.is_file() {
        return Err(failed(Fault::NoInput, format!("{source}: not a regular file; podssh cp copies files")));
    }
    let name = local.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        failed(Fault::NoInput, format!("{source}: the name is not UTF-8, and SFTP names are text here"))
    })?;
    let target = match &progress.target {
        Some(target) => target.clone(),
        None => transfer::remote_target(sftp, dest, name, many).await?,
    };
    // Write on in the temporary file when it holds the bytes below the offset.
    let mut kept = None;
    if let Some(temp) = progress.temp.clone() {
        let fits = progress.offset <= before.len()
            && sftp.stat(&temp).await.is_ok_and(|a| a.size.unwrap_or(0) >= progress.offset);
        if fits {
            kept = sftp.open_file(&temp, OpenFlags::WRITE, FileAttributes::default()).await.ok().map(|f| (temp, f));
        } else {
            let _ = sftp.remove(&temp).await;
        }
    }
    let (temp, file) = match kept {
        Some((temp, file)) => {
            log.verbose(&format!("{source}: continuing {temp} at byte {}", progress.offset));
            (temp, file)
        }
        None => {
            let (dir, leaf) = transfer::split_remote(&target);
            let temp = format!("{dir}{}", transfer::temp_name(leaf));
            let attrs = FileAttributes { permissions: Some(0o600), ..FileAttributes::default() };
            let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE;
            let file =
                sftp.open_file(&temp, flags, attrs).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
            progress.begin(&target, &temp);
            log.verbose(&format!("{source}: writing {temp}"));
            (temp, file)
        }
    };
    let copied = async {
        let mut reader = std::fs::File::open(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        let mut hasher = Sha256::new();
        // The bytes that an earlier attempt sent are in the digest too.
        resume::hash_prefix(&mut reader, &mut hasher, progress.offset)
            .map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        let mut offset = progress.offset;
        let mut buf = vec![0u8; sftp.write_len() as usize];
        loop {
            let n = reader.read(&mut buf).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            sftp.write(&file, offset, &buf[..n]).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
            offset += n as u64;
            progress.advance(offset);
        }
        sftp.fsync(&file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        sftp.close(&file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        let after = std::fs::metadata(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        if after.len() != before.len() || after.modified().ok() != before.modified().ok() || after.len() != offset {
            return Err(failed(Fault::NoInput, format!("{source}: the file changed while it was read")));
        }
        let sum: Sum = hasher.finalize().into();
        let (far, how) = transfer::far_digest(handle, sftp, &temp, offset, Side::Destination).await?;
        transfer::compare(&sum, &far, &how, source)?;
        let mode = FileAttributes { permissions: Some(transfer::local_mode(&before)), ..FileAttributes::default() };
        sftp.setstat(&temp, mode).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        let not_atomic = transfer::rename_onto(sftp, &temp, &target, log).await?;
        Ok(Done {
            source: source.into(),
            destination: target.clone(),
            bytes: offset,
            sum: Some(sum),
            verified_by: how,
            not_atomic,
            removed: None,
        })
    }
    .await;
    match &copied {
        // The next connection writes on in it.
        Err(f) if f.cause == Cause::Broke => progress.save(),
        Err(_) => {
            let _ = sftp.close(&file).await;
            let _ = sftp.remove(&temp).await;
            progress.clear();
        }
        Ok(_) => progress.clear(),
    }
    copied
}

/// Copy `source` on the server to the local `dest`, or write on in the copy
/// that `progress` holds.
pub async fn down(
    sftp: &Sftp,
    handle: &Connection,
    source: &str,
    dest: &str,
    many: bool,
    log: &Log,
    progress: &mut Progress,
) -> Result<Done, Failed> {
    let attrs = sftp.stat(source).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
    if !attrs.is_regular() {
        return Err(failed(Fault::NoInput, format!("{source}: not a regular file; podssh cp copies files")));
    }
    let (_, name) = transfer::split_remote(source.trim_end_matches('/'));
    if name.is_empty() || name == "." || name == ".." {
        return Err(failed(Fault::NoInput, format!("{source}: names no file")));
    }
    let target = match &progress.target {
        Some(target) => PathBuf::from(target),
        None => transfer::local_target(dest, name, many)?,
    };
    let (temp, file, start) = resume::local_temp(&target, attrs.size.unwrap_or(0), progress)?;
    let shown = temp.display().to_string();
    log.verbose(&match start {
        0 => format!("{source}: writing {shown}"),
        n => format!("{source}: continuing {shown} at byte {n}"),
    });
    // An Option, so that the file is closed before it is read back and
    // renamed: Windows renames no open file.
    let mut out = Some(file);
    let copied: Result<Done, Failed> = async {
        let mut hasher = Sha256::new();
        if let Some(f) = out.as_mut() {
            resume::hash_prefix(f, &mut hasher, start)
                .map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
        }
        let file = sftp
            .open_file(source, OpenFlags::READ, FileAttributes::default())
            .await
            .map_err(|e| transfer::from_sftp(e, Side::Source))?;
        let mut offset = start;
        let read = loop {
            match sftp.read(&file, offset, sftp.read_len()).await {
                Ok(Some(data)) if !data.is_empty() => {
                    hasher.update(&data);
                    if let Err(e) = out.as_mut().map_or(Ok(()), |f| f.write_all(&data)) {
                        break Err(failed(Fault::CantCreate, format!("{shown}: {e}")));
                    }
                    offset += data.len() as u64;
                    progress.advance(offset);
                }
                Ok(_) => break Ok(()),
                Err(e) => break Err(transfer::from_sftp(e, Side::Source)),
            }
        };
        let _ = sftp.close(&file).await;
        read?;
        if let Some(f) = out.take() {
            f.sync_all().map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
        }
        let sum: Sum = hasher.finalize().into();
        let on_disk = digest::of_file(&temp).map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
        transfer::compare(&sum, &on_disk, "this disk", &shown)?;
        let (far, how) = transfer::far_digest(handle, sftp, source, offset, Side::Source).await?;
        transfer::compare(&sum, &far, &how, source)?;
        transfer::set_local_mode(&temp, attrs.permissions);
        std::fs::rename(&temp, &target).map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", target.display())))?;
        Ok(Done {
            source: source.into(),
            destination: target.display().to_string(),
            bytes: offset,
            sum: Some(sum),
            verified_by: how,
            not_atomic: false,
            removed: None,
        })
    }
    .await;
    drop(out);
    match &copied {
        Err(f) if f.cause == Cause::Broke => progress.save(),
        Err(_) => {
            let _ = std::fs::remove_file(&temp);
            progress.clear();
        }
        Ok(_) => progress.clear(),
    }
    copied
}
