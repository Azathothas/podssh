//! The end of a copy up over SFTP: the temporary file synced and closed,
//! its size set after holes, the source unchanged, the digests equal, what
//! the copy keeps set, and the rename. The far digest's command starts
//! beside the sync and the close (T-417).

use std::path::Path;

use podssh_ssh::sftp::{FileAttributes, FileHandle, Sftp};
use podssh_ssh::{Connection, Log};

use super::digest::Sum;
use super::meta::{self, Keep, Stamp};
use super::transfer::{self, Done, Failed, Side};
use crate::exitmap::Fault;

/// How a copy up ended: its bytes, their digest, what it keeps, whether it
/// left holes, and whether it wrote into the destination itself.
pub(super) struct Ends {
    pub(super) offset: u64,
    pub(super) sum: Sum,
    pub(super) keep: Keep,
    pub(super) holes: bool,
    pub(super) inplace: bool,
    /// The far file's mode that `podssh edit` keeps (T-149).
    pub(super) mode: Option<u32>,
}

/// The end of a copy up: the temporary file synced and closed, its size set
/// after holes, the source unchanged, the digests equal, what the copy keeps
/// set, and the rename.
#[allow(clippy::too_many_arguments)]
pub(super) async fn finish_up(
    sftp: &Sftp,
    handle: &Connection,
    file: &FileHandle,
    local: &Path,
    source: &str,
    temp: &str,
    target: &str,
    before: &std::fs::Metadata,
    ends: Ends,
    log: &Log,
) -> Result<Done, Failed> {
    let Ends { offset, sum, keep, holes, inplace, mode } = ends;
    {
        let synced = async {
            sftp.fsync(file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
            sftp.close(file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))
        };
        // The server acknowledged each write, so the far digest's command
        // reads the bytes as they stay, and starts beside the sync and the
        // close: their round trips overlap its own (T-417). After holes, and
        // into the destination itself, the size is set first, and it waits.
        let early = async {
            match holes || inplace {
                true => None,
                false => Some(transfer::far_digest(handle, sftp, temp, offset, Side::Destination).await),
            }
        };
        let (synced, early) = tokio::join!(synced, early);
        synced?;
        // After holes, and into the destination itself, whose old bytes past
        // the new end go (T-147).
        if holes || inplace {
            let size = FileAttributes { size: Some(offset), ..FileAttributes::default() };
            sftp.setstat(temp, size).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        }
        let after = std::fs::metadata(local).map_err(|e| Failed::new(Fault::NoInput, format!("{source}: {e}")))?;
        if after.len() != before.len() || after.modified().ok() != before.modified().ok() || after.len() != offset {
            return Err(transfer::changed(source));
        }
        let (far, how) = match early {
            Some(far) => far?,
            None => transfer::far_digest(handle, sftp, temp, offset, Side::Destination).await?,
        };
        transfer::compare(&sum, &far, &how, source)?;
        // The source's mode, or the far file's that `podssh edit` keeps.
        let mut stamp = Stamp::of_local(before);
        stamp.mode = mode.or(stamp.mode);
        meta::set_far(sftp, temp, &stamp, keep, log).await?;
        let mut not_atomic = false;
        if !inplace {
            not_atomic = transfer::rename_onto(sftp, temp, target, log).await?;
            meta::times_after_rename(sftp, target, &stamp, keep).await;
        }
        Ok(Done {
            source: source.into(),
            destination: target.to_string(),
            bytes: offset,
            sum: Some(sum),
            verified_by: how,
            not_atomic,
            removed: None,
        })
    }
}
