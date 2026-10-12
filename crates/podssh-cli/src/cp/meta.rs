//! What a copy keeps of a file besides its bytes (T-146): the permission
//! bits always (T-134); with `-p` the access and the modification times;
//! with `--owner` the owner and the group, by number; the holes of a sparse
//! file; and, within one `-r` upload, two names of one file as one file with
//! two names. Each is set on the temporary file before its rename, so the
//! destination's name gets the file whole, or keeps what it had.
//!
//! SFTP version 3 carries a time in whole seconds, from 1970 to 2106, and no
//! inode, extended attribute or ACL: those are not kept. What a side cannot
//! keep at all (an owner on Windows, or given away by a user who is not
//! root; a time out of that range; a far side with no tool for it) is said
//! once in a run, and the copy goes on; a side that refuses the mode or the
//! times fails the copy.

use std::collections::BTreeSet;
use std::fs::{File, Metadata};
use std::io::{Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_ssh::sftp::{FileAttributes, Sftp, SftpError};
use podssh_ssh::Log;

use super::transfer::{self, Failed, Side};
use crate::exitmap::Fault;

/// A block of a sparse file: one that is all zero, aligned in the file, is a
/// hole.
pub const HOLE: u64 = 64 * 1024;

/// `SSH_FX_PERMISSION_DENIED`.
const PERMISSION_DENIED: u32 = 3;

/// What a copy keeps besides the bytes and the permission bits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Keep {
    /// `-p`: the access and the modification times.
    pub times: bool,
    /// `--owner`: the owner and the group, by number.
    pub owner: bool,
    /// `--sparse`: a hole for each block of zeros, whatever the source;
    /// without it only a copy up of a sparse file makes holes.
    pub sparse: bool,
}

/// What a file or a directory has besides its bytes, as a copy keeps it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stamp {
    pub mode: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

/// A time as SFTP version 3 carries it: whole seconds since 1970, which a
/// `u32` holds until 2106.
pub fn seconds(time: SystemTime) -> Option<u32> {
    time.duration_since(UNIX_EPOCH).ok().and_then(|d| u32::try_from(d.as_secs()).ok())
}

impl Stamp {
    /// A local file's or directory's, with the permission bits that a copy
    /// gives it.
    pub fn of_local(meta: &Metadata) -> Stamp {
        #[cfg(unix)]
        let (uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (Some(meta.uid()), Some(meta.gid()))
        };
        #[cfg(not(unix))]
        let (uid, gid) = (None, None);
        Stamp {
            mode: Some(transfer::local_mode(meta)),
            atime: meta.accessed().ok().and_then(seconds),
            mtime: meta.modified().ok().and_then(seconds),
            uid,
            gid,
        }
    }

    /// What a server told of a file, its permission bits within `mask`.
    pub fn of_far(attrs: &FileAttributes, mask: u32) -> Stamp {
        Stamp {
            mode: attrs.permissions.map(|p| p & mask),
            atime: attrs.atime,
            mtime: attrs.mtime,
            uid: attrs.uid,
            gid: attrs.gid,
        }
    }
}

static SAID: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());

/// Say `text` the first time that `key` comes in the run.
pub(crate) fn note(log: &Log, key: &'static str, text: &str) {
    if SAID.lock().map(|mut said| said.insert(key)).unwrap_or(true) {
        log.info(text);
    }
}

/// What a copy asks a server to set on a file, as `keep` says: the owner
/// first, on its own (none when it is not asked for, or the stamp has none),
/// then the permission bits and, with `-p`, the times.
pub fn plan(stamp: &Stamp, keep: Keep) -> (Option<FileAttributes>, FileAttributes) {
    let owner = match (keep.owner, stamp.uid, stamp.gid) {
        (true, Some(uid), Some(gid)) => {
            Some(FileAttributes { uid: Some(uid), gid: Some(gid), ..FileAttributes::default() })
        }
        _ => None,
    };
    let mut rest = FileAttributes { permissions: stamp.mode, ..FileAttributes::default() };
    if let (true, Some(atime), Some(mtime)) = (keep.times, stamp.atime, stamp.mtime) {
        (rest.atime, rest.mtime) = (Some(atime), Some(mtime));
    }
    (owner, rest)
}

/// Set on the far `path` what `keep` asks of `stamp`, and the permission
/// bits: the owner first, while the writer may still change the rest.
pub async fn set_far(sftp: &Sftp, path: &str, stamp: &Stamp, keep: Keep, log: &Log) -> Result<(), Failed> {
    let (owner, rest) = plan(stamp, keep);
    if keep.owner && owner.is_none() {
        note(log, "owner-none", &format!("{path}: the owner was not kept: this system has no owner by number"));
    }
    if keep.times && rest.mtime.is_none() {
        note(log, "times-range", &format!("{path}: the times were not kept: SFTP carries 1970 to 2106 only"));
    }
    if let Some(owner) = owner {
        match sftp.setstat(path, owner).await {
            Ok(()) => {}
            Err(SftpError::Status { code: PERMISSION_DENIED, .. }) => {
                note(log, "owner-far", &format!("{path}: the owner was not kept: only root may give a file away"));
            }
            Err(e) => return Err(transfer::from_sftp(e, Side::Destination)),
        }
    }
    if rest.permissions.is_none() && rest.mtime.is_none() {
        return Ok(());
    }
    sftp.setstat(path, rest).await.map_err(|e| transfer::from_sftp(e, Side::Destination))
}

/// After the rename onto `path`, with `-p`: a server whose rename changes the
/// times gets them once more. Cygwin's rename sets the access time (measured
/// with the `sftp-server` of Git for Windows, 2026-10-12); one stat, and a
/// second setstat only when they differ.
pub async fn times_after_rename(sftp: &Sftp, path: &str, stamp: &Stamp, keep: Keep) {
    let (true, Some(atime), Some(mtime)) = (keep.times, stamp.atime, stamp.mtime) else { return };
    if let Ok(now) = sftp.stat(path).await {
        if (now.atime, now.mtime) != (Some(atime), Some(mtime)) {
            let times = FileAttributes { atime: Some(atime), mtime: Some(mtime), ..FileAttributes::default() };
            let _ = sftp.setstat(path, times).await;
        }
    }
}

/// Set on the local `path` what `keep` asks of `stamp`, and the permission
/// bits: the owner, the times, then the bits, which may take away the right
/// to write.
pub fn set_local(path: &Path, stamp: &Stamp, keep: Keep, log: &Log) -> Result<(), Failed> {
    if keep.owner {
        own_local(path, stamp, log);
    }
    if keep.times {
        match (stamp.atime, stamp.mtime) {
            (Some(atime), Some(mtime)) => {
                let at = |s: u32| UNIX_EPOCH + Duration::from_secs(u64::from(s));
                let times = std::fs::FileTimes::new().set_accessed(at(atime)).set_modified(at(mtime));
                open_for_times(path).and_then(|file| file.set_times(times)).map_err(|e| {
                    Failed::new(Fault::CantCreate, format!("{}: the times were not set: {e}", path.display()))
                })?;
            }
            _ => note(log, "times-none", &format!("{}: the times were not kept: the server gave none", path.display())),
        }
    }
    #[cfg(unix)]
    if let Some(mode) = stamp.mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
    }
    Ok(())
}

#[cfg(unix)]
fn open_for_times(path: &Path) -> std::io::Result<File> {
    // The owner sets a file's times with no right to write it.
    File::open(path)
}

#[cfg(windows)]
fn open_for_times(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_WRITE_ATTRIBUTES; FILE_FLAG_BACKUP_SEMANTICS opens a directory too.
    std::fs::OpenOptions::new().access_mode(0x100).custom_flags(0x0200_0000).open(path)
}

fn own_local(path: &Path, stamp: &Stamp, log: &Log) {
    #[cfg(unix)]
    match (stamp.uid, stamp.gid) {
        (Some(uid), Some(gid)) => {
            if let Err(e) = std::os::unix::fs::chown(path, Some(uid), Some(gid)) {
                let why = format!("{}: the owner was not kept: {e}; only root gives a file away", path.display());
                note(log, "owner-here", &why);
            }
        }
        _ => note(log, "owner-gone", &format!("{}: the owner was not kept: the server gave none", path.display())),
    }
    #[cfg(not(unix))]
    {
        let _ = stamp;
        let why = format!("{}: the owner was not kept: this system has no owner by number", path.display());
        note(log, "owner-none", &why);
    }
}

/// Whether a local file has holes: fewer blocks than its size needs (Unix),
/// or the sparse attribute (Windows).
pub fn is_sparse(meta: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.blocks().saturating_mul(512) < meta.len()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_SPARSE_FILE.
        meta.file_attributes() & 0x200 != 0
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = meta;
        false
    }
}

fn is_zero(block: &[u8]) -> bool {
    // Words of 64 bytes, each folded with no early exit, which compiles to
    // vector instructions.
    block.chunks(64).all(|word| word.iter().fold(0u8, |acc, b| acc | b) == 0)
}

/// The runs of `data`, which starts at `offset` in its file: holes (`true`),
/// whole blocks of [`HOLE`] bytes aligned in the file and all zero, or data;
/// two runs side by side are of two kinds. With `holes` false, one run of
/// data.
pub fn runs(offset: u64, data: &[u8], holes: bool) -> Vec<(bool, Range<usize>)> {
    if !holes {
        return if data.is_empty() { Vec::new() } else { vec![(false, 0..data.len())] };
    }
    let mut out: Vec<(bool, Range<usize>)> = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        let from = offset + at as u64;
        let end = (at + (HOLE - from % HOLE) as usize).min(data.len());
        let hole = from.is_multiple_of(HOLE) && (end - at) as u64 == HOLE && is_zero(&data[at..end]);
        match out.last_mut() {
            Some((kind, range)) if *kind == hole => range.end = end,
            _ => out.push((hole, at..end)),
        }
        at = end;
    }
    out
}

/// A local file written front to back with holes: each block of [`HOLE`]
/// bytes, aligned in the file, that is all zero is passed over; `finish`
/// sets the size, so that a hole at the end counts.
#[derive(Debug, Default)]
pub struct Holes {
    /// The offset of `pending`'s first byte: each byte before it is written
    /// or passed over.
    at: u64,
    /// The bytes of a block that has not come whole.
    pending: Vec<u8>,
}

impl Holes {
    /// A file whose first `at` bytes are there.
    pub fn new(at: u64) -> Holes {
        Holes { at, pending: Vec::new() }
    }

    /// The end of the part that is written or passed over.
    pub fn done(&self) -> u64 {
        self.at
    }

    /// `data`, after what came before: each whole block written or passed
    /// over, and the rest held.
    pub fn write(&mut self, file: &mut File, data: &[u8]) -> std::io::Result<()> {
        self.pending.extend_from_slice(data);
        let end = self.at + self.pending.len() as u64;
        let whole = (end - end % HOLE).saturating_sub(self.at) as usize;
        self.flush(file, whole)
    }

    fn flush(&mut self, file: &mut File, n: usize) -> std::io::Result<()> {
        for (hole, range) in runs(self.at, &self.pending[..n], true) {
            if hole {
                file.seek(SeekFrom::Current(range.len() as i64))?;
            } else {
                file.write_all(&self.pending[range])?;
            }
        }
        self.pending.drain(..n);
        self.at += n as u64;
        Ok(())
    }

    /// What is held, then the size: the end of the part done.
    pub fn finish(&mut self, file: &mut File) -> std::io::Result<()> {
        self.flush(file, self.pending.len())?;
        file.set_len(self.at)
    }
}

/// The device and the inode of the local file `path` when it has more than
/// one name: the key of its hard links in one `-r` upload. On Windows, the
/// volume's serial number and the file's index.
pub fn inode(path: &Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).ok()?;
        (meta.nlink() > 1).then(|| (meta.dev(), meta.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
        let file = File::open(path).ok()?;
        // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is valid (numbers
        // only); the handle is open while `file` lives, and the function
        // writes one such structure.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let done = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
        let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        (done != 0 && info.nNumberOfLinks > 1).then(|| (u64::from(info.dwVolumeSerialNumber), index))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        None
    }
}

/// `target` on the server as a second name of the far file `first`, by
/// `hardlink@openssh.com`: a temporary name, then the rename onto `target`.
/// `false` when the server has no such extension, for a copy instead.
pub async fn hard_link(sftp: &Sftp, first: &str, target: &str, log: &Log) -> Result<bool, Failed> {
    if !sftp.has("hardlink@openssh.com") {
        note(log, "hardlink", "the server has no hardlink@openssh.com: each name of a file is copied as a file");
        return Ok(false);
    }
    let (dir, leaf) = transfer::split_remote(target);
    let temp = format!("{dir}{}", transfer::temp_name(leaf));
    sftp.hardlink(first, &temp).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
    let renamed = transfer::rename_onto(sftp, &temp, target, log).await;
    // A rename between two names of one file does nothing and says so: the
    // temporary name then stays, and goes here.
    let _ = sftp.remove(&temp).await;
    renamed.map(|_| true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_fits_sftp_from_1970_to_2106() {
        assert_eq!(seconds(UNIX_EPOCH), Some(0));
        assert_eq!(seconds(UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX))), Some(u32::MAX));
        assert_eq!(seconds(UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) + 1)), None);
        assert_eq!(seconds(UNIX_EPOCH - Duration::from_secs(1)), None);
    }

    #[test]
    fn a_hole_is_a_whole_block_of_zeros_aligned_in_the_file() {
        let h = HOLE as usize;
        let mut data = vec![0u8; 3 * h];
        data[h + 5] = 1;
        assert_eq!(runs(0, &data, true), vec![(true, 0..h), (false, h..2 * h), (true, 2 * h..3 * h)]);
        assert_eq!(runs(0, &data, false), vec![(false, 0..3 * h)]);
        // Not aligned: the block across a boundary is data, the whole one a hole.
        let zeros = vec![0u8; 2 * h];
        assert_eq!(
            runs(10, &zeros, true),
            vec![(false, 0..h - 10), (true, h - 10..2 * h - 10), (false, 2 * h - 10..2 * h)]
        );
        // Less than a block: data.
        assert_eq!(runs(0, &zeros[..h - 1], true), vec![(false, 0..h - 1)]);
        assert!(runs(0, &[], true).is_empty());
    }

    #[test]
    fn a_file_written_with_holes_has_each_byte() {
        let dir = std::env::temp_dir().join(format!("podssh-holes-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let h = HOLE as usize;
        let mut want = vec![7u8; 100];
        want.extend(vec![0u8; 3 * h]);
        want.extend(vec![9u8; h + 3]);
        want.extend(vec![0u8; 2 * h]);
        let path = dir.join("f");
        let mut file = File::create(&path).unwrap();
        let mut holes = Holes::new(0);
        // In pieces that cut the blocks anywhere.
        for piece in want.chunks(10_000) {
            holes.write(&mut file, piece).unwrap();
        }
        holes.finish(&mut file).unwrap();
        drop(file);
        assert_eq!(holes.done(), want.len() as u64);
        assert_eq!(std::fs::read(&path).unwrap(), want);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
