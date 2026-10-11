//! A lock on a `known_hosts` file that only other writers see (T-029): on
//! Unix an advisory `flock`, which no reader meets; on Windows one byte far
//! past any end of the file, as a lock of the file's own bytes would refuse
//! each reader meanwhile, OpenSSH's among them.

use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

/// How long a writer waits for another one to finish: a read and one line.
pub const WAIT: Duration = Duration::from_secs(5);

/// The lock, until it is dropped.
pub struct Held<'a>(&'a File);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        unlock(self.0);
    }
}

/// Hold a lock on `file`: `None` when its file system takes no locks, so the
/// caller writes without one and says so, and an error when another writer
/// kept it for `wait`. Never a wait without a limit.
pub fn hold(file: &File, wait: Duration) -> std::io::Result<Option<Held<'_>>> {
    let deadline = Instant::now() + wait;
    loop {
        match try_once(file) {
            Ok(true) => return Ok(Some(Held(file))),
            Ok(false) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(false) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("another writer held its lock for {} s", wait.as_secs()),
                ))
            }
            Err(_) => return Ok(None),
        }
    }
}

/// One try: held, or held by another writer.
#[cfg(not(windows))]
fn try_once(file: &File) -> std::io::Result<bool> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

#[cfg(not(windows))]
fn unlock(file: &File) {
    let _ = file.unlock();
}

/// The byte that the lock covers, far past any end of a file.
#[cfg(windows)]
fn far_byte() -> windows_sys::Win32::System::IO::OVERLAPPED {
    // SAFETY: an OVERLAPPED of zeros is valid; only its offset is set.
    let mut at: windows_sys::Win32::System::IO::OVERLAPPED = unsafe { std::mem::zeroed() };
    at.Anonymous.Anonymous.Offset = u32::MAX - 1;
    at.Anonymous.Anonymous.OffsetHigh = u32::MAX;
    at
}

#[cfg(windows)]
fn try_once(file: &File) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_LOCK_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};
    let mut at = far_byte();
    // SAFETY: the handle is open while `file` lives, and `at` outlives the
    // call, which returns at once instead of waiting.
    let ok = unsafe {
        LockFileEx(file.as_raw_handle(), LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &mut at)
    };
    if ok != 0 {
        return Ok(true);
    }
    // SAFETY: GetLastError has no preconditions.
    match unsafe { GetLastError() } {
        ERROR_LOCK_VIOLATION => Ok(false),
        error => Err(std::io::Error::from_raw_os_error(error as i32)),
    }
}

#[cfg(windows)]
fn unlock(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    let mut at = far_byte();
    // SAFETY: as in `try_once`; Windows asks for each lock to be undone
    // before the handle closes.
    unsafe { UnlockFileEx(file.as_raw_handle(), 0, 1, 0, &mut at) };
}

/// Whether `file` is the file that `path` names now: a writer that waited
/// for the lock while a rewrite put another file in its place holds the
/// old one (T-019).
#[cfg(unix)]
pub fn same_file(file: &File, path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let now = match std::fs::metadata(path) {
        Ok(now) => now,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let held = file.metadata()?;
    Ok(held.dev() == now.dev() && held.ino() == now.ino())
}

#[cfg(windows)]
pub fn same_file(file: &File, path: &Path) -> std::io::Result<bool> {
    let now = match File::open(path) {
        Ok(now) => now,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    Ok(file_id(file)? == file_id(&now)?)
}

/// The volume and the index of an open file, which no other file shares.
#[cfg(windows)]
fn file_id(file: &File) -> std::io::Result<(u32, u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    // SAFETY: zeros are a valid BY_HANDLE_FILE_INFORMATION, which the call
    // fills.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open while `file` lives, and `info` outlives the
    // call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow))
}

#[cfg(not(any(unix, windows)))]
pub fn same_file(_: &File, _: &Path) -> std::io::Result<bool> {
    Ok(true)
}
