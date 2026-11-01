//! The log of a run in the background (T-380, T-397): where it is, how it is
//! cut back past [`LOG_CAP`] with no line lost, and the old files of
//! `detached/`, which nothing else removes, at each start.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The size past which the log is cut back, its last part kept beside it.
pub const LOG_CAP: u64 = 1 << 20;
/// How often a run looks at its log.
const LOOK: Duration = Duration::from_secs(60);
/// A file of `detached/` older than this, of no run that runs, goes at the
/// next start.
pub const OLD: Duration = Duration::from_secs(30 * 86_400);

/// The log of a supervisor's child: the supervisor's own (T-390), when it
/// opens; else `detached/VERB-PID.log` in the first of the cache's
/// directories that can be made private, created with mode 0600; none with
/// `PODSSH_CACHE_DIR=none`.
pub(super) fn log_file(verb: &str) -> Option<(PathBuf, File)> {
    use podssh_relay::cache::{candidate_dirs, private_dir};
    if let Some(path) = std::env::var_os(super::supervise::LOG_VARIABLE).map(PathBuf::from) {
        if let Ok(file) = open_private(&path) {
            return Some((path, file));
        }
    }
    for dir in candidate_dirs() {
        let dir = dir.join(super::lock::DIR);
        if private_dir(&dir).is_err() {
            continue;
        }
        let path = dir.join(format!("{verb}-{}.log", std::process::id()));
        if let Ok(file) = open_private(&path) {
            return Some((path, file));
        }
    }
    None
}

fn open_private(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// The log's watch, once a minute on a thread of its own; `file` is the
/// one that stdout and stderr write. With `rotates`, past [`LOG_CAP`] the
/// log is renamed aside (`.1`) and a new file takes stdout and stderr, so
/// that no line is lost: one written meanwhile goes to `.1`. A run that
/// writes its supervisor's log leaves that to the supervisor, the one
/// writer that cuts it, and takes the new file once the path names another
/// than its own.
pub(super) fn keep(path: PathBuf, file: File, rotates: bool) {
    let _ = std::thread::Builder::new().name("detach-log".into()).spawn(move || {
        let mut file = file;
        loop {
            std::thread::sleep(LOOK);
            if !same_file(&file, &path) {
                // Cut by the supervisor, or removed: the path again.
                if let Ok(new) = open_private(&path) {
                    redirect(&new);
                    file = new;
                }
                continue;
            }
            if rotates && file.metadata().is_ok_and(|m| m.len() > LOG_CAP) {
                file = rotate(&path, file);
            }
        }
    });
}

/// `path` with `.1` after it.
fn aside(path: &Path) -> PathBuf {
    let mut aside = path.as_os_str().to_owned();
    aside.push(".1");
    PathBuf::from(aside)
}

/// The log renamed aside and a new one in its place, which stdout and
/// stderr then write. Where the rename fails (a system that renames no
/// open file), the way of before: a copy aside, then the log cut, which
/// loses the lines written between the two.
fn rotate(path: &Path, file: File) -> File {
    const SAID: &[u8] = b"podssh: the log passed 1 MiB; its earlier part is in .log.1\n";
    match cut(path) {
        Some(Ok(new)) => {
            redirect(&new);
            let _ = (&new).write_all(SAID);
            new
        }
        // With no new file, the old one goes on under its new name, and
        // the next look takes the path again.
        Some(Err(_)) => file,
        None => {
            let _ = std::fs::copy(path, aside(path));
            if file.set_len(0).is_ok() {
                let _ = (&file).write_all(SAID);
            }
            file
        }
    }
}

/// The log renamed aside, and a new file at its path; `None` when the
/// rename failed. A file that wrote the log goes on writing the one aside.
fn cut(path: &Path) -> Option<std::io::Result<File>> {
    std::fs::rename(path, aside(path)).ok()?;
    Some(open_private(path))
}

/// Whether `path` names `file`; true where that cannot be told.
fn same_file(file: &File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (file.metadata(), std::fs::metadata(path)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            (Ok(_), Err(e)) => e.kind() != std::io::ErrorKind::NotFound,
            _ => true,
        }
    }
    #[cfg(windows)]
    {
        let Some(ours) = windows::identity(file) else { return true };
        match File::open(path) {
            Ok(other) => windows::identity(&other).is_none_or(|theirs| theirs == ours),
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, path);
        true
    }
}

/// Stdout and stderr to `file`.
fn redirect(file: &File) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: dup2 of an open file onto this process's own standard
        // descriptors, which replaces each at once: a write of another
        // thread goes to the one file or to the other.
        unsafe {
            libc::dup2(file.as_raw_fd(), libc::STDOUT_FILENO);
            libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO);
        }
    }
    #[cfg(windows)]
    windows::redirect(file);
    #[cfg(not(any(unix, windows)))]
    let _ = file;
}

/// At each start: each file of `detached/` older than [`OLD`] whose run
/// runs no more goes, as nothing else removes them. A run's own files stay
/// while a lock of its name is held; a log stays while the process that its
/// name holds lives (a pid that the system gave again keeps it longer, which
/// does no harm); a file of no form that podssh writes stays.
pub(super) fn sweep() {
    let Some(dir) = super::lock::dir() else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file) = entry.file_name().into_string() else { continue };
        let age = entry.metadata().and_then(|m| m.modified()).ok().and_then(|t| now.duration_since(t).ok());
        if !age.is_some_and(|age| age > OLD) {
            continue;
        }
        let gone = match (run_of(&file), log_pid(&file)) {
            (Some(name), _) => !runs(&dir, name),
            (None, Some(pid)) => !lives(pid),
            _ => false,
        };
        if gone {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// The run's name of a file of a run: `NAME.json`, its part being written,
/// `NAME.lock`, `NAME.run.lock` or `NAME.alive`.
fn run_of(file: &str) -> Option<&str> {
    let file = file.strip_suffix(".part").and_then(|f| f.rsplit_once('.')).map_or(file, |(f, _)| f);
    let name = [".run.lock", ".lock", ".alive", ".json"].iter().find_map(|end| file.strip_suffix(*end))?;
    super::lock::check_name(name).is_ok().then_some(name)
}

/// The pid of a log's name: `VERB-PID.log`, or its earlier part `.log.1`.
fn log_pid(file: &str) -> Option<u32> {
    let stem = file.strip_suffix(".log.1").or_else(|| file.strip_suffix(".log"))?;
    stem.rsplit_once('-')?.1.parse().ok()
}

/// Whether a lock of `name` is held, or cannot be told.
fn runs(dir: &Path, name: &str) -> bool {
    use super::lock::{holder, lock_path, run_lock_path, Holder};
    [lock_path(dir, name), run_lock_path(dir, name)].iter().any(|p| holder(p) != Holder::Free)
}

/// Whether a process of `pid` lives, or cannot be told.
fn lives(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else { return true };
        // SAFETY: signal 0 checks for the process and sends nothing.
        unsafe { libc::kill(pid, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) }
    }
    #[cfg(windows)]
    {
        windows::lives(pid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        true
    }
}

#[cfg(windows)]
mod windows {
    use std::fs::File;
    use std::os::windows::io::{AsRawHandle, IntoRawHandle};
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    /// The volume and the index of an open file.
    pub(super) fn identity(file: &File) -> Option<(u32, u64)> {
        // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is valid (numbers
        // only); the handle is open while `file` lives, and the function
        // writes one such structure.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let done = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
        let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        (done != 0).then_some((info.dwVolumeSerialNumber, index))
    }

    /// Stdout and stderr to copies of `file`. The handles that they replace
    /// stay open: a thread may be writing through one, and a closed handle's
    /// number could name another object; one cut a minute at most leaks two.
    pub(super) fn redirect(file: &File) {
        for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            if let Ok(copy) = file.try_clone() {
                // SAFETY: a handle of an open file, kept open for the
                // process's life as its standard handle.
                unsafe { SetStdHandle(which, copy.into_raw_handle()) };
            }
        }
    }

    pub(super) fn lives(pid: u32) -> bool {
        // SAFETY: the handle is checked, read once and closed once.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                // No such process; or one that this user may not open, which
                // is no run of this user's.
                return false;
            }
            let mut code = 0u32;
            let read = GetExitCodeProcess(process, &mut code) != 0;
            CloseHandle(process);
            !read || code == STILL_ACTIVE as u32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The files of a run are known by their names; a log by its pid; a
    /// file of no such form by neither, so it stays.
    #[test]
    fn the_files_of_a_run_and_of_a_log_are_known_by_their_names() {
        assert_eq!(run_of("web.json"), Some("web"));
        assert_eq!(run_of("web.lock"), Some("web"));
        assert_eq!(run_of("web.run.lock"), Some("web"));
        assert_eq!(run_of("web.alive"), Some("web"));
        assert_eq!(run_of("web.json.4242.part"), Some("web"));
        assert_eq!(run_of("ssh-4242.log"), None);
        assert_eq!(run_of("notes.txt"), None);
        assert_eq!(log_pid("ssh-4242.log"), Some(4242));
        assert_eq!(log_pid("node-17.log.1"), Some(17));
        assert_eq!(log_pid("web.json"), None);
        assert_eq!(log_pid("x.log"), None);
    }

    /// A cut renames the log aside and makes a new one: what the old file
    /// wrote before and after the cut is in `.1` (the copy and the cut of
    /// before lost what came between them), and the path names the new file,
    /// which a follower then takes. The redirect of stdout and stderr is
    /// left out, as it would take this test's own.
    #[test]
    fn a_cut_renames_the_log_aside_and_loses_no_line() {
        let dir = std::env::temp_dir().join(format!("podssh-detach-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pipe-1.log");
        let old = open_private(&path).unwrap();
        (&old).write_all(b"before the cut\n").unwrap();
        let new = cut(&path).expect("renamed").expect("a new file");
        (&old).write_all(b"meanwhile\n").unwrap();
        assert_eq!(std::fs::read_to_string(aside(&path)).unwrap(), "before the cut\nmeanwhile\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        assert!(same_file(&new, &path));
        assert!(!same_file(&old, &path), "a follower sees that the path names another file");
        // Windows keeps the name of a removed file that is open until it
        // closes.
        #[cfg(unix)]
        {
            std::fs::remove_file(&path).unwrap();
            assert!(!same_file(&new, &path), "and that it names none");
        }
        drop((old, new));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
