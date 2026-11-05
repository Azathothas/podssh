//! The passing of a node's sessions to the binary that takes its place, on
//! Unix (T-668): this process becomes the new binary by `execve`, so its
//! pid, its scope of systemd, the lock of a detached run and its supervisor
//! stay as they were. Each target's socket and the bytes of the sessions
//! stay open across it, as no other descriptor of this process does (each
//! is opened close-on-exec). The bytes are in anonymous memory: Linux's
//! `memfd_create`, else on macOS a POSIX shared object unlinked at once,
//! else a private file of the cache unlinked at once; never a path that
//! another process can open. The variable that names them names this pid
//! too, so a child of the new binary, which inherits the variable, reads
//! nothing.

use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;

use podssh_relay::session::handover::{Handed, LayerState, Moved};

use super::state::{self, Session};

/// The value of the variable for the bytes in `fd`: `fd:N:pid:P`.
pub fn value_of(fd: RawFd) -> String {
    format!("fd:{fd}:pid:{}", std::process::id())
}

/// The descriptor that `value` names, when it names this process; `None`
/// for another's, whose child this process is.
pub fn fd_of(value: &str) -> Result<Option<RawFd>, String> {
    let words: Vec<&str> = value.split(':').collect();
    let ["fd", fd, "pid", pid] = words.as_slice() else {
        return Err(format!("{value:?} names no handover"));
    };
    let fd: RawFd = fd.parse().map_err(|_| format!("{value:?} names no descriptor"))?;
    let pid: u32 = pid.parse().map_err(|_| format!("{value:?} names no process"))?;
    Ok((pid == std::process::id() && fd > 2).then_some(fd))
}

/// Whether `fd` stays open across `execve`.
pub fn inherited(fd: RawFd, on: bool) -> Result<(), String> {
    // SAFETY: fcntl of a descriptor that this process owns; it reads and
    // sets its flags alone.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(format!("the flags of descriptor {fd}: {}", std::io::Error::last_os_error()));
    }
    let flags = if on { flags & !libc::FD_CLOEXEC } else { flags | libc::FD_CLOEXEC };
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(format!("the flags of descriptor {fd}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// A socket of the binary before this one at `fd`, once `fstat` says that
/// it is a socket: a descriptor that names anything else is no target.
pub fn adopt(fd: RawFd) -> Result<std::net::TcpStream, String> {
    // SAFETY: a zeroed stat is a valid out value; fstat fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat of a descriptor number, which fails on one not open.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(format!("descriptor {fd}: {}", std::io::Error::last_os_error()));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(format!("descriptor {fd} is no socket"));
    }
    let _ = inherited(fd, false);
    // SAFETY: an open socket that the binary before this one gave this
    // one, which nothing else in this process owns.
    Ok(unsafe { std::net::TcpStream::from_raw_fd(fd) })
}

/// The bytes before the handover's own: their length, little-endian. The
/// object's size is no length: macOS rounds a shared object's up to a page.
const LENGTH: usize = 8;

/// Anonymous memory that holds `bytes`, open across `execve`: their length,
/// then them.
pub fn memory(bytes: &[u8]) -> Result<OwnedFd, String> {
    let fd = anonymous()?;
    let total = LENGTH + bytes.len();
    // SAFETY: a length for the object that this process just made.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), total as libc::off_t) } != 0 {
        return Err(format!("the handover's memory: {}", std::io::Error::last_os_error()));
    }
    with_map(&fd, total, true, |map| {
        map[..LENGTH].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        map[LENGTH..].copy_from_slice(bytes);
    })?;
    inherited(fd.as_raw_fd(), true)?;
    Ok(fd)
}

/// The bytes of the memory at `fd`, which closes after.
pub fn read_memory(fd: OwnedFd) -> Result<Vec<u8>, String> {
    // SAFETY: as in `adopt`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat of an open descriptor.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(format!("the handover's memory: {}", std::io::Error::last_os_error()));
    }
    let size = usize::try_from(st.st_size).map_err(|_| "the handover's memory has no size".to_string())?;
    if size <= LENGTH {
        return Err("the handover's memory is empty".into());
    }
    let mut out = Err("the handover's memory says a length past its end".to_string());
    with_map(&fd, size, false, |map| {
        let mut length = [0u8; LENGTH];
        length.copy_from_slice(&map[..LENGTH]);
        let len = usize::try_from(u64::from_le_bytes(length)).unwrap_or(usize::MAX);
        if len <= size - LENGTH {
            out = Ok(map[LENGTH..LENGTH + len].to_vec());
        }
    })?;
    out
}

/// Run `f` on `len` bytes of `fd` mapped, writable when `write`.
fn with_map(fd: &OwnedFd, len: usize, write: bool, f: impl FnOnce(&mut [u8])) -> Result<(), String> {
    let prot = if write { libc::PROT_READ | libc::PROT_WRITE } else { libc::PROT_READ };
    // SAFETY: a shared mapping of `len` bytes of an object of that size;
    // checked for failure before use.
    let map = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, libc::MAP_SHARED, fd.as_raw_fd(), 0) };
    if map == libc::MAP_FAILED {
        return Err(format!("the handover's memory: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: the mapping is `len` bytes, valid until munmap below, and
    // nothing else in this process aliases it.
    f(unsafe { std::slice::from_raw_parts_mut(map.cast::<u8>(), len) });
    // SAFETY: the mapping made above.
    unsafe { libc::munmap(map, len) };
    Ok(())
}

/// A new anonymous object of memory.
fn anonymous() -> Result<OwnedFd, String> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a name of 16 bytes and its NUL; flags 0 leave it open
        // across execve.
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create, c"podssh-handover".as_ptr(), 0u32) };
        if fd >= 0 {
            // SAFETY: a new descriptor that this process owns alone.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) });
        }
    }
    #[cfg(target_vendor = "apple")]
    if let Some(fd) = shared() {
        return Ok(fd);
    }
    private_file()
}

/// A POSIX shared object with a name of its own, unlinked at once.
#[cfg(target_vendor = "apple")]
fn shared() -> Option<OwnedFd> {
    let name = std::ffi::CString::new(format!("/podssh-h-{:016x}", rand::random::<u64>())).ok()?;
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL;
    // SAFETY: a NUL-terminated name; the mode is passed as the variadic
    // argument that shm_open reads with O_CREAT.
    let fd = unsafe { libc::shm_open(name.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        return None;
    }
    // SAFETY: the name made above; the object lives on by its descriptor.
    unsafe { libc::shm_unlink(name.as_ptr()) };
    // SAFETY: a new descriptor that this process owns alone.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A file of the cache's private directory, mode 0600, unlinked at once.
fn private_file() -> Result<OwnedFd, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = podssh_relay::cache::candidate_dirs()
        .into_iter()
        .find(|dir| podssh_relay::cache::private_dir(dir).is_ok())
        .ok_or("no private directory of the cache for the handover")?;
    let path = dir.join(format!("handover-{}-{:016x}", std::process::id(), rand::random::<u64>()));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let _ = std::fs::remove_file(&path);
    Ok(OwnedFd::from(file))
}

/// Become `binary`, with this run's words and the handover of `handed`,
/// written by `from`. Returns only when the binary did not start: then the
/// sessions, back as the new binary would have read them, and why.
pub fn become_binary(binary: &Path, from: &str, handed: Vec<Handed>) -> (Vec<Handed>, String) {
    let mut sessions = Vec::with_capacity(handed.len());
    for Handed { state, target } in handed {
        let (socket, channel) = match target {
            Ok(Moved { socket, channel }) => {
                let fd = socket.into_raw_fd();
                let _ = inherited(fd, true);
                (Some(fd), channel)
            }
            Err(_) => (None, None),
        };
        sessions.push(Session { layer: state.encode(), socket, channel });
    }
    let bytes = state::encode(from, &sessions);
    let why = match memory(&bytes) {
        Ok(memory) => exec(binary, &value_of(memory.as_raw_fd())),
        Err(why) => why,
    };
    // The binary did not start: the sessions come back as it would have
    // read them, from the same bytes, each socket still open here.
    // Bytes that this build wrote a moment ago read back; were they not, a
    // socket is left open rather than closed twice.
    match taken(&bytes) {
        Ok((_, handed)) => (handed, why),
        Err(lost) => (Vec::new(), format!("{why}; and its sessions could not be read back: {lost}")),
    }
}

/// `execve` of `binary`, with this run's words, and the variable: an
/// error, as a success never returns.
fn exec(binary: &Path, value: &str) -> String {
    use std::os::unix::process::CommandExt;
    // A signal of the next upgrade before the new binary listens for it
    // must not end the node: an ignored signal stays ignored across exec.
    // SAFETY: the disposition of one signal of this process.
    unsafe { libc::signal(libc::SIGUSR2, libc::SIG_IGN) };
    let mut words = std::env::args_os();
    let mut cmd = std::process::Command::new(binary);
    if let Some(first) = words.next() {
        cmd.arg0(first);
    }
    cmd.args(words).env(super::VARIABLE, value);
    cmd.exec().to_string()
}

/// The sessions in `bytes`, each socket adopted: one that is no socket is
/// a session that ends at its resume, with why.
pub fn taken(bytes: &[u8]) -> Result<(String, Vec<Handed>), String> {
    let (from, sessions) = state::decode(bytes).map_err(|e| e.to_string())?;
    let mut handed = Vec::with_capacity(sessions.len());
    for Session { layer, socket, channel } in sessions {
        let state = LayerState::decode(&layer).map_err(|e| e.to_string())?;
        let target = match socket {
            Some(fd) => adopt(fd).map(|socket| Moved { socket, channel }),
            None => Err(String::new()),
        };
        handed.push(Handed { state, target });
    }
    Ok((from, handed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variable_names_this_process_alone() {
        assert_eq!(fd_of(&value_of(9)).unwrap(), Some(9));
        assert_eq!(fd_of(&format!("fd:9:pid:{}", std::process::id() + 1)).unwrap(), None, "a parent's");
        assert_eq!(fd_of(&format!("fd:1:pid:{}", std::process::id())).unwrap(), None, "a standard stream");
        assert!(fd_of("probe").is_err());
        assert!(fd_of("fd:x:pid:1").is_err());
    }

    /// The bytes come back from the memory, as the next binary reads them.
    #[test]
    fn the_memory_gives_its_bytes_back() {
        let bytes: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let fd = memory(&bytes).unwrap();
        assert_eq!(read_memory(fd).unwrap(), bytes);
    }

    #[test]
    fn a_descriptor_that_is_no_socket_is_not_adopted() {
        let file = std::fs::File::open("/dev/null").or_else(|_| std::fs::File::open("/")).unwrap();
        let fd = file.as_raw_fd();
        assert!(adopt(fd).unwrap_err().contains("no socket"));
        drop(file);
    }
}
