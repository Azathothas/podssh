//! The journal's socket for this process, on Linux, where its stderr is
//! the journal's stream (T-640). systemd sets `JOURNAL_STREAM` to the
//! device and inode of that stream; a child that inherited the variable
//! with another stderr has another pair, so the pair is compared with
//! descriptor 2's own: at the start, and again at each line, as a detached
//! run moves its stderr to a file after it started.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};

use podssh_ssh::LogLevel;

use super::entry::{entry, priority, stream_of, STREAM};

/// The journal's socket for entries, where systemd puts it.
pub const SOCKET: &str = "/run/systemd/journal/socket";

/// The device and inode of stderr as it is now.
pub type Now = Box<dyn Fn() -> Option<(u64, u64)> + Send + Sync>;

pub struct Sink {
    /// The device and inode of the journal's stream.
    stream: (u64, u64),
    /// Where each entry goes.
    path: PathBuf,
    /// Bound to nothing: it only sends.
    socket: UnixDatagram,
    stderr: Now,
}

impl Sink {
    /// The sink of this process: `None` unless `JOURNAL_STREAM` names its
    /// stderr.
    pub fn probe() -> Option<Sink> {
        let value = std::env::var("JOURNAL_STREAM").ok()?;
        let stderr = io::stderr();
        let stream = stream_is(&value, stderr.as_fd())?;
        let path = socket_beside(peer_of(stderr.as_fd()).as_deref());
        Sink::to(stream, path, Box::new(|| id_of(io::stderr().as_fd()))).ok()
    }

    /// A sink for `stream` that sends to `path` while `stderr` says that
    /// stderr is that stream; a test gives its own.
    pub fn to(stream: (u64, u64), path: PathBuf, stderr: Now) -> io::Result<Sink> {
        let socket = UnixDatagram::unbound()?;
        // A journal that reads too slowly loses the copy; the line never
        // waits for it, as the stream has it.
        socket.set_nonblocking(true)?;
        Ok(Sink { stream, path, socket, stderr })
    }

    /// A copy of `text` at `level`, where stderr is still the journal's
    /// stream and the level says more than the stream's own priority;
    /// whether it went. A send that fails is dropped, and is no exit code:
    /// a unit stops for good on 64 and 78, and a journal that went away
    /// must not stop a node.
    pub fn say(&self, level: LogLevel, text: &str) -> bool {
        self.say_at(priority(level), text)
    }

    /// [`Sink::say`] at a priority in syslog's numbers: the SSH client's
    /// log gives a warning's, which no level has (T-674).
    pub fn say_at(&self, priority: u8, text: &str) -> bool {
        if priority >= STREAM || (self.stderr)() != Some(self.stream) {
            return false;
        }
        let text = text.strip_suffix('\n').unwrap_or(text);
        self.socket.send_to(&entry(priority, text), &self.path).is_ok()
    }

    /// Whether the socket has no address: a test's look at rule 2.
    #[cfg(test)]
    pub fn binds_nothing(&self) -> bool {
        self.socket.local_addr().is_ok_and(|address| address.is_unnamed())
    }
}

/// The stream that `value` names, where it is `fd`'s own; `None` for a
/// child that inherited the variable with another stderr, which the
/// variable alone cannot tell.
pub fn stream_is(value: &str, fd: BorrowedFd<'_>) -> Option<(u64, u64)> {
    let stream = stream_of(value)?;
    (id_of(fd)? == stream).then_some(stream)
}

/// The device and inode of `fd`, as `fstat` gives them, read on a copy of
/// the descriptor that closes after it.
pub fn id_of(fd: BorrowedFd<'_>) -> Option<(u64, u64)> {
    let meta = File::from(fd.try_clone_to_owned().ok()?).metadata().ok()?;
    Some((meta.dev(), meta.ino()))
}

/// The address of the far end of `fd`, a stream socket: the journal's own
/// `stdout` socket.
fn peer_of(fd: BorrowedFd<'_>) -> Option<PathBuf> {
    let stream = UnixStream::from(fd.try_clone_to_owned().ok()?);
    stream.peer_addr().ok()?.as_pathname().map(Path::to_path_buf)
}

/// The socket for entries beside the journal's stream socket: `socket` in
/// the directory of its `stdout`, so that the journal of a namespace
/// (`/run/systemd/journal.NAME/`) gets its own lines; [`SOCKET`] when the
/// far end is not one that systemd names `stdout`.
pub fn socket_beside(peer: Option<&Path>) -> PathBuf {
    match peer {
        Some(peer) if peer.file_name().is_some_and(|name| name == "stdout") => peer.with_file_name("socket"),
        _ => PathBuf::from(SOCKET),
    }
}
