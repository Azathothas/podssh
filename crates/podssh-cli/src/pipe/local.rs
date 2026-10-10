//! The local ends of `podssh pipe` (T-174): stdin and stdout, an inherited
//! descriptor, and a child.
//!
//! A child gets one end of a socketpair as its stdin and stdout, so that
//! the end of its input is a half-close and its output still comes back.
//! Where a socketpair is refused (a sandbox's seccomp gives EPERM, EACCES or
//! ENOSYS), and on Windows, it gets two pipes. Its stderr is podssh's.

use std::io;
use std::process::Stdio;

use tokio::process::Command;

use super::address::Address;
use super::pump::End;

/// Why an end could not be opened: the exit code, and the words.
#[derive(Debug)]
pub struct Unopened {
    pub code: i32,
    pub why: String,
}

/// Open `address`, in a tokio runtime.
pub fn open(address: &Address) -> Result<End, Unopened> {
    match address {
        Address::Stdio => Ok(stdio()),
        Address::Fd(n) => descriptor(*n),
        Address::Exec(words) => exec(words, &socketpair),
        // A remote address goes to its road (`remote`), never here.
        Address::Relay { .. } | Address::Tcp { .. } | Address::Ssh { .. } | Address::Node(_) | Address::Iroh(_) => {
            Err(Unopened { code: crate::exit_codes::EXIT_SOFTWARE, why: "a remote address is not a local end".into() })
        }
    }
}

#[cfg(unix)]
type Pair = (std::os::unix::net::UnixStream, std::os::unix::net::UnixStream);
#[cfg(not(unix))]
type Pair = ();

#[cfg(unix)]
fn socketpair() -> io::Result<Pair> {
    std::os::unix::net::UnixStream::pair()
}

#[cfg(not(unix))]
fn socketpair() -> io::Result<Pair> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "no socketpair here"))
}

/// stdin and stdout.
pub fn stdio() -> End {
    End::plain(Box::new(tokio::io::stdin()), Box::new(tokio::io::stdout()))
}

/// Start `words` with a socketpair from `pair`, or with two pipes when it
/// gives none.
pub fn exec(words: &[String], pair: &dyn Fn() -> io::Result<Pair>) -> Result<End, Unopened> {
    let mut cmd = Command::new(&words[0]);
    cmd.args(&words[1..]).stderr(Stdio::inherit());
    match pair() {
        #[cfg(unix)]
        Ok((ours, theirs)) => with_socketpair(cmd, words, ours, theirs),
        #[cfg(not(unix))]
        Ok(()) => with_pipes(cmd, words),
        Err(_) => with_pipes(cmd, words),
    }
}

#[cfg(unix)]
fn with_socketpair(
    mut cmd: Command,
    words: &[String],
    ours: std::os::unix::net::UnixStream,
    theirs: std::os::unix::net::UnixStream,
) -> Result<End, Unopened> {
    use std::os::fd::OwnedFd;
    let failed = |e: io::Error| Unopened { code: 126, why: format!("exec:{}: a socketpair: {e}", words[0]) };
    let theirs_out = theirs.try_clone().map_err(failed)?;
    cmd.stdin(Stdio::from(OwnedFd::from(theirs))).stdout(Stdio::from(OwnedFd::from(theirs_out)));
    let child = cmd.spawn().map_err(|e| not_started(&words[0], e))?;
    // The child's ends stay only in the child: else its output would never end.
    drop(cmd);
    ours.set_nonblocking(true).map_err(failed)?;
    let ours = tokio::net::UnixStream::from_std(ours).map_err(failed)?;
    let (read, write) = ours.into_split();
    Ok(child_end(Box::new(read), Box::new(write), child))
}

fn with_pipes(mut cmd: Command, words: &[String]) -> Result<End, Unopened> {
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| not_started(&words[0], e))?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(Unopened { code: 126, why: format!("exec:{}: no pipes to the child", words[0]) });
    };
    Ok(child_end(Box::new(stdout), Box::new(stdin), child))
}

fn child_end(read: super::pump::Reader, write: super::pump::Writer, child: tokio::process::Child) -> End {
    End { read, write, child: Some(child), last_word: false, ending: None }
}

/// A program that cannot start gives what a shell gives: 127 when it is not
/// found, else 126.
fn not_started(program: &str, e: io::Error) -> Unopened {
    let code = if e.kind() == io::ErrorKind::NotFound { 127 } else { 126 };
    Unopened { code, why: format!("exec:{program}: {e}") }
}

/// The exit code of a child, as a shell gives it: its own, or 128 + the
/// number of the signal that ended it.
pub fn code_of(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

#[cfg(unix)]
fn descriptor(n: i32) -> Result<End, Unopened> {
    use std::os::fd::{FromRawFd, RawFd};
    // SAFETY: fcntl and dup take any number and only read the table of
    // descriptors; an unknown one fails with EBADF.
    if unsafe { libc::fcntl(n, libc::F_GETFD) } == -1 {
        return Err(Unopened { code: 64, why: format!("fd:{n}: {}; is it open?", io::Error::last_os_error()) });
    }
    let reading: RawFd = unsafe { libc::dup(n) };
    if reading == -1 {
        return Err(Unopened { code: 71, why: format!("fd:{n}: {}", io::Error::last_os_error()) });
    }
    // SAFETY: each is a descriptor that this process holds, owned once: n
    // came from the parent for podssh to use, and `reading` is a new copy.
    let (read, write) = unsafe { (std::fs::File::from_raw_fd(reading), std::fs::File::from_raw_fd(n)) };
    let write = FdWrite { file: tokio::fs::File::from_std(write), fd: n };
    Ok(End::plain(Box::new(tokio::fs::File::from_std(read)), Box::new(write)))
}

#[cfg(not(unix))]
fn descriptor(n: i32) -> Result<End, Unopened> {
    Err(Unopened { code: 64, why: format!("fd:{n} is for Unix") })
}

/// The write half of `fd:N`: its shutdown is a half-close when the
/// descriptor is a socket; for a pipe or a file, the end of the copy closes
/// it, and its reader sees the end once the other copy is gone too.
#[cfg(unix)]
struct FdWrite {
    file: tokio::fs::File,
    fd: i32,
}

#[cfg(unix)]
impl tokio::io::AsyncWrite for FdWrite {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.file).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let flushed = std::pin::Pin::new(&mut self.file).poll_shutdown(cx);
        if flushed.is_ready() {
            // SAFETY: shutdown on a descriptor that this end owns; on one
            // that is not a socket it fails with ENOTSOCK and does nothing.
            unsafe { libc::shutdown(self.fd, libc::SHUT_WR) };
        }
        flushed
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Where a sandbox refuses the socketpair, the child gets pipes, and the
    /// bytes still go there and back.
    #[tokio::test]
    async fn a_refused_socketpair_falls_back_to_pipes() {
        let refused = || Err(io::Error::from_raw_os_error(libc::EPERM));
        let pairs: [&dyn Fn() -> io::Result<Pair>; 2] = [&socketpair, &refused];
        for pair in pairs {
            let mut end = exec(&["cat".to_string()], pair).expect("cat starts");
            end.write.write_all(b"there and back").await.unwrap();
            end.write.shutdown().await.unwrap();
            drop(end.write);
            let mut back = Vec::new();
            end.read.read_to_end(&mut back).await.unwrap();
            assert_eq!(back, b"there and back");
            let status = end.child.as_mut().unwrap().wait().await.unwrap();
            assert_eq!(code_of(status), 0);
        }
    }

    #[tokio::test]
    async fn a_program_that_is_not_found_gives_127() {
        let refusal = exec(&["podssh-no-such-program".to_string()], &socketpair).err().expect("refused");
        assert_eq!(refusal.code, 127, "{}", refusal.why);
    }

    #[test]
    fn a_closed_descriptor_is_refused_with_64() {
        // A number that this test process does not hold.
        let refusal = descriptor(987).err().expect("refused");
        assert_eq!(refusal.code, 64, "{}", refusal.why);
    }
}
