//! A descriptor that a client passed, read and written without blocking the
//! master. A terminal, a pipe or a socket is made non-blocking and polled;
//! it shares its open file with the client, so its flags change for both,
//! and they are put back when it is dropped, as OpenSSH's master puts them
//! back, or the client's shell would find its terminal non-blocking. A
//! regular file or a device that cannot be polled (`> out.txt`,
//! `/dev/null`) is read and written on tokio's threads for blocking work.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub enum Passed {
    Polled {
        fd: AsyncFd<OwnedFd>,
        /// The file status flags as the client had them.
        flags: libc::c_int,
    },
    Blocking(tokio::fs::File),
}

impl Passed {
    pub fn new(fd: OwnedFd) -> io::Result<Passed> {
        let raw = fd.as_raw_fd();
        // SAFETY: fcntl on a descriptor that this value owns.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above.
        if unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: an `OwnedFd` holds its descriptor open, and gives the same
        // one, until the `AsyncFd` that owns it drops it.
        match unsafe { AsyncFd::register(fd) } {
            Ok(fd) => Ok(Passed::Polled { fd, flags }),
            Err(refused) => {
                // epoll takes no regular file and no /dev/null.
                let (fd, _) = refused.into_parts();
                // SAFETY: as above.
                unsafe { libc::fcntl(raw, libc::F_SETFL, flags) };
                Ok(Passed::Blocking(tokio::fs::File::from_std(std::fs::File::from(fd))))
            }
        }
    }

    /// The descriptor, for an ioctl.
    pub fn raw(&self) -> RawFd {
        match self {
            Passed::Polled { fd, .. } => fd.get_ref().as_raw_fd(),
            Passed::Blocking(file) => file.as_raw_fd(),
        }
    }
}

impl Drop for Passed {
    fn drop(&mut self) {
        if let Passed::Polled { fd, flags } = self {
            // SAFETY: the descriptor is still open: AsyncFd closes it after.
            unsafe { libc::fcntl(fd.get_ref().as_raw_fd(), libc::F_SETFL, *flags) };
        }
    }
}

impl AsyncRead for Passed {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let fd = match self.get_mut() {
            Passed::Blocking(file) => return Pin::new(file).poll_read(cx, buf),
            Passed::Polled { fd, .. } => fd,
        };
        loop {
            let mut guard = ready!(fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            // SAFETY: read into the initialized part of the buffer.
            let n = unsafe { libc::read(guard.get_inner().as_raw_fd(), unfilled.as_mut_ptr().cast(), unfilled.len()) };
            if n >= 0 {
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => guard.clear_ready(),
                io::ErrorKind::Interrupted => {}
                // A terminal whose other end has gone reads EIO: an end.
                _ if e.raw_os_error() == Some(libc::EIO) => return Poll::Ready(Ok(())),
                _ => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for Passed {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let fd = match self.get_mut() {
            Passed::Blocking(file) => return Pin::new(file).poll_write(cx, data),
            Passed::Polled { fd, .. } => fd,
        };
        loop {
            let mut guard = ready!(fd.poll_write_ready(cx))?;
            // SAFETY: write from the caller's buffer.
            let n = unsafe { libc::write(guard.get_inner().as_raw_fd(), data.as_ptr().cast(), data.len()) };
            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => guard.clear_ready(),
                io::ErrorKind::Interrupted => {}
                _ => return Poll::Ready(Err(e)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Passed::Blocking(file) => Pin::new(file).poll_flush(cx),
            Passed::Polled { .. } => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Passed::Blocking(file) => Pin::new(file).poll_shutdown(cx),
            Passed::Polled { .. } => Poll::Ready(Ok(())),
        }
    }
}
