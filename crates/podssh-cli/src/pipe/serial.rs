//! A serial line as an end of `podssh pipe` (T-181): `serial:PATH[,BAUD]`,
//! a device such as `/dev/ttyUSB0`, at BAUD (115200 when none is given),
//! with 8 data bits, no parity, 1 stop bit and no flow control, in raw
//! mode. The attempt is the probe: the path must be a character device that
//! is a terminal, and that this user may open. podssh assumes no group such
//! as `dialout`; a refused open says whose the device is.
//!
//! The device is opened with `O_NOCTTY`, so that it never becomes podssh's
//! controlling terminal, and `O_NONBLOCK`, so that the open does not wait
//! for a modem's carrier; then `TIOCEXCL`, so that no other program opens it
//! meanwhile. Its settings are saved before they change, and they go back on
//! each way out: when the end drops (the pipe ended, or SIGINT or SIGTERM,
//! after which the pipe drops its ends), and in the panic hook, as the
//! release build aborts on a panic and runs no `Drop`.
//!
//! A serial line has no half-close and no end of its own: the end of the
//! other side's input leaves it open, and the pipe ends when the other side
//! ends it, at a signal, or when the device fails (a read or a write that
//! fails: a USB adapter that was pulled out), which exits 69.

#[cfg(unix)]
pub use unix::open;

/// Only Unix opens a serial line; `address` refuses the kind elsewhere.
#[cfg(not(unix))]
pub fn open(path: &str, _baud: u32) -> Result<super::pump::End, super::local::Unopened> {
    let why = format!("serial:{path}: a serial line is opened on Unix only");
    Err(super::local::Unopened { code: crate::exitmap::sysexits::EX_USAGE, why })
}

#[cfg(unix)]
mod unix {
    use std::future::Future;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex, Once};
    use std::task::{ready, Context, Poll};

    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::super::local::Unopened;
    use super::super::pump::{End, Ending, Verdict};
    use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};

    /// The settings to put back, by descriptor, where the panic hook can
    /// reach them.
    static SAVED: Mutex<Vec<(RawFd, libc::termios)>> = Mutex::new(Vec::new());
    static HOOK: Once = Once::new();

    /// The first failure of the line, for the pipe's exit code.
    type Failure = Arc<Mutex<Option<String>>>;

    /// Open `path` as a serial line at `baud`, in a tokio runtime.
    pub fn open(path: &str, baud: u32) -> Result<End, Unopened> {
        let shown = format!("serial:{path}");
        let meta = std::fs::metadata(path).map_err(|e| refused(&shown, e, None))?;
        if !meta.file_type().is_char_device() {
            let why = format!("{shown}: not a character device; a serial line is one, such as /dev/ttyUSB0");
            return Err(Unopened { code: EX_USAGE, why });
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| refused(&shown, e, Some(&meta)))?;
        let fd = file.as_raw_fd();
        // SAFETY: isatty only asks what the descriptor is.
        if unsafe { libc::isatty(fd) } != 1 {
            let why = format!("{shown}: a character device that is no terminal, so no serial line");
            return Err(Unopened { code: EX_USAGE, why });
        }
        // SAFETY: an ioctl with no argument, on a descriptor that this
        // function holds; the request's type differs between systems.
        if unsafe { libc::ioctl(fd, libc::TIOCEXCL as _) } == -1 {
            return Err(failed(&shown, "could not hold it alone", io::Error::last_os_error()));
        }
        // From here, its drop gives the line up, and puts back what changed.
        let line = Line { file };
        let Some(speed) = speed(baud) else {
            return Err(Unopened { code: EX_USAGE, why: format!("{shown}: no speed of {baud} baud here") });
        };
        // SAFETY: an all-zero termios is valid for tcgetattr to fill.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr writes into the struct that this function owns.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(failed(&shown, "could not read its settings", io::Error::last_os_error()));
        }
        let wanted = raw(saved, speed).map_err(|e| failed(&shown, &format!("no speed of {baud} baud"), e))?;
        save(fd, saved);
        // SAFETY: a termios that tcgetattr filled and this function changed.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &wanted) } != 0 {
            let doing = format!("could not set {baud} baud, 8 data bits, no parity, 1 stop bit");
            return Err(failed(&shown, &doing, io::Error::last_os_error()));
        }
        let line = Arc::new(AsyncFd::new(line).map_err(|e| failed(&shown, "could not wait on it", e))?);
        let failure = Failure::default();
        let read = Reader { line: line.clone(), failure: failure.clone() };
        let write = Writer { line, failure: failure.clone() };
        // The end of the line's output is a device that failed: nothing
        // more can come.
        let ending = Failed { shown, failure };
        Ok(End {
            read: Box::new(read),
            write: Box::new(write),
            child: None,
            last_word: true,
            ending: Some(Box::new(ending)),
        })
    }

    /// A refused open is 77, with the device's mode and owner, as podssh
    /// assumes no group; a missing device and the others are 69.
    pub(super) fn refused(shown: &str, e: io::Error, meta: Option<&std::fs::Metadata>) -> Unopened {
        if e.kind() == io::ErrorKind::PermissionDenied {
            let whose = meta.map_or_else(String::new, |m| {
                format!("; the device is mode {:04o}, of uid {} and gid {}", m.mode() & 0o7777, m.uid(), m.gid())
            });
            return Unopened { code: EX_NOPERM, why: format!("{shown}: {e}{whose}") };
        }
        Unopened { code: EX_UNAVAILABLE, why: format!("{shown}: {e}") }
    }

    fn failed(shown: &str, doing: &str, e: io::Error) -> Unopened {
        Unopened { code: EX_UNAVAILABLE, why: format!("{shown}: {doing}: {e}") }
    }

    /// Raw mode at `speed`: 8 data bits, no parity, 1 stop bit, no flow
    /// control, the modem's lines ignored, the receiver on, and a read that
    /// returns as soon as one byte came.
    fn raw(mut t: libc::termios, speed: libc::speed_t) -> io::Result<libc::termios> {
        // SAFETY: cfmakeraw and cfsetspeed write only into the struct passed.
        unsafe { libc::cfmakeraw(&mut t) };
        // SAFETY: as above.
        if unsafe { libc::cfsetspeed(&mut t, speed) } != 0 {
            return Err(io::Error::last_os_error());
        }
        t.c_cflag &= !(libc::CSIZE | libc::PARENB | libc::CSTOPB | libc::CRTSCTS);
        t.c_cflag |= libc::CS8 | libc::CLOCAL | libc::CREAD;
        t.c_iflag &= !(libc::IXON | libc::IXOFF | libc::IXANY);
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        Ok(t)
    }

    /// The kernel's value of a speed of the table: Linux has a code for each.
    #[cfg(target_os = "linux")]
    pub(super) fn speed(baud: u32) -> Option<libc::speed_t> {
        Some(match baud {
            1200 => libc::B1200,
            1800 => libc::B1800,
            2400 => libc::B2400,
            4800 => libc::B4800,
            9600 => libc::B9600,
            19200 => libc::B19200,
            38400 => libc::B38400,
            57600 => libc::B57600,
            115200 => libc::B115200,
            230400 => libc::B230400,
            460800 => libc::B460800,
            500000 => libc::B500000,
            576000 => libc::B576000,
            921600 => libc::B921600,
            1000000 => libc::B1000000,
            1152000 => libc::B1152000,
            1500000 => libc::B1500000,
            2000000 => libc::B2000000,
            2500000 => libc::B2500000,
            3000000 => libc::B3000000,
            3500000 => libc::B3500000,
            4000000 => libc::B4000000,
            _ => return None,
        })
    }

    /// Another Unix takes the number itself; a device that cannot run at it
    /// refuses it at `tcsetattr`, and the line says so.
    #[cfg(not(target_os = "linux"))]
    pub(super) fn speed(baud: u32) -> Option<libc::speed_t> {
        Some(baud as libc::speed_t)
    }

    /// Keep `saved` for `fd` where the panic hook finds it, and set the hook
    /// once for the process.
    fn save(fd: RawFd, saved: libc::termios) {
        HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                restore_all();
                previous(info);
            }));
        });
        SAVED.lock().unwrap_or_else(|e| e.into_inner()).push((fd, saved));
    }

    /// The panic hook's part: each line's settings back at once, and each
    /// line given up.
    fn restore_all() {
        let saved = std::mem::take(&mut *SAVED.lock().unwrap_or_else(|e| e.into_inner()));
        for (fd, t) in saved {
            // SAFETY: settings that tcgetattr read from a descriptor that is
            // still open, as its line removes it from the list before it closes.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) };
            // SAFETY: an ioctl with no argument on the same descriptor.
            unsafe { libc::ioctl(fd, libc::TIOCNXCL as _) };
        }
    }

    /// An open serial line.
    struct Line {
        file: std::fs::File,
    }

    impl AsRawFd for Line {
        fn as_raw_fd(&self) -> RawFd {
            self.file.as_raw_fd()
        }
    }

    impl Drop for Line {
        fn drop(&mut self) {
            let fd = self.file.as_raw_fd();
            let saved = {
                let mut list = SAVED.lock().unwrap_or_else(|e| e.into_inner());
                let at = list.iter().position(|(f, _)| *f == fd);
                at.map(|at| list.remove(at).1)
            };
            if let Some(t) = saved {
                // SAFETY: settings that tcgetattr read from this descriptor.
                // TCSADRAIN: what was written goes out at its own speed first.
                unsafe { libc::tcsetattr(fd, libc::TCSADRAIN, &t) };
            }
            // SAFETY: an ioctl with no argument on a descriptor of this line.
            unsafe { libc::ioctl(fd, libc::TIOCNXCL as _) };
        }
    }

    /// The first failure, kept for the exit code.
    fn note(failure: &Failure, e: &io::Error) {
        let mut slot = failure.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_none() {
            *slot = Some(e.to_string());
        }
    }

    struct Reader {
        line: Arc<AsyncFd<Line>>,
        failure: Failure,
    }

    impl AsyncRead for Reader {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            loop {
                let mut guard = ready!(self.line.poll_read_ready(cx))?;
                let unfilled = buf.initialize_unfilled();
                let read = guard.try_io(|line| {
                    let mut file = &line.get_ref().file;
                    file.read(unfilled)
                });
                match read {
                    Ok(Ok(n)) => {
                        buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Err(e)) => {
                        note(&self.failure, &e);
                        return Poll::Ready(Err(e));
                    }
                    // Not ready after all: wait again.
                    Err(_would_block) => continue,
                }
            }
        }
    }

    struct Writer {
        line: Arc<AsyncFd<Line>>,
        failure: Failure,
    }

    impl AsyncWrite for Writer {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = ready!(self.line.poll_write_ready(cx))?;
                let written = guard.try_io(|line| {
                    let mut file = &line.get_ref().file;
                    file.write(data)
                });
                match written {
                    Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                    Ok(Err(e)) => {
                        note(&self.failure, &e);
                        return Poll::Ready(Err(e));
                    }
                    Err(_would_block) => continue,
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        /// A serial line has no half-close: the other direction goes on.
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// The line's ending: 69 and its failure, when a read or a write failed.
    struct Failed {
        shown: String,
        failure: Failure,
    }

    impl Ending for Failed {
        fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
            let Failed { shown, failure } = *self;
            let failed = failure.lock().unwrap_or_else(|p| p.into_inner()).take();
            let verdict = failed.map(|e| (EX_UNAVAILABLE, vec![format!("{shown}: the line failed: {e}")]));
            Box::pin(std::future::ready(verdict))
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::unix::{refused, speed};
    use std::io;

    #[test]
    fn a_refused_device_is_77_and_says_whose_it_is_and_a_missing_one_is_69() {
        let meta = std::fs::metadata("/dev/null").unwrap();
        let denied = refused("serial:/dev/x", io::Error::from(io::ErrorKind::PermissionDenied), Some(&meta));
        assert_eq!(denied.code, 77);
        assert!(denied.why.contains("of uid") && denied.why.contains("gid"), "{}", denied.why);
        let missing = refused("serial:/dev/x", io::Error::from(io::ErrorKind::NotFound), None);
        assert_eq!(missing.code, 69);
    }

    #[test]
    fn each_speed_of_the_table_has_the_kernel_s_value() {
        for baud in crate::pipe::address::BAUDS {
            assert!(speed(*baud).is_some(), "{baud}");
        }
    }
}
