//! A pseudo terminal of Linux for the tests (T-158): a program runs with a
//! pty as its stdin, stdout and stderr, as in a terminal's window, and the
//! test types into it and reads what it writes. The counterpart of
//! `conpty_harness` on Windows, with the same calls.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A pty and the one process that runs in it.
pub struct Pty {
    input: File,
    seen: Arc<Mutex<Vec<u8>>>,
    child: Mutex<Child>,
}

impl Pty {
    /// Run `command` with a new pty of `rows` by `cols` as its stdin,
    /// stdout and stderr.
    pub fn start(mut command: Command, rows: u16, cols: u16) -> Pty {
        // SAFETY: flags for a new pty; the result is checked.
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        assert!(master >= 0, "posix_openpt: {}", std::io::Error::last_os_error());
        // SAFETY: the pty just opened, which this process owns.
        assert_eq!(unsafe { libc::grantpt(master) }, 0, "grantpt: {}", std::io::Error::last_os_error());
        // SAFETY: the same.
        assert_eq!(unsafe { libc::unlockpt(master) }, 0, "unlockpt: {}", std::io::Error::last_os_error());
        let mut name = [0 as libc::c_char; 128];
        // SAFETY: the pty, and a buffer of the length given.
        let rc = unsafe { libc::ptsname_r(master, name.as_mut_ptr(), name.len()) };
        assert_eq!(rc, 0, "ptsname_r: {rc}");
        // SAFETY: ptsname_r wrote a string that ends in 0 into the buffer.
        let path = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_string_lossy().into_owned();
        let size = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
        // SAFETY: the pty, and a size that lives through the call.
        unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &size as *const libc::winsize) };
        // Not this process's controlling terminal: the program's alone.
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&path)
            .expect("the pty's other end");
        command
            .stdin(Stdio::from(slave.try_clone().expect("the pty's other end")))
            .stdout(Stdio::from(slave.try_clone().expect("the pty's other end")))
            .stderr(Stdio::from(slave));
        let child = command.spawn().expect("the program starts");
        // The program holds the other end now: once it ends, a read of the
        // pty fails, and the reader stops.
        drop(command);
        // SAFETY: the pty, owned by this file from here on.
        let mut output = unsafe { File::from_raw_fd(master) };
        let input = output.try_clone().expect("the pty again");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = seen.clone();
        std::thread::spawn(move || {
            let mut chunk = vec![0u8; 65536];
            while let Ok(n) = output.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                into.lock().unwrap().extend_from_slice(&chunk[..n]);
            }
        });
        Pty { input, seen, child: Mutex::new(child) }
    }

    /// Type `bytes`, as a terminal sends its keys.
    pub fn send(&mut self, bytes: &[u8]) {
        self.input.write_all(bytes).expect("the pty's input");
        self.input.flush().expect("the pty's input");
    }

    /// What the program wrote, as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap()).into_owned()
    }

    /// Wait until the program wrote `needle`, at most `limit`.
    pub fn expect(&self, needle: &str, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        loop {
            if self.text().contains(needle) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The program's exit code, when it ends within `limit`.
    pub fn wait(&self, limit: Duration) -> Option<u32> {
        let end = Instant::now() + limit;
        loop {
            if let Ok(Some(status)) = self.child.lock().unwrap().try_wait() {
                return status.code().map(|code| code as u32);
            }
            if Instant::now() >= end {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let mut child = self.child.lock().unwrap();
        if let Ok(None) = child.try_wait() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}
