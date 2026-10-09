//! The controlling terminal, used only when the kernel says that this process
//! has one.
//!
//! A successful `open("/dev/tty")` is not proof. In a measured sandbox it
//! succeeded while `ps` showed no terminal for the process and stdin, stdout
//! and stderr were not terminals, and a read then blocked for ever. So the
//! descriptor must also be a terminal of this process's session, and the
//! kernel's own record (`tty_nr` in `/proc/self/stat`), when it can be read,
//! must name a terminal.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

/// `/dev/tty` for reading and writing, when it is this process's controlling
/// terminal; else an error that says why it is not used.
pub fn open() -> std::io::Result<File> {
    let tty =
        OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC).open("/dev/tty")?;
    let fd = tty.as_raw_fd();
    // SAFETY: queries with no preconditions, on a descriptor held open here.
    let is_tty = unsafe { libc::isatty(fd) } == 1;
    let (session, own) = unsafe { (libc::tcgetsid(fd), libc::getsid(0)) };
    let kernel = std::fs::read_to_string("/proc/self/stat").ok().and_then(|s| tty_nr(&s));
    if trusted(is_tty, session != -1 && session == own, kernel) {
        Ok(tty)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/dev/tty opens, but it is not the controlling terminal of this process",
        ))
    }
}

/// The decision, apart from the system calls, so that it can be tested. An
/// unreadable `/proc` (`None`) leaves the decision to the other two facts.
pub fn trusted(is_tty: bool, same_session: bool, tty_nr: Option<i64>) -> bool {
    is_tty && same_session && tty_nr != Some(0)
}

/// Field 7 of `/proc/self/stat`: the device number of the controlling
/// terminal, 0 for none. The command name (field 2) can hold spaces and
/// parentheses, so the fields are counted after the last `)`.
pub fn tty_nr(stat: &str) -> Option<i64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(4)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tty_nr_is_field_seven_also_after_an_odd_command_name() {
        let plain = "4242 (podssh) S 1 4242 4242 34816 4242 4194304 100 0 0 0";
        assert_eq!(tty_nr(plain), Some(34816));
        let odd = "4242 (a) b (c) S 1 4242 4242 0 -1 4194304 100 0 0 0";
        assert_eq!(tty_nr(odd), Some(0));
        assert_eq!(tty_nr("garbage"), None);
        assert_eq!(tty_nr("1 (x) S 1 2"), None);
    }

    /// The sandbox case: the open worked, but the kernel names no terminal.
    #[test]
    fn a_tty_the_kernel_does_not_name_is_not_trusted() {
        assert!(!trusted(true, true, Some(0)));
        assert!(!trusted(false, true, None), "not a terminal at all");
        assert!(!trusted(true, false, None), "another session's terminal");
        // The controls: a real controlling terminal, with and without /proc.
        assert!(trusted(true, true, Some(34816)));
        assert!(trusted(true, true, None));
    }

    /// This process's own /proc/self/stat parses (Linux only has /proc).
    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_stat_parses() {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        assert!(tty_nr(&stat).is_some(), "{stat}");
    }
}
