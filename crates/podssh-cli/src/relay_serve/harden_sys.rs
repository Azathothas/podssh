//! The system calls of the drop after the bind (T-629), Linux alone:
//! `capget` and `capset` by `syscall(2)`, as the C library of a static build
//! need not wrap them, and `prctl(2)`. Each acts on the calling thread.

use super::harden::{status_sets, Calls, Sets};

/// `_LINUX_CAPABILITY_VERSION_3`: two records of 32 bits for 64 capabilities.
const VERSION_3: u32 = 0x2008_0522;

// The kernel reads it; this code only writes it.
#[allow(dead_code)]
#[repr(C)]
struct Header {
    version: u32,
    /// 0: the calling thread.
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The calls of this thread.
pub struct Sys;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `prctl(option, arg)`, with the three arguments after it zero, as
/// `PR_SET_NO_NEW_PRIVS` asks.
fn prctl(option: libc::c_int, arg: libc::c_ulong) -> libc::c_int {
    let zero: libc::c_ulong = 0;
    // SAFETY: each argument is an integer of the width that prctl(2) reads.
    unsafe { libc::prctl(option, arg, zero, zero, zero) }
}

impl Calls for Sys {
    fn sets(&mut self) -> Result<Sets, i32> {
        let mut header = Header { version: VERSION_3, pid: 0 };
        let mut data = [Data::default(); 2];
        // SAFETY: a header and two records of version 3, as capget(2) asks;
        // both live through the call.
        let rc = unsafe { libc::syscall(libc::SYS_capget, &mut header as *mut Header, data.as_mut_ptr()) };
        if rc == 0 {
            let join = |low: u32, high: u32| u64::from(low) | (u64::from(high) << 32);
            return Ok(Sets {
                effective: join(data[0].effective, data[1].effective),
                permitted: join(data[0].permitted, data[1].permitted),
                inheritable: join(data[0].inheritable, data[1].inheritable),
            });
        }
        let failed = errno();
        // The kernel's own words of this thread, where capget is refused.
        std::fs::read_to_string("/proc/thread-self/status").ok().and_then(|text| status_sets(&text)).ok_or(failed)
    }

    fn bounded(&mut self, cap: u32) -> Result<bool, i32> {
        match prctl(libc::PR_CAPBSET_READ, libc::c_ulong::from(cap)) {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(errno()),
        }
    }

    fn no_new_privs(&mut self) -> Result<(), i32> {
        match prctl(libc::PR_SET_NO_NEW_PRIVS, 1) {
            0 => Ok(()),
            _ => Err(errno()),
        }
    }

    fn bound_drop(&mut self, cap: u32) -> Result<(), i32> {
        match prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap)) {
            0 => Ok(()),
            _ => Err(errno()),
        }
    }

    fn clear(&mut self) -> Result<(), i32> {
        let mut header = Header { version: VERSION_3, pid: 0 };
        let data = [Data::default(); 2];
        // SAFETY: as in `sets`; the records are only read.
        let rc = unsafe { libc::syscall(libc::SYS_capset, &mut header as *mut Header, data.as_ptr()) };
        match rc {
            0 => Ok(()),
            _ => Err(errno()),
        }
    }
}

/// The effective uid, which the drop keeps.
pub fn euid() -> u32 {
    // SAFETY: geteuid(2) cannot fail.
    unsafe { libc::geteuid() }
}

/// How many threads this process has, and the ids of those whose
/// effective or permitted set is not empty, by `/proc/self/task`. A thread
/// whose status cannot be read as sets counts as one that holds some.
pub fn threads_holding() -> Result<(usize, Vec<String>), String> {
    let dir = std::fs::read_dir("/proc/self/task").map_err(|e| format!("/proc/self/task: {e}"))?;
    let (mut count, mut holding) = (0, Vec::new());
    for entry in dir.flatten() {
        // A thread that ended between the two reads holds nothing.
        let Ok(text) = std::fs::read_to_string(entry.path().join("status")) else { continue };
        count += 1;
        match status_sets(&text) {
            Some(sets) if (sets.effective | sets.permitted) == 0 => {}
            _ => holding.push(entry.file_name().to_string_lossy().into_owned()),
        }
    }
    Ok((count, holding))
}
