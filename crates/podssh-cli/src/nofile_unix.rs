//! The limit of open files on Unix: `getrlimit` and `setrlimit` of
//! `RLIMIT_NOFILE`, and on macOS the kernel's limit for each process.

use super::{target, Limits};

/// The error of too many open files for this process.
pub(super) const EMFILE: Option<i32> = Some(libc::EMFILE);

/// macOS's `OPEN_MAX` (`<sys/syslimits.h>`): its `setrlimit(2)` says to ask
/// for no more than it, and an older release refuses more.
#[cfg(target_os = "macos")]
const OPEN_MAX: u64 = 10_240;

// `rlim_t` is u64 on Linux and macOS, and i64 on the BSDs: one cast each way.
#[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)]
fn to_u64(value: libc::rlim_t) -> u64 {
    value as u64
}

#[allow(clippy::unnecessary_cast, clippy::cast_possible_wrap)]
fn from_u64(value: u64) -> libc::rlim_t {
    value as libc::rlim_t
}

/// The soft and hard limits now.
fn get() -> Option<(u64, u64)> {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: a read of this process's limit into a struct of its own.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0;
    read.then(|| (to_u64(limit.rlim_cur), to_u64(limit.rlim_max)))
}

/// Ask for a soft limit of `soft`, the hard one kept; the error number of a
/// refusal.
fn set(soft: u64, hard: u64) -> Result<(), i32> {
    let limit = libc::rlimit { rlim_cur: from_u64(soft), rlim_max: from_u64(hard) };
    // SAFETY: a change of this process's own limit, within its hard limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// The kernel's limit of open files for each process (`kern.maxfilesperproc`),
/// which a soft limit of macOS may not pass.
#[cfg(target_os = "macos")]
fn per_process() -> Option<u64> {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let name = c"kern.maxfilesperproc";
    // SAFETY: a read of one int that the kernel names, into a buffer of its size.
    let read =
        unsafe { libc::sysctlbyname(name.as_ptr(), (&raw mut value).cast(), &mut size, std::ptr::null_mut(), 0) } == 0;
    (read && value > 0).then(|| u64::from(value.unsigned_abs()))
}

#[cfg(not(target_os = "macos"))]
fn per_process() -> Option<u64> {
    None
}

/// What to ask for, in turn: the target; on macOS, `OPEN_MAX` too, where an
/// older release refuses more.
fn asks(want: u64, soft: u64) -> Vec<u64> {
    let mut asks = vec![want];
    #[cfg(target_os = "macos")]
    asks.push(want.min(OPEN_MAX));
    asks.dedup();
    asks.retain(|ask| *ask > soft);
    asks
}

/// The limits now, as the start would find them with nothing raised.
pub(super) fn read() -> Option<Limits> {
    let (soft, hard) = get()?;
    Some(Limits { at_start: soft, soft, hard, refused: None })
}

/// Raise the soft limit to the target, each ask in turn; the limit is read
/// again after a raise, as the host's answer. `None` when it cannot be read.
pub(super) fn raise() -> Option<Limits> {
    let (soft, hard) = get()?;
    let mut refused = None;
    for ask in asks(target(soft, hard, per_process()), soft) {
        match set(ask, hard) {
            Ok(()) => {
                let now = get().map_or(ask, |(now, _)| now);
                return Some(Limits { at_start: soft, soft: now, hard, refused: None });
            }
            Err(errno) => refused = Some(errno),
        }
    }
    Some(Limits { at_start: soft, soft, hard, refused })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A target at the soft limit asks nothing; macOS asks OPEN_MAX after a
    /// refusal of more.
    #[test]
    fn the_asks_go_up_and_never_down() {
        assert!(asks(64, 64).is_empty(), "nothing to raise");
        assert_eq!(asks(4096, 256)[0], 4096);
        #[cfg(target_os = "macos")]
        assert_eq!(asks(65_536, 256), [65_536, OPEN_MAX]);
        #[cfg(not(target_os = "macos"))]
        assert_eq!(asks(65_536, 256), [65_536]);
    }

    /// The limits of this test process read, the soft one within the hard.
    #[test]
    fn the_limits_of_this_process_read() {
        let limits = read().expect("getrlimit answers");
        assert!(limits.soft <= limits.hard, "{limits:?}");
        assert!(!limits.raised());
    }
}
