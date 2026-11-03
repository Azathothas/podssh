//! The soft limit of open files (T-564). `cp --parallel`, `each`, `job`,
//! `session` and `-L` hold a descriptor each, and a shell of macOS starts
//! at 256, so podssh raises its own soft limit at start, within the hard
//! limit that the host set: no privilege is needed, and the answer of the
//! call is the probe. A host that refuses keeps its limit, with a line at
//! `-v`, never an error; an error of too many open files names the limit.
//! Windows, whose handles have no such soft limit, does nothing.

use std::sync::OnceLock;

/// The highest soft limit that podssh asks for. Each program that podssh
/// starts inherits it, and a container's hard limit can be 2^30, which
/// slows a program that closes each descriptor up to its limit; a run of
/// podssh needs far fewer.
pub const CAP: u64 = 65_536;

/// A hard limit at or above this is no limit (`RLIM_INFINITY`: 2^64 - 1 on
/// Linux, 2^63 - 1 on macOS).
const UNLIMITED: u64 = 1 << 62;

/// What the start found, and what it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The soft limit that the process started with.
    pub at_start: u64,
    /// The soft limit now.
    pub soft: u64,
    /// The hard limit, which no process raises without a privilege.
    pub hard: u64,
    /// The error number of the host's refusal, when it refused the raise.
    pub refused: Option<i32>,
}

impl Limits {
    /// The hard limit, `None` for none.
    pub fn hard_limit(&self) -> Option<u64> {
        (self.hard < UNLIMITED).then_some(self.hard)
    }

    /// Whether the start raised the soft limit.
    pub fn raised(&self) -> bool {
        self.soft > self.at_start
    }

    /// The line of `-v`, said once.
    pub fn line(&self) -> String {
        let hard = self.hard_limit().map_or("none".to_string(), |n| n.to_string());
        match self.refused {
            Some(errno) => format!(
                "open file limit: {}, kept: the host refused more ({}); the hard limit is {hard}",
                self.soft,
                std::io::Error::from_raw_os_error(errno)
            ),
            None if self.raised() => format!("open file limit: {} -> {}", self.at_start, self.soft),
            None if self.soft >= self.hard => format!("open file limit: {}, the hard limit of this host", self.soft),
            None => format!("open file limit: {}, as many as podssh asks for (the hard limit is {hard})", self.soft),
        }
    }

    /// The line after an error of too many open files.
    pub fn hint(&self) -> String {
        let hard = self.hard_limit().map_or("none".to_string(), |n| n.to_string());
        format!(
            "this process may hold {} open files (its soft limit; the hard limit is {hard}): fewer at once, or a \
             higher limit where podssh starts (ulimit -n, ulimit -Hn), helps",
            self.soft
        )
    }
}

/// The soft limit to ask for, from the soft and hard limits and, on macOS,
/// the kernel's limit for each process: the hard limit within [`CAP`], and
/// never lower than now.
pub fn target(soft: u64, hard: u64, per_process: Option<u64>) -> u64 {
    hard.min(CAP).min(per_process.unwrap_or(u64::MAX)).max(soft)
}

static LIMITS: OnceLock<Option<Limits>> = OnceLock::new();

/// Raise the soft limit, once, at the start of the binary: its line goes to
/// the first log at `-v`, and an error of too many open files names it.
pub fn start() {
    let Some(limits) = *LIMITS.get_or_init(platform::raise) else { return };
    podssh_ssh::log::say_once_at_verbose(limits.line());
    podssh_ssh::log::hint_errors(hint);
}

/// What the start found, or the limits read now when it did not run (a
/// test of the library); `None` on Windows, or where the read fails.
pub fn limits() -> Option<Limits> {
    LIMITS.get().copied().flatten().or_else(platform::read)
}

/// The hint of an error line of too many open files for this process
/// (`EMFILE`), not for the whole system (`ENFILE`, "in system").
fn hint(message: &str) -> Option<String> {
    let code = platform::EMFILE.is_some_and(|code| message.contains(&format!("(os error {code})")));
    let words = message.contains("Too many open files") && !message.contains("in system");
    if !(code || words) {
        return None;
    }
    limits().map(|limits| limits.hint())
}

#[cfg(unix)]
#[path = "nofile_unix.rs"]
mod platform;

#[cfg(not(unix))]
mod platform {
    pub(super) const EMFILE: Option<i32> = None;

    pub(super) fn raise() -> Option<super::Limits> {
        None
    }

    pub(super) fn read() -> Option<super::Limits> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hard limit within the cap, never lower than now, and within the
    /// kernel's limit of macOS.
    #[test]
    fn the_target_is_the_hard_limit_within_the_cap_and_never_lower() {
        assert_eq!(target(256, u64::MAX, None), CAP, "no hard limit: the cap");
        assert_eq!(target(256, 10_240, None), 10_240);
        assert_eq!(target(64, 64, None), 64, "the hard limit is the soft one");
        assert_eq!(target(1_048_576, 1_048_576, None), 1_048_576, "never lower than now");
        assert_eq!(target(256, u64::MAX, Some(24_576)), 24_576, "the kernel's limit for each process");
        assert_eq!(target(256, 1 << 30, None), CAP, "a container's hard limit");
    }

    /// The line of -v for each case, and the hint names the limit.
    #[test]
    fn the_line_says_what_the_start_did() {
        let raised = Limits { at_start: 256, soft: 10_240, hard: u64::MAX, refused: None };
        assert_eq!(raised.line(), "open file limit: 256 -> 10240");
        assert_eq!(raised.hard_limit(), None);
        let at_hard = Limits { at_start: 64, soft: 64, hard: 64, refused: None };
        assert_eq!(at_hard.line(), "open file limit: 64, the hard limit of this host");
        let at_cap = Limits { at_start: CAP, soft: CAP, hard: 1 << 20, refused: None };
        assert!(at_cap.line().contains("as many as podssh asks for (the hard limit is 1048576)"), "{}", at_cap.line());
        let refused = Limits { at_start: 256, soft: 256, hard: 4096, refused: Some(1) }.line();
        assert!(refused.starts_with("open file limit: 256, kept: the host refused more ("), "{refused}");
        assert!(raised.hint().starts_with("this process may hold 10240 open files"), "{}", raised.hint());
    }

    /// An error of too many open files of this process gets the hint; one
    /// of the whole system, or another error, does not.
    #[cfg(unix)]
    #[test]
    fn only_too_many_open_files_of_this_process_gets_the_hint() {
        let emfile = std::io::Error::from_raw_os_error(libc::EMFILE).to_string();
        let hinted = hint(&format!("cannot open a.txt: {emfile}"));
        assert!(hinted.as_deref().is_some_and(|h| h.starts_with("this process may hold")), "{emfile}: {hinted:?}");
        let enfile = std::io::Error::from_raw_os_error(libc::ENFILE).to_string();
        assert_eq!(hint(&format!("cannot open a.txt: {enfile}")), None, "{enfile}");
        assert_eq!(hint("connection refused"), None);
    }
}
