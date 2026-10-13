//! Ctrl-C in a session with no remote pty (T-293). The local terminal keeps
//! its own mode there, so Ctrl-C is SIGINT to podssh, or CTRL_C_EVENT in a
//! Windows console, and not a byte for the server. Before, it ended podssh
//! and left the command running on the server. Now the first one sends
//! `signal INT` (RFC 4254, section 6.9) and waits [`WAIT`] for the channel's
//! end: OpenSSH's sshd ends the command and its process group by it, and
//! Dropbear the process that it started (`docs/terminal.md`, "Ctrl-C with no
//! remote pty"); the command's signal is then the exit code, as for each
//! command. A second Ctrl-C, or the end of the wait, ends podssh with
//! [`INTERRUPTED`]. `--no-signal` keeps OpenSSH's way: no handler, and
//! Ctrl-C ends podssh at once.

use std::sync::OnceLock;
use std::time::Duration;

use russh::client::Msg;
use russh::{ChannelWriteHalf, Sig};

use crate::io::End;
use crate::log::Log;

/// How long the command has to end after `signal INT`.
pub const WAIT: Duration = Duration::from_secs(2);

/// The exit code of a session that Ctrl-C ended here: 128 + SIGINT's 2, as a
/// shell reports a process that SIGINT ended.
pub const INTERRUPTED: i32 = 130;

/// What came: a Ctrl-C, or the end of the wait after the first one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// SIGINT, or CTRL_C_EVENT.
    CtrlC,
    /// [`WAIT`] passed after the request, and the channel did not end.
    WaitOver,
}

/// Ctrl-C of one session, from its start to its end.
#[derive(Debug)]
pub struct Interrupt {
    #[cfg(unix)]
    signal: tokio::signal::unix::Signal,
    #[cfg(windows)]
    signal: tokio::signal::windows::CtrlC,
    /// The end of the wait after the request; `None` before the first Ctrl-C.
    until: Option<tokio::time::Instant>,
}

impl Interrupt {
    /// The handler of a session, when `wanted`: it runs a command or a shell
    /// with no remote pty, and `--no-signal` was not given. None where
    /// SIGINT was ignored when podssh started, which it then stays, as in
    /// OpenSSH's client; and where no handler can be set.
    pub fn for_session(wanted: bool) -> Option<Interrupt> {
        if !wanted || ignored_at_start() {
            return None;
        }
        #[cfg(unix)]
        let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok()?;
        #[cfg(windows)]
        let signal = tokio::signal::windows::ctrl_c().ok()?;
        Some(Interrupt { signal, until: None })
    }

    /// The next Ctrl-C, or the end of the wait after the first; never with
    /// no handler.
    pub async fn next(interrupt: &mut Option<Interrupt>) -> Step {
        let Some(this) = interrupt.as_mut() else { return std::future::pending().await };
        let until = this.until;
        tokio::select! {
            got = this.signal.recv() => match got {
                Some(()) => Step::CtrlC,
                // The handler is gone: Ctrl-C can come no more.
                None => std::future::pending().await,
            },
            () = tokio::time::sleep_until(until.unwrap_or_else(tokio::time::Instant::now)), if until.is_some() => {
                Step::WaitOver
            }
        }
    }

    /// Does what `step` asks: the first Ctrl-C sends `signal INT` and starts
    /// the wait; a second, or the wait's end, ends the session.
    pub async fn act(&mut self, step: Step, writer: &ChannelWriteHalf<Msg>, log: &Log) -> Option<End> {
        match (step, self.until) {
            (Step::CtrlC, None) => {
                self.until = Some(tokio::time::Instant::now() + WAIT);
                if let Err(e) = writer.signal(Sig::INT).await {
                    log.verbose(&format!("Ctrl-C: signal INT could not be sent ({e}); ending the session"));
                    return Some(End::Interrupted);
                }
                log.verbose(&format!("Ctrl-C: signal INT sent; the command has {} s to end", WAIT.as_secs()));
                None
            }
            (Step::CtrlC, Some(_)) => {
                log.verbose("Ctrl-C again: ending the session");
                Some(End::Interrupted)
            }
            (Step::WaitOver, _) => {
                log.verbose(&format!("Ctrl-C: the command did not end within {} s", WAIT.as_secs()));
                Some(End::Interrupted)
            }
        }
    }
}

/// Whether SIGINT was ignored when podssh started, as a shell with no job
/// control leaves it for a command that it starts with `&`. Read once, at
/// the first session, before podssh sets a handler of its own. A Windows
/// process that ignores Ctrl-C gets no event at all, so it needs no check.
fn ignored_at_start() -> bool {
    static IGNORED: OnceLock<bool> = OnceLock::new();
    *IGNORED.get_or_init(|| {
        #[cfg(unix)]
        {
            // SAFETY: a plain C struct, whose zero is a valid value.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: a query: no action is set, and `old` is only written.
            let read = unsafe { libc::sigaction(libc::SIGINT, std::ptr::null(), &mut old) };
            read == 0 && old.sa_sigaction == libc::SIG_IGN
        }
        #[cfg(not(unix))]
        {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_is_short_and_the_code_is_a_shell_s_for_sigint() {
        assert_eq!(WAIT, Duration::from_secs(2));
        assert_eq!(INTERRUPTED, 128 + 2);
    }

    #[test]
    fn no_handler_is_set_when_it_is_not_wanted() {
        assert!(Interrupt::for_session(false).is_none());
    }
}
