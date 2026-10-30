//! The keys of the broadcast that the terminal turns into signals (T-185):
//! the emergency stop, Ctrl-\ (SIGQUIT) on Unix and Ctrl-Break
//! (CTRL_BREAK_EVENT) on Windows, which acts at once, also while a line is
//! half typed; and Ctrl-C (SIGINT, or CTRL_C_EVENT), which goes to no host.
//! At either key the terminal itself drops the line that is half typed.
//!
//! Both are armed before the first host connects, and a broadcast whose
//! stop cannot be armed does not start. A SIGQUIT that was ignored when
//! podssh started (a script's `&` leaves it so) is armed too: the stop is
//! the one key that must always work.

/// A key that came.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Key {
    /// The emergency stop.
    Stop,
    /// Ctrl-C.
    Interrupt,
}

/// The two keys, armed on the runtime of the caller.
pub(super) struct Keys {
    #[cfg(unix)]
    stop: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(windows)]
    stop: tokio::signal::windows::CtrlBreak,
    #[cfg(windows)]
    interrupt: tokio::signal::windows::CtrlC,
}

impl Keys {
    /// Both keys, or why one cannot be armed.
    pub(super) fn arm() -> Result<Keys, String> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let stop = signal(SignalKind::quit()).map_err(|e| format!("SIGQUIT, the key Ctrl-\\: {e}"))?;
            let interrupt = signal(SignalKind::interrupt()).map_err(|e| format!("SIGINT, the key Ctrl-C: {e}"))?;
            Ok(Keys { stop, interrupt })
        }
        #[cfg(windows)]
        {
            let stop = tokio::signal::windows::ctrl_break().map_err(|e| format!("Ctrl-Break: {e}"))?;
            let interrupt = tokio::signal::windows::ctrl_c().map_err(|e| format!("Ctrl-C: {e}"))?;
            Ok(Keys { stop, interrupt })
        }
    }

    /// The next key; the stop first when both came. A handler that is gone
    /// gives its key no more.
    pub(super) async fn next(&mut self) -> Key {
        tokio::select! {
            biased;
            Some(()) = self.stop.recv() => Key::Stop,
            Some(()) = self.interrupt.recv() => Key::Interrupt,
            else => std::future::pending().await,
        }
    }
}
