//! The signals that end a session: SIGTERM and SIGHUP while the terminal is
//! raw, and Ctrl-C with no remote pty (T-293). Apart from the session's loop
//! (`crate::io`), so that each file stays short.

use russh::client::Msg;
use russh::ChannelWriteHalf;

use super::interrupt::{Interrupt, Step};
use crate::io::End;
use crate::log::Log;

/// What a signal asks of the session.
pub(crate) enum Stop {
    /// SIGTERM or SIGHUP: end it, so that the terminal is restored. Unix
    /// only: Windows has neither signal.
    #[cfg(unix)]
    Terminated,
    /// Ctrl-C with no remote pty, or the end of the wait after one.
    Interrupt(Step),
}

/// SIGTERM and SIGHUP while the terminal is raw: end the session properly so
/// the terminal is restored, instead of dying with it raw. And the session's
/// Ctrl-C, when it has one.
pub(crate) struct Termination {
    #[cfg(unix)]
    signals: Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>,
    interrupt: Option<Interrupt>,
}

impl Termination {
    pub(crate) fn new(active: bool, interrupt: Option<Interrupt>) -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let signals =
                if active { signal(SignalKind::terminate()).ok().zip(signal(SignalKind::hangup()).ok()) } else { None };
            Termination { signals, interrupt }
        }
        #[cfg(not(unix))]
        {
            let _ = active;
            Termination { interrupt }
        }
    }

    pub(crate) async fn next(&mut self) -> Stop {
        #[cfg(unix)]
        if let Some((term, hup)) = self.signals.as_mut() {
            return tokio::select! {
                _ = term.recv() => Stop::Terminated,
                _ = hup.recv() => Stop::Terminated,
                step = Interrupt::next(&mut self.interrupt) => Stop::Interrupt(step),
            };
        }
        Stop::Interrupt(Interrupt::next(&mut self.interrupt).await)
    }

    /// Does what `stop` asks: `Some` with the session's end when it ends.
    pub(crate) async fn act(&mut self, stop: Stop, writer: &ChannelWriteHalf<Msg>, log: &Log) -> Option<End> {
        match stop {
            #[cfg(unix)]
            Stop::Terminated => Some(End::Terminated),
            Stop::Interrupt(step) => self.interrupt.as_mut()?.act(step, writer, log).await,
        }
    }
}
