//! The signals that end a session: SIGTERM and SIGHUP while the terminal is
//! raw, and Ctrl-C with no remote pty (T-293). Apart from the session's loop
//! (`crate::io`), so that each file stays short. Here too, the `signal INT`
//! that a caller who feeds the input asks for (T-185), which ends nothing.

use russh::client::Msg;
use russh::{ChannelWriteHalf, Sig};

use super::interrupt::{Interrupt, Step};
use crate::io::{End, Feed};
use crate::log::Log;

/// What a signal asks of the session.
pub(crate) enum Stop {
    /// SIGTERM or SIGHUP: end it, so that the terminal is restored. Unix
    /// only: Windows has neither signal.
    #[cfg(unix)]
    Terminated,
    /// Ctrl-C with no remote pty, or the end of the wait after one.
    Interrupt(Step),
    /// The caller asked for `signal INT` on the channel (`podssh each
    /// --interactive`'s `:intr`): sent, and the session goes on.
    Asked,
}

/// SIGTERM and SIGHUP while the terminal is raw: end the session properly so
/// the terminal is restored, instead of dying with it raw. And the session's
/// Ctrl-C, when it has one.
pub(crate) struct Termination {
    #[cfg(unix)]
    signals: Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>,
    interrupt: Option<Interrupt>,
    /// The input that the caller feeds, with its `signal INT` requests.
    feed: Option<Feed>,
}

impl Termination {
    pub(crate) fn new(active: bool, interrupt: Option<Interrupt>) -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let signals =
                if active { signal(SignalKind::terminate()).ok().zip(signal(SignalKind::hangup()).ok()) } else { None };
            Termination { signals, interrupt, feed: None }
        }
        #[cfg(not(unix))]
        {
            let _ = active;
            Termination { interrupt, feed: None }
        }
    }

    /// With the `signal INT` requests of `feed`, when the caller feeds the
    /// session's input.
    pub(crate) fn fed(mut self, feed: Option<Feed>) -> Self {
        self.feed = feed;
        self
    }

    pub(crate) async fn next(&mut self) -> Stop {
        #[cfg(unix)]
        if let Some((term, hup)) = self.signals.as_mut() {
            return tokio::select! {
                _ = term.recv() => Stop::Terminated,
                _ = hup.recv() => Stop::Terminated,
                step = Interrupt::next(&mut self.interrupt) => Stop::Interrupt(step),
                () = asked(self.feed.as_ref()) => Stop::Asked,
            };
        }
        tokio::select! {
            step = Interrupt::next(&mut self.interrupt) => Stop::Interrupt(step),
            () = asked(self.feed.as_ref()) => Stop::Asked,
        }
    }

    /// Does what `stop` asks: `Some` with the session's end when it ends.
    pub(crate) async fn act(&mut self, stop: Stop, writer: &ChannelWriteHalf<Msg>, log: &Log) -> Option<End> {
        match stop {
            #[cfg(unix)]
            Stop::Terminated => Some(End::Terminated),
            Stop::Interrupt(step) => self.interrupt.as_mut()?.act(step, writer, log).await,
            Stop::Asked => {
                // A server may ignore it (`docs/terminal.md`): the session
                // goes on either way.
                match writer.signal(Sig::INT).await {
                    Ok(()) => log.verbose("signal INT sent, as asked"),
                    Err(e) => log.info(&format!("signal INT could not be sent: {e}")),
                }
                None
            }
        }
    }
}

/// The caller's next `signal INT` request; never with no feed.
async fn asked(feed: Option<&Feed>) {
    match feed {
        Some(feed) => feed.interrupted().await,
        None => std::future::pending().await,
    }
}
