//! The signals that end a session whose terminal is raw. Apart from the
//! session's loop (`crate::io`), so that each file stays short.

/// SIGTERM and SIGHUP while the terminal is raw: end the session properly so
/// the terminal is restored, instead of dying with it raw.
pub(crate) struct Termination {
    #[cfg(unix)]
    signals: Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>,
}

impl Termination {
    pub(crate) fn new(active: bool) -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let signals =
                if active { signal(SignalKind::terminate()).ok().zip(signal(SignalKind::hangup()).ok()) } else { None };
            Termination { signals }
        }
        #[cfg(not(unix))]
        {
            let _ = active;
            Termination {}
        }
    }

    pub(crate) async fn next(&mut self) {
        #[cfg(unix)]
        if let Some((term, hup)) = self.signals.as_mut() {
            tokio::select! {
                _ = term.recv() => return,
                _ = hup.recv() => return,
            }
        }
        std::future::pending::<()>().await
    }
}
