//! What the pump of a session waits for besides its bytes: a change of the
//! window's size, and the signals that end a session on a raw terminal.

use super::Size;

/// Window-size changes: SIGWINCH on Unix, polling on Windows (a console has
/// no signal for it).
pub(crate) struct Resize {
    active: bool,
    last: Option<Size>,
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
    #[cfg(windows)]
    tick: tokio::time::Interval,
}

impl Resize {
    pub(crate) fn new(active: bool) -> Self {
        Resize {
            active,
            last: super::size(),
            #[cfg(unix)]
            signal: if active {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
            } else {
                None
            },
            #[cfg(windows)]
            tick: tokio::time::interval(std::time::Duration::from_millis(500)),
        }
    }

    pub(crate) async fn next(&mut self) -> Option<Size> {
        if !self.active {
            return std::future::pending().await;
        }
        loop {
            #[cfg(unix)]
            match self.signal.as_mut() {
                Some(s) => {
                    s.recv().await?;
                }
                None => return std::future::pending().await,
            }
            #[cfg(windows)]
            self.tick.tick().await;
            let now = super::size();
            if now.is_some() && now != self.last {
                self.last = now;
                return now;
            }
        }
    }
}
