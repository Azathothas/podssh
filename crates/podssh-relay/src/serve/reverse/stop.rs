//! The planned stop of the role's reverse road (T-255): each socket of each
//! pair hears `1012 relay restarting` after what waits for it, and no socket
//! joins until the stop is over.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::outbox::Outbox;
use super::{Pair, Pairs};

/// While it lives, no socket joins a pair of the role; its end lets them in
/// again, also when the stop that held it was dropped half way.
pub struct Stopping<'a>(&'a AtomicBool);

impl Drop for Stopping<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Pairs {
    /// A planned stop (T-255): each socket of each pair gets `1012`, which
    /// its client tells from a lost link, after the frames that wait for it,
    /// the sessions' last bytes, for [`super::super::STOP_GRACE`]; a socket that has
    /// not taken them by then gets it before them. Then each socket ends at
    /// its peer's answer, so that the role's end is no reset, which can lose
    /// the Close at the peer (RFC 6455, section 7.1.1). No socket joins
    /// meanwhile, and the pairs stay, in the file too. Whether each Close
    /// went out and each socket ended within `limit`, the whole wait.
    pub async fn restart(&self, limit: Duration) -> bool {
        self.restart_with(super::super::STOP_GRACE.min(limit), limit).await
    }

    pub(super) async fn restart_with(&self, grace: Duration, limit: Duration) -> bool {
        let until = Instant::now() + limit;
        let _held = self.hold_joins();
        for socket in self.sockets() {
            socket.close(super::super::RESTART, super::super::RESTARTING);
        }
        if !self.writers.settled(grace).await {
            // Each socket again, so that one that joined as the stop began
            // hears it too.
            for socket in self.sockets() {
                socket.abort(super::super::RESTART, super::super::RESTARTING);
            }
        }
        let left = || until.saturating_duration_since(Instant::now());
        self.writers.settled(left()).await && self.live.settled(left()).await
    }

    /// The writer of each socket of each pair: each operator's before its
    /// node's, so that no operator hears `node disconnected` first.
    fn sockets(&self) -> Vec<Outbox> {
        let pairs: Vec<Arc<Pair>> = self.map.lock().unwrap_or_else(|e| e.into_inner()).values().cloned().collect();
        let mut sockets = Vec::new();
        for pair in pairs {
            let state = pair.lock();
            sockets.extend(state.sessions.values().map(|session| session.operator.clone()));
            sockets.extend(state.node_outbox());
        }
        sockets
    }

    /// No socket joins until the guard ends: a planned stop's.
    pub(in crate::serve::reverse) fn hold_joins(&self) -> Stopping<'_> {
        self.stopping.store(true, Ordering::SeqCst);
        Stopping(&self.stopping)
    }

    /// Whether a planned stop runs, so that a socket must not join.
    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
}
