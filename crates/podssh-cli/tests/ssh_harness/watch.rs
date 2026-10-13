//! A server that a test of several files at once watches (T-297): it counts
//! the SFTP sessions that one connection has at once, and keeps the most. For
//! a user `cut-N-...`, the first connection of the server ends after N bytes
//! of SFTP input with no word, as a link that drops; while [`Watch::refuse`]
//! is set, each later login of such a user is refused, so that the run ends
//! and leaves its side files for the next one.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::server;

use super::Far;

/// What the server saw, shared by its connections.
#[derive(Default)]
pub struct Watch {
    /// The most SFTP sessions that one connection had at once.
    pub most: AtomicUsize,
    /// Whether the first login of a user `cut-N-...` came.
    pub armed: AtomicBool,
    /// Refuse each later login of such a user.
    pub refuse: AtomicBool,
}

/// What a login gets on a watched server.
enum Armed {
    /// Nothing of the watch.
    No,
    /// The first login of a user `cut-N-...`: its connection ends after N
    /// bytes of SFTP input.
    Cut(u64),
    /// A later login of such a user, while the watch refuses them.
    Refused,
}

impl Watch {
    /// What a login of `user` gets.
    fn arm(&self, user: &str) -> Armed {
        let bytes = user.strip_prefix("cut-").and_then(|rest| rest.split('-').next()).and_then(|n| n.parse().ok());
        let Some(bytes) = bytes else { return Armed::No };
        if !self.armed.swap(true, Ordering::SeqCst) {
            return Armed::Cut(bytes);
        }
        if self.refuse.load(Ordering::SeqCst) {
            Armed::Refused
        } else {
            Armed::No
        }
    }
}

/// A connection on a watched server has `now` SFTP sessions.
pub(super) fn saw(watch: Option<&Watch>, now: usize) {
    if let Some(watch) = watch {
        watch.most.fetch_max(now, Ordering::SeqCst);
    }
}

/// A login of `user` on a watched server: whether it is refused. The first
/// login of a user `cut-N-...` sets `cut`, its connection's.
pub(super) fn refused(watch: Option<&Watch>, user: &str, cut: &mut Option<u64>) -> bool {
    match watch.map_or(Armed::No, |watch| watch.arm(user)) {
        Armed::Cut(bytes) => {
            *cut = Some(bytes);
            false
        }
        Armed::Refused => true,
        Armed::No => false,
    }
}

/// Count `n` bytes of SFTP input against the cut of a connection: true when
/// they reach it, and the connection ends.
pub(super) fn spend(cut: &mut Option<u64>, n: usize) -> bool {
    let Some(left) = cut.as_mut() else { return false };
    if *left > n as u64 {
        *left -= n as u64;
        return false;
    }
    *cut = None;
    true
}

/// The server of `start_counting`, whose connections share a [`Watch`]: its
/// port, the count of the TCP connections that it took, and the watch.
pub async fn start_watched(key: &Path) -> (u16, Arc<AtomicUsize>, Arc<Watch>) {
    let watch = Arc::new(Watch::default());
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    let mut config = server::Config::default();
    config.keys.push(russh::keys::load_secret_key(key, None).expect("the host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    let sftp_root = key.parent().map(Path::to_path_buf);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    let shared = watch.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let config = config.clone();
            let far = Far { sftp_root: sftp_root.clone(), watch: Some(shared.clone()), ..Far::default() };
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, far).await {
                    let _ = session.await;
                }
            });
        }
    });
    (port, connections, watch)
}
