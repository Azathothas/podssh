//! The server of the tests on the loopback: a [`Far`] for each connection,
//! with the host key in a file, and the directory of that file for the
//! subsystem `sftp` (T-140), or a home of the test's (T-193).

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::server;

use super::podssh::Podssh;
use super::shell::Shell;
use super::Far;

/// The server on the loopback, with the host key in `key`, on the current
/// runtime: its port.
pub async fn start(key: &Path) -> u16 {
    start_counting(key).await.0
}

/// [`start`], with the count of the TCP connections that the server took.
pub async fn start_counting(key: &Path) -> (u16, Arc<AtomicUsize>) {
    start_with(key, Vec::new()).await
}

/// [`start_counting`], with host certificates of the key that the server
/// presents to a client that asks for one (T-027).
pub async fn start_with(key: &Path, certificates: Vec<russh::keys::Certificate>) -> (u16, Arc<AtomicUsize>) {
    start_far(key, certificates, None, None).await
}

/// [`start_counting`], with each command `podssh ...` run as the binary
/// under test (T-167), with what `podssh` gives.
pub async fn start_podssh(key: &Path, podssh: Podssh) -> (u16, Arc<AtomicUsize>) {
    start_far(key, Vec::new(), Some(podssh), None).await
}

/// [`start_counting`], with each command run in sh as `shell` says, and
/// the subsystem `sftp` in its home (T-193).
pub async fn start_shell(key: &Path, shell: Shell) -> (u16, Arc<AtomicUsize>) {
    start_far(key, Vec::new(), None, Some(shell)).await
}

async fn start_far(
    key: &Path,
    certificates: Vec<russh::keys::Certificate>,
    podssh: Option<Podssh>,
    shell: Option<Shell>,
) -> (u16, Arc<AtomicUsize>) {
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    let mut config = server::Config::default();
    config.keys.push(russh::keys::load_secret_key(key, None).expect("the host key"));
    config.certificates = certificates;
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    let sftp_root = shell.as_ref().map(|s| s.home.clone()).or_else(|| key.parent().map(Path::to_path_buf));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    let podssh = podssh.map(|podssh| Arc::new(podssh.on(port)));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let config = config.clone();
            let (sftp_root, podssh, shell) = (sftp_root.clone(), podssh.clone(), shell.clone());
            let far = Far { sftp_root, podssh, shell, ..Far::default() };
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, far).await {
                    let _ = session.await;
                }
            });
        }
    });
    (port, connections)
}
