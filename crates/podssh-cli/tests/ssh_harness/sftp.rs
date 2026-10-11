//! The `sftp` subsystem of the test's server (T-140): OpenSSH's
//! `sftp-server`, found as `tests/sftp_client.rs` finds it
//! (`PODSSH_TEST_SFTP_SERVER`, else a usual place), run in the directory of
//! the server's host key, with its pipes joined to the channel. With no
//! `sftp-server` here, the subsystem is refused, as a server with none
//! refuses it.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use russh::server::Session;
use russh::ChannelId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const USUAL: &[&str] = &[
    "/usr/lib/ssh/sftp-server",
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    r"C:\Program Files\Git\usr\lib\ssh\sftp-server.exe",
];

/// The `sftp-server` of this machine, if one is found.
pub fn server_path() -> Option<PathBuf> {
    match std::env::var_os("PODSSH_TEST_SFTP_SERVER") {
        Some(named) => Some(PathBuf::from(named)).filter(|p| p.is_file()),
        None => USUAL.iter().map(PathBuf::from).find(|p| p.is_file()),
    }
}

/// Start the subsystem `name` on `channel` in `root`: true when it runs, and
/// its stdin, which takes the channel's data.
pub(super) fn start(
    name: &str,
    root: Option<&Path>,
    channel: ChannelId,
    session: &mut Session,
) -> Result<Option<tokio::process::ChildStdin>, russh::Error> {
    let child = match (name, root, server_path()) {
        ("sftp", Some(root), Some(program)) => tokio::process::Command::new(program)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok(),
        _ => None,
    };
    let Some(mut child) = child else {
        session.channel_failure(channel)?;
        return Ok(None);
    };
    session.channel_success(channel)?;
    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("the server's stdout");
    let handle = session.handle();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok(n) = stdout.read(&mut buf).await {
            if n == 0 || handle.data(channel, buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
        let code = child.wait().await.ok().and_then(|s| s.code()).unwrap_or(1);
        let _ = handle.exit_status_request(channel, code as u32).await;
        let _ = handle.eof(channel).await;
        let _ = handle.close(channel).await;
    });
    Ok(stdin)
}

/// Data from the client to the server's stdin.
pub(super) async fn input(stdin: &mut tokio::process::ChildStdin, data: &[u8]) {
    let _ = stdin.write_all(data).await;
}
