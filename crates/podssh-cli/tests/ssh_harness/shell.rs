//! A server of `start_shell` (T-193): each command runs as a POSIX host
//! runs it, `sh -c COMMAND`, in the home directory that the test gives, with
//! that home, PATH, `SHELL=/bin/sh` and a directory of tmux's sockets of
//! the test's own, so that its tmux server is no one else's. The channel's
//! data is the command's stdin, and its end the end of that input; its
//! stdout and stderr go to the channel as they come, and its status at the
//! end. On Unix only: a host of the far script has a POSIX sh.

use std::path::PathBuf;
use std::process::Stdio;

use russh::server::{Handle, Session};
use russh::ChannelId;
use tokio::io::{AsyncRead, AsyncReadExt};

/// What each command of a server of `start_shell` gets.
#[derive(Debug, Clone)]
pub struct Shell {
    /// Its working directory and HOME, which is also where the subsystem
    /// sftp runs, so that the files of a copy and of a command are one.
    pub home: PathBuf,
    /// Its PATH.
    pub path: String,
}

/// Run `command` with `sh -c`, and give its stdin, which takes the
/// channel's data; `None` when sh did not start, which the channel says
/// with the status 127.
pub(super) fn run(
    shell: &Shell,
    command: &str,
    channel: ChannelId,
    session: &mut Session,
) -> Result<Option<tokio::process::ChildStdin>, russh::Error> {
    let spawned = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .current_dir(&shell.home)
        .env_clear()
        .env("HOME", &shell.home)
        .env("PATH", &shell.path)
        .env("SHELL", "/bin/sh")
        .env("TMUX_TMPDIR", &shell.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            session.extended_data(channel, 1, format!("sh: {e}\n").into_bytes())?;
            session.exit_status_request(channel, 127)?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(None);
        }
    };
    let stdin = child.stdin.take();
    let (out, err) = (child.stdout.take(), child.stderr.take());
    let (to_out, to_err, end) = (session.handle(), session.handle(), session.handle());
    tokio::spawn(async move {
        let (out, err) = (pump(out, to_out, channel, None), pump(err, to_err, channel, Some(1)));
        let (_, _, status) = tokio::join!(out, err, child.wait());
        let code = status.ok().and_then(|s| s.code()).unwrap_or(255);
        let _ = end.exit_status_request(channel, u32::try_from(code).unwrap_or(255)).await;
        let _ = end.eof(channel).await;
        let _ = end.close(channel).await;
    });
    Ok(stdin)
}

/// Each byte of `from` to the channel, as stdout or as stderr (`ext`), to
/// the end of the pipe.
async fn pump(from: Option<impl AsyncRead + Unpin>, handle: Handle, channel: ChannelId, ext: Option<u32>) {
    let Some(mut from) = from else { return };
    let mut buf = vec![0u8; 16 * 1024];
    while let Ok(n) = from.read(&mut buf).await {
        if n == 0 {
            return;
        }
        let data = buf[..n].to_vec();
        let _ = match ext {
            Some(ext) => handle.extended_data(channel, ext, data).await,
            None => handle.data(channel, data).await,
        };
    }
}
