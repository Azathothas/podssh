//! `podssh` on the test's server (T-167): a command that starts with
//! `podssh ` runs the binary under test, with the words of the command
//! (single quotes as a POSIX shell reads them), the environment that the
//! test gave, and `SSH_CONNECTION` naming this server, as sshd sets it. Its
//! stdout and stderr go to the channel as they come, and its status at the
//! end; each argv is kept for the test to read. A program that the test's
//! runtime still runs at its end is killed.

use std::process::Stdio;
use std::sync::{Arc, Mutex};

use russh::server::{Handle, Session};
use russh::ChannelId;
use tokio::io::{AsyncRead, AsyncReadExt};

/// What a server that runs podssh gives each command.
#[derive(Default)]
pub struct Podssh {
    pub env: Vec<(String, String)>,
    /// The argv of each podssh that ran, in order.
    pub argv: Arc<Mutex<Vec<Vec<String>>>>,
}

impl Podssh {
    /// The same, with `SSH_CONNECTION` for a server on `port`.
    pub(super) fn on(mut self, port: u16) -> Podssh {
        self.env.push(("SSH_CONNECTION".into(), format!("127.0.0.1 40000 127.0.0.1 {port}")));
        self
    }
}

/// Run `command` when it is podssh's, on a server that runs podssh; `None`
/// else.
pub(super) fn run(
    podssh: Option<&Arc<Podssh>>,
    command: &str,
    channel: ChannelId,
    session: &mut Session,
) -> Option<Result<(), russh::Error>> {
    let podssh = podssh?;
    let words = words(command.strip_prefix("podssh ")?);
    podssh.argv.lock().unwrap().push(words.clone());
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(&words).envs(podssh.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    for name in ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "PODSSH_OFFLINE"] {
        cmd.env_remove(name);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            let ended = session
                .extended_data(channel, 1, format!("sh: podssh: {e}\n").into_bytes())
                .and_then(|()| session.exit_status_request(channel, 127))
                .and_then(|()| session.eof(channel))
                .and_then(|()| session.close(channel));
            return Some(ended);
        }
    };
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
    Some(Ok(()))
}

/// Each byte of `from` to the channel, as stdout or as stderr (`ext`). A
/// channel that is gone takes none, but the pipe is read to its end, so the
/// program never writes to a closed pipe.
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

/// The words of a command as a POSIX shell splits them: at spaces, with
/// single quotes kept whole.
fn words(text: &str) -> Vec<String> {
    let (mut out, mut word, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
    for c in text.chars() {
        match c {
            '\'' => {
                quoted = !quoted;
                any = true;
            }
            ' ' if !quoted => {
                if any {
                    out.push(std::mem::take(&mut word));
                    any = false;
                }
            }
            c => {
                word.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(word);
    }
    out
}
