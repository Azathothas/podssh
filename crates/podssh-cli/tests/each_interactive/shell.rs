//! The test's SSH server for the broadcast (T-185): a russh server on the
//! loopback that lets anyone in and gives a shell with no pty, which reads
//! a line at a time as a shell on a pipe does: `echo WORDS` prints WORDS;
//! `touch PATH` makes the file `PATH.USER`, so that each host leaves a file
//! of its own; a line that starts with `#` does nothing; any other line
//! comes back on stderr after a `?`. At the end of its input the shell
//! prints `N lines` and exits 0. Each `signal` request is written into
//! `signals.USER` beside the host key, and the shell runs on. For a user
//! named `stall-...`, the shell reads nothing for [`STALL`] from the first
//! bytes after its first line: its window of [`WINDOW`] then runs out, and
//! what a client sends meanwhile waits on the client's side. (What a
//! handler of russh writes goes out when it returns, so the answer to the
//! first line comes before the stall.)
//!
//! A server of its own, not `ssh_harness`'s: that one runs commands and
//! gives no shell.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, Sig};

/// How long the shell of a user `stall-...` reads nothing.
pub const STALL: Duration = Duration::from_secs(5);

/// The window of each channel: small, so that a stalled shell stops a
/// client soon.
pub const WINDOW: u32 = 16 * 1024;

/// One shell: the start of a line with no end yet, and the lines read.
#[derive(Default)]
struct Shell {
    partial: Vec<u8>,
    lines: usize,
}

/// One connection.
struct Far {
    user: String,
    /// The directory of the host key, where `signals.USER` goes.
    dir: PathBuf,
    shells: HashMap<ChannelId, Shell>,
    /// Whether a `stall-...` shell has had its stall.
    stalled: bool,
}

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.user = user.to_string();
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.shells.insert(channel, Shell::default());
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let Some(shell) = self.shells.get_mut(&channel) else { return Ok(()) };
        // After its first line, whose answer went out as this returned.
        if self.user.starts_with("stall-") && shell.lines > 0 && !self.stalled {
            self.stalled = true;
            // The session's loop waits here: no window adjustment goes out.
            tokio::time::sleep(STALL).await;
        }
        shell.partial.extend_from_slice(data);
        while let Some(end) = shell.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = shell.partial.drain(..=end).collect();
            shell.lines += 1;
            run(&String::from_utf8_lossy(&line[..end]), &self.user, channel, session)?;
        }
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        if let Some(shell) = self.shells.remove(&channel) {
            session.data(channel, format!("{} lines\n", shell.lines).into_bytes())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }

    async fn signal(&mut self, _channel: ChannelId, signal: Sig, _session: &mut Session) -> Result<(), Self::Error> {
        let path = self.dir.join(format!("signals.{}", self.user));
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{}", podssh_ssh::signals::name(&signal));
        }
        Ok(())
    }
}

/// One line of the shell.
fn run(line: &str, user: &str, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
    if let Some(words) = line.strip_prefix("echo ") {
        session.data(channel, format!("{words}\n").into_bytes())?;
    } else if let Some(path) = line.strip_prefix("touch ") {
        let _ = std::fs::write(format!("{path}.{user}"), b"");
    } else if !line.is_empty() && !line.starts_with('#') {
        session.extended_data(channel, 1, format!("?{line}\n").into_bytes())?;
    }
    Ok(())
}

/// The server on the loopback, with the host key in `key`, on the current
/// runtime: its port.
pub async fn start(key: &Path) -> u16 {
    let mut config = server::Config::default();
    config.keys.push(russh::keys::load_secret_key(key, None).expect("the host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    config.window_size = WINDOW;
    let config = Arc::new(config);
    let dir = key.parent().expect("the directory of the key").to_path_buf();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = config.clone();
            let far = Far { user: String::new(), dir: dir.clone(), shells: HashMap::new(), stalled: false };
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, far).await {
                    let _ = session.await;
                }
            });
        }
    });
    port
}
