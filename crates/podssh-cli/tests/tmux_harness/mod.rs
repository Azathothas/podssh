//! An SSH server on the loopback with a stand-in for tmux, for the tests of
//! `podssh ssh --persist` (T-178). `command -v tmux` finds it, or not;
//! `tmux has-session -t =NAME` asks for a session; `tmux new-session -A -s
//! NAME`, with a pty, attaches a session whose shell outlives the
//! connection, as tmux keeps it. The shell reads lines: `MARK=VALUE` sets
//! its one variable, `echo M=$MARK` prints it, `tmux kill-session` ends the
//! session (exit 0), `drop` ends the connection with no word, as a lost link
//! does, and `forget` does the same after the session ends, as a server
//! that restarted.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, Pty};

/// The server's tmux: whether it is on PATH, each session's variable, and
/// the counts that the tests read.
#[derive(Debug, Default)]
pub struct Tmux {
    pub installed: bool,
    pub sessions: HashMap<String, Option<String>>,
    /// Each `new-session -A` that attached or started a session.
    pub attaches: usize,
    /// Each TCP connection that the server took.
    pub connections: usize,
}

/// One connection: the channels with a pty, and each attached session with
/// the part of a line read so far.
struct Far {
    tmux: Arc<Mutex<Tmux>>,
    ptys: HashSet<ChannelId>,
    attached: HashMap<ChannelId, (String, Vec<u8>)>,
}

impl Far {
    fn tmux(&self) -> std::sync::MutexGuard<'_, Tmux> {
        self.tmux.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Answer a command that ends at once: its output, stderr and status.
fn finish(session: &mut Session, channel: ChannelId, out: &str, err: &str, status: u32) -> Result<(), russh::Error> {
    if !out.is_empty() {
        session.data(channel, out.as_bytes().to_vec())?;
    }
    if !err.is_empty() {
        session.extended_data(channel, 1, err.as_bytes().to_vec())?;
    }
    session.exit_status_request(channel, status)?;
    session.eof(channel)?;
    session.close(channel)
}

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
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

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _px_width: u32,
        _px_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.ptys.insert(channel);
        session.channel_success(channel)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let command = String::from_utf8_lossy(data).into_owned();
        let words: Vec<&str> = command.split_whitespace().collect();
        let installed = self.tmux().installed;
        match words.as_slice() {
            ["command", "-v", "tmux"] if installed => finish(session, channel, "/usr/bin/tmux\n", "", 0),
            ["command", "-v", "tmux"] => finish(session, channel, "", "", 1),
            ["tmux", ..] if !installed => finish(session, channel, "", "sh: tmux: not found\n", 127),
            ["tmux", "has-session", "-t", target] => {
                let name = target.trim_start_matches('=');
                let there = self.tmux().sessions.contains_key(name);
                finish(session, channel, "", if there { "" } else { "can't find session\n" }, u32::from(!there))
            }
            ["tmux", "new-session", "-A", "-s", name] if self.ptys.contains(&channel) => {
                let mut tmux = self.tmux();
                tmux.sessions.entry((*name).to_string()).or_default();
                tmux.attaches += 1;
                drop(tmux);
                self.attached.insert(channel, ((*name).to_string(), Vec::new()));
                session.data(channel, format!("[{name}] attached\r\n").into_bytes())
            }
            ["tmux", "new-session", ..] => finish(session, channel, "", "open terminal failed: not a terminal\n", 1),
            _ => finish(session, channel, "", "sh: not found\n", 127),
        }
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let Some((name, line)) = self.attached.get_mut(&channel) else { return Ok(()) };
        line.extend_from_slice(data);
        let name = name.clone();
        while let Some(end) = self.attached[&channel].1.iter().position(|b| *b == b'\n' || *b == b'\r') {
            let read: Vec<u8> = self.attached.get_mut(&channel).unwrap().1.drain(..=end).collect();
            let text = String::from_utf8_lossy(&read[..end]).trim().to_string();
            if let Some(value) = text.strip_prefix("MARK=") {
                self.tmux().sessions.insert(name.clone(), Some(value.to_string()));
            } else if text == "echo M=$MARK" {
                let value = self.tmux().sessions.get(&name).cloned().flatten().unwrap_or_default();
                session.data(channel, format!("M={value}\r\n").into_bytes())?;
            } else if text == "tmux kill-session" {
                self.tmux().sessions.remove(&name);
                self.attached.remove(&channel);
                return finish(session, channel, "", "", 0);
            } else if text == "drop" {
                return Err(russh::Error::Disconnect);
            } else if text == "forget" {
                self.tmux().sessions.remove(&name);
                return Err(russh::Error::Disconnect);
            }
        }
        Ok(())
    }
}

/// The server on the loopback, with the host key in `key` and tmux on PATH
/// or not, on the current runtime: its port, and its tmux.
pub async fn start(key: &Path, installed: bool) -> (u16, Arc<Mutex<Tmux>>) {
    let tmux = Arc::new(Mutex::new(Tmux { installed, ..Tmux::default() }));
    let mut config = server::Config::default();
    config.keys.push(russh::keys::load_secret_key(key, None).expect("the host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    let shared = tmux.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            shared.lock().unwrap_or_else(|e| e.into_inner()).connections += 1;
            let config = config.clone();
            let far = Far { tmux: shared.clone(), ptys: HashSet::new(), attached: HashMap::new() };
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, far).await {
                    let _ = session.await;
                }
            });
        }
    });
    (port, tmux)
}
