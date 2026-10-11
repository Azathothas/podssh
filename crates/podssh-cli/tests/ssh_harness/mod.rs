//! An SSH server on the loopback for the tests of the roads (T-157, T-165,
//! T-203): a russh server in the test process that lets anyone in and runs
//! five commands: `greet` prints [`GREETING`]; `source N` sends N bytes;
//! `sink` prints `R` as it starts to read, reads stdin to its end, then
//! prints the count, as `sh -c 'echo R; wc -c'` does on a POSIX server;
//! `echo` sends stdin back as it comes. Each exits 0. `hold` and `quit` take
//! no input after their first bytes, so the client's window runs out; 2 s
//! later `hold` ends the connection with no word, and `quit` exits 3 and
//! closes its channel, as a command that reads no input (`head`, `true`)
//! does while a large file comes. A direct-tcpip channel (`-W`, `podssh pipe
//! ssh:`) reaches its HOST:PORT from the server, each way with its half-close.
//! The commands of `podssh ping` (T-053) run as a POSIX server runs them:
//! `cat` echoes, `head -c N /dev/zero` sends N zero bytes, and
//! `cat > /dev/null` reads to the end of its input, each then exiting 0;
//! for a user named `bare-...`, a host with neither, they exit 127, and for
//! `bare-early-...` the channel closes before the server's reply to the
//! command, an order that RFC 4254 does not forbid. For `late-...`, `cat`
//! echoes its first bytes 1 s late, as a shell that is still starting it.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId};

/// What `greet` prints.
pub const GREETING: &str = "hello over the iroh road\n";
/// The size of each block that `source` sends.
const BLOCK: usize = 32 * 1024;

/// One connection's handler: the bytes that `sink` has read on each of its
/// channels, and the channels of `echo` and of `hold`.
#[derive(Default)]
struct Far {
    sinks: HashMap<ChannelId, u64>,
    echoes: Vec<ChannelId>,
    holds: Vec<ChannelId>,
    quits: Vec<ChannelId>,
    /// The channels of `spew` and `spew-mute`: their writers stop at the
    /// client's end of input, and `spew` then gives the status 7.
    spews: HashMap<ChannelId, (Arc<std::sync::atomic::AtomicBool>, bool)>,
    /// The user `kick`: the server ends the connection after the login.
    kick: bool,
    /// The channels of `cat > /dev/null`: read to the end, say nothing.
    drains: Vec<ChannelId>,
    /// The user `bare-...`: a host with no `cat` and no `head`; and
    /// `bare-early-...`, whose server ends their channels before its reply.
    bare: bool,
    early: bool,
    /// The user `late-...`, and the channels of `cat` that have not echoed yet.
    late: bool,
    late_echoes: Vec<ChannelId>,
}

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.kick = user == "kick";
        self.bare = user.starts_with("bare-");
        self.early = user.starts_with("bare-early-");
        self.late = user.starts_with("late-");
        // A user named key-...: a key is needed, as from an agent (T-034).
        if user.starts_with("key-") {
            return Ok(Auth::Reject {
                proceed_with_methods: Some(russh::MethodSet::from(&[russh::MethodKind::PublicKey][..])),
                partial_success: false,
            });
        }
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(&mut self, user: &str, _key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        Ok(if user.starts_with("key-") { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, user: &str, _key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        // russh checked the signature first: whoever holds a key gets in.
        Ok(if user.starts_with("key-") { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        if self.kick {
            let handle = session.handle();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ =
                    handle.disconnect(russh::Disconnect::ByApplication, "kicked by the test".into(), "en".into()).await;
            });
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _originator: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match tokio::net::TcpStream::connect(format!("{host}:{port}")).await {
            Ok(mut tcp) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                });
            }
            Err(_) => reply.reject(russh::ChannelOpenFailure::ConnectFailed).await,
        }
        Ok(())
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

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        let program = command.split_whitespace().next().unwrap_or_default();
        if self.bare && matches!(program, "cat" | "head") {
            if !self.early {
                session.channel_success(channel)?;
            }
            session.extended_data(channel, 1, format!("sh: {program}: not found\n").into_bytes())?;
            session.exit_status_request(channel, 127)?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        if let Some(rest) = command.strip_prefix("append ") {
            // `append PATH STATUS DELAY`: a line in the file at once, then
            // the status after DELAY seconds (T-025). A command that ran twice
            // leaves two lines.
            let mut parts = rest.rsplitn(3, ' ');
            let delay: u64 = parts.next().and_then(|d| d.parse().ok()).unwrap_or(0);
            let status: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let path = parts.next().unwrap_or_default().to_string();
            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                let _ = std::io::Write::write_all(&mut file, b"ran\n");
            }
            let handle = session.handle();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(delay)).await;
                let _ = handle.exit_status_request(channel, status).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
            return Ok(());
        }
        if command == "cat" {
            self.echoes.push(channel);
            if self.late {
                self.late_echoes.push(channel);
            }
            return Ok(());
        }
        if command == "cat > /dev/null" {
            self.drains.push(channel);
            return Ok(());
        }
        let zeros = command.strip_prefix("head -c ").and_then(|r| r.strip_suffix(" /dev/zero"));
        let command = match zeros.and_then(|n| n.parse::<u64>().ok()) {
            Some(n) => format!("source {n} zero"),
            None => command,
        };
        let mut words = command.split_whitespace();
        match (words.next(), words.next().and_then(|n| n.parse::<u64>().ok())) {
            (Some("source"), Some(bytes)) => {
                // From a task: the session's loop must go on, to take the
                // client's window adjustments while the bytes go out.
                let handle = session.handle();
                let fill = if words.next() == Some("zero") { 0 } else { 0x5a_u8 };
                tokio::spawn(async move {
                    let block = vec![fill; BLOCK];
                    let mut left = bytes;
                    while left > 0 {
                        let n = left.min(BLOCK as u64) as usize;
                        if handle.data(channel, block[..n].to_vec()).await.is_err() {
                            return;
                        }
                        left -= n as u64;
                    }
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                });
            }
            (Some(spew @ ("spew" | "spew-mute")), _) => {
                // Bytes until the client's end of input; then `spew` gives
                // its status, and `spew-mute` none.
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                self.spews.insert(channel, (stop.clone(), spew == "spew"));
                let handle = session.handle();
                tokio::spawn(async move {
                    let block = vec![0x79_u8; BLOCK];
                    while !stop.load(Ordering::SeqCst) {
                        if handle.data(channel, block.clone()).await.is_err() {
                            return;
                        }
                    }
                });
            }
            (Some("sink"), _) => {
                self.sinks.insert(channel, 0);
                session.data(channel, b"R\n".as_slice())?;
            }
            (Some("echo"), _) => self.echoes.push(channel),
            (Some("hold"), _) => self.holds.push(channel),
            (Some("quit"), _) => self.quits.push(channel),
            _ => {
                session.data(channel, GREETING.as_bytes())?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
        }
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if self.holds.contains(&channel) {
            // The session's loop waits here: no window adjustment goes out.
            tokio::time::sleep(Duration::from_secs(2)).await;
            return Err(russh::Error::Disconnect);
        }
        if let Some(at) = self.quits.iter().position(|c| *c == channel) {
            self.quits.remove(at);
            tokio::time::sleep(Duration::from_secs(2)).await;
            session.exit_status_request(channel, 3)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        if let Some(bytes) = self.sinks.get_mut(&channel) {
            *bytes += data.len() as u64;
        }
        if let Some(at) = self.late_echoes.iter().position(|c| *c == channel) {
            self.late_echoes.remove(at);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        if self.echoes.contains(&channel) {
            session.data(channel, data.to_vec())?;
        }
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        if let Some((stop, status)) = self.spews.remove(&channel) {
            stop.store(true, Ordering::SeqCst);
            if status {
                session.exit_status_request(channel, 7)?;
            }
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }
        let echoed = self.echoes.iter().position(|c| *c == channel).map(|at| self.echoes.remove(at)).is_some();
        let drained = self.drains.iter().position(|c| *c == channel).map(|at| self.drains.remove(at)).is_some();
        if echoed || drained {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        if let Some(bytes) = self.sinks.remove(&channel) {
            session.data(channel, format!("{bytes}\n").into_bytes())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

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
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    let mut config = server::Config::default();
    config.keys.push(russh::keys::load_secret_key(key, None).expect("the host key"));
    config.certificates = certificates;
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, Far::default()).await {
                    let _ = session.await;
                }
            });
        }
    });
    (port, connections)
}
