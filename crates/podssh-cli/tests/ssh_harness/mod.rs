//! An SSH server on the loopback for the tests of the roads (T-157, T-165,
//! T-203): a russh server in the test process that lets anyone in and runs
//! four commands: `greet` prints [`GREETING`]; `source N` sends N bytes;
//! `sink` prints `R` as it starts to read, reads stdin to its end, then
//! prints the count, as `sh -c 'echo R; wc -c'` does on a POSIX server;
//! `echo` sends stdin back as it comes. Each exits 0.

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
/// channels, and the channels of `echo`.
#[derive(Default)]
struct Far {
    sinks: HashMap<ChannelId, u64>,
    echoes: Vec<ChannelId>,
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

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let command = String::from_utf8_lossy(data).into_owned();
        let mut words = command.split_whitespace();
        match (words.next(), words.next().and_then(|n| n.parse::<u64>().ok())) {
            (Some("source"), Some(bytes)) => {
                // From a task: the session's loop must go on, to take the
                // client's window adjustments while the bytes go out.
                let handle = session.handle();
                tokio::spawn(async move {
                    let block = vec![0x5a_u8; BLOCK];
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
            (Some("sink"), _) => {
                self.sinks.insert(channel, 0);
                session.data(channel, b"R\n".as_slice())?;
            }
            (Some("echo"), _) => self.echoes.push(channel),
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
        if let Some(bytes) = self.sinks.get_mut(&channel) {
            *bytes += data.len() as u64;
        }
        if self.echoes.contains(&channel) {
            session.data(channel, data.to_vec())?;
        }
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        let echoed = self.echoes.iter().position(|c| *c == channel).map(|at| self.echoes.remove(at)).is_some();
        if echoed {
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
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    let mut config = server::Config::default();
    config.keys.push(russh::keys::load_secret_key(key, None).expect("the host key"));
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
