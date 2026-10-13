//! A session or a stdio forward that a client asked a master for (T-039): a
//! channel of the master's connection, with the client's terminal, command
//! and environment, copied to and from the descriptors that the client
//! passed, until the channel closes. The client hears SESSION_OPENED or a
//! failure, TTY_ALLOC_FAIL when no pty came, and EXIT_MESSAGE with the
//! status, as OpenSSH's master sends them.

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

use super::afd::Passed;
use super::proto::{Message, NewSession, NO_ESCAPE};
use super::wire;
use crate::escape::{Command, Escapes};
use crate::handler::Client;
use crate::log::Log;
use crate::terminal;

/// The size of each read of the client's input.
const CHUNK: usize = 32 * 1024;
/// How long the server may take to open a stdio forward's channel.
const OPEN_LIMIT: Duration = Duration::from_secs(60);
/// How long one side of a stdio forward may still talk once the other ended.
const GRACE: Duration = Duration::from_secs(2);
const HELP: &[u8] = b"\r\nSupported escape sequences:\r\n ~.   - terminate this session\r\n \
~#   - list forwarded connections\r\n ~?   - this message\r\n \
~~   - send the escape character by typing it twice\r\n(Note that escapes are only recognized immediately after newline.)\r\n";
/// The answer to `~Z` in a session through a master (T-148).
const ZMODEM_NOTE: &[u8] = b"\r\npodssh: ZMODEM works in a session of its own, not through a control master\r\n";

async fn failure(stream: &mut UnixStream, rid: u32, reason: String) {
    let _ = wire::write(stream, &Message::Failure { rid, reason }).await;
}

/// Run `asked` with the client's `fds` (stdin, stdout, stderr) and answer
/// on `stream`. `winch` changes at each SIGWINCH of the master, which a
/// client relays to it; `agent` says whether the master may forward its
/// agent.
#[allow(clippy::too_many_arguments)]
pub async fn session(
    handle: &Handle<Client>,
    asked: NewSession,
    fds: [OwnedFd; 3],
    sid: u32,
    stream: &mut UnixStream,
    agent: bool,
    winch: watch::Receiver<u64>,
    log: &Arc<Log>,
) {
    let rid = asked.rid;
    let [stdin, stdout, stderr] = fds;
    let (mut input, mut out, mut err) = match (Passed::new(stdin), Passed::new(stdout), Passed::new(stderr)) {
        (Ok(input), Ok(out), Ok(err)) => (input, out, err),
        _ => return failure(stream, rid, "the master could not use the client's descriptors".into()).await,
    };
    let mut channel = match handle.channel_open_session().await {
        Ok(channel) => channel,
        Err(e) => return failure(stream, rid, format!("Session open refused by peer: {e}")).await,
    };
    for entry in &asked.env {
        if let Some((name, value)) = entry.split_once('=') {
            // No reply asked for: servers refuse unlisted variables silently.
            let _ = channel.set_env(false, name, value).await;
        }
    }
    let mut early = Vec::new();
    let mut pty = false;
    if asked.tty {
        let size = terminal::size_of_fd(input.raw()).unwrap_or_else(terminal::fallback_size);
        let modes = terminal::pty_modes_of(input.raw());
        let sent =
            channel.request_pty(true, &asked.term, size.cols, size.rows, size.px_width, size.px_height, &modes).await;
        if sent.is_ok() {
            pty = crate::session::wait_reply(&mut channel, &mut early).await.unwrap_or(false);
        }
    }
    if asked.agent && agent {
        let _ = crate::agent_forward::request(&mut channel, &mut early, log).await;
    }
    let sent = if asked.subsystem {
        channel.request_subsystem(true, String::from_utf8_lossy(&asked.command)).await
    } else if asked.command.is_empty() {
        channel.request_shell(true).await
    } else {
        channel.exec(true, asked.command.clone()).await
    };
    let started = sent.is_ok() && crate::session::wait_reply(&mut channel, &mut early).await.unwrap_or(false);
    if !started {
        return failure(stream, rid, "the server refused to start the session".into()).await;
    }
    if wire::write(stream, &Message::SessionOpened { rid, sid }).await.is_err() {
        return;
    }
    if asked.tty && !pty {
        let _ = wire::write(stream, &Message::TtyAllocFail { sid }).await;
    }
    let escapes = match (pty, asked.escape) {
        (true, e) if e != NO_ESCAPE => u8::try_from(e).ok().map(Escapes::new),
        _ => None,
    };
    let winch = pty.then_some(winch);
    let status = pump(channel, early, &mut input, &mut out, &mut err, escapes, winch).await;
    let _ = out.flush().await;
    let _ = err.flush().await;
    if let Some(code) = status {
        let _ = wire::write(stream, &Message::ExitMessage { sid, code: code as u32 }).await;
    }
    log.verbose(&format!("a shared session ended ({})", status.map_or("no status".into(), |c| format!("status {c}"))));
}

/// Copy until the channel closes; the status that came, if one did.
async fn pump(
    channel: Channel<Msg>,
    early: Vec<ChannelMsg>,
    input: &mut Passed,
    out: &mut Passed,
    err: &mut Passed,
    mut escapes: Option<Escapes>,
    mut winch: Option<watch::Receiver<u64>>,
) -> Option<i32> {
    let (mut reader, writer) = channel.split();
    let mut status = None;
    for msg in early {
        if let Some(()) = take(msg, &mut status, out, err).await {
            return status;
        }
    }
    let mut buf = vec![0u8; CHUNK];
    let mut reading = true;
    let mut last = terminal::size_of_fd(input.raw());
    loop {
        tokio::select! {
            read = input.read(&mut buf), if reading => match read {
                Ok(0) | Err(_) => {
                    reading = false;
                    let _ = writer.eof().await;
                }
                Ok(n) => {
                    let (data, commands) = match escapes.as_mut() {
                        Some(e) => e.feed(&buf[..n]),
                        None => (buf[..n].to_vec(), Vec::new()),
                    };
                    if !data.is_empty() && writer.data_bytes(data).await.is_err() {
                        reading = false;
                    }
                    for command in commands {
                        match command {
                            Command::Disconnect => {
                                let _ = writer.close().await;
                                return status;
                            }
                            Command::Help => {
                                let _ = err.write_all(HELP).await;
                            }
                            // The forwards are the master's, as OpenSSH's
                            // ~# lists the master's connections (T-041).
                            Command::List => {
                                let listing = crate::tally::listing().replace('\n', "\r\n");
                                let _ = err.write_all(listing.as_bytes()).await;
                            }
                            // A re-key is the whole connection's: the master's.
                            // A shared session learns no offer of kept shells,
                            // so its escapes never detach (T-158); and it has
                            // no ~C, as a client of OpenSSH's master has none
                            // (T-291).
                            Command::Rekey | Command::Detach | Command::CommandLine => {}
                            // ZMODEM is watched in a session of podssh's own
                            // terminal, not in one that a master carries.
                            Command::Zmodem => {
                                let _ = err.write_all(ZMODEM_NOTE).await;
                            }
                        }
                    }
                }
            },
            msg = reader.wait() => match msg {
                Some(msg) => {
                    if let Some(()) = take(msg, &mut status, out, err).await {
                        return status;
                    }
                }
                None => return status,
            },
            changed = changed(&mut winch) => match changed {
                true => {
                    let size = terminal::size_of_fd(input.raw());
                    if let (Some(s), true) = (size, size != last) {
                        let _ = writer.window_change(s.cols, s.rows, s.px_width, s.px_height).await;
                        last = size;
                    }
                }
                false => winch = None,
            },
        }
    }
}

/// The next change of the window, or pending with none to watch.
async fn changed(winch: &mut Option<watch::Receiver<u64>>) -> bool {
    match winch {
        Some(w) => w.changed().await.is_ok(),
        None => std::future::pending().await,
    }
}

/// One message of the channel: `Some` once it closed.
async fn take(msg: ChannelMsg, status: &mut Option<i32>, out: &mut Passed, err: &mut Passed) -> Option<()> {
    match msg {
        ChannelMsg::Data { data } => {
            let _ = out.write_all(&data).await;
        }
        ChannelMsg::ExtendedData { data, .. } => {
            let _ = err.write_all(&data).await;
        }
        ChannelMsg::ExitStatus { exit_status } => *status = Some(crate::io::status_code(exit_status)),
        ChannelMsg::ExitSignal { signal_name, .. } => {
            *status = Some(crate::signals::number(&signal_name).map_or(255, |n| 128 + n));
        }
        ChannelMsg::Close => return Some(()),
        _ => {}
    }
    None
}

/// `-W HOST:PORT` through the master: a direct-tcpip channel and the
/// client's stdin and stdout, or for the port `PORT_STREAMLOCAL` a
/// direct-streamlocal channel to the socket of `host` (T-040). The client
/// hears SESSION_OPENED, and exits 0 when the master closes the control
/// connection, as OpenSSH's does.
#[allow(clippy::too_many_arguments)]
pub async fn stdio(
    handle: &Handle<Client>,
    rid: u32,
    host: &str,
    port: u32,
    fds: [OwnedFd; 2],
    sid: u32,
    stream: &mut UnixStream,
    log: &Arc<Log>,
) {
    let [stdin, stdout] = fds;
    let (input, output) = match (Passed::new(stdin), Passed::new(stdout)) {
        (Ok(input), Ok(output)) => (input, output),
        _ => return failure(stream, rid, "the master could not use the client's descriptors".into()).await,
    };
    let opening = async {
        if port == super::proto::PORT_STREAMLOCAL {
            handle.channel_open_direct_streamlocal(host).await
        } else {
            handle.channel_open_direct_tcpip(host, port, "127.0.0.1", 0).await
        }
    };
    let opened = tokio::time::timeout(OPEN_LIMIT, opening).await;
    let channel = match opened {
        Ok(Ok(channel)) => channel,
        Ok(Err(e)) => return failure(stream, rid, format!("stdio forwarding failed: {e}")).await,
        Err(_) => return failure(stream, rid, "stdio forwarding failed: no answer from the server".into()).await,
    };
    if wire::write(stream, &Message::SessionOpened { rid, sid }).await.is_err() {
        return;
    }
    let local = tokio::io::join(input, output);
    crate::agent_forward::splice(local, channel.into_stream(), GRACE).await;
    let shown = if port == super::proto::PORT_STREAMLOCAL { host.to_string() } else { format!("{host}:{port}") };
    log.verbose(&format!("a shared stdio forward to {shown} ended"));
}
