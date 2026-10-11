//! Whether a server acts on the `signal` request (RFC 4254, section 6.9), the
//! one way that the protocol gives to stop a command that runs with no pty
//! (T-131). The client logs in as podssh does, execs a command with no pty,
//! sends `signal INT` after 1 s, and reads what ends the channel within 5 s:
//! the command's signal or status, a close with neither, or nothing. It does
//! so for two commands (see [`COMMANDS`]).
//!
//! Two servers of this process show that the reading tells the cases apart:
//! one that ignores the request, as russh's own server does, reads as
//! "ignored", and one that ends the command reads as its signal. The ignored
//! test `each_named_server` measures them, then each server that
//! `PODSSH_SIGNAL_TARGETS` names:
//!
//! - `PODSSH_SIGNAL_TARGETS`: `NAME=[USER@]HOST[:PORT]`, separated by spaces.
//! - `PODSSH_SIGNAL_KEY`: a key file to log in with; with none, a server that
//!   takes the `none` method (Tailscale SSH) still lets the test in.
//! - `PODSSH_SIGNAL_KNOWN_HOSTS`: a known_hosts file that must hold each
//!   server's key. With none, any key is taken and none is recorded: for the
//!   servers of the test's own container.
//!
//! `docs/terminal.md` has the table of what each server did.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use podssh_ssh::handler::Client;
use podssh_ssh::run::connect_hops;
use podssh_ssh::signals;
use podssh_ssh::{Agent, Hop, Log, LogLevel, Options, StrictHostKeyChecking};
use russh::client::Handle;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId, ChannelMsg, Sig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The commands. In `exec sleep 30`, `sleep` is the process that the server
/// started, so its reading is whether the server delivers the signal. In
/// `sleep 30; true`, a shell waits for its child, so its reading is whether
/// the signal reaches a command under the shell too: the server signals the
/// process group, or the shell alone, which ends and leaves `sleep` holding
/// the channel's pipes.
const COMMANDS: [&str; 2] = ["exec sleep 30", "sleep 30; true"];

/// How long the client waits before the signal, and after it.
#[derive(Clone, Copy)]
struct Waits {
    /// From the exec to the signal: the command has started.
    before: Duration,
    /// From the signal to the reading "ignored".
    within: Duration,
}

/// The entry's waits: 1 s, then 5 s.
const MEASURED: Waits = Waits { before: Duration::from_secs(1), within: Duration::from_secs(5) };

/// Shorter waits for the servers of this process, which answer at once.
const QUICK: Waits = Waits { before: Duration::from_millis(100), within: Duration::from_millis(1500) };

/// What ended the channel after `signal INT`, or that nothing did.
#[derive(Debug, PartialEq, Eq)]
enum Reading {
    /// The server reported that the command ended by this signal.
    Signal(String),
    /// The server reported the command's exit status.
    Status(u32),
    /// The channel closed with no status and no signal.
    Closed,
    /// Nothing within the wait: the command still ran.
    Ignored,
}

/// A reading, how long after the signal it came, and whether the channel
/// closed within the wait.
struct Measured {
    reading: Reading,
    after: Duration,
    closed: bool,
    within: Duration,
}

impl std::fmt::Display for Measured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ms = self.after.as_millis();
        let channel = if self.closed { "the channel closed" } else { "the channel stayed open" };
        match &self.reading {
            Reading::Signal(name) => {
                write!(f, "acted: the command ended by signal {name} {ms} ms after the request, {channel}")
            }
            Reading::Status(code) => {
                write!(f, "acted: the command ended with status {code} {ms} ms after the request, {channel}")
            }
            Reading::Closed => write!(f, "acted: the channel closed with no status {ms} ms after the request"),
            Reading::Ignored => {
                write!(f, "ignored: the command still ran {} s after the request", self.within.as_secs_f32())
            }
        }
    }
}

/// Exec `command` with no pty, send `signal INT` after `waits.before`, and
/// read what ends the channel within `waits.within`.
async fn measure(handle: &Handle<Client>, command: &str, waits: Waits) -> Result<Measured, String> {
    let mut channel = handle.channel_open_session().await.map_err(|e| format!("no session channel: {e}"))?;
    channel.exec(true, command).await.map_err(|e| format!("the exec was not sent: {e}"))?;
    // The command starts: a message that ends it before the signal leaves
    // nothing to read.
    let early = tokio::time::timeout(waits.before, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Failure) => return "the server refused the exec".to_string(),
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    return format!("the command ended with status {exit_status} before the signal")
                }
                Some(ChannelMsg::ExitSignal { signal_name: sig, .. }) => {
                    return format!("the command ended by signal {} before the signal", signals::name(&sig))
                }
                Some(ChannelMsg::Close) | None => return "the channel closed before the signal".to_string(),
                Some(_) => {}
            }
        }
    })
    .await;
    if let Ok(why) = early {
        return Err(why);
    }
    channel.signal(Sig::INT).await.map_err(|e| format!("the signal was not sent: {e}"))?;
    let sent = Instant::now();
    let deadline = tokio::time::Instant::from_std(sent + waits.within);
    let mut measured = Measured { reading: Reading::Ignored, after: waits.within, closed: false, within: waits.within };
    loop {
        let got = match tokio::time::timeout_at(deadline, channel.wait()).await {
            Ok(got) => got,
            Err(_) => break,
        };
        let reading = match got {
            Some(ChannelMsg::ExitSignal { signal_name: sig, .. }) => Reading::Signal(signals::name(&sig)),
            Some(ChannelMsg::ExitStatus { exit_status }) => Reading::Status(exit_status),
            Some(ChannelMsg::Close) | None => {
                measured.closed = true;
                if measured.reading == Reading::Ignored {
                    measured.reading = Reading::Closed;
                    measured.after = sent.elapsed();
                }
                break;
            }
            // EOF, data and window messages: the end comes after them.
            Some(_) => continue,
        };
        if measured.reading == Reading::Ignored {
            measured.reading = reading;
            measured.after = sent.elapsed();
        }
    }
    let _ = channel.close().await;
    Ok(measured)
}

/// A stream that keeps the first bytes that the server sends, which hold its
/// identification, such as `SSH-2.0-OpenSSH_9.9`.
struct Banner<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
}

/// The bytes that [`Banner`] keeps.
const KEPT: usize = 1024;

impl<S: AsyncRead + Unpin> AsyncRead for Banner<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        let mut seen = this.seen.lock().expect("the banner's lock");
        let room = KEPT.saturating_sub(seen.len());
        let new = &buf.filled()[before..];
        seen.extend_from_slice(&new[..new.len().min(room)]);
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Banner<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The server's identification line, from what [`Banner`] kept.
fn identification(seen: &Mutex<Vec<u8>>) -> String {
    let seen = seen.lock().expect("the banner's lock");
    String::from_utf8_lossy(&seen)
        .lines()
        .find(|line| line.starts_with("SSH-"))
        .map_or_else(|| "no identification".to_string(), |line| line.trim_end().to_string())
}

/// podssh's options for one server: no agent, never a prompt, the key and
/// the known_hosts file named, if any.
fn options(hop: Hop, key: Option<PathBuf>, known_hosts: Option<PathBuf>) -> Options {
    let user = hop.user.clone().unwrap_or_else(|| "podtest".to_string());
    let mut opts = Options::new(hop, user);
    opts.connect_timeout = Duration::from_secs(10);
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.identities_only = true;
    opts.identity_files = key.into_iter().collect();
    opts.strict_host_key_checking =
        if known_hosts.is_some() { StrictHostKeyChecking::Yes } else { StrictHostKeyChecking::No };
    opts.user_known_hosts = known_hosts.into_iter().collect();
    opts.log_level = LogLevel::Quiet;
    opts
}

/// What one login measured: the server's identification, and the reading of
/// each command, or why there is none.
type Logged = (String, Vec<Result<Measured, String>>);

/// Log in and measure each command in turn, each in a channel of its own.
async fn measure_over<S>(stream: S, opts: &Options, commands: &[&str], waits: Waits) -> Result<Logged, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let seen = Arc::new(Mutex::new(Vec::new()));
    let stream = Banner { inner: stream, seen: seen.clone() };
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let handles = connect_hops(stream, opts, &log).await.map_err(|e| e.to_string())?;
    let handle = handles.last().expect("the destination");
    let mut readings = Vec::new();
    for command in commands {
        readings.push(measure(handle, command, waits).await);
    }
    podssh_ssh::run::disconnect_all(&handles).await;
    Ok((identification(&seen), readings))
}

/// A server of this process: exec succeeds and runs nothing, and the channel
/// stays open until the client closes it. One that acts ends the "command" by
/// the signal that the client sends; one that does not keeps russh's own
/// answer to `signal`, which is to do nothing.
struct StandIn {
    acts: bool,
}

impl server::Handler for StandIn {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<ServerMsg>,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        if self.acts {
            session.exit_signal_request(channel, signal, false, "", "")?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

/// Measure a [`StandIn`] over a pipe of this process.
async fn measure_stand_in(acts: bool, waits: Waits) -> (String, Measured) {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, StandIn { acts }).await {
            let _ = session.await;
        }
    });
    let hop = Hop { user: Some("podtest".into()), host: "stand-in.test".into(), port: 22 };
    let opts = options(hop, None, None);
    let (id, mut readings) =
        tokio::time::timeout(Duration::from_secs(30), measure_over(client_end, &opts, &COMMANDS[..1], waits))
            .await
            .expect("the measurement ended within 30 s")
            .expect("logged in to the stand-in");
    (id, readings.remove(0).expect("the stand-in was measured"))
}

/// `[USER@]HOST[:PORT]`.
fn hop_of(dest: &str) -> Hop {
    let (user, host_port) = match dest.split_once('@') {
        Some((user, rest)) => (Some(user.to_string()), rest),
        None => (None, dest),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().expect("a port of 1 to 65535")),
        None => (host_port, 22),
    };
    Hop { user, host: host.to_string(), port }
}

#[tokio::test]
async fn a_server_that_ignores_the_request_reads_as_ignored() {
    let (id, measured) = measure_stand_in(false, QUICK).await;
    assert!(id.starts_with("SSH-2.0-"), "{id}");
    assert_eq!(measured.reading, Reading::Ignored);
    assert!(!measured.closed);
    assert!(measured.to_string().starts_with("ignored: "), "{measured}");
}

#[tokio::test]
async fn a_server_that_acts_reads_as_the_signal() {
    let (_, measured) = measure_stand_in(true, QUICK).await;
    assert_eq!(measured.reading, Reading::Signal("INT".into()));
    assert!(measured.closed);
    assert!(measured.after < QUICK.within);
    assert!(measured.to_string().starts_with("acted: the command ended by signal INT "), "{measured}");
}

/// The stand-ins, then each server that `PODSSH_SIGNAL_TARGETS` names: one
/// line for each. A server that could not be measured fails the test; one
/// that ignores the request does not.
#[tokio::test]
#[ignore = "measures the servers that PODSSH_SIGNAL_TARGETS names"]
async fn each_named_server() {
    let (id, ignores) = measure_stand_in(false, MEASURED).await;
    println!("signal INT: stand-in that ignores ({id}): {ignores}");
    assert_eq!(ignores.reading, Reading::Ignored, "the plant must read as ignored");
    let (id, acts) = measure_stand_in(true, MEASURED).await;
    println!("signal INT: stand-in that acts ({id}): {acts}");
    assert_eq!(acts.reading, Reading::Signal("INT".into()));

    let key = std::env::var_os("PODSSH_SIGNAL_KEY").map(PathBuf::from);
    let known_hosts = std::env::var_os("PODSSH_SIGNAL_KNOWN_HOSTS").map(PathBuf::from);
    let targets = std::env::var("PODSSH_SIGNAL_TARGETS").unwrap_or_default();
    if targets.trim().is_empty() {
        println!("signal INT: no server is named (PODSSH_SIGNAL_TARGETS)");
    }
    let mut unmeasured = Vec::new();
    for target in targets.split_whitespace() {
        let (name, dest) = target.split_once('=').expect("each target is NAME=[USER@]HOST[:PORT]");
        let hop = hop_of(dest);
        let opts = options(hop.clone(), key.clone(), known_hosts.clone());
        let run = async {
            let stream = tokio::net::TcpStream::connect((hop.host.as_str(), hop.port))
                .await
                .map_err(|e| format!("no connection to {}:{}: {e}", hop.host, hop.port))?;
            measure_over(stream, &opts, &COMMANDS, MEASURED).await
        };
        match tokio::time::timeout(Duration::from_secs(60), run).await {
            Ok(Ok((id, readings))) => {
                for (command, reading) in COMMANDS.iter().zip(readings) {
                    match reading {
                        Ok(measured) => println!("signal INT: {name} ({id}), \"{command}\": {measured}"),
                        Err(why) => {
                            println!("signal INT: {name} ({id}), \"{command}\": not measured: {why}");
                            unmeasured.push(format!("{name}: {command}"));
                        }
                    }
                }
            }
            Ok(Err(why)) => {
                println!("signal INT: {name}: not measured: {why}");
                unmeasured.push(name.to_string());
            }
            Err(_) => {
                println!("signal INT: {name}: not measured: no end within 60 s");
                unmeasured.push(name.to_string());
            }
        }
    }
    assert!(unmeasured.is_empty(), "not measured: {unmeasured:?}");
}
