//! `-A` against a russh server in this process, over a pipe, and a stand-in
//! agent on a socket (a named pipe on Windows) of its own. At each exec the
//! server reaches for the agent, as a program on it would, whether podssh
//! asked for the agent or not.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::client::Handle;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId, ChannelOpenFailure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::handler::Client;
use crate::log::Log;
use crate::options::{Agent, Hop, LogLevel, Options, Request, StrictHostKeyChecking};

/// SSH_AGENTC_REQUEST_IDENTITIES, and the answer of an agent with no key
/// (draft-miller-ssh-agent, sections 3.6 and 6.1).
const REQUEST: &[u8] = &[0, 0, 0, 1, 11];
const ANSWER: &[u8] = &[0, 0, 0, 5, 12, 0, 0, 0, 0];

type Order = Arc<Mutex<Vec<&'static str>>>;
type Reached = Result<Vec<u8>, russh::Error>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Lets anyone in, notes each request, and at an exec sends a request to
/// the agent through an agent channel; the test gets the outcome before the
/// exit status.
struct Server {
    handle: Option<oneshot::Sender<server::Handle>>,
    order: Order,
    reached: Option<oneshot::Sender<Reached>>,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, session: &mut ServerSession) -> Result<(), Self::Error> {
        if let Some(tx) = self.handle.take() {
            let _ = tx.send(session.handle());
        }
        Ok(())
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

    async fn agent_request(&mut self, _channel: ChannelId, _session: &mut ServerSession) -> Result<bool, Self::Error> {
        lock(&self.order).push("agent");
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        lock(&self.order).push("exec");
        session.channel_success(channel)?;
        let (handle, reached) = (session.handle(), self.reached.take());
        tokio::spawn(async move {
            let outcome = round_trip(&handle).await;
            if let Some(tx) = reached {
                let _ = tx.send(outcome);
            }
            let _ = handle.exit_status_request(channel, 0).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }
}

/// A request to the agent and its answer, through a new agent channel,
/// which closes after it.
async fn round_trip(handle: &server::Handle) -> Reached {
    let mut stream = handle.channel_open_agent().await?.into_stream();
    stream.write_all(REQUEST).await?;
    let mut answer = vec![0; ANSWER.len()];
    stream.read_exact(&mut answer).await?;
    Ok(answer)
}

/// A directory of the test's own, gone at its end, also after a failure.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("podssh-agent-fwd-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        Scratch(dir)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.0.join("log")).unwrap_or_default()
    }

    /// A place where no agent runs.
    fn nowhere(&self) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!(r"\\.\pipe\podssh-agent-fwd-none-{}", std::process::id()))
        } else {
            self.0.join("none.sock")
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The stand-in agent reads one request, answers it, and gives the request
/// back with whether its connection then ended.
async fn serve_one<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> (Vec<u8>, bool) {
    let mut request = vec![0; REQUEST.len()];
    if stream.read_exact(&mut request).await.is_err() {
        return (request, false);
    }
    let _ = stream.write_all(ANSWER).await;
    // The connection ends with its channel: at once on a socket, after the
    // grace on a named pipe, which has no half-close.
    let mut rest = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(20), stream.read(&mut rest)).await;
    (request, matches!(read, Ok(Ok(0)) | Ok(Err(_))))
}

#[cfg(unix)]
fn stand_in(scratch: &Scratch) -> (PathBuf, JoinHandle<(Vec<u8>, bool)>) {
    let path = scratch.0.join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&path).expect("the stand-in agent binds");
    let task = tokio::spawn(async move {
        match listener.accept().await {
            Ok((stream, _)) => serve_one(stream).await,
            Err(_) => (Vec::new(), false),
        }
    });
    (path, task)
}

#[cfg(windows)]
fn stand_in(scratch: &Scratch) -> (PathBuf, JoinHandle<(Vec<u8>, bool)>) {
    use tokio::net::windows::named_pipe::ServerOptions;
    // A pipe named after the test's own directory, which no other test has.
    let name = scratch.0.file_name().expect("a directory name").to_string_lossy();
    let path = PathBuf::from(format!(r"\\.\pipe\{name}"));
    let pipe = ServerOptions::new().first_pipe_instance(true).create(&path).expect("the stand-in agent's pipe");
    let task = tokio::spawn(async move {
        match pipe.connect().await {
            Ok(()) => serve_one(pipe).await,
            Err(_) => (Vec::new(), false),
        }
    });
    (path, task)
}

struct Run {
    client: Handle<Client>,
    server: server::Handle,
    order: Order,
    reached: oneshot::Receiver<Reached>,
    opts: Options,
    log: Arc<Log>,
}

/// Log in, as the destination or as a jump hop, with `forward` as the agent
/// that the server may use.
async fn start(forward: Agent, destination: bool, scratch: &Scratch) -> Run {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let (handle_tx, handle_rx) = oneshot::channel();
    let (reached_tx, reached) = oneshot::channel();
    let order = Order::default();
    let handler = Server { handle: Some(handle_tx), order: order.clone(), reached: Some(reached_tx) };
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, handler).await {
            let _ = session.await;
        }
    });
    let hop = Hop { user: Some("podtest".into()), host: "agent.test".into(), port: 22 };
    let mut opts = Options::new(hop.clone(), "podtest".into());
    opts.connect_timeout = Duration::from_secs(10);
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.forward_agent = forward;
    opts.request = Request::Exec("true".into());
    opts.stdin_null = true;
    let log = Arc::new(Log::to_file(LogLevel::Info, &scratch.0.join("log")).expect("a log file"));
    let client = crate::run::connect(client_end, &hop, destination, &opts, &log).await.expect("logged in");
    let server = handle_rx.await.expect("the server's handle");
    Run { client, server, order, reached, opts, log }
}

/// The session of `run`, a command that ends with status 0.
async fn session(run: &Run) {
    let mut input = crate::io::Input::new(true);
    let end = crate::session::attach(&run.client, &run.opts, "agent.test", &run.log, &mut input)
        .await
        .expect("the session ran");
    assert!(matches!(end, crate::io::End::Status(0)), "the session ended so: {end:?}");
}

fn refused<T>(opened: Result<T, russh::Error>, want: ChannelOpenFailure) {
    match opened {
        Err(russh::Error::ChannelOpenFailure(reason)) if reason == want => {}
        Err(e) => panic!("refused with another reason: {e:?}"),
        Ok(_) => panic!("the agent channel was accepted"),
    }
}

#[tokio::test]
async fn agent_channel_with_a_reaches_the_agent() {
    let test = async {
        let scratch = Scratch::new("reach");
        let (place, agent) = stand_in(&scratch);
        let mut run = start(Agent::Path(place), true, &scratch).await;
        session(&run).await;
        assert_eq!(*lock(&run.order), ["agent", "exec"], "podssh asks for the agent before the command");
        let answer = (&mut run.reached).await.expect("the server tried").expect("the agent channel was accepted");
        assert_eq!(answer, ANSWER, "the agent's answer reached the server");
        let (request, closed) = agent.await.expect("the stand-in agent");
        assert_eq!(request, REQUEST, "the server's request reached the agent");
        assert!(closed, "the agent's connection outlived its channel");
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

#[tokio::test]
async fn agent_channel_without_a_is_refused() {
    let test = async {
        let scratch = Scratch::new("without");
        let mut run = start(Agent::Off, true, &scratch).await;
        session(&run).await;
        assert_eq!(*lock(&run.order), ["exec"], "podssh asked for the agent with no -A");
        refused((&mut run.reached).await.expect("the server tried"), ChannelOpenFailure::AdministrativelyProhibited);
        assert!(scratch.log().contains("tried agent forwarding"), "{}", scratch.log());
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

#[tokio::test]
async fn agent_channel_of_a_jump_hop_is_refused() {
    let test = async {
        let scratch = Scratch::new("hop");
        let (place, agent) = stand_in(&scratch);
        let run = start(Agent::Path(place), false, &scratch).await;
        refused(run.server.channel_open_agent().await, ChannelOpenFailure::AdministrativelyProhibited);
        agent.abort();
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

#[tokio::test]
async fn agent_channel_with_no_agent_there_is_refused_and_said() {
    let test = async {
        let scratch = Scratch::new("none");
        let mut run = start(Agent::Path(scratch.nowhere()), true, &scratch).await;
        session(&run).await;
        refused((&mut run.reached).await.expect("the server tried"), ChannelOpenFailure::ConnectFailed);
        assert!(scratch.log().contains("the agent cannot be reached"), "{}", scratch.log());
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// A stream with no half-close, as a named pipe: its shutdown does nothing.
struct NoHalfClose(tokio::io::DuplexStream);

impl AsyncRead for NoHalfClose {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for NoHalfClose {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn agent_channel_splice_closes_a_side_with_no_half_close() {
    let (a, mut a_peer) = tokio::io::duplex(64);
    let (b, mut b_peer) = tokio::io::duplex(64);
    let splice = tokio::spawn(super::splice(a, NoHalfClose(b), Duration::from_millis(200)));
    let mut byte = [0u8; 1];
    a_peer.write_all(b"x").await.expect("a writes");
    b_peer.read_exact(&mut byte).await.expect("b reads");
    assert_eq!(&byte, b"x");
    b_peer.write_all(b"y").await.expect("b writes");
    a_peer.read_exact(&mut byte).await.expect("a reads");
    assert_eq!(&byte, b"y");
    drop(a_peer);
    let read = tokio::time::timeout(Duration::from_secs(5), b_peer.read(&mut byte)).await;
    assert!(matches!(read, Ok(Ok(0))), "the side with no half-close stayed open: {read:?}");
    tokio::time::timeout(Duration::from_secs(5), splice).await.expect("the splice ended").expect("no panic");
}
