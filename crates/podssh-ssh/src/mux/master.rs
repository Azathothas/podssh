//! A control master (T-039): OpenSSH's control protocol, served on a socket
//! that the caller bound, over the run's connection to the destination.
//! Each client of this user (or root, as OpenSSH allows) asks for a
//! session, a stdio forward, a forward of `-O forward`, or `-O check`,
//! `exit` and `stop`. All of them share one relay session, and its limits.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use russh::client::Handle;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch};

use super::proto::{Fwd, FwdKind, Message, VERSION};
use super::{msession, wire};
use crate::handler::Client;
use crate::local::LocalForward;
use crate::log::Log;

/// How long the master stays with no client: `ControlPersist`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persist {
    /// As long as the run lasts.
    No,
    Forever,
    For(Duration),
}

/// Makes the listeners of a forward of `-O forward -L` or `-D`: the
/// caller's, as this crate binds nothing.
pub type Binder = Arc<dyn Fn(Fwd) -> Pin<Box<dyn Future<Output = Result<LocalForward, String>> + Send>> + Send + Sync>;

/// A control socket that the caller bound, and how to serve it.
pub struct Control {
    pub listener: UnixListener,
    /// The socket's file, removed when the master stops listening.
    pub path: PathBuf,
    pub persist: Persist,
    pub binder: Option<Binder>,
    /// `ControlMaster ask`: each request that changes something is
    /// confirmed, on the terminal or through `SSH_ASKPASS`.
    pub ask: bool,
    /// Whether a session of a client may forward the master's agent.
    pub agent: bool,
    /// The destination, for the confirmations.
    pub host: String,
}

/// How serving ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// `-O exit`.
    Terminated,
    /// No client for the time of `ControlPersist`.
    Idle,
    /// No listener and no client is left.
    Done,
}

/// What a client asks of the serving loop.
enum Op {
    Open(Fwd, LocalForward, oneshot::Sender<Result<(), String>>),
    Close(Fwd, oneshot::Sender<Result<(), String>>),
    Stop,
    Terminate,
}

/// Serve `control` on `handle` until a client says `-O exit`, the master
/// is idle for its `ControlPersist`, or nothing is left to serve; with
/// `draining` set, no new client is taken.
pub async fn serve(
    handle: &Handle<Client>,
    control: Control,
    mut draining: watch::Receiver<bool>,
    log: &Arc<Log>,
) -> Served {
    let Control { listener, path, persist, binder, ask, agent, host } = control;
    let mut listener = Some(listener);
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let (ops, mut asked) = mpsc::channel::<Op>(8);
    let (winch_tx, winch) = watch::channel(0u64);
    let mut window = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok();
    let mut clients = FuturesUnordered::new();
    let mut serving = FuturesUnordered::new();
    let mut cancels: Vec<(Fwd, oneshot::Sender<()>)> = Vec::new();
    let mut sid = 0u32;
    let idle_for = match persist {
        Persist::For(d) => Some(d),
        _ => None,
    };
    let idle = tokio::time::sleep(idle_for.unwrap_or(Duration::MAX / 4));
    tokio::pin!(idle);
    let ended = loop {
        if *draining.borrow() && listener.is_some() {
            listener = None;
            let _ = std::fs::remove_file(&path);
        }
        if listener.is_none() && clients.is_empty() {
            break Served::Done;
        }
        tokio::select! {
            accepted = accept(listener.as_ref()) => match accepted {
                Ok(stream) => match stream.peer_cred() {
                    Ok(cred) if cred.uid() == uid || cred.uid() == 0 => {
                        sid += 1;
                        let job = Job { handle, ops: ops.clone(), winch: winch.clone(), log, ask, agent, host: &host, binder: binder.clone(), sid };
                        clients.push(job.run(stream));
                    }
                    Ok(cred) => log.info(&format!("control socket: closed a client of uid {}: this master is uid {uid}'s", cred.uid())),
                    Err(e) => log.info(&format!("control socket: closed a client whose user is not known: {e}")),
                },
                Err(e) => {
                    log.info(&format!("control socket: {e}; it no longer listens"));
                    listener = None;
                    let _ = std::fs::remove_file(&path);
                }
            },
            Some(()) = clients.next() => {
                if let (true, Some(d)) = (clients.is_empty(), idle_for) {
                    idle.as_mut().reset(tokio::time::Instant::now() + d);
                }
            }
            Some(op) = asked.recv() => match op {
                Op::Open(fwd, forward, reply) => {
                    let (cancel, cancelled) = oneshot::channel::<()>();
                    cancels.push((fwd, cancel));
                    serving.push(async move {
                        tokio::select! {
                            () = crate::local::serve(handle, std::slice::from_ref(&forward), log) => {}
                            _ = cancelled => {}
                        }
                    });
                    let _ = reply.send(Ok(()));
                }
                Op::Close(fwd, reply) => match cancels.iter().position(|(f, _)| *f == fwd) {
                    Some(at) => {
                        let _ = cancels.swap_remove(at).1.send(());
                        let _ = reply.send(Ok(()));
                    }
                    None => {
                        let _ = reply.send(Err("no such forward".into()));
                    }
                },
                Op::Stop => {
                    listener = None;
                    let _ = std::fs::remove_file(&path);
                }
                Op::Terminate => break Served::Terminated,
            },
            Some(()) = serving.next() => {}
            Some(()) = signal(&mut window) => winch_tx.send_modify(|n| *n += 1),
            () = &mut idle, if idle_for.is_some() && clients.is_empty() => break Served::Idle,
            Ok(()) = draining.changed() => {}
        }
    };
    let _ = std::fs::remove_file(&path);
    ended
}

async fn accept(listener: Option<&UnixListener>) -> std::io::Result<UnixStream> {
    match listener {
        Some(l) => l.accept().await.map(|(stream, _)| stream),
        None => std::future::pending().await,
    }
}

async fn signal(window: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    match window {
        Some(w) => w.recv().await,
        None => std::future::pending().await,
    }
}

/// One client's connection, and what it may use.
pub(super) struct Job<'a> {
    handle: &'a Handle<Client>,
    ops: mpsc::Sender<Op>,
    winch: watch::Receiver<u64>,
    log: &'a Arc<Log>,
    ask: bool,
    agent: bool,
    host: &'a str,
    binder: Option<Binder>,
    sid: u32,
}

impl Job<'_> {
    /// The hellos, then each request until the client leaves; a session or
    /// a stdio forward takes the rest of the connection.
    async fn run(self, mut stream: UnixStream) {
        let hello = Message::Hello { version: VERSION, extensions: Vec::new() };
        if wire::write(&mut stream, &hello).await.is_err() {
            return;
        }
        match wire::read(&mut stream).await {
            Ok(Some(Message::Hello { version: VERSION, .. })) => {}
            other => {
                self.log.verbose(&format!(
                    "control socket: a client that did not say hello in version {VERSION}: {other:?}"
                ));
                return;
            }
        }
        while let Ok(Some(request)) = wire::read(&mut stream).await {
            if !self.answer(request, &mut stream).await {
                return;
            }
        }
    }

    /// Answer one request: whether the connection takes another.
    async fn answer(&self, request: Message, stream: &mut UnixStream) -> bool {
        let reply = match request {
            Message::AliveCheck { rid } => Message::Alive { rid, pid: std::process::id() },
            Message::Terminate { rid } => {
                if !self.confirm(&format!("Terminate shared connection to {}? ", self.host)).await {
                    return denied(stream, rid).await;
                }
                let _ = wire::write(stream, &Message::Ok { rid }).await;
                let _ = self.ops.send(Op::Terminate).await;
                return false;
            }
            Message::StopListening { rid } => {
                if !self.confirm(&format!("Disable further multiplexing on shared connection to {}? ", self.host)).await
                {
                    return denied(stream, rid).await;
                }
                let _ = self.ops.send(Op::Stop).await;
                Message::Ok { rid }
            }
            Message::NewSession(asked) => {
                let rid = asked.rid;
                let fds = match (wire::recv_fd(stream).await, wire::recv_fd(stream).await, wire::recv_fd(stream).await)
                {
                    (Ok(a), Ok(b), Ok(c)) => [a, b, c],
                    _ => return false,
                };
                if !self.confirm(&format!("Allow shared connection to {}? ", self.host)).await {
                    return denied(stream, rid).await;
                }
                let (handle, agent, winch, log) = (self.handle, self.agent, self.winch.clone(), self.log);
                msession::session(handle, asked, fds, self.sid, stream, agent, winch, log).await;
                return false;
            }
            Message::NewStdioFwd { rid, host, port } => {
                let fds = match (wire::recv_fd(stream).await, wire::recv_fd(stream).await) {
                    (Ok(a), Ok(b)) => [a, b],
                    _ => return false,
                };
                if !self.confirm(&format!("Allow forward to {host}:{port}? ")).await {
                    return denied(stream, rid).await;
                }
                msession::stdio(self.handle, rid, &host, port, fds, self.sid, stream, self.log).await;
                return false;
            }
            Message::OpenFwd { rid, fwd } => {
                if !self.confirm(&format!("Open {} forward on {}? ", kind_name(fwd.kind), self.host)).await {
                    return denied(stream, rid).await;
                }
                super::fwd::open(self, rid, fwd).await
            }
            Message::CloseFwd { rid, fwd } => {
                if !self.confirm(&format!("Close {} forward on {}? ", kind_name(fwd.kind), self.host)).await {
                    return denied(stream, rid).await;
                }
                super::fwd::close(self, rid, fwd).await
            }
            Message::Proxy { rid } => Message::Failure { rid, reason: "podssh's master takes no proxy client".into() },
            Message::Unknown { kind, rid: Some(rid) } => {
                Message::Failure { rid, reason: format!("unsupported request 0x{kind:08x}") }
            }
            other => {
                self.log.verbose(&format!("control socket: an unexpected message {other:?}"));
                return false;
            }
        };
        wire::write(stream, &reply).await.is_ok()
    }

    /// Whether the user allows `question`; always, unless `ControlMaster
    /// ask`, which asks on the terminal or through `SSH_ASKPASS`.
    async fn confirm(&self, question: &str) -> bool {
        if !self.ask {
            return true;
        }
        let question = question.to_string();
        let answer = tokio::task::spawn_blocking(move || crate::prompt::ask(&question, true)).await;
        // An askpass dialog that says OK prints nothing.
        matches!(answer, Ok(Ok(a)) if a.trim().is_empty() || a.trim().to_ascii_lowercase().starts_with('y'))
    }
}

pub(super) fn kind_name(kind: FwdKind) -> &'static str {
    match kind {
        FwdKind::Local => "local",
        FwdKind::Remote => "remote",
        FwdKind::Dynamic => "dynamic",
    }
}

async fn denied(stream: &mut UnixStream, rid: u32) -> bool {
    wire::write(stream, &Message::PermissionDenied { rid, reason: "Permission denied".into() }).await.is_ok()
}

/// The parts of a job that the forwards use.
impl Job<'_> {
    pub(super) fn handle(&self) -> &Handle<Client> {
        self.handle
    }
    pub(super) fn binder(&self) -> Option<&Binder> {
        self.binder.as_ref()
    }
    pub(super) fn log(&self) -> &Log {
        self.log
    }
    pub(super) async fn open_local(&self, fwd: Fwd, forward: LocalForward) -> Result<(), String> {
        let (reply, answer) = oneshot::channel();
        self.ops.send(Op::Open(fwd, forward, reply)).await.map_err(|_| "the master is ending".to_string())?;
        answer.await.map_err(|_| "the master is ending".to_string())?
    }
    pub(super) async fn close_local(&self, fwd: Fwd) -> Result<(), String> {
        let (reply, answer) = oneshot::channel();
        self.ops.send(Op::Close(fwd, reply)).await.map_err(|_| "the master is ending".to_string())?;
        answer.await.map_err(|_| "the master is ending".to_string())?
    }
}
