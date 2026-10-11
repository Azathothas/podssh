//! A client of a control master (T-039), OpenSSH's or podssh's: the hellos,
//! then a session, a stdio forward, or a request of `-O`. A session passes
//! this process's stdin, stdout and stderr, puts the terminal in raw mode
//! with a pty, relays SIGWINCH to the master, which reads the new size from
//! the terminal itself, and exits with the status of EXIT_MESSAGE, or 255
//! with none, as OpenSSH's client does.

use std::io;
use std::path::Path;

use tokio::net::UnixStream;
use tokio::signal::unix::{signal, SignalKind};

use super::proto::{Fwd, Message, NewSession, NO_ESCAPE, VERSION};
use super::wire;
use crate::log::Log;
use crate::options::StdioTarget;

/// Why no master was used.
#[derive(Debug)]
pub enum Unreached {
    /// Nothing answers on the socket: the run may connect alone.
    NoMaster(io::Error),
    /// Something answered that is not a master of version 4.
    Broken(String),
}

impl std::fmt::Display for Unreached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unreached::NoMaster(e) => write!(f, "{e}"),
            Unreached::Broken(why) => f.write_str(why),
        }
    }
}

/// What a session asks the master for.
#[derive(Debug, Clone, Default)]
pub struct SessionRequest {
    pub tty: bool,
    pub agent: bool,
    pub subsystem: bool,
    pub escape: Option<u8>,
    pub term: String,
    pub command: Vec<u8>,
    pub env: Vec<String>,
    /// The destination, for "Shared connection to HOST closed."
    pub host: String,
}

pub struct MuxClient {
    stream: UnixStream,
    rid: u32,
}

/// The master on `path`, after the hellos.
pub async fn connect(path: &Path) -> Result<MuxClient, Unreached> {
    let mut stream = UnixStream::connect(path).await.map_err(Unreached::NoMaster)?;
    let broken = |e: io::Error| Unreached::Broken(format!("the control master broke the hello: {e}"));
    wire::write(&mut stream, &Message::Hello { version: VERSION, extensions: Vec::new() }).await.map_err(broken)?;
    match wire::read(&mut stream).await.map_err(broken)? {
        Some(Message::Hello { version: VERSION, .. }) => Ok(MuxClient { stream, rid: 0 }),
        Some(Message::Hello { version, .. }) => {
            Err(Unreached::Broken(format!("the control master speaks version {version}, not {VERSION}")))
        }
        other => Err(Unreached::Broken(format!("the control master said {other:?} for hello"))),
    }
}

impl MuxClient {
    fn next(&mut self) -> u32 {
        let rid = self.rid;
        self.rid = self.rid.wrapping_add(1);
        rid
    }

    /// One request and its answer, which must name the request.
    async fn ask(&mut self, request: Message) -> Result<Message, String> {
        wire::write(&mut self.stream, &request).await.map_err(|e| format!("the control master left: {e}"))?;
        wire::read(&mut self.stream)
            .await
            .map_err(|e| format!("the control master broke its answer: {e}"))?
            .ok_or_else(|| "the control master closed the connection".to_string())
    }

    /// `-O check`: the master's pid.
    pub async fn alive(&mut self) -> Result<u32, String> {
        let rid = self.next();
        match self.ask(Message::AliveCheck { rid }).await? {
            Message::Alive { rid: r, pid } if r == rid => Ok(pid),
            other => Err(refused(other)),
        }
    }

    /// `-O exit`.
    pub async fn terminate(&mut self) -> Result<(), String> {
        let rid = self.next();
        match self.ask(Message::Terminate { rid }).await {
            Ok(Message::Ok { .. }) => Ok(()),
            // The master may end before its answer leaves.
            Err(why) if why.contains("closed") => Ok(()),
            Ok(other) => Err(refused(other)),
            Err(why) => Err(why),
        }
    }

    /// `-O stop`.
    pub async fn stop(&mut self) -> Result<(), String> {
        let rid = self.next();
        match self.ask(Message::StopListening { rid }).await? {
            Message::Ok { .. } => Ok(()),
            other => Err(refused(other)),
        }
    }

    /// `-O forward` (or `-O cancel`): the port that the server chose for a
    /// remote forward of port 0.
    pub async fn forward(&mut self, fwd: Fwd, cancel: bool) -> Result<Option<u32>, String> {
        let rid = self.next();
        let request = if cancel { Message::CloseFwd { rid, fwd } } else { Message::OpenFwd { rid, fwd } };
        match self.ask(request).await? {
            Message::Ok { .. } => Ok(None),
            Message::RemotePort { port, .. } => Ok(Some(port)),
            other => Err(refused(other)),
        }
    }

    /// A session through the master, with this process's stdin, stdout and
    /// stderr; its exit code.
    pub async fn session(self, request: SessionRequest, log: &Log) -> i32 {
        self.session_on(request, [0, 1, 2], log).await
    }

    /// [`session`](Self::session) with these descriptors.
    pub async fn session_on(mut self, request: SessionRequest, fds: [i32; 3], log: &Log) -> i32 {
        let pid = match self.alive().await {
            Ok(pid) => pid,
            Err(why) => {
                log.error(&format!("control master: {why}"));
                return crate::run::EXIT_FAILURE;
            }
        };
        let rid = self.next();
        let asked = NewSession {
            rid,
            tty: request.tty,
            x11: false,
            agent: request.agent,
            subsystem: request.subsystem,
            escape: request.escape.map_or(NO_ESCAPE, u32::from),
            term: request.term.clone(),
            command: request.command.clone(),
            env: request.env.clone(),
        };
        if let Err(why) = self.send_with(Message::NewSession(asked), &fds).await {
            log.error(&format!("control master: {why}"));
            return crate::run::EXIT_FAILURE;
        }
        let sid = match self.opened(rid, log).await {
            Some(sid) => sid,
            None => return crate::run::EXIT_FAILURE,
        };
        let mut raw = if request.tty { crate::terminal::RawMode::enter().ok() } else { None };
        let code = self.wait(sid, pid, &mut raw, log).await;
        drop(raw);
        if request.tty {
            log.info(&format!("Shared connection to {} closed.", request.host));
        }
        code
    }

    /// `-W HOST:PORT` or `-W /PATH` through the master: 0 once it closes the
    /// connection.
    pub async fn stdio(self, target: &StdioTarget, log: &Log) -> i32 {
        self.stdio_on(target, [0, 1], log).await
    }

    /// [`stdio`](Self::stdio) with these descriptors. A socket goes as
    /// OpenSSH's client sends it: its path, and the port `PORT_STREAMLOCAL`.
    pub async fn stdio_on(mut self, target: &StdioTarget, fds: [i32; 2], log: &Log) -> i32 {
        let rid = self.next();
        let (host, port) = match target {
            StdioTarget::Tcp { host, port } => (host.clone(), u32::from(*port)),
            StdioTarget::Socket(path) => (path.clone(), super::proto::PORT_STREAMLOCAL),
        };
        let request = Message::NewStdioFwd { rid, host, port };
        if let Err(why) = self.send_with(request, &fds).await {
            log.error(&format!("control master: {why}"));
            return crate::run::EXIT_FAILURE;
        }
        if self.opened(rid, log).await.is_none() {
            return crate::run::EXIT_FAILURE;
        }
        loop {
            match wire::read(&mut self.stream).await {
                Ok(None) | Err(_) => return 0,
                Ok(Some(other)) => log.verbose(&format!("control master: unexpected {other:?}")),
            }
        }
    }

    /// `request`, then each descriptor of `fds`, as OpenSSH's client sends.
    async fn send_with(&mut self, request: Message, fds: &[i32]) -> Result<(), String> {
        wire::write(&mut self.stream, &request).await.map_err(|e| format!("the control master left: {e}"))?;
        for fd in fds {
            wire::send_fd(&self.stream, *fd).await.map_err(|e| format!("could not pass descriptor {fd}: {e}"))?;
        }
        Ok(())
    }

    /// SESSION_OPENED for `rid`: the session's id.
    async fn opened(&mut self, rid: u32, log: &Log) -> Option<u32> {
        match wire::read(&mut self.stream).await {
            Ok(Some(Message::SessionOpened { rid: r, sid })) if r == rid => Some(sid),
            Ok(Some(Message::PermissionDenied { reason, .. })) => {
                log.error(&format!("Master refused session request: Permission denied: {reason}"));
                None
            }
            Ok(Some(Message::Failure { reason, .. })) => {
                log.error(&format!("Master refused session request: {reason}"));
                None
            }
            other => {
                log.error(&format!("control master: an unexpected answer to the session request: {other:?}"));
                None
            }
        }
    }

    /// Until the master closes the connection: the status of EXIT_MESSAGE,
    /// or 255 with none or at a signal of this process.
    async fn wait(&mut self, sid: u32, pid: u32, raw: &mut Option<crate::terminal::RawMode>, log: &Log) -> i32 {
        let mut window = signal(SignalKind::window_change()).ok();
        let mut stop = [SignalKind::interrupt(), SignalKind::terminate(), SignalKind::hangup()].map(|k| signal(k).ok());
        let mut code = None;
        loop {
            tokio::select! {
                msg = wire::read(&mut self.stream) => match msg {
                    Ok(Some(Message::TtyAllocFail { sid: s })) if s == sid => *raw = None,
                    Ok(Some(Message::ExitMessage { sid: s, code: c })) if s == sid => {
                        code = Some(crate::io::status_code(c));
                    }
                    Ok(Some(other)) => {
                        log.error(&format!("control master: unexpected {other:?}"));
                        return crate::run::EXIT_FAILURE;
                    }
                    Ok(None) | Err(_) => break,
                },
                Some(()) = recv(&mut window) => {
                    // The master reads the size from the terminal it holds.
                    // SAFETY: kill sends a signal and has no other effect.
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGWINCH) };
                }
                Some(()) = recv_any(&mut stop) => {
                    log.verbose("control master: exiting on a signal");
                    return crate::run::EXIT_FAILURE;
                }
            }
        }
        code.unwrap_or_else(|| {
            log.verbose("the control master ended the session with no status");
            crate::run::EXIT_FAILURE
        })
    }
}

async fn recv(signal: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    match signal {
        Some(s) => s.recv().await,
        None => std::future::pending().await,
    }
}

async fn recv_any(signals: &mut [Option<tokio::signal::unix::Signal>; 3]) -> Option<()> {
    let [a, b, c] = signals;
    tokio::select! {
        Some(()) = recv(a) => Some(()),
        Some(()) = recv(b) => Some(()),
        Some(()) = recv(c) => Some(()),
        else => None,
    }
}

/// The words of a refusal, or of an answer that names another request.
fn refused(answer: Message) -> String {
    match answer {
        Message::PermissionDenied { reason, .. } => format!("permission denied: {reason}"),
        Message::Failure { reason, .. } => reason,
        other => format!("an unexpected answer: {other:?}"),
    }
}
