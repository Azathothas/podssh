//! Copying between the local stdin/stdout/stderr and a session channel, with
//! window-size changes and the escape character, until the channel closes.
//! The input outlives a session: `--persist` attaches a new one after a
//! lost link, and it reads on where the last one stopped.

use std::sync::Arc;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::escape::{Command, Escapes};
use crate::handler::Client;
use crate::log::Log;
use crate::signals;
use crate::terminal::{self, Size};

/// How a session ended.
#[derive(Debug)]
pub enum End {
    /// The remote command's exit status (or 128 + a signal).
    Status(i32),
    /// The channel closed without an exit status.
    NoStatus,
    /// The connection went away under the session.
    Lost,
    /// The user typed an escape that ends the session.
    Escaped(Command),
    /// podssh was told to stop (SIGTERM, SIGHUP).
    Terminated,
}

/// What a user types while `--persist` connects again waits for the next
/// session, this much at most.
pub const QUEUE: usize = 64 * 1024;

/// The local input of a run. It is read on its own task from the first
/// session on, so that a session after a lost link reads on where the last
/// one stopped, and what came between them waits in a queue.
#[derive(Default)]
pub struct Input {
    /// `-n`: nothing is read, and the far side sees the end of input at once.
    null: bool,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// The input has ended: a later session sees its end after the queue.
    ended: bool,
    queued: Vec<u8>,
    /// Bytes that did not fit the queue.
    dropped: usize,
}

impl Input {
    /// The input of a run; none with `null` (`-n`).
    pub fn new(null: bool) -> Self {
        Input { null, ..Input::default() }
    }

    /// Whether a session has input to read.
    fn open(&self) -> bool {
        !self.null && !(self.ended && self.queued.is_empty())
    }

    /// The next bytes: the queue first, then what is read; `None` at the
    /// end. The task that reads starts at the first call, after the login,
    /// so that it takes nothing that a prompt reads.
    async fn next(&mut self) -> Option<Vec<u8>> {
        if !self.queued.is_empty() {
            return Some(std::mem::take(&mut self.queued));
        }
        if self.ended {
            return None;
        }
        let read = self.rx.get_or_insert_with(spawn_stdin).recv().await;
        if read.is_none() {
            self.ended = true;
        }
        read
    }

    /// Between two sessions: keep what is read for the next one, [`QUEUE`]
    /// bytes at most. It never returns; the wait drops it when it ends.
    pub async fn queue(&mut self) {
        loop {
            match self.rx.as_mut() {
                Some(rx) if !self.ended => match rx.recv().await {
                    Some(bytes) => {
                        let kept = bytes.len().min(QUEUE.saturating_sub(self.queued.len()));
                        self.queued.extend_from_slice(&bytes[..kept]);
                        self.dropped += bytes.len() - kept;
                    }
                    None => self.ended = true,
                },
                _ => std::future::pending::<()>().await,
            }
        }
    }

    /// The bytes that did not fit the queue since the last call.
    pub fn take_dropped(&mut self) -> usize {
        std::mem::take(&mut self.dropped)
    }
}

pub async fn pump(
    handle: &Handle<Client>,
    channel: Channel<Msg>,
    early: Vec<ChannelMsg>,
    mut escapes: Option<Escapes>,
    pty: bool,
    input: &mut Input,
    log: &Arc<Log>,
) -> End {
    let (mut reader, writer) = channel.split();
    let mut status: Option<i32> = None;
    for msg in early {
        if let Some(end) = handle_msg(msg, &mut status, log).await {
            return end;
        }
    }
    // False once this session's input has ended, or its channel takes no more.
    let mut reading = input.open();
    if !reading {
        let _ = writer.eof().await;
    }
    let mut resize = Resize::new(pty);
    let mut stop = Termination::new(pty && terminal::raw_active());
    loop {
        tokio::select! {
            chunk = next(input, reading) => match chunk {
                Some(bytes) => {
                    let (data, commands) = match escapes.as_mut() {
                        Some(e) => e.feed(&bytes),
                        None => (bytes, Vec::new()),
                    };
                    if !data.is_empty() {
                        // The send waits for the channel's window, which a
                        // connection that ended never opens: the channel's
                        // messages are read meanwhile, and its end ends this.
                        let send = writer.data_bytes(data);
                        tokio::pin!(send);
                        loop {
                            tokio::select! {
                                sent = &mut send => {
                                    if sent.is_err() {
                                        // The channel is closing; keep reading for its status.
                                        reading = false;
                                    }
                                    break;
                                }
                                msg = reader.wait() => match msg {
                                    Some(m) => {
                                        if let Some(end) = handle_msg(m, &mut status, log).await {
                                            return end;
                                        }
                                    }
                                    None => return status.map(End::Status).unwrap_or(End::Lost),
                                },
                            }
                        }
                    }
                    for command in commands {
                        match command {
                            Command::Disconnect => return End::Escaped(command),
                            Command::Rekey => {
                                log.info("rekeying");
                                let _ = handle.rekey_soon().await;
                            }
                            Command::Help => {
                                if let Some(e) = &escapes {
                                    log.banner(&e.help());
                                }
                            }
                        }
                    }
                }
                None => {
                    reading = false;
                    let _ = writer.eof().await;
                }
            },
            msg = reader.wait() => match msg {
                Some(m) => {
                    if let Some(end) = handle_msg(m, &mut status, log).await {
                        return end;
                    }
                }
                None => return status.map(End::Status).unwrap_or(End::Lost),
            },
            Some(size) = resize.next() => {
                let _ = writer.window_change(size.cols, size.rows, size.px_width, size.px_height).await;
            }
            _ = stop.next() => return End::Terminated,
        }
    }
}

async fn handle_msg(msg: ChannelMsg, status: &mut Option<i32>, log: &Log) -> Option<End> {
    match msg {
        ChannelMsg::Data { data } => {
            if write_out(&data, false).await.is_err() {
                // Whoever reads our stdout has gone (EPIPE): end quietly.
                return Some(End::Status(status.unwrap_or(0)));
            }
        }
        ChannelMsg::ExtendedData { data, .. } => {
            let _ = write_out(&data, true).await;
        }
        ChannelMsg::ExitStatus { exit_status } => {
            *status = Some(i32::try_from(exit_status).unwrap_or(255).min(255));
        }
        ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, .. } => {
            let name = signals::name(&signal_name);
            *status = Some(signals::number(&signal_name).map_or(255, |n| 128 + n));
            let mut note = format!("the remote command was killed by signal {name}");
            if core_dumped {
                note.push_str(" (core dumped)");
            }
            let detail = podssh_ws::text::one_line(&error_message);
            if !detail.is_empty() {
                note.push_str(": ");
                note.push_str(&detail);
            }
            log.info(&note);
        }
        ChannelMsg::Close => return Some(status.map(End::Status).unwrap_or(End::NoStatus)),
        // Eof: the server sends nothing more, but the exit status and the
        // close are still to come.
        _ => {}
    }
    None
}

async fn write_out(data: &[u8], to_stderr: bool) -> std::io::Result<()> {
    if to_stderr {
        let mut err = tokio::io::stderr();
        err.write_all(data).await?;
        err.flush().await
    } else {
        let mut out = tokio::io::stdout();
        out.write_all(data).await?;
        out.flush().await
    }
}

/// Read stdin on its own task. The receiver yields `None` at end of input.
fn spawn_stdin() -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

async fn next(input: &mut Input, reading: bool) -> Option<Vec<u8>> {
    if !reading {
        return std::future::pending().await;
    }
    input.next().await
}

/// Window-size changes: SIGWINCH on Unix, polling on Windows (a console has
/// no signal for it).
struct Resize {
    active: bool,
    last: Option<Size>,
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
    #[cfg(windows)]
    tick: tokio::time::Interval,
}

impl Resize {
    fn new(active: bool) -> Self {
        Resize {
            active,
            last: terminal::size(),
            #[cfg(unix)]
            signal: if active {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
            } else {
                None
            },
            #[cfg(windows)]
            tick: tokio::time::interval(std::time::Duration::from_millis(500)),
        }
    }

    async fn next(&mut self) -> Option<Size> {
        if !self.active {
            return std::future::pending().await;
        }
        loop {
            #[cfg(unix)]
            match self.signal.as_mut() {
                Some(s) => {
                    s.recv().await?;
                }
                None => return std::future::pending().await,
            }
            #[cfg(windows)]
            self.tick.tick().await;
            let now = terminal::size();
            if now.is_some() && now != self.last {
                self.last = now;
                return now;
            }
        }
    }
}

/// SIGTERM and SIGHUP while the terminal is raw: end the session properly so
/// the terminal is restored, instead of dying with it raw.
struct Termination {
    #[cfg(unix)]
    signals: Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>,
}

impl Termination {
    fn new(active: bool) -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let signals =
                if active { signal(SignalKind::terminate()).ok().zip(signal(SignalKind::hangup()).ok()) } else { None };
            Termination { signals }
        }
        #[cfg(not(unix))]
        {
            let _ = active;
            Termination {}
        }
    }

    async fn next(&mut self) {
        #[cfg(unix)]
        if let Some((term, hup)) = self.signals.as_mut() {
            tokio::select! {
                _ = term.recv() => return,
                _ = hup.recv() => return,
            }
        }
        std::future::pending::<()>().await
    }
}
