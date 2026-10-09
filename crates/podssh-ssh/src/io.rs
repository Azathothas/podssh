//! Copying between the local stdin/stdout/stderr and a session channel, with
//! window-size changes and the escape character, until the channel closes.

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

pub async fn pump(
    handle: &Handle<Client>,
    channel: Channel<Msg>,
    early: Vec<ChannelMsg>,
    mut escapes: Option<Escapes>,
    pty: bool,
    stdin_null: bool,
    log: &Arc<Log>,
) -> End {
    let (mut reader, writer) = channel.split();
    let mut status: Option<i32> = None;
    for msg in early {
        if let Some(end) = handle_msg(msg, &mut status, log).await {
            return end;
        }
    }
    let mut input = if stdin_null {
        let _ = writer.eof().await;
        None
    } else {
        Some(spawn_stdin())
    };
    let mut resize = Resize::new(pty);
    let mut stop = Termination::new(pty && terminal::raw_active());
    loop {
        tokio::select! {
            chunk = recv(&mut input) => match chunk {
                Some(bytes) => {
                    let (data, commands) = match escapes.as_mut() {
                        Some(e) => e.feed(&bytes),
                        None => (bytes, Vec::new()),
                    };
                    if !data.is_empty() && writer.data_bytes(data).await.is_err() {
                        // The channel is closing; keep reading for its status.
                        input = None;
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
                    input = None;
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

async fn recv(input: &mut Option<mpsc::Receiver<Vec<u8>>>) -> Option<Vec<u8>> {
    match input {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
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
