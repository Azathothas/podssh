//! Copying between the local stdin/stdout/stderr and a session channel, with
//! window-size changes, the escape character and ZMODEM, until the channel
//! closes. The input outlives a session: `--persist` attaches a new one
//! after a lost link, and it reads on where the last one stopped.

use std::sync::Arc;
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::io::AsyncWriteExt;

use crate::elevate::Elevated;
use crate::escape::{Command, Escapes};
use crate::handler::Client;
use crate::log::Log;
use crate::record::Recorder;
use crate::signals;
use crate::terminal;
use crate::terminal::interrupt::Interrupt;
use crate::terminal::termination::Termination;
use crate::terminal::text::Consoles;
use crate::terminal::watch::Resize;
use crate::zmodem::Zmodem;

mod feed;
mod input;

pub use feed::Feed;
pub use input::Input;

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
    /// `~d`: the far end keeps the shell under this name (T-158).
    Detached(String),
    /// Ctrl-C with no remote pty, and the command did not end by it (T-293).
    Interrupted,
}

/// What a user types while `--persist` connects again waits for the next
/// session, this much at most.
pub const QUEUE: usize = 64 * 1024;

/// How long the exit status may take once stdout's reader has gone (T-026):
/// the session then ends with it, or with none.
pub const STATUS_WAIT: Duration = Duration::from_secs(5);

/// The exit code of an `exit-status` request. A status above 255 gives 255:
/// OpenSSH passes the value to `exit()`, where 256 would read as a success.
pub fn status_code(exit_status: u32) -> i32 {
    i32::try_from(exit_status).unwrap_or(255).min(255)
}

/// How a session ends once it may: with its status, or with none. A closed
/// stdout and a Close both end so, whether the status came before or after.
pub fn end_with(status: Option<i32>) -> End {
    status.map(End::Status).unwrap_or(End::NoStatus)
}

/// Where a session's output goes in place of this process's stdout and
/// stderr (T-183): each piece as it came, and whether it is stderr's. One
/// process then runs several sessions, and the receiver says whose each
/// piece is. A receiver that is gone reads as a stdout whose reader went.
pub type Sink = tokio::sync::mpsc::Sender<(Vec<u8>, bool)>;

/// Whether stdout's reader has gone, and since when: the channel's data then
/// goes nowhere, the server hears the end of input, and the status is
/// awaited for a while, never read as a success.
#[derive(Default)]
struct Out {
    gone: Option<tokio::time::Instant>,
    told: bool,
    /// The text of stdout and of stderr for a Windows console (T-294).
    consoles: Consoles,
    /// The sink in place of the process's streams, when there is one.
    sink: Option<Sink>,
}

/// What a session's output passes through on its way out: the filter of an
/// elevated command (T-032), ZMODEM (T-148), then the recording (T-033).
/// A detach that waits for the far end's answer reads the session's
/// messages too (T-158).
#[derive(Default)]
pub struct Through {
    pub elevated: Option<Elevated>,
    pub zmodem: Option<Zmodem>,
    pub record: Option<Recorder>,
    pub detaching: crate::keep::Detaching,
    /// Where the output goes in place of stdout and stderr (T-183).
    pub sink: Option<Sink>,
}

impl Through {
    fn out(&mut self, data: &[u8], stderr: bool, log: &Log) -> Vec<u8> {
        let data = match self.elevated.as_mut() {
            Some(e) => e.feed(data, stderr),
            None => data.to_vec(),
        };
        // A transfer takes its bytes off stdout, and adds podssh's words.
        let data = match self.zmodem.as_mut().filter(|_| !stderr) {
            Some(z) => z.output(&data, std::time::Instant::now()),
            None => data,
        };
        self.recorded(data, log)
    }

    /// What the terminal shows, into the recording.
    fn recorded(&mut self, data: Vec<u8>, log: &Log) -> Vec<u8> {
        if let Some(Err(e)) = self.record.as_mut().map(|r| r.output(&data)) {
            log.info(&format!("--record stopped: {e}"));
            self.record = None;
        }
        data
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn pump(
    handle: &Handle<Client>,
    channel: Channel<Msg>,
    early: Vec<ChannelMsg>,
    mut escapes: Option<Escapes>,
    pty: bool,
    input: &mut Input,
    mut through: Through,
    interrupt: Option<Interrupt>,
    log: &Arc<Log>,
) -> End {
    let (mut reader, writer) = channel.split();
    let mut status: Option<i32> = None;
    // A sink takes the bytes unchanged: its receiver knows where they go.
    let sink = through.sink.take();
    let consoles = if sink.is_some() { Consoles::default() } else { Consoles::of_this_process() };
    let mut out = Out { consoles, sink, ..Out::default() };
    // False once this session's input has ended, or its channel takes no more.
    let mut reading = input.open();
    // An elevated command's input waits for it to start (T-032).
    let mut held = through.elevated.is_some();
    for msg in early {
        if let Some(end) = handle_msg(msg, &mut status, &mut out, &mut through, log).await {
            return end;
        }
    }
    if let Some(e) = through.elevated.as_mut() {
        e.act(&writer, &mut held, !reading, log).await;
    }
    if !reading && !held {
        let _ = writer.eof().await;
    }
    let mut resize = Resize::new(pty);
    let mut stop = Termination::new(pty && terminal::raw_active(), interrupt).fed(input.feed());
    loop {
        if let Err(end) = zmodem_out(&writer, &mut reader, &mut status, &mut out, &mut through, log).await {
            return end;
        }
        let zmodem_at = through.zmodem.as_ref().and_then(Zmodem::deadline);
        let streaming = through.zmodem.as_ref().is_some_and(Zmodem::more);
        tokio::select! {
            chunk = input::next(input, reading && !held) => match chunk {
                Some(bytes) => {
                    let (data, commands) = match escapes.as_mut() {
                        Some(e) => e.feed(&bytes),
                        None => (bytes, Vec::new()),
                    };
                    // A question or a transfer of ZMODEM takes the keys.
                    let data = match through.zmodem.as_mut() {
                        Some(z) => z.keys(data, std::time::Instant::now()),
                        None => data,
                    };
                    if !data.is_empty() {
                        crate::outcome::stdin(data.len());
                        match send(&writer, &mut reader, data, &mut status, &mut out, &mut through, log).await {
                            Ok(true) => {}
                            // The channel is closing; keep reading for its status.
                            Ok(false) => reading = false,
                            Err(end) => return end,
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
                            Command::List => log.banner(&crate::tally::listing()),
                            Command::Detach => through.detaching.ask(&writer, log).await,
                            Command::Zmodem => match through.zmodem.as_mut() {
                                Some(z) => z.escape(),
                                None => log.info("ZMODEM works in a session with a pty and a local terminal"),
                            },
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
                    if let Some(end) = handle_msg(m, &mut status, &mut out, &mut through, log).await {
                        return end;
                    }
                    if let Some(e) = through.elevated.as_mut() {
                        e.act(&writer, &mut held, !reading, log).await;
                    }
                    // stdout's reader went: the server hears the end of input.
                    if out.gone.is_some() && !out.told {
                        out.told = true;
                        reading = false;
                        let _ = writer.eof().await;
                    }
                }
                None => return status.map(End::Status).unwrap_or(End::Lost),
            },
            () = sleep_until(out.gone.map(|at| at + STATUS_WAIT)), if out.gone.is_some() => {
                if status.is_none() {
                    log.info(&format!(
                        "stdout was closed, and no exit status came within {} s",
                        STATUS_WAIT.as_secs()
                    ));
                }
                return end_with(status);
            }
            expired = elevating(&mut through.elevated, &writer, log) => if expired {
                log.error(&format!(
                    "the remote command neither asked for a password nor started within {} s",
                    crate::elevate::WAIT.as_secs()
                ));
                return End::NoStatus;
            },
            Some(size) = resize.next() => {
                let _ = writer.window_change(size.cols, size.rows, size.px_width, size.px_height).await;
                if let Some(r) = through.record.as_mut() {
                    let _ = r.resize(size);
                }
            }
            // A wait of ZMODEM that ran out, and a sender's next bytes,
            // which the top of the loop sends.
            () = sleep_until(zmodem_at.map(Into::into)), if zmodem_at.is_some() => {
                if let Some(z) = through.zmodem.as_mut() {
                    z.tick(std::time::Instant::now());
                }
            }
            () = std::future::ready(()), if streaming => {}
            stopped = stop.next() => if let Some(end) = stop.act(stopped, &writer, log).await {
                return end;
            },
        }
    }
}

/// Send `data` on the channel. The send waits for the channel's window,
/// which a connection that ended never opens: the channel's messages are
/// read meanwhile, and its end ends this (`Err`). `Ok(false)`: the channel
/// is closing.
async fn send(
    writer: &ChannelWriteHalf<Msg>,
    reader: &mut ChannelReadHalf,
    data: Vec<u8>,
    status: &mut Option<i32>,
    out: &mut Out,
    through: &mut Through,
    log: &Log,
) -> Result<bool, End> {
    let send = writer.data_bytes(data);
    tokio::pin!(send);
    loop {
        tokio::select! {
            sent = &mut send => return Ok(sent.is_ok()),
            msg = reader.wait() => match msg {
                Some(m) => {
                    if let Some(end) = handle_msg(m, status, out, through, log).await {
                        return Err(end);
                    }
                }
                None => return Err(status.map_or(End::Lost, End::Status)),
            },
        }
    }
}

/// What ZMODEM has for the terminal and for the server between the
/// server's messages: its words after a key or a wait, and a sender's next
/// bytes (T-148). `Err` when the channel ended meanwhile.
async fn zmodem_out(
    writer: &ChannelWriteHalf<Msg>,
    reader: &mut ChannelReadHalf,
    status: &mut Option<i32>,
    out: &mut Out,
    through: &mut Through,
    log: &Log,
) -> Result<(), End> {
    let Some(taken) = through.zmodem.as_mut().map(|z| z.take(std::time::Instant::now())) else {
        return Ok(());
    };
    if !taken.screen.is_empty() {
        let screen = through.recorded(taken.screen, log);
        let _ = write_out(out.sink.as_ref(), &out.consoles.text(false, screen), false).await;
    }
    if !taken.server.is_empty() {
        send(writer, reader, taken.server, status, out, through, log).await?;
    }
    Ok(())
}

async fn handle_msg(
    msg: ChannelMsg,
    status: &mut Option<i32>,
    out: &mut Out,
    through: &mut Through,
    log: &Log,
) -> Option<End> {
    match msg {
        ChannelMsg::Data { data } => {
            let data = out.consoles.text(false, through.out(&data, false, log));
            // Whoever reads our stdout has gone (EPIPE): the data goes
            // nowhere, and the exit status is awaited (T-026).
            if out.gone.is_none() && write_out(out.sink.as_ref(), &data, false).await.is_err() {
                out.gone = Some(tokio::time::Instant::now());
            }
        }
        ChannelMsg::ExtendedData { data, .. } => {
            let data = out.consoles.text(true, through.out(&data, true, log));
            let _ = write_out(out.sink.as_ref(), &data, true).await;
        }
        ChannelMsg::ExitStatus { exit_status } => {
            crate::outcome::status(exit_status);
            *status = Some(status_code(exit_status));
        }
        ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, .. } => {
            let name = signals::name(&signal_name);
            crate::outcome::signal(&name, core_dumped);
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
        ChannelMsg::Close => {
            // A command that never started: what su said, its refusal.
            if let Some(e) = through.elevated.as_mut().filter(|e| !e.started()) {
                let _ = write_out(out.sink.as_ref(), &out.consoles.text(true, e.finish()), true).await;
            }
            // A sequence that the end cut, for a console (T-294).
            for stderr in [false, true] {
                let tail = out.consoles.finish(stderr);
                if !tail.is_empty() {
                    let _ = write_out(out.sink.as_ref(), &tail, stderr).await;
                }
            }
            return Some(end_with(*status));
        }
        // The answer to `~d`, when one is awaited (T-158).
        reply @ (ChannelMsg::Success | ChannelMsg::Failure) => return through.detaching.answer(&reply, log),
        // Eof: the server sends nothing more, but the exit status and the
        // close are still to come.
        _ => {}
    }
    None
}

async fn write_out(sink: Option<&Sink>, data: &[u8], to_stderr: bool) -> std::io::Result<()> {
    if let Some(sink) = sink {
        sink.send((data.to_vec(), to_stderr))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
    } else if to_stderr {
        let mut err = tokio::io::stderr();
        err.write_all(data).await?;
        err.flush().await?;
    } else {
        let mut out = tokio::io::stdout();
        out.write_all(data).await?;
        out.flush().await?;
    }
    // What `--result-file` counts (T-054).
    crate::outcome::output(data.len(), to_stderr);
    Ok(())
}

/// An elevated command's question and time (T-032): true when its time is
/// up; for ever with none.
async fn elevating(elevated: &mut Option<Elevated>, writer: &ChannelWriteHalf<Msg>, log: &Log) -> bool {
    match elevated {
        Some(e) => e.next(writer, log).await,
        None => std::future::pending().await,
    }
}

/// Until `at`, or for ever with none.
async fn sleep_until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
