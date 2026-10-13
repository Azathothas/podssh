//! A session channel: a shell, a command or a subsystem, with or without a
//! pty, until the server closes it. Returns the exit code podssh should exit
//! with.

use std::sync::Arc;
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg};

use crate::escape::Escapes;
use crate::handler::Client;
use crate::io;
use crate::keep::Ask;
use crate::log::Log;
use crate::options::{Agent, Elevate, Options, Request, RequestTty};
use crate::terminal;

/// The exit code when the session ends without an exit status (OpenSSH: 255).
const NO_STATUS: i32 = 255;
/// How long to wait for the server to answer a pty or session request.
const REPLY_WAIT: Duration = Duration::from_secs(30);

/// Run `opts.request` on a new session channel.
pub async fn run(handle: &Handle<Client>, opts: &Options, host: &str, log: &Arc<Log>) -> Result<i32, String> {
    let mut input = io::Input::new(opts.stdin_null);
    let end = attach(handle, opts, host, log, &mut input).await?;
    // russh tells the handler why the connection failed, before the channel
    // ends: a lost session says it.
    code(end, host).map_err(|lost| match crate::handler::take_last_error() {
        Some(cause) => format!("{lost}: {cause}"),
        None => lost,
    })
}

/// The exit code of a session that ended so, or the words of a lost link.
pub fn code(end: io::End, host: &str) -> Result<i32, String> {
    crate::outcome::ended(&end);
    match end {
        io::End::Status(code) => Ok(code),
        io::End::NoStatus | io::End::Escaped(_) | io::End::Terminated => Ok(NO_STATUS),
        io::End::Lost => Err(format!("the connection to {host} was lost before the session ended")),
        // The far end keeps the shell, as the user asked (T-158).
        io::End::Detached(_) => Ok(0),
        // Ctrl-C ended podssh before the command ended (T-293).
        io::End::Interrupted => Ok(terminal::interrupt::INTERRUPTED),
    }
}

/// `opts.request` on a new session channel with `input`, until the session
/// ends: how it ended. `--persist` reads a lost link in it, and keeps the
/// input for the next session.
pub async fn attach(
    handle: &Handle<Client>,
    opts: &Options,
    host: &str,
    log: &Arc<Log>,
    input: &mut io::Input,
) -> Result<io::End, String> {
    // `--attach` needs a far end that keeps shells (T-158).
    opts.keep.check(host)?;
    let mut channel =
        handle.channel_open_session().await.map_err(|e| format!("the server refused to open a session: {e}"))?;
    for (name, value) in environment(opts) {
        // No reply asked for: servers refuse unlisted variables silently.
        let _ = channel.set_env(false, name, value).await;
    }

    let stdin_tty = terminal::stdin_is_terminal();
    let want_pty = match opts.request_tty {
        RequestTty::No => false,
        RequestTty::Force => true,
        RequestTty::Yes => {
            if !stdin_tty {
                log.info("Pseudo-terminal will not be allocated because stdin is not a terminal.");
            }
            stdin_tty
        }
        RequestTty::Auto => stdin_tty && opts.request == Request::Shell,
    };
    let mut early = Vec::new();
    let mut pty = false;
    if want_pty {
        let size = terminal::size().unwrap_or_else(terminal::fallback_size);
        let modes = terminal::pty_modes();
        channel
            .request_pty(true, &terminal::term_name(), size.cols, size.rows, size.px_width, size.px_height, &modes)
            .await
            .map_err(|e| format!("could not request a pseudo-terminal: {e}"))?;
        pty = wait_reply(&mut channel, &mut early).await?;
        if !pty {
            log.info("the server did not grant a pseudo-terminal; continuing without one");
        }
    }

    // Before the shell or the command, as OpenSSH asks (T-036, T-037).
    if opts.forward_agent != Agent::Off {
        crate::agent_forward::request(&mut channel, &mut early, log).await?;
    }
    if let Some(x11) = &opts.forward_x11 {
        crate::x11::request(&mut channel, &mut early, x11, log).await?;
    }

    // From here a drop is no failure to try again: the server may run it.
    crate::retry::reached(crate::retry::Phase::Requested);
    // `--attach NAME` (T-158): the shell request joins the kept shell.
    if let Some(Ask::Attach { name, take }) = &opts.keep.ask {
        crate::keep::ask_attach(&mut channel, &mut early, name, *take).await?;
    }
    let mut elevated = None;
    let what = match &opts.request {
        Request::Shell => {
            channel.request_shell(true).await.map_err(|e| e.to_string())?;
            "a shell".to_string()
        }
        Request::Exec(command) => {
            let line = match opts.elevate {
                Some(how) => {
                    let markers = crate::elevate::Markers::new();
                    let line = crate::elevate::command(how, command, &markers);
                    let may_ask = !opts.batch_mode && crate::prompt::can_ask();
                    elevated = Some(crate::elevate::Elevated::new(how, markers, question(how, opts, host), may_ask));
                    line
                }
                None => command.clone(),
            };
            channel.exec(true, line.as_bytes()).await.map_err(|e| e.to_string())?;
            "the command".to_string()
        }
        Request::Subsystem(name) => {
            channel.request_subsystem(true, name.as_str()).await.map_err(|e| e.to_string())?;
            format!("the subsystem '{name}'")
        }
        Request::StdioForward(_) | Request::Nothing => unreachable!("not a session request"),
    };
    if !wait_reply(&mut channel, &mut early).await? {
        return Err(format!("the server refused to start {what}"));
    }

    // Raw mode only when the server runs the line discipline (a pty) and the
    // local side is a terminal; otherwise the local terminal keeps its own.
    let raw = if pty && stdin_tty {
        match terminal::RawMode::enter() {
            Ok(r) => Some(r),
            Err(e) => {
                log.info(&format!("could not put the terminal in raw mode: {e}"));
                None
            }
        }
    } else {
        None
    };
    // `~d` keeps a shell on a far end that keeps shells (T-158).
    let detach = opts.keep.detach_name(pty && stdin_tty && opts.request == Request::Shell);
    let escapes = match (pty && stdin_tty, opts.escape_char) {
        (true, Some(c)) => Some(Escapes::new(c).with_detach(detach.is_some())),
        _ => None,
    };
    // `--record` (T-033): the output from here on, with the size of now.
    let record = opts.record.as_ref().and_then(|target| target.take()).and_then(|file| {
        let size = terminal::size().unwrap_or_else(terminal::fallback_size);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        crate::record::Recorder::start(file, size, &terminal::term_name(), now)
            .map_err(|e| log.info(&format!("--record: the file could not be written: {e}")))
            .ok()
    });
    // ZMODEM (T-148) only with a raw terminal and a terminal on stdout: with
    // no terminal, nothing is ever received.
    let zmodem = crate::zmodem::Zmodem::for_session(raw.is_some() && terminal::stdout_is_terminal());
    let detaching = crate::keep::Detaching::new(detach);
    let through = io::Through { elevated, zmodem, record, detaching, sink: opts.output.clone() };
    // With no remote pty, Ctrl-C sends `signal INT` to a command or a shell
    // (T-293); a subsystem gets none, as sshd refuses it for one.
    let runs = matches!(opts.request, Request::Shell | Request::Exec(_));
    let interrupt = terminal::interrupt::Interrupt::for_session(!pty && runs && opts.interrupt_signal);
    let end = io::pump(handle, channel, early, escapes, pty, input, through, interrupt, log).await;
    drop(raw);
    if let io::End::Detached(name) = &end {
        log.info(&crate::keep::kept_line(name, host));
    }
    if pty && stdin_tty {
        log.info(&format!("Connection to {host} closed."));
    }
    Ok(end)
}

/// The question for the password of `--sudo` or `--su` (T-032).
fn question(how: Elevate, opts: &Options, host: &str) -> String {
    match how {
        Elevate::Sudo => {
            let user = opts.destination.user.as_deref().unwrap_or(&opts.user);
            format!("[sudo] password for {user}@{host}: ")
        }
        Elevate::Su => format!("[su] password of root@{host}: "),
    }
}

/// Wait for the reply to a request sent with `want_reply`. Messages that
/// arrive first are kept for the pump. Silence for [`REPLY_WAIT`] counts as a
/// refusal (RFC 4254 gives the reply no reason, and a server may never send
/// one). The `sftp` subsystem of [`crate::sftp`] waits the same way.
pub(crate) async fn wait_reply(channel: &mut Channel<Msg>, early: &mut Vec<ChannelMsg>) -> Result<bool, String> {
    let deadline = tokio::time::Instant::now() + REPLY_WAIT;
    loop {
        match tokio::time::timeout_at(deadline, channel.wait()).await {
            Err(_) => return Ok(false),
            Ok(None) => return Err("the server closed the session".into()),
            Ok(Some(ChannelMsg::Success)) => return Ok(true),
            Ok(Some(ChannelMsg::Failure)) => return Ok(false),
            Ok(Some(ChannelMsg::WindowAdjusted { .. })) => {}
            Ok(Some(other)) => early.push(other),
        }
    }
}

/// `SetEnv` pairs, then local variables matching a `SendEnv` pattern.
/// The variables of `SetEnv` and `SendEnv`, as a session sends them; a
/// client of a control master sends them too (T-039).
pub fn environment(opts: &Options) -> Vec<(String, String)> {
    let mut out = opts.set_env.clone();
    if opts.send_env.is_empty() {
        return out;
    }
    for (name, value) in std::env::vars() {
        let wanted = opts.send_env.iter().any(|p| {
            let (negated, pattern) = match p.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, p.as_str()),
            };
            !negated && crate::known_hosts::wildcard(pattern.as_bytes(), name.as_bytes())
        });
        if wanted && !out.iter().any(|(n, _)| *n == name) {
            out.push((name, value));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each end of a session gives its code, and none with no status gives 0
    /// (T-026).
    #[test]
    fn exit_code_of_end_is_never_a_success_with_no_status() {
        assert_eq!(code(io::End::Status(0), "h"), Ok(0));
        assert_eq!(code(io::End::Status(7), "h"), Ok(7));
        assert_eq!(code(io::End::Status(141), "h"), Ok(141));
        assert_eq!(code(io::End::NoStatus, "h"), Ok(NO_STATUS));
        assert_eq!(code(io::End::Terminated, "h"), Ok(NO_STATUS));
        assert_eq!(code(io::End::Escaped(crate::escape::Command::Disconnect), "h"), Ok(NO_STATUS));
        assert!(code(io::End::Lost, "h").unwrap_err().contains("was lost before the session ended"));
        assert_eq!(NO_STATUS, 255);
    }

    /// Ctrl-C that ended podssh before the command ended gives 130, as a
    /// shell reports a process that SIGINT ended (T-293).
    #[test]
    fn exit_code_of_end_after_ctrl_c_is_130() {
        assert_eq!(code(io::End::Interrupted, "h"), Ok(130));
    }

    /// A status above 255 is no success: OpenSSH's 256 would read as 0.
    #[test]
    fn exit_code_of_end_with_a_status_above_255() {
        assert_eq!(io::status_code(0), 0);
        assert_eq!(io::status_code(255), 255);
        assert_eq!(io::status_code(256), 255);
        assert_eq!(io::status_code(u32::MAX), 255);
        assert_eq!(code(io::End::Status(io::status_code(256)), "h"), Ok(255));
    }

    /// A closed stdout ends with the status that came before or after it,
    /// within the wait, and with 255 when none came.
    #[test]
    fn exit_code_of_end_after_a_closed_stdout() {
        assert_eq!(code(io::end_with(Some(0)), "h"), Ok(0));
        assert_eq!(code(io::end_with(Some(7)), "h"), Ok(7));
        assert_eq!(code(io::end_with(None), "h"), Ok(NO_STATUS));
    }
}
