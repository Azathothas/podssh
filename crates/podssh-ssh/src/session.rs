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
use crate::log::Log;
use crate::options::{Options, Request, RequestTty};
use crate::terminal;

/// The exit code when the session ends without an exit status (OpenSSH: 255).
const NO_STATUS: i32 = 255;
/// How long to wait for the server to answer a pty or session request.
const REPLY_WAIT: Duration = Duration::from_secs(30);

/// Run `opts.request` on a new session channel.
pub async fn run(handle: &Handle<Client>, opts: &Options, host: &str, log: &Arc<Log>) -> Result<i32, String> {
    let mut input = io::Input::new(opts.stdin_null);
    let end = attach(handle, opts, host, log, &mut input).await?;
    code(end, host)
}

/// The exit code of a session that ended so, or the words of a lost link.
pub fn code(end: io::End, host: &str) -> Result<i32, String> {
    match end {
        io::End::Status(code) => Ok(code),
        io::End::NoStatus | io::End::Escaped(_) | io::End::Terminated => Ok(NO_STATUS),
        io::End::Lost => Err(format!("the connection to {host} was lost before the session ended")),
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

    let what = match &opts.request {
        Request::Shell => {
            channel.request_shell(true).await.map_err(|e| e.to_string())?;
            "a shell".to_string()
        }
        Request::Exec(command) => {
            channel.exec(true, command.as_bytes()).await.map_err(|e| e.to_string())?;
            "the command".to_string()
        }
        Request::Subsystem(name) => {
            channel.request_subsystem(true, name.as_str()).await.map_err(|e| e.to_string())?;
            format!("the subsystem '{name}'")
        }
        Request::StdioForward { .. } | Request::Nothing => unreachable!("not a session request"),
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
    let escapes = match (pty && stdin_tty, opts.escape_char) {
        (true, Some(c)) => Some(Escapes::new(c)),
        _ => None,
    };
    let end = io::pump(handle, channel, early, escapes, pty, input, log).await;
    drop(raw);
    if pty && stdin_tty {
        log.info(&format!("Connection to {host} closed."));
    }
    Ok(end)
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
fn environment(opts: &Options) -> Vec<(String, String)> {
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
