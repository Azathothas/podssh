//! The sudo and su of the test's server (T-032): a command of either,
//! until it starts. su reads its pty as a line in canonical mode: Ctrl-U
//! drops the line, and Ctrl-D at its start is su's end of file, which it
//! refuses; the channel's EOF never reaches it, as OpenSSH's server keeps
//! the pty open (T-501). The su of a user `su-deaf-...` ignores both, as a
//! su that waits until its pty hangs up.

use russh::server::Session;
use russh::ChannelId;

/// The kill key and the end of file key of a pty's defaults.
const KILL: u8 = 0x15;
const EOF: u8 = 0x04;

/// A command of sudo (with its prompt) or of su (with none), until it starts.
pub(super) struct Elevated {
    pub(super) prompt: Option<String>,
    pub(super) started: String,
    pub(super) line: Vec<u8>,
    /// A su that ignores the keys that end its read.
    pub(super) deaf: bool,
}

impl Elevated {
    pub(super) fn new(prompt: Option<String>, started: String, deaf: bool) -> Self {
        Elevated { prompt, started, line: Vec::new(), deaf }
    }
}

/// The prompt of `sudo -S -k -p PROMPT -- sh -c '...'` (none for `su -c`),
/// and the marker that the command prints as it starts.
pub(super) fn elevation(command: &str) -> Option<(Option<String>, String)> {
    let started = command.split("printf %s ").nth(1)?.split_whitespace().next()?.to_string();
    if let Some(rest) = command.strip_prefix("sudo -S -k -p ") {
        Some((Some(rest.split_whitespace().next()?.to_string()), started))
    } else {
        command.starts_with("su -c ").then_some((None, started))
    }
}

/// What the input of a command that waits for its password led to.
pub(super) enum Read {
    /// No whole line yet, or a wrong password to sudo: it waits again.
    Waiting(Elevated),
    /// The right password: the command started, and echoes its input.
    Started,
    /// A wrong password to su, or its end of file: the command ended.
    Refused,
}

/// Input to a command that waits for its password: the password alone, as
/// any other input is held until the start, and then `secret`. su takes
/// its pty's keys first.
pub(super) fn password(
    mut elevated: Elevated,
    data: &[u8],
    channel: ChannelId,
    session: &mut Session,
) -> Result<Read, russh::Error> {
    for &byte in data {
        match (elevated.prompt.is_none(), byte) {
            (true, KILL | EOF) if elevated.deaf => {}
            (true, KILL) => elevated.line.clear(),
            (true, EOF) if elevated.line.is_empty() => return su_refuses(channel, session),
            _ => elevated.line.push(byte),
        }
    }
    let Some(end) = elevated.line.iter().position(|b| *b == b'\n') else { return Ok(Read::Waiting(elevated)) };
    let Elevated { prompt, started, line, deaf } = elevated;
    let password = String::from_utf8_lossy(&line[..end]).trim_end_matches('\r').to_string();
    let right = password == "secret" && end + 1 == line.len();
    Ok(match (prompt, right) {
        (Some(_), true) => {
            session.extended_data(channel, 1, started.into_bytes())?;
            session.data(channel, b"0\n".as_slice())?;
            Read::Started
        }
        (None, true) => {
            session.data(channel, format!("\r\n{started}0\n").into_bytes())?;
            Read::Started
        }
        (Some(prompt), false) => {
            session.extended_data(channel, 1, format!("Sorry, try again.\n{prompt}").into_bytes())?;
            Read::Waiting(Elevated { prompt: Some(prompt), started, line: Vec::new(), deaf })
        }
        (None, false) => su_refuses(channel, session)?,
    })
}

/// su's refusal of a wrong password, or of none: its words and status 1.
fn su_refuses(channel: ChannelId, session: &mut Session) -> Result<Read, russh::Error> {
    session.data(channel, b"\r\nsu: Authentication failure\r\n".as_slice())?;
    session.exit_status_request(channel, 1)?;
    session.eof(channel)?;
    session.close(channel)?;
    Ok(Read::Refused)
}

/// The client's EOF to a command that waits for its password: sudo, whose
/// stdin is the channel, refuses; su reads its pty, which stays open, and
/// waits on (the command is given back).
pub(super) fn eof(
    elevated: Elevated,
    channel: ChannelId,
    session: &mut Session,
) -> Result<Option<Elevated>, russh::Error> {
    if elevated.prompt.is_none() {
        return Ok(Some(elevated));
    }
    session.extended_data(channel, 1, b"sudo: 1 incorrect password attempt\n".to_vec())?;
    session.exit_status_request(channel, 1)?;
    session.eof(channel)?;
    session.close(channel)?;
    Ok(None)
}
