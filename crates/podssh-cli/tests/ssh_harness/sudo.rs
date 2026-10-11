//! The sudo and su of the test's server (T-032): a command of either,
//! until it starts.

use russh::server::Session;
use russh::ChannelId;

/// A command of sudo (with its prompt) or of su (with none), until it starts.
pub(super) struct Elevated {
    pub(super) prompt: Option<String>,
    pub(super) started: String,
    pub(super) line: Vec<u8>,
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
    /// A wrong password to su: the command ended.
    Refused,
}

/// Input to a command that waits for its password: the password alone, as
/// any other input is held until the start, and then `secret`.
pub(super) fn password(
    mut elevated: Elevated,
    data: &[u8],
    channel: ChannelId,
    session: &mut Session,
) -> Result<Read, russh::Error> {
    elevated.line.extend_from_slice(data);
    let Some(end) = elevated.line.iter().position(|b| *b == b'\n') else { return Ok(Read::Waiting(elevated)) };
    let Elevated { prompt, started, line } = elevated;
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
            Read::Waiting(Elevated { prompt: Some(prompt), started, line: Vec::new() })
        }
        (None, false) => {
            session.data(channel, b"\r\nsu: Authentication failure\r\n".as_slice())?;
            session.exit_status_request(channel, 1)?;
            session.eof(channel)?;
            session.close(channel)?;
            Read::Refused
        }
    })
}
