//! A command that waits for a `signal` request (T-293): `wait-signal PATH
//! acts` and `wait-signal PATH deaf` print `started`, then write the name of
//! each signal that the client sends into PATH, a line each. `acts` ends by
//! the first, as OpenSSH's sshd ends a command, and `deaf` runs on, as a
//! server that ignores the request.

use std::io::Write;
use std::path::PathBuf;

use russh::server::Session;
use russh::{ChannelId, Sig};

/// A command that waits: where its signals are written, and whether it
/// ends by one.
pub struct Wait {
    path: PathBuf,
    acts: bool,
}

/// `wait-signal PATH acts|deaf`, started; `None` for another command.
pub fn wait(command: &str, channel: ChannelId, session: &mut Session) -> Result<Option<Wait>, russh::Error> {
    let Some((path, how)) = command.strip_prefix("wait-signal ").and_then(|rest| rest.rsplit_once(' ')) else {
        return Ok(None);
    };
    session.data(channel, b"started\n".as_slice())?;
    Ok(Some(Wait { path: PathBuf::from(path), acts: how == "acts" }))
}

/// A `signal` request on a channel: written down, and acted on by a command
/// that acts. A channel of another command keeps russh's way: nothing.
pub fn received(
    wait: Option<&Wait>,
    channel: ChannelId,
    signal: Sig,
    session: &mut Session,
) -> Result<(), russh::Error> {
    let Some(wait) = wait else { return Ok(()) };
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&wait.path) {
        let _ = writeln!(file, "{}", podssh_ssh::signals::name(&signal));
    }
    if wait.acts {
        session.exit_signal_request(channel, signal, false, "", "")?;
        session.eof(channel)?;
        session.close(channel)?;
    }
    Ok(())
}
