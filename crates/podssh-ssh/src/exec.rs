//! One command on a new session channel, its output read in full, within a
//! limit: for the probes and the digest of `cp`, which read a short answer
//! and never a terminal.

use std::time::Duration;

use russh::client::Handle;
use russh::ChannelMsg;

use crate::handler::Client;

/// What a command wrote, and how it ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Captured {
    /// The exit status, when the server sent one.
    pub status: Option<u32>,
    /// Standard output, up to the cap.
    pub stdout: Vec<u8>,
    /// Standard error, up to the cap.
    pub stderr: Vec<u8>,
}

/// Why a command did not run to its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The server refused the channel or the command (`ForceCommand
    /// internal-sftp` does).
    Refused(String),
    /// No end within the limit.
    Timeout(Duration),
    /// The connection or the channel broke.
    Lost(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Refused(why) => write!(f, "the server refused the command: {why}"),
            ExecError::Timeout(limit) => write!(f, "the command did not end within {} s", limit.as_secs()),
            ExecError::Lost(why) => write!(f, "the command's channel broke: {why}"),
        }
    }
}

impl std::error::Error for ExecError {}

/// Keep `data` in `into`, `cap` bytes at most: a command that writes more
/// than its answer is not believed past it.
fn keep(into: &mut Vec<u8>, data: &[u8], cap: usize) {
    let room = cap.saturating_sub(into.len());
    into.extend_from_slice(&data[..data.len().min(room)]);
}

/// Run `command` on a new session channel with no pty and no input, and read
/// each output, `cap` bytes at most, until the channel closes, within `limit`.
pub async fn capture(
    handle: &Handle<Client>,
    command: &str,
    limit: Duration,
    cap: usize,
) -> Result<Captured, ExecError> {
    let run = async {
        let mut channel =
            handle.channel_open_session().await.map_err(|e| ExecError::Refused(format!("no session channel: {e}")))?;
        channel.exec(true, command.as_bytes()).await.map_err(|e| ExecError::Lost(e.to_string()))?;
        // The command reads no input: the end of it at once, so a command
        // that reads anyway does not wait.
        let _ = channel.eof().await;
        let mut out = Captured::default();
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Failure => return Err(ExecError::Refused("exec".into())),
                ChannelMsg::Data { data } => keep(&mut out.stdout, &data, cap),
                ChannelMsg::ExtendedData { data, ext: 1 } => keep(&mut out.stderr, &data, cap),
                ChannelMsg::ExitStatus { exit_status } => out.status = Some(exit_status),
                _ => {}
            }
        }
        Ok(out)
    };
    match tokio::time::timeout(limit, run).await {
        Err(_) => Err(ExecError::Timeout(limit)),
        Ok(result) => result,
    }
}

/// `text` as one word for a POSIX shell, in single quotes. A newline or a
/// NUL has no safe spelling across the shells that a login may run, so such
/// a word has none here.
pub fn shell_word(text: &str) -> Option<String> {
    if text.contains(['\n', '\0']) {
        return None;
    }
    Some(format!("'{}'", text.replace('\'', r"'\''")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_word_is_quoted_whole_and_a_newline_has_no_spelling() {
        assert_eq!(shell_word("/srv/a b").as_deref(), Some("'/srv/a b'"));
        assert_eq!(shell_word("it's").as_deref(), Some(r"'it'\''s'"));
        assert_eq!(shell_word("-n").as_deref(), Some("'-n'"));
        assert_eq!(shell_word("a\nb"), None);
        assert_eq!(shell_word("a\0b"), None);
    }

    #[test]
    fn output_past_the_cap_is_dropped() {
        let mut into = Vec::new();
        keep(&mut into, b"abcdef", 4);
        keep(&mut into, b"gh", 4);
        assert_eq!(into, b"abcd");
    }
}
