//! `prompt` on the test's server, for a user `pty-...` (T-191): a shell's
//! prompt, as a pty shows it, for the expect rules of `podssh ssh`. It
//! prints `$ `; each key that comes is echoed, as a pty echoes it, and a
//! line that a `\r` or a `\n` ends is answered: `echo WORDS` prints WORDS,
//! `exit N` ends with N, another line says that it is not found; then `$ `
//! again.

use russh::server::Session;
use russh::ChannelId;

/// The prompt, as the command starts.
pub(super) fn start(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
    session.data(channel, b"$ ".to_vec())
}

/// Keys that came to `prompt`, with `line`, the keys of its line so far:
/// whether the command ended.
pub(super) fn input(
    line: &mut Vec<u8>,
    data: &[u8],
    channel: ChannelId,
    session: &mut Session,
) -> Result<bool, russh::Error> {
    for &key in data {
        if key != b'\r' && key != b'\n' {
            line.push(key);
            session.data(channel, vec![key])?;
            continue;
        }
        session.data(channel, b"\r\n".to_vec())?;
        let text = String::from_utf8_lossy(&std::mem::take(line)).trim().to_string();
        if let Some(n) = text.strip_prefix("exit ") {
            session.exit_status_request(channel, n.trim().parse().unwrap_or(1))?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(true);
        }
        let answer = match text.strip_prefix("echo") {
            Some(words) => format!("{}\r\n", words.trim()),
            None if text.is_empty() => String::new(),
            None => format!("sh: {text}: not found\r\n"),
        };
        session.data(channel, format!("{answer}$ ").into_bytes())?;
    }
    Ok(false)
}
