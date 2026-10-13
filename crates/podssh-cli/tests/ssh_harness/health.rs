//! The command of `podssh health` (T-189) on the test's server: its fixed
//! script, as `sh -c`, gets the answer that a Debian host gives
//! (`tests/fixtures/health/debian.txt`), and the status 0.

use russh::server::Session;
use russh::ChannelId;

/// What the server answers.
pub const ANSWER: &str = include_str!("../fixtures/health/debian.txt");

/// The end of `command` when it is the script of `podssh health`; `None`
/// else.
pub(super) fn answer(command: &str, channel: ChannelId, session: &mut Session) -> Option<Result<(), russh::Error>> {
    if !(command.starts_with("sh -c '") && command.contains("podssh-health 1")) {
        return None;
    }
    let sent = session
        .data(channel, ANSWER.as_bytes().to_vec())
        .and_then(|()| session.exit_status_request(channel, 0))
        .and_then(|()| session.eof(channel))
        .and_then(|()| session.close(channel));
    Some(sent)
}
