//! The command of `podssh health` (T-189) on the test's server: its fixed
//! script, as `sh -c`, gets the answer that a Debian host gives
//! (`tests/fixtures/health/debian.txt`), and the status 0. A user named
//! `health-v2-...`, `health-v1-...` or `health-free-...` gets the answer of
//! a container of 4 CPUs and 4 GiB under cgroup v2 or v1, or of one with no
//! limit (T-480).

use russh::server::Session;
use russh::ChannelId;

/// What the server answers.
pub const ANSWER: &str = include_str!("../fixtures/health/debian.txt");
const V2: &str = include_str!("../fixtures/health/container-v2.txt");
const V1: &str = include_str!("../fixtures/health/container-v1.txt");
const FREE: &str = include_str!("../fixtures/health/container-free.txt");

/// The answer for the user `user`: a container's, by the start of its name;
/// `None` for the Debian host's.
pub(super) fn of_user(user: &str) -> Option<&'static str> {
    [("health-v2-", V2), ("health-v1-", V1), ("health-free-", FREE)]
        .into_iter()
        .find_map(|(prefix, answer)| user.starts_with(prefix).then_some(answer))
}

/// The end of `command` when it is the script of `podssh health`, answered
/// with `answer` (else the Debian host's); `None` else.
pub(super) fn answer(
    answer: Option<&'static str>,
    command: &str,
    channel: ChannelId,
    session: &mut Session,
) -> Option<Result<(), russh::Error>> {
    if !(command.starts_with("sh -c '") && command.contains("podssh-health 1")) {
        return None;
    }
    let sent = session
        .data(channel, answer.unwrap_or(ANSWER).as_bytes().to_vec())
        .and_then(|()| session.exit_status_request(channel, 0))
        .and_then(|()| session.eof(channel))
        .and_then(|()| session.close(channel));
    Some(sent)
}
