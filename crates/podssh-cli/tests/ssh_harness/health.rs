//! The command of `podssh health` (T-189) on the test's server: its fixed
//! script, as `sh -c`, gets the answer that a Debian host gives
//! (`tests/fixtures/health/debian.txt`), and the status 0. A user named
//! `health-v2-...`, `health-v1-...` or `health-free-...` gets the answer of
//! a container of 4 CPUs and 4 GiB under cgroup v2 or v1, or of one with no
//! limit (T-480). For the preflight (T-482), a user `preflight-ok-...` gets
//! a server that allows each probe: `tcpip-forward` on a port that it names
//! and its cancel, and each tool of the exec; `preflight-no-...` one that
//! refuses `tcpip-forward`, answers `direct-tcpip` with administratively
//! prohibited and has no `sftp` subsystem, as OpenSSH with
//! `AllowTcpForwarding no` and no `Subsystem` would.

use russh::server::Session;
use russh::ChannelId;

/// What the server answers.
pub const ANSWER: &str = include_str!("../fixtures/health/debian.txt");
const V2: &str = include_str!("../fixtures/health/container-v2.txt");
const V1: &str = include_str!("../fixtures/health/container-v1.txt");
const FREE: &str = include_str!("../fixtures/health/container-free.txt");

/// The port that the server of `preflight-ok-...` names for a
/// `tcpip-forward` of port 0.
pub const FORWARD_PORT: u32 = 40022;

/// The tools that the exec of the preflight finds, each on a line after
/// the mark.
const TOOLS: &str = "cat mv rm mkdir sleep wc tail nohup setsid base64 stat chmod touch chown dd head sha256sum tmux";

/// What the server of the preflight allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Preflight {
    Allows,
    Refuses,
}

/// The answer for the user `user`: a container's, by the start of its name;
/// `None` for the Debian host's.
pub(super) fn of_user(user: &str) -> Option<&'static str> {
    [("health-v2-", V2), ("health-v1-", V1), ("health-free-", FREE)]
        .into_iter()
        .find_map(|(prefix, answer)| user.starts_with(prefix).then_some(answer))
}

/// The server of the preflight for `user`, by the start of its name.
pub(super) fn preflight_of(user: &str) -> Option<Preflight> {
    if user.starts_with("preflight-ok-") {
        Some(Preflight::Allows)
    } else if user.starts_with("preflight-no-") {
        Some(Preflight::Refuses)
    } else {
        None
    }
}

/// A `tcpip-forward` of a user of the preflight: granted on
/// [`FORWARD_PORT`] for a port of 0, or refused; `None` for another user.
pub(super) fn forward(preflight: Option<Preflight>, port: &mut u32) -> Option<bool> {
    match preflight? {
        Preflight::Allows => {
            if *port == 0 {
                *port = FORWARD_PORT;
            }
            Some(true)
        }
        Preflight::Refuses => Some(false),
    }
}

/// Whether a `cancel-tcpip-forward` is granted: for the server that allows.
pub(super) fn cancels(preflight: Option<Preflight>) -> bool {
    preflight == Some(Preflight::Allows)
}

/// The end of `command` when it is the script of `podssh health`, answered
/// with `answer` (else the Debian host's), or the exec of the preflight,
/// answered with each tool; `None` else.
pub(super) fn answer(
    answer: Option<&'static str>,
    command: &str,
    channel: ChannelId,
    session: &mut Session,
) -> Option<Result<(), russh::Error>> {
    let script = command.starts_with("sh -c '");
    let text = if script && command.contains("podssh-health 1") {
        answer.unwrap_or(ANSWER).to_string()
    } else if script && command.contains("podssh-preflight 1") {
        // A login's words first, as a host's start-up files print them.
        let have: String = TOOLS.split(' ').map(|t| format!("have {t}\n")).collect();
        format!("Welcome to the test's server\npodssh-preflight 1\n{have}")
    } else {
        return None;
    };
    let sent = session
        .data(channel, text.into_bytes())
        .and_then(|()| session.exit_status_request(channel, 0))
        .and_then(|()| session.eof(channel))
        .and_then(|()| session.close(channel));
    Some(sent)
}
