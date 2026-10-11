//! The commands of the test's server that end as a shell's do (T-054):
//! `exit N` prints `out` on stdout and `err!` on stderr, then exits N;
//! `kill NAME` ends with the signal NAME, its core dumped for `kill SEGV`.

use russh::server::Session;
use russh::{ChannelId, Sig};

/// The end of `command`, when it is one of these; `None` else.
pub(super) fn ended(command: &str, channel: ChannelId, session: &mut Session) -> Option<Result<(), russh::Error>> {
    let mut words = command.split_whitespace();
    let ended = match (words.next(), words.next()) {
        (Some("exit"), Some(n)) => {
            let n: u32 = n.parse().ok()?;
            session
                .data(channel, b"out\n".to_vec())
                .and_then(|()| session.extended_data(channel, 1, b"err!\n".to_vec()))
                .and_then(|()| session.exit_status_request(channel, n))
        }
        (Some("kill"), Some(name)) => {
            let signal = match name {
                "TERM" => Sig::TERM,
                "KILL" => Sig::KILL,
                "SEGV" => Sig::SEGV,
                other => Sig::Custom(other.to_string()),
            };
            session.exit_signal_request(channel, signal, name == "SEGV", "", "")
        }
        _ => return None,
    };
    Some(ended.and_then(|()| session.eof(channel)).and_then(|()| session.close(channel)))
}
