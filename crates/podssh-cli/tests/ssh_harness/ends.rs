//! The commands of the test's server that end as a shell's do (T-054):
//! `exit N` prints `out` on stdout and `err!` on stderr, then exits N;
//! `kill NAME` ends with the signal NAME, its core dumped for `kill SEGV`;
//! `append PATH STATUS DELAY` (T-025) ends with STATUS after DELAY seconds.

use std::time::Duration;

use russh::server::Session;
use russh::{ChannelId, Sig};

/// `append PATH STATUS DELAY`: a line in the file at once, then the status
/// after DELAY seconds (T-025). A command that ran twice leaves two lines.
/// `None` for another command.
pub(super) fn append(command: &str, channel: ChannelId, session: &mut Session) -> Option<Result<(), russh::Error>> {
    let rest = command.strip_prefix("append ")?;
    let mut parts = rest.rsplitn(3, ' ');
    let delay: u64 = parts.next().and_then(|d| d.parse().ok()).unwrap_or(0);
    let status: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let path = parts.next().unwrap_or_default().to_string();
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = std::io::Write::write_all(&mut file, b"ran\n");
    }
    let handle = session.handle();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(delay)).await;
        let _ = handle.exit_status_request(channel, status).await;
        let _ = handle.eof(channel).await;
        let _ = handle.close(channel).await;
    });
    Some(Ok(()))
}

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
