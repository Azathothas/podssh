//! What an SFTP step can end in, in words a user can act on.
//!
//! Each failure names the step and its path, and a status from the server
//! becomes a sentence; the server's own text goes through
//! [`podssh_ws::text::one_line`], so it cannot draw on the terminal.

use std::fmt;
use std::time::Duration;

use russh_sftp::client::error::Error as Raw;
use russh_sftp::protocol::StatusCode;

/// Why an SFTP step failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SftpError {
    /// The server refused the `sftp` subsystem, or did not answer the
    /// request: the one failure after which `cp` copies by exec (T-135).
    NoSftp,
    /// No reply came within the limit of the step.
    Timeout {
        /// The step, with its path.
        what: String,
        /// The limit that passed.
        limit: Duration,
    },
    /// The server answered with an error status.
    Status {
        /// The step, with its path.
        what: String,
        /// The `SSH_FX_*` code.
        code: u32,
        /// The server's own text, on one line.
        message: String,
    },
    /// The server broke the protocol: a reply of the wrong type or size.
    Protocol(String),
    /// The channel or the connection ended.
    Closed(String),
}

/// How russh-sftp 3.0.1 says that its session ended: a receive or a send on
/// a closed channel, a closed session, or a reply whose sender was dropped
/// (`src/client/error.rs`, `src/client/rawsession.rs` of the crate).
const GONE: &[&str] = &["RecvError", "SendError", "session closed", "sender dropped"];

impl SftpError {
    /// The error of a step from the library's error.
    pub(crate) fn from_raw(what: &str, raw: Raw, limit: Duration) -> SftpError {
        match raw {
            Raw::Status(s) => SftpError::Status {
                what: what.to_string(),
                code: s.status_code as u32,
                message: podssh_ws::text::one_line(&s.error_message),
            },
            Raw::Timeout => SftpError::Timeout { what: what.to_string(), limit },
            Raw::IO(why) => SftpError::Closed(format!("{what}: {why}")),
            Raw::Limited(why) => SftpError::Protocol(format!("{what}: over the server's limits ({why})")),
            Raw::UnexpectedPacket => SftpError::Protocol(format!("{what}: a reply of the wrong type")),
            // The library's reader stopped, its channel to the writer closed,
            // or a request's reply can no longer come: the session is gone,
            // and a copy can go on over a new one (T-136).
            Raw::UnexpectedBehavior(why) if GONE.iter().any(|said| why.contains(said)) => {
                SftpError::Closed(format!("{what}: the server closed the SFTP session"))
            }
            Raw::UnexpectedBehavior(why) => SftpError::Protocol(format!("{what}: {}", podssh_ws::text::one_line(&why))),
        }
    }

    /// Whether the server said that the path does not exist.
    pub fn is_missing(&self) -> bool {
        matches!(self, SftpError::Status { code, .. } if *code == StatusCode::NoSuchFile as u32)
    }
}

/// The sentence of an `SSH_FX_*` code (draft-ietf-secsh-filexfer-02, 7).
pub fn sentence(code: u32) -> &'static str {
    match code {
        1 => "the end of the file",
        2 => "no such file or directory",
        3 => "permission denied",
        4 => "the server could not do it",
        5 => "the server could not read the request",
        6 | 7 => "the connection is lost",
        8 => "the server does not support this request",
        _ => "the server refused it",
    }
}

impl fmt::Display for SftpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SftpError::NoSftp => write!(f, "the server has no SFTP subsystem"),
            SftpError::Timeout { what, limit } => write!(f, "{what}: no reply within {} s", limit.as_secs()),
            SftpError::Status { what, code, message } => {
                write!(f, "{what}: {}", sentence(*code))?;
                if !message.is_empty() {
                    write!(f, " (the server says: {message})")?;
                }
                Ok(())
            }
            SftpError::Protocol(why) => write!(f, "the SFTP server broke the protocol: {why}"),
            SftpError::Closed(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for SftpError {}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::Status;

    fn status(code: StatusCode, message: &str) -> Raw {
        Raw::Status(Status { id: 7, status_code: code, error_message: message.into(), language_tag: "en".into() })
    }

    #[test]
    fn a_status_is_a_sentence_with_the_path_and_the_server_text_on_one_line() {
        let e =
            SftpError::from_raw("stat /srv/a", status(StatusCode::NoSuchFile, "No such\nfile\x1b[2J"), Duration::ZERO);
        assert_eq!(e.to_string(), "stat /srv/a: no such file or directory (the server says: No such file[2J)");
        assert!(e.is_missing());
        let e = SftpError::from_raw("open /srv/b", status(StatusCode::PermissionDenied, ""), Duration::ZERO);
        assert_eq!(e.to_string(), "open /srv/b: permission denied");
        assert!(!e.is_missing());
    }

    #[test]
    fn a_timeout_names_its_limit_and_a_closed_session_says_so() {
        let e = SftpError::from_raw("read /x", Raw::Timeout, Duration::from_secs(60));
        assert_eq!(e.to_string(), "read /x: no reply within 60 s");
        let e =
            SftpError::from_raw("stat /x", Raw::UnexpectedBehavior("RecvError: channel closed".into()), Duration::ZERO);
        assert_eq!(e, SftpError::Closed("stat /x: the server closed the SFTP session".into()));
        // A request in flight when the connection broke (measured through a
        // stand-in relay that cuts, T-136), and a send after it.
        for said in ["sender dropped", "SendError: channel closed", "session closed"] {
            let e = SftpError::from_raw("read /x", Raw::UnexpectedBehavior(said.into()), Duration::ZERO);
            assert_eq!(e, SftpError::Closed("read /x: the server closed the SFTP session".into()), "{said}");
        }
        let e = SftpError::from_raw("read /x", Raw::UnexpectedBehavior("Duplicate version".into()), Duration::ZERO);
        assert!(matches!(e, SftpError::Protocol(_)), "{e:?}");
    }
}
