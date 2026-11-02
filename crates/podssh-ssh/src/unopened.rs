//! One reading of a channel that podssh asked for after the login and that
//! did not open (T-464, GitHub #104). russh gives `ChannelOpenFailure` for
//! the server's refusal alone, `Disconnect` when the connection ended before
//! the answer, and `SendError` when it ended before the request: each was
//! read as a refusal, in russh's words, so a far host that had stopped read
//! as a server that refuses sessions, and the user debugged the relay.

use std::time::Duration;

use russh::client::Handle;
use russh::ChannelOpenFailure;

use crate::handler::Client;

/// How long the handler may take to keep the cause after an open saw the
/// connection's end: russh closes the queue of requests first, so an open
/// can fail before the handler hears why.
const SETTLE: Duration = Duration::from_millis(500);

/// What a connection that ended before a channel opened may mean. No
/// product's name: a stopped sandbox is one case of the first.
pub const MEANING: &str =
    "the far host may be stopped, the login may no longer be valid, or the server takes no more sessions";

/// Why a channel did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unopened {
    /// The server refused it: OpenSSH's words of its reason.
    Refused(String),
    /// The connection ended first: the server's words of its DISCONNECT,
    /// else russh's cause, when either was kept.
    Ended(Option<String>),
    /// Another error of russh, in podssh's words.
    Other(String),
}

/// The reading of `e`, the error of an open on `handle`.
pub async fn read(e: &russh::Error, handle: &Handle<Client>) -> Unopened {
    match e {
        russh::Error::ChannelOpenFailure(reason) => Unopened::Refused(reason_text(reason)),
        e if ended(e) || handle.is_closed() => {
            settle().await;
            Unopened::Ended(cause())
        }
        other => Unopened::Other(crate::run::describe(other)),
    }
}

/// An error that says the connection's task went: its channel closed before
/// the request or the answer, or the stream ended.
fn ended(e: &russh::Error) -> bool {
    match e {
        russh::Error::Disconnect | russh::Error::SendError | russh::Error::HUP | russh::Error::RecvError => true,
        russh::Error::IO(io) => io.kind() == std::io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

/// Until the handler kept a cause, [`SETTLE`] at most.
async fn settle() {
    let deadline = tokio::time::Instant::now() + SETTLE;
    while !crate::handler::cause_kept() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The server's words of its DISCONNECT, else russh's error, as a lost
/// session names them.
fn cause() -> Option<String> {
    let said = crate::handler::take_last_disconnect().map(|s| format!("the server said: {s}"));
    said.or_else(crate::handler::take_last_error)
}

/// OpenSSH's words of a reason of refusal (`reason2txt` in its
/// `channels.c`); the words of a reason that it does not know are the
/// server's, made safe.
pub fn reason_text(reason: &ChannelOpenFailure) -> String {
    match reason {
        ChannelOpenFailure::AdministrativelyProhibited => "administratively prohibited".into(),
        ChannelOpenFailure::ConnectFailed => "connect failed".into(),
        ChannelOpenFailure::UnknownChannelType => "unknown channel type".into(),
        ChannelOpenFailure::ResourceShortage => "resource shortage".into(),
        ChannelOpenFailure::Other { reason, .. } => {
            let said = podssh_ws::text::one_line(reason);
            if said.is_empty() {
                "unknown reason".into()
            } else {
                format!("unknown reason: {said}")
            }
        }
    }
}

impl Unopened {
    /// The words for an open of `what` ("a session", "the channel of the
    /// command"): the fact first, so that a script that reads the first line
    /// gets it; then, for a connection that ended, a line of what it may
    /// mean, indented as a message's next lines are. `after_login`: the open
    /// came right after the login, as a session's does.
    pub fn words(&self, what: &str, after_login: bool) -> String {
        match self {
            Unopened::Refused(reason) => format!("the server refused to open {what}: open failed: {reason}"),
            Unopened::Ended(cause) => {
                let when = if after_login { "right after the login, " } else { "" };
                let cause = cause.as_ref().map(|c| format!(": {c}")).unwrap_or_default();
                format!("the server ended the connection {when}before {what} opened{cause}\n  {MEANING}")
            }
            Unopened::Other(why) => format!("{what} did not open: {why}"),
        }
    }

    /// Whether the server refused the channel, where a connection that ended
    /// is no refusal.
    pub fn refused(&self) -> bool {
        matches!(self, Unopened::Refused(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal is the server's, in OpenSSH's words of its reason.
    #[test]
    fn a_refusal_names_its_reason_as_openssh_does() {
        let words = Unopened::Refused(reason_text(&ChannelOpenFailure::AdministrativelyProhibited));
        let want = "the server refused to open a session: open failed: administratively prohibited";
        assert_eq!(words.words("a session", true), want);
        assert_eq!(reason_text(&ChannelOpenFailure::ResourceShortage), "resource shortage");
        let other = ChannelOpenFailure::Other { code: 9, reason: "no\x1b[31m more".into() };
        assert!(!reason_text(&other).contains('\x1b'), "{}", reason_text(&other));
        assert!(reason_text(&other).starts_with("unknown reason: "));
        assert_eq!(reason_text(&ChannelOpenFailure::Other { code: 9, reason: String::new() }), "unknown reason");
    }

    /// A connection that ended is never a refusal: its cause, then what it
    /// may mean (GitHub #104 read "the server refused to open a session:
    /// Disconnected").
    #[test]
    fn a_connection_that_ended_is_no_refusal() {
        let ended = Unopened::Ended(Some("the server said: bye (ByApplication)".into()));
        assert!(!ended.refused());
        let words = ended.words("a session", true);
        let mut lines = words.lines();
        let first = "the server ended the connection right after the login, before a session opened: the server \
                     said: bye (ByApplication)";
        assert_eq!(lines.next(), Some(first));
        assert_eq!(lines.next(), Some(format!("  {MEANING}").as_str()));
        assert!(!words.contains("refused"), "{words}");
        let bare = Unopened::Ended(None).words("the channel of the command", false);
        let want = "the server ended the connection before the channel of the command opened\n";
        assert!(bare.starts_with(want), "{bare}");
    }

    /// russh's errors of a connection that went read as its end; another
    /// error does not.
    #[test]
    fn the_errors_of_a_connection_that_went() {
        assert!(ended(&russh::Error::Disconnect));
        assert!(ended(&russh::Error::SendError));
        assert!(ended(&russh::Error::IO(std::io::ErrorKind::UnexpectedEof.into())));
        assert!(!ended(&russh::Error::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed)));
        assert!(!ended(&russh::Error::Inconsistent));
    }
}
