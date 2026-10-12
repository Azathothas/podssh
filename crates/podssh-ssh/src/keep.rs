//! Detach and attach again (T-158): a far end that keeps a shell after its
//! client leaves, so that a later podssh, on this host or another, joins it
//! again with a new login. The SSH connection's keys live in this process,
//! so a new process cannot go on with its bytes: the far end keeps the
//! shell, not the connection.
//!
//! The far end says that it keeps shells with the feature `keep.v1` of the
//! resumable layer, which the road reads and puts in [`Offer`]; with no
//! offer, `~d` goes to the server as two bytes and `--attach` is refused.
//! The far end decides who may join a shell: one client at a time, unless
//! the user takes it, and never the shell that the client runs in. Its
//! refusal comes as its words on stderr and an exit status.
//!
//! The requests, each of podssh's own far end; a server that does not know
//! one answers FAILURE:
//!
//! - `env detach@podssh NAME`, on the shell's channel: keep the shell as
//!   NAME. SUCCESS ends the session here; FAILURE leaves it running.
//! - `env attach@podssh NAME`, before `shell` on a channel with a pty: the
//!   shell request joins NAME to the channel. Before it, `env take@podssh
//!   yes` takes NAME from a client that has it, and `env from@podssh ID`
//!   names the shell that this podssh runs in, from [`SHELL_ID`].
//! - The subsystem `shells@podssh`: the kept shells, one line each.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use russh::client::Msg;
use russh::{Channel, ChannelMsg, ChannelWriteHalf};

use crate::io::End;
use crate::log::Log;

/// The `env` request that keeps the shell of its channel under a name.
pub const DETACH: &str = "detach@podssh";
/// The `env` request that joins a kept shell to the next `shell` request.
pub const ATTACH: &str = "attach@podssh";
/// The `env` request that takes a kept shell from the client that has it.
pub const TAKE: &str = "take@podssh";
/// The `env` request that names the shell that the client runs in.
pub const FROM: &str = "from@podssh";
/// The subsystem that lists the kept shells.
pub const LIST: &str = "shells@podssh";
/// The variable that a far end that keeps shells puts in each shell: the
/// shell's id there. podssh sends it with an attach, so that the far end
/// refuses to join a shell to itself.
pub const SHELL_ID: &str = "PODSSH_SHELL_ID";
/// The longest name of a kept shell.
pub const NAME_MAX: usize = 32;

/// Whether the far end keeps shells: the road sets it when the layer's
/// handshake names `keep.v1`, before the SSH login, and the session reads it.
#[derive(Debug, Clone, Default)]
pub struct Offer(Arc<AtomicBool>);

impl Offer {
    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn offered(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What the user asked of the kept shells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// `--attach NAME`, with `--take`: join the shell NAME.
    Attach { name: String, take: bool },
    /// `--attach DEST`: list the kept shells.
    List,
}

/// The kept shells of a connection: the far end's offer, and what the
/// user asked, if anything.
#[derive(Debug, Clone, Default)]
pub struct Keep {
    pub offer: Offer,
    pub ask: Option<Ask>,
}

impl Keep {
    /// An attach or a list needs a far end that keeps shells; else the
    /// words of the refusal, before a session is opened.
    pub fn check(&self, host: &str) -> Result<(), String> {
        match (&self.ask, self.offer.offered()) {
            (Some(_), false) => Err(format!(
                "{host} keeps no shells: its far end does not offer keep.v1 in the resumable layer, so --attach has \
                 nothing to join; with a standard sshd, --persist keeps the shell in tmux"
            )),
            _ => Ok(()),
        }
    }

    /// The name that `~d` keeps the shell as, in a session with a pty on a
    /// terminal, where the far end keeps shells: the name that was attached,
    /// or a new one. `None` turns `~d` off.
    pub fn detach_name(&self, terminal: bool) -> Option<String> {
        if !terminal || !self.offer.offered() {
            return None;
        }
        match &self.ask {
            Some(Ask::Attach { name, .. }) => Some(name.clone()),
            Some(Ask::List) => None,
            None => Some(new_name()),
        }
    }
}

/// A name of a kept shell: letters, digits, `_` and `-`, [`NAME_MAX`] at
/// most, so that it is one word in a line and in a command.
pub fn check_name(name: &str) -> Result<(), String> {
    let good = !name.is_empty()
        && name.len() <= NAME_MAX
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if good {
        Ok(())
    } else {
        Err(format!("{name:?} is not a name of a kept shell: letters, digits, _ and -, {NAME_MAX} at most"))
    }
}

/// A new name for a shell that `~d` keeps: 8 hexadecimal digits, so that
/// two shells of one user have the same name once in 4 billion.
pub fn new_name() -> String {
    format!("{:08x}", rand::random::<u32>())
}

/// The line after a detach: where the shell is, and how to join it again.
pub fn kept_line(name: &str, host: &str) -> String {
    format!("{host} keeps the shell as {name}; podssh ssh --attach {name} with this destination joins it again")
}

/// Before `shell`, on a new session's channel with a pty: ask the far end
/// to join the kept shell `name` to it, and to take it when `take`. Each
/// request waits for its answer; a FAILURE is a far end that takes none.
pub(crate) async fn ask_attach(
    channel: &mut Channel<Msg>,
    early: &mut Vec<ChannelMsg>,
    name: &str,
    take: bool,
) -> Result<(), String> {
    let mut asks: Vec<(&str, String)> = Vec::new();
    // The shell that this podssh runs in, if a far end keeps it.
    if let Some(id) = std::env::var(SHELL_ID).ok().filter(|id| !id.is_empty()) {
        asks.push((FROM, id));
    }
    if take {
        asks.push((TAKE, "yes".to_string()));
    }
    asks.push((ATTACH, name.to_string()));
    for (request, value) in asks {
        channel.set_env(true, request, value).await.map_err(|e| format!("could not ask to attach {name}: {e}"))?;
        if !crate::session::wait_reply(channel, early).await? {
            return Err(format!("the far end refused {request} for the kept shell {name}"));
        }
    }
    Ok(())
}

/// A detach in a session: the name that `~d` keeps the shell as, and
/// whether the far end's answer is awaited.
#[derive(Debug, Default)]
pub struct Detaching {
    name: Option<String>,
    asked: bool,
}

impl Detaching {
    /// `name`: see [`Keep::detach_name`]; `None` for a session with no `~d`.
    pub fn new(name: Option<String>) -> Self {
        Detaching { name, asked: false }
    }

    /// `~d`: ask the far end to keep the shell. Its answer comes on the
    /// channel, as the next reply of a request (RFC 4254, section 5.4).
    pub(crate) async fn ask(&mut self, writer: &ChannelWriteHalf<Msg>, log: &Log) {
        let Some(name) = self.name.as_deref() else { return };
        if self.asked {
            return;
        }
        match writer.set_env(true, DETACH, name).await {
            Ok(()) => self.asked = true,
            Err(e) => log.info(&format!("could not ask the far end to keep the shell: {e}")),
        }
    }

    /// The far end's answer to `~d`, while one is awaited: the end of the
    /// session when it keeps the shell; when it refuses, a line, and the
    /// session goes on. `None` for each other message.
    pub(crate) fn answer(&mut self, msg: &ChannelMsg, log: &Log) -> Option<End> {
        if !self.asked {
            return None;
        }
        match msg {
            ChannelMsg::Success => {
                self.asked = false;
                self.name.clone().map(End::Detached)
            }
            ChannelMsg::Failure => {
                self.asked = false;
                log.info("the far end did not keep the shell; the session goes on");
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_one_word_of_32_bytes_at_most() {
        let (longest, longer) = ("x".repeat(NAME_MAX), "x".repeat(NAME_MAX + 1));
        for good in ["work", "a1b2c3d4", "build-2_x", longest.as_str()] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in ["", "a b", "a.b", "../x", "node://lab", longer.as_str()] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        let made = new_name();
        assert_eq!(made.len(), 8);
        assert!(check_name(&made).is_ok(), "{made}");
    }

    /// `~d` only where the far end keeps shells and a terminal runs the
    /// session; an attached shell is kept again under its own name.
    #[test]
    fn a_detach_needs_the_offer_and_a_terminal() {
        let mut keep = Keep::default();
        assert_eq!(keep.detach_name(true), None);
        keep.offer.set();
        assert_eq!(keep.detach_name(false), None);
        assert_eq!(keep.detach_name(true).map(|n| n.len()), Some(8));
        keep.ask = Some(Ask::Attach { name: "work".into(), take: false });
        assert_eq!(keep.detach_name(true).as_deref(), Some("work"));
        keep.ask = Some(Ask::List);
        assert_eq!(keep.detach_name(true), None);
    }

    /// An attach or a list with no offer is refused before any session.
    #[test]
    fn an_attach_with_no_offer_is_refused() {
        let keep = Keep { ask: Some(Ask::List), ..Keep::default() };
        assert!(keep.check("node://lab").unwrap_err().contains("node://lab keeps no shells"));
        keep.offer.set();
        assert!(keep.check("node://lab").is_ok());
        assert!(Keep::default().check("h").is_ok());
    }
}
