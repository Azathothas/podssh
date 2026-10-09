//! What the user may send, and when podssh refuses to send it.
//!
//! ⛔ **Split out of `session.rs`, which went over the 500-line gate with these
//! methods in.** ⛔ They are one subject ⛔ — ⛔ *the writes* — ⛔ and ⛔ the
//! reason a write is refused is worth more next to the write than next to the
//! receive path.
//!
//! ⛔ **Every refusal here is a refusal, never a truncation.** ⛔ A `PRIVMSG`
//! cut at 510 bytes is a message the user believes was sent whole, ⛔ and ⛔ for
//! a file transfer it is a chunk with a hole in it ⛔ and a digest that will
//! never match.

use std::collections::BTreeSet;

use crate::irc::message::{fits_in_allowed_line, Command, Message, Middle, Trailing};
use crate::irc::session::{Registered, Session, SessionError};
use crate::irc::session_parts::join_message;

impl Session {
    /// ⛔ **Queue a user message**, ⛔ refusing it before the 512-byte limit
    /// rather than after. ⛔ **The refusal is `Err` and not a silently
    /// truncated send**: ⛔ a `PRIVMSG` cut at 510 bytes is a message the user
    /// believes was sent whole, ⛔ and for a file transfer it is a chunk with a
    /// hole in it and a digest that will never match.
    pub fn send_privmsg(&mut self, target: &str, text: &str) -> Result<Message, SessionError> {
        if !matches!(self.registered, Registered::Yes) {
            return Err(SessionError::NotRegistered);
        }
        let message = Message {
            tags: Vec::new(),
            prefix: None,
            command: Command::Privmsg { target: Middle(target.to_string()), text: Trailing::new(text) },
        };
        let bytes = message.to_wire().len();
        if !fits_in_allowed_line(&message) {
            return Err(SessionError::TooLong { bytes });
        }
        Ok(message)
    }

    /// ⛔ `JOIN`, **remembering it** so a reconnect rejoins. ⛔ **Memory is
    /// written at send time, not on confirmation**, ⛔ and that is deliberate:
    /// ⛔ waiting for the server's echo means a `JOIN` that fails ⛔ — a banned
    /// channel, a key the user mistyped ⛔ — is remembered anyway, ⛔ and the
    /// reconnect then rejoins a channel the user never got into.
    pub fn send_join(&mut self, channel: &str, key: Option<String>) -> Vec<Message> {
        self.memory.remember(channel, key.clone());
        vec![join_message(channel, key.as_deref())]
    }

    /// ⛔ `PART`, ⛔ **forgetting it** ⛔ for the same reason: ⛔ a remembered
    /// room the user left is rejoined silently after a reconnect.
    pub fn send_part(&mut self, channel: &str, reason: Option<&str>) -> Vec<Message> {
        self.memory.forget(channel);
        vec![Message {
            tags: Vec::new(),
            prefix: None,
            command: Command::Part { channels: vec![Middle(channel.to_string())], reason: reason.map(Trailing::new) },
        }]
    }

    /// ⛔ **The heartbeat to send, or `None`.** ⛔ **It is a `PRIVMSG`
    /// and not a `PONG`** ⛔ — ⛔ spec line 233 says the reaper counts *payload*
    /// and that ⛔ **"transport keepalives do not reset this"** ⛔, so a client
    /// that answers `PING`s and calls that keepalive is reaped at 180 s all the
    /// same. ⛔ See [`crate::irc::reap`].
    pub fn heartbeat(&self, target: &str, generation: u64) -> Option<Message> {
        match self.registered {
            Registered::Yes => Some(Message {
                tags: Vec::new(),
                prefix: None,
                command: Command::Privmsg {
                    target: Middle(target.to_string()),
                    text: Trailing::new(crate::irc::reap::heartbeat_text(generation)),
                },
            }),
            _ => None,
        }
    }

    /// ⛔ The channels a reconnect rejoins, ⛔ **as a set**, ⛔ so a caller that
    /// wants to tell a user "you are back in 3 rooms" does not count a
    /// `Vec` that could carry duplicates.
    pub fn rejoined_channels(&self) -> BTreeSet<&str> {
        self.memory.channels().iter().map(|c| c.as_str()).collect()
    }

    /// ⛔ The `QUIT` that ends a session deliberately. ⛔ **Deliberate and
    /// separate**: ⛔ an idle reconnect must **not** send `QUIT` ⛔ because a
    /// `QUIT` tells the server the client is leaving, ⛔ and the server then
    /// removes it from every channel, so the rejoin is a race the user wins
    /// only sometimes.
    pub fn quit(reason: &str) -> Message {
        Message { tags: Vec::new(), prefix: None, command: Command::Quit { reason: Some(Trailing::new(reason)) } }
    }
}
