//! The two halves of a session that are not the session: what it remembers, and
//! the messages it composes.
//!
//! ⛔ **Split out of `session.rs`, which went over the 500-line gate with them
//! in**, and ⛔ split rather than trimmed. ⛔ `ChannelMemory` carries the
//! reconnect's correctness ⛔ — ⛔ a memory that keeps a room the user left
//! rejoins them into it silently ⛔ — ⛔ and that reasoning is the reason the
//! bug cannot recur.

use crate::irc::message::{Command, Message, Middle, Trailing};
use crate::irc::session::Server;

/// ⛔ **What a reconnect must restore.** A `Vec` and not a `HashSet`, ⛔
/// because ⛔ **join order is part of the contract** ⛔ — podssh rejoins in the
/// order the user joined, ⛔ which is the order they expect to see the rooms
/// appear, ⛔ and a set would make it arbitrary between runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChannelMemory {
    channels: Vec<String>,
    keys: Vec<Option<String>>,
}

impl ChannelMemory {
    /// ⛔ Remember a channel. ⛔ **A duplicate join is not remembered twice**,
    /// ⛔ or a reconnect would send two `JOIN`s for the same room and the user
    /// would see it echoed back twice.
    pub fn remember(&mut self, channel: &str, key: Option<String>) -> bool {
        if self.channels.iter().any(|c| Middle(c.clone()).eq_irc(channel)) {
            return false;
        }
        self.channels.push(channel.to_string());
        self.keys.push(key);
        true
    }

    /// ⛔ Forget a channel ⛔ — **when the user parts, and when the server
    /// kicks them out.** ⛔ A memory that keeps a room the user was removed from
    /// rejoins them into it on the next reconnect, ⛔ which on a moderated
    /// channel is a `+b` ban the user did not ask for and cannot see.
    pub fn forget(&mut self, channel: &str) {
        if let Some(i) = self.channels.iter().position(|c| Middle(c.clone()).eq_irc(channel)) {
            self.channels.remove(i);
            self.keys.remove(i);
        }
    }

    pub fn channels(&self) -> &[String] {
        &self.channels
    }

    pub fn key_for(&self, index: usize) -> Option<&str> {
        self.keys.get(index).and_then(|k| k.as_deref())
    }

    pub fn len(&self) -> usize {
        self.channels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }
}

pub fn nick_message(nick: &str) -> Message {
    Message {
        tags: Vec::new(),
        prefix: None,
        command: Command::Nick { nickname: Middle(nick.to_string()) },
    }
}

/// ⛔ `USER <user> <mode> <unused> :<realname>` ⛔ **with the `<unused>`
/// parameter present**, ⛔ because RFC 1459 §4.1.2 has five parameters there and
/// a client that sends four is answered with `461` during registration.
pub fn user_message(server: &Server) -> Message {
    Message {
        tags: Vec::new(),
        prefix: None,
        command: Command::User {
            user: Middle(server.username.clone()),
            mode: Middle("0".to_string()),
            unused: Middle("*".to_string()),
            realname: Trailing::new(server.realname.clone()),
        },
    }
}

pub fn join_message(channel: &str, key: Option<&str>) -> Message {
    Message {
        tags: Vec::new(),
        prefix: None,
        command: Command::Join {
            channels: vec![Middle(channel.to_string())],
            key: key.map(|k| k.to_string()),
        },
    }
}
