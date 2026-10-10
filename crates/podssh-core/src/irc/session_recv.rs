//! What the session reads: each line from the server, the state that it
//! changes, and the events that it gives.
//!
//! **Split out of `session.rs`, which went over the 500-line gate with T-095
//! in.** The receive path is one subject, and the reason a line changes the
//! session is worth more next to the line than next to the writes.
//!
//! **The session knows its own nick** (T-095): the one that `001` names, and
//! each `NICK` of it after. A `JOIN`, a `PART` or a `KICK` changes the
//! channels to rejoin only when it is about that nick; about another user it
//! is an event about them. Two nicks are the same by the server's
//! `CASEMAPPING`.

use crate::irc::cap::Stage;
use crate::irc::message::{Command, Message};
use crate::irc::numeric::Numeric as Code;
use crate::irc::session::{Event, Registered, RegistrationFailure, Session};
use crate::irc::session_parts::nick_message;

/// How many times a nick that another holds is tried again before `001`,
/// each time with one more `_`, before the registration is refused.
pub const NICK_TRIES: u8 = 3;

impl Session {
    pub(crate) fn on_line(&mut self, line: &str, out: &mut Vec<Message>, events: &mut Vec<Event>) {
        let message = match Message::parse(line) {
            Ok(m) => m,
            // **A line that does not parse is reported, not fatal.** One
            // malformed line from a peer is not a reason to drop a conversation,
            // and a client that disconnects on a parse error is a client a
            // misbehaving server can take offline at will.
            Err(e) => {
                events.push(Event::Protocol(format!("unparsed line dropped: {e}")));
                return;
            }
        };
        if let Some(next) = self.negotiation.observe(&message.command) {
            out.push(next);
        }
        // A second copy follows its first at once, or is no second copy.
        let previous_self_echo = self.last_self_echo.take();
        let from_me = self.about_me(&message);
        let sender = message.prefix.as_ref().map(|p| p.nick.clone()).unwrap_or_default();
        match &message.command {
            Command::Ping { token } => {
                self.pending_pongs.push(token.as_str().to_string());
            }
            Command::Numeric(reply) => self.on_numeric(&message, reply.code, out, events),
            // This client's new nick, which each later line names.
            Command::Nick { nickname, .. } if from_me => self.nick = nickname.0.clone(),
            Command::Join { channels, .. } => {
                for channel in channels.iter().filter(|c| c.0.starts_with('#')) {
                    if from_me {
                        self.memory.remember(&channel.0, None);
                        events.push(Event::Joined { channel: channel.0.clone() });
                    } else {
                        events.push(Event::PeerJoined { nick: sender.clone(), channel: channel.0.clone() });
                    }
                }
            }
            Command::Part { channels, reason, .. } => {
                let reason = reason.as_ref().map(|r| r.as_str().to_string());
                for channel in channels {
                    if from_me {
                        self.memory.forget(&channel.0);
                        events.push(Event::Left { channel: channel.0.clone(), reason: reason.clone() });
                    } else {
                        let (nick, channel) = (sender.clone(), channel.0.clone());
                        events.push(Event::PeerLeft { nick, channel, reason: reason.clone() });
                    }
                }
            }
            // **A kick of this client is forgotten**, or a reconnect would
            // join the user into a channel that removed them.
            Command::Kick { channel, user, reason } => {
                let reason = reason.as_ref().map(|r| r.as_str().to_string());
                if self.is_me(&user.0) {
                    self.memory.forget(&channel.0);
                    events.push(Event::Kicked { channel: channel.0.clone(), by: sender, reason });
                } else {
                    events.push(Event::PeerLeft { nick: user.0.clone(), channel: channel.0.clone(), reason });
                }
            }
            Command::Privmsg { target, text } if self.is_echo(&message) => {
                // Shown once: the second copy of a message to this client's
                // own nick is dropped.
                let to_self = self.is_me(&target.0);
                if !(to_self && previous_self_echo.as_deref() == Some(text.as_str())) {
                    if to_self {
                        self.last_self_echo = Some(text.as_str().to_string());
                    }
                    events.push(Event::Echo { target: target.0.clone(), text: text.as_str().to_string() });
                }
            }
            Command::Privmsg { target, text } => {
                let from = message.prefix.clone().unwrap_or_default();
                events.push(Event::Privmsg { from, target: target.0.clone(), text: text.as_str().to_string() });
            }
            // The server's answer to podssh's keepalive: a reception, with the
            // token as a trailing (ngircd, InspIRCd) or a middle (ergo).
            Command::Pong { token: Some(token), .. } => {
                if let Some(generation) = crate::irc::reap::parse_keepalive(token.as_str()) {
                    events.push(Event::Heartbeat { generation });
                }
            }
            Command::Notice { target, text } => {
                events.push(Event::Notice {
                    from: message.prefix.clone().unwrap_or_default(),
                    target: target.0.clone(),
                    text: text.as_str().to_string(),
                });
            }
            Command::Quit { reason } => {
                events.push(Event::Protocol(format!(
                    "peer quit: {}",
                    reason.as_ref().map(|r| r.as_str().to_string()).unwrap_or_default()
                )));
            }
            // The server's last word before it closes the link (T-252).
            Command::Unknown { name, params, trailing } if name.eq_ignore_ascii_case("ERROR") => {
                let words = trailing
                    .as_ref()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_else(|| params.iter().map(|p| p.0.as_str()).collect::<Vec<_>>().join(" "));
                events.push(Event::ServerError(words));
            }
            Command::Unknown { name, params, .. } => {
                // A file-transfer line rides on `PRIVMSG`, so it is recognised
                // there; anything else unknown is reported by name so an
                // operator can see what the network added.
                let _ = params;
                events.push(Event::Protocol(format!("unhandled command {name}")));
            }
            _ => {}
        }
        // **A `PRIVMSG` carrying `PODSSH1|…` is a transfer line, and it is
        // consumed before the text is shown.** The reverse would put a
        // `PODSSH1|chunk|…` line in a user's terminal on every chunk of every
        // transfer. An echo of this client's own line is no line from a peer.
        if let Command::Privmsg { text, .. } = &message.command {
            if let Some(line) = crate::irc::transfer::Line::parse(text.as_str()).filter(|_| !self.is_echo(&message)) {
                events.retain(|e| !matches!(e, Event::Privmsg { .. }));
                events.push(Event::Transfer(line));
            }
        }
    }

    fn on_numeric(&mut self, message: &Message, code: u16, out: &mut Vec<Message>, events: &mut Vec<Event>) {
        // Each `005` adds to the ones before it.
        if code == Code::RplIsupport as u16 {
            let params: Vec<String> = message.command.params().iter().map(|p| p.0.clone()).collect();
            self.isupport.merge(&params);
        }
        // A `421` for `CAP` is a server with no `CAP`: it holds no
        // registration, so it is no refusal, and no `CAP END` is due.
        // MEASURED live 2026-10-07: undernet answers `CAP LS` with
        // `421 Unknown command`, after 001.
        let no_cap = code == Code::ErrUnknownCommand as u16
            && message.command.params().get(1).is_some_and(|p| p.0.eq_ignore_ascii_case("CAP"));
        if no_cap {
            self.negotiation.unsupported();
        }
        // Registration-time numerics only count while Pending: a late one
        // must not un-register a working session and fail every later send
        // with NotRegistered. **A nick that another holds is tried again**
        // with a suffix, as ngircd 27, InspIRCd 4.11.0 and ergo 2.18.0 then
        // welcome `pa_` (T-095); only after the last try is it a refusal.
        let in_use = code == Code::ErrNicknameInUse as u16;
        if self.registered == Registered::Pending && in_use && self.nick_tries < NICK_TRIES {
            self.nick_tries += 1;
            self.nick = suffixed(&self.server.nick, self.nick_tries, self.isupport.nicklen());
            out.push(nick_message(&self.nick));
        } else if self.registered == Registered::Pending && !no_cap {
            if let Some(failure) = registration_failure(code) {
                self.registered = Registered::Refused(failure);
            }
        }
        if code == Code::RplWelcome as u16 {
            self.registered = Registered::Yes;
            // The welcome's first parameter is the nick that the server gave.
            if let Some(me) = message.command.params().first().filter(|p| !p.0.is_empty() && p.0 != "*") {
                self.nick = me.0.clone();
            }
            // A server with `CAP` holds the welcome until `CAP END`, so a
            // welcome before any answer to `CAP LS` is a server with none:
            // InspIRCd 4 with no cap module answers nothing.
            if self.negotiation.stage() == Stage::LsSent {
                self.negotiation.unsupported();
            }
        }
        events.push(Event::Numeric { code, text: message.command.trailing().map(|t| t.as_str().to_string()) });
    }

    /// Whether `nick` is this client's, by the server's `CASEMAPPING`.
    pub(crate) fn is_me(&self, nick: &str) -> bool {
        self.isupport.same(nick, &self.nick)
    }

    /// A line about this client: from its nick, or from no one.
    fn about_me(&self, message: &Message) -> bool {
        message.prefix.as_ref().is_none_or(|p| self.is_me(&p.nick))
    }

    /// A message that this client sent, back from the server: with
    /// `echo-message` on, it comes from this client's nick.
    fn is_echo(&self, message: &Message) -> bool {
        self.negotiation.enabled().iter().any(|c| c.eq_ignore_ascii_case(crate::irc::CAP_ECHO_MESSAGE))
            && message.prefix.as_ref().is_some_and(|p| self.is_me(&p.nick))
    }
}

/// The nick to try after `n` refusals: the wanted one with `n` `_`, cut to
/// fit `NICKLEN`, or to the wanted one's own length when that is longer, as
/// the server's limit is then above what it said so far.
fn suffixed(wanted: &str, n: u8, nicklen: usize) -> String {
    let suffix = "_".repeat(n as usize);
    let room = nicklen.max(wanted.chars().count());
    wanted.chars().take(room.saturating_sub(suffix.len())).chain(suffix.chars()).collect()
}

/// **Map a registration-time numeric to a named failure, and `None` for
/// everything else.** Only the codes RFC 2812 §6 uses during
/// registration are named, so an unrelated `404` arriving mid-chat does
/// not mark a working session refused.
fn registration_failure(code: u16) -> Option<RegistrationFailure> {
    Some(match code {
        c if c == Code::ErrNicknameInUse as u16 => RegistrationFailure::NicknameInUse,
        c if c == Code::ErrErroneousNickname as u16 => RegistrationFailure::NicknameErroneous,
        c if c == Code::ErrPasswdMismatch as u16 => RegistrationFailure::PasswdMismatch,
        c if c == Code::ErrNeedMoreParams as u16 => RegistrationFailure::NeedMoreParams,
        c if c == Code::ErrUnknownCommand as u16 => RegistrationFailure::UnknownCommand,
        other => {
            if matches!(other, 432 | 433 | 436 | 461 | 464 | 421) {
                RegistrationFailure::Other(other)
            } else {
                return None;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::suffixed;

    #[test]
    fn a_suffixed_nick_fits_nicklen() {
        assert_eq!(suffixed("pa", 1, 9), "pa_");
        assert_eq!(suffixed("podtest12", 1, 9), "podtest1_");
        assert_eq!(suffixed("podtest12", 3, 9), "podtes___");
        // Longer than the limit known so far: the server took that length.
        assert_eq!(suffixed("podsshuser42", 1, 9), "podsshuser4_");
    }
}
