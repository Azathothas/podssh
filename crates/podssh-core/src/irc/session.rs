//! Registration, what to remember, and what to re-send after a drop.
//!
//! **This module owns no socket and no clock.** Every entry point takes the
//! bytes the relay handed over, and every "what next" answer is a
//! [`Vec<Message>`] the caller writes in order. That is what makes an idle
//! session's whole life — register, sit, get reaped, reconnect, rejoin —
//! testable in a function with no `tokio::time` in it, which is the only way
//! to test the entry's four plants.
//!
//! ## The reconnect rule, stated once
//!
//! A reconnect **must re-issue `CAP`, `NICK` and `USER`, and rejoin every
//! channel it remembers**, in that order, because that is a *new TCP
//! session* and not a resumed one. The three that get forgotten are the ones
//! that fail silently: a reconnect that skips `CAP` loses
//! `znc.in/self-message` so file transfers stop echoing and the user sees
//! nothing happen; a reconnect that skips `NICK`/`USER` is not registered
//! and every `JOIN` is answered with `ERR_NOTREGISTERED`; a reconnect that
//! skips the rejoins leaves the user in a window they are watching and not in
//! the room they are talking in.
//!
//! **`CAP END` comes after `001`, never before.** IRCv3 §4: registration
//! is incomplete until `CAP END`, and a client that writes it immediately
//! races the server's state and is refused on some servers and not on others.

use crate::irc::cap::Negotiation;
use crate::irc::isupport::Isupport;
use crate::irc::message::{Command, Message, Prefix, Trailing};
use crate::irc::numeric::Numeric as Code;
use crate::irc::reap::ReapPolicy;
use crate::irc::session_parts::{join_message, nick_message, user_message, ChannelMemory};
use crate::irc::transfer::Line as TransferLine;

/// Who podssh is on the far side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub host: String,
    pub port: u16,
    /// The nick podssh wants. **A `433` renames it**, because the one
    /// reply a server sends that is not an error is a nick collision, and a
    /// client that treats it as fatal cannot connect to a network where somebody
    /// else already holds its preferred name.
    pub nick: String,
    pub username: String,
    pub realname: String,
}

impl Server {
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// **How far registration has got.** Three states and no more, because
/// the only thing a caller needs to know is **"may I send user traffic yet"**
/// — and a client that sends a `PRIVMSG` before `001` has it silently
/// dropped by the server with no error to anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// `CAP`/`NICK`/`USER` written, `001` not yet seen.
    Pending,
    /// `001` seen. **This is the state a user traffic message needs.**
    Yes,
    /// A registration error arrived. **Named, not a bool**, because
    /// `ERR_NICKNAMEINUSE` is recoverable by changing the nick and
    /// `ERR_PASSWDMISMATCH` is not, and a client that reports both as "failed
    /// to connect" makes the second one look like a race.
    Refused(RegistrationFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationFailure {
    NicknameInUse,
    NicknameErroneous,
    PasswdMismatch,
    NeedMoreParams,
    UnknownCommand,
    Other(u16),
}

/// Something a caller must show the user, **and something it must be able
/// to replay after a reconnect.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A `PRIVMSG` from someone, already parsed.
    Privmsg { from: Prefix, target: String, text: String },
    /// A `NOTICE`, which **is not shown** — RFC 2812 §3.3.2 says notices
    /// are never sent to a client that did not send the matching `PRIVMSG`
    /// except for `NOTICE AUTH`, and a client that displays them puts a
    /// server's status messages in the middle of a conversation.
    Notice { from: Prefix, target: String, text: String },
    /// The user joined a channel.
    Joined { channel: String },
    /// The user left, by `PART` or by `KICK`.
    Left { channel: String, reason: Option<String> },
    /// The server answered a numeric podssh acts on.
    Numeric { code: u16, text: Option<String> },
    /// A file-transfer line arrived.
    Transfer(TransferLine),
    /// A heartbeat from a peer podssh recognises. **Not displayed**,
    /// and its whole purpose is that a user does not see it.
    Heartbeat { generation: u64 },
    /// An error podssh reports without a user message of its own.
    Protocol(String),
}

/// **Why a [`Session::on_bytes`] call failed.** **The distinction is
/// load-bearing**: a stream that ended mid-line is a *clean* end that a
/// reconnect handles, while a bad frame is a bug that must not be retried in
/// a loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The stream ended **with bytes still buffered**. **The partial
    /// line is in the message and must not be shown** — this is the
    /// entry's `truncate` plant, and it is reported rather than swallowed so
    /// the reconnect path can say "the link dropped mid-message" instead of
    /// printing half a `PRIVMSG` and pretending the peer went quiet.
    TruncatedMidLine { partial: String, pending_bytes: usize },
    /// A line was not UTF-8, or was over the length limit.
    Frame(crate::irc::framing::FrameError),
    /// The session is not registered and cannot send user traffic.
    NotRegistered,
    /// The message would exceed the 512-byte line limit.
    TooLong { bytes: usize },
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::TruncatedMidLine { pending_bytes, .. } => write!(
                f,
                "the IRC stream ended mid-line with {pending_bytes} byte(s) buffered; \
                 the partial line is NOT shown and the session reconnects"
            ),
            SessionError::Frame(e) => write!(f, "{e}"),
            SessionError::NotRegistered => {
                write!(f, "not registered yet; a server drops traffic sent before 001")
            }
            SessionError::TooLong { bytes } => write!(
                f,
                "the message is {bytes} bytes and RFC 2812 2.3 caps a message at 512 \
                 including the terminator"
            ),
        }
    }
}

impl std::error::Error for SessionError {}

/// The IRC session. **No I/O, no clock, no state the relay knows about.**
#[derive(Debug, Clone)]
pub struct Session {
    server: Server,
    pub(crate) registered: Registered,
    negotiation: Negotiation,
    isupport: Isupport,
    pub(crate) memory: ChannelMemory,
    reassembler: crate::irc::framing::Reassembler,
    /// The `PONG` tokens podssh has not yet answered, **in arrival order.**
    /// A queue and not a set: **two `PING`s with the same token must get
    /// two `PONG`s**, and collapsing them into a set would answer a second
    /// ping that was a genuine retry with nothing.
    pending_pongs: Vec<String>,
    policy: ReapPolicy,
}

impl Session {
    pub fn new(server: Server, policy: ReapPolicy) -> Self {
        Session {
            server,
            registered: Registered::Pending,
            negotiation: Negotiation::new(),
            isupport: Isupport::empty(),
            memory: ChannelMemory::default(),
            reassembler: crate::irc::framing::Reassembler::new(),
            pending_pongs: Vec::new(),
            policy,
        }
    }

    pub fn registered(&self) -> Registered {
        self.registered
    }

    pub fn server(&self) -> &Server {
        &self.server
    }

    pub fn isupport(&self) -> &Isupport {
        &self.isupport
    }

    pub fn memory(&self) -> &ChannelMemory {
        &self.memory
    }

    pub fn negotiation(&self) -> &Negotiation {
        &self.negotiation
    }

    pub fn policy(&self) -> ReapPolicy {
        self.policy
    }

    pub fn pending_pongs(&self) -> &[String] {
        &self.pending_pongs
    }

    /// **Everything a fresh connection must write, in order.** **The
    /// order is the contract**: `CAP LS` before `NICK`/`USER` so the server's
    /// capability list arrives before registration, and `CAP END` not in this
    /// list at all because it is not legal until `001`.
    pub fn initial_burst(&mut self) -> Vec<Message> {
        let mut out = vec![self.negotiation.cap_ls()];
        out.push(nick_message(&self.server.nick));
        out.push(user_message(&self.server));
        out
    }

    /// **What a reconnect writes.** Identical to
    /// [`Session::initial_burst`] **plus one `JOIN` per remembered
    /// channel**, and **that is the entire difference**, which is worth
    /// asserting rather than describing: a reconnect that is not byte-equal to
    /// a first connection plus the rejoins is a reconnect that has forgotten
    /// something.
    ///
    /// **The `JOIN`s are sent immediately, before `001`.** They are legal
    /// and are buffered by every server until registration completes —
    /// and sending them immediately means the user is back in the rooms before
    /// they can notice they left. Sending them after `001` would be a
    /// **visible** gap, and "reconnect invisibly" is the entry's own phrase.
    pub fn reconnect_burst(&mut self) -> Vec<Message> {
        let mut out = self.initial_burst();
        for (i, channel) in self.memory.channels().iter().enumerate() {
            out.push(join_message(channel, self.memory.key_for(i)));
        }
        out
    }

    /// **The stream ended.** **This is the reconnect path**, and it is
    /// separate from [`Session::on_bytes`] because **a clean end and a
    /// mid-line truncation are different facts**: the first is a normal
    /// reconnect, the second means bytes were lost and the caller should say
    /// so. **The partial line is returned and is NOT shown to the user**,
    /// which is the whole of the entry's `truncate` clause.
    pub fn on_stream_end(&mut self) -> Option<SessionError> {
        let pending = self.reassembler.pending_len();
        match self.reassembler.take_rest() {
            None if pending == 0 => None,
            Some(partial) => Some(SessionError::TruncatedMidLine { partial, pending_bytes: pending }),
            None => Some(SessionError::TruncatedMidLine { partial: String::new(), pending_bytes: pending }),
        }
    }

    /// **Feed one frame's bytes.** Returns what to write next and what
    /// to show, **in that order**: a `PONG` that arrives after the text
    /// it should precede is a dropped client.
    pub fn on_bytes(&mut self, frame: &[u8]) -> Result<(Vec<Message>, Vec<Event>), SessionError> {
        let lines = self.reassembler.push(frame).map_err(SessionError::Frame)?;
        let mut out = Vec::new();
        let mut events = Vec::new();
        for line in lines {
            self.on_line(&line, &mut out, &mut events);
        }
        // **PONGs are drained after the whole frame**, so a frame carrying
        // `PING a` then `PING b` produces `PONG a`, `PONG b` and a frame
        // carrying nothing else produces nothing.
        out.extend(self.take_pongs());
        Ok((out, events))
    }

    /// The queued `PONG`s, in arrival order. **The token is used
    /// verbatim and is never re-quoted**: a server that sends `PING :a b c`
    /// is answered `PONG :a b c`, and a token that is trimmed, re-spaced or
    /// re-escaped is a token the server does not recognise and the answer to
    /// that is to drop the client.
    pub fn take_pongs(&mut self) -> Vec<Message> {
        std::mem::take(&mut self.pending_pongs)
            .into_iter()
            .map(|token| Message {
                tags: Vec::new(),
                prefix: None,
                command: Command::Pong { token: Some(Trailing::new(token)) },
            })
            .collect()
    }

    fn on_line(&mut self, line: &str, out: &mut Vec<Message>, events: &mut Vec<Event>) {
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
        match &message.command {
            Command::Ping { token } => {
                self.pending_pongs.push(token.as_str().to_string());
            }
            Command::Numeric(reply) => {
                let code = reply.code;
                if code == Code::RplIsupport as u16 {
                    let params: Vec<String> = message.command.params().iter().map(|p| p.0.clone()).collect();
                    self.isupport = Isupport::parse(&params);
                }
                // Registration-time numerics only count while Pending: a
                // late 421 — MEASURED live 2026-10-07, undernet answers CAP
                // LS with `421 Unknown command` AFTER 001 (no IRCv3) — must
                // not un-register a working session and fail every later
                // send with NotRegistered.
                if self.registered == Registered::Pending {
                    if let Some(failure) = registration_failure(code) {
                        self.registered = Registered::Refused(failure);
                    }
                }
                if code == Code::RplWelcome as u16 {
                    self.registered = Registered::Yes;
                    // **THE ORDERING, and it is the one IRCv3 requires.**
                    // `001` is what makes `CAP END` legal, so `CAP END` is
                    // produced here and not before. A client that emitted it
                    // with the initial burst is refused on some servers.
                    if let Some(end) = self.negotiation.on_registration() {
                        out.push(end);
                    }
                }
                events.push(Event::Numeric { code, text: message.command.trailing().map(|t| t.as_str().to_string()) });
            }
            Command::Join { channels, .. } => {
                for channel in channels {
                    if channel.0.starts_with('#') {
                        self.memory.remember(&channel.0, None);
                        events.push(Event::Joined { channel: channel.0.clone() });
                    }
                }
            }
            Command::Part { channels, reason } => {
                for channel in channels {
                    self.memory.forget(&channel.0);
                    events.push(Event::Left {
                        channel: channel.0.clone(),
                        reason: reason.as_ref().map(|r| r.as_str().to_string()),
                    });
                }
            }
            Command::Privmsg { target, text } => {
                let from = message.prefix.clone().unwrap_or_default();
                // **THE HEARTBEAT IS CONSUMED HERE, and nowhere else.** A
                // heartbeat reaching the display path is a heartbeat in a user's
                // scrollback, so the recognition and the suppression are one
                // decision rather than two that can disagree.
                if let Some(generation) = crate::irc::reap::parse_heartbeat(text.as_str()) {
                    events.push(Event::Heartbeat { generation });
                    return;
                }
                events.push(Event::Privmsg { from, target: target.0.clone(), text: text.as_str().to_string() });
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
        // transfer.
        if let Command::Privmsg { text, .. } = &message.command {
            if let Some(line) = crate::irc::transfer::Line::parse(text.as_str()) {
                events.retain(|e| !matches!(e, Event::Privmsg { .. }));
                events.push(Event::Transfer(line));
            }
        }
    }
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
