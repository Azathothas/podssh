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
//! **`CAP END` comes before `001`.** A server that answers `CAP LS` holds the
//! registration until the client ends the negotiation, so the answer to the
//! request ends it ([`crate::irc::cap`], T-091).

use crate::irc::cap::Negotiation;
use crate::irc::framing::{Framed, Reassembler};
use crate::irc::isupport::Isupport;
use crate::irc::message::{Command, Message, Prefix, Trailing};
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
    /// **The server's echo of a message that this client sent**, with
    /// `echo-message` on: the proof that it was delivered. Shown once, and
    /// never read as a peer's message or a peer's file line (T-092).
    Echo { target: String, text: String },
    /// A `NOTICE`, which **is not shown** — RFC 2812 §3.3.2 says notices
    /// are never sent to a client that did not send the matching `PRIVMSG`
    /// except for `NOTICE AUTH`, and a client that displays them puts a
    /// server's status messages in the middle of a conversation.
    Notice { from: Prefix, target: String, text: String },
    /// The user joined a channel.
    Joined { channel: String },
    /// The user left, by its `PART`.
    Left { channel: String, reason: Option<String> },
    /// The user was removed from a channel by `KICK`, and is not joined to
    /// it again (T-095).
    Kicked { channel: String, by: String, reason: Option<String> },
    /// Another user joined a channel.
    PeerJoined { nick: String, channel: String },
    /// Another user left a channel, by `PART` or by `KICK`.
    PeerLeft { nick: String, channel: String, reason: Option<String> },
    /// The server answered a numeric podssh acts on.
    Numeric { code: u16, text: Option<String> },
    /// A file-transfer line arrived.
    Transfer(TransferLine),
    /// The server answered podssh's keepalive (`PONG :podssh-N`): a
    /// reception, which no user sees.
    Heartbeat { generation: u64 },
    /// The server's `ERROR`, which it sends as it closes the link: its words,
    /// as a ban, a limit or a timeout (T-252).
    ServerError(String),
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
    /// The session is not registered and cannot send user traffic.
    NotRegistered,
    /// The message would exceed the 512-byte line limit.
    TooLong { bytes: usize },
    /// A part of the message would change the line it is written in: a CR,
    /// LF or NUL, or in a middle a space, a leading `:` or nothing.
    Unsafe(crate::irc::encode::Unsafe),
}

impl From<crate::irc::encode::Unsafe> for SessionError {
    fn from(e: crate::irc::encode::Unsafe) -> Self {
        SessionError::Unsafe(e)
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::TruncatedMidLine { pending_bytes, .. } => write!(
                f,
                "the IRC stream ended mid-line with {pending_bytes} byte(s) buffered; \
                 the partial line is NOT shown and the session reconnects"
            ),
            SessionError::Unsafe(e) => write!(f, "{e}"),
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
    pub(crate) server: Server,
    pub(crate) registered: Registered,
    pub(crate) negotiation: Negotiation,
    pub(crate) isupport: Isupport,
    pub(crate) memory: ChannelMemory,
    reassembler: Reassembler,
    /// The `PONG` tokens podssh has not yet answered, **in arrival order.**
    /// A queue and not a set: **two `PING`s with the same token must get
    /// two `PONG`s**, and collapsing them into a set would answer a second
    /// ping that was a genuine retry with nothing.
    pub(crate) pending_pongs: Vec<String>,
    policy: ReapPolicy,
    /// **This client's nick as the server knows it** (T-095): the one that
    /// `001` names, then each `NICK` of it. A line about another nick is
    /// about another user.
    pub(crate) nick: String,
    /// How many times a nick in use was tried again before `001`.
    pub(crate) nick_tries: u8,
    /// The text of the last echo of a message to this client's own nick,
    /// while its second copy may follow: with `echo-message`, InspIRCd 4.11.0
    /// and ergo 2.18.0 send such a message back twice, as delivered and as
    /// echoed, one after the other.
    pub(crate) last_self_echo: Option<String>,
}

impl Session {
    pub fn new(server: Server, policy: ReapPolicy) -> Self {
        Session {
            registered: Registered::Pending,
            negotiation: Negotiation::new(),
            isupport: Isupport::empty(),
            memory: ChannelMemory::default(),
            reassembler: Reassembler::new(),
            pending_pongs: Vec::new(),
            policy,
            nick: server.nick.clone(),
            nick_tries: 0,
            last_self_echo: None,
            server,
        }
    }

    pub fn registered(&self) -> Registered {
        self.registered
    }

    pub fn server(&self) -> &Server {
        &self.server
    }

    /// This client's nick as the server knows it: after a `433` before
    /// `001`, or a `NICK`, it is not [`Server::nick`].
    pub fn nick(&self) -> &str {
        &self.nick
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
        out.push(nick_message(&self.nick));
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
        // **A new connection, of which nothing of the old one holds but the
        // channels** (T-095): not registered, a negotiation again (that keeps
        // what the server refused), no half line, no old `PING`, no `005`, and
        // the nick that the user wants again.
        self.registered = Registered::Pending;
        self.reassembler = Reassembler::new();
        self.pending_pongs.clear();
        self.isupport = Isupport::empty();
        self.nick = self.server.nick.clone();
        self.nick_tries = 0;
        self.last_self_echo = None;
        let mut out = vec![self.negotiation.reconnect()];
        out.push(nick_message(&self.nick));
        out.push(user_message(&self.server));
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
    /// it should precede is a dropped client. A line that the byte layer
    /// lost, or read as Latin-1, is an [`Event::Protocol`], and the session
    /// goes on: one line from one peer does not end it.
    pub fn on_bytes(&mut self, frame: &[u8]) -> (Vec<Message>, Vec<Event>) {
        let mut out = Vec::new();
        let mut events = Vec::new();
        for framed in self.reassembler.push(frame) {
            match framed {
                Framed::Line(line) => self.on_line(&line, &mut out, &mut events),
                Framed::Latin1(line) => {
                    events.push(Event::Protocol("a line that is not UTF-8 was read as Latin-1".into()));
                    self.on_line(&line, &mut out, &mut events);
                }
                Framed::Lost(e) => events.push(Event::Protocol(e.to_string())),
            }
        }
        // **PONGs are drained after the whole frame**, so a frame carrying
        // `PING a` then `PING b` produces `PONG a`, `PONG b` and a frame
        // carrying nothing else produces nothing.
        out.extend(self.take_pongs());
        (out, events)
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
                command: Command::Pong { server: None, token: Some(Trailing::new(token)) },
            })
            .collect()
    }
}
