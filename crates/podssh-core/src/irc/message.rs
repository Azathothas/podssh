//! A line ⇄ a [`Message`]. **The parser is the whole entry; everything else
//! is transport.** The relay already moves bytes, so what is left to own is the
//! grammar of RFC 1459 / RFC 2812 and nothing beyond it.
//!
//! ## The grammar, and the three places a naive parser gets it wrong
//!
//! ```text
//! [':' prefix SPACE] command *( SPACE middle ) [ SPACE ':' trailing ] CRLF
//! ```
//!
//! 1. **The trailing is the only part that may contain spaces, and it is
//!    announced by its leading `:`.** `PRIVMSG #c :hello there world` is one
//!    parameter, and the message *inside* it may contain further colons:
//!    `PRIVMSG #c :see 12:30` keeps `12:30`. A parser that splits on spaces
//!    and then re-joins the tail with spaces cannot tell `a  b` from `a b`,
//!    so the split is done once and the trailing is taken verbatim.
//! 2. **A middle may be empty** — RFC 2812 §2.3.2 permits `:` to follow a
//!    space directly. `PRIVMSG #c :` is a PRIVMSG with an empty message, and a
//!    parser that drops the empty trailing loses the message.
//! 3. **`@tag ;` precedes the prefix**, not the command. IRCv3 message tags
//!    arrived after RFC 1459, and a peer that sends one to a client that does
//!    not understand tags still expects the *rest* of the line to parse.
//!
//! **Byte-exact in both directions.** Every command has a round-trip test
//! against a fixture, and the encoder writes the shortest legal spelling: no
//! padding and no trailing space. A user who types `/msg bob hello` gets
//! `:nick!user@host PRIVMSG bob :hello` — the `:` before `hello` is
//! **required**, because without it the words would be six parameters, and the
//! server would answer `ERR_NEEDMOREPARAMS` or deliver nothing. A trailing
//! that already contains a space does not get a second colon; one colon
//! introduces the trailing and everything after it is the trailing.
//!
//! **The command table is in [`crate::irc::command`] and the tag codec in
//! [`crate::irc::tag`].** This file holds the grammar's shape — prefix,
//! parameter split, encode — and those two hold the parts that grew past the
//! 500-line gate. **Split, not trimmed**: the reasoning is the protocol.

use std::fmt;

use crate::irc::framing::MAX_ALLOWED_LINE;

/// The prefix of a message: who sent it, or where it came from.
///
/// ```text
/// <source> ::= <nick> [ '!' <user> ] '@' <host>      a client
///            | <server>                              a server: no '!' or '@'
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Prefix {
    pub nick: String,
    pub user: Option<String>,
    pub host: Option<String>,
}

impl Prefix {
    /// A server prefix has no `!` and no `@`; inferring a client from the
    /// *absence* of those would make `irc.example.org` look like a nick.
    pub fn server(name: impl Into<String>) -> Self {
        Prefix { nick: name.into(), user: None, host: None }
    }

    pub fn client(nick: impl Into<String>, user: impl Into<String>, host: impl Into<String>) -> Self {
        Prefix { nick: nick.into(), user: Some(user.into()), host: Some(host.into()) }
    }

    /// True when the prefix carries a `!` or an `@`, which is the only
    /// reliable test. `:irc.example.org` and `:bob` are both legal prefixes and
    /// neither may be assumed to be a client.
    pub fn is_server(&self) -> bool {
        self.user.is_none() && self.host.is_none()
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.nick)?;
        if let Some(user) = &self.user {
            write!(f, "!{user}")?;
        }
        if let Some(host) = &self.host {
            write!(f, "@{host}")?;
        }
        Ok(())
    }
}

/// **An IRCv3 message tag**, kept as its name and its value.
///
/// **The value is `Option` because a valueless tag is legal and different.**
/// `@+draft/shield=please` has a value; `@room` does not. A parser that maps
/// "absent" to "empty string" loses the difference, and a client that then
/// echoes the tag back with `room=` changes its meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub key: String,
    pub value: Option<String>,
}

/// A parameter that the server sends as `<host>` in its documentation: a
/// channel name, a nick, or a mask. Kept distinct from [`Trailing`] so the
/// parser is total — every parameter occupies exactly one of three places, and
/// there is no fourth case to fall through.
///
/// **String matching uses IRC's own rules, not `str::eq`.** RFC 1459 §2.2:
/// ```text
/// letter = "A".."Z" / "a".."z"
/// digit  = "0".."9"
/// special = "-" / "/" / "[" / "]" / "\" / "`" / "^" / "_" / "{"
///          / "}" / "|"
/// hostname = 1*( letter / digit / "." / "-" )
/// ```
/// so `irc.example.com` and `IRC.EXAMPLE.COM` are the same channel and
/// `nick!user@host` is a mask, not a nick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `001`…`999`, **with its parameters.** **The code is a number,
    /// never a string**, because a reply code compared as text compares `"100"`
    /// with `"001"` as equal; **and the parameters are carried rather than
    /// dropped**, because a parse that cannot be re-encoded has thrown the
    /// message away — MEASURED 2026-10-02, with a bare `Numeric(u16)` the
    /// round-trip test re-encoded `:irc.example.org 001 alice :Welcome` as
    /// `:irc.example.org 1`.
    Numeric(crate::irc::numeric::Replies),
    Privmsg {
        target: Middle,
        text: Trailing,
    },
    Notice {
        target: Middle,
        text: Trailing,
    },
    Join {
        channels: Vec<Middle>,
        key: Option<String>,
    },
    Part {
        channels: Vec<Middle>,
        reason: Option<Trailing>,
    },
    Topic {
        channel: Middle,
        topic: Option<Trailing>,
    },
    Names {
        channels: Vec<Middle>,
    },
    List {
        channels: Vec<Middle>,
    },
    Mode {
        target: Middle,
        flags: Vec<Middle>,
    },
    Quit {
        reason: Option<Trailing>,
    },
    Ping {
        token: Trailing,
    },
    Pong {
        token: Option<Trailing>,
    },
    Nick {
        nickname: Middle,
    },
    User {
        user: Middle,
        mode: Middle,
        unused: Middle,
        realname: Trailing,
    },
    /// `CAP <target> <subcommand> [args] [:trailing]`. **The target is
    /// its own field**, not part of `args`: a server has no nick to
    /// address and sends `CAP * LS :…`, so the `*` sits *before* the
    /// verb on the wire — an encoder that treats it as an ordinary
    /// argument writes `CAP LS *`, MEASURED 2026-10-02.
    Cap {
        target: Option<Middle>,
        subcommand: CapVerb,
        args: Vec<Middle>,
        trailing: Option<Trailing>,
    },
    /// Anything else, **whole**. An IRC client that errors on `AWAY` or on a
    /// vendor extension has a client that breaks when the peer adds a command.
    /// The unknown command keeps its spelling and its parameters, so it can be
    /// forwarded or logged byte-exactly.
    Unknown {
        name: String,
        params: Vec<Middle>,
        trailing: Option<Trailing>,
    },
}

/// The `CAP` subcommand. **`Ls`/`Req`/`Ack`/`Nak`/`List`/`Del`/`New`/`End`
/// are the whole vocabulary; anything else is `Unknown`** and is preserved,
/// because a peer that invents a subcommand must not make the client silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapVerb {
    Ls,
    Req,
    Ack,
    Nak,
    List,
    Del,
    New,
    End,
    Unknown,
}

/// A middle parameter: no spaces, and never introduced by `:`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Middle(pub String);

/// The trailing parameter: **every byte after the first `:`, verbatim.**
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Trailing {
    pub value: String,
    /// **Whether the wire wrote a `:` before it, and it is kept because
    /// both spellings are legal.** RFC 2812 §2.3.2 makes the `:` mandatory
    /// for `PRIVMSG` and `NOTICE` — and both are what public ircds send —
    /// while RFC 1459 §2.3.2 allows a server to leave it off when the
    /// parameter has no space or colon in it, and `PING 12345` with no colon is
    /// a real thing on the wire.
    ///
    /// **MEASURED 2026-10-02**: the fixture round-trip caught this, — a
    /// client that re-encodes `PING 12345` as `PING :12345` still works, but
    /// a test asserting "re-encodes to the line it came from" cannot hold while
    /// this flag does not exist.
    ///
    /// **podssh always writes the `:` when it sends a trailing**, so a
    /// message it composes is never the ambiguous one.
    pub colon: bool,
}

impl fmt::Display for Middle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Trailing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.colon {
            f.write_str(":")?;
        }
        f.write_str(&self.value)
    }
}

impl Trailing {
    /// **The spelling podssh writes**, and it is always the explicit one.
    pub fn new(value: impl Into<String>) -> Self {
        Trailing { value: value.into(), colon: true }
    }

    /// The spelling that arrived.
    pub fn as_written(value: impl Into<String>, colon: bool) -> Self {
        Trailing { value: value.into(), colon }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn into_inner(self) -> String {
        self.value
    }
}

impl Middle {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// **RFC 1459 §2.2 case folding: A-Z only, never `to_lowercase`.**
    /// Turkish dotless ı, German ß and Greek sigma all change under a
    /// Unicode-aware lowercase, and `#Channel` and `#channel` are the same
    /// channel. The character class is the ASCII one, applied to bytes.
    pub fn eq_irc(&self, other: &str) -> bool {
        self.0.as_bytes().eq_ignore_ascii_case(other.as_bytes())
    }
}

/// A parsed message, byte-exact enough to re-encode to the same line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub tags: Vec<Tag>,
    pub prefix: Option<Prefix>,
    pub command: Command,
}

/// **Every way a line is not a message**, named. Each variant exists because
/// a different thing is wrong and they have different remedies: a peer sending
/// `[` is a peer sending a CTCP quote to a client that does not answer it
/// (which must be answered), while a peer sending ` PRIVMSG` is a broken peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The line began with `:` but had no command after the prefix.
    PrefixOnly { line: String },
    /// The line began with a space, so the command is empty. RFC 2812 §2.3.1
    /// allows a leading space to be ignored; **it is not ignored here**,
    /// because a line whose command is empty has no message and emitting an
    /// empty one would put a blank line in a user's terminal.
    MissingCommand { line: String },
    /// A command arrived with fewer parameters than it needs. The number is
    /// the command's arity, not a guess.
    TooFewParams { command: String, need: usize, got: usize },
    /// A `PRIVMSG`/`NOTICE` with no text: RFC 2812 §2.3.2 makes the colon
    /// mandatory for these two, and a PRIVMSG without one is either a broken
    /// peer or an attempt to smuggle a parameter count past a client.
    MissingTrailing { command: String },
    /// The line was not UTF-8. Caught by [`crate::irc::framing`] first in
    /// normal use; reachable by a direct [`Message::parse`] call.
    NotUtf8,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::PrefixOnly { line } => {
                write!(f, "IRC line has a prefix and no command: {line:?}")
            }
            ParseError::MissingCommand { line } => {
                write!(f, "IRC line has no command: {line:?}")
            }
            ParseError::TooFewParams { command, need, got } => {
                write!(f, "{command} needs {need} parameter(s) and arrived with {got}")
            }
            ParseError::MissingTrailing { command } => {
                write!(f, "{command} requires a trailing parameter introduced by ':'")
            }
            ParseError::NotUtf8 => write!(f, "IRC line is not UTF-8"),
        }
    }
}

impl std::error::Error for ParseError {}

/// **The parameters of a message, in wire order.** A `CAP REQ` and an
/// `Unknown` are *variable* in arity, so they cannot be flattened into a fixed
/// tuple at the point they are parsed; this is where that is resolved, and it
/// is resolved once rather than in every caller.
pub(crate) fn split_params(rest: &str) -> (Vec<String>, Option<(String, bool)>) {
    // **TWO BUGS A FIXTURE CAUGHT HERE, and both are the reason this
    // function is 20 lines rather than 5.**
    //
    // **Bug 1: the run-skipping.** The first version advanced past *every*
    // space after a delimiter. A middle is separated from the next
    // parameter by **exactly one** space (RFC 2812 §2.3.1), and
    // `PRIVMSG #ops :hello there world` has **one** space before the `:`.
    // Skipping the run therefore swallowed the `:` that introduced the trailing.
    //
    // **Bug 2, the one that survived bug 1's fix: the trailing was cut at
    // the next space.** The obvious loop slices each parameter at
    // `find(' ')` and then asks whether the slice began with `:`. **`find`
    // scans the whole remaining string**, so the slice for `:hello there world`
    // is `:hello`, the `:` is found, and the trailing becomes `hello` with
    // `there world` left over as two middles.
    //
    // **MEASURED 2026-10-02**, both caught by
    // `tests/grammar.rs::the_trailing_keeps_spaces_and_the_colons_inside_it`:
    // `PRIVMSG #ops :hello there world` produced the trailing `hello`.
    //
    // **The fix is the order of the two tests, not a cleverer search.**
    // The trailing is announced by a `:` *at the start of a parameter*, and
    // a parameter boundary is a space, so:
    //   1. is this parameter's first byte a `:`? → if so the **rest of the
    //      line** is the trailing and the loop is over;
    //   2. otherwise cut at the next space and push it as a middle.
    // **Once the `:` test is first, the trailing is taken to end-of-line and
    // the spaces inside it are never examined** — which is the whole
    // requirement, and it is a property of the order rather than of a search.
    let mut middles = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    loop {
        // `i` is always the first byte of a parameter: 0, or one byte past
        // a delimiter.
        if i < bytes.len() && bytes[i] == b':' {
            return (middles, Some((rest[i + 1..].to_string(), true)));
        }
        let end = rest[i..].find(' ').map(|rel| i + rel).unwrap_or(bytes.len());
        middles.push(rest[i..end].to_string());
        if end == bytes.len() {
            return (middles, None);
        }
        i = end + 1;
        if i == bytes.len() {
            // A line ending in a space carries an empty final parameter, and
            // dropping it would make the count disagree with the wire.
            middles.push(String::new());
            return (middles, None);
        }
    }
}

pub(crate) fn parse_prefix(text: &str) -> Prefix {
    match text.split_once('!') {
        Some((nick, rest)) => {
            let (user, host) = match rest.split_once('@') {
                Some((u, h)) => (u.to_string(), Some(h.to_string())),
                None => (rest.to_string(), None),
            };
            Prefix { nick: nick.to_string(), user: Some(user), host }
        }
        None => match text.split_once('@') {
            Some((nick, host)) => Prefix { nick: nick.to_string(), user: None, host: Some(host.to_string()) },
            None => Prefix::server(text),
        },
    }
}

/// **The wire length a message will occupy, including `\r\n`.**
///
/// The encoder is the only way podssh writes a message, so a caller sizing
/// a frame asks this rather than counting a string it built itself — and
/// [`MAX_ALLOWED_LINE`] is 512 including the terminator, which is the number
/// that matters when a server refuses an over-long line.
pub fn wire_len(message: &Message) -> usize {
    message.to_line().len() + 2
}

/// Will this message fit the 512-byte limit RFC 2812 §2.3 states?
///
/// **Used by the file-transfer path**, which is the only place podssh builds
/// messages whose size it controls rather than the user's typing: a chunk's
/// base64 payload plus its offer header must land inside it, or the server
/// silently truncates and the transfer resumes from a boundary that was never
/// written.
pub fn fits_in_allowed_line(message: &Message) -> bool {
    wire_len(message) <= MAX_ALLOWED_LINE
}
