//! The IRC state machine — RFC 1459 / RFC 2812 — and nothing else.
//!
//! Why a module and no crate: the relay moves bytes, and the code that carries
//! them (`podssh-relay`, `podssh-ws`) never learns the word IRC. One road, many
//! protocols: podssh speaks the protocol at the ends, and the relay carries
//! the bytes without knowing which. So IRC depends on neither, and needs no
//! change to them.
//!
//! **This module owns no I/O policy and no clock.** Everything here is a
//! pure function of bytes, a caller's push buffer, and an injected clock. That
//! is why the whole protocol is testable with no network, and why the tests
//! that matter — a frame boundary landing mid-message — can be reproduced
//! exactly rather than waited for.
//!
//! ## The five modules, and what each is for
//!
//! | module | holds |
//! | --- | --- |
//! | [`framing`] | bytes ⇄ lines. The defect the whole transport can cause. |
//! | [`message`] | a line ⇄ a [`Message`](message::Message). The parser is the entry. |
//! | [`isupport`] | `005`, the capability vocabulary, and `PREFIX`/`CHANMODES` decoding |
//! | [`numeric`] | `RPL_WELCOME` … `ERR_*`, so an unnamed number is a compile error |
//! | [`cap`] | `CAP LS/REQ/ACK/NAK`, the capability negotiation state machine |
//!
//! ## The three that decide whether this works at all
//!
//! * [`limits`] — **the relay's limits, not ours.** The chunk size and the
//!   per-session cap live here so file transfer cannot be written against a
//!   number nothing measured. `include_str!`s
//!   `podssh-probe/facts/relay-facts.toml` — **the same file
//!   `podssh-probe`'s Rust gate, `scripts/check-relay-spec.py` and
//!   `docs/relay.md` all follow**, so **one copy of the
//!   numbers and four readers over it**.
//! * [`transfer`] — a file, as bytes over sessions, chunked at those limits,
//!   resumable from the chunk boundary.
//! * [`session`] and [`reap`] — registration, what to remember across a
//!   reconnect, and the payload activity that keeps the relay's idle reaper
//!   from winning a fight it always wins.

pub mod cap;
pub mod command;
pub mod command_view;
pub mod encode;
pub mod framing;
pub mod isupport;
pub mod limits;
pub mod message;
pub mod numeric;
pub mod reap;
pub mod session;
pub mod session_parts;
pub mod session_send;
pub mod tag;
pub mod transfer;

pub use encode::Unsafe;
pub use framing::{FrameError, Framed, Reassembler, DEFAULT_MAX_LINE, MAX_ALLOWED_LINE};
pub use limits::TransferLimits;
pub use message::{Command, Message, ParseError, Prefix, Tag, Trailing};
pub use reap::{payload_plan_for, PayloadPlan, ReapPolicy};
pub use session::{Event, Registered, RegistrationFailure, Server, Session, SessionError};
pub use session_parts::{join_message, nick_message, user_message, ChannelMemory};

/// The capability name podssh advertises, so a second surface that speaks
/// this protocol cannot invent a second spelling.
///
/// `znc.in/self-message` is what makes a client see its own message back, which
/// is how the user knows the transfer they asked for was echoed into the room
/// and not lost. **`sasl` is deliberately NOT advertised**: podssh's IRC leg
/// authenticates nothing, and advertising a mechanism the client cannot
/// complete is how a client ends up in a loop a user cannot leave.
pub const CAP_SELF_MESSAGE: &str = "znc.in/self-message";

/// **Defaults only, and every one of them is superseded by the server's
/// `005`** — see [`isupport::Isupport`], which is where a client reads the
/// real value. **These are the numbers a client falls back to when the
/// server sent nothing**, and they are here rather than hardcoded at each
/// use so there is one fallback and not four.
///
/// `NICKLEN` 9 and `CHANNELLEN` 64 are **RFC 1459 §2.6's own defaults**.
/// `TOPICLEN` 390 is RFC 2812 §2.3.4's.
pub mod rfc_limits {
    /// RFC 1459 §2.6. **A server that sends `NICKLEN` overrides this.**
    pub const NICKLEN: usize = crate::irc::isupport::DEFAULT_NICKLEN;
    /// RFC 1459 §2.6. **A server that sends `CHANNELLEN` overrides this.**
    pub const CHANNELLEN: usize = crate::irc::isupport::DEFAULT_CHANNELLEN;
    /// RFC 2812 §2.3.4. **A server that sends `TOPICLEN` overrides this.**
    pub const TOPICLEN: usize = 390;
}
