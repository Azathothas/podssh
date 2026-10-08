//! `CAP LS` / `REQ` / `ACK` / `NAK` / `END` — IRCv3 capability negotiation.
//!
//! ⛔ **Why podssh negotiates at all.** `CAP` exists so a client and a server
//! can agree on extensions *before* registration. podssh wants one of them:
//! `znc.in/self-message`, without which a client never sees its own `PRIVMSG`
//! echoed back, and **a user who sends a file and sees nothing at all has no
//! way to tell "sent" from "lost"**.
//!
//! ⛔ **The sequence is fixed by the spec and every step is a message**, which
//! is why this is a state machine rather than a helper:
//!
//! ```text
//! client → CAP LS 302
//! server → CAP * LS :multi-prefix sasl
//! client → CAP REQ :multi-prefix          (or REQ :-multiprefix)
//! server → CAP * ACK :multi-prefix
//! client → NICK …
//! client → USER …
//! client → CAP END                        ← only after 001
//! ```
//!
//! ⛔ **`CAP END` may not be sent before `001`.** IRCv3 §4 says registration is
//! incomplete until `CAP END`, and a client that sends it immediately — before
//! the server's welcome — races the server's own state and is answered with
//! `ERR_NEEDMOREPARAMS` or silently ignored, ⛔ on some servers and not on
//! others. So [`Negotiation`] refuses to produce `CAP END` until
//! [`Negotiation::observe`] has seen `001`, and [`Negotiation::on_registration`]
//! is the only thing that unblocks it.
//!
//! ⛔ **`sasl` is never requested.** podssh's IRC leg authenticates nothing, and
//! a client that advertises a mechanism it cannot complete gets a server that
//! waits for credentials it will never receive.

use crate::irc::message::{CapVerb, Command, Middle, Message, Trailing};

/// ⛔ What negotiation is currently doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Stage {
    /// ⛔ The state before anything is sent. ⛔ **`Default` is `Start`
    /// deliberately**, so a `Negotiation` built by `Default` is a negotiation
    /// that has not sent anything.
    #[default]
    /// ⛔ Nothing sent yet.
    Start,
    /// ⛔ `CAP LS` sent, waiting for the server's list.
    LsSent,
    /// ⛔ `CAP REQ` sent, waiting for `ACK` or `NAK`.
    ReqSent,
    /// ⛔ Waiting for `001` before `CAP END` may be written.
    AwaitingWelcome,
    /// ⛔ `CAP END` written; registration is ordinary IRC from here.
    Ended,
}

/// ⛔ What the server advertised, and what was actually agreed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Negotiation {
    stage: Stage,
    /// ⛔ **The server's list, minus the ones podssh refuses.** ⛔ `sasl` is
    /// removed here rather than in the `REQ`, ⛔ because a capability that was
    /// never acknowledged is a capability the client must not believe it has.
    offered: Vec<String>,
    requested: Vec<String>,
    enabled: Vec<String>,
    /// ⛔ Capabilities the server `NAK`ed, kept so a reconnect does not ask
    /// again. ⛔ **A server that refused `multi-prefix` once will refuse it
    /// again**, and asking twice is how a client ends up in a `CAP` loop it
    /// never leaves.
    refused: Vec<String>,
}

impl Negotiation {
    pub fn new() -> Self {
        Negotiation { stage: Stage::Start, ..Default::default() }
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// ⛔ What the server actually granted, sorted. ⛔ **The server's `ACK` is
    /// the only authority**, never the client's request — a client that
    /// assumed its request succeeded would enable `multi-prefix` on a server
    /// that refused it and mis-parse every `353` it receives.
    pub fn enabled(&self) -> &[String] {
        &self.enabled
    }

    pub fn offered(&self) -> &[String] {
        &self.offered
    }

    pub fn refused(&self) -> &[String] {
        &self.refused
    }

    /// ⛔ **The `CAP LS` to send on connect.** ⛔ **This is the same message on
    /// every connection, including a reconnect**, ⛔ which is the one thing the
    /// entry's reconnect clause is easy to get wrong: a client that skips
    /// `CAP` on reconnect silently loses `self-message`, so file transfers
    /// stop echoing and the user sees nothing happen.
    pub fn cap_ls(&mut self) -> Message {
        self.stage = Stage::LsSent;
        cap_message(CapVerb::Ls, &[Middle("302".to_string())], None)
    }

    /// ⛔ **Observe a `CAP` from the server**, and return whatever podssh must
    /// send next. ⛔ **`None` means "send nothing"**, which is a real answer and
    /// not an absence: the common case is a server replying `ACK` to a request
    /// podssh has already made.
    pub fn observe(&mut self, command: &Command) -> Option<Message> {
        let (verb, names) = cap_parts(command)?;
        match verb {
            CapVerb::Ls => {
                // ⛔ **THE FILTER, and it is the point of the whole module.**
                // `sasl` is dropped, and `requested` is *not* built here: it is
                // built by [`Negotiation::request_message`] after the caller has
                // decided what it wants, so a negotiation that changes its mind
                // mid-stream cannot leave a half-built request behind.
                self.offered = names
                    .into_iter()
                    .filter(|n| !n.eq_ignore_ascii_case("sasl"))
                    .collect();
                self.offered.sort();
                self.offered.dedup();
                Some(self.request_message())
            }
            CapVerb::Ack => {
                for name in names {
                    if !self.enabled.iter().any(|e| e.eq_ignore_ascii_case(&name)) {
                        self.enabled.push(name);
                    }
                }
                self.enabled.sort();
                self.stage = Stage::AwaitingWelcome;
                None
            }
            CapVerb::Nak => {
                for name in names {
                    if !self.refused.iter().any(|e| e.eq_ignore_ascii_case(&name)) {
                        self.refused.push(name);
                    }
                }
                self.refused.sort();
                self.stage = Stage::AwaitingWelcome;
                None
            }
            // ⛔ A `CAP LS` arriving *after* registration is legal: it is how a
            // server introduces a capability it added while the client was
            // connected. ⛔ **Answering with `REQ` again would re-open
            // negotiation and require a second `CAP END`**, which RFC 2812 has
            // no slot for. So a late `LS` is recorded and nothing is sent.
            CapVerb::New => {
                for name in names {
                    if !self.offered.iter().any(|o| o.eq_ignore_ascii_case(&name)) {
                        self.offered.push(name);
                    }
                }
                self.offered.sort();
                None
            }
            // ⛔ `CAP END` from the server is not a thing; and `DEL` arrives
            // from a *server* telling a *client* to drop a capability, which
            // podssh honours by forgetting it rather than by replying.
            CapVerb::Del => {
                self.enabled.retain(|e| !names.iter().any(|n| n.eq_ignore_ascii_case(e)));
                None
            }
            CapVerb::List => None,
            CapVerb::Req | CapVerb::End | CapVerb::Unknown => None,
        }
    }

    /// ⛔ **`CAP REQ` for everything worth having.** ⛔ Refused capabilities are
    /// excluded, ⛔ so a reconnect does not re-request what the server has
    /// already refused — which is the second half of why
    /// [`Negotiation::observe`] records a `NAK`.
    fn request_message(&mut self) -> Message {
        let wanted: Vec<String> = self
            .offered
            .iter()
            .filter(|o| !self.refused.iter().any(|r| r.eq_ignore_ascii_case(o)))
            .cloned()
            .collect();
        self.requested = wanted.clone();
        self.stage = Stage::ReqSent;
        cap_message(CapVerb::Req, &[], Some(Trailing::new(wanted.join(" "))))
    }

    /// ⛔ **`001` arrived.** ⛔ **This is the only thing that makes `CAP END`
    /// legal**, and it is a separate call rather than a flag read by the
    /// encoder, ⛔ because the encoder has no way to know whether the welcome
    /// has been seen and must not be told to guess.
    pub fn on_registration(&mut self) -> Option<Message> {
        if self.stage == Stage::Ended {
            return None;
        }
        self.stage = Stage::Ended;
        Some(cap_message(CapVerb::End, &[], None))
    }

    /// ⛔ Reset for a fresh connection, ⛔ **keeping what the server refused** —
    /// see [`Negotiation::refused`]. Used by reconnect.
    pub fn reconnect(&mut self) -> Message {
        let refused = std::mem::take(&mut self.refused);
        let mut next = Negotiation::new();
        next.refused = refused;
        next.stage = Stage::Start;
        *self = next;
        self.cap_ls()
    }
}

fn cap_message(verb: CapVerb, args: &[Middle], trailing: Option<Trailing>) -> Message {
    Message {
        tags: Vec::new(),
        prefix: None,
        command: Command::Cap {
            // ⛔ **A client sends no target.** ⛔ `CAP LS 302` and
            // `CAP REQ :…` carry no nick, ⛔ and the server fills in its own
            // when it answers.
            target: None,
            subcommand: verb,
            args: args.to_vec(),
            trailing,
        },
    }
}

pub fn verb_name(verb: CapVerb) -> &'static str {
    match verb {
        CapVerb::Ls => "LS",
        CapVerb::Req => "REQ",
        CapVerb::Ack => "ACK",
        CapVerb::Nak => "NAK",
        CapVerb::List => "LIST",
        CapVerb::Del => "DEL",
        CapVerb::New => "NEW",
        CapVerb::End => "END",
        CapVerb::Unknown => "?",
    }
}

/// ⛔ Pull the verb and the capability names out of a `CAP`, whatever field they
/// arrived in. ⛔ **`CAP * LS :a b` puts the names in the trailing while
/// `CAP REQ :a b` puts them there too and `CAP ACK a b` puts them in middles**,
/// so both are read and a client that read only one parses half of what a
/// server sends.
fn cap_parts(command: &Command) -> Option<(CapVerb, Vec<String>)> {
    let Command::Cap { subcommand, args, trailing, .. } = command else {
        return None;
    };
    let mut names: Vec<String> = args.iter().map(|a| a.0.clone()).collect();
    if let Some(trailing) = trailing {
        names.extend(trailing.as_str().split_whitespace().map(|s| s.to_string()));
    }
    Some((*subcommand, names))
}
