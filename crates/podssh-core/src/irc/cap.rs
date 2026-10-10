//! `CAP LS` / `REQ` / `ACK` / `NAK` / `END` — IRCv3 capability negotiation.
//!
//! **Why podssh negotiates at all.** `CAP` exists so a client and a server
//! can agree on extensions *before* registration. podssh wants one of them:
//! `znc.in/self-message`, without which a client never sees its own `PRIVMSG`
//! echoed back, and **a user who sends a file and sees nothing at all has no
//! way to tell "sent" from "lost"**.
//!
//! **The sequence is fixed by the spec and every step is a message**, which
//! is why this is a state machine rather than a helper:
//!
//! ```text
//! client → CAP LS 302
//! client → NICK …
//! client → USER …
//! server → CAP * LS :multi-prefix sasl
//! client → CAP REQ :multi-prefix
//! server → CAP * ACK :multi-prefix        (or NAK)
//! client → CAP END                        ← the answer to the request
//! server → 001 …
//! ```
//!
//! **`CAP END` comes before `001`, and `001` waits for it.** A server that
//! answers `CAP LS` holds the registration until the client ends the
//! negotiation (IRCv3, "Capability Negotiation"), so a client that waited for
//! `001` first would wait for ever, and the server would close the connection
//! at its registration limit (T-091; measured with ngircd 27, whose `001`
//! comes only after `CAP END`). So `CAP END` answers the server's `ACK` or
//! `NAK` of the request, and goes at once when nothing is wanted. A server
//! with no `CAP` answers `421`, holds nothing, and gets no `CAP END`.
//!
//! **`sasl` is never requested.** podssh's IRC leg authenticates nothing, and
//! a client that advertises a mechanism it cannot complete gets a server that
//! waits for credentials it will never receive.
//!
//! **Only the names of [`WANTED_CAPS`] are requested, without a value** (T-092).
//! With `CAP LS 302` a server sends values (`sasl=PLAIN,EXTERNAL`), and one
//! long list over several lines, each but the last with a `*` before its
//! trailing: ergo 2.18.0 does both. A `REQ` that carries a value, or a name
//! that the server does not offer, is refused whole (measured with ngircd
//! 27, InspIRCd 4.11.0 and ergo 2.18.0), so the request names only offered
//! names, once the last line has come.

use crate::irc::WANTED_CAPS;

use crate::irc::message::{CapVerb, Command, Message, Middle, Trailing};

/// What negotiation is currently doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Stage {
    /// The state before anything is sent. **`Default` is `Start`
    /// deliberately**, so a `Negotiation` built by `Default` is a negotiation
    /// that has not sent anything.
    #[default]
    /// Nothing sent yet.
    Start,
    /// `CAP LS` sent, waiting for the server's list.
    LsSent,
    /// `CAP REQ` sent, waiting for `ACK` or `NAK`.
    ReqSent,
    /// `CAP END` written, or the server has no `CAP`: registration is
    /// ordinary IRC from here.
    Ended,
}

/// What the server advertised, and what was actually agreed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Negotiation {
    stage: Stage,
    /// **The names that the server offers**, from each line of its `LS`, the
    /// values left out: a value is the server's to give, never the client's
    /// to send back.
    offered: Vec<String>,
    requested: Vec<String>,
    enabled: Vec<String>,
    /// Capabilities the server `NAK`ed, kept so a reconnect does not ask
    /// again. **A server that refused `multi-prefix` once will refuse it
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

    /// What the server actually granted, sorted. **The server's `ACK` is
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

    /// **The `CAP LS` to send on connect.** **This is the same message on
    /// every connection, including a reconnect**, which is the one thing the
    /// entry's reconnect clause is easy to get wrong: a client that skips
    /// `CAP` on reconnect silently loses `self-message`, so file transfers
    /// stop echoing and the user sees nothing happen.
    pub fn cap_ls(&mut self) -> Message {
        self.stage = Stage::LsSent;
        cap_message(CapVerb::Ls, &[Middle("302".to_string())], None)
    }

    /// **Observe a `CAP` from the server**, and return whatever podssh must
    /// send next. **`None` means "send nothing"**, which is a real answer and
    /// not an absence: the common case is a server replying `ACK` to a request
    /// podssh has already made, or a line of an `LS` that more lines follow.
    pub fn observe(&mut self, command: &Command) -> Option<Message> {
        let Reply { verb, names, more } = reply(command)?;
        match verb {
            CapVerb::Ls => {
                for name in names {
                    if !self.offered.iter().any(|o| o.eq_ignore_ascii_case(&name)) {
                        self.offered.push(name);
                    }
                }
                self.offered.sort();
                // **One request, after the last line**: a line with the `*`
                // marker is not the end of the list, and an `LS` that comes
                // after the negotiation ended reopens nothing.
                if more || self.stage != Stage::LsSent {
                    return None;
                }
                Some(self.request_message())
            }
            CapVerb::Ack => {
                // **The server's `ACK` is the authority, for the names that
                // were asked for**; `-name` turns one off.
                for name in names {
                    match name.strip_prefix('-') {
                        Some(off) => self.enabled.retain(|e| !e.eq_ignore_ascii_case(off)),
                        None if self.requested.iter().any(|r| r.eq_ignore_ascii_case(&name))
                            && !self.enabled.iter().any(|e| e.eq_ignore_ascii_case(&name)) =>
                        {
                            self.enabled.push(name)
                        }
                        None => {}
                    }
                }
                self.enabled.sort();
                self.end()
            }
            CapVerb::Nak => {
                for name in names {
                    if !self.refused.iter().any(|e| e.eq_ignore_ascii_case(&name)) {
                        self.refused.push(name);
                    }
                }
                self.refused.sort();
                self.end()
            }
            // `CAP NEW` and `CAP DEL` come to a client that has `cap-notify`,
            // which `CAP LS 302` turns on by itself (IRCv3): a server says so
            // when it adds or takes away a capability while the client is
            // connected. A new one is recorded, and nothing is sent: podssh
            // asks only during registration.
            CapVerb::New => {
                for name in names {
                    if !self.offered.iter().any(|o| o.eq_ignore_ascii_case(&name)) {
                        self.offered.push(name);
                    }
                }
                self.offered.sort();
                None
            }
            // `CAP END` from the server is not a thing; and `DEL` arrives
            // from a *server* telling a *client* to drop a capability, which
            // podssh honours by forgetting it rather than by replying.
            CapVerb::Del => {
                self.enabled.retain(|e| !names.iter().any(|n| n.eq_ignore_ascii_case(e)));
                self.offered.retain(|o| !names.iter().any(|n| n.eq_ignore_ascii_case(o)));
                None
            }
            CapVerb::List => None,
            CapVerb::Req | CapVerb::End | CapVerb::Unknown => None,
        }
    }

    /// **`CAP REQ` for each name of [`WANTED_CAPS`] that the server offers**,
    /// or `CAP END` at once when that is none: an empty request would wait
    /// for an answer that ends nothing. Refused capabilities are excluded, so
    /// a reconnect does not re-request what the server has already refused —
    /// which is the second half of why [`Negotiation::observe`] records a
    /// `NAK`.
    fn request_message(&mut self) -> Message {
        let wanted: Vec<String> = WANTED_CAPS
            .iter()
            .filter(|w| self.offered.iter().any(|o| o.eq_ignore_ascii_case(w)))
            .filter(|w| !self.refused.iter().any(|r| r.eq_ignore_ascii_case(w)))
            .map(|w| w.to_string())
            .collect();
        if wanted.is_empty() {
            self.stage = Stage::Ended;
            return cap_message(CapVerb::End, &[], None);
        }
        self.requested = wanted.clone();
        self.stage = Stage::ReqSent;
        cap_message(CapVerb::Req, &[], Some(Trailing::new(wanted.join(" "))))
    }

    /// **The answer to the request ends the negotiation**: `CAP END`, once.
    /// An `ACK` or `NAK` that answers no request of this negotiation (a later
    /// one) ends nothing.
    fn end(&mut self) -> Option<Message> {
        if self.stage != Stage::ReqSent {
            return None;
        }
        self.stage = Stage::Ended;
        Some(cap_message(CapVerb::End, &[], None))
    }

    /// **The server has no `CAP`**: it answered `CAP LS` with `421`, so it
    /// holds no registration, and no `CAP END` is due.
    pub fn unsupported(&mut self) {
        self.stage = Stage::Ended;
    }

    /// Reset for a fresh connection, **keeping what the server refused** —
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
            // **A client sends no target.** `CAP LS 302` and
            // `CAP REQ :…` carry no nick, and the server fills in its own
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

/// What a `CAP` from the server says: its verb, the names of its last
/// parameter, and whether more lines of the same list follow.
struct Reply {
    verb: CapVerb,
    names: Vec<String>,
    more: bool,
}

/// **The names are the last parameter, as a trailing or as a middle**:
/// `CAP * LS :a b`, `CAP * ACK :a b` and ergo's `CAP * ACK echo-message`.
/// Each is `name[=value]`, and the value is left out. **A `*` before the
/// last parameter of an `LS` or a `LIST` says that more lines follow**, and
/// is no name: ergo 2.18.0 sends `CAP * LS * :…` and then `CAP * LS :…`.
fn reply(command: &Command) -> Option<Reply> {
    let Command::Cap { subcommand, args, trailing, .. } = command else {
        return None;
    };
    let mut params: Vec<&str> = args.iter().map(|a| a.0.as_str()).collect();
    if let Some(trailing) = trailing {
        params.push(trailing.as_str());
    }
    let last = params.pop().unwrap_or_default();
    let more = matches!(subcommand, CapVerb::Ls | CapVerb::List) && params.last() == Some(&"*");
    let names = last.split_whitespace().map(|token| token.split('=').next().unwrap_or(token).to_string()).collect();
    Some(Reply { verb: *subcommand, names, more })
}
