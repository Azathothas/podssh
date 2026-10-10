//! How a [`Command`] presents itself to the encoder.
//!
//! **Split out of `message.rs`, which went over the 500-line gate with it
//! in**, and split rather than trimmed — the reasoning on those arms is
//! where four defects were caught on the first run, and deleting it would
//! delete the reason they cannot recur.
//!
//! **`Command::Numeric`'s parameters live on its [`crate::irc::numeric::Replies`]**, so this
//! file asks the reply rather than enumerating reply shapes. MEASURED
//! 2026-10-02: with a bare `Numeric(u16)` the fixture round-trip re-encoded
//! `:irc.example.org 001 alice :Welcome` as `:irc.example.org 1`.

use crate::irc::message::{Command, Middle, Trailing};

impl Command {
    /// **The parameters of a message, in wire order, for encoding.**
    ///
    /// **A numeric's parameters come from its [`crate::irc::numeric::Replies`], not from a match
    /// arm that enumerates reply shapes** — `001 <me> :Welcome` and
    /// `353 <me> = #chan :nick nick2` have different shapes and the same
    /// grammar, so the shape is data on the reply and not code here.
    pub fn params(&self) -> Vec<Middle> {
        match self {
            Command::Numeric(reply) => reply.all_params(),
            Command::Privmsg { target, .. } | Command::Notice { target, .. } => {
                vec![target.clone()]
            }
            Command::Join { channels, key, .. } => {
                // RFC 2812 §4.2.1 writes the channels comma-separated and the
                // key list after a comma too, so re-encoding one JOIN produces
                // one JOIN and not two.
                let mut out: Vec<Middle> = Vec::new();
                let joined: Vec<String> = channels.iter().map(|c| c.0.clone()).collect();
                out.push(Middle(joined.join(",")));
                if let Some(key) = key {
                    out.push(Middle(key.clone()));
                }
                out
            }
            Command::Part { channels, .. } => {
                let joined: Vec<String> = channels.iter().map(|c| c.0.clone()).collect();
                vec![Middle(joined.join(","))]
            }
            Command::Topic { channel, .. } => vec![channel.clone()],
            Command::Names { channels } | Command::List { channels } => channels.clone(),
            Command::Mode { target, flags, .. } => {
                let mut out = vec![target.clone()];
                out.extend(flags.iter().cloned());
                out
            }
            Command::Quit { .. } => Vec::new(),
            // `PING`'s token is written as the **trailing**, never as a
            // middle, so it carries its `:` on the wire. A token with a space in
            // it is legal and must survive that round trip whole.
            Command::Ping { .. } => Vec::new(),
            // **The verb is written back as a parameter.** `Command::name`
            // supplies it from `CapVerb`, so `args` holds only the
            // parameters *beside* the verb — and the target `*` is one
            // of them. MEASURED 2026-10-02: with `*` folded into the verb
            // position the fixture round-trip re-encoded `CAP * LS :…` as
            // `CAP * :…`, **the whole capability list with no verb to
            // interpret it**.
            // **`CAP` writes target, then verb, then args** — and the
            // target is not an arg, because on a server's `CAP * LS` it
            // comes *before* the verb. MEASURED 2026-10-02: with the `*`
            // as an ordinary parameter the fixture round-trip re-encoded
            // `CAP * LS :…` as `CAP LS * :…`.
            Command::Cap { target, subcommand, args, .. } => {
                let mut out = Vec::new();
                if let Some(t) = target {
                    out.push(t.clone());
                }
                out.push(Middle(crate::irc::cap::verb_name(*subcommand).to_string()));
                out.extend(args.iter().cloned());
                out
            }
            // **A `PONG`'s token is the trailing, not a middle** — it
            // answers a `PING`, and a `PING`'s token is the trailing.
            // Writing it as a middle as well turns `PONG :aBcD1234` into
            // `PONG aBcD1234`. A server's answer names the server first.
            Command::Pong { server, .. } => server.iter().cloned().collect(),
            Command::Nick { nickname, .. } => vec![nickname.clone()],
            Command::User { user, mode, unused, .. } => {
                vec![user.clone(), mode.clone(), unused.clone()]
            }
            Command::Unknown { params, .. } => params.clone(),
        }
    }

    /// **Whether the last parameter is written with its `:`** where it sits
    /// in a middle field: see `colon` on [`Command::Join`]. A trailing field
    /// keeps its own (see [`Trailing`]).
    pub fn last_colon(&self) -> bool {
        match self {
            Command::Join { colon, .. }
            | Command::Part { colon, .. }
            | Command::Mode { colon, .. }
            | Command::Nick { colon, .. } => *colon,
            _ => false,
        }
    }

    /// **The trailing parameter, if this command has one and it was present.**
    ///
    /// **This is the single accessor, and there is no second one.** An earlier
    /// draft matched `Part`/`Topic`/`Quit`/`Mode` in one arm and returned `None`
    /// for all of them while a private `trailing_of` returned the value — two
    /// functions answering the same question differently, which is how an
    /// encoder ends up dropping half the trailing parameters it parses.
    pub fn trailing(&self) -> Option<&Trailing> {
        trailing_of(self)
    }

    /// The uppercase spelling, for logs and for the tests that compare a
    /// parse against the line it came from.
    pub fn name(&self) -> String {
        match self {
            // `{:03}`, so `1` is `001`. A code over 999 has no legal
            // three-digit spelling; it is printed as four digits rather than
            // silently wrapped, because a wrapped code would name a different
            // reply.
            Command::Numeric(reply) => format!("{:03}", reply.code),
            Command::Privmsg { .. } => "PRIVMSG".into(),
            Command::Notice { .. } => "NOTICE".into(),
            Command::Join { .. } => "JOIN".into(),
            Command::Part { .. } => "PART".into(),
            Command::Topic { .. } => "TOPIC".into(),
            Command::Names { .. } => "NAMES".into(),
            Command::List { .. } => "LIST".into(),
            Command::Mode { .. } => "MODE".into(),
            Command::Quit { .. } => "QUIT".into(),
            Command::Ping { .. } => "PING".into(),
            Command::Pong { .. } => "PONG".into(),
            Command::Nick { .. } => "NICK".into(),
            Command::User { .. } => "USER".into(),
            Command::Cap { .. } => "CAP".into(),
            Command::Unknown { name, .. } => name.clone(),
        }
    }
}

pub(crate) fn trailing_of(command: &Command) -> Option<&Trailing> {
    match command {
        Command::Privmsg { text, .. } | Command::Notice { text, .. } => Some(text),
        Command::Ping { token } => Some(token),
        Command::Part { reason, .. } => reason.as_ref(),
        Command::Topic { topic, .. } => topic.as_ref(),
        Command::Quit { reason, .. } => reason.as_ref(),
        Command::User { realname, .. } => Some(realname),
        // **A `PONG` is written from its trailing, like every other
        // command**, so the token arrives with its `:` and is echoed byte for
        // byte. This is the whole of the entry's PING/PONG plant.
        Command::Pong { token, .. } => token.as_ref(),
        Command::Cap { trailing, .. } => trailing.as_ref(),
        Command::Unknown { trailing, .. } => trailing.as_ref(),
        // A numeric's text lives on its `Replies`. Returning it from
        // the one accessor is what stops a caller reaching past the enum and
        // reading it in two places.
        Command::Numeric(reply) => reply.text.as_ref(),
        _ => None,
    }
}
