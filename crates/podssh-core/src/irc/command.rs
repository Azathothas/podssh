//! The command table: a parameter list ⇄ a [`Command`].
//!
//! ⛔ **Split out of `message.rs` because that file went over the 500-line gate
//! with it in**, and ⛔ **not by deleting its comments to fit** — the comments
//! are where the protocol decisions live, and a file that only fits because its
//! reasoning was removed is a file that loses it on the next edit.
//!
//! ⛔ **Two shapes of grammar, and the difference is the point.**
//!
//! * A **fixed-arity** command — `PRIVMSG <target> :<text>`, `USER` — takes its
//!   fields by name, and a message with too few parameters is a
//!   [`ParseError::TooFewParams`] naming how many the grammar needs. ⛔ The
//!   number is the command's arity, written here once.
//! * A **variable-arity** command — `CAP`, anything unknown — keeps its
//!   parameters as a list. ⛔ Flattening those into a tuple would mean picking
//!   an arity, and the arity belongs to the peer, not to podssh.

use crate::irc::message::{
    CapVerb, Command, Middle, ParseError, Trailing,
};

/// ⛔ Parse the command half of a message, **given its parameters already split**
/// by [`crate::irc::message::split_params`].
/// ⛔ **`trailing` is `(value, colon)`**, ⛔ because whether the wire wrote
/// the introducing `:` is a property of the line and ⛔ both spellings occur on
/// a real server — see [`crate::irc::message::Trailing`].
pub fn parse_command(
    params: Vec<String>,
    trailing: Option<(String, bool)>,
) -> Result<Command, ParseError> {
    let name = params.first().cloned().unwrap_or_default();
    let middles: Vec<Middle> = params[1..].iter().map(|p| Middle(p.clone())).collect();
    let trail = trailing.map(|(value, colon)| Trailing::as_written(value, colon));
    let take_middle = |i: usize| -> Middle {
        middles.get(i).cloned().unwrap_or_else(|| Middle(String::new()))
    };
    let arity = |need: usize| -> Result<(), ParseError> {
        if middles.len() < need {
            Err(ParseError::TooFewParams { command: name.clone(), need, got: middles.len() })
        } else {
            Ok(())
        }
    };

    Ok(match name.as_str() {
        "PRIVMSG" => {
            arity(1)?;
            let text = trail.ok_or_else(|| ParseError::MissingTrailing { command: name.clone() })?;
            Command::Privmsg { target: take_middle(0), text }
        }
        "NOTICE" => {
            arity(1)?;
            let text = trail.ok_or_else(|| ParseError::MissingTrailing { command: name.clone() })?;
            Command::Notice { target: take_middle(0), text }
        }
        "JOIN" => {
            arity(1)?;
            // ⛔ RFC 2812 §4.2.1: `JOIN <channel>{,<channel>} [,<key>]`. One
            // JOIN carries every channel the client joins at once, and splitting
            // on ',' here means a client asking for ten channels sends one
            // message rather than ten.
            let mut channels = Vec::new();
            let mut keys = Vec::new();
            for param in middles[0].0.split(',').filter(|s| !s.is_empty()) {
                channels.push(Middle(param.to_string()));
            }
            if let Some(trail) = trail {
                for key in trail.as_str().split(',').filter(|s| !s.is_empty()) {
                    keys.push(key.to_string());
                }
            }
            Command::Join { channels, key: (!keys.is_empty()).then(|| keys.join(",")) }
        }
        "PART" => {
            arity(1)?;
            let mut channels = Vec::new();
            for param in middles[0].0.split(',').filter(|s| !s.is_empty()) {
                channels.push(Middle(param.to_string()));
            }
            for extra in middles.iter().skip(1) {
                for param in extra.0.split(',').filter(|s| !s.is_empty()) {
                    channels.push(Middle(param.to_string()));
                }
            }
            Command::Part { channels, reason: trail }
        }
        "TOPIC" => {
            arity(1)?;
            Command::Topic { channel: take_middle(0), topic: trail }
        }
        "NAMES" => Command::Names { channels: middles },
        "LIST" => Command::List { channels: middles },
        "MODE" => {
            arity(1)?;
            // ⛔ **Mode flags are middles, never a trailing.** RFC 2812
            // §4.2.2 writes `MODE <channel> {[+|-]|o|p|s|i|t|n|b|v} [limit]
            // [user] [mask]`, and ⛔ a flag list can be **followed by more
            // middles** — `MODE #c +o alice +v bob`. ⛔ Taking only the
            // first would drop every flag after the first space, ⛔ and taking
            // the tail as a trailing would re-emit `+o alice +v bob` with a `:`
            // in front of it, ⛔ which a server parses as one parameter.
            Command::Mode { target: take_middle(0), flags: middles[1..].to_vec() }
        }
        "QUIT" => Command::Quit { reason: trail },
        "PING" => {
            // ⛔ **The token is a trailing and nothing else.** RFC 2812 §2.3.2
            // allows `PING <server1> [<server2>]` with *no* trailing, and a
            // server that sends `PING` bare is legal. ⛔ The fallback joins the
            // middles with a single space rather than taking only the first,
            // because a token containing a space must be echoed whole or the
            // peer will not recognise it — and a token that is echoed wrong
            // drops the client.
            let token = match trail {
                Some(t) => t,
                // ⛔ **A `PING` with no trailing re-encodes WITH one.** ⛔ RFC 1459
                // §2.3.2 allows the shorter spelling, ⛔ the token is identical, ⛔
                // and the fixture's round trip covers `PING 12345` separately — ⛔
                // ⛔ **a test that asserts every line re-encodes to itself cannot
                // hold for a normalising encoder**, and pretending otherwise is
                // how a test stops testing. See `grammar.rs`.
                None => Trailing::new(middles.iter().map(|m| m.0.clone()).collect::<Vec<_>>().join(" ")),
            };
            Command::Ping { token }
        }
        "PONG" => Command::Pong { token: trail },
        "NICK" => {
            arity(1)?;
            Command::Nick { nickname: take_middle(0) }
        }
        "USER" => {
            // ⛔ RFC 1459 §4.1.2: `USER <user> <mode> <unused> :<realname>`.
            // ⛔ `<unused>` is genuinely unused — RFC 2812 still calls it that —
            // and a client that omits it sends four parameters where the
            // grammar needs five, which some servers answer with
            // `ERR_NEEDMOREPARAMS` during registration and nothing else.
            arity(3)?;
            let realname =
                trail.ok_or_else(|| ParseError::MissingTrailing { command: name.clone() })?;
            Command::User {
                user: take_middle(0),
                mode: take_middle(1),
                unused: take_middle(2),
                realname,
            }
        }
        "CAP" => {
            // ⛔ **`CAP * <verb>` keeps its `*`, and that is a fact about the
            // grammar rather than about negotiation.** ⛔ RFC 2812 §3.2
            // writes `CAP <nick> <subcmd>`, ⛔ and a server has no nick to
            // address — ⛔ it sends `CAP * LS :…`, ⛔ with `*` where the
            // client's nick would be. ⛔ **Dropping it and calling `*` the
            // verb** is what a first reading does, ⛔ and the result is a
            // `CAP` whose subcommand is `Unknown` — ⛔ MEASURED 2026-10-02:
            // the fixture round-trip re-encoded `CAP * LS :multi-prefix` as
            // `CAP LS :multi-prefix`. ⛔ Every capability a server offers
            // arrives this way, ⛔ so the bug is not an edge case.
            //
            // ⛔ The `*` is kept as the first **arg** and ⛔
            // [`CapVerb`](crate::irc::message::CapVerb) stays a verb.
            let (target, rest) = if middles.first().map(|m| m.0.as_str()) == Some("*") {
                (Some(middles[0].clone()), &middles[1..])
            } else {
                (None, &middles[..])
            };
            let sub = match rest.first().map(|m| m.0.as_str()) {
                Some("LS") => CapVerb::Ls,
                Some("REQ") => CapVerb::Req,
                Some("ACK") => CapVerb::Ack,
                Some("NAK") => CapVerb::Nak,
                Some("LIST") => CapVerb::List,
                Some("DEL") => CapVerb::Del,
                Some("NEW") => CapVerb::New,
                Some("END") => CapVerb::End,
                // ⛔ Anything else is preserved, ⛔ not an error: ⛔ a peer
                // that invents a subcommand must not make the client silent.
                _ => CapVerb::Unknown,
            };
            Command::Cap {
                target,
                subcommand: sub,
                args: rest[1.min(rest.len())..].to_vec(),
                trailing: trail,
            }
        }
        // ⛔ **Three digits, and only digits.** ⛔ `numeric` is checked as a
        // number rather than as a string because `"100"` and `"001"` are equal
        // as text and are different replies.
        _ if name.len() == 3 && name.bytes().all(|b| b.is_ascii_digit()) => {
            let code = name
                .parse::<u16>()
                .map_err(|_| ParseError::MissingCommand { line: name.clone() })?;
            Command::Numeric(crate::irc::numeric::Replies::new(code, &middles, trail.as_ref()))
        }
        // ⛔ Anything else is kept whole. An IRC client that errors on `AWAY`, on
        // `ACCOUNT` or on a vendor extension is a client that breaks when the
        // peer adds a command, which is every vendor and every network.
        _ => Command::Unknown { name, params: middles, trailing: trail },
    })
}
