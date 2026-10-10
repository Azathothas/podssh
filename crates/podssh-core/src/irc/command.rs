//! The command table: a parameter list ⇄ a [`Command`].
//!
//! **Split out of `message.rs` because that file went over the 500-line gate
//! with it in**, and **not by deleting its comments to fit** — the comments
//! are where the protocol decisions live, and a file that only fits because its
//! reasoning was removed is a file that loses it on the next edit.
//!
//! **Two shapes of grammar, and the difference is the point.**
//!
//! * A **fixed-arity** command — `PRIVMSG <target> :<text>`, `USER` — takes its
//!   fields by name, and a message with too few parameters is a
//!   [`ParseError::TooFewParams`] naming how many the grammar needs. The
//!   number is the command's arity, written here once.
//! * A **variable-arity** command — `CAP`, anything unknown — keeps its
//!   parameters as a list. Flattening those into a tuple would mean picking
//!   an arity, and the arity belongs to the peer, not to podssh.
//!
//! **Each field is read by its place in one list**: the middles, then the
//! trailing. The last parameter comes with or without its `:`, as each
//! server chooses: measured on 2026-10-10, ngircd 27 and InspIRCd 4 write
//! `JOIN :#t` and `NICK :pa2`, and ergo 2.18 writes `JOIN #t`, `PART #t bye`
//! and `QUIT Quit`. A parser that wants a middle here and a trailing there
//! drops one server's lines, or reads a reason as a channel. A known command
//! with more parameters than its grammar is kept whole, as `Unknown`, so no
//! field reads a parameter that is not its own.

use crate::irc::message::{CapVerb, Command, Middle, ParseError, Trailing};

/// Parse the command half of a message, **given its parameters already split**
/// by [`crate::irc::message::split_params`].
/// **`trailing` is `(value, colon)`**, because whether the wire wrote
/// the introducing `:` is a property of the line and both spellings occur on
/// a real server — see [`crate::irc::message::Trailing`].
pub fn parse_command(params: Vec<String>, trailing: Option<(String, bool)>) -> Result<Command, ParseError> {
    let name = params.first().cloned().unwrap_or_default();
    let middles: Vec<Middle> = params[1..].iter().map(|p| Middle(p.clone())).collect();
    let trail = trailing.map(|(value, colon)| Trailing::as_written(value, colon));
    let all: Vec<Trailing> =
        middles.iter().map(|m| Trailing::as_written(m.0.clone(), false)).chain(trail.clone()).collect();
    // The last parameter came with its `:`; a middle field keeps that here.
    let colon = trail.as_ref().is_some_and(|t| t.colon);
    let middle = |i: usize| -> Middle { Middle(all.get(i).map(|t| t.value.clone()).unwrap_or_default()) };
    let arity = |need: usize| -> Result<(), ParseError> {
        if all.len() < need {
            Err(ParseError::TooFewParams { command: name.clone(), need, got: all.len() })
        } else {
            Ok(())
        }
    };
    // RFC 2812 §4.2.1: `JOIN <channel>{,<channel>} [,<key>]`. One JOIN
    // carries every channel the client joins at once, and splitting on ','
    // here means a client asking for ten channels sends one message rather
    // than ten. `PART` writes its channels the same way.
    let channels = |i: usize| -> Vec<Middle> {
        all.get(i)
            .map(|t| t.value.split(',').filter(|s| !s.is_empty()).map(|c| Middle(c.to_string())).collect())
            .unwrap_or_default()
    };
    let whole = Command::Unknown { name: name.clone(), params: middles.clone(), trailing: trail.clone() };

    Ok(match name.as_str() {
        "PRIVMSG" | "NOTICE" => {
            arity(1)?;
            if all.len() > 2 {
                return Ok(whole);
            }
            // No server measured writes the text without its `:`, and a
            // client may: the text is the second parameter either way.
            let text = all.get(1).cloned().ok_or_else(|| ParseError::MissingTrailing { command: name.clone() })?;
            if name == "PRIVMSG" {
                Command::Privmsg { target: middle(0), text }
            } else {
                Command::Notice { target: middle(0), text }
            }
        }
        "JOIN" => {
            arity(1)?;
            // A third parameter is `extended-join`'s account and real name,
            // which podssh does not ask for; read as keys, the real name
            // would be a key.
            if all.len() > 2 {
                return Ok(whole);
            }
            Command::Join { channels: channels(0), key: all.get(1).map(|t| t.value.clone()), colon }
        }
        "PART" => {
            arity(1)?;
            if all.len() > 2 {
                return Ok(whole);
            }
            // ergo writes `PART #t bye`: the second parameter is the reason
            // with or without its `:`, never a second channel.
            let reason = all.get(1).cloned();
            Command::Part { channels: channels(0), colon: colon && reason.is_none(), reason }
        }
        "TOPIC" => {
            arity(1)?;
            if all.len() > 2 {
                return Ok(whole);
            }
            Command::Topic { channel: middle(0), topic: all.get(1).cloned() }
        }
        "NAMES" => Command::Names { channels: all.iter().map(|t| Middle(t.value.clone())).collect() },
        "LIST" => Command::List { channels: all.iter().map(|t| Middle(t.value.clone())).collect() },
        "MODE" => {
            arity(1)?;
            // **Mode flags are middles.** RFC 2812 §4.2.2 writes `MODE
            // <channel> {[+|-]|o|p|s|i|t|n|b|v} [limit] [user] [mask]`, and a
            // flag list can be **followed by more middles** — `MODE #c +o
            // alice +v bob`. Taking only the first would drop every flag after
            // the first space. The last may come as the trailing: InspIRCd
            // writes `MODE #t +k :secret`, and ngircd `MODE pa2 :+i`.
            Command::Mode {
                target: middle(0),
                flags: all[1..].iter().map(|t| Middle(t.value.clone())).collect(),
                colon,
            }
        }
        "QUIT" => {
            if all.len() > 1 {
                return Ok(whole);
            }
            // ergo writes `QUIT Quit`.
            Command::Quit { reason: all.first().cloned() }
        }
        "PING" => {
            // **The token is a trailing and nothing else.** RFC 2812 §2.3.2
            // allows `PING <server1> [<server2>]` with *no* trailing, and a
            // server that sends `PING` bare is legal. The fallback joins the
            // middles with a single space rather than taking only the first,
            // because a token containing a space must be echoed whole or the
            // peer will not recognise it — and a token that is echoed wrong
            // drops the client.
            let token = match trail {
                Some(t) => t,
                // **A `PING` with no trailing re-encodes WITH one.** RFC 1459
                // §2.3.2 allows the shorter spelling, the token is identical,
                // and the fixture's round trip covers `PING 12345` separately —
                // **a test that asserts every line re-encodes to itself cannot
                // hold for a normalising encoder**, and pretending otherwise is
                // how a test stops testing. See `grammar.rs`.
                None => Trailing::new(middles.iter().map(|m| m.0.clone()).collect::<Vec<_>>().join(" ")),
            };
            Command::Ping { token }
        }
        "PONG" => {
            if all.len() > 2 {
                return Ok(whole);
            }
            // The token is the last parameter; a server's answer names the
            // server before it.
            let server = (all.len() == 2).then(|| middle(0));
            Command::Pong { server, token: all.last().cloned() }
        }
        "NICK" => {
            arity(1)?;
            if all.len() > 1 {
                return Ok(whole);
            }
            Command::Nick { nickname: middle(0), colon }
        }
        "USER" => {
            // RFC 1459 §4.1.2: `USER <user> <mode> <unused> :<realname>`.
            // `<unused>` is genuinely unused — RFC 2812 still calls it that —
            // and a client that omits it sends four parameters where the
            // grammar needs five, which some servers answer with
            // `ERR_NEEDMOREPARAMS` during registration and nothing else.
            arity(3)?;
            if all.len() > 4 {
                return Ok(whole);
            }
            let realname = all.get(3).cloned().ok_or_else(|| ParseError::MissingTrailing { command: name.clone() })?;
            Command::User { user: middle(0), mode: middle(1), unused: middle(2), realname }
        }
        "CAP" => {
            // **`CAP * <verb>` keeps its `*`, and that is a fact about the
            // grammar rather than about negotiation.** RFC 2812 §3.2
            // writes `CAP <nick> <subcmd>`, and a server has no nick to
            // address — it sends `CAP * LS :…`, with `*` where the
            // client's nick would be. **Dropping it and calling `*` the
            // verb** is what a first reading does, and the result is a
            // `CAP` whose subcommand is `Unknown` — MEASURED 2026-10-02:
            // the fixture round-trip re-encoded `CAP * LS :multi-prefix` as
            // `CAP LS :multi-prefix`. Every capability a server offers
            // arrives this way, so the bug is not an edge case.
            //
            // The `*` is kept as the first **arg** and
            // [`CapVerb`](crate::irc::message::CapVerb) stays a verb. Once
            // the client has a nick, a server names it there instead:
            // ngircd answers `CAP podtest ACK :multi-prefix` (T-091, T-094).
            // So the first is the target when the second is a verb; a
            // client's own `CAP` starts with its verb.
            let verb_at = |i: usize| {
                middles.get(i).is_some_and(|m| {
                    matches!(m.0.as_str(), "LS" | "REQ" | "ACK" | "NAK" | "LIST" | "DEL" | "NEW" | "END")
                })
            };
            let (target, rest) = if middles.first().map(|m| m.0.as_str()) == Some("*") || verb_at(1) {
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
                // Anything else is preserved, not an error: a peer
                // that invents a subcommand must not make the client silent.
                _ => CapVerb::Unknown,
            };
            Command::Cap { target, subcommand: sub, args: rest[1.min(rest.len())..].to_vec(), trailing: trail }
        }
        // **Three digits, and only digits.** `numeric` is checked as a
        // number rather than as a string because `"100"` and `"001"` are equal
        // as text and are different replies.
        _ if name.len() == 3 && name.bytes().all(|b| b.is_ascii_digit()) => {
            let code = name.parse::<u16>().map_err(|_| ParseError::MissingCommand { line: name.clone() })?;
            Command::Numeric(crate::irc::numeric::Replies::new(code, &middles, trail.as_ref()))
        }
        // Anything else is kept whole. An IRC client that errors on `AWAY`, on
        // `ACCOUNT` or on a vendor extension is a client that breaks when the
        // peer adds a command, which is every vendor and every network.
        _ => whole,
    })
}
