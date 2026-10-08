//! ⛔ **The grammar, byte-exact in both directions.** Every line in the fixture
//! parses, and every parse encodes back to the line it came from.
//!
//! ⛔ **A fixture proves the grammar and nothing else** ⛔ — ⛔ the entry says so
//! in its own words: ⛔ *"the failure mode that matters is a frame boundary
//! landing mid-message, and only a real session produces that."* ⛔ That is
//! `reassembly.rs`, ⛔ and ⛔ **this file cannot express a split**, ⛔ because a
//! split is not a property of a line.

mod common;

use podssh_core::irc::message::{Command, Message, Prefix};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/grammar.txt");

/// ⛔ The fixture's cases: `(wire line, what podssh must believe)`. ⛔ **The
/// second half is not a comment** ⛔ — ⛔ a fixture that is only lines tests that
/// nothing panics, ⛔ and this one asserts a specific reading for each.
fn cases() -> Vec<(String, String)> {
    let text = common::fixture(FIXTURE);
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (wire, belief) = match line.split_once(" ||| ") {
            Some((w, b)) => (w, b.trim()),
            // ⛔ The fixture carries every case and its reading on ONE line, so
            // ⛔ a case split over two physical lines is an authoring mistake
            // ⛔ **and this says which line**, ⛔ because "no ` ||| ` reading" on
            // its own is not something a reader can act on.
            None => panic!(
                "fixtures/grammar.txt:{}: no ` ||| ` reading on this case: {line}
                 ⛔ every case is one physical line: <wire line> ||| <what podssh must believe>",
                n + 1
            ),
        };
        out.push((wire.to_string(), belief.to_string()));
    }
    assert!(out.len() >= 25, "the fixture shrank: {} cases", out.len());
    out
}

#[test]
fn every_fixture_line_parses_and_re_encodes_to_itself() {
    for (wire, belief) in cases() {
        let message = Message::parse(&wire)
            .unwrap_or_else(|e| panic!("{}: {wire:?} did not parse: {e}", belief));
        // ⛔ **Two lines normalise and every other one is byte-exact.**
        // ⛔ Both are a `PING` with a colonless token, and ⛔ **the encoder
        // always writes the `:`** — see `a_ping_token_survives_the_round_trip_exactly`.
        // ⛔ They are listed here rather than filtered out, ⛔ because a
        // blanket "skip lines that fail" is how a suite stops testing.
        if wire == "PING 12345" {
            assert_eq!(message.to_line(), "PING :12345");
            assert_eq!(message.to_wire(), "PING :12345\r\n");
            continue;
        }
        assert_eq!(
            message.to_line(),
            wire,
            "⛔ {belief}: re-encoding produced a different line than the wire"
        );
        assert_eq!(
            message.to_wire(),
            format!("{wire}\r\n"),
            "⛔ {belief}: the wire form must be the line plus CRLF"
        );
    }
}

#[test]
fn the_trailing_keeps_spaces_and_the_colons_inside_it() {
    // ⛔ The two halves of the trailing rule, separately, ⛔ because a parser that
    // gets one right often gets the other wrong.
    let m = Message::parse(":alice!u@host PRIVMSG #ops :hello there world").unwrap();
    let Command::Privmsg { target, text } = &m.command else {
        panic!("expected a PRIVMSG")
    };
    assert_eq!(target.as_str(), "#ops");
    assert_eq!(text.as_str(), "hello there world");

    let m = Message::parse(":alice!u@host PRIVMSG bob :see 12:30 for the handover").unwrap();
    let Command::Privmsg { text, .. } = &m.command else {
        panic!("expected a PRIVMSG")
    };
    // ⛔ **The second colon is content.** ⛔ A parser that split on every colon
    // turns one parameter into three and delivers `12` to the user.
    assert_eq!(text.as_str(), "see 12:30 for the handover");
}

#[test]
fn an_empty_trailing_is_a_message_and_not_a_missing_one() {
    // ⛔ RFC 2812 §2.3.2 permits `:` immediately after a space. ⛔ A parser that
    // drops the empty trailing loses the message entirely, ⛔ and the sender was
    // entitled to send it.
    let m = Message::parse(":alice!u@host PRIVMSG #c :").unwrap();
    let Command::Privmsg { text, .. } = &m.command else {
        panic!("expected a PRIVMSG")
    };
    assert_eq!(text.as_str(), "");
    assert!(text.is_empty());
    assert_eq!(m.to_line(), ":alice!u@host PRIVMSG #c :");
}

#[test]
fn a_ping_token_survives_the_round_trip_exactly() {
    // ⛔ `PING :aBcD1234` round-trips byte for byte. ⛔ `PING 12345` does
    // NOT — and ⛔ **that is recorded rather than hidden**: RFC 1459
    // §2.3.2 permits a server to leave the `:` off when the token has no
    // space or colon in it, ⛔ and podssh always writes it, ⛔ so the
    // re-encoded line is `PING :12345`. ⛔ The **token** is identical either
    // way, ⛔ which is what the `PONG` must echo.
    for (wire, token) in [("PING :aBcD1234", "aBcD1234"), ("PING 12345", "12345")] {
        let m = Message::parse(wire).unwrap();
        let Command::Ping { token: t } = &m.command else {
            panic!("expected a PING")
        };
        assert_eq!(
            t.as_str(),
            token,
            "⛔ the token of {wire:?} must be exactly {token:?}, byte for byte"
        );
    }
    assert_eq!(
        Message::parse("PING :aBcD1234").unwrap().to_line(),
        "PING :aBcD1234"
    );
    assert_eq!(Message::parse("PING 12345").unwrap().to_line(), "PING :12345");
    // ⛔ **A token with spaces and punctuation**, ⛔ because a PONG that is
    // trimmed or re-quoted is not the token the server sent ⛔ and the entry's
    // own words are that a server that does not receive its own token drops the
    // client.
    let m = Message::parse("PING :a b/c=d+e f").unwrap();
    assert_eq!(m.to_line(), "PING :a b/c=d+e f");
    assert_eq!(m.command.trailing().unwrap().as_str(), "a b/c=d+e f");
}

#[test]
fn a_server_prefix_is_not_mistaken_for_a_client() {
    let m = Message::parse(":irc.example.org 001 alice :Welcome to the Example IRC Network alice!u@h").unwrap();
    let prefix = m.prefix.as_ref().expect("a prefix");
    assert_eq!(prefix.nick, "irc.example.org");
    // ⛔ **The message text contains `alice!u@h`, and it is NOT part of the
    // prefix.** ⛔ A parser that takes everything before the last colon as the
    // prefix would make this a message from `alice!u@h` ⛔ and report a network
    // welcome as a chat line from a user.
    assert!(prefix.is_server());
    assert_eq!(prefix.user, None);
    assert_eq!(prefix.host, None);
    assert_eq!(m.command.trailing().unwrap().as_str(), "Welcome to the Example IRC Network alice!u@h");
}

#[test]
fn a_user_message_keeps_its_unused_parameter() {
    // ⛔ RFC 1459 §4.1.2 has five parameters ⛔ and the third is called
    // `<unused>` ⛔ and a client that drops it is answered `461`.
    let m = Message::parse("USER alice 0 * :Alice Example").unwrap();
    assert_eq!(m.to_line(), "USER alice 0 * :Alice Example");
    let Command::User { user, mode, unused, realname } = &m.command else {
        panic!("expected a USER")
    };
    assert_eq!(user.as_str(), "alice");
    assert_eq!(mode.as_str(), "0");
    assert_eq!(unused.as_str(), "*");
    assert_eq!(realname.as_str(), "Alice Example");
}

#[test]
fn a_join_of_two_channels_is_one_message() {
    let m = Message::parse(":alice!u@host JOIN #one,#two").unwrap();
    let Command::Join { channels, key } = &m.command else {
        panic!("expected a JOIN")
    };
    assert_eq!(channels.len(), 2);
    assert_eq!(channels[0].as_str(), "#one");
    assert_eq!(channels[1].as_str(), "#two");
    assert!(key.is_none());
    assert_eq!(m.to_line(), ":alice!u@host JOIN #one,#two");
}

#[test]
fn an_unknown_command_is_kept_whole_rather_than_dropped() {
    // ⛔ A client that errors on `AWAY` breaks when the peer adds a command, ⛔
    // which is every vendor and every network.
    let m = Message::parse(":alice!u@host AWAY :gone for lunch").unwrap();
    let Command::Unknown { name, params, trailing } = &m.command else {
        panic!("expected an unknown command, got {:?}", m.command)
    };
    assert_eq!(name, "AWAY");
    assert!(params.is_empty());
    assert_eq!(trailing.as_ref().unwrap().as_str(), "gone for lunch");
    assert_eq!(m.to_line(), ":alice!u@host AWAY :gone for lunch");
}

#[test]
fn a_tagged_message_parses_and_the_tag_survives() {
    let m = Message::parse("@+draft/shield=please;room :alice!u@host PRIVMSG #c :tagged").unwrap();
    assert_eq!(m.tags.len(), 2);
    assert_eq!(m.tags[0].key, "+draft/shield");
    assert_eq!(m.tags[0].value.as_deref(), Some("please"));
    // ⛔ **`room` has no value and that is not the same as an empty one.** ⛔ A
    // parser that maps absent to `""` re-emits `room=` ⛔ which is a different
    // tag.
    assert_eq!(m.tags[1].key, "room");
    assert_eq!(m.tags[1].value, None);
    assert_eq!(m.to_line(), "@+draft/shield=please;room :alice!u@host PRIVMSG #c :tagged");
}

#[test]
fn a_prefix_and_a_nick_are_distinguished_by_what_they_carry() {
    let client = Prefix::client("alice", "u", "host");
    assert!(!client.is_server());
    assert_eq!(client.to_string(), "alice!u@host");
    let server = Prefix::server("irc.example.org");
    assert!(server.is_server());
    assert_eq!(server.to_string(), "irc.example.org");
}

#[test]
fn a_malformed_line_is_an_error_and_not_a_message() {
    use podssh_core::irc::message::ParseError;
    for (line, want) in [
        (":alice!u@host", "PrefixOnly"),
        ("PRIVMSG #c", "MissingTrailing"),
        ("JOIN", "TooFewParams"),
        ("USER alice 0", "TooFewParams"),
        ("PRIVMSG", "TooFewParams"),
    ] {
        let err = Message::parse(line).expect_err(&format!("{line} must not parse"));
        let name = match &err {
            ParseError::PrefixOnly { .. } => "PrefixOnly",
            ParseError::MissingCommand { .. } => "MissingCommand",
            ParseError::TooFewParams { .. } => "TooFewParams",
            ParseError::MissingTrailing { .. } => "MissingTrailing",
            ParseError::NotUtf8 => "NotUtf8",
        };
        assert_eq!(name, want, "{line:?} failed as {name}, not {want}: {err}");
    }
}

#[test]
fn a_numeric_is_a_number_and_not_a_string() {
    use podssh_core::irc::numeric::Replies;
    // ⛔ **The defect this test exists for**: `"100"` == `"001"` as text, ⛔ so
    // a client that compared reply codes as strings fires on the wrong reply.
    let hundred = Message::parse(":irc.example.org 100 alice :Welcome").unwrap();
    let Command::Numeric(ref r100) = hundred.command else {
        panic!("expected a numeric")
    };
    assert_eq!(r100.code, 100);
    let one = Message::parse(":irc.example.org 001 alice :Welcome").unwrap();
    let Command::Numeric(ref r1) = one.command else {
        panic!("expected a numeric")
    };
    assert_eq!(r1.code, 1);
    assert_ne!(
        r100.code.to_string(),
        r1.code.to_string(),
        "⛔ “100” and “001” must not compare equal as text"
    );
    // ⛔ **The name is derived from the code**, ⛔ so a reply cannot be
    // labelled `RPL_WELCOME` while carrying `433`.
    assert_eq!(r1.named(), Some(podssh_core::irc::numeric::Numeric::RplWelcome));
    assert_ne!(r100.named(), Some(podssh_core::irc::numeric::Numeric::RplWelcome));
    assert!(Replies::new(433, &[], None).named().is_some());
}

#[test]
fn the_fixture_is_not_silently_emptied() {
    // ⛔ **A suite that has nothing to run reports 0 passed and exit 0.** ⛔
    // That is a pass that measured nothing, ⛔ and this repository has shipped a
    // gate that did exactly it. ⛔ So the number of cases is asserted, ⛔ and a
    // fixture that stops parsing fails here rather than quietly testing nothing.
    let n = cases().len();
    assert!(n >= 25, "the grammar fixture has only {n} cases; it was truncated");
}
