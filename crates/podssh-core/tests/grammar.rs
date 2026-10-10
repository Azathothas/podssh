//! **The grammar, byte-exact in both directions.** Every line in the fixture
//! parses, and every parse encodes back to the line it came from.
//!
//! **A fixture proves the grammar and nothing else** — the entry says so
//! in its own words: *"the failure mode that matters is a frame boundary
//! landing mid-message, and only a real session produces that."* That is
//! `reassembly.rs`, and **this file cannot express a split**, because a
//! split is not a property of a line.

mod common;

use podssh_core::irc::message::{Command, Message, Prefix, Trailing};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/grammar.txt");

/// The fixture's cases: `(wire line, what podssh must believe)`. **The
/// second half is not a comment** — a fixture that is only lines tests that
/// nothing panics, and this one asserts a specific reading for each.
fn cases() -> Vec<(String, String)> {
    let text = common::fixture(FIXTURE);
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (wire, belief) = match line.split_once(" ||| ") {
            Some((w, b)) => (w, b.trim()),
            // The fixture carries every case and its reading on ONE line, so
            // a case split over two physical lines is an authoring mistake
            // **and this says which line**, because "no ` ||| ` reading" on
            // its own is not something a reader can act on.
            None => panic!(
                "fixtures/grammar.txt:{}: no ` ||| ` reading on this case: {line}
                 every case is one physical line: <wire line> ||| <what podssh must believe>",
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
        let message = Message::parse(&wire).unwrap_or_else(|e| panic!("{}: {wire:?} did not parse: {e}", belief));
        // **Two lines normalise and every other one is byte-exact.**
        // Both are a `PING` with a colonless token, and **the encoder
        // always writes the `:`** — see `a_ping_token_survives_the_round_trip_exactly`.
        // They are listed here rather than filtered out, because a
        // blanket "skip lines that fail" is how a suite stops testing.
        if wire == "PING 12345" {
            assert_eq!(message.to_line(), "PING :12345");
            assert_eq!(message.to_wire().unwrap(), "PING :12345\r\n");
            continue;
        }
        assert_eq!(message.to_line(), wire, "{belief}: re-encoding produced a different line than the wire");
        assert_eq!(
            message.to_wire().unwrap(),
            format!("{wire}\r\n"),
            "{belief}: the wire form must be the line plus CRLF"
        );
    }
}

#[test]
fn the_trailing_keeps_spaces_and_the_colons_inside_it() {
    // The two halves of the trailing rule, separately, because a parser that
    // gets one right often gets the other wrong.
    let m = Message::parse(":alice!u@host PRIVMSG #ops :hello there world").unwrap();
    let Command::Privmsg { target, text } = &m.command else { panic!("expected a PRIVMSG") };
    assert_eq!(target.as_str(), "#ops");
    assert_eq!(text.as_str(), "hello there world");

    let m = Message::parse(":alice!u@host PRIVMSG bob :see 12:30 for the handover").unwrap();
    let Command::Privmsg { text, .. } = &m.command else { panic!("expected a PRIVMSG") };
    // **The second colon is content.** A parser that split on every colon
    // turns one parameter into three and delivers `12` to the user.
    assert_eq!(text.as_str(), "see 12:30 for the handover");
}

#[test]
fn an_empty_trailing_is_a_message_and_not_a_missing_one() {
    // RFC 2812 §2.3.2 permits `:` immediately after a space. A parser that
    // drops the empty trailing loses the message entirely, and the sender was
    // entitled to send it.
    let m = Message::parse(":alice!u@host PRIVMSG #c :").unwrap();
    let Command::Privmsg { text, .. } = &m.command else { panic!("expected a PRIVMSG") };
    assert_eq!(text.as_str(), "");
    assert!(text.is_empty());
    assert_eq!(m.to_line(), ":alice!u@host PRIVMSG #c :");
}

#[test]
fn a_ping_token_survives_the_round_trip_exactly() {
    // `PING :aBcD1234` round-trips byte for byte. `PING 12345` does
    // NOT — and **that is recorded rather than hidden**: RFC 1459
    // §2.3.2 permits a server to leave the `:` off when the token has no
    // space or colon in it, and podssh always writes it, so the
    // re-encoded line is `PING :12345`. The **token** is identical either
    // way, which is what the `PONG` must echo.
    for (wire, token) in [("PING :aBcD1234", "aBcD1234"), ("PING 12345", "12345")] {
        let m = Message::parse(wire).unwrap();
        let Command::Ping { token: t } = &m.command else { panic!("expected a PING") };
        assert_eq!(t.as_str(), token, "the token of {wire:?} must be exactly {token:?}, byte for byte");
    }
    assert_eq!(Message::parse("PING :aBcD1234").unwrap().to_line(), "PING :aBcD1234");
    assert_eq!(Message::parse("PING 12345").unwrap().to_line(), "PING :12345");
    // **A token with spaces and punctuation**, because a PONG that is
    // trimmed or re-quoted is not the token the server sent and the entry's
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
    // **The message text contains `alice!u@h`, and it is NOT part of the
    // prefix.** A parser that takes everything before the last colon as the
    // prefix would make this a message from `alice!u@h` and report a network
    // welcome as a chat line from a user.
    assert!(prefix.is_server());
    assert_eq!(prefix.user, None);
    assert_eq!(prefix.host, None);
    assert_eq!(m.command.trailing().unwrap().as_str(), "Welcome to the Example IRC Network alice!u@h");
}

#[test]
fn a_user_message_keeps_its_unused_parameter() {
    // RFC 1459 §4.1.2 has five parameters and the third is called
    // `<unused>` and a client that drops it is answered `461`.
    let m = Message::parse("USER alice 0 * :Alice Example").unwrap();
    assert_eq!(m.to_line(), "USER alice 0 * :Alice Example");
    let Command::User { user, mode, unused, realname } = &m.command else { panic!("expected a USER") };
    assert_eq!(user.as_str(), "alice");
    assert_eq!(mode.as_str(), "0");
    assert_eq!(unused.as_str(), "*");
    assert_eq!(realname.as_str(), "Alice Example");
}

#[test]
fn a_join_of_two_channels_is_one_message() {
    let m = Message::parse(":alice!u@host JOIN #one,#two").unwrap();
    let Command::Join { channels, key, .. } = &m.command else { panic!("expected a JOIN") };
    assert_eq!(channels.len(), 2);
    assert_eq!(channels[0].as_str(), "#one");
    assert_eq!(channels[1].as_str(), "#two");
    assert!(key.is_none());
    assert_eq!(m.to_line(), ":alice!u@host JOIN #one,#two");
}

#[test]
fn an_unknown_command_is_kept_whole_rather_than_dropped() {
    // A client that errors on `AWAY` breaks when the peer adds a command,
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
    // **`room` has no value and that is not the same as an empty one.** A
    // parser that maps absent to `""` re-emits `room=` which is a different
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

/// The text of each field, for the tests of the trailing forms.
fn values(fields: &[podssh_core::irc::message::Middle]) -> Vec<&str> {
    fields.iter().map(|m| m.as_str()).collect()
}

fn text(field: &Option<Trailing>) -> Option<&str> {
    field.as_ref().map(|t| t.as_str())
}

/// **The last parameter comes with or without its `:`** (T-094), and a field
/// reads the same either way. The lines are what ngircd 27, ergo 2.18.0 and
/// InspIRCd 4.11.0 sent (the fixture's captured part); each encodes back to
/// itself.
#[test]
fn the_trailing_forms_of_join_nick_and_privmsg_parse() {
    let parse = |line: &str| {
        let m = Message::parse(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        assert_eq!(m.to_line(), line);
        m
    };
    for line in [":pa!~pa@127.0.0.1 JOIN :#t", ":pa!pa@127.0.0.1 JOIN :#t", ":pa!~u@mcevjy93nmghu.irc JOIN #t"] {
        let Command::Join { channels, key, .. } = parse(line).command else { panic!("{line}: not a JOIN") };
        assert_eq!((values(&channels), key), (vec!["#t"], None), "{line}");
    }
    for line in [":pa!~pa@127.0.0.1 NICK :pa2", ":pa!~u@mcevjy93nmghu.irc NICK pa2"] {
        let Command::Nick { nickname, .. } = parse(line).command else { panic!("{line}: not a NICK") };
        assert_eq!(nickname.as_str(), "pa2", "{line}");
    }
    for line in [":pb!~pb@127.0.0.1 PART #t :bye", ":pb!~u@mcevjy93nmghu.irc PART #t bye"] {
        let Command::Part { channels, reason, .. } = parse(line).command else { panic!("{line}: not a PART") };
        assert_eq!((values(&channels), text(&reason)), (vec!["#t"], Some("bye")), "{line}: bye is no channel");
    }
    for line in [":pa!~pa@127.0.0.1 TOPIC #t :newtopic", ":pa!~u@mcevjy93nmghu.irc TOPIC #t newtopic"] {
        let Command::Topic { channel, topic } = parse(line).command else { panic!("{line}: not a TOPIC") };
        assert_eq!((channel.as_str(), text(&topic)), ("#t", Some("newtopic")), "{line}");
    }
    for (line, want) in
        [(":pa2!~u@mcevjy93nmghu.irc QUIT Quit", "Quit"), (":pb!~u@mcevjy93nmghu.irc QUIT :Quit: done", "Quit: done")]
    {
        let Command::Quit { reason } = parse(line).command else { panic!("{line}: not a QUIT") };
        assert_eq!(text(&reason), Some(want), "{line}");
    }
    for (line, target, flags) in [
        (":pa!~pa@127.0.0.1 MODE #t +k secret", "#t", vec!["+k", "secret"]),
        (":pa!pa@127.0.0.1 MODE #t +k :secret", "#t", vec!["+k", "secret"]),
        (":pa2!~pa@127.0.0.1 MODE pa2 :+i", "pa2", vec!["+i"]),
    ] {
        let Command::Mode { target: t, flags: f, .. } = parse(line).command else { panic!("{line}: not a MODE") };
        assert_eq!((t.as_str(), values(&f)), (target, flags), "{line}");
    }
    // No server measured writes a text without its colon, and a client may:
    // the text is the second parameter either way.
    for line in [":a!u@h PRIVMSG #c word", ":a!u@h NOTICE #c word", ":pa!~pa@127.0.0.1 PRIVMSG #t :word"] {
        let (Command::Privmsg { target, text } | Command::Notice { target, text }) = parse(line).command else {
            panic!("{line}: not a PRIVMSG or a NOTICE")
        };
        assert_eq!((target.as_str(), text.as_str()), (line.split(' ').nth(2).unwrap(), "word"), "{line}");
    }
}

/// A server answers a client's `PING` with its own name, then the token:
/// what ngircd 27, InspIRCd 4.11.0 and ergo 2.18.0 answered to `PING :tok123`.
#[test]
fn a_server_s_pong_names_the_server_then_the_token() {
    for (line, server) in [
        (":irc.ngircd.test PONG irc.ngircd.test :tok123", "irc.ngircd.test"),
        (":irc.inspircd.test PONG irc.inspircd.test :tok123", "irc.inspircd.test"),
        (":ergo.test PONG ergo.test tok123", "ergo.test"),
    ] {
        let m = Message::parse(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        let Command::Pong { server: s, token } = &m.command else { panic!("{line}: {:?}", m.command) };
        assert_eq!((s.as_ref().map(|s| s.as_str()), text(token)), (Some(server), Some("tok123")), "{line}");
        assert_eq!(m.to_line(), line);
    }
    let own = Message::parse("PONG :aBcD1234").unwrap();
    assert!(matches!(&own.command, Command::Pong { server: None, .. }), "{:?}", own.command);
}

#[test]
fn a_parsed_join_keeps_its_key() {
    for (line, channels, key) in [
        ("JOIN #c key", vec!["#c"], Some("key")),
        ("JOIN #c :key", vec!["#c"], Some("key")),
        ("JOIN #a,#b k1,k2", vec!["#a", "#b"], Some("k1,k2")),
        ("JOIN #c", vec!["#c"], None),
    ] {
        let m = Message::parse(line).unwrap();
        let Command::Join { channels: c, key: k, .. } = &m.command else { panic!("{line}: not a JOIN") };
        assert_eq!((values(c), k.as_deref()), (channels, key), "{line}");
        assert_eq!(m.to_line(), line);
    }
    // podssh writes the key as a middle.
    let written = podssh_core::irc::join_message("#c", Some("key"));
    assert_eq!(written.to_wire().unwrap(), "JOIN #c key\r\n");
}

/// A known command with more parameters than its grammar is kept whole: no
/// field reads a parameter that is not its own, and it encodes to its bytes.
/// `extended-join`'s account and real name would otherwise be a key.
#[test]
fn a_known_command_with_more_parameters_than_its_grammar_is_kept_whole() {
    for line in [
        ":a!u@h JOIN #c account :Real Name",
        ":a!u@h PRIVMSG #c word more",
        ":a!u@h PART #c bye now",
        ":a!u@h NICK b 1",
        ":a!u@h QUIT bye now",
        ":irc.example.org PONG irc.example.org a :token",
    ] {
        let m = Message::parse(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        let name = line.split(' ').nth(1).unwrap();
        assert!(matches!(&m.command, Command::Unknown { name: n, .. } if n == name), "{line}: {:?}", m.command);
        assert_eq!(m.to_line(), line);
    }
}

#[test]
fn a_numeric_is_a_number_and_not_a_string() {
    use podssh_core::irc::numeric::Replies;
    // **The defect this test exists for**: `"100"` == `"001"` as text, so
    // a client that compared reply codes as strings fires on the wrong reply.
    let hundred = Message::parse(":irc.example.org 100 alice :Welcome").unwrap();
    let Command::Numeric(ref r100) = hundred.command else { panic!("expected a numeric") };
    assert_eq!(r100.code, 100);
    let one = Message::parse(":irc.example.org 001 alice :Welcome").unwrap();
    let Command::Numeric(ref r1) = one.command else { panic!("expected a numeric") };
    assert_eq!(r1.code, 1);
    assert_ne!(r100.code.to_string(), r1.code.to_string(), "“100” and “001” must not compare equal as text");
    // **The name is derived from the code**, so a reply cannot be
    // labelled `RPL_WELCOME` while carrying `433`.
    assert_eq!(r1.named(), Some(podssh_core::irc::numeric::Numeric::RplWelcome));
    assert_ne!(r100.named(), Some(podssh_core::irc::numeric::Numeric::RplWelcome));
    assert!(Replies::new(433, &[], None).named().is_some());
}

#[test]
fn the_fixture_is_not_silently_emptied() {
    // **A suite that has nothing to run reports 0 passed and exit 0.**
    // That is a pass that measured nothing, and this repository has shipped a
    // gate that did exactly it. So the number of cases is asserted, and a
    // fixture that stops parsing fails here rather than quietly testing nothing.
    let n = cases().len();
    assert!(n >= 25, "the grammar fixture has only {n} cases; it was truncated");
}
