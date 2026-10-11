//! Inputs that the fuzz targets of `fuzz/` found (T-198), each kept as a
//! test that runs with the others: a line that a peer can send must parse or
//! be refused, never stop the process.

use podssh_core::irc::message::{Message, ParseError};

/// From the target `irc_message`: `@ @ :` parses as a command named `@`,
/// which a server would read back as tags. A command is letters or three
/// digits (RFC 2812 §2.3.1), and the encoder refuses each other name.
#[test]
fn a_command_that_is_not_letters_or_three_digits_is_not_written() {
    for line in ["@ @ :", "@a=b #x :y", ":p.example 12 :short numeric", ":p.example 1234 :long numeric"] {
        let message = Message::parse(line).unwrap_or_else(|e| panic!("{line:?}: {e:?}"));
        let refused = message.to_wire().expect_err(line);
        assert!(refused.to_string().contains("the command holds"), "{line:?}: {refused}");
    }
    for line in ["PRIVMSG #c :hi", ":irc.example.org 001 alice :Welcome"] {
        let wire = Message::parse(line).unwrap().to_wire().expect(line);
        assert_eq!(wire, format!("{line}\r\n"));
    }
}

/// From the target `irc_message`: a trailing with no command before it.
/// `parse_command` sliced the parameters past a command that was not there,
/// and the release build, which aborts on a panic, would have ended
/// `podssh chat --irc` at one such line of a server.
#[test]
fn a_trailing_with_no_command_is_refused() {
    for line in [
        ":alice!u@host\0QUIT :\x01\0\0\0\0\0\0\0\x11\0\0\0\0\0\0\0uit\r\n",
        ":irc.example.org :Welcome",
        "@time=2026-10-11T00:00:00Z :irc.example.org :text",
    ] {
        assert!(
            matches!(Message::parse(line), Err(ParseError::MissingCommand { .. })),
            "{line:?}: {:?}",
            Message::parse(line)
        );
    }
}
