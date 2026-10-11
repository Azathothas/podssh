//! An IRC line (`podssh_core::irc::message::Message::parse`), as a server
//! sends it: a message that passes the checks of `to_wire` is one line, with
//! no CR, LF or NUL but its end, and it parses back to itself.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_core::irc::message::Message;
use podssh_fuzz::text;

fuzz_target!(|data: &[u8]| {
    let Some(line) = text(data) else { return };
    // The byte layer drops each NUL before a line is parsed (framing.rs), and
    // the encoder drops one too, so a line with a NUL never comes here.
    let line = line.replace('\0', "");
    let Ok(message) = Message::parse(&line) else { return };
    let Ok(wire) = message.to_wire() else { return };
    let body = wire.strip_suffix("\r\n").expect("a wire line ends with CRLF");
    assert!(!body.contains(['\r', '\n', '\0']), "{wire:?}");
    assert_eq!(Message::parse(&wire).as_ref(), Ok(&message), "{wire:?}");
});
