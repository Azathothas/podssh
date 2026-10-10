//! Shared helpers for the IRC suites. One place, so the four suites cannot
//! drift on what a "line" is.

#![allow(dead_code)]

use podssh_core::irc::framing::{Framed, Reassembler};

/// Read a fixture that is committed **with CRLF endings**, because a
/// fixture rewritten by an editor to LF would stop testing the terminator the
/// protocol actually uses. **The assertion is in the helper**: a fixture
/// that has been normalised is a fixture that no longer proves anything, and
/// the failure names the file.
pub mod session;

pub fn fixture(name: &str) -> String {
    let raw = std::fs::read(name).unwrap_or_else(|e| panic!("cannot read {name}: {e}"));
    assert!(
        raw.windows(2).any(|w| w == b"\r\n"),
        "{name} has no CRLF in it; an editor rewrote it, and it no longer \
         tests the terminator"
    );
    String::from_utf8(raw).expect("a fixture is UTF-8")
}

/// Push bytes through a fresh reassembler and return the lines.
pub fn lines_from(bytes: &[u8]) -> Vec<String> {
    let mut r = Reassembler::new();
    texts(r.push(bytes))
}

/// The text of each line that a push completed, for the cases that hold no
/// lost line and no Latin-1: either one fails the test, named.
pub fn texts(framed: Vec<Framed>) -> Vec<String> {
    framed
        .into_iter()
        .map(|f| match f {
            Framed::Line(text) => text,
            other => panic!("not a line of UTF-8: {other:?}"),
        })
        .collect()
}
