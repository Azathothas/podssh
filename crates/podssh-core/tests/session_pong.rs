//! ⛔ **PLANT: the `PONG` must echo the server's `PING` token byte for byte.**
//!
//! ⛔ **Its own file, and the reason is the file count.** ⛔ `session.rs` went
//! over the 500-line gate with this section in, ⛔ and ⛔ one client can only be
//! answered with one `PONG` ⛔ so ⛔ **the keepalive protocol is a subject, not a
//! helper** ⛔ and it deserves a name a reader can find.

mod common;

use common::session::registered;


#[test]
fn plant_a_ping_with_a_token_gets_a_pong_that_echoes_it_byte_for_byte() {
    // ⛔ **THE PLANT.** ⛔ "a server that does not receive its own token drops
    // the client", in the entry's words.
    let mut s = registered();

    for token in [
        "aBcD1234",
        "12345",
        "a b c",
        "with:colon",
        "with spaces and : a colon",
        "CAP-3.0-hello",
        "\u{2764}",
        "-_.!~*'()/",
        "",
    ] {
        let (out, _events) = s
            .on_bytes(format!("PING :{token}\r\n").as_bytes())
            .unwrap_or_else(|e| panic!("a PING must not error: {e}"));
        let pongs: Vec<String> = out.iter().map(|m| m.to_line()).collect();
        assert_eq!(
            pongs,
            vec![format!("PONG :{token}")],
            "⛔ PLANT: a PING of {token:?} was answered with {pongs:?}; the token \
             must be echoed byte for byte"
        );
    }
}

#[test]
fn plant_the_control_a_pong_is_not_sent_when_nothing_pinged() {
    // ⛔ **The other direction.** ⛔ A client that answers a `PING` it was never
    // sent produces a `PONG` on every frame, ⛔ and the first symptom is an
    // infinite echo between two such clients.
    let mut s = registered();
    let (out, events) = s.on_bytes(b":bob!u@h PRIVMSG #c :hello\r\n").expect("short");
    assert!(out.is_empty(), "⛔ a PRIVMSG needs no reply; got {:?}", out.iter().map(|m| m.to_line()).collect::<Vec<_>>());
    assert_eq!(events.len(), 1, "⛔ the PRIVMSG is the only event");
}

#[test]
fn a_ping_with_no_colon_is_still_answered_with_its_token() {
    // ⛔ RFC 1459 §2.3.2 allows `PING <server>` with no colon at all. ⛔ The
    // client that only looked for a trailing sees no token ⛔ and answers
    // nothing, and the server times it out.
    let mut s = registered();
    let (out, _) = s.on_bytes(b"PING 12345\r\n").expect("short");
    assert_eq!(
        out.iter().map(|m| m.to_line()).collect::<Vec<_>>(),
        vec!["PONG :12345".to_string()],
        "⛔ a colonless PING must still be answered with the token"
    );
}

#[test]
fn two_pings_get_two_pongs_in_arrival_order() {
    // ⛔ **A queue and not a set.** ⛔ Two `PING`s carrying the same token must
    // get two `PONG`s, ⛔ and ⛔ collapsing them into a set would answer a
    // genuine retry with nothing.
    let mut s = registered();
    let (out, _) = s.on_bytes(b"PING :same\r\nPING :same\r\nPING :other\r\n").expect("short");
    assert_eq!(
        out.iter().map(|m| m.to_line()).collect::<Vec<_>>(),
        vec!["PONG :same".to_string(), "PONG :same".to_string(), "PONG :other".to_string()],
        "⛔ two PINGs with one token need two PONGs, in order"
    );
}

#[test]
fn a_pong_echoed_back_by_the_server_is_not_answered_again() {
    // ⛔ **The infinite echo, prevented.** ⛔ A `PONG` from the peer is not a
    // `PING`; ⛔ answering it produces a loop between two podssh peers.
    let mut s = registered();
    let (out, _) = s.on_bytes(b"PONG :aBcD1234\r\n").expect("short");
    assert!(out.is_empty(), "⛔ a PONG must never be answered");
}

