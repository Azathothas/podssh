//! The keepalive of the IRC client (T-098): a `PING` with podssh's token,
//! which the server answers to this client alone, never a `PRIVMSG` that each
//! user of a channel would see. The server's `PONG` counts as a reception, in
//! the forms that real servers write: `:srv PONG srv :tok` (ngircd 27,
//! InspIRCd 4.11.0) and `:srv PONG srv tok` (ergo 2.18.0), measured
//! 2026-10-10 in the build image.

use podssh_core::irc::reap::{keepalive_token, parse_keepalive, ReapPolicy};
use podssh_core::irc::session::{Event, Registered, Server, Session};

fn server() -> Server {
    Server {
        host: "irc.example.org".into(),
        port: 6667,
        nick: "alice".into(),
        username: "alice".into(),
        realname: "Alice Example".into(),
    }
}

/// Registration driven to `001`, as a server drives it.
fn registered() -> Session {
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.on_bytes(b"CAP * LS :multi-prefix znc.in/self-message\r\n");
    let _ = s.on_bytes(b":irc.example.org 001 alice :Welcome\r\n");
    assert_eq!(s.registered(), Registered::Yes);
    s
}

#[test]
fn the_keepalive_is_a_ping_and_never_a_privmsg() {
    let s = registered();
    for generation in [1u64, 2, 99] {
        let line = s.heartbeat(generation).expect("a registered session keeps alive").to_line();
        assert_eq!(line, format!("PING :podssh-{generation}"), "the keepalive is a PING that nobody sees");
        assert!(!line.contains("PRIVMSG"), "{line}");
    }
    assert_eq!(keepalive_token(7), "podssh-7");
    assert_eq!(parse_keepalive("podssh-7"), Some(7));
    for other in ["podssh-", "podssh-x", "tok123", "\u{200b}podssh/7", "podssh-7 "] {
        assert_eq!(parse_keepalive(other), None, "{other:?}");
    }
}

#[test]
fn a_session_that_is_not_registered_sends_no_keepalive() {
    let s = Session::new(server(), ReapPolicy::default());
    assert!(s.heartbeat(1).is_none());
}

/// The answers of ngircd 27, InspIRCd 4.11.0 and ergo 2.18.0 to `PING
/// :tok123`, as the grammar's fixture captured them.
fn captured_pongs() -> Vec<String> {
    let fixture = include_str!("fixtures/grammar.txt");
    let pongs: Vec<String> = fixture
        .lines()
        .filter(|l| l.contains(" PONG ") && l.contains("tok123"))
        .map(|l| l.split(" ||| ").next().unwrap_or(l).to_string())
        .collect();
    assert_eq!(pongs.len(), 3, "the three servers' answers: {pongs:?}");
    pongs
}

#[test]
fn a_matching_pong_counts_as_a_reception() {
    // The servers echo the token as they got it: here, podssh's.
    for captured in captured_pongs() {
        let line = format!("{}\r\n", captured.replace("tok123", "podssh-3"));
        let mut s = registered();
        let (_, events) = s.on_bytes(line.as_bytes());
        assert!(events.iter().any(|e| matches!(e, Event::Heartbeat { generation: 3 })), "{line}: {events:?}");
        assert!(!events.iter().any(|e| matches!(e, Event::Privmsg { .. })), "{events:?}");
    }
    // Another token is no answer to podssh's keepalive.
    for captured in captured_pongs() {
        let mut s = registered();
        let (_, events) = s.on_bytes(format!("{captured}\r\n").as_bytes());
        assert!(!events.iter().any(|e| matches!(e, Event::Heartbeat { .. })), "{captured}: {events:?}");
    }
}

/// The text of the former heartbeat, from a peer, is a message like another:
/// no podssh sends it, and nothing that a peer writes is hidden.
#[test]
fn the_former_heartbeat_text_is_an_ordinary_message() {
    let mut s = registered();
    let (_, events) = s.on_bytes(":bob!b@h PRIVMSG #one :\u{200b}podssh/4\r\n".as_bytes());
    assert!(events.iter().any(|e| matches!(e, Event::Privmsg { .. })), "{events:?}");
    assert!(!events.iter().any(|e| matches!(e, Event::Heartbeat { .. })), "{events:?}");
}
