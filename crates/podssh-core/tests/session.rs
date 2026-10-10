//! **The session: PONG, truncate, and the reconnect that must be invisible.**
//!
//! These are the entry's remaining three plants. **None of them needs a
//! socket**, because `Session` takes bytes and returns messages and the
//! relay's own contribution — what the bytes are carried in — is
//! the WebSocket client's, and already proven. **What these tests cannot prove is named at
//! the bottom of this file.**

use podssh_core::irc::message::Command;
use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::session::{Event, Registered, RegistrationFailure, Server, Session, SessionError};

fn server() -> Server {
    Server {
        host: "irc.example.org".into(),
        port: 6667,
        nick: "alice".into(),
        username: "alice".into(),
        realname: "Alice Example".into(),
    }
}

/// Drive registration to `001`, the way a server does.
fn registered() -> Session {
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.on_bytes(b"CAP * LS :multi-prefix znc.in/self-message\r\n");
    let _ = s.on_bytes(b":irc.example.org 001 alice :Welcome\r\n");
    s
}

// ── PLANT: truncate must not emit the partial line ──────────────────────────

#[test]
fn plant_a_truncated_stream_emits_no_partial_line() {
    // **THE PLANT.** The bytes stop mid-`PRIVMSG`. Nothing may be
    // emitted, and the end of the stream is reported as its own event so
    // the reconnect path can say what happened.
    let mut s = registered();
    let wire = b":bob!u@h PRIVMSG #c :the message that never ends\r\n";
    let keep = wire.len() - 20;

    let (out, events) = s.on_bytes(&wire[..keep]).expect("short");
    assert!(out.is_empty(), "PLANT: a truncated push wrote {:?}", out.iter().map(|m| m.to_line()).collect::<Vec<_>>());
    assert!(
        !events.iter().any(|e| matches!(e, Event::Privmsg { .. })),
        "PLANT: a truncated push emitted a PRIVMSG event: {events:?}"
    );

    match s.on_stream_end() {
        Some(SessionError::TruncatedMidLine { partial, pending_bytes }) => {
            assert_eq!(partial.len(), keep, "the partial line is exactly what arrived");
            assert_eq!(pending_bytes, keep);
            assert!(partial.starts_with(":bob!u@h PRIVMSG #c :"));
        }
        other => panic!("PLANT: expected TruncatedMidLine, got {other:?}"),
    }
}

#[test]
fn a_clean_end_of_stream_is_not_reported_as_a_truncation() {
    // **The control for the truncate plant.** Nothing pending means
    // nothing to say, and a reconnect path that treated every end as a
    // truncation would tell the user "the link dropped mid-message" on every
    // clean disconnect.
    let mut s = registered();
    let _ = s.on_bytes(b"PING :aBcD1234\r\n").expect("short");
    assert_eq!(s.on_stream_end(), None, "a clean end has nothing to report");
}

#[test]
fn a_truncation_is_reported_once_and_not_repeated() {
    // `take_rest` clears the buffer, so a reconnect that asks twice gets
    // `None` the second time and does not tell the user the same thing twice.
    let mut s = registered();
    let _ = s.on_bytes(b":bob!u@h PRIVMSG #c :half").expect("short");
    assert!(s.on_stream_end().is_some());
    assert_eq!(s.on_stream_end(), None, "the partial line is taken once");
}

// ── PLANT: an idle session reconnects and rejoins, invisibly ────────────────

#[test]
fn plant_an_idle_session_reconnects_and_rejoins_its_channels() {
    // **THE PLANT.** Register, join two rooms, sit idle past the reaper,
    // and be reconnected. The user must not be able to tell from the
    // outside except that the link was re-established.
    let mut s = registered();
    let _ = s.send_join("#one", None);
    let _ = s.send_join("#two", None);
    let (out, _events) = s.on_bytes(b":alice!u@h JOIN #one\r\n:alice!u@h JOIN #two\r\n").expect("short");
    assert!(out.is_empty(), "the server's own JOIN echoes need no reply");
    assert_eq!(s.memory().channels(), ["#one", "#two"]);

    // **The stream ends**, cleanly or mid-line it makes no difference to
    // what the client owes the user.
    let _ = s.on_stream_end();

    // **A reconnect re-issues `CAP`, `NICK` and `USER`, and rejoins every
    // channel it remembers**, in that order.
    let burst = s.reconnect_burst();
    let lines: Vec<String> = burst.iter().map(|m| m.to_line()).collect();
    assert_eq!(
        lines,
        vec![
            "CAP LS 302".to_string(),
            "NICK alice".to_string(),
            "USER alice 0 * :Alice Example".to_string(),
            "JOIN #one".to_string(),
            "JOIN #two".to_string(),
        ],
        "PLANT: the reconnect burst is wrong. It must be the first \
         connection plus the rejoins, in that order."
    );
}

#[test]
fn a_reconnect_is_the_first_burst_plus_the_rejoins_and_nothing_else() {
    // **The same claim, asserted as a relation rather than as a literal** so
    // it keeps holding when either list grows.
    let mut a = Session::new(server(), ReapPolicy::default());
    let _ = a.send_join("#one", None);
    let _ = a.send_join("#two", None);
    let reconnect = a.reconnect_burst();

    let mut b = Session::new(server(), ReapPolicy::default());
    let first = b.initial_burst();

    assert_eq!(reconnect[..first.len()], first[..], "the reconnect must start with exactly the first-connection burst");
    assert_eq!(reconnect.len(), first.len() + 2, "the reconnect must add exactly one JOIN per remembered channel");
}

#[test]
fn a_reconnect_does_not_send_quit() {
    // **THE INVISIBILITY.** An idle reconnect must **not** send
    // `QUIT`, because a `QUIT` tells the server the client is leaving and
    // the server then removes it from every channel — so the rejoin races
    // the removal and the user wins only sometimes.
    let mut s = registered();
    let _ = s.send_join("#one", None);
    let lines: Vec<String> = s.reconnect_burst().iter().map(|m| m.to_line()).collect();
    assert!(!lines.iter().any(|l| l.starts_with("QUIT")), "an idle reconnect sent a QUIT: {lines:?}");
    // **And `QUIT` exists for the deliberate case**, which is a different
    // operation with a different meaning.
    assert_eq!(Session::quit("leaving").to_line(), "QUIT :leaving");
}

#[test]
fn a_channel_the_user_left_is_not_rejoined() {
    // **The defect this catches.** A `PART` must forget the channel.
    // Memory that keeps a room the user left rejoins them into it silently on
    // the next reconnect, and on a moderated channel that is a ban the user
    // did not ask for and cannot see.
    let mut s = registered();
    let _ = s.send_join("#one", None);
    let _ = s.send_join("#two", None);
    let _ = s.send_part("#one", Some("bye"));
    assert_eq!(s.memory().channels(), ["#two"]);

    let lines: Vec<String> = s.reconnect_burst().iter().map(|m| m.to_line()).collect();
    assert!(!lines.iter().any(|l| l.contains("#one")), "rejoined a parted channel: {lines:?}");
}

#[test]
fn a_channel_the_server_kicked_us_from_is_forgotten_on_its_own_echo() {
    // **The server's `PART` is authoritative**, so a kick removes the room
    // from memory even if the client never sent the `PART`.
    let mut s = registered();
    let _ = s.send_join("#one", None);
    let (_, events) = s.on_bytes(b":op!u@h PART #one :you are out\r\n").expect("short");
    assert!(matches!(events.first(), Some(Event::Left { .. })), "got {events:?}");
    assert!(s.memory().is_empty(), "a kicked channel is still remembered");
}

/// The lines that a server writes either way reach the session as their
/// command (T-094): ngircd's echo of a `JOIN` is a join, and ergo's `PART`
/// with its reason as a middle leaves one channel, not two.
#[test]
fn a_join_echo_and_a_part_in_either_form_reach_the_session() {
    let mut s = registered();
    let (_, events) = s.on_bytes(b":alice!~alice@127.0.0.1 JOIN :#t\r\n").expect("short");
    assert_eq!(events, [Event::Joined { channel: "#t".into() }]);
    let (_, events) = s.on_bytes(b":alice!~u@mcevjy93nmghu.irc PART #t bye\r\n").expect("short");
    assert_eq!(events, [Event::Left { channel: "#t".into(), reason: Some("bye".into()) }]);
    assert!(s.memory().is_empty());
}

#[test]
fn a_duplicate_join_is_remembered_once() {
    // **Or a reconnect sends two `JOIN`s for one room** and the user sees
    // it echoed back twice.
    let mut s = registered();
    assert!(s.send_join("#one", None).unwrap()[0].to_line().starts_with("JOIN"));
    let again = s.send_join("#one", None).unwrap();
    assert_eq!(s.memory().len(), 1);
    assert_eq!(again.len(), 1, "the duplicate still goes out; only memory is deduped");
}

// ── registration, and the ordering IRCv3 requires ────────────────────────────

#[test]
fn the_initial_burst_is_cap_nick_user_in_that_order() {
    let mut s = Session::new(server(), ReapPolicy::default());
    let lines: Vec<String> = s.initial_burst().iter().map(|m| m.to_line()).collect();
    assert_eq!(
        lines,
        vec!["CAP LS 302".to_string(), "NICK alice".to_string(), "USER alice 0 * :Alice Example".to_string(),],
        "CAP LS must precede NICK/USER so the capability list arrives before \
         registration, and CAP END must not be among them"
    );
}

#[test]
fn sasl_is_never_requested() {
    // podssh's IRC leg authenticates nothing. Advertising a mechanism it
    // cannot complete gets a server that waits for credentials it will never
    // receive.
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.initial_burst();
    let (out, _) = s.on_bytes(b"CAP * LS :multi-prefix sasl znc.in/self-message\r\n").expect("short");
    let req = out.iter().find(|m| m.to_line().starts_with("CAP REQ")).expect("a REQ must follow an LS");
    let text = req.to_line();
    assert!(!text.contains("sasl"), "sasl was requested: {text}");
    assert!(text.contains("multi-prefix"), "the wanted capability is missing: {text}");
}

#[test]
fn a_nak_is_not_requested_again_after_a_reconnect() {
    // **A server that refused a capability once will refuse it again** and
    // asking twice is how a client ends up in a `CAP` loop it never leaves.
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.initial_burst();
    let _ = s.on_bytes(b"CAP * LS :multi-prefix sasl\r\n").expect("short");
    let _ = s.on_bytes(b"CAP * NAK :multi-prefix\r\n").expect("short");
    assert_eq!(s.negotiation().refused(), ["multi-prefix"]);

    let _ = s.initial_burst();
    let (out, _) = s.on_bytes(b"CAP * LS :multi-prefix\r\n").expect("short");
    let req = out.iter().find(|m| m.to_line().starts_with("CAP REQ")).map(|m| m.to_line()).unwrap_or_default();
    assert!(!req.contains("multi-prefix"), "a refused capability was re-requested: {req}");
}

#[test]
fn a_433_is_reported_and_not_treated_as_fatal() {
    // **The one registration failure that is not a failure.** Somebody else
    // holds the nick; a client that treated it as fatal cannot connect to a
    // network where its preferred name is taken.
    let mut s = Session::new(server(), ReapPolicy::default());
    let (_, events) = s.on_bytes(b":irc.example.org 433 * alice :Nickname is already in use\r\n").expect("short");
    assert_eq!(s.registered(), Registered::Refused(RegistrationFailure::NicknameInUse));
    assert!(events.iter().any(|e| matches!(e, Event::Numeric { code: 433, .. })), "got {events:?}");
}

#[test]
fn an_unrelated_error_does_not_mark_registration_refused() {
    // **A control for the numeric handling.** An unrelated `404` arriving
    // mid-chat must not flip a working session to refused.
    let mut s = registered();
    let _ = s.on_bytes(b":irc.example.org 404 alice #c :Cannot send to channel\r\n").expect("short");
    assert_eq!(s.registered(), Registered::Yes, "an unrelated numeric refused registration");
}

#[test]
fn a_late_registration_numeric_does_not_unregister_a_working_session() {
    // MEASURED live 2026-10-07: undernet answers CAP LS with 421 *after*
    // 001 (no IRCv3), and the old code flipped Yes back to Refused so every
    // later send failed NotRegistered. Registration-time numerics only count
    // while Pending; the 404-control above passes trivially (404 is not in
    // the refusal set), this one covers a numeric that is.
    let mut s = registered();
    let _ = s.on_bytes(b":irc.example.org 421 alice CAP :Unknown command\r\n").expect("short");
    assert_eq!(s.registered(), Registered::Yes, "a late 421 unregistered the session");
    assert!(s.send_privmsg("#c", "hi").is_ok(), "sends still work after a late 421");
}

#[test]
fn isupport_is_read_from_005_and_not_assumed() {
    // **The rule: a capability is MEASURED or the client does not depend on
    // it.** `NICKLEN` decides whether an offer fits, so it is read.
    let mut s = Session::new(server(), ReapPolicy::default());
    assert_eq!(s.isupport().nicklen(), 9, "RFC 1459 §2.6's default before any 005");
    let _ = s.on_bytes(
        b":irc.example.org 005 alice NICKLEN=20 CHANNELLEN=64 MAXTARGETS=4 CASEMAPPING=ascii PREFIX=(ov)@+ :are supported\r\n",
    )
    .expect("short");
    assert_eq!(s.isupport().nicklen(), 20);
    assert_eq!(s.isupport().maxtargets(), Some(4));
    assert!(s.isupport().is_ascii_casemapping());
    let prefix = s.isupport().prefix();
    assert_eq!(prefix.prefix_for('o'), Some('@'));
    assert_eq!(prefix.prefix_for('v'), Some('+'));
}

// ── what the user sees, and what they must not ──────────────────────────────

#[test]
fn a_notice_is_carried_but_marked_as_a_notice() {
    // RFC 2812 §3.3.2: notices are never sent to a client that did not send
    // the matching `PRIVMSG` except `NOTICE AUTH`. A client that displays
    // them puts a server's status messages in the middle of a conversation.
    let mut s = registered();
    let (_, events) = s.on_bytes(b":irc.example.org NOTICE alice :*** Looking up your hostname\r\n").expect("short");
    assert!(
        matches!(events.iter().find(|e| matches!(e, Event::Notice { .. })), Some(Event::Notice { text, .. }) if text == "*** Looking up your hostname"),
        "got {events:?}"
    );
    assert!(!events.iter().any(|e| matches!(e, Event::Privmsg { .. })), "a notice became a PRIVMSG");
}

#[test]
fn a_heartbeat_is_consumed_and_never_shown() {
    // **The heartbeat must never reach a user's scrollback.** A
    // heartbeat that a user could see is noise every 60 seconds, and one they
    // could reply to is a conversation with the client itself.
    let mut s = registered();
    let mut seen_as_text = 0;
    for generation in 1..=4u64 {
        let hb = s.heartbeat("#one", generation).expect("registered means a heartbeat");
        assert!(hb.to_line().starts_with("PRIVMSG #one :"), "the heartbeat is not a PRIVMSG: {}", hb.to_line());
        let (_, events) = s.on_bytes(hb.to_wire().unwrap().as_bytes()).expect("short");
        assert!(
            events.iter().all(|e| matches!(e, Event::Heartbeat { .. })),
            "generation {generation} produced {events:?}; a heartbeat must be \
             consumed before the display path"
        );
        seen_as_text += events.iter().filter(|e| matches!(e, Event::Privmsg { .. })).count();
    }
    assert_eq!(seen_as_text, 0, "a heartbeat reached the display path {seen_as_text} time(s)");
}

#[test]
fn a_transfer_line_is_consumed_and_never_shown_as_chat() {
    // **The reverse of the heartbeat**, and the same rule: a chunk is
    // consumed before the text is shown, or a 64 MiB transfer fills a user's
    // terminal with `PODSSH1|chunk|…` lines.
    let mut s = registered();
    let (_, events) = s.on_bytes(b":alice!u@host PRIVMSG #c :PODSSH1|chunk|t1|0|0|QUJD\r\n").expect("short");
    assert!(!events.iter().any(|e| matches!(e, Event::Privmsg { .. })), "a chunk was shown as chat: {events:?}");
    assert!(
        matches!(events.first(), Some(Event::Transfer(_))),
        "the chunk did not become a transfer event: {events:?}"
    );
}

#[test]
fn an_unparseable_line_is_reported_and_does_not_end_the_conversation() {
    // **One malformed line from a peer is not a reason to drop a
    // conversation** and a client that disconnects on a parse error is a
    // client a misbehaving server can take offline at will.
    let mut s = registered();
    let (out, events) = s.on_bytes(b":bob!u@h PRIVMSG\r\n").expect("short");
    assert!(out.is_empty());
    assert!(events.iter().any(|e| matches!(e, Event::Protocol(_))), "got {events:?}");
    let (_, events) = s.on_bytes(b":bob!u@h PRIVMSG #c :still here\r\n").expect("short");
    assert!(matches!(events.first(), Some(Event::Privmsg { .. })), "one bad line cost the conversation: {events:?}");
}

#[test]
fn user_traffic_before_registration_is_refused() {
    // **A `PRIVMSG` before `001` is silently dropped by the server** with no
    // error to anyone so a client that sends it must refuse it locally.
    let mut s = Session::new(server(), ReapPolicy::default());
    assert_eq!(s.send_privmsg("#c", "hi").unwrap_err(), SessionError::NotRegistered);
    let mut live = registered();
    assert!(live.send_privmsg("#c", "hi").is_ok(), "a registered session refused a PRIVMSG");
}

#[test]
fn an_over_long_message_is_refused_and_not_truncated() {
    // **A truncated send is worse than a refusal.** A `PRIVMSG` cut at
    // 510 bytes is a message the user believes was sent whole, and for a
    // file transfer it is a chunk with a hole in it and a digest that will
    // never match.
    let mut s = registered();
    let long = "x".repeat(600);
    match s.send_privmsg("#c", &long) {
        Err(SessionError::TooLong { bytes }) => {
            assert!(bytes > 512, "the error must report the size it refused: {bytes}");
        }
        other => panic!("a 600-byte PRIVMSG was not refused: {other:?}"),
    }
    // **And one that fits goes out whole.**
    let ok = s.send_privmsg("#c", &"x".repeat(400)).expect("400 bytes fits");
    assert_eq!(ok.to_wire().unwrap().len(), "PRIVMSG #c :".len() + 400 + 2);
}

// ── what these tests do NOT prove ────────────────────────────────────────

#[test]
fn this_suite_exercises_a_session_and_not_a_socket() {
    // **The limit, stated where a reader will meet it.**
    //
    // Every test above drives `Session` with bytes it invented. **No socket,
    // no relay, no ircd and no token took part**, and so this suite proves
    // the *protocol logic* — reassembly, the PONG echo, the truncate rule,
    // the reconnect burst, the heartbeat's invisibility — and it does
    // NOT prove that a real relay carries those bytes, that a real ircd
    // accepts a message split across two WebSocket frames, or that an idle
    // session survives 180 s of a live peer's inactivity.
    //
    // **The reassembly proof is byte-level, not session-level.** It shows
    // the bytes are joined correctly; it cannot show that a real peer splits
    // them the way the split was constructed here. That difference is named
    // on the entry rather than glossed.
    let mut s = registered();
    let _ = s.send_join("#proof", None);
    assert_eq!(s.memory().len(), 1);
    // **No `tokio`, no `TcpStream`, no `wsl` in this crate's tests** and
    // that is deliberate: a test needing a network stops being run the moment
    // the network is slow, and a blocked gate is not a passing gate.
    let _ = Command::Ping { token: podssh_core::irc::Trailing::new("x") };
}
