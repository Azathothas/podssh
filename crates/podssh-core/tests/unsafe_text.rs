//! A caller's text never changes the IRC line it is written in (T-093). A CR
//! or LF ends the line, and the server runs what follows as a command of its
//! own; a NUL ends it for a server written in C; in a middle, a space starts
//! the next parameter. Each is refused where podssh writes the line, and a
//! peer's file name is kept as a base name.

use podssh_core::irc::message::{CapVerb, Command, Middle, Prefix, Tag, Trailing};
use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::transfer::{deny, Line, Offer, Receiver, Sender};
use podssh_core::irc::{nick_message, user_message, Message, Server, Session, SessionError, TransferLimits};

fn server() -> Server {
    Server {
        host: "irc.example.org".into(),
        port: 6667,
        nick: "alice".into(),
        username: "alice".into(),
        realname: "Alice".into(),
    }
}

fn registered() -> Session {
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.on_bytes(b"CAP * LS :multi-prefix\r\n");
    let _ = s.on_bytes(b":irc.example.org 001 alice :Welcome\r\n");
    s
}

fn message(command: Command) -> Message {
    Message { tags: Vec::new(), prefix: None, command }
}

fn privmsg(target: &str, text: &str) -> Message {
    message(Command::Privmsg { target: Middle(target.into()), text: Trailing::new(text) })
}

/// The field and what it holds, of a refusal by the session.
fn refused(result: Result<impl std::fmt::Debug, SessionError>) -> (String, String) {
    match result {
        Err(SessionError::Unsafe(e)) => (e.field, e.found),
        other => panic!("not refused as unsafe: {other:?}"),
    }
}

#[test]
fn crlf_in_a_privmsg_is_refused() {
    // The encoder, which each written byte passes: with its check gone, the
    // wire holds `\r\nQUIT`, a second command.
    match privmsg("#c", "a\r\nQUIT").to_wire() {
        Err(e) => assert_eq!((e.field.as_str(), e.found.as_str()), ("the trailing of PRIVMSG", r"a CR (\r) at byte 1")),
        Ok(wire) => panic!("written: {wire:?}"),
    }
    // The session refuses it first, by the caller's name for it, and the
    // refusal shows the character escaped, so that it stays one line.
    let mut s = registered();
    match s.send_privmsg("#c", "a\r\nQUIT") {
        Err(SessionError::Unsafe(e)) => {
            assert_eq!((e.field.as_str(), e.found.as_str()), ("the text", r"a CR (\r) at byte 1"));
            let shown = SessionError::Unsafe(e).to_string();
            assert!(shown.contains(r"\r") && !shown.contains('\r'), "{shown:?}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(refused(s.send_privmsg("#c", "a\nQUIT")), ("the text".into(), r"an LF (\n) at byte 1".into()));
    // Colons, a tab and spaces are a text's own.
    let ok = s.send_privmsg("#c", "see 12:30 :) \tthen").expect("no CR, LF or NUL");
    assert_eq!(ok.to_wire().unwrap(), "PRIVMSG #c :see 12:30 :) \tthen\r\n");
}

#[test]
fn nul_cr_or_lf_in_each_parameter_is_refused() {
    type Make = Box<dyn Fn(&str) -> Message>;
    let with = |f: fn(&mut Server, String), v: &str| {
        let mut server = server();
        f(&mut server, v.to_string());
        server
    };
    let cases: Vec<(&str, Make)> = vec![
        ("parameter 1 of PRIVMSG", Box::new(|v| privmsg(&format!("#c{v}"), "hi"))),
        ("the trailing of PRIVMSG", Box::new(|v| privmsg("#c", &format!("hi{v}")))),
        (
            "parameter 1 of NOTICE",
            Box::new(|v| message(Command::Notice { target: Middle(format!("bob{v}")), text: Trailing::new("hi") })),
        ),
        (
            "the trailing of NOTICE",
            Box::new(|v| {
                message(Command::Notice { target: Middle("bob".into()), text: Trailing::new(format!("hi{v}")) })
            }),
        ),
        ("parameter 1 of JOIN", Box::new(|v| podssh_core::irc::join_message(&format!("#c{v}"), None))),
        ("parameter 2 of JOIN", Box::new(|v| podssh_core::irc::join_message("#c", Some(&format!("key{v}"))))),
        (
            "parameter 1 of PART",
            Box::new(|v| {
                message(Command::Part { channels: vec![Middle(format!("#c{v}"))], reason: None, colon: false })
            }),
        ),
        (
            "the trailing of PART",
            Box::new(|v| {
                message(Command::Part {
                    channels: vec![Middle("#c".into())],
                    reason: Some(Trailing::new(format!("bye{v}"))),
                    colon: false,
                })
            }),
        ),
        (
            "parameter 1 of TOPIC",
            Box::new(|v| message(Command::Topic { channel: Middle(format!("#c{v}")), topic: None })),
        ),
        (
            "the trailing of TOPIC",
            Box::new(|v| {
                message(Command::Topic { channel: Middle("#c".into()), topic: Some(Trailing::new(format!("t{v}"))) })
            }),
        ),
        ("the trailing of QUIT", Box::new(|v| Session::quit(&format!("bye{v}")))),
        (
            "the trailing of PONG",
            Box::new(|v| message(Command::Pong { server: None, token: Some(Trailing::new(format!("t{v}"))) })),
        ),
        ("parameter 1 of NICK", Box::new(|v| nick_message(&format!("alice{v}")))),
        ("parameter 1 of USER", Box::new(move |v| user_message(&with(|s, v| s.username += &v, v)))),
        ("the trailing of USER", Box::new(move |v| user_message(&with(|s, v| s.realname += &v, v)))),
        (
            "parameter 2 of CAP",
            Box::new(|v| {
                message(Command::Cap {
                    target: None,
                    subcommand: CapVerb::Ls,
                    args: vec![Middle(format!("302{v}"))],
                    trailing: None,
                })
            }),
        ),
        (
            "the trailing of CAP",
            Box::new(|v| {
                message(Command::Cap {
                    target: None,
                    subcommand: CapVerb::Req,
                    args: Vec::new(),
                    trailing: Some(Trailing::new(format!("multi-prefix{v}"))),
                })
            }),
        ),
        (
            "the command",
            Box::new(|v| message(Command::Unknown { name: format!("AWAY{v}"), params: Vec::new(), trailing: None })),
        ),
        (
            "the prefix",
            Box::new(|v| Message { prefix: Some(Prefix::server(format!("irc{v}"))), ..privmsg("#c", "hi") }),
        ),
        (
            "a tag's key",
            Box::new(|v| Message { tags: vec![Tag { key: format!("k{v}"), value: None }], ..privmsg("#c", "hi") }),
        ),
    ];
    for (field, make) in &cases {
        let control = make("");
        assert!(control.to_wire().is_ok(), "{field}: the control is refused: {:?}", control.to_wire());
        for (bad, name) in [("\0", r"a NUL (\0)"), ("\r", r"a CR (\r)"), ("\n", r"an LF (\n)")] {
            match make(bad).to_wire() {
                Err(e) => {
                    assert_eq!(e.field, *field, "{e}");
                    assert!(e.found.starts_with(name), "{field}: {e}");
                }
                Ok(wire) => panic!("{field} with {name} was written: {wire:?}"),
            }
        }
    }
    // The session's writers refuse first: a refused JOIN is not remembered,
    // so no reconnect writes it, and a refused PART forgets nothing.
    let mut s = registered();
    s.send_join("#keep", None).unwrap();
    for bad in ["\0", "\r", "\n"] {
        assert_eq!(refused(s.send_join(&format!("#c{bad}"), None)).0, "the channel");
        assert_eq!(refused(s.send_join("#c", Some(format!("k{bad}")))).0, "the key");
        assert_eq!(refused(s.send_part("#keep", Some(&format!("bye{bad}")))).0, "the reason");
        assert_eq!(refused(s.send_privmsg(&format!("#c{bad}"), "hi")).0, "the target");
    }
    assert_eq!(s.memory().channels(), ["#keep"]);
}

#[test]
fn a_space_in_a_target_is_refused() {
    let mut s = registered();
    for (target, found) in [("#a b", "a space at byte 2"), ("", "nothing"), (":x", "a leading ':'")] {
        assert_eq!(refused(s.send_privmsg(target, "hi")), ("the target".into(), found.into()), "{target:?}");
        let e = privmsg(target, "hi").to_wire().expect_err(target);
        assert_eq!((e.field.as_str(), e.found.as_str()), ("parameter 1 of PRIVMSG", found), "{target:?}");
    }
    // JOIN and PART write their lists with commas, so a comma names a second
    // channel, or a second key, which a reconnect would not know of.
    assert_eq!(refused(s.send_join("#a,#b", None)), ("the channel".into(), "',' at byte 2".into()));
    assert_eq!(refused(s.send_join("#a", Some("k,2".into()))), ("the key".into(), "',' at byte 1".into()));
    assert_eq!(refused(s.send_part("#a,#b", None)), ("the channel".into(), "',' at byte 2".into()));
    assert!(s.memory().is_empty());
    // A trailing written with no `:` is read as a middle, and checked as one.
    let bare = message(Command::Ping { token: Trailing::as_written("a b", false) });
    let e = bare.to_wire().expect_err("a space in a trailing with no ':'");
    assert_eq!((e.field.as_str(), e.found.as_str()), ("the trailing of PING", "a space at byte 1"));
    let written = message(Command::Ping { token: Trailing::new("a b") });
    assert_eq!(written.to_wire().unwrap(), "PING :a b\r\n");
}

#[test]
fn an_offer_name_with_a_bar_is_refused() {
    let limits = TransferLimits::default();
    for (id, name, field, found) in [
        ("t1", "a|b.bin", "the name", "'|' at byte 1"),
        ("t1", "a\r\nQUIT", "the name", r"a CR (\r) at byte 1"),
        ("t1", "a\0.bin", "the name", r"a NUL (\0) at byte 1"),
        ("t1", "", "the name", "nothing"),
        ("t|1", "a.bin", "the transfer id", "'|' at byte 1"),
        ("", "a.bin", "the transfer id", "nothing"),
    ] {
        let e = Sender::new(id, name, 10, limits).expect_err(name);
        assert_eq!((e.field.as_str(), e.found.as_str()), (field, found), "{id:?} {name:?}");
    }
    // Why: a bar shifts each field after it, and the peer reads no offer.
    let shifted =
        Line::Offer(Offer { transfer_id: "t1".into(), name: "a|b.bin".into(), total: 10, chunks: 1, chunk_bytes: 320 });
    assert_eq!(Line::parse(&shifted.render()), None);
    // A deny's reason is read up to the next bar, so a bar would cut it
    // short; an empty reason is legal.
    let e = deny("#c", "t1", "no|room").expect_err("a bar in a reason");
    assert_eq!((e.field.as_str(), e.found.as_str()), ("the reason", "'|' at byte 2"));
    assert!(deny("#c", "t1", "a\nb").is_err());
    assert!(deny("#c", "t|1", "full").is_err());
    assert_eq!(deny("#c", "t1", "").unwrap().to_wire().unwrap(), "PRIVMSG #c :PODSSH1|deny|t1|\r\n");
    // A space and dots are a name's own.
    let sender = Sender::new("t1", "notes v2.tar.gz", 10, limits).expect("a name");
    let Command::Privmsg { text, .. } = sender.offer("#c").command else { panic!("an offer is a PRIVMSG") };
    match Line::parse(text.as_str()) {
        Some(Line::Offer(o)) => assert_eq!(o.name, "notes v2.tar.gz"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_peer_file_name_becomes_a_base_name() {
    let offer = |name: &str| Offer {
        transfer_id: "t1".into(),
        name: name.into(),
        total: 10,
        chunks: TransferLimits::default().chunk_count(10),
        chunk_bytes: TransferLimits::default().chunk_bytes as u64,
    };
    for (sent, kept) in [
        ("f.bin", "f.bin"),
        ("../../.ssh/authorized_keys", "authorized_keys"),
        ("/etc/passwd", "passwd"),
        (r"..\..\Windows\win.ini", "win.ini"),
        (r"C:\Users\x\f.bin", "f.bin"),
        (r"dir/sub\f.bin", "f.bin"),
        ("notes v2.txt", "notes v2.txt"),
        ("..f", "..f"),
    ] {
        let r = Receiver::from_offer(&offer(sent)).unwrap_or_else(|e| panic!("{sent:?}: {e}"));
        assert_eq!(r.name(), kept, "{sent:?}");
    }
    // No base name, a drive or a stream of Windows, or a control character.
    for sent in ["", ".", "..", "dir/", "dir/..", "C:x", "f.bin:stream", "a\u{7}b", "a\tb"] {
        let e = Receiver::from_offer(&offer(sent)).expect_err(sent);
        assert!(e.contains(&format!("{sent:?}")), "the refusal names the name: {e}");
    }
}
