//! The session against a real IRC server: ngircd, which holds the
//! registration until the client's `CAP END` (T-091), and which echoes a
//! `JOIN` with its channel as the trailing, `JOIN :#c` (T-094). Ignored
//! unless `PODSSH_IRC_SERVER` names one, as HOST:PORT; the build image runs
//! it with ngircd on the loopback.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use podssh_core::irc::cap::Stage;
use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::session::{Registered, Server, Session};
use podssh_core::irc::{Event, Message};

#[test]
#[ignore = "a real IRC server: PODSSH_IRC_SERVER=HOST:PORT"]
fn a_server_that_holds_the_registration_for_cap_end_welcomes_the_client() {
    let Ok(address) = std::env::var("PODSSH_IRC_SERVER") else {
        eprintln!("skipped: PODSSH_IRC_SERVER names no server");
        return;
    };
    let (host, port) = address.rsplit_once(':').expect("HOST:PORT");
    // A nick of this run, within ngircd's 9 characters: a run before may
    // still hold the last one.
    let nick = format!("pt{}", std::process::id() % 1_000_000);
    let channel = format!("#{nick}");
    let server = Server {
        host: host.into(),
        port: port.parse().expect("a port"),
        nick: nick.clone(),
        username: nick,
        realname: "podssh test".into(),
    };
    let mut stream = TcpStream::connect(&address).expect("the server answers");
    stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let mut s = Session::new(server, ReapPolicy::default());
    let mut sent = Vec::new();
    let mut send = |stream: &mut TcpStream, messages: Vec<Message>| {
        for message in messages {
            stream.write_all(message.to_wire().expect("a line podssh may write").as_bytes()).unwrap();
            sent.push(message.to_line());
        }
    };
    send(&mut stream, s.initial_burst());
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut buf = [0u8; 4096];
    let mut joined = false;
    let mut events = Vec::new();
    while !joined {
        assert!(
            Instant::now() < deadline,
            "registered {:?}, joined {joined} in 15 s; podssh sent {sent:?}; events {events:?}",
            s.registered()
        );
        let n = match stream.read(&mut buf) {
            Ok(0) => panic!("the server closed the connection; podssh sent {sent:?}"),
            Ok(n) => n,
            Err(_) => continue,
        };
        let was = s.registered();
        let (out, new) = s.on_bytes(&buf[..n]).expect("lines of the server");
        assert!(!matches!(s.registered(), Registered::Refused(_)), "refused: {:?}; sent {sent:?}", s.registered());
        send(&mut stream, out);
        // Once welcomed, the channel: the server's echo of the `JOIN` is the
        // join, in whichever form the server writes it.
        if was != Registered::Yes && s.registered() == Registered::Yes {
            send(&mut stream, s.send_join(&channel, None).expect("a channel podssh may join"));
        }
        joined = new.iter().any(|e| matches!(e, Event::Joined { channel: c } if *c == channel));
        events.extend(new);
    }
    // A server with `CAP` gets its `CAP END` after the request; one with
    // none answers `421`, holds nothing, and gets none.
    assert_eq!(s.negotiation().stage(), Stage::Ended, "podssh sent {sent:?}");
    let asked = sent.iter().any(|l| l.starts_with("CAP REQ"));
    assert_eq!(asked, sent.iter().any(|l| l == "CAP END"), "a request, and its end: {sent:?}");
    let _ = stream.write_all(b"QUIT :done\r\n");
}
