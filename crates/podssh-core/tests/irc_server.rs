//! The session against a real IRC server (T-091): ngircd, which holds the
//! registration until the client's `CAP END`. Ignored unless
//! `PODSSH_IRC_SERVER` names one, as HOST:PORT; the build image runs it
//! with ngircd on the loopback.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::session::{Registered, Server, Session};

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
    let mut send = |stream: &mut TcpStream, messages: Vec<podssh_core::irc::Message>| {
        for message in messages {
            stream.write_all(message.to_wire().expect("a line podssh may write").as_bytes()).unwrap();
            sent.push(message.to_line());
        }
    };
    send(&mut stream, s.initial_burst());
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut buf = [0u8; 4096];
    while s.registered() != Registered::Yes {
        assert!(Instant::now() < deadline, "no 001 in 15 s: the server still waits; podssh sent {sent:?}");
        let n = match stream.read(&mut buf) {
            Ok(0) => panic!("the server closed the connection; podssh sent {sent:?}"),
            Ok(n) => n,
            Err(_) => continue,
        };
        let (out, _) = s.on_bytes(&buf[..n]).expect("lines of the server");
        assert!(!matches!(s.registered(), Registered::Refused(_)), "refused: {:?}; sent {sent:?}", s.registered());
        send(&mut stream, out);
    }
    assert!(sent.iter().any(|l| l == "CAP END"), "the client ended the negotiation: {sent:?}");
    let _ = stream.write_all(b"QUIT :done\r\n");
}
