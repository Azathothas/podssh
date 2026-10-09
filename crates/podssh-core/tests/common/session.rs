//! ⛔ **One `Server` and one way to register**, shared by the session suites.
//! ⛔ Two suites that each built their own would drift, ⛔ and a drift in the
//! fixtures is a test that stops testing the thing it names.

#![allow(dead_code)]

use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::session::{Server, Session};

pub fn server() -> Server {
    Server {
        host: "irc.example.org".into(),
        port: 6667,
        nick: "alice".into(),
        username: "alice".into(),
        realname: "Alice Example".into(),
    }
}

/// ⛔ Drive registration to `001`, the way a server does.
pub fn registered() -> Session {
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.on_bytes(b"CAP * LS :multi-prefix znc.in/self-message\r\n");
    let _ = s.on_bytes(b":irc.example.org 001 alice :Welcome\r\n");
    s
}

/// ⛔ The lines a batch of messages would put on the wire, in order.
pub fn lines(messages: &[podssh_core::irc::Message]) -> Vec<String> {
    messages.iter().map(|m| m.to_line()).collect()
}
