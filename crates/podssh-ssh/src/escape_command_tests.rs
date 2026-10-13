//! The command line of `~C` (T-291): each command of OpenSSH's, as its
//! `process_cmdline` reads it, and the refusal of each other line.

use super::*;
use crate::zmodem::ask::{Answer, Question};

fn port(bind: Option<&str>, port: u16) -> Place {
    Place::Port { bind: bind.map(str::to_string), port }
}

#[test]
fn escape_command_parses_each_command_of_openssh() {
    let add = |kind, spec: &str| Ok(Order::Add(kind, spec.to_string()));
    assert_eq!(parse("-L 8080:db:5432"), add(Kind::Local, "8080:db:5432"));
    assert_eq!(parse("-L8080:db:5432"), add(Kind::Local, "8080:db:5432"));
    assert_eq!(parse("  L 127.0.0.1:8080:db:5432  "), add(Kind::Local, "127.0.0.1:8080:db:5432"));
    assert_eq!(parse("-R 0:web:80"), add(Kind::Remote, "0:web:80"));
    assert_eq!(parse("-R[::1]:8080:[::1]:80"), add(Kind::Remote, "[::1]:8080:[::1]:80"));
    assert_eq!(parse("-D 1080"), add(Kind::Dynamic, "1080"));
    assert_eq!(parse("-D /tmp/socks.sock"), add(Kind::Dynamic, "/tmp/socks.sock"));
    assert_eq!(parse("-KL 8080"), Ok(Order::Cancel(Kind::Local, port(None, 8080))));
    assert_eq!(parse("-KL127.0.0.1:8080"), Ok(Order::Cancel(Kind::Local, port(Some("127.0.0.1"), 8080))));
    assert_eq!(parse("-KL /tmp/l.sock"), Ok(Order::Cancel(Kind::Local, Place::Path("/tmp/l.sock".into()))));
    assert_eq!(parse("-KR [::1]:2290"), Ok(Order::Cancel(Kind::Remote, port(Some("::1"), 2290))));
    assert_eq!(parse("-KR *:2290"), Ok(Order::Cancel(Kind::Remote, port(Some("*"), 2290))));
    assert_eq!(parse("KD 1080"), Ok(Order::Cancel(Kind::Dynamic, port(None, 1080))));
    for help in ["help", "-h", "?", "-?", "H"] {
        assert_eq!(parse(help), Ok(Order::Help), "{help}");
    }
    assert_eq!(parse(""), Ok(Order::Nothing));
    assert_eq!(parse("   "), Ok(Order::Nothing));
    assert_eq!(parse("-"), Ok(Order::Nothing));
}

/// Another word, a cancel with no port or with a port of 0, and an add with
/// no spec are refused in OpenSSH's words; `!` runs no local command.
#[test]
fn escape_command_refuses_another_line() {
    for line in ["-X 8080", "ls", "-k 8080", "-K", "-KX 8080", "-l 8080:db:80", "exit"] {
        assert_eq!(parse(line), Err(INVALID.to_string()), "{line}");
    }
    for line in ["-KL", "-KR 0", "-KD port", "-KL ::1:8080", "-KR [::1]8080", "-KL 70000"] {
        assert_eq!(parse(line), Err("Bad forwarding close specification.".to_string()), "{line}");
    }
    assert_eq!(parse("-L"), Err("Bad local forwarding specification.".to_string()));
    assert_eq!(parse("-D  "), Err("Bad local forwarding specification.".to_string()));
    assert_eq!(parse("-R"), Err("Bad remote forwarding specification.".to_string()));
    assert!(parse("!ls").unwrap_err().contains("no local command"));
}

/// A place holds a listener of its port, at its address when one is given.
#[test]
fn escape_command_place_holds_the_listeners_it_names() {
    let v4: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("an address");
    let v6: std::net::SocketAddr = "[::1]:8080".parse().expect("an address");
    let any: std::net::SocketAddr = "0.0.0.0:8080".parse().expect("an address");
    let (v4, v6, any) = (Listening::Tcp(v4), Listening::Tcp(v6), Listening::Tcp(any));
    assert!(port(None, 8080).holds(&v4) && port(None, 8080).holds(&v6) && port(None, 8080).holds(&any));
    assert!(!port(None, 8081).holds(&v4));
    assert!(port(Some("127.0.0.1"), 8080).holds(&v4) && !port(Some("127.0.0.1"), 8080).holds(&v6));
    assert!(port(Some("localhost"), 8080).holds(&v6) && !port(Some("localhost"), 8080).holds(&any));
    assert!(port(Some("*"), 8080).holds(&any));
    assert!(!port(Some("db.example"), 8080).holds(&v4));
    let path = Listening::Path("/tmp/l.sock".into());
    assert!(Place::Path("/tmp/l.sock".into()).holds(&path));
    assert!(!Place::Path("/tmp/other.sock".into()).holds(&path) && !port(None, 8080).holds(&path));
}

/// The line of `~C` is read as a question is, and the keys after its Enter
/// in the same read are the session's: a CR LF is one Enter.
#[test]
fn escape_command_line_leaves_the_keys_after_it() {
    let (mut question, _) = Question::new("ssh> ");
    let keys = b"-R 0:web:80\r\nls\r";
    let (echo, answer) = question.keys_and_rest(keys);
    assert_eq!(answer, Some((Answer::Line("-R 0:web:80".into()), 13)));
    assert_eq!(&keys[13..], b"ls\r");
    assert!(echo.starts_with(b"-R 0:web:80"), "{echo:?}");
    // Backspace takes a character back; Ctrl-C gives up, and leaves the rest.
    let (mut question, _) = Question::new("ssh> ");
    assert_eq!(question.keys_and_rest(b"-KR 22900\x7f\r").1, Some((Answer::Line("-KR 2290".into()), 11)));
    let (mut question, _) = Question::new("ssh> ");
    assert_eq!(question.keys_and_rest(b"-L 80\x03pwd\r").1, Some((Answer::Refused, 6)));
}
