//! The unit tests of `podssh session` (T-186): the command line, the text
//! of `send`, the protocol's lines and the place of the socket.

use std::time::Duration;

use super::wire::{Op, Wait};
use super::*;
use crate::tree::{parse, Parsed};

fn args(words: &[&str]) -> SessionArgs {
    let mut argv = vec!["session"];
    argv.extend_from_slice(words);
    match parse(argv) {
        Parsed::Session(args) => *args,
        other => panic!("{words:?}: {other:?}"),
    }
}

fn asked(words: &[&str]) -> Result<Ask, String> {
    check(&args(words)).map_err(|r| {
        assert_eq!(r.code, 64, "{words:?}: {}", r.message);
        r.message
    })
}

#[test]
fn the_command_line_says_what_it_asks_for() {
    assert_eq!(asked(&["start", "w", "user@host"]), Ok(Ask::Start));
    assert_eq!(asked(&["start", "w", "-p", "2222", "user@host", "top"]), Ok(Ask::Start));
    assert_eq!(asked(&["serve", "--detach", "w", "host"]), Ok(Ask::Serve));
    assert_eq!(asked(&["list"]), Ok(Ask::List));
    assert_eq!(asked(&["send", "w", "echo", "hi"]), Ok(Ask::Request(Op::Send(b"echo hi\r".to_vec()))));
    assert_eq!(asked(&["send", "--no-enter", "w", "q"]), Ok(Ask::Request(Op::Send(b"q".to_vec()))));
    assert_eq!(asked(&["send", "w"]), Ok(Ask::SendStdin));
    assert_eq!(asked(&["capture", "--raw", "w"]), Ok(Ask::Request(Op::Capture { raw: true })));
    assert_eq!(asked(&["stop", "--socket", "/tmp/s", "w"]), Ok(Ask::Request(Op::Stop)));
    let wait = |idle: Option<u64>, text: Option<&str>, timeout: u64| {
        Ok(Ask::Request(Op::Wait(Wait {
            idle: idle.map(Duration::from_millis),
            text: text.map(|t| t.as_bytes().to_vec()),
            timeout: Duration::from_secs(timeout),
        })))
    };
    assert_eq!(asked(&["wait", "w"]), wait(Some(2000), None, 60), "the default: 2 s of quiet within 60 s");
    assert_eq!(asked(&["wait", "w", "--idle", "500ms", "--timeout", "5s"]), wait(Some(500), None, 5));
    assert_eq!(asked(&["wait", "w", "--match", "$ "]), wait(None, Some("$ "), 60), "a match alone has no idle");
}

#[test]
fn each_refusal_of_the_command_line_is_64_and_says_why() {
    for (words, says) in [
        (&[][..], "give a subcommand"),
        (&["frob", "w"][..], "no subcommand \"frob\""),
        (&["-v", "start", "w", "host"][..], "the subcommand comes first"),
        (&["start", "w"][..], "give the host"),
        (&["send"][..], "give the session's name"),
        (&["send", "--", "-x", "hi"][..], "a session's name"),
        (&["send", "a/b", "hi"][..], "a session's name"),
        (&["send", "w", "--idle", "1s", "hi"][..], "--idle is for wait"),
        (&["capture", "w", "-p", "22"][..], "a connection flag is for start and serve"),
        (&["start", "--raw", "w", "host"][..], "--raw is for capture"),
        (&["wait", "w", "--idle", "0"][..], "greater than zero"),
        (&["wait", "w", "--timeout", "30x"][..], "--timeout"),
        (&["wait", "w", "--match", ""][..], "not empty"),
        (&["stop", "w", "now"][..], "takes only the session's name"),
        (&["list", "w"][..], "list takes no name"),
        (&["list", "--socket", "/tmp/s"][..], "--socket is for"),
        (&["send", "w", "a\\qb"][..], "\\q is no escape"),
        (&["send", "w", "\\x0"][..], "two hex digits"),
    ] {
        let said = asked(words).expect_err(&format!("{words:?} was taken"));
        assert!(said.contains(says), "{words:?}: {said}");
    }
    let (long, longest) = ("n".repeat(NAME_MAX + 1), "n".repeat(NAME_MAX));
    assert!(asked(&["stop", long.as_str()]).unwrap_err().contains("32 at most"));
    assert!(asked(&["stop", longest.as_str()]).is_ok());
}

/// `send`'s escapes give the keys that have no letter; a `\` that is no
/// escape is refused, so that a path of Windows is not typed as a TAB.
#[test]
fn the_text_of_send_reads_its_escapes() {
    assert_eq!(text_bytes("echo hi").unwrap(), b"echo hi");
    assert_eq!(text_bytes("a\\r\\n\\t\\e[A\\\\").unwrap(), b"a\r\n\t\x1b[A\\");
    assert_eq!(text_bytes("\\x03\\x7f\\xFF").unwrap(), b"\x03\x7f\xff");
    assert_eq!(text_bytes("C:\\\\temp").unwrap(), b"C:\\temp", "a \\ written twice is one");
    assert!(text_bytes("ends with \\").unwrap_err().contains("ends with a \\"));
    assert!(text_bytes("\\x+1").is_err(), "a sign is no hex digit");
    assert!(text_bytes("\\xg0").is_err());
}

#[test]
fn a_request_goes_and_comes_back_whole() {
    let ops = [
        Op::Info,
        Op::Send(b"echo hi\r".to_vec()),
        Op::Send(vec![0xff, 0x00, 0x1b]),
        Op::Wait(Wait { idle: Some(Duration::from_millis(1500)), text: None, timeout: Duration::from_secs(9) }),
        Op::Wait(Wait { idle: None, text: Some(b"done".to_vec()), timeout: Duration::from_secs(60) }),
        Op::Capture { raw: false },
        Op::Capture { raw: true },
        Op::Stop,
    ];
    for op in ops {
        let line = wire::request("work", &op);
        assert!(line.starts_with("{\"schema\":1,"), "the version first: {line}");
        assert!(!line.contains('\n'), "one line: {line}");
        let back = wire::parse_request(line.as_bytes()).unwrap_or_else(|e| panic!("{line}: {e:?}"));
        assert_eq!((back.name.as_str(), back.op), ("work", op));
    }
}

#[test]
fn a_line_of_another_schema_or_shape_is_refused_with_64() {
    for (line, says) in [
        (r#"{"schema":2,"name":"w","op":"info"}"#, "schema 2: this podssh speaks schema 1"),
        (r#"{"name":"w","op":"info"}"#, "no schema"),
        (r#"{"schema":1,"op":"info"}"#, "names its name"),
        (r#"{"schema":1,"name":"w","op":"reboot"}"#, "no operation"),
        (r#"{"schema":1,"name":"w","op":"send"}"#, "a text or bytes"),
        (r#"{"schema":1,"name":"w","op":"send","bytes":"%%"}"#, "not base64"),
        (r#"{"schema":1,"name":"w","op":"wait","match":""}"#, "empty"),
        ("not json", "not a line of JSON"),
        ("[1]", "a JSON object"),
    ] {
        let (code, why) = wire::parse_request(line.as_bytes()).expect_err(line);
        assert_eq!(code, 64, "{line}");
        assert!(why.contains(says), "{line}: {why}");
    }
    // A wait of a client that names neither waits for 2 s of quiet.
    let line = r#"{"schema":1,"name":"w","op":"wait"}"#;
    let Op::Wait(wait) = wire::parse_request(line.as_bytes()).unwrap().op else { panic!("not a wait") };
    assert_eq!((wait.idle, wait.timeout), (Some(DEFAULT_IDLE), DEFAULT_TIMEOUT));
}

#[test]
fn an_answer_gives_its_fields_or_its_failure() {
    let ok = wire::ok(wire::by("idle"));
    assert!(ok.starts_with("{\"schema\":1,"), "{ok}");
    assert_eq!(wire::parse_answer(ok.as_bytes()).unwrap()["by"], "idle");
    let failed = wire::failed(75, "nothing came");
    assert_eq!(wire::parse_answer(failed.as_bytes()), Err((75, "nothing came".to_string())));
    // A code out of range, or a line that is no answer, is podssh's fault.
    assert_eq!(wire::parse_answer(wire::failed(0, "x").as_bytes()).unwrap_err().0, 70);
    assert_eq!(wire::parse_answer(b"{\"schema\":7,\"ok\":true}").unwrap_err().0, 70);
    let raw = wire::ok(wire::raw(&[0, 0x1b, 0xff]));
    assert_eq!(wire::raw_bytes(&wire::parse_answer(raw.as_bytes()).unwrap()).unwrap(), [0, 0x1b, 0xff]);
    let ready = wire::ready("w", "/run/w.sock", 7);
    assert_eq!(wire::ready_socket(&ready).as_deref(), Some("/run/w.sock"));
    assert_eq!(wire::ready_socket("podssh: a line of the log"), None);
}

/// The socket goes in the first directory that fits: one whose path is too
/// long for a socket's address is passed over, and named when none fits.
#[test]
fn the_socket_goes_in_the_first_directory_that_fits() {
    let root = std::env::temp_dir().join(format!("podssh-session-place-{}", std::process::id()));
    let long = root.join("x".repeat(crate::pipe::unix::SUN_PATH));
    let short = root.join("sessions");
    let path = place::new_in(&[long.clone(), short.clone()], "work").unwrap();
    assert_eq!(std::path::PathBuf::from(&path), short.join("work.sock"));
    assert!(short.is_dir(), "the directory was made");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&short).unwrap().permissions().mode() & 0o777, 0o700);
    }
    let why = place::new_in(&[long], "work").unwrap_err();
    assert!(why.contains("too long for the address of a socket") && why.contains("--socket"), "{why}");
    let _ = std::fs::remove_dir_all(&root);
}
