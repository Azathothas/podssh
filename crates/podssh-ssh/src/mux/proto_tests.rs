//! The messages of OpenSSH 10.3p1's own client and master, captured on the
//! control socket by `scripts/mux-capture.py` in the build image
//! (2026-10-11): each one parses to what it means, and is written back
//! byte for byte.

use super::*;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

/// The packet in `captured` parses to `want`, which writes it back.
fn same(captured: &str, want: Message) {
    let packet = hex(captured);
    let len = u32::from_be_bytes(packet[..4].try_into().unwrap()) as usize;
    assert_eq!(len, packet.len() - 4, "the length of {captured}");
    assert_eq!(Message::parse(&packet[4..]), Ok(want.clone()), "{captured}");
    assert_eq!(want.packet(), packet, "{want:?} written back");
}

#[test]
fn mux_protocol_hello_and_alive() {
    same("00000008 00000001 00000004", Message::Hello { version: 4, extensions: vec![] });
    // OpenSSH 10.3p1's master says the extension "info".
    same(
        "00000015 00000001 00000004 00000004 696e666f 00000001 30",
        Message::Hello { version: 4, extensions: vec![("info".into(), "0".into())] },
    );
    same("00000008 10000004 00000000", Message::AliveCheck { rid: 0 });
    same("0000000c 80000005 00000000 0000001b", Message::Alive { rid: 0, pid: 27 });
}

#[test]
fn mux_protocol_sessions() {
    // `ssh -S CTL -o SetEnv=FOO=bar HOST 'exit 3'`: each bool is a uint32.
    same(
        "00000039 10000002 00000001 00000000 00000000 00000000 00000000 00000000 0000007e 00000000
         00000006 65786974 2033 00000007 464f4f3d626172",
        Message::NewSession(NewSession {
            rid: 1,
            escape: 0x7e,
            command: b"exit 3".to_vec(),
            env: vec!["FOO=bar".into()],
            ..NewSession::default()
        }),
    );
    // `-tt`, then the master's answers.
    same(
        "00000037 10000002 00000001 00000000 00000001 00000000 00000000 00000000 0000007e 00000000
         0000000f 6563686f2068693b20657869742034",
        Message::NewSession(NewSession {
            rid: 1,
            tty: true,
            escape: 0x7e,
            command: b"echo hi; exit 4".to_vec(),
            ..NewSession::default()
        }),
    );
    same("0000000c 80000006 00000001 00000002", Message::SessionOpened { rid: 1, sid: 2 });
    same("0000000c 80000004 00000002 00000004", Message::ExitMessage { sid: 2, code: 4 });
    // `-s HOST sftp`.
    same(
        "0000002c 10000002 00000001 00000000 00000000 00000000 00000000 00000001 0000007e 00000000
         00000004 73667470",
        Message::NewSession(NewSession {
            rid: 1,
            subsystem: true,
            escape: 0x7e,
            command: b"sftp".to_vec(),
            ..NewSession::default()
        }),
    );
    // `-W 127.0.0.1:2201`: the port is a uint32.
    same(
        "0000001d 10000008 00000001 00000000 00000009 3132372e302e302e31 00000899",
        Message::NewStdioFwd { rid: 1, host: "127.0.0.1".into(), port: 2201 },
    );
}

#[test]
fn mux_protocol_forwards_and_control() {
    let fwd = |kind, listen_host: &str, listen_port, connect_host: &str, connect_port| Fwd {
        kind,
        listen_host: listen_host.into(),
        listen_port,
        connect_host: connect_host.into(),
        connect_port,
    };
    // `-O forward -L 8085:127.0.0.1:2201`, and its answer.
    same(
        "00000025 10000006 00000000 00000001 00000000 00001f95 00000009 3132372e302e302e31 00000899",
        Message::OpenFwd { rid: 0, fwd: fwd(FwdKind::Local, "", 8085, "127.0.0.1", 2201) },
    );
    same("00000008 80000001 00000000", Message::Ok { rid: 0 });
    // `-O forward -D 127.0.0.1:1085`: the target is "socks", port 0.
    same(
        "0000002a 10000006 00000000 00000003 00000009 3132372e302e302e31 0000043d 00000005 736f636b73 00000000",
        Message::OpenFwd { rid: 0, fwd: fwd(FwdKind::Dynamic, "127.0.0.1", 1085, "socks", 0) },
    );
    // `-O forward -R 0:127.0.0.1:22`, and the port that the server chose.
    same(
        "00000025 10000006 00000000 00000002 00000000 00000000 00000009 3132372e302e302e31 00000016",
        Message::OpenFwd { rid: 0, fwd: fwd(FwdKind::Remote, "", 0, "127.0.0.1", 22) },
    );
    same("0000000c 80000007 00000000 00009d75", Message::RemotePort { rid: 0, port: 40309 });
    same(
        "00000025 10000007 00000000 00000001 00000000 00001f95 00000009 3132372e302e302e31 00000899",
        Message::CloseFwd { rid: 0, fwd: fwd(FwdKind::Local, "", 8085, "127.0.0.1", 2201) },
    );
    same("00000008 10000009 00000000", Message::StopListening { rid: 0 });
    same("00000008 10000005 00000000", Message::Terminate { rid: 0 });
}

#[test]
fn mux_protocol_refusals_and_damage() {
    let failure = Message::Failure { rid: 3, reason: "no".into() };
    assert_eq!(Message::parse(&failure.body()), Ok(failure));
    let denied = Message::PermissionDenied { rid: 4, reason: "no".into() };
    assert_eq!(Message::parse(&denied.body()), Ok(denied));
    assert_eq!(Message::parse(&hex("1000000f 00000009")), Ok(Message::Proxy { rid: 9 }));
    assert_eq!(Message::parse(&hex("100000ff 00000007")), Ok(Message::Unknown { kind: 0x1000_00ff, rid: Some(7) }));
    assert!(Message::parse(&hex("10000004")).is_err(), "a request id is missing");
    assert!(Message::parse(&hex("10000008 00000001 00000000 00000009 3132")).is_err(), "a short string");
    assert!(Message::parse(&hex("10000006 00000000 00000009")).unwrap_err().contains("type 9"));
    assert!(Message::parse(&[]).is_err());
}
