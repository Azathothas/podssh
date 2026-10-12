//! UDP through a node (T-168), through the stand-in relay's reverse road on
//! the loopback, to a UDP server of this test that answers each query as a
//! DNS server does: the same bytes with the QR bit set. `podssh node lab
//! udp:127.0.0.1:PORT` sends each datagram from its host; `podssh pipe`
//! carries them as `udp:node:lab`: on stdin and stdout, each after its
//! 16-bit length, and on Unix to a program on a datagram socketpair. The
//! checks through the relay say that they did not run when this host has no
//! Python or no openssl for the stand-in.

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use throughput_harness::{lines_of, wait_for, Cell, Session};

/// How long a run of podssh may take here.
const LIMIT: Duration = Duration::from_secs(60);

/// A UDP server on the loopback that answers each datagram with the same
/// bytes and the QR bit set, as a DNS server answers a query: its port.
fn answering_server() -> u16 {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65_536];
        while let Ok((n, from)) = server.recv_from(&mut buf) {
            let mut answer = buf[..n].to_vec();
            if answer.len() > 2 {
                answer[2] |= 0x80;
            }
            let _ = server.send_to(&answer, from);
        }
    });
    port
}

/// A DNS query for `example.org`, type A, with the id `0x12`, `n`.
fn query(n: u8) -> Vec<u8> {
    let mut q = vec![0x12, n, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x07example\x03org\x00\x00\x01\x00\x01");
    q
}

fn answer_to(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    answer[2] |= 0x80;
    answer
}

fn framed(datagram: &[u8]) -> Vec<u8> {
    let mut out = (datagram.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(datagram);
    out
}

/// A pair `lab` on the stand-in relay, and its node in front of a UDP
/// server, online: the flags of `podssh pipe` for the relay, and the CA's
/// file; `None` when the stand-in cannot run here.
fn udp_node(session: &Session) -> Option<(Vec<String>, String)> {
    let cell = match Cell::fake_relay_mode(session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = vec!["--relay-addr".to_string(), "relay-a.test=127.0.0.1".into()];
    let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay];
    args.extend(pins.iter().cloned());
    let out = command(session, &ca, &args).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let mut args = vec!["node".to_string(), "lab".into(), format!("udp:127.0.0.1:{}", answering_server())];
    args.extend(pins.iter().cloned());
    let mut node = command(session, &ca, &args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let first = wait_for(&lines, "serving").expect("the node starts");
    assert!(first.contains("udp:127.0.0.1:"), "the node names its UDP target: {first}");
    // The relay has the node's socket only from this line on.
    wait_for(&lines, "online").expect("the node is online");
    Some((pins, ca))
}

fn command(session: &Session, ca: &str, args: &[String]) -> Command {
    let mut cmd = session.command(args);
    cmd.env("SSL_CERT_FILE", ca);
    cmd
}

/// The exit code of `child` within the limit, and its stderr; a child past
/// the limit is killed, and the test fails.
fn finished(mut child: Child) -> (i32, String) {
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh pipe did not end within {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut err);
    }
    (status.code().unwrap_or(-1), err)
}

#[test]
fn a_target_of_udp_is_a_node_s_alone_and_this_host_sends_none() {
    let session = Session::start("pipe-udp-args");
    let run = |args: &[&str]| {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let out = session.command(&args).stdin(Stdio::null()).env("PODSSH_OFFLINE", "1").output().unwrap();
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    // The pipe sends no UDP: it names the node's form instead.
    let (code, err) = run(&["pipe", "stdio", "udp:example.org:53"]);
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("udp:node:NAME"), "{err}");
    // A UDP TARGET is the node's only one, with no route, on the pair's road.
    for args in [
        &["node", "lab", "udp:127.0.0.1:53", "127.0.0.1:22"][..],
        &["node", "lab", "dns=udp:127.0.0.1:53"][..],
        &["node", "lab", "udp:127.0.0.1"][..],
        &["node", "lab", "udp:127.0.0.1:53", "--iroh"][..],
    ] {
        let (code, err) = run(args);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains("udp:"), "{args:?}: {err}");
    }
}

#[test]
fn datagrams_on_stdin_and_stdout_reach_a_udp_target_through_a_node() {
    let session = Session::start("pipe-udp-stdio");
    let Some((pins, ca)) = udp_node(&session) else { return };
    let mut args = vec!["pipe".to_string(), "stdio".into(), "udp:node:lab".into()];
    args.extend(pins.iter().cloned());
    let mut child = command(&session, &ca, &args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let queries: Vec<Vec<u8>> = (0..3).map(query).collect();
    for q in &queries {
        stdin.write_all(&framed(q)).unwrap();
    }
    stdin.flush().unwrap();
    // Each answer, after its length; their order is the server's.
    let want: usize = queries.iter().map(|q| 2 + q.len()).sum();
    let read = std::thread::spawn(move || {
        let mut got = vec![0u8; want];
        stdout.read_exact(&mut got).map(|()| got)
    });
    let deadline = Instant::now() + LIMIT;
    while !read.is_finished() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("no answers within {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let got = read.join().unwrap().expect("the answers");
    let mut answers = Vec::new();
    let mut at = 0;
    while at < got.len() {
        let len = u16::from_be_bytes([got[at], got[at + 1]]) as usize;
        answers.push(got[at + 2..at + 2 + len].to_vec());
        at += 2 + len;
    }
    answers.sort();
    let mut expected: Vec<Vec<u8>> = queries.iter().map(|q| answer_to(q)).collect();
    expected.sort();
    assert_eq!(answers, expected, "each query got its answer, whole");
    // The end of input: the session waits for late answers, then ends.
    drop(stdin);
    let (code, err) = finished(child);
    assert_eq!(code, 0, "{err}");
    // A stream that is not the framing is refused here, with the reason.
    let mut child = command(&session, &ca, &args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"\xff\xffnot a datagram").unwrap();
    let (code, err) = finished(child);
    assert_eq!(code, 65, "{err}");
    assert!(err.contains("65535"), "{err}");
}

/// A program on a datagram socketpair: each send is one datagram at the
/// target, and each answer one receive. It checks its answers, and its
/// status is the pipe's.
#[cfg(unix)]
#[test]
fn a_program_s_datagrams_reach_a_udp_target_through_a_node() {
    let session = Session::start("pipe-udp-exec");
    let Some(python) = ["python3", "python"].into_iter().find(|p| throughput_harness::found(p, &["--version"])) else {
        eprintln!("did not run: no Python here");
        return;
    };
    let Some((pins, ca)) = udp_node(&session) else { return };
    let script = session.home.join("queries.py");
    std::fs::write(&script, CHILD).unwrap();
    let mut args = vec!["pipe".to_string(), format!("exec:{python} '{}'", script.display()), "udp:node:lab".into()];
    args.extend(pins);
    let child = command(&session, &ca, &args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (code, err) = finished(child);
    assert_eq!(code, 0, "the program's status: {err}");
}

/// The program: three queries on its datagram socket, then each answer
/// checked; 0 when each came whole, 3 when one did not, 4 when its stdin is
/// no datagram socket.
#[cfg(unix)]
const CHILD: &str = r#"import socket, sys
s = socket.socket(fileno=0)
if s.type != socket.SOCK_DGRAM:
    print("not a datagram socket:", s.type, file=sys.stderr)
    sys.exit(4)
queries = []
for i in range(3):
    q = bytes([0x12, i, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]) + b"\x07example\x03org\x00\x00\x01\x00\x01"
    queries.append(q)
    s.send(q)
s.settimeout(30)
got = {}
for _ in queries:
    r = s.recv(65535)
    got[r[:2]] = r
for q in queries:
    want = q[:2] + bytes([q[2] | 0x80]) + q[3:]
    if got.get(q[:2]) != want:
        print("the answer to", q, "is", got.get(q[:2]), file=sys.stderr)
        sys.exit(3)
sys.exit(0)
"#;
