//! The remote ends of `podssh pipe` (T-175), through the stand-in relay on
//! the loopback, to small targets of this test: a late reply comes back
//! after the end of input (no Close went out), through `relay:` and through
//! `podssh proxy`, which now runs the same pipe; `tcp:` and `ssh:` pass the
//! end of input on as a half-close; `node:` reaches a node's TARGET over
//! the reverse road; and with `PODSSH_OFFLINE`, no road opens (69). The
//! checks through the relay say that they did not run when this host has
//! no Python or no openssl for the stand-in.

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

use throughput_harness::{Cell, Session};

/// A target on the loopback that answers each connection with `reply`
/// `after` its accept, then closes: its port.
fn late_target(reply: &'static [u8], after: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                std::thread::sleep(after);
                let _ = stream.write_all(reply);
            });
        }
    });
    port
}

/// A target that reads to the end of its input, then answers with the count
/// of the bytes, and closes: its port.
fn counting_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut got = Vec::new();
                let _ = stream.read_to_end(&mut got);
                let _ = stream.write_all(format!("{}\n", got.len()).as_bytes());
            });
        }
    });
    port
}

/// A target that sends each chunk back as it comes: its port.
fn echo_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// `cmd`, a line sent, its echo read back, then the end of input: (code,
/// stderr). For a road with no half-close, whose session ends at the end
/// of input.
fn echoed(mut cmd: Command) -> (i32, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    stdin
        .write_all(
            b"there and back
",
        )
        .unwrap();
    let mut back = vec![0u8; 15];
    let read = std::thread::spawn(move || stdout.read_exact(&mut back).map(|()| back));
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while !read.is_finished() {
        assert!(std::time::Instant::now() < deadline, "no echo within 60 s");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        read.join().unwrap().expect("the echo"),
        b"there and back
"
    );
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// `podssh ARGS` with `input` on stdin: (code, stdout, stderr).
fn run(mut cmd: Command, input: &[u8]) -> (i32, String, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// The stand-in relay's flags, or `None` when it cannot run here: its host,
/// the pin of its name, and its CA.
fn relay_flags(session: &Session) -> Option<Vec<String>> {
    let cell = match Cell::fake_relay_mode(session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let mut flags = vec!["--relay-host".to_string(), at("--relay-host"), "--ca-file".into(), at("--ca-file")];
    flags.extend(["--relay-addr".to_string(), "relay-a.test=127.0.0.1".into()]);
    Some(flags)
}

#[test]
fn a_late_reply_comes_back_after_the_end_of_input_through_the_relay() {
    let session = Session::start("pipe-relay");
    let Some(flags) = relay_flags(&session) else { return };
    let port = late_target(b"the late reply\n", Duration::from_secs(1));
    let mut args = vec!["pipe".to_string()];
    args.extend(flags.iter().cloned());
    args.extend(["stdio".to_string(), format!("relay:127.0.0.1:{port}")]);
    let (code, out, err) = run(session.command(&args), b"");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "the late reply\n", "{err}");
    // podssh proxy runs the same pipe, with its own words.
    let mut args = vec!["proxy".to_string()];
    args.extend(flags);
    args.extend(["127.0.0.1".to_string(), port.to_string()]);
    let (code, out, err) = run(session.command(&args), b"");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "the late reply\n", "{err}");
}

#[test]
fn tcp_passes_the_end_of_input_on_and_the_answer_comes_back() {
    let session = Session::start("pipe-tcp");
    let port = counting_target();
    let args = ["pipe".to_string(), "stdio".into(), format!("tcp:127.0.0.1:{port}")];
    let (code, out, err) = run(session.command(&args), b"twelve bytes");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "12\n", "the target saw the end of its input: {err}");
}

#[test]
fn ssh_opens_the_target_from_the_server_and_passes_the_end_of_input_on() {
    let session = Session::start("pipe-ssh");
    let port = counting_target();
    let mut args = vec!["pipe".to_string(), "--direct".into()];
    args.extend(session.common());
    args.extend(["stdio".to_string(), format!("ssh:tester@127.0.0.1:{},127.0.0.1:{port}", session.port)]);
    let (code, out, err) = run(session.command(&args), b"twelve bytes");
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        out,
        "12
",
        "the target saw the end of its input: {err}"
    );
    // A keyword of a session is refused before anything connects.
    args.extend(["-o".to_string(), "RequestTTY=yes".into()]);
    let (code, _, err) = run(session.command(&args), b"");
    assert_eq!(code, 64, "{err}");
}

#[test]
fn node_reaches_the_target_of_a_node_over_the_reverse_road() {
    let session = Session::start("pipe-node");
    let Some(flags) = relay_flags(&session) else { return };
    let (relay, ca) = (flags[1].clone(), flags[3].clone());
    let command = |args: &[String]| {
        let mut cmd = session.command(args);
        cmd.env("SSL_CERT_FILE", &ca);
        cmd
    };
    let pin = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".into()];
    let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay];
    args.extend(pin.iter().cloned());
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", echo_target())];
    args.extend(pin.iter().cloned());
    let mut node = command(&args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = throughput_harness::lines_of(&mut node);
    session.keep(node);
    throughput_harness::wait_for(&lines, "serving").expect("the node starts");
    let mut args = vec!["pipe".to_string(), "stdio".into(), "node:lab".into()];
    args.extend(pin);
    let (code, err) = echoed(command(&args));
    assert_eq!(code, 0, "{err}");
}

#[test]
fn offline_no_road_opens_and_the_pipe_exits_69() {
    let session = Session::start("pipe-offline");
    for address in ["relay:127.0.0.1:9", "tcp:127.0.0.1:9"] {
        let mut cmd = session.command(&["pipe".to_string(), "stdio".into(), address.into()]);
        cmd.env("PODSSH_OFFLINE", "1");
        let (code, out, err) = run(cmd, b"");
        assert_eq!(code, 69, "{address}: {err}");
        assert!(out.is_empty(), "{address}");
    }
}
