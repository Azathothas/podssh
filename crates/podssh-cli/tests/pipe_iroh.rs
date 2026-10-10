//! `podssh pipe iroh:TICKET` (T-175) from end to end, on this machine's
//! loopback: iroh's relay server for the tests, a node of the iroh road in
//! front of an echo target, which lets this client's key in, and the pipe:
//! a line goes there and comes back.
#![cfg(feature = "iroh-test")]

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{lines_of, wait_for, Session};

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

#[test]
fn a_line_goes_to_the_target_of_a_node_of_the_iroh_road_and_comes_back() {
    let session = Session::start("pipe-iroh");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let relay = runtime.block_on(podssh_iroh::test_relay::spawn(&session.home)).expect("a relay on the loopback");
    let (url, cert) = (relay.url.to_string(), relay.cert.to_string_lossy().into_owned());
    let text = |p: &std::path::Path| p.to_string_lossy().into_owned();
    // The client's key, made here, so that the node's allowlist holds it.
    let client_key = session.home.join("client.key");
    let place = podssh_iroh::keys::Place::File(client_key.clone());
    let key = podssh_iroh::keys::load(&place, &mut podssh_relay::session::OsEntropy).expect("a key");
    let allow = session.home.join("allow");
    std::fs::write(&allow, format!("{} the test's client\n", podssh_iroh::keys::fingerprint(&key.public()))).unwrap();
    let node_args = [
        "node".to_string(),
        "lab".into(),
        format!("127.0.0.1:{}", echo_target()),
        "--iroh".into(),
        "--iroh-relay".into(),
        url.clone(),
        "--ca-file".into(),
        cert.clone(),
        "--iroh-allow".into(),
        text(&allow),
        "--iroh-key".into(),
        text(&session.home.join("node.key")),
    ];
    let mut node = session.command(&node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let line = wait_for(&lines, "ticket iroh:").expect("the node's ticket");
    let ticket = line[line.find("iroh:").unwrap()..].trim().to_string();

    let pipe_args = [
        "pipe".to_string(),
        "--iroh-key".into(),
        text(&client_key),
        "--iroh-relay".into(),
        url,
        "--ca-file".into(),
        cert,
        "stdio".into(),
        ticket,
    ];
    let mut child = session
        .command(&pipe_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    stdin.write_all(b"there and back\n").unwrap();
    let read = std::thread::spawn(move || {
        let mut back = vec![0u8; 15];
        stdout.read_exact(&mut back).map(|()| back)
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while !read.is_finished() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let mut err = String::new();
            let _ = child.stderr.take().unwrap().read_to_string(&mut err);
            panic!("no echo within 60 s: {err}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(read.join().unwrap().expect("the echo"), b"there and back\n");
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    drop(relay);
}
