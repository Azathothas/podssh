//! The record of pkarr from end to end (T-350), on this machine's loopback:
//! two of the tests' iroh relays, a server of pkarr, and a node of the iroh
//! road in front of an echo target. The node stops on the first relay and
//! starts again on the second with the same key, and keeps its record at the
//! server that `PODSSH_IROH_PKARR` names; `podssh pipe` with the first
//! ticket finds it there, and a line goes to the target and comes back.
#![cfg(feature = "iroh-test")]

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use throughput_harness::{lines_of, wait_for, Session};

/// The variable of the record's server, as the manual names it.
const SERVER_VAR: &str = "PODSSH_IROH_PKARR";

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

/// The node of the test on `relay`, its stderr a line at a time; the line
/// of its ticket, once its record names `relay`.
fn node(session: &Session, args: &[String], relay: &str, server: &str) -> (Child, Receiver<String>, String) {
    let mut args = args.to_vec();
    args.extend(["--iroh-relay".to_string(), relay.to_string()]);
    let mut command = session.command(&args);
    command.env(SERVER_VAR, server).stdin(Stdio::null()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("the node");
    let lines = lines_of(&mut child);
    let ticket = wait_for(&lines, "ticket iroh:").expect("the node's ticket");
    let record = wait_for(&lines, "names the home relay").expect("the node's record");
    assert!(record.contains(relay.trim_end_matches('/')), "the record names {relay}: {record}");
    (child, lines, ticket[ticket.find("iroh:").unwrap()..].trim().to_string())
}

#[test]
fn a_pipe_with_the_first_ticket_finds_the_node_on_its_second_relay() {
    let session = Session::start("pipe-iroh-record");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let text = |p: &std::path::Path| p.to_string_lossy().into_owned();
    let (dir_a, dir_b) = (session.home.join("relay-a"), session.home.join("relay-b"));
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    let first = runtime.block_on(podssh_iroh::test_relay::spawn(&dir_a)).expect("the first relay");
    let second = runtime.block_on(podssh_iroh::test_relay::spawn(&dir_b)).expect("the second relay");
    let pkarr = runtime.block_on(podssh_iroh::test_pkarr::spawn(&session.home)).expect("a server of pkarr");
    // One file of trust for the two relays and the server, as --ca-file
    // takes a bundle.
    let ca = session.home.join("ca.pem");
    let bundle: String = [&first.cert, &second.cert, &pkarr.cert]
        .iter()
        .map(|cert| std::fs::read_to_string(cert).expect("a certificate"))
        .collect();
    std::fs::write(&ca, bundle).unwrap();
    let server = pkarr.url.to_string();

    // The client's key, made here, so that the node's allowlist holds it.
    let client_key = session.home.join("client.key");
    let place = podssh_iroh::keys::Place::File(client_key.clone());
    let key = podssh_iroh::keys::load(&place, &mut podssh_relay::session::OsEntropy).expect("a key");
    // In a directory of its own: the node refuses an allowlist that others
    // can change, as a host's temporary directory may let them.
    let private = session.home.join("private");
    podssh_relay::cache::private_dir(&private).unwrap();
    let allow = private.join("allow");
    std::fs::write(&allow, format!("{} the test's client\n", podssh_iroh::keys::fingerprint(&key.public()))).unwrap();
    let node_args = [
        "node".to_string(),
        "lab".into(),
        format!("127.0.0.1:{}", echo_target()),
        "--iroh".into(),
        "--ca-file".into(),
        text(&ca),
        "--iroh-allow".into(),
        text(&allow),
        "--iroh-key".into(),
        text(&session.home.join("node.key")),
    ];

    // The node on the first relay, then on the second with the same key.
    let (mut before, _, ticket) = node(&session, &node_args, &first.url.to_string(), &server);
    let _ = before.kill();
    let _ = before.wait();
    let (after, _lines, again) = node(&session, &node_args, &second.url.to_string(), &server);
    session.keep(after);
    assert_ne!(ticket, again, "the second ticket names the second relay");

    // The pipe with the first ticket, and the first relay alone.
    let pipe_args = [
        "pipe".to_string(),
        "--iroh-key".into(),
        text(&client_key),
        "--iroh-relay".into(),
        first.url.to_string(),
        "--ca-file".into(),
        text(&ca),
        "stdio".into(),
        ticket,
    ];
    let mut child = session
        .command(&pipe_args)
        .env(SERVER_VAR, &server)
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
    let deadline = Instant::now() + Duration::from_secs(90);
    while !read.is_finished() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let mut err = String::new();
            let _ = child.stderr.take().unwrap().read_to_string(&mut err);
            panic!("no echo within 90 s: {err}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(read.join().unwrap().expect("the echo"), b"there and back\n");
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(pkarr.payload(&key_of(&again)).is_some(), "the server keeps the node's record");
    drop((first, second, pkarr));
}

/// The node's key in its ticket.
fn key_of(ticket: &str) -> iroh::PublicKey {
    podssh_iroh::ticket::parse(ticket).expect("a ticket").id
}
