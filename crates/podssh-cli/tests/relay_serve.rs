//! `podssh relay serve` (T-169): the relay's forward road served by podssh
//! itself, on the loopback with a certificate of a test CA (made by
//! `openssl`, as for the stand-in relay), against podssh's own client: bytes
//! both ways through `podssh ssh`, the policy's refusals, a relay that mints
//! for no one, and the documents that `podssh relay` reads. The suite of the
//! stand-in also runs against the role with `PODSSH_RELAY_UNDER_TEST=podssh`.

mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(120);

/// The role with `extra` flags, or `None` when this host cannot make its
/// certificate.
fn role(s: &Session, extra: &[&str]) -> Option<Cell> {
    match Cell::podssh_relay(s, "podssh's relay role", extra) {
        Ok(cell) => Some(cell),
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            None
        }
    }
}

/// The relay flags of a cell: its host, its CA and the pinned address.
fn relay_flags(cell: &Cell) -> Vec<String> {
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    vec![
        "--relay-host".into(),
        at("--relay-host"),
        "--ca-file".into(),
        at("--ca-file"),
        "--relay-addr".into(),
        "relay-a.test=127.0.0.1".into(),
    ]
}

fn ran(mut cmd: Command) -> Output {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn said(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// A target that greets each connection with one line.
fn banner_target(line: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            let _ = stream.write_all(line.as_bytes());
        }
    });
    port
}

#[test]
fn podssh_ssh_carries_8_mib_each_way_through_the_relay_role() {
    let s = Session::start("serve-bytes");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    // The harness's run checks the count of the bytes that arrived.
    let up = throughput_harness::run(&s, &cell, true, 8 << 20).expect("8 MiB up through the role");
    let down = throughput_harness::run(&s, &cell, false, 8 << 20).expect("8 MiB down through the role");
    eprintln!("through podssh relay serve: up {up:.1} MiB/s, down {down:.1} MiB/s");
}

#[test]
fn a_private_target_and_port_25_are_refused_by_the_policy() {
    let s = Session::start("serve-policy");
    let Some(cell) = role(&s, &[]) else { return };
    let target = banner_target("SSH-2.0-never-reached\r\n");
    let mut args = vec!["proxy".to_string()];
    args.extend(relay_flags(&cell));
    args.extend(["127.0.0.1".into(), target.to_string()]);
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(!out.status.success(), "a loopback target through a relay that dials public ones: {text}");
    assert!(text.contains("ALLOW list") && text.contains("not a public address"), "{text}");
    assert!(!text.contains("SSH-2.0-never-reached"), "{text}");

    let mut args = vec!["proxy".to_string()];
    args.extend(relay_flags(&cell));
    // An address of GitHub's: the port is refused before any dial.
    args.extend(["140.82.112.3".into(), "25".into()]);
    let text = said(&ran(s.command(&args)));
    assert!(text.contains("port 25 is refused"), "{text}");
}

#[test]
fn a_relay_that_mints_for_no_one_says_503_and_is_not_asked_again() {
    let s = Session::start("serve-nobody");
    let Some(cell) = role(&s, &["--allow-private", "--mint", "nobody"]) else { return };
    let target = banner_target("SSH-2.0-never-reached\r\n");
    let mut args = vec!["proxy".to_string()];
    args.extend(relay_flags(&cell));
    args.extend(["127.0.0.1".into(), target.to_string()]);
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("503") || text.contains("mints no token"), "{text}");
}

#[test]
fn status_info_and_trace_read_the_role_as_they_read_the_default_relay() {
    let s = Session::start("serve-docs");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let mut args = vec!["relay".to_string(), "status".into(), "--json".into()];
    args.extend(relay_flags(&cell));
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("tcp-ssh-relay") && text.contains("podssh"), "{text}");

    let target = banner_target("SSH-2.0-relay-role-trace\r\n");
    let mut args = vec!["relay".to_string(), "trace".into(), "127.0.0.1".into(), target.to_string()];
    args.extend(relay_flags(&cell));
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("SSH-2.0-relay-role-trace"), "the trace reads the target's first line: {text}");

    let mut args = vec!["relay".to_string(), "info".into(), "github.com".into(), "22".into()];
    args.extend(relay_flags(&cell));
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("262144") || text.contains("256 KiB"), "the five limits: {text}");
}

#[test]
fn serve_refuses_a_missing_certificate_or_listener_and_its_flags_elsewhere() {
    let s = Session::start("serve-usage");
    let cases: [(&[&str], &str); 4] = [
        (&["relay", "serve", "--cert", "c.pem", "--key", "k.pem"], "needs --listen"),
        (&["relay", "serve", "--listen", "127.0.0.1:0"], "needs --cert FILE and --key FILE"),
        (&["relay", "serve", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k", "--mint", "some"], "anyone or nobody"),
        (&["relay", "spec", "--listen", "127.0.0.1:0"], "go with `podssh relay serve` only"),
    ];
    for (args, says) in cases {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let out = ran(s.command(&args));
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", said(&out));
        assert!(said(&out).contains(says), "{args:?}: {}", said(&out));
    }
}
