//! The cleartext road (T-326) as processes: `podssh relay serve` on the
//! loopback, as each role serves it (TLS, and the cleartext road beside it),
//! and a stand-in proxy of the test's as the host's proxy of the client,
//! which carries each CONNECT to `relay-a.test` to the role: one that resets
//! cleartext and carries TLS, as a proxy that expects TLS alone does, and
//! one that resets TLS and carries cleartext, as a proxy that intercepts TLS
//! by its SNI or its certificate does. `podssh doctor`'s line `cleartext`
//! names the reset, and the role's `/health` in cleartext; `podssh ssh`
//! opens its session in cleartext after its TLS failed, with the test's SSH
//! server as the target. The checks say that they did not run when this
//! host has no Python or no openssl for the role's certificate.

mod ssh_harness;
mod throughput_harness;

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The bound on each run of podssh.
const LIMIT: Duration = Duration::from_secs(180);
/// The bound on each wait of the stand-in proxy.
const STEP: Duration = Duration::from_secs(30);

/// The name of the role, which only the stand-in proxy reaches.
const RELAY: &str = "relay-a.test";

/// The stand-in proxy on the loopback: a CONNECT to [`RELAY`] goes to the
/// role's port, the one that it names; another is refused (403); and of a
/// tunnel's first bytes, TLS's are reset when `cut_tls`, else cleartext's.
fn proxy(s: &Session, cut_tls: bool) -> u16 {
    let listener = s.runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    s.runtime.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(tunnel(tcp, cut_tls));
        }
    });
    port
}

async fn tunnel(mut tcp: TcpStream, cut_tls: bool) {
    // The CONNECT's head byte by byte, so that nothing of the tunnel is read.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(STEP, tcp.read(&mut byte)).await {
            Ok(Ok(1)) if head.len() < 16 * 1024 => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let target = head.split_whitespace().nth(1).unwrap_or_default().to_string();
    let port = match target.rsplit_once(':') {
        Some((RELAY, port)) => port.parse::<u16>().ok(),
        _ => None,
    };
    let Some(port) = port else {
        let _ = tcp.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
        return;
    };
    if tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
        return;
    }
    let mut first = [0u8; 1];
    let Ok(Ok(1)) = tokio::time::timeout(STEP, tcp.peek(&mut first)).await else { return };
    if (first[0] == 0x16) == cut_tls {
        // A reset, as such a proxy ends what it does not carry.
        let _ = tcp.set_zero_linger();
        return;
    }
    let Ok(mut to) = TcpStream::connect(("127.0.0.1", port)).await else { return };
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut to).await;
}

/// The role, with `extra` flags, and no proxy of the machine for its own
/// dials; `None`, with why, when this host cannot make its certificate.
fn role(s: &Session, extra: &[&str]) -> Option<Cell> {
    let unset: Vec<(&str, String)> =
        ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"].iter().map(|v| (*v, String::new())).collect();
    match Cell::podssh_relay_env(s, "podssh's relay role", extra, &unset) {
        Ok(cell) => Some(cell),
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            None
        }
    }
}

/// The value of `flag` in a cell's arguments.
fn at(cell: &Cell, flag: &str) -> String {
    cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap()
}

/// `podssh ARGS` against the role, through the stand-in proxy at
/// `proxy_port`, which the name of the role goes to, with no pin.
fn through(s: &Session, args: &[String], ca: &str, proxy_port: u16) -> Output {
    let mut cmd: Command = s.stand_in(args, ca);
    cmd.env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy_port}"));
    for name in ["PODSSH_RELAY_TOKEN", "PODSSH_RELAY", "PODSSH_OFFLINE", "PODSSH_CLEARTEXT", "PODSSH_RELAY_ADDR"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

/// The label and the detail of the line `cleartext` of `podssh doctor
/// --quick` at the role, through the stand-in proxy.
fn cleartext_line(s: &Session, cell: &Cell, proxy_port: u16) -> (String, String) {
    let (host, ca) = (at(cell, "--relay-host"), at(cell, "--ca-file"));
    let args: Vec<String> = ["doctor", "--quick", "--relay-host", &host, "--ca-file", &ca].map(String::from).to_vec();
    let out = through(s, &args, &ca, proxy_port);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let relay = text.split("\nrelay\n").nth(1).unwrap_or_else(|| panic!("no section relay: {text}"));
    // `  LABEL  CHECK          DETAIL`: the label in 4, the check in 14.
    let line = relay
        .lines()
        .take_while(|l| l.starts_with("  "))
        .find(|l| l.get(8..22).map(str::trim) == Some("cleartext"))
        .unwrap_or_else(|| panic!("no line cleartext in the section relay: {text}"));
    (line[2..6].trim().to_string(), line[23..].to_string())
}

/// A path that resets cleartext, where TLS passes: the line names the
/// reset, as no fault, since the TLS road answered.
#[test]
fn a_path_that_resets_cleartext_is_named_by_doctor() {
    let s = Session::start("doctor-cleartext-reset");
    let Some(cell) = role(&s, &[]) else { return };
    let proxy_port = proxy(&s, false);
    let (label, detail) = cleartext_line(&s, &cell, proxy_port);
    assert_eq!(label, "ok", "{detail}");
    let reset = "reset, with no answer: a hop that expects TLS cuts cleartext";
    assert!(detail.contains(reset), "the line names the reset: {detail}");
    assert!(detail.ends_with("the TLS road answered, and podssh needs no cleartext road here"), "{detail}");
}

/// A path that resets TLS and carries cleartext: the relay's line fails,
/// and the line `cleartext` names the role's `/health` and the road.
#[test]
fn a_path_that_intercepts_tls_reaches_the_role_s_health_in_cleartext() {
    let s = Session::start("doctor-cleartext-health");
    let Some(cell) = role(&s, &[]) else { return };
    let proxy_port = proxy(&s, true);
    let (label, detail) = cleartext_line(&s, &cell, proxy_port);
    assert_eq!(label, "ok", "{detail}");
    assert!(detail.contains(": an answer: the relay's /health, tcp-ssh-relay podssh "), "the role's answer: {detail}");
    assert!(detail.contains("podssh takes it last, as its TLS failed"), "{detail}");
}

/// Through a proxy that intercepts TLS, `podssh ssh` opens its session on
/// the cleartext road, after its TLS failed, and the session carries SSH to
/// the test's server; `-v` names the road.
#[test]
fn podssh_ssh_opens_its_session_in_cleartext_after_its_tls_failed() {
    let s = Session::start("ssh-cleartext");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let proxy_port = proxy(&s, true);
    let ca = at(&cell, "--ca-file");
    // The cell's arguments with no pin of the role's name, which goes to the
    // proxy as a proxy takes a name; then -v and the command.
    let mut args: Vec<String> = Vec::new();
    let mut given = cell.args.iter();
    while let Some(arg) = given.next() {
        if arg == "--relay-addr" {
            given.next();
            continue;
        }
        args.push(arg.clone());
    }
    let last = args.pop().unwrap();
    args.extend(["-v".to_string(), last, "greet".to_string()]);
    let out = through(&s, &args, &ca, proxy_port);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), ssh_harness::GREETING, "{err}");
    assert!(err.contains("opened the session in cleartext"), "-v names the road: {err}");
    assert!(err.contains("carries the session in cleartext, with a token of one session"), "{err}");
}
