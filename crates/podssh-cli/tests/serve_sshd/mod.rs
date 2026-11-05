//! `podssh relay serve --sshd ADDR:PORT` (T-644, GitHub #142): OpenSSH's
//! client on the role's own port logs in to OpenSSH's sshd that the flag
//! names, with a key of the test, and runs a command there, software that
//! podssh did not write at both ends; on the same port, podssh's client
//! still takes TLS's upgrade and the cleartext road still answers HTTP. With
//! no `--sshd`, an SSH client gets no sshd, and the cleartext road answers
//! HTTP once a head ends, as before.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use super::{banner_target, live_harness, ran, relay_flags, role, said, this_user, LIMIT};
use crate::throughput_harness::{self, Cell, Session};

/// The port of the role of `cell`, from its relay host.
fn role_port(cell: &Cell) -> u16 {
    let at = cell.args.iter().position(|a| a == "--relay-host").expect("a relay host");
    cell.args[at + 1].rsplit_once(':').and_then(|(_, port)| port.parse().ok()).expect("a port")
}

/// OpenSSH's client, with no file of this user's and no host key kept, to
/// `user@127.0.0.1` on `port`, with `key` where one is given, running
/// `remote`; its connection and its banner within `wait` seconds.
fn openssh(s: &Session, key: Option<&Path>, port: u16, user: &str, remote: &str, wait: u32) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"])
        .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
        .arg("-o")
        .arg(format!("ConnectTimeout={wait}"));
    if let Some(key) = key {
        cmd.arg("-i").arg(key);
    }
    cmd.args(["-p", &port.to_string(), &format!("{user}@127.0.0.1"), remote]).env("HOME", &s.home);
    cmd
}

/// One request of HTTP in cleartext to the role's `port`: what came back.
fn cleartext_health(port: u16) -> String {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(LIMIT)).unwrap();
    tcp.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut answer = String::new();
    let _ = tcp.read_to_string(&mut answer);
    answer
}

#[test]
fn openssh_on_the_role_s_port_logs_in_to_the_named_sshd_and_tls_still_upgrades() {
    let s = Session::start("serve-sshd");
    let (Some(user), true) = (this_user(), throughput_harness::found("ssh", &["-V"])) else {
        eprintln!("did not run: no OpenSSH client or no user name here");
        return;
    };
    let dir = s.home.join("sshd-door");
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("id");
    let keygen: Vec<String> = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f"]
        .iter()
        .map(|word| word.to_string())
        .chain([key.display().to_string()])
        .collect();
    let made = ran(s.command(&keygen));
    assert!(made.status.success(), "{}", said(&made));
    let sshd = match live_harness::sshd::start(&dir, &key.with_extension("pub")) {
        Ok(sshd) => sshd,
        Err(why) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let named = format!("127.0.0.1:{}", sshd.port);
    let Some(cell) = role(&s, &["--allow-private", "--sshd", &named]) else { return };
    let port = role_port(&cell);
    // OpenSSH on the role's own port: the sshd runs the command, whose shell
    // computes what it prints.
    let out = ran(openssh(&s, Some(&key), port, &user, "echo through-the-role-$((6 * 7))", 20));
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "through-the-role-42", "{text}");
    let first = std::fs::read_to_string(s.home.join("fake-relay-normal-role.log")).unwrap_or_default();
    let words = format!("SSH on this port to the sshd at {named} (a shell for each client that reaches the port");
    assert!(first.contains(&words), "the first line: {first}");
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    assert!(events.contains("sshd from 127.0.0.1:") && events.contains(", at the sshd as 127.0.0.1:"), "{events}");
    // podssh's client on the same port: TLS, and its upgrade, as before.
    let target = banner_target("SSH-2.0-beside-the-sshd\r\n");
    let mut args = vec!["proxy".to_string()];
    args.extend(relay_flags(&cell));
    args.extend(["127.0.0.1".into(), target.to_string()]);
    let out = ran(s.command(&args));
    assert!(said(&out).contains("SSH-2.0-beside-the-sshd"), "TLS's upgrade on the same port: {}", said(&out));
    // And the cleartext road.
    let answer = cleartext_health(port);
    assert!(answer.starts_with("HTTP/1.1 200") && answer.contains("tcp-ssh-relay"), "{answer}");
}

#[test]
fn with_no_sshd_an_ssh_client_gets_no_sshd_and_the_cleartext_road_answers_http() {
    let s = Session::start("serve-no-sshd");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let port = role_port(&cell);
    let first = std::fs::read_to_string(s.home.join("fake-relay-normal-role.log")).unwrap_or_default();
    assert!(!first.contains("SSH on this port"), "{first}");
    // A version line: no line comes back while the cleartext road waits for
    // the end of a head of HTTP, which no SSH client sends.
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
    tcp.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").unwrap();
    let mut buf = [0u8; 64];
    let early = tcp.read(&mut buf);
    assert!(early.is_err(), "the role answered a version line: {early:?}");
    tcp.set_read_timeout(Some(LIMIT)).unwrap();
    tcp.write_all(b"\r\n").unwrap();
    let mut answer = String::new();
    let _ = tcp.read_to_string(&mut answer);
    assert!(answer.starts_with("HTTP/1.1 400"), "the cleartext road's answer: {answer}");
    let answer = cleartext_health(port);
    assert!(answer.starts_with("HTTP/1.1 200") && answer.contains("tcp-ssh-relay"), "{answer}");
    // OpenSSH's client, where this host has one: no banner within its bound.
    if let (Some(user), true) = (this_user(), throughput_harness::found("ssh", &["-V"])) {
        let out = ran(openssh(&s, None, port, &user, "true", 3));
        assert!(!out.status.success() && out.stdout.is_empty(), "an sshd answered: {}", said(&out));
    }
}
