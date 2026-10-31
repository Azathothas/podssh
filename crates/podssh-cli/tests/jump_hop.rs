//! A first hop of `-J` on port 443 with `--direct`, through a proxy that
//! allows port 443 only (T-371, GitHub #61). The hop and the target are the
//! harness's SSH server (russh's); the proxy is a stand-in that sends each
//! CONNECT to a name on port 443 to the hop, and refuses any other port
//! with 403, as an egress of HTTPS alone does. The hop's password comes
//! from a stand-in of `SSH_ASKPASS`, never from the command line.

#![cfg(unix)]

mod ssh_harness;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const STEERING: &[&str] =
    &["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", "SSH_AUTH_SOCK", "DISPLAY"];

/// A scratch directory, removed when the test ends, as it passes or fails.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("podssh-jump-hop-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The hop: the harness's server, kept up by the runtime.
struct Hop {
    _runtime: tokio::runtime::Runtime,
    port: u16,
}

fn hop(home: &Scratch) -> Hop {
    let key = home.0.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(&key)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (port, _) = runtime.block_on(ssh_harness::start_counting(&key));
    Hop { _runtime: runtime, port }
}

/// A proxy of port 443 alone: each CONNECT is recorded; one to port 443 is
/// carried to `to`, any other gets 403.
fn proxy_of_443(to: u16) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = asked.clone();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || carry(client, to, &seen));
        }
    });
    (port, asked)
}

fn carry(mut client: TcpStream, to: u16, seen: &Mutex<Vec<String>>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match client.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let target = text.split_whitespace().nth(1).unwrap_or_default().to_string();
    seen.lock().unwrap().push(target.clone());
    if !target.ends_with(":443") {
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    let Ok(server) = TcpStream::connect(("127.0.0.1", to)) else { return };
    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let (mut a, mut b) = (client.try_clone().unwrap(), server.try_clone().unwrap());
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a, &mut b);
        let _ = b.shutdown(std::net::Shutdown::Write);
    });
    let (mut c, mut d) = (server, client);
    let _ = std::io::copy(&mut c, &mut d);
    let _ = d.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}

/// `podssh ssh ARGS` with the proxy at `proxy`, the hop's password from a
/// stand-in of `SSH_ASKPASS`, and `stdin` as its input.
fn ssh(home: &Scratch, proxy: u16, args: &[String], stdin: &[u8]) -> (i32, Vec<u8>, String) {
    let askpass = home.0.join("askpass");
    std::fs::write(&askpass, format!("#!/bin/sh\nprintf '%s\\n' '{}'\n", ssh_harness::pass::PASSWORD)).unwrap();
    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("ssh").arg("--direct").arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o").arg(format!("UserKnownHostsFile={}", home.0.join("known_hosts").display()));
    cmd.args(args).env("HOME", &home.0).env("XDG_CONFIG_HOME", home.0.join("config"));
    for name in STEERING {
        cmd.env_remove(name);
    }
    cmd.env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy}"));
    cmd.env("SSH_ASKPASS", &askpass).env("SSH_ASKPASS_REQUIRE", "force");
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let started = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("podssh ssh did not end within 60 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_hop_on_443_logs_in_with_askpass_s_password_and_reaches_the_target() {
    let home = Scratch::new("login");
    let hop = hop(&home);
    let (proxy, asked) = proxy_of_443(hop.port);
    let target = format!("tester@127.0.0.1:{}", hop.port);
    let args: Vec<String> = ["-J", "pass-hop@hop.test:443", &target, "greet"].iter().map(|s| s.to_string()).collect();
    let (code, out, err) = ssh(&home, proxy, &args, b"");
    assert_eq!(code, 0, "{err}");
    assert_eq!(String::from_utf8_lossy(&out), ssh_harness::GREETING, "{err}");
    assert_eq!(*asked.lock().unwrap(), vec!["hop.test:443".to_string()], "the hop alone went through the proxy");
    assert!(!err.contains(ssh_harness::pass::PASSWORD), "the password is never shown: {err}");
}

#[test]
fn w_through_the_hop_carries_bytes_both_ways() {
    let home = Scratch::new("w");
    let hop = hop(&home);
    let (proxy, _) = proxy_of_443(hop.port);
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = echo.accept() {
            let mut copy = s.try_clone().unwrap();
            let _ = std::io::copy(&mut s, &mut copy);
        }
    });
    let data: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let args: Vec<String> = [
        "-J",
        "pass-hop@hop.test:443",
        "-W",
        &format!("127.0.0.1:{echo_port}"),
        &format!("tester@127.0.0.1:{}", hop.port),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (code, out, err) = ssh(&home, proxy, &args, &data);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, data, "the echo's bytes, whole: {err}");
}

#[test]
fn a_hop_that_refuses_forwarding_is_named_in_its_words() {
    let home = Scratch::new("nofwd");
    let hop = hop(&home);
    let (proxy, _) = proxy_of_443(hop.port);
    let target = format!("tester@127.0.0.1:{}", hop.port);
    let args: Vec<String> =
        ["-J", "pass-nofwd-hop@hop.test:443", &target, "greet"].iter().map(|s| s.to_string()).collect();
    let (code, _, err) = ssh(&home, proxy, &args, b"");
    assert_eq!(code, 255, "{err}");
    assert!(err.to_lowercase().contains("prohibited"), "the hop's own refusal: {err}");
}
