//! `podssh chat --irc SERVER --direct` (T-252) as a process: TCP to the
//! server, not the relay, against a server on this machine's loopback that
//! answers with the lines that ngircd 27 wrote (podssh-core's tests). The
//! message goes to the channel, and the run ends with a `QUIT`.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

/// The server: one client, answered with ngircd's lines; the client's lines.
fn serve(listener: TcpListener) -> std::thread::JoinHandle<Vec<String>> {
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("a client");
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        let mut write = stream.try_clone().unwrap();
        let mut seen = Vec::new();
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            seen.push(line.clone());
            let answer: &[u8] = if line.starts_with("CAP LS") {
                b":irc.ngircd.test CAP * LS :multi-prefix\r\n"
            } else if line.starts_with("USER") {
                b":irc.ngircd.test 001 pa :Welcome to the Internet Relay Network pa!~pa@127.0.0.1\r\n"
            } else if line.starts_with("JOIN") {
                b":pa!~pa@127.0.0.1 JOIN :#t\r\n"
            } else if line.starts_with("QUIT") {
                break;
            } else {
                b""
            };
            if write.write_all(answer).is_err() {
                break;
            }
        }
        seen
    })
}

#[test]
fn a_direct_chat_sends_its_message_and_quits() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = serve(listener);
    let home = std::env::temp_dir().join(format!("podssh-chat-direct-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["chat", "--irc", &format!("127.0.0.1:{port}"), "--direct", "--irc-plaintext", "--nick", "pa"]);
    cmd.args(["--timeout", "20s", "--send", "hello from podssh", "#t"]);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_NICK"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", &home).env("USERPROFILE", &home).env("XDG_CACHE_HOME", &home).env("LOCALAPPDATA", &home);
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh chat did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("plain text (--irc-plaintext)"), "the risk is said: {err}");
    let seen = server.join().unwrap();
    assert!(seen.iter().any(|l| l == "PRIVMSG #t :hello from podssh"), "{seen:?}");
    assert!(seen.iter().any(|l| l.starts_with("QUIT")), "{seen:?}");
    let _ = std::fs::remove_dir_all(&home);
}
