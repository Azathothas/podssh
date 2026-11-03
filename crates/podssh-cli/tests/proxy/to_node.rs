//! `podssh proxy node://NAME` (T-587) through the stand-in relay of the
//! reverse road (Python and openssl): through a node in front of a target
//! that echoes, 1 MiB goes each way with equal digests; and OpenSSH's
//! client, with `podssh proxy node://NAME` as its ProxyCommand, runs a
//! command on the test's SSH server behind a node. Each says that it did not
//! run where this host has no Python, no openssl or no OpenSSH client.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::throughput_harness::{lines_of, wait_for, Cell, Session};

/// The bound on each wait of a test: the bytes, an exit.
const LIMIT: Duration = Duration::from_secs(120);
/// The bytes of each way.
const MIB: usize = 1 << 20;

/// A target that sends each chunk back as it comes: its port.
fn echo_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut buf = [0u8; 16 * 1024];
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

/// The stand-in relay, a pair under `lab` on it, and a node of the pair in
/// front of `target`, online: the command that runs podssh against the
/// stand-in, or `None` when it cannot run here.
fn node_in_front_of(s: &Session, target: u16) -> Option<impl Fn(&[&str]) -> Command + '_> {
    let cell = match Cell::fake_relay_mode(s, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let command = move |args: &[&str]| {
        let words: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        // The pin of the stand-in's name goes after the verb.
        let mut cmd = s.stand_in(&words[..1], &ca);
        cmd.args(["--relay-addr", "relay-a.test=127.0.0.1"]).args(&words[1..]);
        cmd
    };
    let out = command(&["relay", "pair", "lab", "--relay-host", relay.as_str()]).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let at_target = format!("127.0.0.1:{target}");
    let mut node =
        command(&["node", "lab", at_target.as_str()]).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    wait_for(&lines, "online").expect("the node is online");
    Some(command)
}

/// The exit code of `child` within `limit`; past it the child is killed, and
/// the test fails.
fn exited(child: &mut Child, limit: Duration) -> Option<i32> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            return status.code();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[test]
fn proxy_carries_a_session_to_a_node_by_its_name() {
    let s = Session::start("proxy-node");
    let Some(command) = node_in_front_of(&s, echo_target()) else { return };
    let mut child = command(&["proxy", "node://lab"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let said = lines_of(&mut child);
    let data: Vec<u8> = (0..MIB as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    let sent = data.clone();
    // The input stays open until the echo came back: a node's session ends
    // with the end of its input.
    let writer = std::thread::spawn(move || stdin.write_all(&sent).map(|()| stdin));
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut back = vec![0u8; MIB];
        let _ = tx.send(stdout.read_exact(&mut back).map(|()| back));
    });
    let back = match rx.recv_timeout(LIMIT) {
        Ok(Ok(back)) => back,
        Ok(Err(e)) => panic!("the echo ended early: {e}: {:?}", said.try_iter().collect::<Vec<_>>()),
        Err(_) => {
            let _ = child.kill();
            panic!("1 MiB did not come back within {LIMIT:?}: {:?}", said.try_iter().collect::<Vec<_>>());
        }
    };
    let stdin = writer.join().unwrap().expect("1 MiB went in");
    drop(stdin);
    let code = exited(&mut child, LIMIT);
    let lines: Vec<String> = said.try_iter().collect();
    assert_eq!(code, Some(0), "a session that the node took: {lines:?}");
    assert_eq!(digest(&back), digest(&data), "1 MiB came back whole: {lines:?}");
}

/// The words of `cmd` as one line of the shell, as OpenSSH runs a
/// ProxyCommand: each in single quotes, none of which holds one, nor the
/// `%` of OpenSSH's tokens.
#[cfg(unix)]
fn shell_line(cmd: &Command) -> String {
    let words = std::iter::once(cmd.get_program()).chain(cmd.get_args());
    let quoted = words.map(|word| {
        let word = word.to_string_lossy();
        assert!(!word.contains('\'') && !word.contains('%'), "a word that the line cannot carry: {word}");
        format!("'{word}'")
    });
    quoted.collect::<Vec<_>>().join(" ")
}

/// `cmd`'s exit code, stdout and stderr, each read to its end; past `limit`
/// it is killed, and the test fails.
#[cfg(unix)]
fn output_within(mut cmd: Command, limit: Duration) -> (Option<i32>, String, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("ssh runs");
    let read = |mut pipe: Box<dyn Read + Send>| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut text = Vec::new();
            let _ = pipe.read_to_end(&mut text);
            let _ = tx.send(text);
        });
        rx
    };
    let out = read(Box::new(child.stdout.take().expect("stdout")));
    let err = read(Box::new(child.stderr.take().expect("stderr")));
    let code = exited(&mut child, limit);
    let text = |rx: mpsc::Receiver<Vec<u8>>| {
        String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default()).into_owned()
    };
    (code, text(out), text(err))
}

/// OpenSSH's client with `ProxyCommand=podssh proxy node://lab`: the
/// command's output and its exit 0, from the test's SSH server behind the
/// node.
#[cfg(unix)]
#[test]
fn openssh_through_proxy_node_reaches_the_node_s_sshd() {
    let s = Session::start("proxy-node-openssh");
    if !crate::throughput_harness::found("ssh", &["-V"]) {
        eprintln!("did not run: no OpenSSH client here");
        return;
    }
    let Some(command) = node_in_front_of(&s, s.port) else { return };
    let proxy = command(&["proxy", "node://lab"]);
    let mut ssh = Command::new("ssh");
    ssh.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null"])
        .args(["-o", "LogLevel=ERROR", "-o"])
        .arg(format!("ProxyCommand={}", shell_line(&proxy)))
        .args(["tester@lab", "greet"]);
    // The ProxyCommand's variables are the proxy's: its HOME and cache, the
    // stand-in's CA, no proxy of this host.
    for (name, value) in proxy.get_envs() {
        match value {
            Some(value) => ssh.env(name, value),
            None => ssh.env_remove(name),
        };
    }
    let (code, out, err) = output_within(ssh, LIMIT);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, crate::ssh_harness::GREETING, "{err}");
}
