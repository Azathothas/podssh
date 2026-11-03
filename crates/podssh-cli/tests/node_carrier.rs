//! A carrier (T-595), through the binary: `podssh operator --carrier
//! exec:'podssh node --carrier stdio box TARGET' box`, the node at the other
//! end of a program's stdin and stdout, with no relay and no pair, as the
//! exec channel of a platform's own SSH gives them. The bytes of an echo
//! server come back whole and both ends exit 0; a node key that the pin of
//! `box` does not hold is refused with 77, and no byte of TARGET comes; a
//! program that ends at once is said, with 69, in time; the flags of a relay
//! and of a pair, and stdio for the operator, are refused with 64; a
//! terminal on the node's stdin is refused with 64 (Linux, in a pty); and
//! OpenSSH's client, with that operator as its ProxyCommand, logs in to
//! OpenSSH's sshd behind the node, or says that it did not run where this
//! host has no OpenSSH.

mod live_harness;
#[cfg(target_os = "linux")]
mod pty_harness;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use live_harness::{echo_server, scratch, LIMIT};

const BIN: &str = env!("CARGO_BIN_EXE_podssh");

/// Removes the scratch directory, with its keys, however the test ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Bytes from a fixed xorshift, so that a byte out of place shows.
fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// `exec:` of this binary's node on stdio, in front of `target`, with the
/// node's own `flags`: podssh's words, the binary's path in quotes.
fn node_exec(target: &str, flags: &str) -> String {
    assert!(!BIN.contains('\'') && !BIN.contains('"') && !BIN.contains('%'), "a path that the words cannot carry");
    format!("exec:'{BIN}' node --carrier stdio box {target} {flags}")
}

/// `podssh ARGS` in the scratch HOME, its node too, which inherits it.
fn podssh(home: &Path, args: &[&str]) -> Command {
    live_harness::command(home, args)
}

/// `cmd` with `input` on stdin, within `limit`: its code, stdout and stderr,
/// each pipe read to its end (a ProxyCommand holds OpenSSH's stderr until
/// it exits); a run past the limit is killed, and fails the test.
fn run_with(mut cmd: Command, input: Vec<u8>, limit: Duration) -> (Option<i32>, Vec<u8>, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let mut stdin = child.stdin.take().expect("stdin");
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let reader = |mut pipe: Box<dyn Read + Send>| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            let _ = tx.send(bytes);
        });
        rx
    };
    let out = reader(Box::new(child.stdout.take().expect("stdout")));
    let err = reader(Box::new(child.stderr.take().expect("stderr")));
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{cmd:?} did not end within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_secs(15));
    let (out, err) = (out.recv_timeout(left).unwrap_or_default(), err.recv_timeout(left).unwrap_or_default());
    (status.code(), out, String::from_utf8_lossy(&err).into_owned())
}

#[test]
fn an_operator_reaches_the_node_at_the_other_end_of_a_program_s_stdio() {
    let home = scratch("carrier-echo");
    let _scratch = Scratch(home.clone());
    let target = format!("127.0.0.1:{}", echo_server());
    let carrier = node_exec(&target, "");
    let sent = pattern(1 << 20);
    let (code, out, err) = run_with(podssh(&home, &["operator", "--carrier", &carrier, "box"]), sent.clone(), LIMIT);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out.len(), sent.len(), "{err}");
    assert!(out == sent, "the bytes came back changed: {err}");
    // The node's lines, on the operator's stderr, which it inherits.
    assert!(err.contains(&format!("podssh node: box: serving {target} over the carrier stdio")), "{err}");
    assert!(err.contains("podssh node: box: online"), "{err}");
    assert!(err.contains("podssh node: box: the carrier's client ended the stream"), "the node's end, 0: {err}");
    assert!(err.contains("is pinned at its first sight"), "the node's key, pinned under box: {err}");
}

#[test]
fn a_node_key_that_the_pin_does_not_hold_is_refused_with_77() {
    let home = scratch("carrier-pin");
    let _scratch = Scratch(home.clone());
    let target = format!("127.0.0.1:{}", echo_server());
    let key = home.join("node.key");
    let first = node_exec(&target, &format!("--key '{}'", key.display()));
    let (code, out, err) = run_with(podssh(&home, &["operator", "--carrier", &first, "box"]), b"one\n".to_vec(), LIMIT);
    assert_eq!((code, out.as_slice()), (Some(0), &b"one\n"[..]), "{err}");
    // A stream that another key answers: the pin of box refuses it.
    let other = node_exec(&target, "--ephemeral-key");
    let (code, out, err) = run_with(podssh(&home, &["operator", "--carrier", &other, "box"]), b"two\n".to_vec(), LIMIT);
    assert_eq!(code, Some(77), "{err}");
    assert!(out.is_empty(), "no byte of TARGET: {out:?}");
    assert!(err.contains("refused the node") && err.contains("pins"), "{err}");
}

#[test]
fn a_program_that_ends_at_once_is_said_with_69() {
    let home = scratch("carrier-gone");
    let _scratch = Scratch(home.clone());
    // `true` on Unix; a program that exits at once on each system.
    let program = if cfg!(windows) { "exec:cmd /c exit 0" } else { "exec:true" };
    let (code, out, err) = run_with(podssh(&home, &["operator", "--carrier", program, "box"]), Vec::new(), LIMIT);
    assert_eq!(code, Some(69), "{err}");
    assert!(out.is_empty(), "{out:?}");
    assert!(err.contains("it ended before a node read it"), "{err}");
}

#[test]
fn the_flags_of_a_relay_and_a_pair_and_stdio_for_an_operator_are_refused_with_64() {
    let home = scratch("carrier-flags");
    let _scratch = Scratch(home.clone());
    let refused: [&[&str]; 6] = [
        &["node", "box", "127.0.0.1:1", "--carrier", "exec:cat", "--iroh"],
        &["node", "box", "127.0.0.1:1", "--carrier", "exec:cat", "--pair-file", "x"],
        &["node", "box", "127.0.0.1:1", "--carrier", "exec:cat", "--install"],
        &["node", "box", "127.0.0.1:1", "--carrier", "tcp:127.0.0.1:1"],
        &["operator", "--carrier", "stdio", "box"],
        &["operator", "--carrier", "exec:cat", "--pair-file", "x", "box"],
    ];
    for args in refused {
        let (code, out, err) = run_with(podssh(&home, args), Vec::new(), LIMIT);
        assert_eq!(code, Some(64), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out:?}");
        assert!(err.contains("--carrier"), "{args:?}: {err}");
    }
}

/// A person's keys are not frames: a node of `--carrier stdio` started on a
/// terminal refuses at once.
#[cfg(target_os = "linux")]
#[test]
fn a_terminal_on_the_node_s_stdin_is_refused_with_64() {
    let home = scratch("carrier-tty");
    let _scratch = Scratch(home.clone());
    let pty = pty_harness::Pty::start(podssh(&home, &["node", "box", "127.0.0.1:1", "--carrier", "stdio"]), 24, 80);
    assert_eq!(pty.wait(LIMIT), Some(64), "{}", pty.text());
    assert!(pty.text().contains("stdin is a terminal"), "{}", pty.text());
}

/// OpenSSH at both ends: its client, with `podssh operator --carrier` as its
/// ProxyCommand, logs in to its sshd behind the node on the carrier, as the
/// tester's agent wanted it (GitHub #124). Unix's: OpenSSH for Windows takes
/// no command line of a shell for a ProxyCommand.
#[cfg(unix)]
#[test]
fn openssh_logs_in_to_its_sshd_through_a_node_on_a_carrier() {
    let home = scratch("carrier-openssh");
    let _scratch = Scratch(home.clone());
    let found = Command::new("ssh").arg("-V").stdin(Stdio::null()).output().is_ok_and(|o| o.status.success());
    if !found {
        eprintln!("did not run: no OpenSSH client here");
        return;
    }
    let key = home.join("id");
    let made = podssh(&home, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &key.display().to_string()]).output();
    assert!(made.is_ok_and(|o| o.status.success()), "podssh keygen");
    let sshd = match live_harness::sshd::start(&home, &key.with_extension("pub")) {
        Ok(sshd) => sshd,
        Err(why) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    // The ProxyCommand runs in OpenSSH's shell: each word of podssh's in
    // quotes, and the node's words in the quotes of exec:.
    let carrier = node_exec(&format!("127.0.0.1:{}", sshd.port), "");
    let proxy = format!("'{BIN}' operator --carrier \"{carrier}\" box");
    let mut ssh = Command::new("ssh");
    ssh.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"])
        .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
        .arg("-i")
        .arg(&key)
        .arg("-o")
        .arg(format!("ProxyCommand={proxy}"))
        .args([format!("{}@box", live_harness::this_user()).as_str(), "echo carried"]);
    // The ProxyCommand's variables are podssh's: its HOME and its cache.
    let podssh_env = podssh(&home, &[]);
    for (name, value) in podssh_env.get_envs() {
        match value {
            Some(value) => ssh.env(name, value),
            None => ssh.env_remove(name),
        };
    }
    let (code, out, err) = run_with(ssh, Vec::new(), LIMIT);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out), "carried\n", "{err}");
}
