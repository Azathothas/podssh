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
//! host has no OpenSSH; so does `podssh proxy --carrier ... node://box`, the
//! same pipe, which carries the echo server's bytes whole too, and whose
//! open `--ConnectTimeout` bounds (Unix). podssh's own clients take it:
//! `podssh ssh --carrier ... node://USER@box` runs a command on that sshd;
//! `cp` up and down, `scp` up and `sftp`'s put and get agree with the disk,
//! through the sshd's own SFTP; and a client's carrier beside a flag of
//! another road, stdio, or a destination that is no node is refused with 64.

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
    let refused: [&[&str]; 9] = [
        &["node", "box", "127.0.0.1:1", "--carrier", "exec:cat", "--iroh"],
        &["node", "box", "127.0.0.1:1", "--carrier", "exec:cat", "--pair-file", "x"],
        &["node", "box", "127.0.0.1:1", "--carrier", "exec:cat", "--install"],
        &["node", "box", "127.0.0.1:1", "--carrier", "tcp:127.0.0.1:1"],
        &["operator", "--carrier", "stdio", "box"],
        &["operator", "--carrier", "exec:cat", "--pair-file", "x", "box"],
        // proxy node://NAME takes operator's checks, and a node alone (T-587).
        &["proxy", "--carrier", "stdio", "node://box"],
        &["proxy", "--carrier", "exec:cat", "--pair-file", "x", "node://box"],
        &["proxy", "--carrier", "exec:cat", "example.org", "22"],
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

/// OpenSSH at both ends: its client, with `podssh operator --carrier`, then
/// `podssh proxy --carrier ... node://box`, as its ProxyCommand, logs in to
/// its sshd behind the node on the carrier, as the tester's agent wanted it
/// (GitHub #124). Unix's: OpenSSH for Windows takes no command line of a
/// shell for a ProxyCommand.
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
    // quotes, and the node's words in the quotes of exec:. operator NAME,
    // then proxy node://NAME, its form of a destination (T-587).
    let carrier = node_exec(&format!("127.0.0.1:{}", sshd.port), "");
    for proxy in [
        format!("'{BIN}' operator --carrier \"{carrier}\" box"),
        format!("'{BIN}' proxy --carrier \"{carrier}\" node://box"),
    ] {
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
        assert_eq!(code, Some(0), "{proxy}: {err}");
        assert_eq!(String::from_utf8_lossy(&out), "carried\n", "{proxy}: {err}");
    }
}

/// `podssh proxy --carrier ... node://box`, the pipe of `operator --carrier`
/// by the form of a destination: an echo server's bytes come back whole, and
/// the node hears the Close.
#[test]
fn proxy_reaches_the_node_at_the_other_end_of_a_program_s_stdio() {
    let home = scratch("carrier-proxy");
    let _scratch = Scratch(home.clone());
    let target = format!("127.0.0.1:{}", echo_server());
    let carrier = node_exec(&target, "");
    let sent = pattern(1 << 20);
    let proxy = podssh(&home, &["proxy", "--carrier", &carrier, "node://box"]);
    let (code, out, err) = run_with(proxy, sent.clone(), LIMIT);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out.len(), sent.len(), "{err}");
    assert!(out == sent, "the bytes came back changed: {err}");
    assert!(err.contains("podssh node: box: the carrier's client ended the stream"), "the node's end, 0: {err}");
}

/// `pipe`'s node: side on a carrier: an echo server's bytes come back whole,
/// as through `operator --carrier`, and the node hears the Close at the end.
#[test]
fn pipe_s_node_side_reaches_the_node_at_the_other_end_of_a_carrier() {
    let home = scratch("carrier-pipe");
    let _scratch = Scratch(home.clone());
    let carrier = node_exec(&format!("127.0.0.1:{}", echo_server()), "");
    let sent = pattern(1 << 20);
    let pipe = podssh(&home, &["pipe", "-", "node:box", "--carrier", &carrier]);
    let (code, out, err) = run_with(pipe, sent.clone(), LIMIT);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out.len(), sent.len(), "{err}");
    assert!(out == sent, "the bytes came back changed: {err}");
    assert!(err.contains("podssh node: box: the carrier's client ended the stream"), "the node's end, 0: {err}");
}

/// A run that is ended however its test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A listening side on a carrier: each client is a session of its own on
/// the one stream, so one node, started once, serves both, each client's
/// bytes back whole.
#[test]
fn each_client_of_a_listening_pipe_is_a_session_of_the_one_stream() {
    let home = scratch("carrier-listen");
    let _scratch = Scratch(home.clone());
    let carrier = node_exec(&format!("127.0.0.1:{}", echo_server()), "");
    let args = ["pipe", "tcp-listen:127.0.0.1:0", "node:box", "--carrier", carrier.as_str(), "--keep-listening"];
    let mut cmd = podssh(&home, &args);
    let child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("it runs");
    let mut pipe = Running(child);
    let lines = live_harness::lines_of(&mut pipe.0);
    let mut said = Vec::new();
    let at = loop {
        let line = lines.recv_timeout(LIMIT).unwrap_or_else(|_| panic!("no line of where it listens: {said:#?}"));
        said.push(line.clone());
        if let Some(rest) = line.split("listening on ").nth(1) {
            break rest.split(": ").next().unwrap_or_default().to_string();
        }
    };
    for len in [64 * 1024, 256 * 1024] {
        let sent = pattern(len);
        let stream = std::net::TcpStream::connect(&at).expect("the pipe takes a client");
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        let mut reader = stream.try_clone().unwrap();
        let to_send = sent.clone();
        let writing = std::thread::spawn(move || {
            let mut stream = stream;
            let _ = stream.write_all(&to_send);
            stream
        });
        let mut got = vec![0u8; len];
        if let Err(e) = reader.read_exact(&mut got) {
            panic!("the client of {len} bytes: {e}: {said:#?}");
        }
        assert!(got == sent, "the client of {len} bytes: the bytes came back changed");
        // The client goes, and its session with it.
        drop(writing.join());
        drop(reader);
    }
    drop(pipe);
    while let Ok(line) = lines.recv_timeout(Duration::from_secs(2)) {
        said.push(line);
    }
    let online = said.iter().filter(|line| line.contains("podssh node: box: online")).count();
    assert_eq!(online, 1, "one node, on the one stream, for both clients: {said:#?}");
}

/// `--ConnectTimeout` bounds the open on a carrier too: a program that never
/// starts a node is said at the bound, with 69, as a node out of reach.
#[cfg(unix)]
#[test]
fn the_bound_of_connect_timeout_holds_on_a_carrier() {
    let home = scratch("carrier-bound");
    let _scratch = Scratch(home.clone());
    let args = ["proxy", "--carrier", "exec:sleep 5", "--ConnectTimeout", "1", "node://box"];
    let started = Instant::now();
    let (code, out, err) = run_with(podssh(&home, &args), Vec::new(), LIMIT);
    assert_eq!(code, Some(69), "{err}");
    assert!(out.is_empty(), "{out:?}");
    assert!(err.contains("the carrier's node did not read the stream within 1 s (--ConnectTimeout)"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(30), "the bound, not the program, ended the run: {err}");
}

/// A TARGET that takes each connection and closes it at once.
fn closing_server() -> u16 {
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in server.incoming().map_while(Result::ok) {
            drop(stream);
        }
    });
    port
}

/// `podssh ssh --carrier` starts the node of its carrier, on each host, and
/// ends it: a TARGET that speaks no SSH fails the login (255), and the node,
/// online, hears the client's Close at the end, as it does after a login.
#[test]
fn podssh_ssh_starts_the_node_of_its_carrier_and_closes_it_at_the_end() {
    let home = scratch("carrier-ssh-start");
    let _scratch = Scratch(home.clone());
    let carrier = node_exec(&format!("127.0.0.1:{}", closing_server()), "");
    let args = ["ssh", "-o", "BatchMode=yes", "--carrier", carrier.as_str(), "node://tester@box", "true"];
    let (code, out, err) = run_with(podssh(&home, &args), Vec::new(), LIMIT);
    assert_eq!(code, Some(255), "{err}");
    assert!(out.is_empty(), "{out:?}");
    assert!(err.contains("podssh node: box: online"), "the node of the carrier: {err}");
    assert!(err.contains("podssh node: box: the carrier's client ended the stream"), "the node's end, 0: {err}");
}

/// A key of the test, and OpenSSH's sshd that takes it, with the server's
/// own SFTP when `sftp`; `None`, said, where this host has no sshd.
#[cfg(unix)]
fn openssh_server(home: &Path, sftp: bool) -> Option<(PathBuf, live_harness::sshd::Sshd)> {
    let key = home.join("id");
    let made = podssh(home, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &key.display().to_string()]).output();
    assert!(made.is_ok_and(|o| o.status.success()), "podssh keygen");
    let more = if sftp { "Subsystem sftp internal-sftp\n" } else { "" };
    match live_harness::sshd::start_with(home, &key.with_extension("pub"), more) {
        Ok(sshd) => Some((key, sshd)),
        Err(why) => {
            eprintln!("did not run: {why}");
            None
        }
    }
}

/// `verb`'s words of a login of podssh's client with `key`, the host key
/// recorded in the scratch HOME, and the node at the other end of
/// `carrier`, then `rest`.
#[cfg(unix)]
fn carried(verb: &str, home: &Path, key: &Path, carrier: &str, rest: &[&str]) -> Command {
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let key = key.display().to_string();
    let mut words: Vec<&str> = vec![verb, "-i", key.as_str(), "-o", "IdentitiesOnly=yes"];
    words.extend(["-o", "StrictHostKeyChecking=accept-new", "-o", known.as_str(), "-o", "BatchMode=yes"]);
    words.extend(["--carrier", carrier]);
    words.extend(rest.iter().copied());
    podssh(home, &words)
}

/// podssh's own client on the carrier, to OpenSSH's sshd behind the node:
/// the command runs, and at the end the node hears the client's Close.
#[cfg(unix)]
#[test]
fn podssh_ssh_runs_a_command_on_openssh_s_sshd_through_a_node_on_a_carrier() {
    let home = scratch("carrier-ssh");
    let _scratch = Scratch(home.clone());
    let Some((key, sshd)) = openssh_server(&home, false) else { return };
    let carrier = node_exec(&format!("127.0.0.1:{}", sshd.port), "");
    let destination = format!("node://{}@box", live_harness::this_user());
    let ssh = carried("ssh", &home, &key, &carrier, &["-T", destination.as_str(), "echo carried"]);
    let (code, out, err) = run_with(ssh, Vec::new(), LIMIT);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out), "carried\n", "{err}");
    assert!(err.contains("podssh node: box: online"), "{err}");
    assert!(err.contains("podssh node: box: the carrier's client ended the stream"), "the node's end, 0: {err}");
}

/// cp up and down, scp up, and sftp's put and get, each on a node that the
/// run's own stream starts, through the sshd's own SFTP: each file as it was.
#[cfg(unix)]
#[test]
fn the_copies_reach_openssh_s_sshd_through_a_node_on_a_carrier() {
    let home = scratch("carrier-copy");
    let _scratch = Scratch(home.clone());
    let Some((key, sshd)) = openssh_server(&home, true) else { return };
    let carrier = node_exec(&format!("127.0.0.1:{}", sshd.port), "");
    let path = |name: &str| home.join(name).display().to_string();
    assert!(!path("x").contains(' '), "a path that the batch of sftp cannot carry");
    let user = live_harness::this_user();
    let far = |name: &str| format!("node://{user}@box:{}", path(name));
    let want = pattern(300_000);
    std::fs::write(path("here.bin"), &want).unwrap();
    let copy = |verb: &str, rest: &[&str]| run_with(carried(verb, &home, &key, &carrier, rest), Vec::new(), LIMIT);
    let (here, there) = (path("here.bin"), far("there.bin"));
    let (code, _, err) = copy("cp", &[here.as_str(), there.as_str()]);
    assert_eq!(code, Some(0), "cp up: {err}");
    assert!(std::fs::read(path("there.bin")).unwrap() == want, "cp up: {err}");
    assert!(err.contains("podssh node: box: the carrier's client ended the stream"), "the node's end: {err}");
    let back = path("back.bin");
    let (code, _, err) = copy("cp", &[there.as_str(), back.as_str()]);
    assert_eq!(code, Some(0), "cp down: {err}");
    assert!(std::fs::read(&back).unwrap() == want, "cp down: {err}");
    let scp = far("scp.bin");
    let (code, _, err) = copy("scp", &[here.as_str(), scp.as_str()]);
    assert_eq!(code, Some(0), "scp up: {err}");
    assert!(std::fs::read(path("scp.bin")).unwrap() == want, "scp up: {err}");
    let (put, got, batch) = (path("put.bin"), path("got.bin"), path("batch"));
    std::fs::write(&batch, format!("put {here} {put}\nget {put} {got}\n")).unwrap();
    let node = format!("node://{user}@box");
    let (code, out, err) = copy("sftp", &["-b", batch.as_str(), node.as_str()]);
    assert_eq!(code, Some(0), "sftp: {err}");
    assert!(String::from_utf8_lossy(&out).contains("sftp> put "), "{err}");
    assert!(std::fs::read(&put).unwrap() == want, "sftp's put: {err}");
    assert!(std::fs::read(&got).unwrap() == want, "sftp's get: {err}");
}

/// A client's carrier is its node's one road: a flag of another road, stdio
/// (the client's own), a kind that is no stream, and a destination that is
/// no node are refused before anything starts.
#[test]
fn a_client_s_carrier_takes_no_other_road_and_reaches_a_node_alone() {
    let home = scratch("carrier-client-flags");
    let _scratch = Scratch(home.clone());
    let a = home.join("a");
    std::fs::write(&a, b"a").unwrap();
    let a = a.display().to_string();
    let refused: [&[&str]; 11] = [
        &["pipe", "-", "node:box", "--carrier", "stdio"],
        &["pipe", "-", "tcp:127.0.0.1:1", "--carrier", "exec:cat"],
        &["pipe", "-", "node:box", "--carrier", "exec:cat", "--pair-file", "x"],
        &["ssh", "--carrier", "stdio", "node://tester@box", "true"],
        &["ssh", "--carrier", "exec:cat", "--pair-file", "x", "node://tester@box", "true"],
        &["ssh", "--carrier", "exec:cat", "--direct", "node://tester@box", "true"],
        &["ssh", "--carrier", "exec:cat", "--derp-server", "derp.example", "node://tester@box", "true"],
        &["ssh", "--carrier", "exec:cat", "tester@example.org", "true"],
        &["ssh", "--carrier", "exec:cat", "--exit", "gw", "tester@example.org", "true"],
        &["cp", "--carrier", "exec:cat", "--relay-host", "relay.example", a.as_str(), "node://tester@box:x"],
        &["scp", "--carrier", "tcp:127.0.0.1:1", a.as_str(), "node://tester@box:x"],
    ];
    for args in refused {
        let (code, out, err) = run_with(podssh(&home, args), Vec::new(), LIMIT);
        assert_eq!(code, Some(64), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out:?}");
        assert!(err.contains("--carrier"), "{args:?}: {err}");
    }
}
