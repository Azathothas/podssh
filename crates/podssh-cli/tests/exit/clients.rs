//! The exit over a carrier for `ssh`, `proxy` and `pipe` (T-614, the
//! operator's ruling Q90), beside the tests of `exit --listen --carrier`:
//! each command starts the node of the role exit as the program of its
//! `--carrier exec:`, `podssh node gw --exit --carrier stdio`, with no relay
//! and no pair, and carries its own session through the node's egress, by
//! the net's rule. `ssh` starts and closes the node on each host, before a
//! host that speaks no SSH, and where this host has OpenSSH's sshd (Unix)
//! runs a command there and copies a file up with `scp`; `proxy` and `pipe`
//! carry an echo server's 1 MiB back whole; a member that no rule names is
//! refused, and its target is never dialled.

use std::time::Instant;

use super::*;

/// The bound on each run of a client, which starts its node first.
const RUN_LIMIT: Duration = Duration::from_secs(90);

/// The net of a test, in a scratch HOME: the exit gw, whose net gives it the
/// role exit; a, whom a rule lets out and lets reach the loopback's range;
/// and c, a member whom no rule names. Each end takes the owner's document.
struct Exit {
    scratch: Scratch,
    doc: PathBuf,
    gw_key: String,
    a_key: String,
    c_key: String,
}

impl Exit {
    fn new(tag: &str) -> Exit {
        let scratch = Scratch(throughput_harness::scratch(tag));
        let home = scratch.0.clone();
        let dir = home.join("private");
        podssh_relay::cache::private_dir(&dir).unwrap();
        let ((gw_key, gw), (a_key, a), (c_key, c)) =
            (key_file(&dir, "gw.key", 0x52), key_file(&dir, "a.key", 0x62), key_file(&dir, "c.key", 0x72));
        let owner = owner_key(&dir).display().to_string();
        let owner_doc = dir.join("owner.doc");
        let owner_says = |args: &[&str]| {
            let mut args = args.to_vec();
            args.extend(["--owner-key", owner.as_str()]);
            let (rc, _, err) = net(&home, &owner_doc, &args);
            assert_eq!(rc, 0, "{args:?}: {err}");
        };
        owner_says(&["net", "init", "home"]);
        owner_says(&["net", "add", "gw", &gw, "--roles", "node,exit"]);
        owner_says(&["net", "add", "a", &a]);
        owner_says(&["net", "add", "c", &c]);
        let policy = dir.join("policy.json");
        std::fs::write(&policy, r#"{"rules": [{"from": ["a"], "to": ["exit:gw", "127.0.0.1/32"]}]}"#).unwrap();
        owner_says(&["net", "policy", "set", &policy.display().to_string()]);
        let (given, doc) = (dir.join("given.doc"), dir.join("net.doc"));
        std::fs::copy(&owner_doc, &given).unwrap();
        let (rc, _, err) = net(&home, &doc, &["net", "take", &given.display().to_string()]);
        assert_eq!(rc, 0, "net take: {err}");
        Exit { scratch, doc, gw_key, a_key, c_key }
    }

    fn home(&self) -> &Path {
        &self.scratch.0
    }

    /// `exec:` of this binary's node gw of the role exit on its stdio, with
    /// no TARGET of its own and the loopback's range in `--routes`.
    fn node(&self) -> String {
        let bin = env!("CARGO_BIN_EXE_podssh");
        assert!(![bin, self.gw_key.as_str()].iter().any(|w| w.contains('\'')), "a path that the words cannot carry");
        format!("exec:'{bin}' node gw --exit --routes 127.0.0.1/32 --key '{}' --carrier stdio", self.gw_key)
    }

    /// `podssh VERB --exit gw --client-key KEY --carrier NODE REST`, in the
    /// scratch HOME with the net's document and no proxy of this machine's,
    /// which the node inherits: the exit dials the loopback itself.
    fn client<S: AsRef<str>>(&self, verb: &str, key: &str, rest: &[S]) -> Command {
        let node = self.node();
        let head = [verb, "--exit", "gw", "--client-key", key, "--carrier", node.as_str()];
        let words: Vec<String> = head.into_iter().chain(rest.iter().map(|w| w.as_ref())).map(str::to_string).collect();
        let mut cmd = without_proxy(command_in(self.home(), &words));
        cmd.env("PODSSH_NET", &self.doc);
        cmd
    }
}

/// `cmd` with `input` on stdin, within [`RUN_LIMIT`]: its code, stdout and
/// stderr, each pipe read to its end (the node writes to the same stderr);
/// a run past the limit is killed, and fails the test.
fn within(mut cmd: Command, input: Vec<u8>) -> (Option<i32>, Vec<u8>, String) {
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
    let deadline = Instant::now() + RUN_LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{cmd:?} did not end within {RUN_LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let left = Duration::from_secs(15);
    let (out, err) = (out.recv_timeout(left).unwrap_or_default(), err.recv_timeout(left).unwrap_or_default());
    (status.code(), out, String::from_utf8_lossy(&err).into_owned())
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

/// An echo server on the loopback, for each connection while the test runs:
/// its port, and the count of its connections.
fn echo() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            counted.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut reader = stream.try_clone().unwrap();
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
            });
        }
    });
    (port, count)
}

/// A host that takes each connection and closes it at once, as one that
/// speaks no SSH.
fn closing_server() -> u16 {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in server.incoming().map_while(Result::ok) {
            drop(stream);
        }
    });
    port
}

/// `podssh ssh --exit gw --carrier exec:'podssh node gw --exit --carrier
/// stdio'`: the node of the stream dials the host from its own host. On each
/// host, a host that speaks no SSH: the login fails (255), the node said its
/// exit and online, and hears the client's Close at the end; c, whom no rule
/// names, is refused by the node. Then, where this host has OpenSSH's sshd
/// (Unix), a command runs there and `scp` copies a file there whole.
#[test]
fn ssh_reaches_a_host_through_the_exit_at_the_other_end_of_a_carrier() {
    let exit = Exit::new("exit-carrier-ssh");
    let port = closing_server().to_string();
    let asked = ["-o", "BatchMode=yes", "-p", port.as_str(), "tester@127.0.0.1", "true"];
    let (code, out, err) = within(exit.client("ssh", &exit.a_key, &asked), Vec::new());
    assert_eq!(code, Some(255), "{err}");
    assert!(out.is_empty(), "{out:?}");
    assert!(err.contains("podssh node: gw: an exit of the net home as gw"), "the node of the carrier: {err}");
    assert!(err.contains("podssh node: gw: online"), "{err}");
    assert!(!err.contains("lets a reach"), "a's rule lets it out: {err}");
    assert!(err.contains("podssh node: gw: the carrier's client ended the stream"), "the node's end, 0: {err}");
    // c: no rule names it, so the node refuses it before any dial.
    let (code, _, err) = within(exit.client("ssh", &exit.c_key, &asked), Vec::new());
    assert!(code == Some(255) && err.contains("lets c reach"), "{code:?}: {err}");
    #[cfg(unix)]
    openssh(&exit);
}

/// OpenSSH's sshd behind the exit, where this host has one: `ssh` runs a
/// command, with the host key recorded under the host's own name, and `scp`
/// copies a file up whole, each on a node that its own stream starts.
#[cfg(unix)]
fn openssh(exit: &Exit) {
    let home = exit.home();
    let key = home.join("id");
    let words: Vec<String> = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f"].iter().map(|w| w.to_string()).collect();
    let mut keygen = command_in(home, &words);
    keygen.arg(&key);
    let (rc, _, err) = ran(&mut keygen);
    assert_eq!(rc, 0, "podssh keygen: {err}");
    // The server's own SFTP, for scp, which needs no sftp-server here.
    let sftp = "Subsystem sftp internal-sftp\n";
    let sshd = match live_harness::sshd::start_with(home, &key.with_extension("pub"), sftp) {
        Ok(sshd) => sshd,
        Err(why) => return eprintln!("did not run: {why}"),
    };
    let (port, known) = (sshd.port.to_string(), home.join("known_hosts"));
    let destination = format!("{}@127.0.0.1", live_harness::this_user());
    let ssh = login(&key, &known, &["-p", port.as_str(), "-T", destination.as_str(), "echo carried"]);
    let (code, out, err) = within(exit.client("ssh", &exit.a_key, &ssh), Vec::new());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out), "carried\n", "{err}");
    assert!(err.contains("podssh node: gw: the carrier's client ended the stream"), "the node's end, 0: {err}");
    let recorded = std::fs::read_to_string(&known).unwrap_or_default();
    assert!(recorded.contains("127.0.0.1") && !recorded.contains("node://"), "the host's key, by name: {recorded}");
    // The copies take the same road (`cp/link.rs`), each connection a leg.
    let (here, there) = (home.join("here.bin"), home.join("there.bin"));
    let want = pattern(300_000);
    std::fs::write(&here, &want).unwrap();
    let (from, far) = (here.display().to_string(), format!("{destination}:{}", there.display()));
    let scp = login(&key, &known, &["-P", port.as_str(), from.as_str(), far.as_str()]);
    let (code, _, err) = within(exit.client("scp", &exit.a_key, &scp), Vec::new());
    assert_eq!(code, Some(0), "scp up: {err}");
    assert!(std::fs::read(&there).unwrap_or_default() == want, "scp up, the file whole: {err}");
}

/// The words of a login of podssh's client with `key`, the host key
/// recorded in `known`, then `rest`.
#[cfg(unix)]
fn login(key: &Path, known: &Path, rest: &[&str]) -> Vec<String> {
    let mut words = vec!["-i".to_string(), key.display().to_string(), "-o".into(), "IdentitiesOnly=yes".into()];
    let known = format!("UserKnownHostsFile={}", known.display());
    for option in ["BatchMode=yes", "StrictHostKeyChecking=accept-new", known.as_str()] {
        words.extend(["-o".to_string(), option.to_string()]);
    }
    words.extend(rest.iter().map(|w| w.to_string()));
    words
}

/// `podssh proxy --exit gw --carrier exec:... 127.0.0.1 PORT`: an echo
/// server's 1 MiB, through the node's egress, back whole, and the node hears
/// the Close; c, whom no rule names, is refused, and its target never
/// dialled.
#[test]
fn proxy_carries_its_pipe_from_the_exit_at_the_other_end_of_a_carrier() {
    let exit = Exit::new("exit-carrier-proxy");
    let (port, dials) = echo();
    let target = ["127.0.0.1".to_string(), port.to_string()];
    let sent = pattern(1 << 20);
    let (code, out, err) = within(exit.client("proxy", &exit.a_key, &target), sent.clone());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out.len(), sent.len(), "{err}");
    assert!(out == sent, "the bytes came back changed: {err}");
    assert!(err.contains("podssh node: gw: online"), "the node of the carrier: {err}");
    assert!(err.contains("podssh node: gw: the carrier's client ended the stream"), "the node's end, 0: {err}");
    let before = dials.load(Ordering::SeqCst);
    let (code, out, err) = within(exit.client("proxy", &exit.c_key, &target), b"no\n".to_vec());
    assert!(code != Some(0) && out.is_empty(), "c went out: {code:?} {err}");
    assert!(err.contains("lets c reach"), "the refusal names the rules: {err}");
    assert_eq!(dials.load(Ordering::SeqCst), before, "the exit dialled a target for a member with no rule");
}

/// `podssh pipe - relay:127.0.0.1:PORT --exit gw --carrier exec:...`: the
/// relay: side starts at the exit at the other end of the stream, and the
/// echo server's 1 MiB comes back whole; the node hears the Close at the end.
#[test]
fn pipe_s_relay_side_starts_at_the_exit_at_the_other_end_of_a_carrier() {
    let exit = Exit::new("exit-carrier-pipe");
    let (port, _) = echo();
    let sides = ["-".to_string(), format!("relay:127.0.0.1:{port}")];
    let sent = pattern(1 << 20);
    let (code, out, err) = within(exit.client("pipe", &exit.a_key, &sides), sent.clone());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out.len(), sent.len(), "{err}");
    assert!(out == sent, "the bytes came back changed: {err}");
    assert!(err.contains("podssh node: gw: the carrier's client ended the stream"), "the node's end, 0: {err}");
}
