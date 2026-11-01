//! The DERP road of the command line from end to end (T-379), on this
//! machine's loopback: two stand-in DERP servers (podssh-relay's, behind TLS
//! of the test's own CA, `derp_support`), an SSH server for the node's
//! TARGET, `podssh node --derp` with an allowlist, and `podssh ssh
//! derp:TICKET`. The client is refused and says its key; once that key is in
//! the allowlist, the same command logs in. With the pair's road blocked,
//! `node://NAME --derp-ticket` takes the DERP road, and a later run with no
//! ticket falls back on the one that it kept. A node with no pair serves the
//! road unasked. When the node's home goes away, the node moves to the next
//! server and says its new ticket, and a client of the old ticket finds it
//! there; a client that tries the ticket's server alone does not.

mod cleanup;
mod derp_support;
mod ssh_harness;
// The TLS acceptor of the test's own CA.
#[path = "update_support/mod.rs"]
mod update_support;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use derp_support::Front;
use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use ssh_harness::GREETING;

const LIMIT: Duration = Duration::from_secs(60);

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-derp-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Private, as a user's own directory is: the node refuses an allowlist
    // that others can change.
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, and none of the
/// settings of the machine that runs the test.
fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in [
        "PODSSH_OFFLINE",
        "PODSSH_DERP",
        "PODSSH_DERP_SERVER",
        "PODSSH_RELAY",
        "PODSSH_RELAY_ADDR",
        "SSL_CERT_FILE",
        "SSH_AUTH_SOCK",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// Run `podssh ARGS` to its end, within the limit: (code, stdout, stderr).
fn run(cmd: &mut Command) -> (i32, String, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh did not end within {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("output");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// Kills the node when the test ends, as it ends.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The node's stderr, a line at a time.
fn lines_of(node: &mut Child) -> mpsc::Receiver<String> {
    let stderr = node.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
}

/// The lines of `lines` up to the first that holds `needle`, that one last,
/// within the limit.
fn wait_for(lines: &mpsc::Receiver<String>, needle: &str) -> Vec<String> {
    let deadline = Instant::now() + LIMIT;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) => {
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return seen;
                }
            }
            Err(_) => panic!("no line with {needle:?} from the node within {} s: {seen:#?}", LIMIT.as_secs()),
        }
    }
}

/// The word that starts at `derp:` in the line of `seen` that holds `needle`.
fn ticket_in(seen: &[String], needle: &str) -> String {
    let line = seen.iter().find(|l| l.contains(needle)).unwrap_or_else(|| panic!("no {needle:?}: {seen:#?}"));
    let at = line.find(needle).unwrap() + needle.len() - "derp:".len();
    line[at..].split_whitespace().next().unwrap().to_string()
}

/// The place of one test: its runtime, which serves the stand-ins and the
/// SSH server; two DERP servers; the node's home and the client's.
struct Lab {
    runtime: tokio::runtime::Runtime,
    a: Front,
    b: Front,
    ca: String,
    target: String,
    node_home: PathBuf,
    client_home: PathBuf,
    allow: PathBuf,
    client_key: String,
    known: String,
}

impl Lab {
    fn new(name: &str) -> Lab {
        let home = scratch(name);
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let (acceptor, ca) = update_support::acceptor(&home, &["127.0.0.1"]);
        let (a, b) = runtime.block_on(async { (Front::start(acceptor.clone()).await, Front::start(acceptor).await) });
        let host_key = home.join("host_key");
        let host_key_text = host_key.to_string_lossy().into_owned();
        let (rc, _, err) = run(&mut command(&home, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key_text]));
        assert_eq!(rc, 0, "{err}");
        let port = runtime.block_on(ssh_harness::start(&host_key));
        let (node_home, client_home) = (home.join("node"), home.join("client"));
        for dir in [&node_home, &client_home] {
            podssh_relay::cache::private_dir(dir).unwrap();
        }
        let allow = node_home.join("allow");
        std::fs::write(&allow, "# the client keys that may come in\n").unwrap();
        Lab {
            runtime,
            a,
            b,
            ca: ca.to_string_lossy().into_owned(),
            target: format!("127.0.0.1:{port}"),
            client_key: client_home.join("client.key").to_string_lossy().into_owned(),
            known: client_home.join("known_hosts").to_string_lossy().into_owned(),
            node_home,
            client_home,
            allow,
        }
    }

    /// The servers of the list, A first.
    fn servers(&self) -> String {
        format!("{},{}", self.a.server(), self.b.server())
    }

    /// `podssh node lab TARGET` with `extra`, its lines, and the lines up to
    /// its ticket.
    fn node(&self, extra: &[&str]) -> (Node, mpsc::Receiver<String>, Vec<String>) {
        let allow = self.allow.to_string_lossy().into_owned();
        let key = self.node_home.join("node.key").to_string_lossy().into_owned();
        let mut args = vec!["node", "lab", &self.target, "--allow", &allow, "--key", &key, "--ca-file", &self.ca];
        args.extend_from_slice(extra);
        let mut child = command(&self.node_home, &args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let lines = lines_of(&mut child);
        let node = Node(child);
        let started = wait_for(&lines, "ticket derp:");
        (node, lines, started)
    }

    /// `podssh ssh` from the client's home, with its key and known hosts.
    fn ssh(&self, words: &[&str]) -> Command {
        let mut args = vec![
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "--ca-file",
            &self.ca,
            "--client-key",
            &self.client_key,
        ];
        let known = format!("UserKnownHostsFile={}", self.known);
        args.extend_from_slice(&["-o", &known]);
        args.extend_from_slice(words);
        command(&self.client_home, &args)
    }

    /// The client's key, made now, as its allowlist's line.
    fn client_fingerprint(&self) -> String {
        let key = file::load(&Place::File(PathBuf::from(&self.client_key)), &mut OsEntropy).expect("the key");
        key.identity.public().fingerprint()
    }

    /// Let the client's key in, as the node's operator does.
    fn let_in(&self) {
        let mut list = std::fs::OpenOptions::new().append(true).open(&self.allow).unwrap();
        writeln!(list, "{} the test's client", self.client_fingerprint()).unwrap();
    }
}

#[test]
fn a_client_is_refused_then_let_in_and_runs_a_command_over_the_derp_road() {
    let lab = Lab::new("e2e");
    let (_node, lines, started) = lab.node(&["--derp", "--derp-server", &lab.servers()]);
    let ticket = ticket_in(&started, "ticket derp:");
    let key_line = started.iter().find(|l| l.contains(", the node derp:")).expect("the node's key line").clone();
    assert!(started.iter().any(|l| l.contains(&format!("home {}", lab.a.server()))), "A is home: {started:#?}");
    let destination = format!("tester@{ticket}");
    let servers = lab.servers();

    // Refused: the client's key is in no allowlist yet.
    let (rc, out, err) = run(&mut lab.ssh(&["--derp-server", &servers, &destination, "greet"]));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    let key = lab.client_fingerprint();
    assert!(err.contains(&format!("refused this client's key {key}")), "the client names its key: {err}");
    let refused = wait_for(&lines, "refused the operator key");
    assert!(refused.last().unwrap().contains(&key), "the node names the key: {refused:#?}");

    // The node's operator adds the key; the node reads the file again.
    lab.let_in();
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--derp-server", &servers, &destination, "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("over the DERP road"), "-v names the road: {err}");
    let hex = key_line.split(", the node derp:").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
    assert_eq!(hex.len(), 64, "{key_line}");
    let recorded = std::fs::read_to_string(&lab.known).unwrap();
    assert!(recorded.contains(&format!("derp:{hex}")), "the host key is under the node's key: {recorded}");
    assert!(lab.a.stand_in.logins.load(std::sync::atomic::Ordering::SeqCst) >= 3, "the node and two clients");
    drop(lab.runtime);
}

#[test]
fn with_the_pair_s_road_blocked_the_race_gives_the_session_to_the_derp_road() {
    let lab = Lab::new("race");
    lab.let_in();
    let (_node, _lines, started) = lab.node(&["--derp", "--derp-server", &lab.servers()]);
    let ticket = ticket_in(&started, "ticket derp:");
    // The client's pair: its relay is a port of the loopback where nothing
    // listens, so the pair's road fails at once.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let relay = podssh_relay::relay::Relay { host: "127.0.0.1".into(), port: closed };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    // The repository's fixture form of a token, which names no credential.
    let token = |kind: &str| format!("testonly{kind}{}", "0".repeat(56 - kind.len()));
    let body = serde_json::json!({
        "name": "p-0123456789abcdef0123456789abcdef",
        "node_token": token("node"),
        "connect_token": token("connect"),
        "stop_token": token("stop"),
        "expires": now + 72 * 3600 * 1000,
    });
    let pair = podssh_relay::pair::parse(&relay, body.to_string().as_bytes(), now).expect("a test pair");
    let cache = lab.client_home.join("cache").join("podssh");
    podssh_relay::pair::store_in_first(&[cache], "lab", &pair).expect("the pair stored");
    let servers = lab.servers();

    let (rc, out, err) =
        run(&mut lab.ssh(&["-v", "--derp-ticket", &ticket, "--derp-server", &servers, "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING);
    assert!(err.contains("the DERP road answered first"), "{err}");
    assert!(err.contains("the DERP ticket is kept in"), "{err}");

    // No ticket now: the kept one, once the pair's road failed (Q50).
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--derp-server", &servers, "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING);
    assert!(err.contains("when each road before it failed (a kept ticket)"), "{err}");
    assert!(err.contains("the DERP road answered first"), "{err}");

    // PODSSH_DERP=no: the pair's road alone, which fails.
    let (rc, out, err) =
        run(lab.ssh(&["--derp-server", &servers, "node://tester@lab", "greet"]).env("PODSSH_DERP", "no"));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(!err.contains("DERP"), "no DERP road with PODSSH_DERP=no: {err}");
    drop(lab.runtime);
}

#[test]
fn a_node_with_no_pair_serves_the_derp_road_unasked_unless_podssh_derp_is_no() {
    let lab = Lab::new("unasked");
    let (node, _lines, started) = lab.node(&["--derp-server", &lab.servers()]);
    let said = started.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{started:#?}"));
    assert!(said.contains("no pair is stored") && said.contains("PODSSH_DERP=no"), "{said}");
    drop(node);
    let allow = lab.allow.to_string_lossy().into_owned();
    let mut off = command(&lab.node_home, &["node", "lab", &lab.target, "--allow", &allow, "--ca-file", &lab.ca]);
    let (rc, _, err) = run(off.env("PODSSH_DERP", "no"));
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("no pair is stored"), "{err}");
    drop(lab.runtime);
}

#[test]
fn a_client_of_the_old_ticket_finds_the_node_whose_home_moved_at_the_next_server() {
    let lab = Lab::new("moved");
    lab.let_in();
    let (_node, lines, started) = lab.node(&["--derp", "--derp-server", &lab.servers()]);
    let old = ticket_in(&started, "ticket derp:");
    lab.a.stop();
    let moved = wait_for(&lines, "the ticket is now derp:");
    let new = ticket_in(&moved, "the ticket is now derp:");
    assert_ne!(new, old, "the ticket names the new home");
    assert!(moved.last().unwrap().contains(&lab.b.server()), "{moved:#?}");
    let destination = format!("tester@{old}");

    // The ticket's server, then the rest of the list.
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--derp-server", &lab.servers(), &destination, "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING);
    assert!(err.contains(&format!("the DERP server {} carried the session", lab.b.server())), "{err}");

    // The ticket's server alone, as the planted client does: no node there.
    let (rc, out, err) = run(&mut lab.ssh(&["--derp-server", &lab.a.server(), &destination, "greet"]));
    assert_eq!(rc, 255, "the ticket's server alone found the node that moved: {out:?} {err}");
    drop(lab.runtime);
}
