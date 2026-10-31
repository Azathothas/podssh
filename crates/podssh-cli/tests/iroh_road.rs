//! The iroh road of the command line from end to end (T-163, T-165), on this
//! machine's loopback: iroh's relay server with a certificate that
//! `--ca-file` gives, an SSH server for the node's TARGET, `podssh node
//! --iroh` with an allowlist, and `podssh ssh iroh:TICKET`. The client is
//! refused and says its key; once that key is in the allowlist, with no new
//! start of the node, the same command logs in and runs.
#![cfg(feature = "iroh-test")]

mod cleanup;
mod ssh_harness;
// A TLS stand-in of the test's own CA, for a relay that refuses (T-348).
#[path = "update_support/mod.rs"]
mod update_support;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ssh_harness::GREETING;

const LIMIT: Duration = Duration::from_secs(60);

/// A fresh, empty scratch directory unique to one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-iroh-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Private, as a user's own directory is: the node refuses an allowlist
    // that others can change, as a host's temporary directory may let them.
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, and none of the
/// settings of the machine that runs the test.
fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args);
    // The ssh_config of the machine that runs the test must not change it.
    cmd.env("PODSSH_SSH_CONFIG", "none");
    for name in [
        "PODSSH_OFFLINE",
        "PODSSH_IROH_RELAY",
        "PODSSH_TIMEOUT",
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
        "PODSSH_IROH_UDP",
    ] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// Run `podssh ARGS` to its end, within the limit: (code, stdout, stderr).
fn run(home: &Path, args: &[&str]) -> (i32, String, String) {
    let mut child = command(home, args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh {args:?} did not end within {} s", LIMIT.as_secs());
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

/// The line of `seen` that holds `needle`.
fn line_with<'a>(seen: &'a [String], needle: &str) -> &'a str {
    seen.iter().find(|l| l.contains(needle)).unwrap_or_else(|| panic!("no line with {needle:?}: {seen:#?}"))
}

/// The 64 hex digits after `after` in `text`.
fn key_after(text: &str, after: &str) -> String {
    let start = text.find(after).unwrap_or_else(|| panic!("{after:?} is not in {text}")) + after.len();
    text[start..].chars().take_while(char::is_ascii_hexdigit).collect()
}

/// The fingerprint (`SHA256:` and its base64) that follows `after` in `text`.
fn fingerprint_after(text: &str, after: &str) -> String {
    let start = text.find(after).unwrap_or_else(|| panic!("{after:?} is not in {text}")) + after.len();
    let body =
        text[start..].strip_prefix("SHA256:").unwrap_or_else(|| panic!("no fingerprint after {after:?}: {text}"));
    let digits: String = body.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/').collect();
    format!("SHA256:{digits}")
}

#[test]
fn a_client_is_refused_then_let_in_and_runs_a_command_over_the_iroh_road() {
    let home = scratch("e2e");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let relay = runtime.block_on(podssh_iroh::test_relay::spawn(&home)).expect("a relay on the loopback");
    let host_key = home.join("host_key");
    let host_key_text = host_key.to_string_lossy().into_owned();
    let (rc, _, err) = run(&home, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key_text]);
    assert_eq!(rc, 0, "{err}");
    let port = runtime.block_on(ssh_harness::start(&host_key));

    let cert = relay.cert.to_string_lossy().into_owned();
    let url = relay.url.to_string();
    let allow = home.join("allow");
    std::fs::write(&allow, "# the client keys that may connect\n").unwrap();
    let allow_text = allow.to_string_lossy().into_owned();
    let node_key = home.join("node.key").to_string_lossy().into_owned();
    let target = format!("127.0.0.1:{port}");
    let node_args = [
        "node",
        "lab",
        &target,
        "--iroh",
        "--iroh-relay",
        &url,
        "--ca-file",
        &cert,
        "--iroh-allow",
        &allow_text,
        "--iroh-key",
        &node_key,
    ];
    let mut child = command(&home, &node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().expect("the node");
    let lines = lines_of(&mut child);
    let _node = Node(child);
    let started = wait_for(&lines, "ticket iroh:");
    let ticket_line = line_with(&started, "ticket iroh:");
    let ticket = ticket_line[ticket_line.find("iroh:").unwrap()..].trim().to_string();
    let node_line = line_with(&started, ": key ").to_string();
    assert!(node_line.contains("a new key"), "a new node key is said: {node_line}");
    // The relay on the loopback runs no QUIC address discovery, so no
    // datagram comes back, and the node says that its relay carries each
    // byte, whatever a UDP bind does here (T-359).
    let udp_line = line_with(&started, "relay carries each byte");
    assert!(!udp_line.contains("direct paths may take UDP"), "{udp_line}");

    let known = home.join("known_hosts").to_string_lossy().into_owned();
    let client_key = home.join("client.key").to_string_lossy().into_owned();
    let destination = format!("tester@{ticket}");
    let ssh = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        &format!("UserKnownHostsFile={known}"),
        "--ca-file",
        &cert,
        "--iroh-relay",
        &url,
        "--iroh-key",
        &client_key,
        &destination,
        "greet",
    ];
    // Refused: the client's key is in no allowlist yet.
    let (rc, out, err) = run(&home, &ssh);
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    let key = fingerprint_after(&err, "refused this client's key ");
    assert_eq!(key.len(), 50, "the client says its key's fingerprint: {err}");
    let refused = wait_for(&lines, "refused the client key");
    assert!(line_with(&refused, "refused the client key").contains(&key), "the node names the key: {refused:#?}");

    // The node's operator adds the key; the node reads the file again.
    let mut file = std::fs::OpenOptions::new().append(true).open(&allow).unwrap();
    writeln!(file, "{key} the test's client").unwrap();
    drop(file);
    // With -v, the client says the answer that its road took (T-359).
    let mut verbose = ssh.to_vec();
    verbose.insert(1, "-v");
    let (rc, out, err) = run(&home, &verbose);
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    let said = err.lines().find(|l| l.contains("the iroh road: ")).unwrap_or_default();
    assert!(said.contains("relay carries each byte"), "-v says the road's answer of UDP: {err}");
    let connected = wait_for(&lines, "connected");
    assert!(line_with(&connected, "connected").contains(&key), "{connected:#?}");
    let recorded = std::fs::read_to_string(&known).unwrap();
    let node_key_hex = key_after(&node_line, ", the node iroh:");
    assert_eq!(node_key_hex.len(), 64, "the node says its name in the known hosts: {node_line}");
    assert!(recorded.contains(&format!("iroh:{node_key_hex}")), "the host key is under the node's key: {recorded}");
    drop(relay);
}

/// A home relay that refuses this build's iroh (T-348), as iroh's relay
/// server words a refusal of the version: the node stops at once, well
/// before its limit of 30 s, with the notice, which names the relay, this
/// binary's iroh, the relay's words and the two ways out.
#[test]
fn a_relay_that_refuses_this_iroh_stops_the_node_with_its_notice() {
    let home = scratch("refused");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let relay = runtime.block_on(update_support::Server::start(&home));
    relay.body("/ping", Vec::new());
    let words = "invalid header value for sec-websocket-protocol: unsupported relay version: we support \
                 iroh-relay-v3 but you only provide iroh-relay-v2, iroh-relay-v1";
    relay.route("/relay", update_support::Answer::Refuse(400, words.into()));
    let (url, cert) = (relay.url(), relay.ca_file.to_string_lossy().into_owned());
    let allow = home.join("allow");
    std::fs::write(&allow, "# the client keys that may connect\n").unwrap();
    let allow = allow.to_string_lossy().into_owned();
    // The node checks its TARGET first: a port of the test's own, open.
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target_text = target.local_addr().unwrap().to_string();
    let started = Instant::now();
    let args =
        ["node", "lab", &target_text, "--iroh", "--iroh-relay", &url, "--ca-file", &cert, "--iroh-allow", &allow];
    let (code, _, err) = run(&home, &args);
    let took = started.elapsed();
    assert_ne!(code, 0, "{err}");
    for part in [
        "127.0.0.1 refuses the iroh of this binary",
        &format!("iroh {}", podssh_iroh::version::IROH),
        "we support iroh-relay-v3",
        "podssh update",
        "--iroh-relay URL",
    ] {
        assert!(err.contains(part), "{part}: {err}");
    }
    assert!(took < Duration::from_secs(25), "the node waited {} s for a relay that refused it", took.as_secs());
    assert!(relay.was_asked("/relay"), "the relay was never asked");
}

/// `podssh doctor` asks `/ping` of each iroh relay of the list, in order,
/// names the first that answers as the home relay (T-165), and gives the
/// road's own answer of UDP from it (T-359). Live: the
/// doctor's other checks reach the relay of the forward road.
#[test]
#[ignore = "live: podssh doctor reaches the relay of the forward road"]
fn doctor_says_the_ping_of_each_iroh_relay_and_the_home_relay() {
    let home = scratch("doctor");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let relay = runtime.block_on(podssh_iroh::test_relay::spawn(&home)).expect("a relay on the loopback");
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let list = format!("https://localhost:{silent},{}", relay.url);
    let mut cmd = command(&home, &["doctor"]);
    cmd.env("PODSSH_IROH_RELAY", &list).env("SSL_CERT_FILE", &relay.cert);
    let out = cmd.stdin(Stdio::null()).output().expect("podssh doctor runs");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = |needle: &str| text.lines().find(|l| l.contains(needle)).unwrap_or_default().trim_start().to_string();
    assert!(line(&format!("iroh relay localhost:{silent}")).starts_with("FAIL"), "the silent relay: {text}");
    let port = relay.url.port().expect("the relay's port");
    assert!(line(&format!("iroh relay localhost:{port}")).starts_with("ok"), "the relay that answers: {text}");
    let home_line = line("iroh home relay");
    assert!(home_line.starts_with("ok") && home_line.contains(relay.url.as_str()), "{text}");
    // A bind says only that it bound; the road's own probe, to a relay that
    // runs no QUIC address discovery, finds no datagram that came back, and
    // the road keeps its relay alone, which works (T-359).
    assert!(!line("bind UDP").contains("direct"), "a bind claims a direct path: {text}");
    let out = line("iroh UDP out");
    assert!(out.starts_with("ok") && out.contains("relay carries each byte"), "{text}");
    drop(relay);
}
