//! `podssh chat` over the iroh road (T-099), on this machine's loopback:
//! iroh's relay server with a certificate that `--ca-file` gives, a side
//! that waits with `--listen --iroh` and an allowlist, and the side that
//! reaches its ticket. A key that the allowlist does not hold is refused,
//! and says itself; once it is there, a message and a file go, and the file
//! is kept whole only in the accept directory. `/quit` ends the side that
//! waits while no peer is there.
#![cfg(feature = "iroh-test")]

mod cleanup;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(90);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-chat-iroh-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, and none of the
/// settings of the machine that runs the test.
fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).current_dir(home);
    for name in ["PODSSH_OFFLINE", "PODSSH_IROH_RELAY", "PODSSH_TIMEOUT", "SSL_CERT_FILE", "HTTPS_PROXY", "https_proxy"]
    {
        cmd.env_remove(name);
    }
    for name in ["ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"] {
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

/// Kills the side that waits if the test ends before it did.
struct Waiting(Child);

impl Drop for Waiting {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The lines of a stream, a line at a time, read by a thread.
fn lines_of(stream: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
}

/// The lines up to the first that holds `needle`, that one last.
fn wait_for(lines: &mpsc::Receiver<String>, needle: &str) -> Vec<String> {
    let deadline = Instant::now() + LIMIT;
    let mut seen = Vec::new();
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => {
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return seen;
                }
            }
            Err(_) => panic!("no line with {needle:?} within {} s: {seen:#?}", LIMIT.as_secs()),
        }
    }
}

/// The fingerprint (`SHA256:` and its base64) that follows `after` in `text`.
fn fingerprint_after(text: &str, after: &str) -> String {
    let start = text.find(after).unwrap_or_else(|| panic!("{after:?} is not in {text}")) + after.len();
    let body = text[start..].strip_prefix("SHA256:").unwrap_or_else(|| panic!("no fingerprint: {text}"));
    let digits: String = body.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/').collect();
    format!("SHA256:{digits}")
}

#[test]
fn a_chat_over_the_iroh_road_lets_in_only_the_allowed_key() {
    let home = scratch("road");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let relay = runtime.block_on(podssh_iroh::test_relay::spawn(&home)).expect("a relay on the loopback");
    let (cert, url) = (relay.cert.to_string_lossy().into_owned(), relay.url.to_string());
    let path = |name: &str| home.join(name).to_string_lossy().into_owned();
    std::fs::create_dir_all(home.join("inbox")).unwrap();
    std::fs::write(home.join("allow"), "# the keys that may come in\n").unwrap();
    let file: Vec<u8> = (0..300_000u32).map(|i| (i * 13 % 251) as u8).collect();
    std::fs::write(home.join("notes.bin"), &file).unwrap();

    let (allow, node_key, inbox) = (path("allow"), path("node.key"), path("inbox"));
    let listen = [
        "chat",
        "--listen",
        "lab",
        "--iroh",
        "--iroh-relay",
        &url,
        "--ca-file",
        &cert,
        "--allow",
        &allow,
        "--key",
        &node_key,
        "--accept-dir",
        &inbox,
        "--nick",
        "ana",
        "--timeout",
        "180s",
    ];
    let mut child = command(&home, &listen)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the side that waits");
    let notes = lines_of(child.stderr.take().unwrap());
    let said = lines_of(child.stdout.take().unwrap());
    let mut stdin = child.stdin.take().unwrap();
    let mut waiting = Waiting(child);
    let started = wait_for(&notes, "ticket iroh:");
    let line = started.iter().find(|l| l.contains("ticket iroh:")).unwrap();
    let ticket = line[line.find("iroh:").unwrap()..].trim().to_string();
    assert!(started.iter().any(|l| l.contains("waiting for the peer over the iroh road alone")), "{started:#?}");

    let client_key = path("client.key");
    let reach = |more: &[&str]| {
        let mut args = vec!["chat", &ticket, "--iroh-relay", &url, "--ca-file", &cert, "--client-key", &client_key];
        args.extend_from_slice(&["--nick", "bo", "--timeout", "60s"]);
        args.extend_from_slice(more);
        run(&home, &args)
    };
    // Refused: this key is in no allowlist yet, and it says itself.
    let (rc, _, err) = reach(&["--send", "not yet"]);
    assert_eq!(rc, 77, "{err}");
    let key = fingerprint_after(&err, "the node refused this client's key ");
    wait_for(&notes, "refused the client key");

    // Let in, a message and a file go.
    let mut list = std::fs::OpenOptions::new().append(true).open(home.join("allow")).unwrap();
    writeln!(list, "{key} the test's peer").unwrap();
    drop(list);
    let (rc, _, err) = reach(&["--send", "over the iroh road"]);
    assert_eq!(rc, 0, "{err}");
    wait_for(&said, "bo: over the iroh road");
    let notes_path = path("notes.bin");
    let (rc, _, err) = reach(&["--file", &notes_path]);
    assert_eq!(rc, 0, "{err}");
    wait_for(&notes, "its SHA-256 matched");
    assert_eq!(std::fs::read(home.join("inbox").join("notes.bin")).unwrap(), file);

    // `/quit` while no peer is there ends the side that waits, with 0.
    writeln!(stdin, "/quit").unwrap();
    drop(stdin);
    let deadline = Instant::now() + LIMIT;
    let code = loop {
        if let Some(status) = waiting.0.try_wait().unwrap() {
            break status.code();
        }
        assert!(Instant::now() < deadline, "the side that waits did not end at /quit");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(code, Some(0));
    drop(relay);
}
