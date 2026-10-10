//! `podssh chat --irc` (T-252) against a real IRC server, as processes:
//! ignored unless `PODSSH_IRC_TLS_SERVER` names one, as HOST:PORT, with its
//! TLS, and `PODSSH_IRC_CA` the CA of its certificate. The build image runs
//! it with ngircd on the loopback (`scripts/irc-in-image.sh`): a message
//! between two clients, a file with equal digests, and plain text to the TLS
//! port, which must fail. `PODSSH_IRC_PLANT=plaintext` is the planted defect:
//! each run then skips the TLS, and the test must fail at the handshake.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(90);

struct Server {
    address: String,
    ca: String,
    plant: bool,
    home: PathBuf,
}

impl Server {
    fn from_environment() -> Option<Server> {
        let address = std::env::var("PODSSH_IRC_TLS_SERVER").ok()?;
        let ca = std::env::var("PODSSH_IRC_CA").expect("PODSSH_IRC_CA names the CA of the server's certificate");
        let plant = std::env::var("PODSSH_IRC_PLANT").is_ok_and(|v| v == "plaintext");
        let home = std::env::temp_dir().join(format!("podssh-chat-irc-server-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("inbox")).unwrap();
        Some(Server { address, ca, plant, home })
    }

    /// `podssh chat --irc` to the server directly, with its CA, and `args`.
    fn chat(&self, nick: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(["chat", "--irc", &self.address, "--direct", "--nick", nick, "--timeout", "80s"]);
        if self.plant {
            cmd.arg("--irc-plaintext");
        } else {
            cmd.args(["--irc-ca-file", &self.ca]);
        }
        cmd.args(args);
        for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_NICK"] {
            cmd.env_remove(name);
        }
        cmd.env("HOME", &self.home).env("XDG_CACHE_HOME", &self.home);
        cmd
    }
}

/// Run to the end, within the limit: (code, stdout, stderr).
fn run(mut cmd: Command) -> (i32, String, String) {
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
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// A stream's lines, read by a thread.
fn lines_of(stream: impl std::io::Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
}

fn wait_for(lines: &mpsc::Receiver<String>, needle: &str) {
    let deadline = Instant::now() + LIMIT;
    let mut seen = Vec::new();
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) if line.contains(needle) => return,
            Ok(line) => seen.push(line),
            Err(_) => panic!("no {needle:?} within {LIMIT:?}: {seen:#?}"),
        }
    }
}

struct Taking(Child);

impl Drop for Taking {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "a real IRC server with TLS: PODSSH_IRC_TLS_SERVER=HOST:PORT and PODSSH_IRC_CA=FILE"]
fn a_message_and_a_file_cross_a_real_server_over_tls() {
    let Some(server) = Server::from_environment() else {
        eprintln!("skipped: PODSSH_IRC_TLS_SERVER names no server");
        return;
    };
    let id = std::process::id() % 100_000;
    let channel = format!("#pt{id}");
    let inbox = server.home.join("inbox");
    let inbox_text = inbox.to_string_lossy().into_owned();
    let mut taking = server.chat(&format!("pb{id}"), &["--accept-dir", &inbox_text, &channel]);
    let mut child = taking.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let said = lines_of(child.stdout.take().unwrap());
    let notes = lines_of(child.stderr.take().unwrap());
    let mut stdin = child.stdin.take().unwrap();
    let _taking = Taking(child);
    wait_for(&notes, "joined");

    // A message.
    let (rc, _, err) = run(server.chat(&format!("pc{id}"), &["--send", "hello over TLS", &channel]));
    assert_eq!(rc, 0, "{err}");
    wait_for(&said, &format!("pc{id}: hello over TLS"));

    // A file, with an equal digest.
    let data: Vec<u8> = (0..2000u32).map(|i| (i * 31 % 251) as u8).collect();
    let file = server.home.join("f.bin");
    std::fs::write(&file, &data).unwrap();
    let file_text = file.to_string_lossy().into_owned();
    let (rc, _, err) = run(server.chat(&format!("pa{id}"), &["--file", &file_text, &channel]));
    assert_eq!(rc, 0, "{err}");
    wait_for(&notes, "its SHA-256 matched");
    assert_eq!(std::fs::read(inbox.join("f.bin")).unwrap(), data);

    writeln!(stdin, "/quit").unwrap();
    let _ = std::fs::remove_dir_all(Path::new(&server.home));
}

/// The control: plain text to the TLS port never registers.
#[test]
#[ignore = "a real IRC server with TLS: PODSSH_IRC_TLS_SERVER=HOST:PORT and PODSSH_IRC_CA=FILE"]
fn plain_text_to_the_tls_port_never_registers() {
    let Some(server) = Server::from_environment() else {
        eprintln!("skipped: PODSSH_IRC_TLS_SERVER names no server");
        return;
    };
    let id = std::process::id() % 100_000;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["chat", "--irc", &server.address, "--direct", "--irc-plaintext", "--nick", &format!("px{id}")]);
    cmd.args(["--timeout", "20s", "--send", "never", &format!("#pt{id}")]);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        cmd.env_remove(name);
    }
    let (rc, _, err) = run(cmd);
    assert_ne!(rc, 0, "plain text registered on the TLS port: {err}");
}
