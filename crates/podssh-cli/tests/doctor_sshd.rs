//! `podssh doctor`'s line `sshd` (T-590, GitHub #116), as a process and
//! offline: where this host has the sshd of a roost, and what one dial of
//! 127.0.0.1:22 reads first. The line is a note, ok in each form. The port
//! is this host's, so the test reads it too and holds the line to what it
//! found there; a form that this host does not give is said not to have run,
//! and the unit tests of `doctor::sshd` hold each form's words. Unix's: the
//! stand-ins on PATH are files with the mode of a program.
#![cfg(unix)]

mod cleanup;

use std::io::Read;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The bound on each run of doctor offline.
const LIMIT: Duration = Duration::from_secs(120);

/// One doctor at a time: each copies its binary into the directories that
/// it probes.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A fresh directory, removed when the test ends; the count tells apart two
/// calls that read the same clock.
fn scratch(tag: &str) -> PathBuf {
    static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-doctor-sshd-{tag}-{}-{call}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// A directory with an empty runnable file for each of `names`: a PATH on
/// which the look finds them, and runs none.
fn stand_ins(names: &[&str]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("path");
    for name in names {
        let file = dir.join(name);
        std::fs::write(&file, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir
}

/// `podssh doctor --json` offline, with HOME in a scratch directory and
/// PATH `path`: the status and the detail of its item `sshd`.
fn sshd_line(path: &Path) -> (String, String) {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let home = scratch("home");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["doctor", "--json"]).env("HOME", &home).env("PATH", path).env("PODSSH_OFFLINE", "1");
    for name in ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("podssh runs");
    let mut stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || std::io::read_to_string(&mut stdout).unwrap_or_default());
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh doctor still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = out.join().unwrap();
    let doc: serde_json::Value = serde_json::from_str(&out).expect("stdout is one JSON object");
    let checks = doc["checks"].as_array().expect("checks");
    let item = checks.iter().find(|c| c["check"] == "sshd").unwrap_or_else(|| panic!("no line sshd: {out}"));
    assert_eq!(item["section"], "this host", "{item}");
    let text = |key: &str| item[key].as_str().unwrap_or_default().to_string();
    (text("status"), text("detail"))
}

/// What this host's 127.0.0.1:22 gives one dial, read by the test.
enum Port22 {
    /// A version line of SSH.
    Ssh(String),
    /// The dial was refused.
    Refused,
    /// Anything else, which this test does not hold the line to.
    Other,
}

fn port_22() -> Port22 {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 22));
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(stream) => stream,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Port22::Refused,
        Err(_) => return Port22::Other,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let (mut line, mut byte) = (Vec::new(), [0u8; 1]);
    while !line.ends_with(b"\n") && line.len() < 255 {
        match stream.read(&mut byte) {
            Ok(1) => line.push(byte[0]),
            _ => break,
        }
    }
    let line = String::from_utf8_lossy(&line).trim_end().to_string();
    match line.starts_with("SSH-2.0-") || line.starts_with("SSH-1.99-") {
        true => Port22::Ssh(line),
        false => Port22::Other,
    }
}

/// The sshd that the look finds after PATH on this host, if any.
fn placed() -> Option<PathBuf> {
    podssh_cli::local_sshd::places().into_iter().map(|d| d.join("sshd")).find(|p| p.is_file())
}

/// An sshd on PATH, a stand-in: the line names it first, and then what
/// 127.0.0.1:22 gave the test's own dial.
#[test]
fn the_line_names_the_sshd_on_path_and_what_port_22_answers() {
    let path = stand_ins(&["sshd"]);
    let (status, detail) = sshd_line(&path);
    assert_eq!(status, "ok", "a note, never a failure: {detail}");
    let at = path.join("sshd");
    assert!(detail.starts_with(&format!("present at {}; ", at.display())), "{detail}");
    match port_22() {
        Port22::Ssh(line) => assert!(detail.contains(&format!("127.0.0.1:22 answers {line}")), "{detail}"),
        Port22::Refused => {
            assert!(detail.contains("nothing listens at 127.0.0.1:22"), "{detail}");
            assert!(detail.contains("a roost (podssh node --sshd) needs it started there"), "{detail}");
        }
        Port22::Other => eprintln!("the forms of port 22 did not run: 127.0.0.1:22 here is neither sshd nor closed"),
    }
}

/// No sshd on PATH, a stand-in `apt-get` there: with none in the places
/// after PATH either, the line says absent and names the package; where
/// this host has one there, it names that one, and the form of absent is
/// said not to have run.
#[test]
fn with_no_sshd_the_line_says_absent_and_names_the_package() {
    let path = stand_ins(&["apt-get"]);
    let (status, detail) = sshd_line(&path);
    assert_eq!(status, "ok", "a note, never a failure: {detail}");
    if let Some(at) = placed() {
        eprintln!("the form of absent did not run: this host has {}", at.display());
        assert!(detail.starts_with(&format!("present at {}; ", at.display())), "{detail}");
        return;
    }
    assert!(detail.starts_with("absent (none on PATH or in /usr/sbin, /usr/local/sbin, /sbin); "), "{detail}");
    match port_22() {
        Port22::Ssh(line) => assert!(detail.contains(&format!("127.0.0.1:22 answers {line}")), "{detail}"),
        Port22::Refused => {
            let said = "nothing listens at 127.0.0.1:22; a roost (podssh node --sshd) needs one: apt-get install -y \
                        openssh-server";
            assert!(detail.contains(said), "{detail}");
        }
        Port22::Other => eprintln!("the forms of port 22 did not run: 127.0.0.1:22 here is neither sshd nor closed"),
    }
}
