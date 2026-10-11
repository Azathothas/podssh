//! `podssh ssh --record FILE` and `podssh play FILE` (T-033): a session's
//! output in an asciicast v2 file, against the test's SSH server, played
//! again with its timing.

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
}

fn ran(cmd: &mut Command) -> Ran {
    let out = cmd.output().unwrap();
    Ran {
        code: out.status.code(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-record-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

fn play(args: &[&str]) -> Ran {
    ran(Command::new(env!("CARGO_BIN_EXE_podssh")).arg("play").args(args))
}

/// `podssh ssh --direct --record FILE tester@127.0.0.1 greet`, to the
/// server on `port`.
fn recorded(dir: &Path, port: u16, file: &Path, more: &[&str]) -> Ran {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.arg("--record").arg(file).args(more).args(["tester@127.0.0.1", "greet"]);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", dir).env("USERPROFILE", dir);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    ran(&mut cmd)
}

/// A session recorded: the header of version 2, the output as an event,
/// nothing typed; the file is closed to others, never written over, and
/// `podssh play` shows the output again.
#[test]
fn record_keeps_the_output_and_play_shows_it_again() {
    let dir = scratch("session");
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    let file = dir.join("s.cast");
    let first = recorded(&dir, port, &file, &[]);
    assert_eq!((first.code, first.out.as_str()), (Some(0), ssh_harness::GREETING), "{}", first.err);
    let text = std::fs::read_to_string(&file).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with(r#"{"version": 2, "width": "#), "{text}");
    assert!(lines[1].ends_with(r#", "o", "hello over the iroh road\n"]"#), "{text}");
    assert_eq!(lines.len(), 2, "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let again = recorded(&dir, port, &file, &[]);
    assert_eq!(again.code, Some(255), "{}", again.err);
    assert!(again.err.contains("the file exists"), "{}", again.err);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text, "the recording is as it was");

    let shown = play(&[file.to_str().unwrap()]);
    assert_eq!((shown.code, shown.out.as_str()), (Some(0), ssh_harness::GREETING), "{}", shown.err);
}

/// --record needs a session, and goes with no --persist: usage errors, and
/// no file is made.
#[test]
fn record_refuses_a_run_with_no_session() {
    let dir = scratch("refused");
    let file = dir.join("s.cast");
    for more in [&["-N"][..], &["-W", "127.0.0.1:22"], &["--persist"]] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(["ssh", "--direct", "--record"]).arg(&file).args(more).arg("u@127.0.0.1");
        let refused = ran(cmd.env("PODSSH_SSH_CONFIG", "none"));
        assert_eq!(refused.code, Some(64), "{more:?}: {}", refused.err);
        assert!(!file.exists(), "{more:?}");
    }
}

/// The output events in order, each at its time; another kind is passed
/// over; --speed and --idle-limit shorten the waits.
#[test]
fn play_writes_each_output_event_and_passes_over_the_others() {
    let dir = scratch("play");
    let file = dir.join("p.cast");
    std::fs::write(
        &file,
        "{\"version\": 2, \"width\": 80, \"height\": 24}\n[0.0, \"o\", \"a\"]\n[0.1, \"r\", \"100x30\"]\n\
         [0.2, \"o\", \"b\\u001b[0m\\r\\n\"]\n[0.3, \"x\", \"other\"]\n[0.4, \"o\", \"\u{e9}\"]\n",
    )
    .unwrap();
    let shown = play(&[file.to_str().unwrap()]);
    assert_eq!((shown.code, shown.out.as_str()), (Some(0), "ab\u{1b}[0m\r\n\u{e9}"), "{}", shown.err);

    let slow = dir.join("slow.cast");
    std::fs::write(&slow, "{\"version\": 2, \"width\": 80, \"height\": 24}\n[30.0, \"o\", \"late\"]\n").unwrap();
    for flags in [&["--speed", "1000"][..], &["--idle-limit", "0.1"]] {
        let started = Instant::now();
        let shown = play(&[flags, &[slow.to_str().unwrap()]].concat());
        assert_eq!((shown.code, shown.out.as_str()), (Some(0), "late"), "{flags:?}: {}", shown.err);
        assert!(started.elapsed() < Duration::from_secs(10), "{flags:?}: {:?}", started.elapsed());
    }
}

/// A file of another version, a line that is no event, a missing file and
/// bad flags are refused.
#[test]
fn play_refuses_what_it_cannot_play() {
    let dir = scratch("bad");
    let old = dir.join("v1.cast");
    std::fs::write(&old, "{\"version\": 1, \"width\": 80, \"height\": 24, \"stdout\": []}\n").unwrap();
    let refused = play(&[old.to_str().unwrap()]);
    assert_eq!(refused.code, Some(1));
    assert!(refused.err.contains("not an asciicast v2 recording"), "{}", refused.err);

    let broken = dir.join("broken.cast");
    std::fs::write(&broken, "{\"version\": 2, \"width\": 80, \"height\": 24}\n[0.0, \"o\", \"a\"]\nnot json\n")
        .unwrap();
    let refused = play(&[broken.to_str().unwrap()]);
    assert_eq!((refused.code, refused.out.as_str()), (Some(1), "a"), "{}", refused.err);
    assert!(refused.err.contains("broken.cast:3: not an event"), "{}", refused.err);

    assert_eq!(play(&[dir.join("missing.cast").to_str().unwrap()]).code, Some(1));
    assert_eq!(play(&[]).code, Some(64));
    assert_eq!(play(&["--speed", "0", old.to_str().unwrap()]).code, Some(64));
    assert_eq!(play(&["--idle-limit", "x", old.to_str().unwrap()]).code, Some(64));
}
