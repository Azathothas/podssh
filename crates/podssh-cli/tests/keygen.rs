//! `podssh keygen` as a process. OpenSSH's own `ssh-keygen` checks the keys
//! in the interop harness (`scripts/interop-keygen.sh`); these tests hold the
//! command line, the files and the refusals, and that no private key is ever
//! printed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Run {
    code: i32,
    out: String,
    err: String,
}

fn scratch() -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-keygen-test-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `podssh ARGS` with no way to ask anything: no askpass program and no
/// controlling terminal, so a test can never wait for a passphrase.
fn podssh(args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .env("PODSSH_OFFLINE", "1")
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    detach(&mut cmd);
    let output = cmd.output().expect("the podssh binary runs");
    Run {
        code: output.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&output.stdout).into_owned(),
        err: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A new session has no controlling terminal, so `/dev/tty` cannot open.
#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setsid is async-signal-safe and touches no memory.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
}

/// A detached process has no console, so `CONIN$` cannot open.
#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    cmd.creation_flags(DETACHED_PROCESS);
}

fn file(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

#[test]
fn a_key_pair_is_made_and_read_back_and_the_private_key_is_never_printed() {
    let dir = scratch();
    let key = file(&dir, "id_ed25519");
    let made = podssh(&["keygen", "-N", "", "-C", "test@podssh", "-f", &key]);
    assert_eq!(made.code, 0, "{}{}", made.out, made.err);
    assert!(made.out.contains("Your identification has been saved in"), "{}", made.out);
    assert!(made.out.contains("SHA256:") && made.out.contains("test@podssh"), "{}", made.out);
    let public = std::fs::read_to_string(format!("{key}.pub")).unwrap();
    assert!(public.starts_with("ssh-ed25519 ") && public.trim_end().ends_with(" test@podssh"), "{public}");
    let private = std::fs::read_to_string(&key).unwrap();
    assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"), "not OpenSSH's format");
    let body = private.lines().nth(1).unwrap();

    let printed = podssh(&["keygen", "-y", "-f", &key]);
    assert_eq!(printed.code, 0, "{}", printed.err);
    assert_eq!(printed.out.trim_end(), public.trim_end());

    let line = podssh(&["keygen", "-l", "-f", &format!("{key}.pub")]);
    assert_eq!(line.code, 0, "{}", line.err);
    assert!(
        line.out.starts_with("256 SHA256:") && line.out.trim_end().ends_with(" test@podssh (ED25519)"),
        "{}",
        line.out
    );

    for run in [&made, &printed, &line] {
        assert!(!run.out.contains("PRIVATE KEY") && !run.out.contains(body), "a private key was printed");
        assert!(!run.err.contains("PRIVATE KEY") && !run.err.contains(body), "a private key was printed");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn quiet_prints_nothing_and_sizes_are_honoured() {
    let dir = scratch();
    let key = file(&dir, "id_ecdsa");
    let made = podssh(&["ssh-keygen", "-t", "ecdsa", "-b", "384", "-N", "", "-q", "-f", &key]);
    assert_eq!(made.code, 0, "{}", made.err);
    assert!(made.out.is_empty() && made.err.is_empty(), "{}{}", made.out, made.err);
    let line = podssh(&["keygen", "-l", "-f", &key]);
    assert!(line.out.starts_with("384 SHA256:") && line.out.trim_end().ends_with("(ECDSA)"), "{}", line.out);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_existing_key_is_never_overwritten() {
    let dir = scratch();
    let key = file(&dir, "id_ed25519");
    assert_eq!(podssh(&["keygen", "-N", "", "-q", "-f", &key]).code, 0);
    let before = std::fs::read(&key).unwrap();
    let again = podssh(&["keygen", "-N", "", "-q", "-f", &key]);
    assert_eq!(again.code, 1, "{}", again.err);
    assert!(again.err.contains("already exists"), "{}", again.err);
    assert_eq!(std::fs::read(&key).unwrap(), before);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_passphrase_on_the_command_line_is_refused_and_nothing_is_written() {
    let dir = scratch();
    let key = file(&dir, "id_ed25519");
    let run = podssh(&["keygen", "-N", "secret words", "-f", &key]);
    assert_eq!(run.code, 64, "{}", run.err);
    assert!(run.err.contains("every process on this host can read it"), "{}", run.err);
    assert!(!run.err.contains("secret words") && !run.out.contains("secret words"));
    assert!(!Path::new(&key).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn with_no_way_to_ask_for_a_passphrase_the_refusal_names_the_remedy() {
    let dir = scratch();
    let key = file(&dir, "id_ed25519");
    let run = podssh(&["keygen", "-f", &key]);
    assert_eq!(run.code, 1, "{}{}", run.out, run.err);
    assert!(run.err.contains("-N ''"), "{}", run.err);
    assert!(!Path::new(&key).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn usage_errors_exit_64_with_nothing_on_stdout() {
    let dir = scratch();
    let key = file(&dir, "k");
    for args in [
        vec!["keygen", "-t", "dsa", "-N", "", "-f", &key],
        vec!["keygen", "-t", "rsa", "-b", "1024", "-N", "", "-f", &key],
        vec!["keygen", "-y"],
        vec!["keygen", "-y", "-l", "-f", &key],
        vec!["keygen", "-N", "", "-C", "two\nlines", "-f", &key],
    ] {
        let run = podssh(&args);
        assert_eq!(run.code, 64, "{args:?}: {}", run.err);
        assert!(run.out.is_empty(), "{args:?}: {}", run.out);
        assert!(run.err.starts_with("podssh keygen: "), "{args:?}: {}", run.err);
    }
    assert!(!Path::new(&key).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}
