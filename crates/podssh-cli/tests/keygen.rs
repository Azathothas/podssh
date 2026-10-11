//! `podssh keygen` as a process. OpenSSH's own `ssh-keygen` checks the keys
//! in the interop harness (`scripts/interop-keygen.sh`); these tests hold the
//! command line, the files and the refusals, and that no private key is ever
//! printed.

mod cleanup;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

struct Run {
    code: i32,
    out: String,
    err: String,
}

/// A directory of one test's own, removed when the test ends. The count of
/// the calls tells apart two tests that run at once: the time alone did not,
/// as two calls can read the same clock (CI on Windows, 2026-10-10, where one
/// test found the key that another had written).
fn scratch() -> PathBuf {
    static CALLS: AtomicU32 = AtomicU32::new(0);
    let call = CALLS.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-keygen-test-{}-{call}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
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

/// An askpass program in `dir`: a question with "old" in it, and the
/// question of `-y`, get `PODSSH_TEST_OLD`; each other gets
/// `PODSSH_TEST_NEW`.
fn askpass(dir: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("askpass");
        let script =
            "#!/bin/sh\ncase \"$1\" in\n  *old*|\"Enter passphrase: \") printf '%s\\n' \"$PODSSH_TEST_OLD\" ;;\n  \
                      *) printf '%s\\n' \"$PODSSH_TEST_NEW\" ;;\nesac\n";
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.to_string_lossy().into_owned()
    }
    #[cfg(windows)]
    {
        // `echo(` prints an empty answer as an empty line, not "ECHO is off."
        let path = dir.join("askpass.cmd");
        let script = "@echo off\r\necho %~1| findstr /I /C:\"old\" >nul && (echo(%PODSSH_TEST_OLD%& exit /b 0)\r\n\
                      if \"%~1\"==\"Enter passphrase: \" (echo(%PODSSH_TEST_OLD%& exit /b 0)\r\n\
                      echo(%PODSSH_TEST_NEW%\r\n";
        std::fs::write(&path, script).unwrap();
        path.to_string_lossy().into_owned()
    }
}

/// `podssh ARGS` with `askpass` to answer, `old` and `new` its answers.
fn podssh_asked(args: &[&str], askpass: &str, old: &str, new: &str) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .env("PODSSH_OFFLINE", "1")
        .env("SSH_ASKPASS", askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("PODSSH_TEST_OLD", old)
        .env("PODSSH_TEST_NEW", new)
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

/// The key part of a public key line: its type and its base64.
fn key_part(line: &str) -> String {
    line.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

/// `-p` asks for the old passphrase and the new one two times, and the
/// file keeps its key: `-y` with the new passphrase prints the same public
/// key, and the old passphrase no longer opens it (T-018).
#[test]
fn change_passphrase_keeps_the_key() {
    let dir = scratch();
    let key = file(&dir, "k");
    let ask = askpass(&dir);
    assert_eq!(podssh(&["keygen", "-q", "-N", "", "-C", "the-comment", "-f", &key]).code, 0);
    let public = key_part(&std::fs::read_to_string(format!("{key}.pub")).unwrap());
    let run = podssh_asked(&["keygen", "-p", "-f", &key], &ask, "", "first passphrase");
    assert_eq!(run.code, 0, "{}", run.err);
    assert!(run.out.contains("new passphrase"), "{}", run.out);
    let run = podssh_asked(&["keygen", "-p", "-f", &key], &ask, "first passphrase", "second-one");
    assert_eq!(run.code, 0, "{}", run.err);
    let shown = podssh_asked(&["keygen", "-y", "-f", &key], &ask, "second-one", "");
    assert_eq!(shown.code, 0, "{}", shown.err);
    assert_eq!(key_part(&shown.out), public, "the key changed");
    assert!(shown.out.contains("the-comment"), "the comment is kept: {}", shown.out);
    let old = podssh_asked(&["keygen", "-y", "-f", &key], &ask, "first passphrase", "");
    assert_eq!(old.code, 1, "the old passphrase still opens the key");
    assert!(old.err.contains("incorrect passphrase"), "{}", old.err);
    let wrong = podssh_asked(&["keygen", "-p", "-f", &key], &ask, "not it", "third");
    assert_eq!(wrong.code, 1, "{}", wrong.err);
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(left.len(), 3, "a file was left beside the key: {left:?}");
}

/// A passphrase on the command line, old or new, is refused, and the file
/// is not touched; with nobody to ask, an encrypted key is refused at once.
#[test]
fn change_refuses_a_passphrase_on_the_command_line() {
    let dir = scratch();
    let key = file(&dir, "k");
    let ask = askpass(&dir);
    assert_eq!(podssh_asked(&["keygen", "-q", "-f", &key], &ask, "", "a passphrase").code, 0);
    let before = std::fs::read(&key).unwrap();
    for args in [
        vec!["keygen", "-p", "-P", "secret", "-f", &key],
        vec!["keygen", "-p", "-N", "secret", "-f", &key],
        vec!["keygen", "-c", "-P", "secret", "-C", "x", "-f", &key],
        vec!["keygen", "-p", "-c", "-f", &key],
        vec!["keygen", "-p"],
    ] {
        let run = podssh(&args);
        assert_eq!(run.code, 64, "{args:?}: {}", run.err);
    }
    let run = podssh(&["keygen", "-p", "-N", "", "-f", &key]);
    assert_eq!(run.code, 1, "{}", run.err);
    assert!(run.err.contains("-P ''") && run.err.contains("-N ''"), "{}", run.err);
    assert_eq!(std::fs::read(&key).unwrap(), before, "the key file changed");
}

/// `-c -C NEW` changes the comment in the key and in FILE.pub, and keeps
/// the key and its passphrase.
#[test]
fn change_comment_in_the_key_and_in_its_public_file() {
    let dir = scratch();
    let key = file(&dir, "k");
    let ask = askpass(&dir);
    assert_eq!(podssh_asked(&["keygen", "-q", "-C", "old-comment", "-f", &key], &ask, "", "pass").code, 0);
    let public = key_part(&std::fs::read_to_string(format!("{key}.pub")).unwrap());
    let run = podssh_asked(&["keygen", "-c", "-C", "new-comment", "-f", &key], &ask, "pass", "");
    assert_eq!(run.code, 0, "{}", run.err);
    assert!(run.out.contains("Old comment: old-comment"), "{}", run.out);
    let line = std::fs::read_to_string(format!("{key}.pub")).unwrap();
    assert!(line.trim_end().ends_with(" new-comment"), "{line}");
    assert_eq!(key_part(&line), public);
    let shown = podssh_asked(&["keygen", "-y", "-f", &key], &ask, "pass", "");
    assert_eq!(shown.code, 0, "the passphrase was kept: {}", shown.err);
    assert!(shown.out.trim_end().ends_with(" new-comment"), "{}", shown.out);
}
