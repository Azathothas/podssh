//! What the tests of `podssh keygen` share: a run of the binary that can
//! ask nothing or asks an askpass program, and a scratch directory of each
//! test's own.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

pub struct Run {
    pub code: i32,
    pub out: String,
    pub err: String,
}

/// A directory of one test's own, removed when the test ends. The count of
/// the calls tells apart two tests that run at once: the time alone did not,
/// as two calls can read the same clock (CI on Windows, 2026-10-10, where one
/// test found the key that another had written).
pub fn scratch() -> PathBuf {
    static CALLS: AtomicU32 = AtomicU32::new(0);
    let call = CALLS.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-keygen-test-{}-{call}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    super::cleanup::at_test_end(&dir);
    dir
}

/// Run `podssh ARGS` with no way to ask anything: no askpass program and no
/// controlling terminal, so a test can never wait for a passphrase.
pub fn podssh(args: &[&str]) -> Run {
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

pub fn file(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

/// An askpass program in `dir`: a question with "old" in it, and the
/// question of `-y`, get `PODSSH_TEST_OLD`; each other gets
/// `PODSSH_TEST_NEW`.
pub fn askpass(dir: &Path) -> String {
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
pub fn podssh_asked(args: &[&str], askpass: &str, old: &str, new: &str) -> Run {
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
pub fn key_part(line: &str) -> String {
    line.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}
