//! A login to the test's SSH server on the loopback, for the modules of
//! `ssh_config_file` that need one (T-502, T-505): the server with a host
//! key of the kind asked for, and `podssh ssh --direct` with a home of the
//! test's, within a limit.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::ssh_harness;

/// The longest that one run of podssh may take.
const LIMIT: Duration = Duration::from_secs(30);

/// The test's server, with a host key of `kind` (`ed25519`, or `rsa` with
/// `bits`) that `podssh keygen` makes in `home`: its runtime, which must
/// live as long as the server, and its port.
pub fn server(home: &Path, kind: &str, bits: Option<&str>) -> (tokio::runtime::Runtime, u16) {
    let key = home.join(format!("host_key_{kind}"));
    let mut keygen = Command::new(env!("CARGO_BIN_EXE_podssh"));
    keygen.args(["keygen", "-q", "-t", kind, "-N", ""]);
    if let Some(bits) = bits {
        keygen.args(["-b", bits]);
    }
    let status = keygen.arg("-f").arg(&key).status().expect("podssh keygen runs");
    assert!(status.success(), "podssh keygen -t {kind}");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    (runtime, port)
}

/// `podssh ssh --direct` to the test's server, with `home` as HOME, no
/// agent and no prompt: its exit code, stdout and stderr, within the limit.
pub fn direct(home: &Path, words: &[&str]) -> (i32, String, String) {
    let known = home.join("known_hosts");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", known.display()));
    cmd.args(["-o", "IdentityAgent=none"]);
    cmd.args(words);
    cmd.env("HOME", home).env("USERPROFILE", home).env_remove("PODSSH_SSH_CONFIG");
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh ssh did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// `podssh VERB ARGS` offline with no terminal and no ssh_config of this
/// machine's: its exit code and stderr. Nothing connects.
pub fn offline(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(args)
        .env("PODSSH_OFFLINE", "1")
        .env_remove("PODSSH_TIMEOUT")
        .env_remove("PODSSH_SSH_CONFIG")
        .stdin(Stdio::null())
        .output()
        .expect("the podssh binary runs");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}
