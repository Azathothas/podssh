//! A key of a security key in `podssh agent` (T-229), as processes: `add`
//! gives it, `list` shows it, and with no device the agent signs nothing,
//! so a login through it ends with 255 and says why, after the line of the
//! touch; `remove` takes it back. PODSSH_SK_DEVICE set to none stands in
//! for a host with no device, which this test's host may not be.

mod cleanup;
mod ssh_harness;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{generate, KeyKind};
use podssh_ssh::russh::keys::ssh_key::LineEnding;
use podssh_ssh::sk::{private_key, Alg, Enrolled, USER_PRESENCE_REQUIRED};

const LIMIT: Duration = Duration::from_secs(60);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-agent-sk-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// podssh with a clean environment, `home` as HOME, `sock` as SSH_AUTH_SOCK,
/// and no device of security keys.
fn podssh(home: &Path, sock: Option<&str>, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("TMPDIR", home)
        .env("PODSSH_SK_DEVICE", "none");
    for name in
        ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_ASKPASS", "XDG_RUNTIME_DIR"]
    {
        cmd.env_remove(name);
    }
    match sock {
        Some(sock) => cmd.env("SSH_AUTH_SOCK", sock),
        None => cmd.env_remove("SSH_AUTH_SOCK"),
    };
    cmd
}

/// Run to the end, within the limit.
fn ran(mut cmd: Command) -> Output {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

/// The agent, killed when the test ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A key file of an ED25519-SK key, as `ssh-keygen` writes one.
fn security_key_file(path: &Path) {
    let base = generate(KeyKind::Ed25519, "").unwrap();
    let point = base.public_key().key_data().ed25519().unwrap().0.to_vec();
    let enrolled = Enrolled { public: point, key_handle: vec![3; 64] };
    let key = private_key(Alg::Ed25519, &enrolled, "ssh:", USER_PRESENCE_REQUIRED, "sk-test").unwrap();
    std::fs::write(path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    let line = key.public_key().to_openssh().unwrap();
    std::fs::write(format!("{}.pub", path.display()), format!("{line}\n")).unwrap();
}

#[test]
fn agent_holds_a_security_key_and_signs_nothing_with_no_device() {
    let home = scratch("hold");
    let key = home.join("id_ed25519_sk");
    security_key_file(&key);
    let host_key = home.join("host_key");
    let made = ran({
        let mut cmd = podssh(&home, None, &["keygen", "-q", "-N", "", "-f"]);
        cmd.arg(&host_key);
        cmd
    });
    assert_eq!(made.status.code(), Some(0), "{}", String::from_utf8_lossy(&made.stderr));
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&host_key));

    let mut serve = podssh(&home, None, &["agent"]);
    let mut child = serve.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let first = lines.next().expect("a line").expect("the line of SSH_AUTH_SOCK");
    let sock = first
        .strip_prefix("SSH_AUTH_SOCK=")
        .and_then(|rest| rest.split_once(';'))
        .map(|(sock, _)| sock.to_string())
        .unwrap_or_else(|| panic!("not the line of SSH_AUTH_SOCK: {first}"));
    std::thread::spawn(move || for _ in lines {});
    let running = Running(child);

    let added = ran(podssh(&home, Some(&sock), &["agent", "add", key.to_str().unwrap()]));
    assert_eq!(added.status.code(), Some(0), "{}", String::from_utf8_lossy(&added.stderr));
    let listed = ran(podssh(&home, Some(&sock), &["agent", "list"]));
    let out = String::from_utf8_lossy(&listed.stdout);
    assert!(out.starts_with("256 SHA256:") && out.contains("(ED25519-SK)"), "{out}");

    let mut login = podssh(&home, Some(&sock), &["ssh", "--direct", "-v", "-p", &port.to_string()]);
    login.args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"]);
    login.arg(format!("UserKnownHostsFile={}", home.join("known_hosts").display()));
    login.args(["key-sk@127.0.0.1", "greet"]);
    let refused = ran(login);
    let err = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(255), "{err}");
    assert!(err.contains("Confirm user presence for key ED25519-SK SHA256:"), "the touch is asked: {err}");
    assert!(err.contains("the agent could not sign"), "{err}");

    let removed = ran(podssh(&home, Some(&sock), &["agent", "remove", key.to_str().unwrap()]));
    assert_eq!(removed.status.code(), Some(0), "{}", String::from_utf8_lossy(&removed.stderr));
    let empty = ran(podssh(&home, Some(&sock), &["agent", "list"]));
    assert_eq!(empty.status.code(), Some(1), "{}", String::from_utf8_lossy(&empty.stdout));
    drop(running);
    drop(runtime);
}
