//! `podssh agent` as processes (T-034): the agent serves and says
//! `SSH_AUTH_SOCK`; `add` sends a key, `list` shows it, and `podssh ssh`
//! logs in with it, with no `-i`, to the test's SSH server, which needs a
//! key for a user named `key-...`; `remove` takes it back, and then the
//! login fails. The agent ends at SIGTERM, and its socket goes.

mod cleanup;
mod ssh_harness;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-agent-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// podssh with a clean environment: `home` as HOME, and `sock` as
/// SSH_AUTH_SOCK when given. The agent's directory goes in `home` too, so a
/// test that fails leaves nothing outside its scratch directory.
fn podssh(home: &Path, sock: Option<&str>, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("HOME", home).env("USERPROFILE", home).env("PODSSH_SSH_CONFIG", "none").env("TMPDIR", home);
    for name in [
        "PODSSH_OFFLINE",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "SSH_ASKPASS",
        "PODSSH_LISTEN",
        "XDG_RUNTIME_DIR",
    ] {
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

/// A process that is killed when the test ends, also when it fails.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The agent, started, and the socket of its line `SSH_AUTH_SOCK=...;`.
fn agent(home: &Path, args: &[&str]) -> (Running, String) {
    let mut all = vec!["agent"];
    all.extend_from_slice(args);
    let mut child =
        podssh(home, None, &all).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let first = lines.next().expect("a line").expect("the line of SSH_AUTH_SOCK");
    let sock = first
        .strip_prefix("SSH_AUTH_SOCK=")
        .and_then(|rest| rest.split_once(';'))
        .map(|(sock, _)| sock.to_string())
        .unwrap_or_else(|| panic!("not the line of SSH_AUTH_SOCK: {first}"));
    std::thread::spawn(move || for _ in lines {});
    (Running(child), sock)
}

#[test]
fn agent_serves_and_podssh_ssh_logs_in_with_its_key() {
    let home = scratch("serve");
    let key = home.join("id_agent");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-C", "agent-test", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let host_key = home.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&host_key));

    let (running, sock) = agent(&home, &[]);
    let empty = ran(podssh(&home, Some(&sock), &["agent", "list"]));
    assert_eq!(empty.status.code(), Some(1), "{}", String::from_utf8_lossy(&empty.stderr));
    assert!(String::from_utf8_lossy(&empty.stdout).contains("The agent has no identities."));

    let added = ran(podssh(&home, Some(&sock), &["agent", "add", key.to_str().unwrap()]));
    assert_eq!(added.status.code(), Some(0), "{}", String::from_utf8_lossy(&added.stderr));
    let listed = ran(podssh(&home, Some(&sock), &["agent", "list"]));
    let out = String::from_utf8_lossy(&listed.stdout);
    assert_eq!(listed.status.code(), Some(0), "{out}");
    // russh's agent keeps no comment: the fingerprint and the type.
    let fingerprint = String::from_utf8_lossy(
        &ran({
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
            cmd.args(["keygen", "-l", "-f"]).arg(&key);
            cmd
        })
        .stdout,
    )
    .split_whitespace()
    .nth(1)
    .unwrap_or_default()
    .to_string();
    assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");
    assert!(out.starts_with("256 ") && out.contains(&fingerprint) && out.contains("(ED25519)"), "{out}");

    let login = |sock: Option<&str>| {
        let known = home.join("known_hosts");
        let mut cmd = podssh(&home, sock, &["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes"]);
        cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
        cmd.arg(format!("UserKnownHostsFile={}", known.display()));
        cmd.args(["key-agent@127.0.0.1", "greet"]);
        ran(cmd)
    };
    let with = login(Some(&sock));
    assert_eq!(with.status.code(), Some(0), "the agent's key: {}", String::from_utf8_lossy(&with.stderr));
    let removed = ran(podssh(&home, Some(&sock), &["agent", "remove", "--all"]));
    assert_eq!(removed.status.code(), Some(0), "{}", String::from_utf8_lossy(&removed.stderr));
    let without = login(Some(&sock));
    assert_eq!(without.status.code(), Some(255), "no key: {}", String::from_utf8_lossy(&without.stderr));

    // SIGTERM, as a user ends it: the agent removes its socket and its
    // directory, and exits 143. A kill of the guard could not let it.
    #[cfg(unix)]
    {
        let mut running = running;
        // SAFETY: a signal to the child that this test started and still holds.
        unsafe { libc::kill(running.0.id() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + LIMIT;
        let status = loop {
            if let Some(status) = running.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "the agent did not end at SIGTERM within {LIMIT:?}");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(status.code(), Some(143), "the agent's exit at SIGTERM");
        let dir = Path::new(&sock).parent().expect("the socket's directory");
        assert!(!Path::new(&sock).exists() && !dir.exists(), "the socket or its directory stayed: {sock}");
        assert!(dir.starts_with(&home), "the agent's directory is in the test's: {}", dir.display());
    }
    #[cfg(not(unix))]
    drop(running);
}

#[test]
fn agent_subcommands_with_no_agent_say_so() {
    let home = scratch("none");
    let out = ran(podssh(&home, None, &["agent", "list"]));
    let err = String::from_utf8_lossy(&out.stderr);
    if cfg!(unix) {
        assert_eq!(out.status.code(), Some(69), "{err}");
        assert!(err.contains("SSH_AUTH_SOCK is not set"), "{err}");
    }
    let usage = ran(podssh(&home, None, &["agent", "frob"]));
    assert_eq!(usage.status.code(), Some(64), "{}", String::from_utf8_lossy(&usage.stderr));
}

#[test]
fn agent_refuses_to_listen_when_listening_is_off() {
    let home = scratch("off");
    let mut cmd = podssh(&home, None, &["agent"]);
    cmd.env("PODSSH_LISTEN", "no");
    let out = ran(cmd);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(78), "{err}");
    assert!(err.contains("PODSSH_LISTEN=no"), "{err}");
}

/// `podssh keygen -Y sign -U` signs with the agent's key, as git signs with
/// a key that an agent holds (T-020): `-f` names the public key alone, and
/// the signature holds. Once the agent forgets the key, `-U` refuses.
#[test]
fn keygen_signs_with_the_agents_key() {
    let home = scratch("sign");
    let key = home.join("id_sign");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sign-test", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let (running, sock) = agent(&home, &[]);
    let added = ran(podssh(&home, Some(&sock), &["agent", "add", key.to_str().unwrap()]));
    assert_eq!(added.status.code(), Some(0), "{}", String::from_utf8_lossy(&added.stderr));
    let data = home.join("data");
    std::fs::write(&data, b"signed by the agent\n").unwrap();
    let public = format!("{}.pub", key.display());
    let sign = |sock: &str| {
        let mut cmd = podssh(&home, Some(sock), &["keygen", "-q", "-Y", "sign", "-U", "-f", &public, "-n", "git"]);
        cmd.arg(&data);
        ran(cmd)
    };
    let signed = sign(&sock);
    assert_eq!(signed.status.code(), Some(0), "{}", String::from_utf8_lossy(&signed.stderr));
    let mut check = podssh(&home, None, &["keygen", "-Y", "check-novalidate", "-n", "git", "-s"]);
    check.arg(format!("{}.sig", data.display())).stdin(std::fs::File::open(&data).unwrap());
    let checked = check.output().unwrap();
    assert_eq!(checked.status.code(), Some(0), "{}", String::from_utf8_lossy(&checked.stderr));
    assert!(String::from_utf8_lossy(&checked.stdout).starts_with("Good \"git\" signature with ED25519 key SHA256:"));
    std::fs::remove_file(format!("{}.sig", data.display())).unwrap();
    let removed = ran(podssh(&home, Some(&sock), &["agent", "remove", "--all"]));
    assert_eq!(removed.status.code(), Some(0), "{}", String::from_utf8_lossy(&removed.stderr));
    let refused = sign(&sock);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("the agent does not hold the key"));
    drop(running);
}

/// `podssh keygen -s CA.pub -U` certifies a key with the CA that the agent
/// holds (T-021): `-L` names that CA.
#[test]
fn keygen_certifies_with_the_agents_ca() {
    let home = scratch("cert");
    let ca = home.join("ca");
    let user = home.join("user");
    for key in [&ca, &user] {
        let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
            .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(key)
            .status()
            .unwrap();
        assert!(made.success());
    }
    let (running, sock) = agent(&home, &[]);
    let added = ran(podssh(&home, Some(&sock), &["agent", "add", ca.to_str().unwrap()]));
    assert_eq!(added.status.code(), Some(0), "{}", String::from_utf8_lossy(&added.stderr));
    let ca_pub = format!("{}.pub", ca.display());
    let user_pub = format!("{}.pub", user.display());
    let signed =
        ran(podssh(&home, Some(&sock), &["keygen", "-q", "-s", &ca_pub, "-U", "-I", "by-agent", "-n", "a", &user_pub]));
    assert_eq!(signed.status.code(), Some(0), "{}", String::from_utf8_lossy(&signed.stderr));
    let fingerprint = String::from_utf8_lossy(&ran(podssh(&home, None, &["keygen", "-l", "-f", &ca_pub])).stdout)
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let cert = format!("{}-cert.pub", user.display());
    let shown = String::from_utf8_lossy(&ran(podssh(&home, None, &["keygen", "-L", "-f", &cert])).stdout).into_owned();
    assert!(shown.contains(&format!("Signing CA: ED25519 {fingerprint} (using ssh-ed25519)")), "{shown}");
    assert!(shown.contains("Key ID: \"by-agent\""), "{shown}");
    drop(running);
}
