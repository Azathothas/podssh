//! The reverse road of `podssh relay serve` (T-427), on the loopback with a
//! certificate of a test CA, as the binary's own commands and OpenSSH use
//! it with no other relay: `podssh relay pair`, `status` and `revoke`
//! against the role; `podssh ssh node://` to the test's server through a
//! node of the role's pair; and OpenSSH's `ssh`, with `podssh operator` as
//! its ProxyCommand, to OpenSSH's sshd behind `podssh node`, 8 MiB each way
//! with equal digests. The node tests of the stand-in run against the role
//! with `PODSSH_RELAY_UNDER_TEST=podssh` (`throughput_harness/cells.rs`).

mod live_harness;
mod ssh_harness;
mod throughput_harness;

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use throughput_harness::{lines_of, wait_for, without_proxy, Cell, Far, Session};

const LIMIT: Duration = Duration::from_secs(120);

/// The role, its host (`relay-a.test:PORT`) and its CA, or `None` when this
/// host cannot make its certificate.
fn role(s: &Session) -> Option<(Cell, String, String)> {
    let cell = match Cell::podssh_relay(s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (host, ca) = (at("--relay-host"), at("--ca-file"));
    Some((cell, host, ca))
}

/// The variables of each run against the role: its CA, and its name pinned
/// to the loopback, for the commands and for a ProxyCommand alike.
fn role_env(ca: &str) -> Vec<(String, String)> {
    vec![("SSL_CERT_FILE".into(), ca.to_string()), ("PODSSH_RELAY_ADDR".into(), "relay-a.test=127.0.0.1".into())]
}

/// `podssh ARGS` against the role, within `LIMIT`.
fn podssh(s: &Session, ca: &str, args: &[&str]) -> Output {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let mut cmd = without_proxy(s.command(&args));
    cmd.envs(role_env(ca)).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh {args:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn said(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// A pair of the role's under `label`, and its node in front of `target`,
/// online.
fn node(s: &Session, host: &str, ca: &str, label: &str, target: &str) {
    let out = podssh(s, ca, &["relay", "pair", label, "--relay-host", host]);
    assert!(out.status.success(), "podssh relay pair against the role: {}", said(&out));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with(&format!("{label}: expires ")), "{}", said(&out));
    let args = vec!["node".to_string(), label.to_string(), target.to_string()];
    let mut node = without_proxy(s.command(&args))
        .envs(role_env(ca))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    wait_for(&lines, "online").expect("the node is online on the role");
}

#[test]
fn podssh_ssh_reaches_a_node_through_the_role_and_relay_reads_its_pair() {
    let s = Session::start("serve-node");
    let Some((_, host, ca)) = role(&s) else { return };
    node(&s, &host, &ca, "lab", &format!("127.0.0.1:{}", s.port));
    let out = podssh(&s, &ca, &["relay", "status", "lab"]);
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("lab: online"), "{}", said(&out));

    let mut args = vec!["ssh".to_string()];
    args.extend(s.common());
    args.push("node://tester@lab".into());
    let cell = Cell { name: "node://".into(), args, far: Far::Test, env: role_env(&ca), must_say: None, through: None };
    // The harness checks the count of the bytes that arrived.
    let up = throughput_harness::run(&s, &cell, true, 4 << 20).expect("4 MiB up through a node of the role");
    let down = throughput_harness::run(&s, &cell, false, 4 << 20).expect("4 MiB down through a node of the role");
    eprintln!("through a node of podssh relay serve: up {up:.1} MiB/s, down {down:.1} MiB/s");

    let out = podssh(&s, &ca, &["relay", "revoke", "lab"]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("lab: stopped"), "{}", said(&out));
    let out = podssh(&s, &ca, &["relay", "status", "lab"]);
    assert!(!out.status.success(), "no pair after revoke: {}", said(&out));
}

/// The SHA-256 of `path`, by the system's `sha256sum`.
fn digest_of(path: &std::path::Path) -> Option<String> {
    let out = Command::new("sha256sum").arg(path).output().ok()?;
    String::from_utf8(out.stdout).ok()?.split_whitespace().next().map(str::to_string)
}

/// This user's name, for OpenSSH's login to the loopback's sshd.
fn this_user() -> Option<String> {
    let name = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).ok().filter(|u| !u.is_empty());
    name.or_else(|| {
        let out = Command::new("id").arg("-un").output().ok()?;
        Some(String::from_utf8(out.stdout).ok()?.trim().to_string()).filter(|u| !u.is_empty())
    })
}

#[test]
fn openssh_through_podssh_operator_and_a_node_of_the_role_reaches_openssh_with_equal_digests() {
    let s = Session::start("serve-node-openssh");
    let Some((_, host, ca)) = role(&s) else { return };
    let (Some(user), true) = (this_user(), throughput_harness::found("ssh", &["-V"])) else {
        eprintln!("did not run: no OpenSSH client or no user name here");
        return;
    };
    let dir = s.home.join("openssh");
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("id");
    let made = podssh(&s, &ca, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &key.display().to_string()]);
    assert!(made.status.success(), "{}", said(&made));
    let sshd = match live_harness::sshd::start(&dir, &key.with_extension("pub")) {
        Ok(sshd) => sshd,
        Err(why) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    // The node runs the resumable layer and the channel, which `podssh
    // operator` speaks: OpenSSH at each end sees a byte stream.
    node(&s, &host, &ca, "lab", &format!("127.0.0.1:{}", sshd.port));
    let data = dir.join("data");
    let bytes: Vec<u8> = (0..8u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    std::fs::write(&data, &bytes).unwrap();
    let want = digest_of(&data).expect("sha256sum");
    let proxy = format!("{} operator lab", env!("CARGO_BIN_EXE_podssh"));
    let ssh = |remote: &str| {
        let mut cmd = Command::new("ssh");
        cmd.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"])
            .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
            .arg("-i")
            .arg(&key)
            .arg("-o")
            .arg(format!("ProxyCommand={proxy}"))
            .args(["-p", &sshd.port.to_string(), &format!("{user}@127.0.0.1"), remote])
            // The ProxyCommand finds the pair in this HOME's cache.
            .env("HOME", &s.home)
            .env("XDG_CACHE_HOME", s.home.join("cache"))
            .env("PODSSH_SSH_CONFIG", "none")
            .env("PODSSH_TRANSIT", "no")
            .envs(role_env(&ca));
        without_proxy(cmd)
    };
    let mut up = ssh("sha256sum");
    up.stdin(std::fs::File::open(&data).unwrap()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = up.output().unwrap();
    let text = said(&out);
    assert!(out.status.success(), "up: {text}");
    assert_eq!(text.split_whitespace().next(), Some(want.as_str()), "up: {text}");
    let back = dir.join("back");
    let mut down = ssh(&format!("cat {}", data.display()));
    down.stdin(Stdio::null()).stdout(std::fs::File::create(&back).unwrap()).stderr(Stdio::piped());
    let out = down.output().unwrap();
    assert!(out.status.success(), "down: {}", said(&out));
    assert_eq!(digest_of(&back).as_deref(), Some(want.as_str()), "down: the 8 MiB came back whole");
}
