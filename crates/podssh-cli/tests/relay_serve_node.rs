//! The reverse road of `podssh relay serve` (T-427), on the loopback with a
//! certificate of a test CA, as the binary's own commands and OpenSSH use
//! it with no other relay: `podssh relay pair`, `status` and `revoke`
//! against the role; `podssh ssh node://` to the test's server through a
//! node of the role's pair; and OpenSSH's `ssh`, with `podssh operator` as
//! its ProxyCommand, to OpenSSH's sshd behind `podssh node`, 8 MiB each way
//! with equal digests. The node tests of the stand-in run against the role
//! with `PODSSH_RELAY_UNDER_TEST=podssh` (`throughput_harness/cells.rs`).
//! The renewal of T-592: `podssh relay pair --renew` and a node in its
//! pair's last day renew it at the role, with its tokens, so that an
//! operator's file past its end still reaches the node; the stand-in, whose
//! contract renews no pair, gets the way of the next pair and 69.

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

/// Milliseconds since the epoch, now.
fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

/// The end that the pair's file at `path` names.
fn expires_of(path: &std::path::Path) -> i64 {
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    doc["expires"].as_i64().unwrap()
}

/// The pair's file at `path`, naming the end `ms` and nothing else new: the
/// record of a pair in its last day, or of an operator's file past its end,
/// where the role's own pairs live 72 h.
fn set_expires(path: &std::path::Path, ms: i64) {
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    doc["expires"] = ms.into();
    // The file keeps its mode, 0600.
    std::fs::write(path, doc.to_string()).unwrap();
}

/// T-592: the owner's `relay pair --renew` at the role, then a node whose
/// pair is in its last day by its record: it renews the pair by itself and
/// says so, and the store keeps the new end; an operator's file whose end
/// has passed still reaches the node, as the role names the later end, and
/// `podssh ssh` logs in to the test's server through it.
#[test]
fn a_node_renews_its_pair_in_its_last_day() {
    let s = Session::start("serve-renew");
    let Some((_, host, ca)) = role(&s) else { return };
    let file = s.home.join("lab-operator.json");
    let file_text = file.display().to_string();
    let out = podssh(&s, &ca, &["relay", "pair", "lab", "--relay-host", &host, "--operator-file", &file_text]);
    assert!(out.status.success(), "podssh relay pair against the role: {}", said(&out));
    let out = podssh(&s, &ca, &["relay", "pair", "--renew", "lab"]);
    assert!(out.status.success(), "the owner's renewal: {}", said(&out));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("lab: expires "), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("its tokens are the same"), "{}", said(&out));
    let stored = s.home.join("cache").join("podssh").join(podssh_relay::pair::file_name("lab").unwrap());
    set_expires(&stored, now_ms() + 23 * 3_600_000);
    set_expires(&file, now_ms() + 2_000);
    let args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", s.port)];
    let mut node = without_proxy(s.command(&args));
    let node = node.envs(role_env(&ca)).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    let mut node = node.spawn().unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    wait_for(&lines, "online").expect("the node is online on the role");
    let renewed = wait_for(&lines, "the pair is renewed at its relay until").expect("the node renews its pair");
    assert!(renewed.contains("each operator's file holds"), "{renewed}");
    assert!(expires_of(&stored) > now_ms() + 71 * 3_600_000, "the store keeps the new end");
    // Past the end that the operator's file names.
    while expires_of(&file) >= now_ms() {
        std::thread::sleep(Duration::from_millis(200));
    }
    let out = podssh(&s, &ca, &["relay", "status", "--pair-file", &file_text, "lab"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success() && text.starts_with("lab: online"), "{}", said(&out));
    assert!(!text.contains("expires in"), "the role's end, 72 h ahead, not the file's: {text}");
    let mut login = vec!["ssh".to_string()];
    login.extend(s.common());
    login.extend(["--pair-file".to_string(), file_text.clone(), "node://tester@lab".into(), "greet".into()]);
    let login: Vec<&str> = login.iter().map(String::as_str).collect();
    let out = podssh(&s, &ca, &login);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), ssh_harness::GREETING);
}

/// T-592: the stand-in relay, whose contract has no renewal, answers its
/// path with 404: `relay pair --renew` says that it renews no pair, with the
/// way of the next pair, exits 69, and leaves the store as it was. The mode
/// `expirefirst` is the stand-in's alone, so the role never stands in.
#[test]
fn renew_on_a_relay_with_none_says_so() {
    let s = Session::start("serve-renew-none");
    let cell = match Cell::fake_relay_mode(&s, "expirefirst:600", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let run = |words: &[&str]| {
        let mut args: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        args.extend(["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()]);
        s.stand_in(&args, &ca).stdin(Stdio::null()).output().unwrap()
    };
    let out = run(&["relay", "pair", "lab", "--relay-host", &relay]);
    assert!(out.status.success(), "podssh relay pair: {}", said(&out));
    let stored = s.home.join("cache").join("podssh").join(podssh_relay::pair::file_name("lab").unwrap());
    let before = std::fs::read(&stored).unwrap();
    let out = run(&["relay", "pair", "--renew", "lab"]);
    assert_eq!(out.status.code(), Some(69), "{}", said(&out));
    assert!(out.stdout.is_empty(), "no line of a renewal: {}", said(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("renews no pair") && err.contains("podssh relay pair lab --operator-file NEW"), "{err}");
    assert_eq!(std::fs::read(&stored).unwrap(), before, "the store is as it was");
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
