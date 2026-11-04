//! `podssh doctor --exit NAME` (T-458) as a process, on the stand-in relay:
//! the net of `tests/exit.rs`, a node `gw` with `--exit` and `--routes
//! 127.0.0.1/32`, `a` whom the policy lets out and lets reach the range, `b`
//! whom it lets out to public addresses alone, and `lab`, a member with no
//! role exit, served by a node of its own. The section `exit` gives three
//! lines: the net's word, the pair, and one session from the exit, each with
//! whose refusal it is. The target of each session is the tests' SSH server
//! on the loopback, so no run leaves this host. The check says that it did
//! not run when this host has no Python or no openssl for the stand-in.

mod live_harness;
mod ssh_harness;
mod throughput_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use podssh_relay::identity::Identity;
use throughput_harness::{command_in, lines_of, wait_for, Cell, Session};

/// The bound on each run of doctor.
const LIMIT: Duration = Duration::from_secs(180);

fn ran(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// An end's key in a private file of `dir`, from one byte; and its hex.
fn key_file(dir: &Path, name: &str, seed: u8) -> (String, String) {
    let path = dir.join(name);
    let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    podssh_relay::cache::create_private(&path, format!("{hex}\n").as_bytes()).unwrap();
    (path.display().to_string(), Identity::from_seed(&[seed; 32]).public().hex())
}

/// The lines of the section `exit` of a run: (label, check, detail).
fn section(text: &str) -> Vec<(String, String, String)> {
    let part = text.split("\nexit\n").nth(1).unwrap_or_else(|| panic!("no section exit: {text}"));
    // `  LABEL  CHECK          DETAIL`: the label in 4, the check in 14.
    let lines = part.lines().take_while(|l| l.starts_with("  "));
    lines.map(|l| (l[2..6].trim().into(), l[8..22].trim().into(), l[23..].into())).collect()
}

/// The detail of the check `name`, whose label must be `label`.
fn detail<'a>(lines: &'a [(String, String, String)], name: &str, label: &str) -> &'a str {
    let line = lines.iter().find(|l| l.1 == name).unwrap_or_else(|| panic!("no line {name}: {lines:?}"));
    assert_eq!(line.0, label, "{name}: {}", line.2);
    &line.2
}

#[test]
fn doctor_names_the_exit_its_net_its_pair_and_whose_a_refusal_is() {
    let session = Session::start("doctor-exit");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => return eprintln!("did not run: {why}"),
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let dir = session.home.join("private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let ((gw_key, gw), (lab_key, lab)) = (key_file(&dir, "gw.key", 0x21), key_file(&dir, "lab.key", 0x22));
    let ((a_key, a), (b_key, b)) = (key_file(&dir, "a.key", 0x31), key_file(&dir, "b.key", 0x41));
    let owner: PathBuf = dir.join("owner");
    let keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f"].iter().map(|w| w.to_string());
    let keygen: Vec<String> = keygen.chain([owner.display().to_string()]).collect();
    assert_eq!(ran(&mut command_in(&session.home, &keygen)).0, 0, "podssh keygen");
    let owner_doc = dir.join("owner.doc");
    let owner_says = |args: &[&str]| {
        let mut words: Vec<String> = args.iter().map(|w| w.to_string()).collect();
        words.extend(["--owner-key".to_string(), owner.display().to_string()]);
        let (rc, _, err) = ran(command_in(&session.home, &words).env("PODSSH_NET", &owner_doc));
        assert_eq!(rc, 0, "{args:?}: {err}");
    };
    owner_says(&["net", "init", "home"]);
    owner_says(&["net", "add", "gw", &gw, "--roles", "node,exit"]);
    owner_says(&["net", "add", "lab", &lab]);
    owner_says(&["net", "add", "a", &a]);
    owner_says(&["net", "add", "b", &b]);
    let policy = dir.join("policy.json");
    let a_rule = r#"{"from": ["a"], "to": ["exit:gw", "127.0.0.1/32", "lab"]}"#;
    std::fs::write(&policy, format!(r#"{{"rules": [{a_rule}, {{"from": ["b"], "to": ["exit:gw"]}}]}}"#)).unwrap();
    owner_says(&["net", "policy", "set", &policy.display().to_string()]);
    let doc = dir.join("net.doc");
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let take = words(&["net", "take", &owner_doc.display().to_string()]);
    let (rc, _, err) = ran(command_in(&session.home, &take).env("PODSSH_NET", &doc));
    assert_eq!(rc, 0, "podssh net take: {err}");
    // Each end: the pins after the verb, the stand-in's CA, the net's document.
    let end = |args: &[String]| {
        let mut cmd = session.stand_in(&args[..1], &ca);
        cmd.args(&pins).args(&args[1..]).env("PODSSH_NET", &doc);
        cmd
    };
    for name in ["gw", "lab"] {
        let (rc, _, err) = ran(&mut end(&words(&["relay", "pair", name, "--relay-host", &relay])));
        assert_eq!(rc, 0, "podssh relay pair {name}: {err}");
    }
    let target = format!("127.0.0.1:{}", session.port);
    let nodes = [
        words(&["node", "gw", "--exit", "--routes", "127.0.0.1/32", "--key", &gw_key]),
        words(&["node", "lab", &target, "--key", &lab_key]),
    ];
    for args in nodes {
        let mut node = end(&args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let lines = lines_of(&mut node);
        session.keep(node);
        wait_for(&lines, "online").expect("the node is online");
    }
    let doctor = |exit: &str, key: &str, to: &str| {
        let args = words(&["doctor", "--quick", "--relay-host", &relay, "--exit", exit, "--exit-target", to]);
        let mut cmd = end(&args);
        cmd.args(["--client-key", key]).env_remove("PODSSH_RELAY_TOKEN").env_remove("PODSSH_OFFLINE");
        let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let deadline = Instant::now() + LIMIT;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("podssh doctor --exit {exit} still ran after {LIMIT:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let out = child.wait_with_output().unwrap();
        let lines = section(&String::from_utf8_lossy(&out.stdout));
        for (label, check, detail) in lines.iter().filter(|l| l.1.starts_with("exit")) {
            eprintln!("--exit {exit}: {label} {check}: {detail}");
        }
        lines
    };

    // a: the exit lets it out, and the session reaches the server's banner.
    let lines = doctor("gw", &a_key, &target);
    let net = detail(&lines, "exit net", "ok");
    assert!(net.starts_with("gw is an exit of the net home (serial ") && net.contains("lets a out: rule 1"), "{net}");
    assert!(detail(&lines, "exit pair", "ok").starts_with(&format!("the pair gw at {relay}, until ")));
    let session_line = detail(&lines, "exit", "ok");
    assert!(session_line.starts_with(&format!("{target} from the exit gw, over the pair's road at {relay}")));
    assert!(session_line.contains("; its first bytes: SSH-2.0-"), "{session_line}");

    // b: let out, but not to the loopback: the net's policy, at the exit.
    let lines = doctor("gw", &b_key, &target);
    assert!(detail(&lines, "exit net", "ok").contains("lets b out: rule 2"));
    let refused = detail(&lines, "exit", "FAIL");
    assert!(refused.starts_with(&format!("{target} from the exit gw: refused by the net's policy: ")), "{refused}");
    assert!(refused.contains("lets b reach 127.0.0.1"), "{refused}");

    // a, to an address of no range of --routes: the exit's own check.
    let lines = doctor("gw", &a_key, "10.255.255.1:9");
    let refused = detail(&lines, "exit", "FAIL");
    assert!(refused.contains("refused by the exit's check of the address") && refused.contains("not a public"));

    // lab: a member with no role exit, and a node that lends no egress.
    let lines = doctor("lab", &a_key, &target);
    let net = detail(&lines, "exit net", "FAIL");
    assert!(net.ends_with("gives lab no role exit, so it lets nobody out"), "{net}");
    let refused = detail(&lines, "exit", "FAIL");
    assert!(refused.starts_with(&format!("{target} from the exit lab: refused by ")), "{refused}");
}

#[test]
fn a_flag_of_the_exit_with_no_exit_is_refused_before_any_check() {
    let home = throughput_harness::scratch("doctor-exit-flags");
    for (args, says) in [
        (vec!["doctor", "--exit-target", "h.example:22"], "--exit-target is for --exit NAME"),
        (vec!["doctor", "--client-key", "k"], "--client-key is for --exit NAME"),
        (vec!["doctor", "--exit", "gw", "--exit-target", "h.example"], "--exit-target h.example: give HOST:PORT"),
    ] {
        let words: Vec<String> = args.iter().map(|w| w.to_string()).collect();
        let (rc, out, err) = ran(&mut command_in(&home, &words));
        assert!(rc == 64 && out.is_empty() && err.contains(says), "{args:?}: {rc} {err}");
    }
    let _ = std::fs::remove_dir_all(&home);
}
