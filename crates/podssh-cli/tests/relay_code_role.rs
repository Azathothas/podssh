//! Pairing by a short code (T-086) from end to end, through `podssh relay
//! serve` on the loopback with a certificate of a test CA, its mailbox the
//! meeting point (`--pair-mailbox wss://HOST/v1/mailbox`): `podssh relay
//! pair lab --code --allow FILE` on a pseudo terminal shows the code there;
//! `podssh relay join lab` on another host's HOME takes it from a pipe, pins
//! the node's key and keeps the operator's part; the node's allowlist gets
//! the operator's key; neither output of the operator holds the code; and
//! the operator's host then asks the pair's status at the role by its label.
//! Linux alone, as the pseudo terminal of `pty_harness` is Linux's.
#![cfg(target_os = "linux")]

mod live_harness;
mod pty_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

use pty_harness::Pty;
use throughput_harness::{command_in, without_proxy, Cell, Session};

const LIMIT: Duration = Duration::from_secs(120);
/// What precedes the code on the giver's terminal.
const SHOWN: &str = "valid for 10 minutes: ";

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

fn role_env(ca: &str) -> [(&'static str, String); 2] {
    [("SSL_CERT_FILE", ca.to_string()), ("PODSSH_RELAY_ADDR", "relay-a.test=127.0.0.1".to_string())]
}

fn strings(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

#[test]
fn a_node_s_host_gives_its_pair_by_a_code_through_the_role_s_mailbox() {
    let s = Session::start("code-role");
    let Some((_role, host, ca)) = role(&s) else { return };
    let mailbox = format!("wss://{host}/v1/mailbox");
    let allow = s.home.join("allow");
    let allow_text = allow.display().to_string();
    let mut args = strings(&["relay", "pair", "lab", "--code", "--relay-host", host.as_str()]);
    args.extend(strings(&["--pair-mailbox", mailbox.as_str(), "--allow", allow_text.as_str()]));
    let mut giver = without_proxy(s.command(&args));
    giver.envs(role_env(&ca));
    let giver = Pty::start(giver, 24, 160);
    assert!(giver.expect(SHOWN, LIMIT), "the code shows on the terminal: {}", giver.text());
    let text = giver.text();
    let after = text.split(SHOWN).nth(1).unwrap_or_default();
    let code = after.split(['\r', '\n']).next().unwrap_or_default().trim().to_string();
    assert_eq!(code.split('-').count(), 4, "a nameplate and three words: {code:?}");

    let operator_home = throughput_harness::scratch("code-operator");
    let joining = strings(&["relay", "join", "lab", "--pair-mailbox", mailbox.as_str()]);
    let mut taker = without_proxy(command_in(&operator_home, &joining));
    taker.envs(role_env(&ca)).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut taker = taker.spawn().expect("podssh relay join runs");
    writeln!(taker.stdin.take().expect("its stdin"), "{code}").expect("the code on its stdin");
    let deadline = Instant::now() + LIMIT;
    while taker.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "podssh relay join did not end within {LIMIT:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = taker.wait_with_output().unwrap();
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "podssh relay join: {stdout}{stderr}");
    assert!(stdout.starts_with("lab: joined the node lab (SHA256:"), "{stdout}");
    for word in code.split('-').skip(1) {
        assert!(!stdout.contains(word) && !stderr.contains(word), "a word of the code in the operator's output");
    }
    assert_eq!(giver.wait(LIMIT), Some(0), "podssh relay pair --code: {}", giver.text());
    assert!(giver.text().contains("lab: given to SHA256:"), "{}", giver.text());
    let allowed = std::fs::read_to_string(&allow).expect("the node's allowlist");
    assert!(allowed.contains("# paired by a code"), "{allowed}");

    let pins = std::fs::read_to_string(operator_home.join("cache").join("podssh").join("known-nodes")).unwrap();
    assert!(pins.starts_with("lab SHA256:"), "the node's key is pinned under the label: {pins}");
    let status = without_proxy(command_in(&operator_home, &strings(&["relay", "status", "lab"])))
        .envs(role_env(&ca))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&status.stdout);
    assert!(status.status.success() && said.starts_with("lab: offline"), "the operator's part, by its label: {said}");
}
