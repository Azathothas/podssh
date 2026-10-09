//! `podssh relay spec` (T-060) as a process: the pinned copy of the relay's
//! document agrees with the facts that podssh was built with, a copy with a
//! fact changed fails on that fact, and the refusals come before any request.
//! The live relay: `relay_spec_live`, below, with `--ignored`.

mod pair_harness;

use pair_harness::*;

/// The pinned copy of the relay's document, which the facts were measured on.
const PINNED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt");

#[test]
fn the_pinned_copy_agrees_with_the_facts() {
    let home = scratch("spec-ok");
    let (rc, out, err) = podssh(&home, &["relay", "spec", "--document", PINNED], &[]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.starts_with("ok   the relay's document agrees with the "), "{out}");
    assert!(out.contains("246 lines") && out.contains("pinned 2026-10-03-r2"), "{out}");
    assert_eq!(out.lines().count(), 1, "one line: {out}");
}

#[test]
fn a_copy_with_a_renamed_node_path_fails_on_that_fact() {
    // The plant of crates/podssh-probe/tests/relay_facts.rs, through the binary.
    let home = scratch("spec-plant");
    let text = std::fs::read_to_string(PINNED).unwrap();
    assert!(text.contains("/v1/node/<name>"), "the pinned copy names the node path");
    let planted = home.join("planted.txt");
    std::fs::write(&planted, text.replacen("/v1/node/<name>", "/v1/drop/<name>", 1)).unwrap();
    let (rc, out, err) = podssh(&home, &["relay", "spec", "--document", planted.to_str().unwrap()], &[]);
    assert_eq!(rc, 1, "{out}{err}");
    assert!(out.lines().any(|l| l.starts_with("FAIL reverse-node-path:")), "{out}");
    assert!(err.contains("the relay changed something that podssh depends on"), "{err}");
}

#[test]
fn the_refusals_come_before_any_request() {
    let home = scratch("spec-refuse");
    let (rc, out, err) = podssh(&home, &["relay", "spec", "extra"], &[]);
    assert_eq!((rc, out.is_empty()), (64, true), "{err}");
    assert!(err.contains("spec takes no NAME"), "{err}");
    let (rc, _, err) = podssh(&home, &["relay", "status", "lab", "--document", PINNED], &[]);
    assert_eq!(rc, 64, "--document goes with spec only: {err}");
    let missing = home.join("missing.txt");
    let (rc, out, err) = podssh(&home, &["relay", "spec", "--document", missing.to_str().unwrap()], &[]);
    assert_eq!((rc, out.is_empty()), (78, true), "{err}");
    assert!(err.contains("--document"), "{err}");
    // Offline, the live relay is not asked, and the check did not run.
    let (rc, out, err) = podssh(&home, &["relay", "spec"], &[("PODSSH_OFFLINE", "1")]);
    assert_eq!((rc, out.is_empty()), (69, true), "{err}");
}

/// The live relay: its document agrees with the facts (exit 0), or the
/// relay changed (exit 1). Either way the verdict is one that ran.
#[test]
#[ignore = "network: reads the live relay's /health and /llms-full.txt"]
fn relay_spec_live() {
    // The harness keeps each run offline; this one goes out, through the
    // proxy of the environment if there is one, to the built-in relay.
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_podssh"));
    for name in ["PODSSH_RELAY", "PODSSH_RELAY_ADDR", "PODSSH_RELAY_TOKEN", "PODSSH_OFFLINE"] {
        cmd.env_remove(name);
    }
    let done = cmd.args(["relay", "spec"]).stdin(std::process::Stdio::null()).output().expect("podssh runs");
    let (rc, out, err) = (
        done.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&done.stdout).into_owned(),
        String::from_utf8_lossy(&done.stderr).into_owned(),
    );
    eprintln!("{out}{err}");
    assert!(rc == 0 || rc == 1, "the check did not run: exit {rc}: {err}");
    assert!(out.starts_with("ok ") || out.starts_with("FAIL "), "{out}");
}
