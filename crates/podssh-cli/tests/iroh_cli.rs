//! The command line of the iroh road (T-163), against the binary and
//! offline: the flags of `podssh node` that need `--iroh`, `--iroh-key` of
//! `podssh ssh` with no iroh destination, and, in a build with the feature,
//! each refusal of `podssh node --iroh` and `podssh ssh iroh:TICKET` before
//! anything connects, a key file included.

use std::process::{Command, Stdio};

/// iroh's own ticket: the test vector of iroh-tickets 1.0.0 (a key, the
/// relay `http://derp.me./` and `127.0.0.1:1024`).
#[cfg(feature = "iroh")]
const TICKET: &str =
    "iroh:endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";

/// Run the binary offline with no terminal, with its cache in `cache`:
/// (exit code, stdout, stderr).
fn podssh(args: &[&str], cache: &std::path::Path) -> (i32, Vec<u8>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(args)
        // The ssh_config of the machine that runs the test must not change it.
        .env("PODSSH_SSH_CONFIG", "none")
        // No test may reach the network, nor touch the user's cache.
        .env("PODSSH_OFFLINE", "1")
        .env("XDG_CACHE_HOME", cache)
        .env("LOCALAPPDATA", cache)
        .env_remove("PODSSH_TIMEOUT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the podssh binary runs");
    (out.status.code().unwrap_or(-1), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// A fresh, empty scratch directory unique to one test.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-iroh-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_flag_of_the_iroh_road_needs_iroh() {
    let cache = scratch("needs");
    for flag in [&["--iroh-key", "node.key"][..], &["--iroh-allow", "allow"][..], &["--iroh-ephemeral"][..]] {
        let mut args = vec!["node", "lab", "127.0.0.1:22"];
        args.extend_from_slice(flag);
        let (rc, out, err) = podssh(&args, &cache);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(out.is_empty());
        assert!(err.contains(flag[0]) && err.contains("add --iroh"), "{args:?}: {err}");
    }
}

#[test]
fn iroh_ticket_needs_a_node_destination() {
    let (rc, _, err) = podssh(&["ssh", "--iroh-ticket", "iroh:x", "user@example.org", "true"], &scratch("ticket"));
    if cfg!(feature = "iroh") {
        assert_eq!(rc, 64, "{err}");
        assert!(err.contains("--iroh-ticket is for a node://NAME destination"), "{err}");
    } else {
        assert_eq!(rc, 70, "{err}");
        assert!(err.contains("--features iroh"), "{err}");
    }
}

#[cfg(feature = "iroh")]
#[test]
fn a_race_with_a_bad_ticket_is_refused_before_anything_connects() {
    let cache = scratch("race-ticket");
    let (rc, _, err) = podssh(&["ssh", "--iroh-ticket", "iroh:endpoint0189", "node://user@lab", "true"], &cache);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("not an iroh ticket"), "{err}");
    // With a good ticket, offline: the pair is looked for first, and no key
    // is made.
    let ticket = format!("--iroh-ticket={TICKET}");
    let (rc, _, err) = podssh(&["ssh", "-o", "BatchMode=yes", &ticket, "node://user@lab", "true"], &cache);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("node://lab"), "{err}");
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0, "no key was made");
}

#[test]
fn iroh_key_needs_an_iroh_destination() {
    let (rc, _, err) = podssh(&["ssh", "--iroh-key", "client.key", "user@example.org", "true"], &scratch("ssh-key"));
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--iroh-key is for an iroh:TICKET destination"), "{err}");
}

#[cfg(not(feature = "iroh"))]
#[test]
fn a_node_on_the_iroh_road_names_the_feature() {
    let cache = scratch("not-built");
    let (rc, out, err) = podssh(&["node", "lab", "127.0.0.1:22", "--iroh"], &cache);
    assert_eq!(rc, 70, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("--features iroh"), "{err}");
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0, "nothing was written");
}

#[cfg(feature = "iroh")]
#[test]
fn a_node_on_the_iroh_road_refuses_what_it_cannot_use() {
    let cache = scratch("node-refusals");
    for (args, says) in [
        (
            &["node", "lab", "127.0.0.1:22", "--iroh", "--iroh-key", "k", "--iroh-ephemeral"][..],
            "keeps the key in no file",
        ),
        (&["node", "lab", "--iroh"][..], "missing TARGET"),
    ] {
        let (rc, _, err) = podssh(args, &cache);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    // A pair file gives the node the pair's road too (T-164): one that
    // cannot be read is a configuration error.
    let (rc, _, err) = podssh(&["node", "lab", "127.0.0.1:22", "--iroh", "--pair-file", "p.json"], &cache);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("--pair-file p.json"), "{err}");
    // Offline, the node stops before its key or its target.
    let (rc, _, err) = podssh(&["node", "lab", "127.0.0.1:22", "--iroh"], &cache);
    assert_eq!(rc, 69, "{err}");
    assert!(err.contains("PODSSH_OFFLINE"), "{err}");
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0, "no key was made");
}

#[cfg(feature = "iroh")]
#[test]
fn an_iroh_destination_is_checked_before_anything_connects() {
    let cache = scratch("ssh-refusals");
    let bad = podssh(&["ssh", "user@iroh:endpoint0189", "true"], &cache);
    assert_eq!(bad.0, 64, "{}", bad.2);
    assert!(bad.2.contains("not an iroh ticket"), "{}", bad.2);
    let destination = format!("user@{TICKET}");
    for (flag, says) in [
        (&["-p", "2222"][..], "a node has no port"),
        (&["--direct"][..], "--direct cannot reach a node of the iroh road"),
        (&["-J", "jump.example"][..], "-J hop"),
        (&["--pair-file", "p.json"][..], "needs no pair"),
    ] {
        let mut args = vec!["ssh"];
        args.extend_from_slice(flag);
        args.extend_from_slice(&[&destination, "true"]);
        let (rc, _, err) = podssh(&args, &cache);
        assert_eq!(rc, 64, "{args:?}: {err}");
        // The node is named by its key, as in the known hosts.
        assert!(err.contains("iroh:ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6"), "{err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    // Offline, the client stops before its key is made.
    let (rc, _, err) = podssh(&["ssh", "-o", "BatchMode=yes", &destination, "true"], &cache);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("PODSSH_OFFLINE"), "{err}");
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0, "no key was made");
}
