//! `podssh node` and `podssh relay` (T-083) as processes, offline, with a
//! scratch HOME and cache: the parse, each refusal and its code, a pair file,
//! the doctor's line for each stored pair, and no token in any output, with
//! tokens in the environment and in the store.

mod pair_harness;

use podssh_relay::pair;

use pair_harness::*;

/// The targets of a node with routes (T-089): `ROUTE=TARGET`, one TARGET
/// with no route at most, each route once, a route with the form of a pair's
/// name, and none with `--no-e2e`, as a route travels in the channel.
#[test]
fn node_routes_are_read_and_refused_before_any_connection() {
    let home = scratch("routes");
    for (args, says) in [
        (vec!["node", "lab", "web=127.0.0.1:80", "web=127.0.0.1:81"], "the route web is given twice"),
        (vec!["node", "lab", "127.0.0.1:80", "127.0.0.1:81"], "two TARGETs with no route"),
        (vec!["node", "lab", ".web=127.0.0.1:80"], "is not a route"),
        (vec!["node", "lab", "a/b=127.0.0.1:80"], "is not a route"),
        (vec!["node", "lab", "web=127.0.0.1"], "TARGET web=127.0.0.1"),
        (vec!["node", "lab", "web=127.0.0.1:80", "--no-e2e"], "travels in the end-to-end channel"),
        (vec!["operator", "lab/../x"], "is not a route"),
        (vec!["operator", "lab/web", "--no-e2e"], "travels in the end-to-end channel"),
        (vec!["ssh", "node://lab/a b"], "is not a route"),
        (vec!["ssh", "--no-e2e", "node://lab/web"], "travels in the end-to-end channel"),
    ] {
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

/// A quick tunnel (T-300): the layer and the channel, with no pair, one
/// TCP TARGET with no route, and an allowlist, as its name is public; each
/// refused before any connection. With PODSSH_OFFLINE, nothing is asked.
#[test]
fn a_quick_tunnel_is_refused_before_any_connection_without_its_needs() {
    let home = scratch("quick");
    let allow = home.join("allow");
    std::fs::write(&allow, "").unwrap();
    let allow = allow.to_string_lossy().into_owned();
    for (args, says) in [
        (vec!["node", "lab", "127.0.0.1:22", "--quick-tunnel"], "needs --allow FILE"),
        (
            vec!["node", "lab", "127.0.0.1:22", "--quick-tunnel", "--plain", "--allow", &allow],
            "--plain is not for --quick-tunnel",
        ),
        (vec!["node", "lab", "127.0.0.1:22", "--quick-tunnel", "--no-e2e"], "--no-e2e is not for --quick-tunnel"),
        (vec!["node", "lab", "udp:127.0.0.1:53", "--quick-tunnel", "--allow", &allow], "carries TCP only"),
        (vec!["node", "lab", "web=127.0.0.1:80", "--quick-tunnel", "--allow", &allow], "one TARGET, with no route"),
    ] {
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
    let args = ["node", "lab", "127.0.0.1:22", "--quick-tunnel", "--allow", &allow];
    let (rc, out, err) = podssh(&home, &args, &[("PODSSH_OFFLINE", "1")]);
    assert_eq!(rc, 69, "{err}");
    assert!(err.contains("PODSSH_OFFLINE") && out.is_empty(), "{err}");
}

/// `--warp` (T-374) is a flag of the quick tunnel's node alone, and of a
/// build with the feature `warp`; each refusal comes before any connection.
#[test]
fn warp_is_a_flag_of_the_quick_tunnel_alone() {
    let home = scratch("warp");
    let (rc, out, err) = podssh(&home, &["node", "lab", "127.0.0.1:22", "--warp"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--warp is for --quick-tunnel") && out.is_empty(), "{err}");
    if cfg!(not(feature = "warp")) {
        let allow = home.join("allow");
        std::fs::write(&allow, "").unwrap();
        let allow = allow.to_string_lossy().into_owned();
        let args = ["node", "lab", "127.0.0.1:22", "--quick-tunnel", "--warp", "--allow", &allow];
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 70, "{err}");
        assert!(err.contains("--features warp") && out.is_empty(), "{err}");
    }
}

#[test]
fn node_needs_a_name_and_a_target_and_refuses_bad_ones_before_any_connection() {
    let home = scratch("parse");
    for (args, says) in [
        (vec!["node"], "missing NAME"),
        (vec!["node", "lab"], "missing TARGET"),
        (vec!["node", "lab", "127.0.0.1:0"], "not a port"),
        (vec!["node", "lab", "127.0.0.1"], "PORT"),
        (vec!["node", "../x", "127.0.0.1:22"], "not a pair name"),
        (vec!["node", "lab", "127.0.0.1:22", "extra"], "extra"),
    ] {
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

/// `--plain` is a flag of `node` alone, and of the pair's road: the iroh
/// road always runs the resumable layer (T-263).
#[test]
fn plain_is_a_flag_of_the_node_of_a_pair_only() {
    let home = scratch("plain");
    let (rc, _, err) = podssh(&home, &["node", "lab", "127.0.0.1:22", "--plain", "--iroh"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--plain is for the pair's road"), "{err}");
    for args in [&["operator", "lab", "--plain"][..], &["ssh", "--plain", "node://lab"][..]] {
        let (rc, _, err) = podssh(&home, args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
    }
    // With a pair to find, the node gets past the flag: no stored pair, 78.
    let (rc, _, err) = podssh(&home, &["node", "lab", "127.0.0.1:22", "--plain"], &[]);
    assert_eq!(rc, 78, "{err}");
}

/// `--resume-deadline TIME` (T-306): a whole number and a unit, from a
/// minute to 72 h, for the node's layer and for a client's own deadline;
/// refused before anything is read or connects.
#[test]
fn a_resume_deadline_is_read_and_refused_before_any_connection() {
    let home = scratch("deadline");
    let node = |more: &[&'static str]| [&["node", "lab", "127.0.0.1:22", "--resume-deadline"][..], more].concat();
    for (args, says) in [
        (node(&["8x"]), "a whole number, then s, m, h or d"),
        (node(&["4d"]), "from 1 minute to 72 h"),
        (node(&["8h", "--plain"]), "which --plain turns off"),
        (vec!["node", "--temporary", "x", "--resume-deadline", "8h"], "does not go with --temporary"),
        (vec!["operator", "lab", "--resume-deadline", "30"], "from 1 minute to 72 h"),
        (vec!["ssh", "--resume-deadline", "x", "node://lab"], "a whole number, then s, m, h or d"),
    ] {
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
    // A good time gets the node past the flag: no stored pair, 78.
    let (rc, _, err) = podssh(&home, &node(&["8h"]), &[]);
    assert_eq!(rc, 78, "{err}");
}

#[test]
fn with_no_stored_pair_each_command_names_the_remedy() {
    let home = scratch("none");
    for args in [vec!["node", "lab", "127.0.0.1:22"], vec!["relay", "status", "lab"]] {
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 78, "{args:?}: {err}");
        assert!(err.contains("podssh relay pair lab"), "{args:?}: {err}");
        assert!(out.is_empty());
    }
    let (rc, _, err) = podssh(&home, &["relay", "revoke", "lab"], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("no pair is stored"), "{err}");
}

#[test]
fn an_expired_pair_is_refused_with_77_and_the_remedy() {
    let home = scratch("expired");
    store(&home, "lab", EXPIRED);
    for args in [vec!["node", "lab", "127.0.0.1:22"], vec!["relay", "status", "lab"]] {
        let (rc, _, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 77, "{args:?}: {err}");
        assert!(err.contains("expired") && err.contains("podssh relay pair lab"), "{args:?}: {err}");
    }
}

/// With a pair in the store and a token in the environment, each command gets
/// as far as the network, which `PODSSH_OFFLINE` stops, and prints no token.
#[test]
fn a_stored_pair_reaches_the_network_and_no_token_is_shown() {
    let home = scratch("redact");
    let stored = store(&home, "lab", 0);
    let set = [("PODSSH_RELAY_TOKEN", FORWARD)];
    for (args, code) in [
        (vec!["node", "lab", "127.0.0.1:22"], 69),
        (vec!["relay", "status", "lab"], 69),
        (vec!["relay", "revoke", "lab"], 69),
        (vec!["relay", "pair", "lab"], 78),
        (vec!["doctor"], 0),
    ] {
        let (rc, out, err) = podssh(&home, &args, &set);
        assert_eq!(rc, code, "{args:?}: {err}");
        no_token(&out);
        no_token(&err);
    }
    assert!(stored.exists(), "a revoke that reached no relay keeps the stored copy");
    let (_, _, err) = podssh(&home, &["relay", "pair", "lab"], &set);
    assert!(err.contains("podssh relay revoke lab"), "a pair is not replaced while it lives: {err}");
}

/// The next pair of a label is made in the last day of its pair (T-395),
/// whose node takes it at the expiry; before that day, it is refused, as a
/// second pair would leave the first with no holder for days.
#[test]
fn the_next_pair_may_be_made_in_the_last_day_only() {
    let home = scratch("next");
    store(&home, "lab", 0);
    let (rc, _, err) = podssh(&home, &["relay", "pair", "lab"], &[]);
    assert_eq!(rc, 78, "72 h left: {err}");
    assert!(err.contains("podssh relay revoke lab") && err.contains("last 24 hours"), "{err}");
    let stored = store(&home, "lab", 49 * 3600 * 1000);
    let kept = std::fs::read(&stored).unwrap();
    let (rc, _, err) = podssh(&home, &["relay", "pair", "lab"], &[]);
    assert_eq!(rc, 69, "23 h left: the store lets it pass, and only the network stops it: {err}");
    assert!(err.contains("the next one takes its place in the store"), "{err}");
    assert_eq!(std::fs::read(&stored).unwrap(), kept, "a next pair that was not made leaves the pair as it was");
    no_token(&err);
}

/// `podssh status` names each stored pair and its expiry (T-395), and
/// whether its next pair can be made now; never a token.
#[test]
fn status_names_each_stored_pair_and_its_expiry() {
    let home = scratch("status");
    store(&home, "lab", 0);
    store(&home, "late", 49 * 3600 * 1000);
    store(&home, "old", EXPIRED);
    let (rc, out, err) = podssh(&home, &["status"], &[]);
    assert_eq!(rc, 0, "{err}");
    no_token(&out);
    let line: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    let pair = |label: &str| {
        line["pairs"].as_array().unwrap().iter().find(|p| p["label"] == label).cloned().unwrap_or_default()
    };
    assert_eq!(
        (pair("lab")["expired"].clone(), pair("lab")["next_now"].clone()),
        (false.into(), false.into()),
        "{out}"
    );
    assert_eq!(
        (pair("late")["expired"].clone(), pair("late")["next_now"].clone()),
        (false.into(), true.into()),
        "{out}"
    );
    assert_eq!(pair("old")["expired"], true, "{out}");
    assert!(pair("lab")["expires_ms"].as_i64().unwrap() > pair("late")["expires_ms"].as_i64().unwrap(), "{out}");
}

#[test]
fn relay_pair_refuses_an_operator_file_that_exists_before_any_request() {
    let home = scratch("opfile");
    let file = home.join("operator.json");
    std::fs::write(&file, b"keep me").unwrap();
    let path = file.to_str().unwrap();
    let (rc, _, err) = podssh(&home, &["relay", "pair", "lab", "--operator-file", path], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("never replaces"), "{err}");
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    let (rc, _, err) = podssh(&home, &["relay", "status", "lab", "--operator-file", path], &[]);
    assert_eq!(rc, 64, "--operator-file goes with pair only: {err}");
}

/// T-058's subcommands, and `status` with no NAME, ask the relay: offline,
/// nothing (69), and `trace` first needs its target (64).
#[test]
fn the_relay_diagnostics_ask_nothing_offline() {
    let home = scratch("t058");
    for sub in ["status", "info"] {
        let (rc, out, err) = podssh(&home, &["relay", sub], &[]);
        assert_eq!(rc, 69, "{sub}: {err}");
        assert!(err.contains("PODSSH_OFFLINE") && out.is_empty(), "{sub}: {err}");
    }
    let (rc, _, err) = podssh(&home, &["relay", "trace"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("missing HOST"), "{err}");
    let (rc, _, err) = podssh(&home, &["relay", "bogus", "lab"], &[]);
    assert_eq!(rc, 64, "{err}");
    let (rc, _, err) = podssh(&home, &["relay", "--timeout", "5s", "pair", "lab"], &[]);
    assert_eq!(rc, 64, "relay has no --timeout: {err}");
}

#[test]
fn a_pair_file_is_used_in_place_of_the_store() {
    let home = scratch("pairfile");
    let elsewhere = home.join("elsewhere");
    let file = pair::store_in_first(std::slice::from_ref(&elsewhere), "carried", &test_pair(0)).unwrap();
    let path = file.to_str().unwrap();
    let (rc, out, err) = podssh(&home, &["node", "lab", "127.0.0.1:22", "--pair-file", path], &[]);
    assert_eq!(rc, 69, "the pair was read, and only the network stopped it: {err}");
    no_token(&out);
    no_token(&err);
    let operator = home.join("operator.json");
    pair::write_operator_file(&operator, &test_pair(0)).unwrap();
    let (rc, _, err) = podssh(&home, &["node", "lab", "127.0.0.1:22", "--pair-file", operator.to_str().unwrap()], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("operator's part"), "{err}");
    no_token(&err);
}

/// A label maps to the newest pair (T-090): a new pair kept under the same
/// label takes the old one's place, and each command finds it by the label,
/// so a script stays the same; no output names a token.
#[test]
fn labels_survive_a_new_pair() {
    let home = scratch("labels");
    let doctor = |home: &std::path::Path| {
        let (_, out, err) = podssh(home, &["doctor"], &[]);
        no_token(&out);
        no_token(&err);
        out.lines().find(|l| l.contains("pair lab ")).unwrap_or_default().to_string()
    };
    store(&home, "lab", EXPIRED);
    let old = doctor(&home);
    assert!(old.starts_with("  FAIL") && old.contains("podssh relay pair lab"), "{old}");
    // The new pair, kept as `podssh relay pair lab` keeps it.
    store(&home, "lab", 0);
    let new = doctor(&home);
    assert!(new.starts_with("  ????") && new.contains("expires"), "the label's pair is the new one: {new}");
    // The operator and the node find it by the label: offline, they go as
    // far as the network, past the store.
    for args in [&["operator", "lab"][..], &["node", "lab", "127.0.0.1:22"][..]] {
        let (rc, out, err) = podssh(&home, args, &[]);
        assert_eq!(rc, 69, "{args:?}: {err}");
        assert!(!err.contains("expired") && !err.contains("no pair"), "{args:?}: {err}");
        no_token(&out);
        no_token(&err);
    }
}

#[test]
fn doctor_has_a_line_for_each_stored_pair() {
    let home = scratch("doctor");
    let (_, out, _) = podssh(&home, &["doctor"], &[]);
    assert!(out.contains("pairs          none in the store"), "{out}");
    store(&home, "lab", 0);
    store(&home, "old", EXPIRED);
    let (rc, out, err) = podssh(&home, &["doctor"], &[]);
    assert_eq!(rc, 1, "an expired pair is a FAIL: {out}{err}");
    let line =
        |label: &str| out.lines().find(|l| l.contains(&format!("pair {label} "))).unwrap_or_default().to_string();
    assert!(line("lab").starts_with("  ????") && line("lab").contains("expires"), "{out}");
    assert!(line("old").starts_with("  FAIL") && line("old").contains("podssh relay pair old"), "{out}");
    no_token(&out);
}
