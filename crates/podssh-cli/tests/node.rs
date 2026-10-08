//! `podssh node` and `podssh relay` (T-083) as processes, offline, with a
//! scratch HOME and cache: the parse, each refusal and its code, a pair file,
//! the doctor's line for each stored pair, and no token in any output, with
//! tokens in the environment and in the store.

mod pair_harness;

use podssh_relay::pair;

use pair_harness::*;

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

/// T-058's subcommands, and `status` with no NAME, refuse until it.
#[test]
fn the_other_relay_subcommands_are_not_implemented() {
    let home = scratch("t058");
    for sub in ["status", "info", "spec", "trace"] {
        let (rc, out, err) = podssh(&home, &["relay", sub], &[]);
        assert_eq!(rc, 70, "{sub}: {err}");
        assert!(err.contains("not implemented yet") && out.is_empty(), "{sub}: {err}");
    }
    let (rc, _, err) = podssh(&home, &["relay", "bogus", "lab"], &[]);
    assert_eq!(rc, 64, "{err}");
    let (rc, _, err) = podssh(&home, &["relay", "--timeout", "5s", "pair", "lab"], &[]);
    assert_eq!(rc, 64, "relay has no --timeout: {err}");
}

#[test]
fn a_pair_file_is_used_in_place_of_the_store() {
    let home = scratch("pairfile");
    let elsewhere = home.join("elsewhere");
    let file = pair::store_in_first(&[elsewhere.clone()], "carried", &test_pair(0)).unwrap();
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

#[test]
fn doctor_has_a_line_for_each_stored_pair() {
    let home = scratch("doctor");
    let (_, out, _) = podssh(&home, &["doctor"], &[]);
    assert!(out.contains("pairs          none in the store"), "{out}");
    store(&home, "lab", 0);
    store(&home, "old", EXPIRED);
    let (rc, out, err) = podssh(&home, &["doctor"], &[]);
    assert_eq!(rc, 1, "an expired pair is a FAIL: {out}{err}");
    let line = |label: &str| out.lines().find(|l| l.contains(&format!("pair {label} "))).unwrap_or_default().to_string();
    assert!(line("lab").starts_with("  ????") && line("lab").contains("expires"), "{out}");
    assert!(line("old").starts_with("  FAIL") && line("old").contains("podssh relay pair old"), "{out}");
    no_token(&out);
}
