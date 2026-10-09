//! `podssh operator` and `podssh ssh node://NAME` (T-084) as processes,
//! offline, with a scratch HOME and cache: each refusal and its code, a pair
//! file of either form, stdout that stays empty, and no token in any output.

mod pair_harness;

use podssh_relay::pair;

use pair_harness::*;

#[test]
fn with_no_stored_pair_each_names_the_remedy_and_opens_nothing() {
    let home = scratch("op-none");
    let (rc, out, err) = podssh(&home, &["operator", "lab"], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("podssh relay pair lab") && err.contains("--pair-file"), "{err}");
    assert!(out.is_empty());
    let (rc, out, err) = podssh(&home, &["ssh", "-T", "node://lab", "true"], &[]);
    assert_eq!(rc, 255, "OpenSSH's code for a failure of podssh: {err}");
    assert!(err.contains("node://lab") && err.contains("podssh relay pair lab"), "{err}");
    assert!(!err.contains("PODSSH_OFFLINE"), "refused before any connection: {err}");
    assert!(out.is_empty());
}

#[test]
fn an_expired_pair_is_refused_with_its_remedy() {
    let home = scratch("op-expired");
    store(&home, "lab", EXPIRED);
    let (rc, _, err) = podssh(&home, &["operator", "lab"], &[]);
    assert_eq!(rc, 77, "{err}");
    assert!(err.contains("expired") && err.contains("podssh relay pair lab"), "{err}");
    let (rc, _, err) = podssh(&home, &["ssh", "-T", "node://lab", "true"], &[]);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("expired"), "{err}");
}

/// A stored pair gets each command as far as the network, which
/// `PODSSH_OFFLINE` stops, and no output holds a token.
#[test]
fn a_stored_pair_reaches_the_network_and_no_token_is_shown() {
    let home = scratch("op-redact");
    store(&home, "lab", 0);
    let set = [("PODSSH_RELAY_TOKEN", FORWARD)];
    for (args, code) in [(vec!["operator", "lab"], 69), (vec!["ssh", "-T", "node://lab", "true"], 255)] {
        let (rc, out, err) = podssh(&home, &args, &set);
        assert_eq!(rc, code, "{args:?}: {err}");
        assert!(err.contains("PODSSH_OFFLINE"), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout carries the node's bytes alone: {out:?}");
        no_token(&err);
    }
}

#[test]
fn a_pair_file_of_either_form_gives_the_operator_its_part() {
    let home = scratch("op-file");
    let operator_file = home.join("operator.json");
    pair::write_operator_file(&operator_file, &test_pair(0)).unwrap();
    let whole = pair::store_in_first(&[home.join("elsewhere")], "carried", &test_pair(0)).unwrap();
    for file in [&operator_file, &whole] {
        let path = file.to_str().unwrap();
        for args in
            [vec!["operator", "lab", "--pair-file", path], vec!["ssh", "-T", "--pair-file", path, "node://lab", "true"]]
        {
            let (rc, out, err) = podssh(&home, &args, &[]);
            assert!(
                err.contains("PODSSH_OFFLINE"),
                "{args:?}: the part was read, and only the network stopped it: {err}"
            );
            assert!(rc == 69 || rc == 255, "{args:?}: {rc}");
            no_token(&out);
            no_token(&err);
        }
    }
    let junk = home.join("junk.json");
    std::fs::write(&junk, b"{}").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (rc, _, err) = podssh(&home, &["operator", "lab", "--pair-file", junk.to_str().unwrap()], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("no operator's part"), "{err}");
}

#[test]
fn operator_needs_a_name_and_takes_no_target() {
    let home = scratch("op-parse");
    let (rc, _, err) = podssh(&home, &["operator"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("missing NAME"), "{err}");
    let (rc, _, err) = podssh(&home, &["operator", "lab", "127.0.0.1:22"], &[]);
    assert_eq!(rc, 64, "the node, not the operator, names the TARGET: {err}");
    let (rc, _, err) = podssh(&home, &["operator", "../x"], &[]);
    assert_eq!(rc, 64, "{err}");
}
