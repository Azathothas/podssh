//! The end-to-end channel and the node's keys on the command line (T-087,
//! T-088), offline: each flag that conflicts, or that names no key, is
//! refused with 64 before anything is read or connects; the check of a
//! node's key names both keys; and each failure of the channel has its exit.

mod pair_harness;

use std::sync::Arc;

use pair_harness::*;
use podssh_cli::channel::{self, Ask, Expect};
use podssh_cli::exitmap::Fault;
use podssh_relay::e2e::{Error, Refusal};
use podssh_relay::identity::{Identity, KeyName};

const FINGERPRINT: &str = "SHA256:4GCq9Leo8YikY6DuOUiMStys+sW6A5GLCsemjyLisjY";

#[test]
fn the_nodes_flags_are_refused_with_64_when_they_conflict() {
    let home = scratch("chan-node");
    for (args, says) in [
        (vec!["--key", "a.key", "--iroh-key", "b.key"], "--key and --iroh-key are one flag by two names"),
        (vec!["--allow", "a", "--iroh-allow", "b"], "--allow and --iroh-allow are one flag by two names"),
        (vec!["--ephemeral-key", "--key", "a.key"], "--ephemeral-key keeps the key in no file"),
        (vec!["--no-e2e", "--allow", "a"], "which --no-e2e turns off"),
        (vec!["--no-e2e", "--key", "a.key"], "which --no-e2e turns off"),
    ] {
        store(&home, "lab", 0);
        let mut all = vec!["node", "lab", "127.0.0.1:22"];
        all.extend_from_slice(&args);
        let (rc, out, err) = podssh(&home, &all, &[]);
        assert_eq!(rc, 64, "{all:?}: {err}");
        assert!(err.contains(says), "{all:?}: {err}");
        assert!(out.is_empty());
    }
}

#[test]
fn the_clients_flags_are_refused_with_64_when_they_name_no_key_or_conflict() {
    let home = scratch("chan-client");
    store(&home, "lab", 0);
    for args in [
        vec!["operator", "lab", "--node-key", "not-a-key"],
        vec!["ssh", "--node-key", "SHA256:short", "node://lab", "true"],
        vec!["pipe", "--node-key", "laptop", "-", "node:lab"],
    ] {
        let (rc, _, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains("--node-key") && err.contains("not a key"), "{args:?}: {err}");
    }
    let (rc, _, err) = podssh(&home, &["operator", "lab", "--no-e2e", "--node-key", FINGERPRINT], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("which --no-e2e turns off"), "{err}");
    let (rc, _, err) = podssh(&home, &["ssh", "--client-key", "a", "--iroh-key", "b", "node://lab", "true"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--client-key and --iroh-key are one flag by two names"), "{err}");
    // Nothing was made: no key, no pin.
    let cache = home.join("cache").join("podssh");
    for made in ["client.key", "known-nodes"] {
        assert!(!cache.join(made).exists(), "{made} was made by a refused command line");
    }
}

#[test]
fn a_node_key_that_differs_is_refused_with_both_keys() {
    let named = KeyName::parse(FINGERPRINT).unwrap();
    let other = Identity::from_seed(&[3; 32]).public();
    let why = channel::check(Expect::Named(named.clone()), |_| {})(&other).unwrap_err();
    assert!(why.contains(FINGERPRINT) && why.contains(&other.to_string()) && why.contains("--node-key"), "{why}");
    let ticket = Identity::from_seed(&[4; 32]).public();
    let why = channel::check(Expect::Ticket(ticket), |_| {})(&other).unwrap_err();
    assert!(why.contains(&ticket.to_string()) && why.contains("ticket"), "{why}");
    assert_eq!(channel::check(Expect::Ticket(other), |_| {})(&other), Ok(()));
}

#[test]
fn each_failure_of_the_channel_has_its_exit() {
    let me = Identity::from_seed(&[5; 32]);
    let auth = |e: Error| channel::judged(&e, Some(&me)).map(|(fault, why)| (fault.code(), why));
    let (code, why) = auth(Error::NodeKey("the node has another key".into())).unwrap();
    assert_eq!(code, Fault::Auth.code());
    assert!(why.contains("another key"), "{why}");
    let (code, why) = auth(Error::Refused(Refusal::NotAllowed)).unwrap();
    assert_eq!(code, 77, "a refused key, as cp refuses a host key");
    assert!(why.contains(&me.public().to_string()) && why.contains("--allow"), "the line to add: {why}");
    assert_eq!(auth(Error::Refused(Refusal::NoTarget("refused".into()))).unwrap().0, Fault::SessionFault.code());
    assert_eq!(auth(Error::Tampered).unwrap().0, Fault::SessionFault.code());
    assert_eq!(auth(Error::NotChannel("\"SSH-2.0\"".into())).unwrap().0, Fault::SessionFault.code());
    assert_eq!(auth(Error::Timeout("the node's verdict")).unwrap().0, Fault::RelayUnreachable.code());
    assert!(auth(Error::Cut).is_none(), "a cut leaves the word to the layer and the relay's close");
}

#[test]
fn the_flags_of_the_channel_read_as_one_ask() {
    let ask = Ask::of(None, Some("old.key"), Some(FINGERPRINT), false).unwrap();
    assert_eq!(ask.client_key.as_deref(), Some("old.key"), "--iroh-key, by its earlier name");
    let operator = ask.with(Arc::new(Identity::from_seed(&[6; 32])), Expect::Pinned("lab".into())).unwrap();
    assert!(matches!(operator.expect, Expect::Named(_)), "--node-key comes before the pins");
    let off = Ask::of(None, None, None, true).unwrap();
    assert!(off.with(Arc::new(Identity::from_seed(&[6; 32])), Expect::Pinned("lab".into())).is_none());
}
