//! The tests of the role's pairs, in a file of their own so that `pairs.rs`
//! stays within 500 lines.

use super::*;

#[test]
fn a_pair_has_the_shapes_of_the_default_relays_and_takes_its_own_tokens_alone() {
    let pairs = Pairs::default();
    let made = pairs.make(1_000).unwrap();
    assert_eq!(made.name.len(), 34);
    assert!(crate::relay::check_node_name(&made.name).is_ok());
    for token in [&made.node, &made.connect, &made.stop] {
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()), "{token:?}");
    }
    assert_eq!(made.expires_ms, 1_000 + LIFETIME_MS);
    assert!(pairs.find(&made.name, Role::Node, Some(&made.node), 2_000).is_some());
    assert!(pairs.find(&made.name, Role::Connect, Some(&made.node), 2_000).is_none(), "the node's token");
    assert!(pairs.find(&made.name, Role::Stop, None, 2_000).is_none(), "no token");
    assert!(pairs.find("p-other", Role::Node, Some(&made.node), 2_000).is_none());
    assert!(pairs.find(&made.name, Role::Node, Some(&made.node), made.expires_ms).is_none(), "expired");
    assert!(pairs.is_empty(), "an expired pair is forgotten");
}

#[test]
fn a_carriers_pair_never_expires_has_no_cap_and_takes_no_token() {
    let pair = Pair::carried("carrier");
    assert_eq!((pair.expires_ms(), pair.session_bytes), (u64::MAX, u64::MAX));
    for role in [Role::Node, Role::Connect, Role::Stop] {
        assert!(!pair.takes(role, ""), "{role:?}");
    }
    let pairs = Pairs::default();
    let made = pairs.make(1_000).unwrap();
    let found = pairs.find(&made.name, Role::Connect, Some(&made.connect), 2_000).unwrap();
    assert_eq!(found.session_bytes, super::super::SESSION_BYTES, "a pair of the role keeps the contract's cap");
}

/// A renewal (T-592) moves the expiry to 72 h after it, never back, and
/// keeps each token: the connect token works past the old expiry.
#[test]
fn a_renewal_moves_the_expiry_and_keeps_the_tokens() {
    let pairs = Pairs::default();
    let made = pairs.make(1_000).unwrap();
    let later = made.expires_ms - 60_000;
    assert_eq!(pairs.renew(&made.name, later), Ok(Some(later + LIFETIME_MS)));
    let past = made.expires_ms + 1;
    let found = pairs.find(&made.name, Role::Connect, Some(&made.connect), past);
    assert_eq!(found.map(|p| p.expires_ms()), Some(later + LIFETIME_MS), "the same connect token, past the old end");
    // Never less than it was: a renewal that a clock behind sends.
    assert_eq!(pairs.renew(&made.name, 2_000), Ok(Some(later + LIFETIME_MS)));
    assert_eq!(pairs.renew("p-other", 2_000), Ok(None), "no such pair");
    pairs.end(&made.name, 1001, "operator stopped reverse relay");
    assert_eq!(pairs.renew(&made.name, 2_000), Ok(None), "a stopped pair stays stopped");
}

/// A pair of `once` (T-226): its connect token takes one upgrade, then
/// neither an upgrade nor the status; its node's and its stop token stay;
/// a pair of before takes each upgrade.
#[test]
fn a_connect_token_of_once_takes_one_upgrade_alone() {
    let pairs = Pairs::default();
    let made = pairs.make_with(1_000, true).unwrap();
    assert!(made.once);
    let pair = pairs.find(&made.name, Role::Connect, Some(&made.connect), 2_000).unwrap();
    assert!(pairs.spend_connect(&pair), "the first upgrade");
    assert!(!pairs.spend_connect(&pair), "a second upgrade that found the pair before the first took it");
    assert!(pairs.find(&made.name, Role::Connect, Some(&made.connect), 2_000).is_none(), "the token after its use");
    assert!(pairs.find(&made.name, Role::Node, Some(&made.node), 2_000).is_some(), "the node's token stays");
    assert!(pairs.find(&made.name, Role::Stop, Some(&made.stop), 2_000).is_some(), "the stop token stays");
    let plain = pairs.make(1_000).unwrap();
    let pair = pairs.find(&plain.name, Role::Connect, Some(&plain.connect), 2_000).unwrap();
    assert!(!plain.once && pairs.spend_connect(&pair) && pairs.spend_connect(&pair), "a pair of before");
}

/// The use of a token of `once` is kept in the file: a restart does not
/// give it a second.
#[test]
fn a_spent_connect_token_stays_spent_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("podssh-pairs-{}-{}", std::process::id(), line!()));
    crate::cache::private_dir(&dir).unwrap();
    let path = dir.join("pairs.json");
    let now = super::super::super::tokens::now_ms();
    let pairs = Pairs::open(Some(path.clone())).unwrap();
    let made = pairs.make_with(now, true).unwrap();
    let pair = pairs.find(&made.name, Role::Connect, Some(&made.connect), now).unwrap();
    assert!(pairs.spend_connect(&pair));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"spent\":true") && !text.contains(&made.connect), "{text}");
    let again = Pairs::open(Some(path)).unwrap();
    assert!(again.find(&made.name, Role::Connect, Some(&made.connect), now).is_none(), "after a restart");
    assert!(again.find(&made.name, Role::Node, Some(&made.node), now).is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_closed_session_is_in_flight_for_its_grace_alone() {
    let mut state = State::default();
    let id = SessionId::parse(b"0123456789abcdef0123456789abcdef").unwrap();
    assert_eq!(state.in_flight(&id), None, "an id never given");
    state.closed.insert(id, (Instant::now(), false));
    assert_eq!(state.in_flight(&id), Some(true), "said once");
    assert_eq!(state.in_flight(&id), Some(false));
    state.closed.insert(id, (Instant::now() - IN_FLIGHT, false));
    assert_eq!(state.in_flight(&id), None, "closed long before");
}

#[test]
fn the_file_keeps_digests_and_no_token() {
    let dir = std::env::temp_dir().join(format!("podssh-pairs-{}-{}", std::process::id(), line!()));
    crate::cache::private_dir(&dir).unwrap();
    let path = dir.join("pairs.json");
    let made = Pairs::open(Some(path.clone())).unwrap().make(super::super::super::tokens::now_ms()).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(&made.name) && !text.contains(&made.node) && !text.contains(&made.stop), "{text}");
    let again = Pairs::open(Some(path.clone())).unwrap();
    let now = super::super::super::tokens::now_ms();
    assert!(again.find(&made.name, Role::Connect, Some(&made.connect), now).is_some(), "after a restart");
    // A renewal is kept in the file, for the next restart (T-592).
    let renewed = again.renew(&made.name, now + 1_000).unwrap().unwrap();
    let kept = Pairs::open(Some(path.clone())).unwrap();
    let found = kept.find(&made.name, Role::Connect, Some(&made.connect), now).map(|p| p.expires_ms());
    assert_eq!(found, Some(renewed), "the renewed expiry, after a restart");
    again.end(&made.name, 1001, "operator stopped reverse relay");
    assert!(Pairs::open(Some(path)).unwrap().is_empty(), "a stopped pair leaves the file");
    let _ = std::fs::remove_dir_all(&dir);
}
