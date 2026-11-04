//! The tests of the tokens of one leg (T-615), in a file of their own so that
//! `legs.rs` stays short.

use super::*;

/// A sink of frames that keeps each one, as JSON.
fn sink() -> (Frames, Arc<Mutex<Vec<serde_json::Value>>>) {
    let kept: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
    let into = kept.clone();
    let frames: Frames = Arc::new(move |text: String| into.lock().unwrap().push(serde_json::from_str(&text).unwrap()));
    (frames, kept)
}

/// The digests that `frames` registered (an end ahead) and withdrew (an end
/// of 0), in order.
fn split(frames: &[serde_json::Value]) -> (Vec<String>, Vec<String>) {
    let now = now_ms();
    let (mut registered, mut withdrawn) = (Vec::new(), Vec::new());
    for f in frames {
        assert_eq!(f["type"], "token", "{f}");
        let digest = f["digest"].as_str().unwrap().to_string();
        match f["expires"].as_u64().unwrap() {
            0 => withdrawn.push(digest),
            end => {
                assert!(end > now + LIFE_MS - 60_000, "a registration ends a day ahead: {f}");
                registered.push(digest);
            }
        }
    }
    (registered, withdrawn)
}

fn digests(seed: &[u8; 32], legs: std::ops::RangeInclusive<u64>) -> Vec<String> {
    legs.map(|index| hex(&digest(&token(seed, index)))).collect()
}

#[test]
fn a_token_is_64_hex_digits_of_its_seed_and_its_leg() {
    let (seed, other) = ([7u8; 32], [8u8; 32]);
    let first = token(&seed, 1);
    assert_eq!(first.len(), 64);
    assert!(first.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{}", first.as_str());
    assert_eq!(token(&seed, 1), first, "the same seed and leg, the same token");
    assert_ne!(token(&seed, 2), first, "another leg");
    assert_ne!(token(&other, 1), first, "another seed");
    assert!(crate::cache::valid_token(&first), "the shape that a relay token has");
    assert_eq!(unhex(&hex(&digest(&first))), Some(digest(&first)));
    assert_eq!(unhex("not hex"), None);
}

#[test]
fn a_seed_is_given_only_with_a_socket_that_registers_and_its_window_goes_first() {
    let leases = Arc::new(Leases::default());
    assert!(leases.issue().is_none(), "no socket of a role that registers tokens");
    let (frames, kept) = sink();
    leases.attach(Some(frames));
    let lease = leases.issue().expect("a seed");
    let (registered, withdrawn) = split(&kept.lock().unwrap());
    assert_eq!(registered, digests(lease.seed(), 1..=WINDOW), "the window of its first legs");
    assert!(withdrawn.is_empty());
    assert_eq!(leases.held(), 1);
    leases.attach(None);
    assert!(leases.issue().is_none(), "the socket ended");
}

#[test]
fn a_spent_token_moves_the_window_past_it() {
    let leases = Arc::new(Leases::default());
    let (frames, kept) = sink();
    leases.attach(Some(frames));
    let lease = leases.issue().expect("a seed");
    let seed = *lease.seed();
    kept.lock().unwrap().clear();
    // Leg 1 failed before the role's answer, and leg 2 took its token.
    leases.spent(&hex(&digest(&token(&seed, 2))));
    let (registered, withdrawn) = split(&kept.lock().unwrap());
    assert_eq!(withdrawn, digests(&seed, 1..=1), "leg 1 is one that no leg takes any more");
    assert_eq!(registered, digests(&seed, 3..=2 + WINDOW), "the window after leg 2");
    kept.lock().unwrap().clear();
    leases.spent(&hex(&digest(&token(&seed, 2))));
    leases.spent(&hex(&[0u8; 32]));
    leases.spent("not hex");
    assert!(kept.lock().unwrap().is_empty(), "a token spent before, or never given, moves nothing");
}

#[test]
fn an_ended_session_withdraws_its_window_and_a_new_socket_registers_each_again() {
    let leases = Arc::new(Leases::default());
    let (frames, kept) = sink();
    leases.attach(Some(frames));
    let (first, second) = (leases.issue().unwrap(), leases.issue().unwrap());
    let seed = *second.seed();
    let (again, kept_again) = sink();
    leases.attach(Some(again));
    let (registered, _) = split(&kept_again.lock().unwrap());
    assert_eq!(registered.len(), 2 * WINDOW as usize, "each window, on the new socket");
    kept_again.lock().unwrap().clear();
    drop(second);
    let (registered, withdrawn) = split(&kept_again.lock().unwrap());
    assert_eq!((registered.len(), withdrawn), (0, digests(&seed, 1..=WINDOW)));
    assert_eq!(leases.held(), 1);
    drop(first);
    assert_eq!(leases.held(), 0);
    assert_eq!(kept.lock().unwrap().len(), 2 * WINDOW as usize, "the old socket got nothing after it ended");
}

#[test]
fn a_taker_goes_leg_by_leg_and_after_its_refusals_takes_the_pair_s() {
    let taker = Taker::default();
    assert!(matches!(taker.pick(), Pick::Pair), "no seed: the pair's token");
    let seed = [3u8; 32];
    taker.give(seed);
    taker.give([4u8; 32]);
    assert!(taker.holds());
    let leg = |want: u64| match taker.pick() {
        Pick::Leg(index, token) => {
            assert_eq!(index, want);
            assert_eq!(token, super::token(&seed, want), "the first seed stays");
        }
        Pick::Pair => panic!("the pair's token where leg {want} was due"),
    };
    leg(1);
    taker.upgraded(1);
    leg(2);
    taker.upgraded(1);
    leg(2);
    // Once refused: the role may have restarted; twice: the next one.
    taker.refused(2);
    leg(2);
    taker.refused(2);
    leg(3);
    for _ in 2..2 * WINDOW {
        let Pick::Leg(index, _) = taker.pick() else { panic!("a token while the refusals are fewer") };
        taker.refused(index);
    }
    assert!(matches!(taker.pick(), Pick::Pair), "twice the window refused in a row: the pair's");
    assert_eq!(taker.token_at(5), Some(super::token(&seed, 5)));
}

#[test]
fn only_a_true_of_its_field_is_an_offer() {
    let read = |text: &str| -> serde_json::Map<String, serde_json::Value> { serde_json::from_str(text).unwrap() };
    assert!(offered(&read(r#"{"legTokens":true}"#)));
    for text in [r#"{}"#, r#"{"legTokens":"true"}"#, r#"{"legTokens":1}"#, r#"{"legtokens":true}"#] {
        assert!(!offered(&read(text)), "{text}");
    }
}

#[tokio::test]
async fn a_session_has_its_taker_inside_during_alone() {
    assert!(current().is_none());
    let inside = during(async {
        let taker = current().expect("a taker inside");
        taker.give([1u8; 32]);
        current().expect("the same taker").holds()
    })
    .await;
    assert!(inside, "the same taker for the whole session");
    assert!(current().is_none());
}
