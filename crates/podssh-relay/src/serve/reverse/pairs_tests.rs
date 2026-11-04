//! The tests of the role's pairs, in a file of their own so that `pairs.rs`
//! stays within 500 lines.

use podssh_ws::frame;
use podssh_ws::session::{close_code_and_reason, RelaySession};
use tokio::io::DuplexStream;

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

/// T-615: a rotation is kept in the file, so that after a restart the stop
/// token before it and the one to come both take, until the first use of
/// the new one ends the old; the file holds their digests alone.
#[test]
fn a_rotation_is_kept_and_the_first_use_of_the_new_stop_token_ends_the_old() {
    let dir = std::env::temp_dir().join(format!("podssh-pairs-{}-{}", std::process::id(), line!()));
    crate::cache::private_dir(&dir).unwrap();
    let path = dir.join("pairs.json");
    let now = super::super::super::tokens::now_ms();
    let pairs = Pairs::open(Some(path.clone())).unwrap();
    let made = pairs.make(now).unwrap();
    let next = "e".repeat(64);
    assert_eq!(pairs.rotate(&made.name, digest(&next), now), Ok(Some(())));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(&hex(&digest(&next))) && !text.contains(&next) && !text.contains(&made.stop), "{text}");
    let again = Pairs::open(Some(path.clone())).unwrap();
    let stop = |pairs: &Pairs, token: &str| pairs.find(&made.name, Role::Stop, Some(token), now).is_some();
    assert!(stop(&again, made.stop.as_str()), "the one before, after a restart");
    assert!(stop(&again, next.as_str()), "the new one's first use");
    assert!(!stop(&again, made.stop.as_str()), "the one before, after it");
    assert_eq!(again.rotate(&made.name, digest(&next), now), Ok(Some(())), "a rotation to itself keeps the use");
    let kept = Pairs::open(Some(path)).unwrap();
    assert!(!stop(&kept, made.stop.as_str()) && stop(&kept, next.as_str()), "after a second restart");
    assert_eq!(kept.rotate("p-other", digest(&next), now), Ok(None), "no such pair");
    let _ = std::fs::remove_dir_all(&dir);
}

/// T-615: a pair keeps [`MAX_LEGS`] tokens of one leg, the ones that end
/// first going; one is taken only with a node joined, once, and a spent one
/// is never registered again.
#[tokio::test]
async fn the_tokens_of_one_leg_are_bounded_and_a_spent_one_stays_spent() {
    let pairs = Pairs::default();
    let made = pairs.make(1_000).unwrap();
    let pair = pairs.find(&made.name, Role::Node, Some(&made.node), 2_000).unwrap();
    let token = |n: u64| format!("{n:064}");
    for n in 0..MAX_LEGS as u64 + 10 {
        assert!(pair.register_leg(&hex(&digest(&token(n))), 10_000 + n, 2_000));
    }
    assert!(!pair.register_leg("not 64 hex digits", 10_000, 2_000));
    assert_eq!(pair.legs(), MAX_LEGS);
    assert!(pairs.find_leg(&made.name, Some(token(0).as_str()), 2_000).is_none(), "the first to end went");
    let last = token(MAX_LEGS as u64 + 9);
    let (found, leg) = pairs.find_leg(&made.name, Some(last.as_str()), 2_000).expect("the last one registered");
    assert_eq!(pairs.spend_leg(&found, &leg, 2_000), Leg::NoNode, "no node is joined: nothing is taken");
    let (ours, _theirs) = tokio::io::duplex(1024);
    let outbox = Outbox::start(Arc::new(podssh_ws::server::session(ours, Vec::new(), None)), pairs.writers.clone());
    pair.lock().node = Some(NodeLink { serial: 1, outbox: Some(outbox) });
    assert_eq!(pairs.spend_leg(&found, &leg, 2_000), Leg::Taken);
    assert_eq!(pairs.spend_leg(&found, &leg, 2_000), Leg::Refused, "once");
    assert!(pair.register_leg(&hex(&leg), 20_000, 3_000));
    assert!(pairs.find_leg(&made.name, Some(last.as_str()), 3_000).is_none(), "a spent token, registered again");
    assert!(pair.register_leg(&hex(&digest(&token(20))), 0, 3_000), "a withdrawal");
    assert!(pairs.find_leg(&made.name, Some(token(20).as_str()), 3_000).is_none(), "a withdrawn token");
    assert!(pairs.find_leg(&made.name, Some(token(21).as_str()), 30_000).is_none(), "past its end");
}

/// The key of `seed`, among `keys` keys that the role mints for (T-630).
fn asker(seed: u8, keys: usize) -> Asker {
    Asker { key: format!("SHA256:the-key-of-seed-{seed}"), keys }
}

/// The pairs that `asker` makes at `now` until one is refused: their names,
/// and why the next was not made. The table's own bound ends it.
fn until_refused(pairs: &Pairs, asker: Option<&Asker>, now: u64) -> (Vec<String>, NotMade) {
    let mut names = Vec::new();
    loop {
        match pairs.make_for(now, false, asker) {
            Ok(made) => names.push(made.name),
            Err(why) => return (names, why),
        }
    }
}

#[test]
fn the_reserve_is_half_the_table_in_equal_parts_and_the_whole_for_a_key_alone() {
    assert_eq!((reserve(16, 4), reserve(4096, 3), reserve(8, 100)), (2, 682, 1));
    assert_eq!((reserve(16, 1), reserve(16, 0)), (16, 16), "a key alone, and a role that cannot count its keys");
    assert_eq!(Pairs::default().room(), MAX_PAIRS);
}

/// Three keys of four that pair in turns, as fast as they can: each meets
/// its share, and the fourth still finds its reserve, then the full table.
#[test]
fn greedy_keys_leave_each_other_key_its_reserve() {
    let pairs = Pairs::default().with_room(16);
    let greedy: Vec<Asker> = (1..=3).map(|seed| asker(seed, 4)).collect();
    let mut refused: Vec<Option<NotMade>> = vec![None; greedy.len()];
    while refused.iter().any(Option::is_none) {
        for (n, key) in greedy.iter().enumerate() {
            if refused[n].is_none() {
                refused[n] = pairs.make_for(1_000, false, Some(key)).err();
            }
        }
    }
    for why in &refused {
        assert!(matches!(why, Some(NotMade::Share { share: 2, .. })), "{refused:?}");
    }
    assert_eq!(pairs.len(), 14, "the last key's reserve stays free");
    let (last, why) = until_refused(&pairs, Some(&asker(4, 4)), 1_000);
    assert_eq!((last.len(), why), (2, NotMade::Full), "the last key's reserve, then the table's own bound");
}

/// A busy key among idle ones borrows past its reserve, up to the places
/// that the others' reserves hold; each other key then finds its own. A key
/// alone takes the whole table. The refusal holds its own count and share.
#[test]
fn a_busy_key_borrows_past_its_reserve_and_a_key_alone_takes_the_whole_table() {
    let pairs = Pairs::default().with_room(16);
    let (busy, why) = until_refused(&pairs, Some(&asker(1, 4)), 1_000);
    assert_eq!((busy.len(), why), (10, NotMade::Share { holds: 10, share: 2 }), "past its reserve of 2");
    for seed in 2..=4 {
        let (own, _) = until_refused(&pairs, Some(&asker(seed, 4)), 1_000);
        assert_eq!(own.len(), 2, "the key of seed {seed} finds its reserve");
    }
    assert_eq!(pairs.len(), 16);
    let alone = Pairs::default().with_room(16);
    let (each, why) = until_refused(&alone, Some(&asker(1, 1)), 1_000);
    assert_eq!((each.len(), why), (16, NotMade::Full), "a key alone takes each place");
}

/// A pair that ends, or expires, gives its place back to its key; a renewal
/// keeps its maker.
#[test]
fn an_ended_or_expired_pair_returns_its_place_to_its_key() {
    let pairs = Pairs::default().with_room(8);
    let key = asker(1, 2);
    let (held, why) = until_refused(&pairs, Some(&key), 1_000);
    assert_eq!((held.len(), why), (6, NotMade::Share { holds: 6, share: 2 }));
    assert_eq!(pairs.renew(&held[0], 2_000), Ok(Some(2_000 + LIFETIME_MS)));
    let refused = pairs.make_for(2_000, false, Some(&key)).err();
    assert_eq!(refused, Some(NotMade::Share { holds: 6, share: 2 }), "a renewal keeps its maker");
    pairs.end(&held[1], 1001, "operator stopped reverse relay");
    let (again, _) = until_refused(&pairs, Some(&key), 2_000);
    assert_eq!(again.len(), 1, "the place of the stopped pair");
    // Each pair made at 1 000 has expired; the renewed one holds on.
    let later = 1_000 + LIFETIME_MS + 1;
    let (after, why) = until_refused(&pairs, Some(&key), later);
    assert_eq!((after.len(), why), (4, NotMade::Share { holds: 6, share: 2 }), "the places of the expired pairs");
}

/// A role for anyone counts no key, and its pairs count against none: a key
/// that comes later meets its share by its own count alone.
#[test]
fn a_pair_of_no_key_counts_against_none() {
    let pairs = Pairs::default().with_room(16);
    for _ in 0..6 {
        pairs.make(1_000).unwrap();
    }
    let (own, why) = until_refused(&pairs, Some(&asker(1, 4)), 1_000);
    assert_eq!((own.len(), why), (4, NotMade::Share { holds: 4, share: 2 }), "its own 4, not the table's 10");
    let anyone = Pairs::default().with_room(16);
    let (each, why) = until_refused(&anyone, None, 1_000);
    assert_eq!((each.len(), why), (16, NotMade::Full), "a role for anyone");
}

/// A file of before, with no maker, reads, and its pair counts against no
/// key; a pair's maker is kept, and comes back from a restart.
#[test]
fn a_file_of_before_reads_and_a_maker_comes_back_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("podssh-pairs-{}-{}", std::process::id(), line!()));
    crate::cache::private_dir(&dir).unwrap();
    let path = dir.join("pairs.json");
    let now = super::super::super::tokens::now_ms();
    let before = serde_json::json!({ "pairs": [{
        "name": format!("p-{}", "a".repeat(32)), "expires": now + LIFETIME_MS,
        "node": hex(&digest("n")), "connect": hex(&digest("c")), "stop": hex(&digest("s")),
    }]});
    write_private(&path, before.to_string().as_bytes()).unwrap();
    let pairs = Pairs::open(Some(path.clone())).unwrap().with_room(4);
    assert_eq!(pairs.len(), 1, "the pair of before");
    let key = asker(1, 2);
    let (made, why) = until_refused(&pairs, Some(&key), now);
    assert_eq!((made.len(), why), (2, NotMade::Share { holds: 2, share: 1 }), "the pair of before is no key's");
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.matches(&format!("\"maker\":\"{}\"", key.key)).count(), 2, "{text}");
    let again = Pairs::open(Some(path.clone())).unwrap().with_room(4);
    let past = Some(NotMade::Share { holds: 2, share: 1 });
    assert_eq!(again.make_for(now, false, Some(&key)).err(), past, "its count, after a restart");
    // A renewal keeps the maker in the file too.
    assert!(again.renew(&made[0], now + 1_000).unwrap().is_some());
    let renewed = Pairs::open(Some(path)).unwrap().with_room(4);
    assert_eq!(renewed.make_for(now, false, Some(&key)).err(), past, "its count, after a renewal and a restart");
    assert!(renewed.make_for(now, false, Some(&asker(2, 2))).is_ok(), "the other key's reserve");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pair of the role with one operator's socket on a pipe of 1 KiB, so
/// that its frames wait in the queue, four of 16 KiB queued; the client's
/// end of the socket.
fn one_operator_with_four_frames() -> (Pairs, RelaySession<DuplexStream>) {
    let pairs = Pairs::default();
    let made = pairs.make(1_000).unwrap();
    let pair = pairs.find(&made.name, Role::Connect, Some(&made.connect), 2_000).unwrap();
    let (ours, theirs) = tokio::io::duplex(1024);
    let outbox = Outbox::start(Arc::new(podssh_ws::server::session(ours, Vec::new(), None)), pairs.writers.clone());
    let id = SessionId::parse(b"0123456789abcdef0123456789abcdef").unwrap();
    let session = Session { operator: outbox.clone(), ready: true, answer: None, bytes: 0 };
    pair.lock().sessions.insert(id, session);
    for n in 0..4u8 {
        outbox.binary_or_full(vec![n; 16 * 1024]).unwrap();
    }
    (pairs, RelaySession::new(theirs, Vec::new(), None, Duration::from_secs(10)))
}

/// The first byte of each binary frame that `client` reads, then its Close.
async fn frames_then_close(client: &RelaySession<DuplexStream>) -> (Vec<u8>, (Option<u16>, String)) {
    let mut firsts = Vec::new();
    loop {
        let read = tokio::time::timeout(Duration::from_secs(10), client.read_frame()).await;
        let f = read.expect("a frame in time").expect("a frame");
        if f.opcode == frame::OPCODE_CLOSE {
            return (firsts, close_code_and_reason(&f.payload));
        }
        firsts.push(f.payload.first().copied().unwrap_or_default());
    }
}

/// T-255: a planned stop gives a socket the frames that wait for it, the
/// sessions' last bytes, and then its `1012`.
#[tokio::test]
async fn a_planned_stop_sends_what_waits_then_its_1012() {
    let (pairs, client) = one_operator_with_four_frames();
    let (closed, (firsts, close)) = tokio::join!(pairs.restart(Duration::from_secs(5)), frames_then_close(&client));
    assert!(closed, "each Close went out");
    assert_eq!(firsts, [0, 1, 2, 3], "each frame that waited, in order, before the Close");
    assert_eq!(close, (Some(1012), "relay restarting".to_string()));
    assert!(!pairs.stopping(), "the stop is over");
}

/// T-255: a socket that takes nothing for the grace gets its `1012` before
/// what still waits, and no socket joins while the stop runs.
#[tokio::test]
async fn past_the_grace_a_socket_that_took_nothing_gets_1012_first() {
    let (pairs, client) = one_operator_with_four_frames();
    let grace = Duration::from_millis(200);
    let stop = pairs.restart_with(grace, Duration::from_secs(5));
    tokio::pin!(stop);
    // Nobody reads: the writer stays in its first frame past the grace.
    assert!(tokio::time::timeout(2 * grace, &mut stop).await.is_err(), "the stop waits for the socket");
    assert!(pairs.stopping(), "no socket joins while the stop runs");
    let (closed, (firsts, close)) = tokio::join!(stop, frames_then_close(&client));
    assert!(closed, "each Close went out");
    assert_eq!(firsts, [0], "the frame on its way, and none after it");
    assert_eq!(close, (Some(1012), "relay restarting".to_string()));
    assert!(!pairs.stopping(), "the stop is over");
}
