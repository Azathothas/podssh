//! The pair that a node holds, with no network (T-620): a move to the next
//! pair replaces it and wakes each task that waits on it; a rotation or a
//! renewal of the pair before the move changes nothing after it; and the
//! next pair's rotation waits for a socket that heard the offer after the
//! move. Only the last test makes a socket of this process hear one.

use podssh_relay::reverse::control::Hello;

use super::*;

/// A pair of the relay's shapes, named by `n`, with each token `token` and
/// its end at `expires_ms`.
fn pair_of(n: u8, token: char, expires_ms: i64) -> Pair {
    let name = format!("p-{}", char::from(b'0' + n).to_string().repeat(32));
    let token = token.to_string().repeat(64);
    let body = serde_json::json!({
        "name": name, "node_token": token, "connect_token": token, "stop_token": token, "expires": expires_ms,
    });
    let relay = podssh_relay::relay::Relay { host: "relay.test".into(), port: 443 };
    pair::parse(&relay, body.to_string().as_bytes(), 0).unwrap()
}

#[test]
fn a_move_replaces_the_pair_and_wakes_each_task_that_waits_on_it() {
    let (first, next) = (pair_of(1, 'a', 3_600_000), pair_of(2, 'b', 7_200_000));
    let held = Held::of(&first);
    let (mut rotation, renewal) = (held.moves(), held.clone().moves());
    assert_eq!((held.name(), held.end()), (first.name.clone(), 3_600_000));
    assert!(!rotation.has_changed().unwrap(), "no move yet");
    held.move_to(&next);
    assert_eq!((held.name(), held.end()), (next.name.clone(), 7_200_000), "the next pair, with its end");
    assert_eq!(held.pair().stop_token(), next.stop_token(), "and its own stop token");
    assert!(rotation.has_changed().unwrap() && renewal.has_changed().unwrap(), "each task hears the move");
    rotation.mark_unchanged();
    assert!(!rotation.has_changed().unwrap());
    assert!(renewal.has_changed().unwrap(), "each receiver on its own");
}

#[test]
fn a_rotation_or_a_renewal_of_the_pair_before_a_move_changes_nothing_after_it() {
    let (first, next) = (pair_of(3, 'c', 3_600_000), pair_of(4, 'd', 7_200_000));
    let held = Held::of(&first);
    let rotated = held.restop(&first.name, &"e".repeat(64)).expect("the pair now");
    assert_eq!(rotated.stop_token(), "e".repeat(64));
    assert!(held.renewed(&first.name, 5_000_000));
    assert_eq!((held.pair().stop_token(), held.end()), ("e".repeat(64).as_str(), 5_000_000));
    held.move_to(&next);
    // A rotation of the first pair that ends after the move.
    assert!(held.restop(&first.name, &"f".repeat(64)).is_none(), "not the pair now");
    assert_eq!(held.pair().stop_token(), next.stop_token(), "the next pair's own token stays");
    assert!(!held.renewed(&first.name, 9_000_000), "a renewal of the first pair");
    assert_eq!((held.name(), held.end()), (next.name.clone(), 7_200_000));
}

#[tokio::test]
async fn one_request_by_the_stop_token_at_a_time() {
    let held = Held::of(&pair_of(5, 'g', 3_600_000));
    let turn = held.turn().await;
    let other = held.clone();
    let waiting = tokio::spawn(async move {
        let _turn = other.turn().await;
    });
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished(), "a second request waits for the first");
    drop(turn);
    tokio::time::timeout(Duration::from_secs(5), waiting).await.expect("the second goes after it").unwrap();
}

/// The only test of this library that makes a socket of this process hear a
/// role that rotates: the count only grows, so each check is of its growth.
#[test]
fn the_next_pair_s_rotation_waits_for_a_socket_that_heard_the_offer_after_the_move() {
    let offer: Hello = serde_json::from_str(r#"{"maxSessions":64,"stopRotation":true}"#).unwrap();
    let (first, next) = (pair_of(6, 'h', 3_600_000), pair_of(7, 'i', 7_200_000));
    let held = Held::of(&first);
    legs::heard(&offer);
    assert!(held.heard(), "a socket of the first pair heard the offer");
    held.move_to(&next);
    assert!(!held.heard(), "the first pair's sockets are not the next one's");
    let plain: Hello = serde_json::from_str(r#"{"maxSessions":64}"#).unwrap();
    legs::heard(&plain);
    assert!(!held.heard(), "a socket of a relay that offers none");
    legs::heard(&offer);
    assert!(held.heard(), "the next pair's own socket heard it");
}
