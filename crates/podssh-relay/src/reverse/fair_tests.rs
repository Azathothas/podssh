//! The tests of the fair queue (T-648), in a file of their own so that
//! `fair.rs` stays short.

use std::time::Duration;

use super::*;

/// Each piece that the writer takes now, in order, its room given back as it
/// goes, until no line holds one.
async fn drain(fair: &Fair<char, u32>) -> Vec<(char, u32)> {
    let mut out = Vec::new();
    while let Ok(Some(turn)) = tokio::time::timeout(Duration::from_millis(50), fair.next()).await {
        out.push((turn.key, turn.piece));
    }
    out
}

#[tokio::test]
async fn each_line_takes_a_turn_in_a_round_and_keeps_its_own_order() {
    let fair = Fair::new(8, 64);
    for (key, piece) in [('a', 1), ('a', 2), ('a', 3), ('b', 1), ('c', 1), ('b', 2)] {
        fair.try_push(key, piece, 1).unwrap();
    }
    let order = drain(&fair).await;
    assert_eq!(order, [('a', 1), ('b', 1), ('c', 1), ('a', 2), ('b', 2), ('a', 3)]);
    assert_eq!((fair.used(), fair.lines()), (0, 0), "each room back, and no line kept");
}

#[tokio::test]
async fn a_middle_line_that_is_dropped_leaves_the_turns_where_they_were() {
    let fair = Fair::new(8, 64);
    for key in ['a', 'b', 'c'] {
        for piece in 1..=2 {
            fair.try_push(key, piece, 1).unwrap();
        }
    }
    fair.drop_line(&'b');
    assert_eq!(fair.used(), 4, "b's room is back");
    assert_eq!(drain(&fair).await, [('a', 1), ('c', 1), ('a', 2), ('c', 2)]);
}

/// A line holds its room, the socket all of them; an empty line takes one
/// piece whatever the others hold; a piece in flight keeps its room until
/// its slot goes.
#[tokio::test]
async fn the_rooms_hold_and_an_empty_line_always_takes_one_piece() {
    let fair = Fair::new(2, 3);
    fair.try_push('a', 1, 1).unwrap();
    fair.try_push('a', 2, 1).unwrap();
    assert_eq!(fair.try_push('a', 3, 1), Err(Refused::Full), "a's room");
    fair.try_push('b', 1, 1).unwrap();
    assert_eq!(fair.try_push('b', 2, 1), Err(Refused::Full), "the socket's room");
    fair.try_push('c', 1, 1).unwrap();
    assert_eq!(fair.used(), 4, "past the socket's room by c's one piece");
    let turn = fair.next().await.unwrap();
    assert_eq!((turn.key, turn.piece), ('a', 1));
    assert_eq!(fair.try_push('a', 3, 1), Err(Refused::Full), "a piece in flight keeps its room");
    drop(turn.slot);
    assert_eq!(fair.used(), 3, "its room is back once it is written");
    let turn = fair.next().await.unwrap();
    assert_eq!((turn.key, turn.piece), ('b', 1), "b's turn after a's");
    drop(turn.slot);
    fair.try_push('a', 3, 1).unwrap();
    // A piece larger than a line's room goes alone into an empty line.
    fair.try_push('d', 1, 10).unwrap();
    assert_eq!(fair.try_push('d', 2, 1), Err(Refused::Full));
}

/// A sender waits for room, and goes on once a piece of its line is
/// written; the end of a session goes after its bytes with no wait; a shut
/// queue gives what it holds, then `None`, and a sender that waits hears it.
#[tokio::test]
async fn a_sender_waits_for_room_and_the_last_piece_never_waits() {
    let fair = Fair::new(1, 8);
    fair.push('a', 1, 1).await.unwrap();
    let waiting = {
        let fair = fair.clone();
        tokio::spawn(async move { fair.push('a', 2, 1).await })
    };
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished(), "a's room is taken");
    fair.push_last('a', 99).unwrap();
    let turn = fair.next().await.unwrap();
    assert_eq!(turn.piece, 1);
    drop(turn.slot);
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), waiting).await.unwrap().unwrap(), Ok(()));
    let turn = fair.next().await.unwrap();
    assert_eq!(turn.piece, 99, "the end after the bytes before it");
    let blocked = {
        let fair = fair.clone();
        tokio::spawn(async move { fair.push('a', 3, 1).await })
    };
    tokio::task::yield_now().await;
    fair.shut();
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), blocked).await.unwrap().unwrap(), Err(Shut));
    assert_eq!(fair.next().await.map(|turn| turn.piece), Some(2), "what was queued before the shut");
    assert!(fair.next().await.is_none(), "then the end");
    assert_eq!(fair.push_last('a', 100), Err(Shut));
    drop(turn.slot);
}

/// A line dropped while a piece of it is in flight, then made again by a new
/// piece of the same key: the old piece's room goes back to the socket, not
/// to the new line.
#[tokio::test]
async fn the_room_of_a_dropped_lines_piece_never_goes_to_the_line_after_it() {
    let fair = Fair::new(2, 8);
    fair.try_push('a', 1, 2).unwrap();
    let old = fair.next().await.unwrap();
    fair.drop_line(&'a');
    fair.try_push('a', 2, 2).unwrap();
    drop(old.slot);
    assert_eq!(fair.used(), 2, "the new line's piece alone");
    assert_eq!(fair.try_push('a', 3, 1), Err(Refused::Full), "the new line still holds its own room");
}
