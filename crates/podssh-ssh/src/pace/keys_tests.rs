//! The user's keys (T-661): typing, a key that waits for its echo, and the
//! hold of a sender.

use std::time::{Duration, Instant};

use super::*;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn a_key_makes_two_seconds_of_typing() {
    let keys = Keys::new();
    let t0 = Instant::now();
    assert!(!keys.typing(t0), "no key yet");
    keys.key(t0);
    assert!(keys.typing(t0));
    assert!(keys.typing(t0 + ms(1999)));
    assert!(!keys.typing(t0 + TYPING));
    keys.key(t0 + ms(1500));
    assert!(keys.typing(t0 + ms(3000)), "each key starts the two seconds again");
}

#[test]
fn a_key_holds_senders_until_its_echo() {
    let keys = Keys::new();
    let t0 = Instant::now();
    assert_eq!(keys.held(t0), None);
    keys.key(t0);
    assert_eq!(keys.held(t0 + ms(100)), Some(HOLD_MAX - ms(100)));
    keys.echo();
    assert_eq!(keys.held(t0 + ms(101)), None);
    // Typing goes on after the echo: windows stay held, senders do not.
    assert!(keys.typing(t0 + ms(101)));
}

#[test]
fn a_key_with_no_echo_holds_for_a_second_at_most() {
    let keys = Keys::new();
    let t0 = Instant::now();
    keys.key(t0);
    // More keys with no echo, as of a password: the hold runs from the first.
    keys.key(t0 + ms(400));
    assert_eq!(keys.held(t0 + ms(900)), Some(ms(100)));
    assert_eq!(keys.held(t0 + HOLD_MAX), None);
    // A key after that waits again, from its own time.
    keys.key(t0 + ms(1500));
    assert_eq!(keys.held(t0 + ms(1600)), Some(HOLD_MAX - ms(100)));
}

#[test]
fn a_time_before_the_first_key_reads_as_none() {
    let keys = Keys::new();
    let t0 = Instant::now();
    assert!(!keys.typing(t0));
    keys.key(t0 + ms(500));
    // Another task's clock may read earlier: no key from its future.
    assert_eq!(keys.held(t0), None);
    assert!(!keys.typing(t0));
}

#[tokio::test]
async fn a_held_sender_goes_on_at_the_echo() {
    // The keys of this test alone, at a fixed place for the turn's polls.
    static KEYS: Keys = Keys::new();
    KEYS.key(Instant::now());
    let mut turn = Turn::default();
    let polled = std::future::poll_fn(|cx| Poll::Ready(turn.poll_with(&KEYS, cx))).await;
    assert!(polled.is_pending(), "a key waits for its echo");
    KEYS.echo();
    let went = tokio::time::timeout(ms(500), std::future::poll_fn(|cx| turn.poll_with(&KEYS, cx))).await;
    assert!(went.is_ok(), "the echo ends the hold within a step");
}

#[tokio::test]
async fn a_held_sender_goes_on_after_a_second_with_no_echo() {
    static KEYS: Keys = Keys::new();
    let started = Instant::now();
    KEYS.key(started);
    let mut turn = Turn::default();
    let went = tokio::time::timeout(ms(3000), std::future::poll_fn(|cx| turn.poll_with(&KEYS, cx))).await;
    assert!(went.is_ok(), "the hold ends");
    assert!(started.elapsed() >= HOLD_MAX - ms(20), "{:?}", started.elapsed());
}

#[tokio::test]
async fn with_no_key_a_sender_goes_at_once() {
    static KEYS: Keys = Keys::new();
    let mut turn = Turn::default();
    let polled = std::future::poll_fn(|cx| Poll::Ready(turn.poll_with(&KEYS, cx))).await;
    assert!(polled.is_ready());
}
