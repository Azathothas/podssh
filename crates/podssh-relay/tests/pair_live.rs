//! Pairs against the live relay (feature `pair`, T-078), on request only:
//! `cargo test -p podssh-relay --features pair --test pair_live -- --ignored`.
//! One run makes a pair, asks for its status, stops it, and then finds each
//! token refused. It prints no token: only the state of the pair.
#![cfg(feature = "pair")]

use std::time::Duration;

use podssh_relay::pair::{self, PairContext, PairError};
use podssh_relay::relay::{Relay, DEFAULT_RELAY_HOST};
use podssh_ws::{ProxyChoice, Trust};

#[tokio::test]
#[ignore = "the live relay: run with --ignored"]
async fn a_pair_is_made_asked_about_and_stopped() {
    let relay = Relay { host: DEFAULT_RELAY_HOST.into(), port: 443 };
    let ctx = PairContext { relay: &relay, trust: &Trust::Default, proxy: &ProxyChoice::FromEnvironment, timeout: Duration::from_secs(20) };
    let made = pair::create(&ctx).await.expect("a pair");
    eprintln!("made a pair: {made:?}");
    let left_h = (made.expires_ms - now_ms()) / 3_600_000;
    assert!((70..=72).contains(&left_h), "{left_h} h left");

    let presence = pair::status(&ctx, &made).await.expect("the status with connect_token");
    eprintln!("status: {presence:?}");
    assert!(!presence.online, "no node runs");

    let stopped = pair::stop(&ctx, &made).await.expect("the stop");
    eprintln!("stopped: {stopped:?}");

    assert!(matches!(pair::status(&ctx, &made).await, Err(PairError::Forbidden)), "after the stop");
    assert!(matches!(pair::stop(&ctx, &made).await, Err(PairError::Forbidden)), "a second stop");
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}
