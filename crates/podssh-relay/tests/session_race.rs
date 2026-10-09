//! The race between two roads (T-164), with stand-in roads on a paused
//! clock: a road gives its link after its connection time, and its far end
//! speaks after its own time, then reads what the client sends. The first
//! road has the head start; the second starts after it, or at once when the
//! first fails; the first far end to speak wins, and the loser's far end
//! reads nothing at all: no `OPEN`, so no target. A planted race that waits
//! for the first road's own time limit fails the first check.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::session::race::{race, Lost, Won, HEAD_START};
use podssh_relay::session::record::kind::GREETING;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const MS: Duration = Duration::from_millis(1);

/// What a road's far end read from the client: `None` while it has no
/// link, then the bytes until the client's end of the link.
type Seen = Arc<Mutex<Option<Vec<u8>>>>;

/// A road whose link comes after `connect`, and whose far end speaks
/// `speaks` after that.
fn road(connect: Duration, speaks: Duration) -> (impl Future<Output = Result<DuplexStream, String>>, Seen) {
    let seen: Seen = Arc::new(Mutex::new(None));
    let far = seen.clone();
    let link = async move {
        tokio::time::sleep(connect).await;
        let (ours, mut theirs) = tokio::io::duplex(4096);
        *far.lock().unwrap() = Some(Vec::new());
        tokio::spawn(async move {
            tokio::time::sleep(speaks).await;
            let _ = theirs.write_all(&[GREETING]).await;
            let mut got = Vec::new();
            let _ = theirs.read_to_end(&mut got).await;
            *far.lock().unwrap() = Some(got);
        });
        Ok(ours)
    };
    (link, seen)
}

/// A road that fails after `after`, as a refused connection does.
async fn failing(after: Duration, why: &str) -> Result<DuplexStream, String> {
    tokio::time::sleep(after).await;
    Err(why.to_string())
}

/// The planted race: the second road only after the first one ended.
async fn sequential<FA, FB>(first: FA, second: FB) -> (bool, Duration)
where
    FA: Future<Output = Result<DuplexStream, String>>,
    FB: Future<Output = Result<DuplexStream, String>>,
{
    let started = tokio::time::Instant::now();
    if first.await.is_ok() {
        return (true, started.elapsed());
    }
    let _ = second.await;
    (false, started.elapsed())
}

/// The first check: with the first road unable to run until its own limit
/// of 10 s, the second road wins within the head start and its own time.
fn in_time(second_won: bool, took: Duration) -> bool {
    second_won && took <= HEAD_START + 50 * MS
}

#[tokio::test(start_paused = true)]
async fn the_second_road_wins_after_the_head_start_when_the_first_cannot_run() {
    let (second, seen) = road(30 * MS, 20 * MS);
    let (won, took) = race(failing(Duration::from_secs(10), "no relay"), second, HEAD_START).await.expect("a winner");
    assert!(in_time(matches!(won, Won::Second(_)), took), "{took:?}");
    assert_eq!(took, HEAD_START + 50 * MS);
    assert_eq!(seen.lock().unwrap().as_deref(), Some(&[][..]), "the winner's far end has its link");
}

#[tokio::test(start_paused = true)]
async fn a_planted_race_that_waits_for_the_first_road_fails_the_check() {
    let (second, _) = road(30 * MS, 20 * MS);
    let (first_won, took) = sequential(failing(Duration::from_secs(10), "no relay"), second).await;
    assert!(!in_time(!first_won, took), "the check cannot tell a race that waits: {took:?}");
}

#[tokio::test(start_paused = true)]
async fn with_both_roads_open_the_first_wins_and_the_second_never_starts() {
    let (first, first_seen) = road(50 * MS, 50 * MS);
    let (second, second_seen) = road(10 * MS, 10 * MS);
    let (won, took) = race(first, second, HEAD_START).await.expect("a winner");
    let Won::First(_) = won else { panic!("the second road won") };
    assert_eq!(took, 100 * MS);
    assert!(second_seen.lock().unwrap().is_none(), "the second road was started");
    assert!(first_seen.lock().unwrap().is_some());
}

#[tokio::test(start_paused = true)]
async fn the_losing_link_sends_nothing_to_its_far_end() {
    // The first road's far end speaks at 300 ms; the second, started at
    // 250 ms, speaks at 280 ms and wins.
    let (first, first_seen) = road(200 * MS, 100 * MS);
    let (second, second_seen) = road(20 * MS, 10 * MS);
    let (won, took) = race(first, second, HEAD_START).await.expect("a winner");
    assert_eq!(took, 280 * MS);
    let Won::Second(_greeted) = won else { panic!("the first road won") };
    // The loser was dropped as it stood: its far end reads the end of the
    // link, and not one byte, so it opens no session and dials no target.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(first_seen.lock().unwrap().as_deref(), Some(&[][..]), "the loser's far end got bytes");
    assert!(second_seen.lock().unwrap().is_some());
}

#[tokio::test(start_paused = true)]
async fn when_the_first_road_fails_at_once_the_second_starts_with_no_head_start() {
    let (second, _) = road(20 * MS, 10 * MS);
    let (won, took) = race(failing(10 * MS, "refused"), second, HEAD_START).await.expect("a winner");
    assert!(matches!(won, Won::Second(_)));
    assert_eq!(took, 40 * MS, "the second road started when the first failed");
}

#[tokio::test(start_paused = true)]
async fn a_silent_far_end_loses_to_one_that_speaks() {
    // The first road's far end never speaks: after the client's wait for a
    // first byte, the second road, slower to connect, wins.
    let (first, _) = road(10 * MS, Duration::from_secs(3600));
    let (second, _) = road(Duration::from_secs(40), 10 * MS);
    let (won, _) = race(first, second, HEAD_START).await.expect("a winner");
    assert!(matches!(won, Won::Second(_)));
}

#[tokio::test(start_paused = true)]
async fn when_both_roads_fail_each_reason_is_said() {
    let lost = race(failing(10 * MS, "the iroh relay refused"), failing(20 * MS, "the pair expired"), HEAD_START)
        .await
        .err()
        .expect("no winner");
    assert_eq!(lost, Lost { first: "the iroh relay refused".into(), second: "the pair expired".into() });
}
