//! A wait for the first network map ends at its limit (T-100). The fork's
//! queries wait until the control server sends a map, and with none they
//! wait for ever: here `std::future::pending` stands for that, under a paused
//! clock, and an outer timeout fails a wait that did not end itself.

use std::time::Duration;

use podssh_ts::node::NodeError;
use podssh_ts::wait::{within, Deadline, FIRST_MAP_WAIT};
use tokio::time::Instant;

/// Longer than any limit here: a wait still running at it had no limit.
const NEVER: Duration = Duration::from_secs(3600);

#[tokio::test(start_paused = true)]
async fn a_wait_with_no_map_ends_at_its_limit() {
    let started = Instant::now();
    let answer = tokio::time::timeout(NEVER, within::<()>(FIRST_MAP_WAIT, std::future::pending()))
        .await
        .expect("the limit ends the wait");
    assert!(matches!(answer, Err(NodeError::NetmapPending)), "{answer:?}");
    assert_eq!(started.elapsed(), FIRST_MAP_WAIT);
    // An answer within the limit is the answer.
    let answer = within(FIRST_MAP_WAIT, async { Ok(7) }).await;
    assert!(matches!(answer, Ok(7)), "{answer:?}");
}

#[tokio::test(start_paused = true)]
async fn each_wait_gets_the_time_that_remains_of_the_bound() {
    let started = Instant::now();
    let deadline = Deadline::after(Some(Duration::from_secs(20)));
    // The start took 5 s: the map wait gets the other 15, not a window of
    // its own.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(deadline.remaining(), Some(Duration::from_secs(15)));
    assert_eq!(deadline.limit(FIRST_MAP_WAIT), Duration::from_secs(15));
    let answer =
        tokio::time::timeout(NEVER, within::<()>(deadline.limit(FIRST_MAP_WAIT), std::future::pending())).await;
    assert!(matches!(answer, Ok(Err(NodeError::NetmapPending))), "{answer:?}");
    assert_eq!(started.elapsed(), Duration::from_secs(20), "the run ends at its bound");
    // Nothing remains for a later wait.
    assert_eq!(deadline.limit(FIRST_MAP_WAIT), Duration::ZERO);
    // A window shorter than what remains is the limit.
    let deadline = Deadline::after(Some(Duration::from_secs(60)));
    assert_eq!(deadline.limit(Duration::from_secs(2)), Duration::from_secs(2));
}

#[tokio::test(start_paused = true)]
async fn with_no_bound_a_wait_has_its_own_window() {
    let deadline = Deadline::after(None);
    assert_eq!(deadline.remaining(), None);
    assert_eq!(deadline.limit(FIRST_MAP_WAIT), FIRST_MAP_WAIT);
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert_eq!(deadline.limit(FIRST_MAP_WAIT), FIRST_MAP_WAIT, "no bound runs out");
}
