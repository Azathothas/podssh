//! The order of the relay hosts of one run (T-220), on tokio's paused clock:
//! attempts that open, fail or say nothing at set times, in each mode; the
//! choice of two that open together; the end of a round at an error that
//! every host would give; the notes in the order of the list; and one mint
//! at a time for each deployment.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::failover::{race, Attempt, MintGate, Mode, STAGGER};
use tokio::time::Instant;

/// What a host does, after so many milliseconds.
#[derive(Clone, Copy)]
enum Host {
    Opens(u64),
    Fails(u64),
    /// Fails with an error that every host would give.
    Stops(u64),
    /// Nothing within the test.
    Silent,
}

/// How a race went: the host kept, those that failed, those dismissed, the
/// time of each start and of the end, in milliseconds, and the notes.
#[derive(Debug, PartialEq)]
struct Outcome {
    kept: Option<usize>,
    failed: Vec<usize>,
    dismissed: Vec<usize>,
    stopped: bool,
    started: Vec<(usize, u128)>,
    ended: u128,
    notes: Vec<String>,
}

async fn run(hosts: &[Host], mode: Mode) -> Outcome {
    let started: Arc<Mutex<Vec<(usize, u128)>>> = Arc::default();
    let t0 = Instant::now();
    let mut notes = Vec::new();
    let hosts = hosts.to_vec();
    let log = started.clone();
    let raced = race(
        hosts.len(),
        mode,
        move |i| {
            let (host, log) = (hosts[i], log.clone());
            async move {
                log.lock().unwrap().push((i, t0.elapsed().as_millis()));
                let (after, result) = match host {
                    Host::Opens(ms) => (ms, Ok(i)),
                    Host::Fails(ms) => (ms, Err("fails")),
                    Host::Stops(ms) => (ms, Err("stops")),
                    Host::Silent => (3_600_000, Err("silent")),
                };
                tokio::time::sleep(Duration::from_millis(after)).await;
                Attempt { result, notes: vec![format!("host {i}")] }
            }
        },
        |e: &&str| *e == "stops",
        &mut |note: &str| notes.push(note.to_string()),
    )
    .await;
    let started = started.lock().unwrap().clone();
    Outcome {
        kept: raced.kept.map(|(i, _)| i),
        failed: raced.failed.iter().map(|(i, _)| *i).collect(),
        dismissed: raced.dismissed.iter().map(|(i, _)| *i).collect(),
        stopped: raced.stopped,
        started,
        ended: t0.elapsed().as_millis(),
        notes,
    }
}

const D: u128 = STAGGER.as_millis();

#[tokio::test(start_paused = true)]
async fn staggered_starts_the_next_host_when_the_first_is_silent() {
    let o = run(&[Host::Silent, Host::Opens(100)], Mode::Staggered).await;
    assert_eq!(o.kept, Some(1));
    assert_eq!(o.started, [(0, 0), (1, D)]);
    assert_eq!(o.ended, D + 100, "the silent host costs the stagger, not its whole step");
    assert!(o.failed.is_empty() && o.dismissed.is_empty(), "{o:?}");
    assert_eq!(o.notes, ["host 1"], "the silent attempt ended with no notes");
}

#[tokio::test(start_paused = true)]
async fn staggered_starts_the_next_host_at_once_when_one_fails() {
    let o = run(&[Host::Fails(100), Host::Opens(100)], Mode::Staggered).await;
    assert_eq!((o.kept, o.failed.clone()), (Some(1), vec![0]));
    assert_eq!(o.started, [(0, 0), (1, 100)]);
    assert_eq!(o.ended, 200);
    assert_eq!(o.notes, ["host 0", "host 1"]);
}

/// The first that opens is kept, wherever it is in the list.
#[tokio::test(start_paused = true)]
async fn staggered_keeps_the_first_that_opens() {
    let o = run(&[Host::Opens(5000), Host::Opens(100)], Mode::Staggered).await;
    assert_eq!(o.kept, Some(1));
    assert_eq!(o.ended, D + 100);
}

/// Two attempts that opened in the same turn: the earlier in the list is
/// kept, the other dismissed, whichever ended first.
#[tokio::test(start_paused = true)]
async fn of_two_that_open_together_the_earlier_in_the_list_is_kept() {
    let wake = [Arc::new(tokio::sync::Notify::new()), Arc::new(tokio::sync::Notify::new())];
    let each = wake.clone();
    let mut notes = |_: &str| {};
    let racing = race(
        2,
        Mode::Staggered,
        move |i| {
            let wake = each[i].clone();
            async move {
                wake.notified().await;
                Attempt { result: Ok::<usize, ()>(i), notes: Vec::new() }
            }
        },
        |_: &()| false,
        &mut notes,
    );
    // Both run after the stagger; host 1 ends first, and host 0 in the same
    // turn, before the race looks again.
    let director = async {
        tokio::time::sleep(STAGGER + Duration::from_millis(100)).await;
        wake[1].notify_one();
        wake[0].notify_one();
    };
    let (raced, ()) = tokio::join!(racing, director);
    assert_eq!(raced.kept.map(|(i, _)| i), Some(0));
    assert_eq!(raced.dismissed.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [1]);
}

#[tokio::test(start_paused = true)]
async fn parallel_waits_for_an_earlier_host_within_the_stagger() {
    let o = run(&[Host::Opens(1500), Host::Opens(100)], Mode::Parallel).await;
    assert_eq!(o.started, [(0, 0), (1, 0)]);
    assert_eq!((o.kept, o.dismissed.clone()), (Some(0), vec![1]));
    assert_eq!(o.ended, 1500);
}

#[tokio::test(start_paused = true)]
async fn parallel_keeps_a_later_host_when_the_earlier_is_silent() {
    let o = run(&[Host::Silent, Host::Opens(100)], Mode::Parallel).await;
    assert_eq!(o.kept, Some(1));
    assert_eq!(o.ended, 100 + D, "the wait for the earlier host is the stagger at most");
}

#[tokio::test(start_paused = true)]
async fn serial_starts_one_host_at_a_time() {
    let o = run(&[Host::Fails(300), Host::Opens(100)], Mode::Serial).await;
    assert_eq!(o.started, [(0, 0), (1, 300)]);
    assert_eq!(o.kept, Some(1));
    let o = run(&[Host::Silent, Host::Opens(100)], Mode::Serial).await;
    assert_eq!(o.started[1].1, 3_600_000, "the next host waits for the silent one: {o:?}");
}

/// An error that every host would give ends the round, and the attempts
/// that still run with it.
#[tokio::test(start_paused = true)]
async fn an_error_of_every_host_ends_the_round() {
    let o = run(&[Host::Silent, Host::Stops(100), Host::Opens(100)], Mode::Staggered).await;
    assert!(o.stopped, "{o:?}");
    assert_eq!((o.kept, o.failed.clone()), (None, vec![1]));
    assert_eq!(o.started, [(0, 0), (1, D)], "no host starts after it");
    assert_eq!(o.ended, D + 100);
}

#[tokio::test(start_paused = true)]
async fn every_host_failed() {
    let o = run(&[Host::Fails(100), Host::Fails(100)], Mode::Parallel).await;
    assert_eq!((o.kept, o.failed.clone(), o.stopped), (None, vec![0, 1], false));
    assert_eq!(o.notes, ["host 0", "host 1"]);
}

/// The notes come in the order of the list: those of an attempt that ended
/// early wait for the attempts before it.
#[tokio::test(start_paused = true)]
async fn the_notes_come_in_the_order_of_the_list() {
    let o = run(&[Host::Fails(3000), Host::Fails(500), Host::Opens(2000)], Mode::Staggered).await;
    assert_eq!(o.started, [(0, 0), (1, D), (2, D + 500)]);
    assert_eq!(o.kept, Some(2));
    assert_eq!(o.notes, ["host 0", "host 1", "host 2"]);
}

/// A second attempt waits at most the stagger for a mint in flight of its
/// deployment, then mints at its own host; another deployment never waits,
/// and the end of the mint lets the next attempt go at once.
#[tokio::test(start_paused = true)]
async fn one_mint_at_a_time_for_each_deployment() {
    let gate = MintGate::default();
    let held = gate.hold("relay.example", STAGGER).await.expect("the first turn");
    let t0 = Instant::now();
    assert!(gate.hold("relay.example", STAGGER).await.is_none(), "a second attempt waits for the mint in flight");
    assert_eq!(t0.elapsed(), STAGGER);
    assert!(gate.hold("other.example", Duration::ZERO).await.is_some(), "another deployment does not wait");
    let next = gate.clone();
    let waiter = tokio::spawn(async move {
        let t = Instant::now();
        next.hold("relay.example", STAGGER).await.map(|_| t.elapsed())
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(held);
    assert_eq!(waiter.await.unwrap(), Some(Duration::from_millis(500)));
}
