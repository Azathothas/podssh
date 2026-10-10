//! podssh's patch 0019: a link is dialled again after a drop, with a capped backoff, a refusal
//! of the node key is not, a quiet close waits for activity, and a link that died with no close
//! is known by its silence. The loop runs fake links under a paused clock: no network.

// Named, not taken from the 2024 prelude: podssh-ts builds this file too, in edition 2021.
use core::future::Future;
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{sync::Mutex, time::Instant};
use ts_runtime::reconnect::{self, Ended, Heard, Link, LinkChange, Reconnect};

/// One turn of a fake link.
enum Turn {
    /// The connect fails so.
    NoConnect(Ended),
    /// The connect succeeds; the link runs this long, then ends so.
    Up(Duration, Ended),
    /// The connect succeeds, and the link runs until it falls silent.
    Silent(Arc<FakeHeard>),
}

/// A link that plays its turns, and keeps when each connect came and each change it was told.
struct Fake {
    turns: VecDeque<Turn>,
    /// When the waits for activity end, from the start; none left means at once, as for home.
    activity: VecDeque<Duration>,
    start: Instant,
    connects: Vec<Duration>,
    changes: Vec<LinkChange>,
}

impl Fake {
    fn new(turns: Vec<Turn>) -> Self {
        Self {
            turns: turns.into(),
            activity: VecDeque::new(),
            start: Instant::now(),
            connects: Vec::new(),
            changes: Vec::new(),
        }
    }
}

enum Running {
    For(Duration, Ended),
    UntilSilent(Arc<FakeHeard>),
}

impl Link for Fake {
    type Pending = ();
    type Transport = Running;

    fn wait(&mut self) -> impl Future<Output = ()> + Send {
        let until = self.activity.pop_front().map(|at| self.start + at);
        async move {
            if let Some(until) = until {
                tokio::time::sleep_until(until).await;
            }
        }
    }

    fn connect(&mut self, (): ()) -> impl Future<Output = Result<Running, Ended>> + Send {
        self.connects.push(self.start.elapsed());
        let turn = self.turns.pop_front();
        async move {
            match turn {
                Some(Turn::NoConnect(ended)) => Err(ended),
                Some(Turn::Up(lasts, ended)) => Ok(Running::For(lasts, ended)),
                Some(Turn::Silent(heard)) => Ok(Running::UntilSilent(heard)),
                // The play is over: the link stays down, and the test ends the loop.
                None => std::future::pending().await,
            }
        }
    }

    async fn run(&mut self, running: Running) -> Ended {
        match running {
            Running::For(lasts, ended) => {
                tokio::time::sleep(lasts).await;
                ended
            }
            Running::UntilSilent(heard) => {
                Ended::Failed(reconnect::until_silent(&*heard, reconnect::PING_EVERY, 3).await)
            }
        }
    }

    fn changed(&mut self, change: LinkChange) {
        self.changes.push(change);
    }
}

/// Run the loop until the play is over, and give back why it returned, if it did.
async fn play(fake: &mut Fake, policy: &Reconnect) -> Option<String> {
    tokio::time::timeout(Duration::from_secs(3600), reconnect::keep(fake, policy))
        .await
        .ok()
}

fn failed(why: &str) -> Ended {
    Ended::Failed(why.to_string())
}

fn secs(at: Duration) -> f64 {
    at.as_secs_f64()
}

#[tokio::test(start_paused = true)]
async fn a_dropped_link_is_dialled_again_with_backoff() {
    let mut fake = Fake::new(vec![
        Turn::Up(Duration::from_secs(1), failed("the relay went away")),
        Turn::NoConnect(failed("connection refused")),
        Turn::NoConnect(failed("connection refused")),
        Turn::Up(Duration::from_secs(5), failed("reset")),
    ]);
    assert_eq!(play(&mut fake, &Reconnect::default()).await, None);
    let at: Vec<f64> = fake.connects.iter().copied().map(secs).collect();
    assert_eq!(at.len(), 5, "connects at {at:?}");
    // 1 s, then 2 s, then 4 s, each by a factor in [0.5, 1.5).
    let gaps = [at[1] - 1.0, at[2] - at[1], at[3] - at[2]];
    for (gap, base) in gaps.iter().zip([1.0, 2.0, 4.0]) {
        assert!(
            (0.5 * base..1.5 * base).contains(gap),
            "a gap of {gap} s for {base} s: {at:?}"
        );
    }
    assert!(matches!(
        fake.changes[0],
        LinkChange::Connected { again: false }
    ));
    assert!(
        matches!(&fake.changes[1], LinkChange::Dropped { reason, .. } if reason == "the relay went away")
    );
    assert!(matches!(
        fake.changes[4],
        LinkChange::Connected { again: true }
    ));
}

#[tokio::test(start_paused = true)]
async fn the_wait_is_capped_and_a_link_that_lasted_counts_from_the_first_again() {
    let policy = Reconnect::default();
    for retry in 6..40 {
        assert!(policy.wait(retry) < Duration::from_secs(45), "{retry}");
    }
    let mut fake = Fake::new(vec![
        Turn::NoConnect(failed("down")),
        Turn::NoConnect(failed("down")),
        Turn::NoConnect(failed("down")),
        Turn::Up(Duration::from_secs(61), failed("dropped after a minute")),
    ]);
    play(&mut fake, &policy).await;
    let at: Vec<f64> = fake.connects.iter().copied().map(secs).collect();
    // After a link of 61 s, the wait is the first one again: under 1.5 s.
    let after = at[4] - at[3] - 61.0;
    assert!((0.5..1.5).contains(&after), "{after} s: {at:?}");
}

#[tokio::test(start_paused = true)]
async fn a_1008_not_authorized_is_not_retried_by_default() {
    let refused = || Ended::Refused("websocket closed: code=1008 reason=\"not authorized\"".into());
    let mut fake = Fake::new(vec![Turn::NoConnect(refused()), Turn::NoConnect(refused())]);
    let reason = play(&mut fake, &Reconnect::default()).await;
    assert!(reason.is_some_and(|r| r.contains("not authorized")));
    assert_eq!(fake.connects.len(), 1);
    assert!(matches!(&fake.changes[..], [LinkChange::Refused { .. }]));

    // While the node waits for its key's admission, a refusal is dialled again.
    let waiting = Reconnect {
        retry_refused: true,
        ..Reconnect::default()
    };
    let mut fake = Fake::new(vec![Turn::NoConnect(refused()), Turn::NoConnect(refused())]);
    assert_eq!(play(&mut fake, &waiting).await, None);
    assert_eq!(fake.connects.len(), 3);
    assert!(matches!(fake.changes[0], LinkChange::Dropped { .. }));
}

#[test]
fn the_relays_close_1008_not_authorized_is_a_refusal() {
    let close = |code, reason: &str| {
        ts_derp::Error::IoFailure(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            ts_derp::ws::WsClose {
                code: Some(code),
                reason: reason.to_string(),
            },
        ))
    };
    assert!(matches!(
        reconnect::ended_by(&close(1008, "not authorized")),
        Ended::Refused(_)
    ));
    // Another 1008, another code, or no close at all is a drop.
    for e in [
        close(1008, "duplicate login"),
        close(1011, "not authorized"),
        ts_derp::Error::NoServerReachable,
    ] {
        assert!(matches!(reconnect::ended_by(&e), Ended::Failed(_)), "{e}");
    }
}

/// A far end that answers the first ping, then nothing.
struct FakeHeard {
    heard: Mutex<Instant>,
    pongs: AtomicU64,
    answers: AtomicU64,
}

impl FakeHeard {
    fn new(answers: u64) -> Arc<Self> {
        Arc::new(Self {
            heard: Mutex::new(Instant::now()),
            pongs: AtomicU64::new(0),
            answers: AtomicU64::new(answers),
        })
    }
}

impl Heard for FakeHeard {
    fn last_heard(&self) -> Instant {
        *self.heard.try_lock().expect("one reader at a time")
    }

    fn pongs(&self) -> u64 {
        self.pongs.load(Ordering::Relaxed)
    }

    async fn ping(&self) -> Result<(), String> {
        if self.answers.load(Ordering::Relaxed) > 0 {
            self.answers.fetch_sub(1, Ordering::Relaxed);
            self.pongs.fetch_add(1, Ordering::Relaxed);
            *self.heard.lock().await = Instant::now();
        }
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn a_silent_link_is_dead_after_three_checks() {
    let mut fake = Fake::new(vec![Turn::Silent(FakeHeard::new(1))]);
    assert_eq!(play(&mut fake, &Reconnect::default()).await, None);
    let at: Vec<f64> = fake.connects.iter().copied().map(secs).collect();
    // Pinged at 10 s and answered; silent at 30, 40 and 50 s: dead at 50 s, and dialled again
    // after the first wait.
    assert!(
        matches!(&fake.changes[1], LinkChange::Dropped { reason, .. } if reason.contains("30 s"))
    );
    assert!((50.5..51.5).contains(&at[1]), "{at:?}");
}

#[tokio::test(start_paused = true)]
async fn a_far_end_that_never_answered_a_ping_is_not_declared_dead() {
    let heard = FakeHeard::new(0);
    let watched = tokio::time::timeout(
        Duration::from_secs(600),
        reconnect::until_silent(&*heard, reconnect::PING_EVERY, 3),
    )
    .await;
    assert!(watched.is_err(), "declared dead: {watched:?}");
}

#[tokio::test(start_paused = true)]
async fn a_non_home_inactivity_close_waits_for_activity() {
    let mut fake = Fake::new(vec![
        Turn::Up(Duration::from_secs(5), Ended::Quiet),
        Turn::Up(Duration::from_secs(5), Ended::Quiet),
    ]);
    fake.activity = [Duration::ZERO, Duration::from_secs(100)].into();
    assert_eq!(play(&mut fake, &Reconnect::default()).await, None);
    // Connected at the first activity, and again only at the next: no backoff, no drop.
    let at: Vec<f64> = fake.connects.iter().copied().map(secs).collect();
    assert_eq!(&at[..2], &[0.0, 100.0]);
    assert!(
        fake.changes
            .iter()
            .all(|c| matches!(c, LinkChange::Connected { again: false })),
        "{:?}",
        fake.changes
    );
}
