//! The race between two roads (T-164), with stand-in roads on a paused
//! clock: a road gives its link after its connection time, and its far end
//! speaks after its own time, then reads what the client sends. The first
//! road has the head start; the second starts after it, or at once when the
//! first fails; the first far end to speak wins, and the loser's far end
//! reads nothing at all: no `OPEN`, so no target. A planted race that waits
//! for the first road's own time limit fails the first check. The measured
//! race of `podssh ping node://NAME` (T-435) times each road that starts, and
//! no far end of it reads a byte either.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::session::race::{each_timed, first_answered, in_turn, race, Lost, Start, Timed, Won, HEAD_START};
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

/// A road of [`in_turn`], boxed, so that roads of each kind share a type.
type Road = std::pin::Pin<Box<dyn Future<Output = Result<DuplexStream, String>>>>;

fn boxed(road: impl Future<Output = Result<DuplexStream, String>> + 'static) -> Road {
    Box::pin(road)
}

/// Three roads in turn (T-379): the third, 250 ms after the second, wins
/// when the first two cannot run until their own limits.
#[tokio::test(start_paused = true)]
async fn in_turn_the_third_road_starts_after_the_second_s_wait_and_wins() {
    let (third, seen) = road(30 * MS, 20 * MS);
    let roads = vec![
        (Start::After(HEAD_START), boxed(failing(Duration::from_secs(10), "no iroh relay"))),
        (Start::After(HEAD_START), boxed(failing(Duration::from_secs(10), "no relay"))),
        (Start::After(HEAD_START), boxed(third)),
    ];
    let Ok((won, took)) = in_turn(roads).await else { panic!("no road won") };
    assert_eq!(won.at, 2);
    assert_eq!(took, 2 * HEAD_START + 50 * MS, "the third started 500 ms in");
    assert!(seen.lock().unwrap().is_some(), "the winner's far end has its link");
}

/// A fallback starts only when each road before it failed: while the first
/// road works, it never starts; when both before it fail, it starts at once.
#[tokio::test(start_paused = true)]
async fn in_turn_a_fallback_starts_only_when_each_road_before_it_failed() {
    let (first, _) = road(Duration::from_secs(2), 10 * MS);
    let (fallback, fallback_seen) = road(10 * MS, 10 * MS);
    let roads = vec![(Start::After(HEAD_START), boxed(first)), (Start::WhenAllFailed, boxed(fallback))];
    let Ok((won, took)) = in_turn(roads).await else { panic!("no road won") };
    assert_eq!((won.at, took), (0, Duration::from_secs(2) + 10 * MS));
    assert!(fallback_seen.lock().unwrap().is_none(), "the fallback started while the first road ran");

    let (fallback, _) = road(10 * MS, 10 * MS);
    let roads = vec![
        (Start::After(HEAD_START), boxed(failing(30 * MS, "refused"))),
        (Start::After(HEAD_START), boxed(failing(40 * MS, "the pair expired"))),
        (Start::WhenAllFailed, boxed(fallback)),
    ];
    let Ok((won, took)) = in_turn(roads).await else { panic!("no road won") };
    assert_eq!(won.at, 2);
    // The second started at 30 ms, as the first failed; it failed at 70 ms.
    assert_eq!(took, 90 * MS, "the fallback started when the second failed");
}

/// The planted fallback, which starts with the others' wait: its far end
/// gets a link while the first road still works, and the check above sees it.
#[tokio::test(start_paused = true)]
async fn in_turn_a_planted_fallback_that_starts_on_a_timer_is_seen() {
    let (first, _) = road(Duration::from_secs(2), 10 * MS);
    let (fallback, fallback_seen) = road(10 * MS, 10 * MS);
    let roads = vec![(Start::After(HEAD_START), boxed(first)), (Start::After(HEAD_START), boxed(fallback))];
    let Ok((won, _)) = in_turn(roads).await else { panic!("no road won") };
    assert_eq!(won.at, 1, "the planted fallback won while the first road ran");
    assert!(fallback_seen.lock().unwrap().is_some(), "the check of the fallback sees a road that started");
}

#[tokio::test(start_paused = true)]
async fn in_turn_says_each_road_s_reason_in_the_order_of_the_list() {
    let roads = vec![
        (Start::After(HEAD_START), boxed(failing(50 * MS, "the iroh relay refused"))),
        (Start::After(HEAD_START), boxed(failing(10 * MS, "the pair expired"))),
        (Start::WhenAllFailed, boxed(failing(10 * MS, "no DERP server holds the node"))),
    ];
    let lost = in_turn(roads).await.err().expect("no winner");
    assert_eq!(lost, ["the iroh relay refused", "the pair expired", "no DERP server holds the node"]);
    assert_eq!(in_turn(Vec::<(Start, Road)>::new()).await.err(), Some(Vec::new()), "no road, no winner");
}

/// The measured race of `podssh ping node://NAME` (T-435): each road that
/// starts is timed to its far end's first bytes, the second at its wait
/// after the first answered; a fallback never starts while a road answered;
/// and no far end gets a byte, so none opens a session.
#[tokio::test(start_paused = true)]
async fn each_timed_measures_each_road_that_starts_and_sends_nothing() {
    let (first, first_seen) = road(100 * MS, 20 * MS);
    let (second, second_seen) = road(10 * MS, 10 * MS);
    let (fallback, fallback_seen) = road(10 * MS, 10 * MS);
    let roads = vec![
        (Start::After(HEAD_START), boxed(first)),
        (Start::After(HEAD_START), boxed(second)),
        (Start::WhenAllFailed, boxed(fallback)),
    ];
    let timed = each_timed(roads, Duration::from_secs(30)).await;
    let ok = |started, took| Some(Timed { started, took, answered: Ok(()) });
    assert_eq!(timed, [ok(Duration::ZERO, 120 * MS), ok(HEAD_START, 20 * MS), None]);
    assert_eq!(first_answered(&timed), Some(0));
    assert!(fallback_seen.lock().unwrap().is_none(), "the fallback started while a road answered");
    tokio::time::sleep(Duration::from_secs(1)).await;
    for seen in [first_seen, second_seen] {
        assert_eq!(seen.lock().unwrap().as_deref(), Some(&[][..]), "a far end got bytes");
    }
}

/// Each road before the fallback fails: each is timed with its reason, the
/// next at once, and the fallback last, which answers.
#[tokio::test(start_paused = true)]
async fn each_timed_starts_a_fallback_once_each_road_before_it_failed() {
    let (fallback, _) = road(10 * MS, 10 * MS);
    let roads = vec![
        (Start::After(HEAD_START), boxed(failing(30 * MS, "refused"))),
        (Start::After(HEAD_START), boxed(failing(40 * MS, "the pair expired"))),
        (Start::WhenAllFailed, boxed(fallback)),
    ];
    let timed = each_timed(roads, Duration::from_secs(30)).await;
    let failed = |started, took, why: &str| Some(Timed { started, took, answered: Err(why.to_string()) });
    assert_eq!(timed[0], failed(Duration::ZERO, 30 * MS, "refused"));
    assert_eq!(timed[1], failed(30 * MS, 40 * MS, "the pair expired"));
    assert_eq!(timed[2], Some(Timed { started: 70 * MS, took: 20 * MS, answered: Ok(()) }));
    assert_eq!(first_answered(&timed), Some(2));
}

/// A road that neither answers nor fails ends at the bound of the measure,
/// with the bound as its reason; the road that answered wins.
#[tokio::test(start_paused = true)]
async fn each_timed_ends_a_road_that_does_not_answer_at_its_bound() {
    let (second, _) = road(10 * MS, 10 * MS);
    let roads = vec![
        (Start::After(HEAD_START), boxed(failing(Duration::from_secs(60), "no relay"))),
        (Start::After(HEAD_START), boxed(second)),
    ];
    let timed = each_timed(roads, Duration::from_secs(2)).await;
    let Some(first) = &timed[0] else { panic!("the first road did not start") };
    assert_eq!((first.started, first.took), (Duration::ZERO, Duration::from_secs(2)));
    assert_eq!(first.answered, Err("no answer within 2 s of the race's start".to_string()));
    assert_eq!(timed[1], Some(Timed { started: HEAD_START, took: 20 * MS, answered: Ok(()) }));
    assert_eq!(first_answered(&timed), Some(1));
    assert!(each_timed(Vec::<(Start, Road)>::new(), Duration::from_secs(1)).await.is_empty(), "no road");
}

/// The road that answered first is the first far end that spoke from the
/// start of the race, not the first road of the list that answered; of two
/// at once, the earlier in the list, as `in_turn` polls them.
#[test]
fn first_answered_is_the_first_far_end_that_spoke() {
    let ms = Duration::from_millis;
    let ok = |started, took| Some(Timed { started: ms(started), took: ms(took), answered: Ok(()) });
    let failed = Some(Timed { started: ms(0), took: ms(5), answered: Err("refused".into()) });
    assert_eq!(first_answered(&[ok(0, 400), ok(250, 20)]), Some(1), "the second spoke at 270 ms");
    assert_eq!(first_answered(&[failed.clone(), ok(5, 30), ok(250, 0), None]), Some(1));
    assert_eq!(first_answered(&[ok(0, 30), ok(10, 20)]), Some(0), "at once: the earlier in the list");
    assert_eq!(first_answered(&[failed, None]), None);
}
