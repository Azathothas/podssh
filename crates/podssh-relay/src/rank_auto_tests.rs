use super::*;
use crate::rank::{Figures, DIRECT, HOLDS, ON_DEMAND, SCHEMA};

const NOW: i64 = 1_800_000_000_000;

/// The default host and nine hosts of its pool, one named twice.
fn pool() -> Vec<String> {
    let all = ["tcp", "a", "b", "A", "c", "d", "e", "f", "g", "h"];
    all.iter().map(|h| format!("{h}.relay.test")).collect()
}

fn opened(ms: f64) -> Probe {
    Probe { open_ms: Some(ms), ping_ms: Some(ms / 4.0), why: None }
}

fn run() -> Run<'static> {
    Run { egress: DIRECT, target: "github.com:22", now_ms: NOW }
}

fn hosts_of(rank: &Rank) -> Vec<&str> {
    rank.hosts.iter().map(|f| f.host.as_str()).collect()
}

#[test]
fn with_no_rank_the_plan_is_the_first_eight_hosts_each_once() {
    let plan = plan(None, &pool(), DIRECT, NOW).expect("a run is due");
    assert_eq!(plan.len(), MOST);
    assert_eq!(&plan[..4], ["tcp.relay.test", "a.relay.test", "b.relay.test", "c.relay.test"]);
    assert_eq!(plan.last().map(String::as_str), Some("g.relay.test"));
}

/// Once a day: a rank that holds for this egress blocks a run, whoever made
/// it; one of another egress, or a day old, does not.
#[test]
fn a_rank_that_holds_blocks_a_run_and_another_egress_or_a_day_does_not() {
    let made = with_probe(None, &run(), "tcp.relay.test", opened(100.0), false);
    assert!(plan(Some(&made), &pool(), DIRECT, NOW + 1).is_none(), "a whole background rank");
    let on_demand = Rank { source: ON_DEMAND.into(), ..made.clone() };
    assert!(plan(Some(&on_demand), &pool(), DIRECT, NOW + 1).is_none(), "a rank of relay rank");
    let before = Rank { source: String::new(), partial: true, ..made.clone() };
    assert!(plan(Some(&before), &pool(), DIRECT, NOW + 1).is_none(), "a rank of before T-608");
    let named = Rank { named: true, partial: true, ..made.clone() };
    assert!(plan(Some(&named), &pool(), DIRECT, NOW + 1).is_none(), "a rank of hosts that the user named");
    assert_eq!(plan(Some(&made), &pool(), "0123456789abcdef", NOW + 1).map(|p| p.len()), Some(MOST));
    let late = NOW + HOLDS.as_millis() as i64;
    assert_eq!(plan(Some(&made), &pool(), DIRECT, late).map(|p| p.len()), Some(MOST), "a day later");
}

/// A session that ended early keeps what it measured; the next one of the
/// day goes on with the hosts that the rank lacks, never one twice, and
/// never past eight in all.
#[test]
fn a_partial_rank_goes_on_with_the_hosts_that_it_lacks() {
    let mut made = with_probe(None, &run(), "tcp.relay.test", opened(300.0), true);
    made = with_probe(Some(made), &run(), "a.relay.test", opened(100.0), true);
    assert!(made.partial && made.background() && made.made_ms == NOW && made.background_ms == NOW);
    assert_eq!(hosts_of(&made), ["a.relay.test:443", "tcp.relay.test:443"], "in order");
    let later = NOW + 3_600_000;
    let left = plan(Some(&made), &pool(), DIRECT, later).expect("it goes on");
    assert_eq!(left.len(), MOST - 2);
    assert_eq!(&left[..2], ["b.relay.test", "c.relay.test"]);
    // A host of the pool that the rank has under another case, or with
    // its port, is not probed again.
    assert!(!left.iter().any(|h| h.eq_ignore_ascii_case("a.relay.test")), "{left:?}");
    let next = Run { now_ms: later, ..run() };
    let went_on = with_probe(Some(made.clone()), &next, "b.relay.test", opened(200.0), false);
    assert_eq!(went_on.made_ms, NOW, "a day from its first probe");
    assert!(!went_on.partial);
    assert_eq!(hosts_of(&went_on), ["a.relay.test:443", "b.relay.test:443", "tcp.relay.test:443"]);
    assert!(plan(Some(&went_on), &pool(), DIRECT, later).is_none(), "whole: no run until the day ends");
    // A pool that grew finds no room past eight.
    let full = Rank { hosts: vec![Figures { host: "x:443".into(), ..Figures::default() }; MOST], ..made };
    assert_eq!(plan(Some(&full), &pool(), DIRECT, later), Some(Vec::new()));
}

/// A new rank keeps the samples of the races that the file held.
#[test]
fn a_new_rank_keeps_the_samples_of_the_file() {
    let mut old = Rank { schema: SCHEMA, ..Rank::default() };
    crate::rank_list::add(&mut old.samples, &[("a.relay.test".into(), 150.0)], &|_: &str| DIRECT.to_string(), NOW);
    let made = with_probe(Some(old.clone()), &run(), "tcp.relay.test", opened(100.0), true);
    assert_eq!(made.samples, old.samples);
    assert_eq!((made.egress.as_str(), made.target.as_str(), made.rounds), (DIRECT, "github.com:22", 1));
}

#[test]
fn the_variable_asks_above_the_file_and_nothing_asks_by_default() {
    assert_eq!(asked_from(None, false), None, "never by default");
    assert_eq!(asked_from(None, true), Some("RelayRank auto"));
    assert_eq!(asked_from(Some(" Auto "), false), Some("PODSSH_RELAY_RANK=auto"));
    assert_eq!(asked_from(Some("yes"), true), None, "the variable wins");
    assert_eq!(asked_from(Some("no"), true), None);
    assert_eq!(asked_from(Some(""), true), Some("RelayRank auto"), "an empty variable is none");
}

#[test]
fn the_pace_of_the_tests_is_two_numbers() {
    let ms = Duration::from_millis;
    assert_eq!(pace_of("400,1200"), Some(Pace { delay: ms(400), gap: ms(1200) }));
    assert_eq!(pace_of(" 0 , 5 "), Some(Pace { delay: ms(0), gap: ms(5) }));
    for bad in ["", "400", "a,b", "400;1200", "-1,2"] {
        assert_eq!(pace_of(bad), None, "{bad}");
    }
    assert_eq!((DELAY, GAP, MOST), (Duration::from_secs(60), Duration::from_secs(10), 8), "Q89's bounds");
}

/// A probe never runs beside a race: one that waits for its turn while a
/// race runs, and one in flight when a race starts, is dropped.
#[tokio::test(start_paused = true)]
async fn a_race_drops_a_probe_in_flight_and_holds_the_next() {
    let probe = async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        "measured"
    };
    let racer = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let race = racing();
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(race);
    });
    let started = tokio::time::Instant::now();
    assert_eq!(unless_a_race(probe).await, None, "dropped as the race started");
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert_eq!(unless_a_race(async { "measured" }).await, None, "none while it runs");
    calm().await;
    assert!(!a_race_runs());
    assert!(started.elapsed() >= Duration::from_secs(3), "{:?}", started.elapsed());
    assert_eq!(unless_a_race(async { "measured" }).await, Some("measured"));
    racer.await.unwrap();
}
