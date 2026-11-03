use super::*;

fn opened(ms: f64) -> Probe {
    Probe { open_ms: Some(ms), ping_ms: Some(ms / 4.0), why: None }
}

fn failed(why: &str) -> Probe {
    Probe { open_ms: None, ping_ms: None, why: Some(why.into()) }
}

fn names(hosts: &[Figures]) -> Vec<&str> {
    hosts.iter().map(|h| h.host.as_str()).collect()
}

#[test]
fn the_figures_are_the_nearest_rank_of_the_probes_that_opened() {
    let f = figures("a", &[opened(300.0), opened(100.0), failed("refused"), opened(200.0)]);
    assert_eq!((f.tries, f.opened), (4, 3));
    assert_eq!((f.open_p50_ms, f.open_p95_ms, f.ping_p50_ms), (Some(200.0), Some(300.0), Some(50.0)));
    assert_eq!(f.why.as_deref(), Some("refused"));
    assert_eq!(f.failed_share(), 0.25);
    let none = figures("b", &[]);
    assert_eq!((none.open_p50_ms, none.failed_share()), (None, 1.0));
    assert_eq!(nearest(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0], 95.0), Some(10.0));
}

/// A host that is slow once in three is ranked by its median, not by its
/// last probe: a rank by the last probe would put it last.
#[test]
fn a_host_slow_once_in_three_keeps_its_place_by_its_median() {
    let steady = figures("steady", &[opened(400.0), opened(410.0), opened(405.0)]);
    let once = figures("once", &[opened(150.0), opened(160.0), opened(900.0)]);
    assert_eq!(names(&order(vec![steady, once])), ["once", "steady"]);
}

#[test]
fn fewer_failures_come_first_then_the_median_then_the_p95() {
    let fast_but_failing = figures("flaky", &[opened(100.0), failed("cut")]);
    let slow = figures("slow", &[opened(600.0), opened(620.0)]);
    let fast = figures("fast", &[opened(200.0), opened(210.0)]);
    let dead = figures("dead", &[failed("no answer"), failed("no answer")]);
    let ranked = order(vec![dead, fast_but_failing, slow, fast]);
    assert_eq!(names(&ranked), ["fast", "slow", "flaky", "dead"]);
    // Same median within the tie, a p95 far apart: the lower p95 first.
    let wide = figures("wide", &[opened(300.0), opened(310.0), opened(900.0)]);
    let tight = figures("tight", &[opened(305.0), opened(310.0), opened(320.0)]);
    assert_eq!(names(&order(vec![wide, tight])), ["tight", "wide"]);
}

/// Within 50 ms, or 10 % of the larger, two hosts keep the order that they
/// came in, so that the noise of one run moves nothing.
#[test]
fn a_tie_keeps_the_order_given() {
    let a = figures("a", &[opened(187.0)]);
    let b = figures("b", &[opened(138.0)]);
    assert_eq!(names(&order(vec![a.clone(), b.clone()])), ["a", "b"]);
    assert_eq!(names(&order(vec![b, a])), ["b", "a"]);
    let c = figures("c", &[opened(1000.0)]);
    let d = figures("d", &[opened(920.0)]);
    assert_eq!(names(&order(vec![c, d])), ["c", "d"], "80 ms is less than 10 % of 1000 ms");
}

#[test]
fn the_egress_keeps_no_name_of_the_proxy() {
    assert_eq!(egress(None), DIRECT);
    let e = egress(Some(("Proxy.Example", 3128)));
    assert_eq!(e.len(), 16);
    assert!(e.chars().all(|c| c.is_ascii_hexdigit()), "{e}");
    assert!(!e.contains("proxy"));
    assert_eq!(e, egress(Some(("proxy.example", 3128))), "the case of a name changes nothing");
    assert_ne!(e, egress(Some(("proxy.example", 8080))));
}

#[test]
fn a_rank_holds_a_day_for_its_egress() {
    let now = 1_800_000_000_000;
    let rank = Rank { schema: SCHEMA, made_ms: now - 3_600_000, egress: DIRECT.into(), ..Rank::default() };
    assert!(rank.holds(now, DIRECT));
    assert!(!rank.holds(now, "0123456789abcdef"), "another egress");
    assert!(!rank.holds(now + HOLDS.as_millis() as i64, DIRECT), "a day later");
    assert!(!Rank { made_ms: now + 1, ..rank.clone() }.holds(now, DIRECT), "from the future");
    assert!(!Rank { schema: 2, ..rank }.holds(now, DIRECT), "another form");
}

#[test]
fn the_file_is_private_and_reads_back() {
    let dir = std::env::temp_dir().join(format!("podssh-rank-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let dirs = vec![dir.clone()];
    let rank = Rank {
        schema: SCHEMA,
        made_ms: 1,
        egress: DIRECT.into(),
        target: "github.com:22".into(),
        rounds: 3,
        named: false,
        hosts: order(vec![figures("b", &[opened(500.0)]), figures("a", &[opened(100.0)])]),
        samples: Default::default(),
    };
    let path = save_in(&dirs, &rank).unwrap();
    assert_eq!(load_from(&dirs), Some(rank.clone()));
    assert_eq!(rank.first().map(|h| h.host.as_str()), Some("a"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{path:?}");
    }
    cache::remove_named_from(&dirs, FILE);
    assert_eq!(load_from(&dirs), None);
    let _ = std::fs::remove_dir_all(&dir);
}
