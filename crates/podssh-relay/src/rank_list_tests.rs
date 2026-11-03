use super::*;
use crate::rank::{DIRECT, HOLDS, SCHEMA};

const NOW: i64 = 1_800_000_000_000;

fn host(name: &str, opened: u32, p50: f64) -> Figures {
    Figures {
        host: format!("{name}:443"),
        tries: 3,
        opened,
        open_p50_ms: (opened > 0).then_some(p50),
        open_p95_ms: (opened > 0).then_some(p50),
        ..Figures::default()
    }
}

/// A rank made an hour ago from this host's egress, best first: c, the
/// default host, a; b never opened.
fn kept() -> Rank {
    Rank {
        schema: SCHEMA,
        made_ms: NOW - 3_600_000,
        egress: DIRECT.into(),
        hosts: vec![
            host("c.relay.test", 3, 100.0),
            host("d.relay.test", 3, 200.0),
            host("a.relay.test", 3, 300.0),
            host("b.relay.test", 0, 0.0),
        ],
        ..Rank::default()
    }
}

/// The egress of a host with no proxy, whatever this host's own is.
fn direct(_: &str) -> String {
    DIRECT.to_string()
}

fn pool() -> Vec<String> {
    ["a.relay.test", "b.relay.test", "c.relay.test", "e.relay.test"].iter().map(|s| s.to_string()).collect()
}

#[test]
fn a_rank_that_holds_orders_the_pool_and_the_rest_keep_their_order() {
    let ordered = alternates(pool(), Some(&kept()), DIRECT, NOW);
    assert_eq!(ordered, ["c.relay.test", "a.relay.test", "b.relay.test", "e.relay.test"]);
}

#[test]
fn a_rank_of_another_egress_an_old_one_or_none_gives_the_pools_order() {
    assert_eq!(alternates(pool(), Some(&kept()), "0123456789abcdef", NOW), pool(), "another egress");
    let late = NOW + HOLDS.as_millis() as i64;
    assert_eq!(alternates(pool(), Some(&kept()), DIRECT, late), pool(), "25 h after it was made");
    assert_eq!(alternates(pool(), None, DIRECT, NOW), pool(), "no rank");
    let named = Rank { named: true, ..kept() };
    assert_eq!(alternates(pool(), Some(&named), DIRECT, NOW), pool(), "a rank of hosts that the user named");
}

#[test]
fn the_samples_order_a_pool_where_no_rank_holds() {
    let mut old = Rank { made_ms: NOW - 2 * HOLDS.as_millis() as i64, ..kept() };
    add(&mut old.samples, &[("e.relay.test".into(), 150.0), ("a.relay.test".into(), 900.0)], &direct, NOW - 60_000);
    // A sample of another egress, or older than a day, counts for nothing.
    old.samples.entry("b.relay.test".into()).or_default().push(Sample {
        at_ms: NOW,
        egress: "elsewhere".into(),
        open_ms: 10.0,
    });
    old.samples.entry("c.relay.test".into()).or_default().push(Sample {
        at_ms: NOW - 2 * HOLDS.as_millis() as i64,
        egress: DIRECT.into(),
        open_ms: 10.0,
    });
    let ordered = alternates(pool(), Some(&old), DIRECT, NOW);
    assert_eq!(ordered, ["e.relay.test", "a.relay.test", "b.relay.test", "c.relay.test"]);
}

#[test]
fn the_default_host_takes_its_place_in_the_rank_and_a_named_list_keeps_its_order() {
    let relay = |h: &str| Relay { host: h.into(), port: 443 };
    let list =
        RelayList { hosts: vec![relay("d.relay.test"), relay("a.relay.test"), relay("c.relay.test")], explicit: false };
    let names = |hosts: Vec<Relay>| hosts.into_iter().map(|r| r.host).collect::<Vec<_>>();
    assert_eq!(names(placed(&list, Some(&kept()), DIRECT, NOW)), ["c.relay.test", "d.relay.test", "a.relay.test"]);
    assert_eq!(names(placed(&list, Some(&kept()), "elsewhere", NOW)), ["d.relay.test", "a.relay.test", "c.relay.test"]);
    let named = RelayList { explicit: true, ..list.clone() };
    assert_eq!(names(placed(&named, Some(&kept()), DIRECT, NOW)), ["d.relay.test", "a.relay.test", "c.relay.test"]);
}

/// The record of failures moves hosts within the list that the rank gave:
/// the rank's first host, failed 30 s ago, is tried last.
#[test]
fn a_host_that_failed_lately_goes_last_over_its_rank() {
    let relay = |h: &str| Relay { host: h.into(), port: 443 };
    let list =
        RelayList { hosts: vec![relay("d.relay.test"), relay("a.relay.test"), relay("c.relay.test")], explicit: false };
    let ranked = placed(&list, Some(&kept()), DIRECT, NOW);
    let mut records = crate::failures::Records::default();
    records.hosts.insert(
        "c.relay.test".into(),
        crate::failures::Record { at_ms: NOW - 30_000, reason: "no answer".into(), ..Default::default() },
    );
    let (order, _) = crate::failures::order(crate::failures::WEBSOCKET, &ranked, &records, NOW);
    let names: Vec<&str> = order.iter().map(|&i| ranked[i].host.as_str()).collect();
    assert_eq!(names, ["d.relay.test", "a.relay.test", "c.relay.test"]);
}

#[test]
fn each_host_keeps_its_last_samples() {
    let mut samples = BTreeMap::new();
    for i in 0..12 {
        add(&mut samples, &[("a.relay.test".into(), f64::from(i))], &direct, NOW + i64::from(i));
    }
    let kept = &samples["a.relay.test"];
    assert_eq!(kept.len(), SAMPLES);
    assert_eq!(kept.first().map(|s| s.open_ms), Some(4.0));
    assert_eq!(kept.last().map(|s| (s.open_ms, s.at_ms)), Some((11.0, NOW + 11)));
}

#[test]
fn the_switch_turns_the_order_off() {
    set_by_settings(false);
    assert!(!enabled());
    set_by_settings(true);
    // The variable, where the test's environment sets none.
    if std::env::var(ENV).is_err() {
        assert!(enabled());
    }
}
