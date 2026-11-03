use super::*;

use crate::ping::relay::Leg;

#[test]
fn a_probe_is_the_dial_tls_and_upgrade_with_the_token_left_out() {
    let leg = Leg {
        token: Some(("minted", Duration::from_millis(900))),
        connect: Some(("DNS and TCP".into(), Duration::from_millis(40))),
        tls: Some(Duration::from_millis(60)),
        upgrade: Some(Duration::from_millis(200)),
        pings: vec![Duration::from_millis(30), Duration::from_millis(10), Duration::from_millis(20)],
        ..Leg::default()
    };
    let p = probe_of(&leg);
    assert!(p.opened(), "{p:?}");
    assert_eq!(p.open_ms.map(|v| v.round()), Some(300.0));
    assert_eq!(p.ping_ms.map(|v| v.round()), Some(20.0));
    // Its pings broke after the upgrade: it opened, with no ping's figure.
    let broke = Leg { pings: vec![], failed: Some("a ping could not be sent".into()), ..leg.clone() };
    let p = probe_of(&broke);
    assert!(p.opened() && p.ping_ms.is_none(), "{p:?}");
    let failed = Leg { failed: Some("refused".into()), connect: leg.connect.clone(), ..Leg::default() };
    let p = probe_of(&failed);
    assert!(!p.opened());
    assert_eq!(p.why.as_deref(), Some("refused"));
    assert_eq!(probe_of(&Leg::default()).why.as_deref(), Some("no session"));
}

#[test]
fn each_round_is_a_permutation() {
    for n in [0, 1, 2, 7, 37] {
        let mut order = shuffled(n);
        order.sort_unstable();
        assert_eq!(order, (0..n).collect::<Vec<_>>());
    }
}

#[test]
fn the_numbers_are_bounded() {
    assert_eq!(number(None, "--rounds", 3, 20).ok(), Some(3));
    assert_eq!(number(Some("20"), "--rounds", 3, 20).ok(), Some(20));
    for bad in ["0", "21", "x", "-1", ""] {
        let refusal = number(Some(bad), "--rounds", 3, 20).unwrap_err();
        assert_eq!(refusal.code, crate::exit_codes::EXIT_USAGE, "{bad}");
        assert!(refusal.message.contains("a number from 1 to 20"), "{}", refusal.message);
    }
}

#[test]
fn the_lines_of_a_rank_name_each_host_best_first() {
    let made = Rank {
        schema: rank::SCHEMA,
        made_ms: 1,
        hosts: vec![
            Figures {
                host: "a:443".into(),
                tries: 3,
                opened: 3,
                open_p50_ms: Some(200.4),
                open_p95_ms: Some(250.0),
                ping_p50_ms: Some(30.0),
                why: None,
            },
            Figures { host: "b:443".into(), tries: 3, opened: 0, why: Some("no answer".into()), ..Figures::default() },
        ],
        ..Rank::default()
    };
    assert_eq!(
        rank_lines(&made),
        [
            " 1 a:443: opened 3 of 3, open p50 200 ms, p95 250 ms, ping p50 30 ms",
            " 2 b:443: opened 0 of 3, open p50 - ms, p95 - ms, ping p50 - ms; no answer",
        ]
    );
    let doc = rank_json(&made, 61_001);
    assert_eq!(doc["age_s"], 61);
    assert_eq!(doc["hosts"][0]["open_p50_ms"], 200.4);
    assert_eq!(ago(Duration::from_secs(61)), "61 s ago");
    assert_eq!(ago(Duration::from_secs(600)), "10 min ago");
    assert_eq!(ago(Duration::from_secs(7200)), "2 h ago");
}
