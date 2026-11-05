//! The tests of the opener, apart from `open.rs` for its length: which
//! errors end the failover and which move to the next host, a failure after
//! the connection, the backoff, and the lines of a failure over several hosts.

use super::*;

fn refused(status: u16, body: &str) -> OpenError {
    OpenError::Connect { error: ConnectError::Refused { status, body: body.into() }, origin: Origin::Minted }
}

#[test]
fn errors_every_host_would_repeat_stop_the_failover() {
    assert!(!OpenError::Offline.another_host_may_help());
    assert!(!OpenError::Token(TokenError::BadEnvironment).another_host_may_help());
    assert!(!refused(403, "forward: github.com:25 not in the ALLOW list").another_host_may_help());
    assert!(!refused(400, "blocked address range").another_host_may_help());
    assert!(!refused(502, "relay: cannot reach x:22 — no AAAA address for x").another_host_may_help());
    assert!(!refused(502, "relay: nope.invalid does not resolve").another_host_may_help());
}

#[test]
fn errors_of_one_host_move_to_the_next() {
    assert!(OpenError::Deadline.another_host_may_help());
    assert!(refused(503, "paused").another_host_may_help());
    assert!(refused(429, "slow down").another_host_may_help());
    assert!(refused(502, "relay: connect failed: timed out").another_host_may_help());
    let proxy_504 = OpenError::Connect {
        error: ConnectError::Dial(DialError::ProxyRefused {
            proxy: "proxy:3128".into(),
            target: "relay:443".into(),
            status: 504,
            reason: "Gateway Timeout".into(),
        }),
        origin: Origin::Cache,
    };
    assert!(proxy_504.another_host_may_help());
    assert!(proxy_504.lines("h:22").iter().any(|l| l.contains("another relay host")));
}

/// A host that failed once its connection opened, as no relay would, is
/// told from one whose connection never opened, and from the relay's own
/// refusals, which keep the address of the cache (T-344).
#[test]
fn a_failure_after_the_connection_is_told_from_the_others() {
    let connect = |error| OpenError::Connect { error, origin: Origin::Minted };
    assert!(after_connection(&connect(ConnectError::Tls("NotValidForName".into()))));
    assert!(after_connection(&refused(530, "error code: 1034")));
    assert!(after_connection(&OpenError::Token(TokenError::Failed { status: 409, detail: String::new() })));
    let unreachable = DialError::Connect { target: "relay:443".into(), detail: "refused".into(), cut: None };
    assert!(!after_connection(&connect(ConnectError::Dial(unreachable.clone()))));
    assert!(!after_connection(&OpenError::Token(TokenError::Connect(ConnectError::Dial(unreachable)))));
    assert!(!after_connection(&OpenError::Token(TokenError::RateLimited { retry_after: None })));
    assert!(!after_connection(&OpenError::Deadline));
    assert!(failures::reason(&refused(403, "not in the ALLOW list")).is_none());
    assert!(failures::reason(&refused(502, "connect failed")).is_none());
}

#[test]
fn backoff_grows_is_capped_and_jittered() {
    for _ in 0..50 {
        let first = backoff(1).as_millis();
        assert!((500..1500).contains(&first), "{first}");
        let late = backoff(20).as_millis();
        assert!((15_000..45_000).contains(&late), "{late}");
    }
}

#[test]
fn a_failure_over_several_hosts_names_each_and_keeps_the_hints() {
    let f = Failure {
        attempts: vec![
            ("a.example".into(), OpenError::Deadline),
            ("b.example".into(), refused(403, "forward: x:25 not in the ALLOW list")),
        ],
    };
    let lines = f.lines("x:25");
    assert!(lines[0].starts_with("a.example: "), "{lines:?}");
    assert!(lines[1].starts_with("b.example: "), "{lines:?}");
    assert!(lines.iter().any(|l| l.contains("policy does not allow x:25")), "{lines:?}");
}

/// A host that this process's gate holds goes on to the next host, records
/// nothing against it and is no answer of the relay's; its line says the
/// wait (T-637).
#[test]
fn a_held_host_moves_to_the_next_and_records_nothing() {
    let held = OpenError::Held { left: Some(Duration::from_millis(2500)) };
    assert!(held.another_host_may_help());
    assert!(failures::reason(&held).is_none());
    assert!(!after_connection(&held));
    assert_eq!(held.lines("x:22"), ["waits 3 s after a failure of this process; trying the next host"]);
    let probing = OpenError::Held { left: None };
    assert_eq!(probing.lines("x:22"), ["waits for the probe of this process after a failure; trying the next host"]);
}
