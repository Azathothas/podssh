//! Chain tests: readiness rules, order preference, forced mode, empty set,
//! and the network check that each mode needs before it is ready (T-102).

use podssh_ts::chain::{default_chain, probe, select_chain, ChainInputs, Verdict};
use podssh_ts::config::TsMode;

/// Key material, and the network checks that `reach` gives.
fn keyed(reach: Vec<(TsMode, Verdict)>) -> ChainInputs {
    ChainInputs { addrs: vec![], socks_endpoint: None, has_key: true, reach }
}

/// Both modes' checks passed.
fn reachable() -> Vec<(TsMode, Verdict)> {
    vec![(TsMode::Tcp, Verdict::Ok), (TsMode::default_relay(), Verdict::Ok)]
}

fn keyless() -> ChainInputs {
    ChainInputs { addrs: vec![], socks_endpoint: None, has_key: false, reach: reachable() }
}

fn fail(why: &str) -> Verdict {
    Verdict::Fail(why.to_string())
}

#[test]
fn keyed_tcp_and_relay_are_ready_when_their_checks_passed() {
    assert_eq!(probe(&TsMode::Tcp, &keyed(reachable())), Verdict::Ok);
    assert_eq!(probe(&TsMode::default_relay(), &keyed(reachable())), Verdict::Ok);
}

#[test]
fn keyless_tcp_and_relay_fail_naming_the_key() {
    assert_eq!(probe(&TsMode::Tcp, &keyless()), fail("no auth key"));
    assert_eq!(probe(&TsMode::default_relay(), &keyless()), fail("no auth key"));
}

#[test]
fn auto_takes_relay_when_the_tcp_probe_fails() {
    let chain = default_chain(TsMode::default_relay());
    assert_eq!(chain.len(), 2);
    // Both checks passed: tcp first, as the order says.
    assert_eq!(select_chain(&chain, &keyed(reachable())), Some(TsMode::Tcp));
    // No stock DERP server answered: the chain falls through to the relay.
    let inputs =
        keyed(vec![(TsMode::Tcp, fail("no stock DERP server answered")), (TsMode::default_relay(), Verdict::Ok)]);
    assert_eq!(probe(&TsMode::Tcp, &inputs), fail("no stock DERP server answered"));
    assert_eq!(select_chain(&chain, &inputs), Some(TsMode::default_relay()));
}

#[test]
fn a_mode_whose_check_did_not_run_is_not_ready() {
    // Unknown is never ready: neither a check that could not run nor one
    // that was never made.
    let chain = default_chain(TsMode::default_relay());
    assert_eq!(probe(&TsMode::Tcp, &keyed(vec![])), Verdict::Unknown);
    assert_eq!(select_chain(&chain, &keyed(vec![])), None);
    let inputs = keyed(vec![(TsMode::Tcp, Verdict::Unknown), (TsMode::default_relay(), fail("refused"))]);
    assert_eq!(select_chain(&chain, &inputs), None);
    // The verdict of one relay host is not another's.
    let other = TsMode::Relay { host: "relay.example".to_string(), port: 443 };
    assert_eq!(probe(&other, &keyed(reachable())), Verdict::Unknown);
}

#[test]
fn a_forced_single_mode_is_honoured() {
    let relay = TsMode::default_relay();
    assert_eq!(select_chain(std::slice::from_ref(&relay), &keyed(reachable())), Some(relay.clone()));
    // Forced, and its check failed: nothing is selected, and the caller says why.
    let inputs = keyed(vec![(relay.clone(), fail("timed out"))]);
    assert_eq!(select_chain(std::slice::from_ref(&relay), &inputs), None);
}

#[test]
fn no_ready_mode_selects_nothing() {
    let chain = default_chain(TsMode::default_relay());
    assert_eq!(select_chain(&chain, &keyless()), None);
    let empty: Vec<TsMode> = vec![];
    assert_eq!(select_chain(&empty, &keyed(reachable())), None);
}
