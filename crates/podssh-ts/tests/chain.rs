//! Chain tests: readiness rules, order preference, forced mode, empty set.

use podssh_ts::chain::{default_chain, probe, select_chain, ChainInputs, Verdict};
use podssh_ts::config::TsMode;

fn keyed() -> ChainInputs {
    ChainInputs { addrs: vec![], socks_endpoint: None, has_key: true }
}

fn keyless() -> ChainInputs {
    ChainInputs { addrs: vec![], socks_endpoint: None, has_key: false }
}

#[test]
fn keyed_tcp_and_relay_are_ready() {
    assert_eq!(probe(&TsMode::Tcp, &keyed()), Verdict::Ok);
    assert_eq!(probe(&TsMode::default_relay(), &keyed()), Verdict::Ok);
}

#[test]
fn keyless_tcp_and_relay_fail_naming_the_key() {
    assert_eq!(probe(&TsMode::Tcp, &keyless()), Verdict::Fail("no auth key".to_string()));
    assert_eq!(probe(&TsMode::default_relay(), &keyless()), Verdict::Fail("no auth key".to_string()));
}

#[test]
fn the_default_chain_prefers_tcp_then_relay() {
    let chain = default_chain(TsMode::default_relay());
    assert_eq!(chain.len(), 2);
    assert_eq!(select_chain(&chain, &keyed()), Some(TsMode::Tcp));
}

#[test]
fn a_forced_single_mode_is_honoured() {
    let relay = TsMode::default_relay();
    assert_eq!(select_chain(std::slice::from_ref(&relay), &keyed()), Some(relay));
}

#[test]
fn no_ready_mode_selects_nothing() {
    let chain = default_chain(TsMode::default_relay());
    assert_eq!(select_chain(&chain, &keyless()), None);
    let empty: Vec<TsMode> = vec![];
    assert_eq!(select_chain(&empty, &keyed()), None);
}
