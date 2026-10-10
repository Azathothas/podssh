//! The DERP links' newest states decide whether the node can speak to its peers (T-105): a key
//! that the relay refused is said at once, in each mode; in `relay` mode the relay is the only
//! DERP link, so it must be up; in `tcp` mode the stock DERP servers are not needed to start.

use std::collections::HashMap;

use podssh_ts::node::{derp_verdict, LinkKind, LinkState, NodeError};

fn states(pairs: &[(LinkKind, LinkState)]) -> HashMap<LinkKind, LinkState> {
    pairs.iter().cloned().collect()
}

fn failed(reason: &str, refused: bool) -> LinkState {
    LinkState::Failed { reason: reason.to_string(), refused }
}

const NOT_AUTHORIZED: &str = "websocket closed: code=1008 reason=\"not authorized\"";

#[test]
fn a_refused_key_is_said_in_each_mode() {
    let refused = states(&[
        (LinkKind::Control, LinkState::Connected),
        (LinkKind::Derp(1), LinkState::Refused { reason: NOT_AUTHORIZED.into() }),
    ]);
    for pinned in [true, false] {
        let Err(NodeError::DerpRefused { reason }) = derp_verdict(&refused, pinned) else {
            panic!("not refused, pinned {pinned}")
        };
        assert_eq!(reason, NOT_AUTHORIZED);
    }
}

#[test]
fn in_relay_mode_the_relays_link_must_be_up() {
    assert!(derp_verdict(&states(&[(LinkKind::Derp(1), LinkState::Connected)]), true).is_ok());
    // Not up yet: no attempt ended, or the last one failed.
    let Err(NodeError::DerpPending { last: None, refused: false }) = derp_verdict(&states(&[]), true) else {
        panic!("ready with no link")
    };
    let Err(NodeError::DerpPending { last, refused: false }) =
        derp_verdict(&states(&[(LinkKind::Derp(1), failed("connection reset", false))]), true)
    else {
        panic!("ready with a failed link")
    };
    assert_eq!(last.as_deref(), Some("connection reset"));
    // Refused, and dialled again while the node waits for its key's admission.
    let Err(NodeError::DerpPending { refused: true, .. }) =
        derp_verdict(&states(&[(LinkKind::Derp(1), failed(NOT_AUTHORIZED, true))]), true)
    else {
        panic!("not a pending refusal")
    };
}

#[test]
fn in_tcp_mode_a_down_derp_link_does_not_stop_the_start() {
    assert!(derp_verdict(&states(&[]), false).is_ok());
    assert!(derp_verdict(&states(&[(LinkKind::Derp(3), failed("timed out", false))]), false).is_ok());
}
