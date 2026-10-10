//! The lines that `podssh ts` writes when a link of the node changes (T-104): a drop with the
//! wait before the next attempt, a link back after a drop, a refusal of the node key; nothing for
//! a first connection, and a far end's words made safe for a terminal.
#![cfg(feature = "ts")]

use std::time::Duration;

use podssh_cli::ts::links::link_line;
use podssh_ts::node::{LinkChange, LinkEvent, LinkKind};

fn line(link: LinkKind, change: LinkChange) -> Option<String> {
    link_line(&LinkEvent { link, change })
}

#[test]
fn a_first_connection_says_nothing_and_a_return_says_so() {
    assert_eq!(line(LinkKind::Control, LinkChange::Connected { again: false }), None);
    assert_eq!(line(LinkKind::Derp(1), LinkChange::Connected { again: false }), None);
    assert_eq!(
        line(LinkKind::Derp(1), LinkChange::Connected { again: true }).as_deref(),
        Some("podssh ts: the DERP link of region 1 is up again.")
    );
    assert_eq!(
        line(LinkKind::Control, LinkChange::Connected { again: true }).as_deref(),
        Some("podssh ts: the connection to the control server is up again.")
    );
}

#[test]
fn a_drop_says_why_and_when_the_next_attempt_comes() {
    let dropped = LinkChange::Dropped {
        reason: "connection reset".into(),
        retry_in: Duration::from_millis(1340),
        refused: false,
    };
    assert_eq!(
        line(LinkKind::Control, dropped).as_deref(),
        Some("podssh ts: the connection to the control server dropped (connection reset); trying again in 1.3 s.")
    );
}

#[test]
fn a_refusal_says_that_no_attempt_follows_and_quotes_the_relay_safely() {
    let refused =
        LinkChange::Refused { reason: "websocket closed: code=1008 reason=\"not\u{1b}[31m authorized\"".into() };
    let text = line(LinkKind::Derp(7), refused).expect("a line");
    assert!(text.starts_with("podssh ts: the DERP link of region 7 was refused ("), "{text}");
    assert!(text.contains("not dialled again"), "{text}");
    assert!(!text.contains('\u{1b}'), "an escape reached the terminal: {text:?}");
}
