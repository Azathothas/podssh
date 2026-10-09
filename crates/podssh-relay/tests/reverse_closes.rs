//! Each close of the relay's table, and the retry that each one allows. Each
//! row is checked against the pinned copy of the relay's document
//! (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`): a line
//! number that only agrees with itself was once wrong by two for every row.
#![cfg(feature = "pair")]

use podssh_relay::reverse::closes::{classify, Classified, Leg, Retry, SessionAction, CLOSE_ROWS};
use podssh_relay::reverse::RelayClose;

/// The document that the `spec_line` values are read from, the file that
/// podssh-probe checks its facts against; included, not copied, so that a
/// second copy cannot drift. When the relay changes, the pin changes, and this
/// test goes red rather than stale.
const SPEC_COPY: &str = include_str!("../../podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt");

/// A close as the relay sends it.
fn closed(code: u16, reason: &str) -> RelayClose {
    RelayClose { code, reason: reason.to_string(), clean: true }
}

#[test]
fn the_table_has_twenty_four_rows_and_one_per_published_line() {
    assert_eq!(
        CLOSE_ROWS.len(),
        25,
        "24 rows are published and 25 are in Rust: one row has the codes 1000 and 1011, and each \
         code needs its own entry, or a `reject` would read as a `close`"
    );
    let mut lines: Vec<u16> = CLOSE_ROWS.iter().map(|r| r.spec_line).collect();
    lines.sort_unstable();
    lines.dedup();
    // Each published line has a row, with no gap and no line invented; the
    // row of two codes has two.
    assert_eq!(lines.len(), 24, "every line from 170 to 193 carries a row");
    assert_eq!(*lines.first().unwrap(), 170);
    assert_eq!(*lines.last().unwrap(), 193);
    assert_eq!(lines, (170..=193).collect::<Vec<u16>>(), "no line skipped, no line invented");
    assert_eq!(CLOSE_ROWS.iter().filter(|r| r.spec_line == 192).count(), 2);

    // Each citation holds the row that it names: a run of numbers shifted by
    // two is as unbroken as the right one.
    let document: Vec<&str> = SPEC_COPY.split('\n').collect();
    for row in CLOSE_ROWS {
        let line = document
            .get((row.spec_line - 1) as usize)
            .unwrap_or_else(|| panic!("spec line {} is past the document", row.spec_line));
        assert!(
            line.to_lowercase().contains(row.reason),
            "spec line {} does not carry {:?}: {}",
            row.spec_line,
            row.reason,
            line.trim()
        );
    }
}

#[test]
fn every_row_matches_the_operators_own_action_column() {
    // The actions are what podssh runs: each is checked, not implied.
    for row in CLOSE_ROWS {
        assert!(
            !row.reason.is_empty() && row.reason.chars().all(|c| c.is_ascii_lowercase() || c == ' ' || c == '-'),
            "row on spec line {} has an unmatchable reason {:?}",
            row.spec_line,
            row.reason
        );
        assert!(!row.action.explain().is_empty(), "spec line {} has no explanation", row.spec_line);
        let classified = classify(&closed(row.code, row.reason));
        assert_eq!(classified.row, Some(*row), "spec line {} must classify back to itself", row.spec_line);
        assert_eq!(classified.session, row.action);
    }
}

#[test]
fn a_1001_is_never_retried_and_the_two_rows_are_never_confused() {
    // Two rows of 1001: a stop (never retry the name) and an expiry (make a
    // new pair). A client that read the code alone would make a new pair after
    // a deliberate revocation.
    let revoked = classify(&closed(1001, "operator stopped reverse relay"));
    assert_eq!(revoked.session, SessionAction::Stop);
    assert_eq!(revoked.retry, Retry::Never);

    let expired = classify(&closed(1001, "pair expired"));
    assert_eq!(expired.session, SessionAction::MintNewPair);
    assert_eq!(expired.retry, Retry::NewPair);
    assert_ne!(revoked.row, expired.row);

    // An empty reason on this code matches no row: no guess between the two.
    let blank = classify(&closed(1001, ""));
    assert_eq!(blank.row, None, "a guess here would make a new pair after a revocation");
    assert_eq!(blank.retry, Retry::Never);
    assert_eq!(blank.session, SessionAction::Unknown);
}

#[test]
fn a_codec_fault_is_never_retried_because_the_next_attempt_sends_the_same_bytes() {
    // Each is a fault of podssh's own bytes: a reconnection sends the same
    // bytes, and a loop would hide the defect behind a network error.
    let never = [
        (1003u16, "invalid control json"),
        (1003, "invalid session id"),
        (1003, "unknown control type"),
        (1003, "bad multiplex id"),
        (1003, "data before ready"),
        (1003, "binary frames required"),
        (1009, "control frame byte cap"),
        (1009, "bad multiplex frame"),
        (1009, "frame byte cap"),
        (1011, "relay backpressure"),
    ];
    for (code, reason) in never {
        let classified = classify(&closed(code, reason));
        assert_eq!(classified.retry, Retry::Never, "`{reason}` ({code}) must not be retried");
        assert!(!classified.retry.is_retryable());
    }
}

#[test]
fn a_session_byte_cap_means_a_new_session_and_not_a_reconnect() {
    // One session passed 64 MiB: the socket is fine, and a reconnection would
    // throw it away. A stale id and data before `ready` call for a new session
    // too, as their rows say; a reconnection would change nothing.
    let stale_id = classify(&closed(1003, "unknown session id"));
    assert_eq!(stale_id.row.expect("a published row").spec_line, 172);
    assert_eq!(stale_id.retry, Retry::NewSession, "the row says re-open the session");
    let too_early = classify(&closed(1008, "wait for ready"));
    assert_eq!(too_early.row.expect("a published row").spec_line, 180);
    assert_eq!(too_early.retry, Retry::NewSession);

    let classified = classify(&closed(1009, "session byte cap"));
    assert_eq!(classified.session, SessionAction::OpenNewSession);
    assert_eq!(classified.retry, Retry::NewSession);
    assert_ne!(classified.retry, Retry::Reconnect, "the two are different actions");
    assert!(classified.retry.is_retryable());
}

#[test]
fn the_three_1011_operator_rows_tell_themselves_apart_only_by_reason() {
    // Three rows of 1011 that differ in their prose alone, so the table
    // matches on the reason.
    let reasons = ["node unavailable", "node offline", "node disconnected", "socket error"];
    let mut seen = std::collections::HashSet::new();
    for reason in reasons {
        let classified = classify(&closed(1011, reason));
        let row = classified.row.unwrap_or_else(|| panic!("`{reason}` must match a row"));
        assert_eq!(row.code, 1011);
        assert_eq!(row.reason, reason);
        assert!(seen.insert(row.spec_line), "`{reason}` reused a line");
        assert_eq!(classified.retry, Retry::Reconnect, "every 1011 here reconnects");
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn a_node_supplied_close_carries_the_nodes_own_reason_and_the_code_is_not_the_signal() {
    // A node's `close` arrives as 1000 and its `reject` as 1011, each with the
    // node's own reason: parse the reason, not the code.
    let node_close = classify(&closed(1000, "connection refused"));
    assert_eq!(node_close.session, SessionAction::ParseReasonNotCode, "the row carries the node's own reason");
    assert_eq!(node_close.row.expect("the node-supplied row").spec_line, 192);

    let node_reject = classify(&closed(1011, "connection refused"));
    assert_eq!(node_reject.session, SessionAction::ParseReasonNotCode);
    assert_eq!(node_reject.retry, Retry::Never, "a refusal is not a transient failure");

    // Both spellings of the row's reason, and its two codes only: a 1001 with
    // a refusal stays unmatched.
    assert_eq!(classify(&closed(1000, "node-supplied")).row.unwrap().spec_line, 192);
    assert_eq!(classify(&closed(1011, "node-supplied")).row.unwrap().spec_line, 192);
    assert_eq!(classify(&closed(1000, "node supplied")).row.unwrap().spec_line, 192);
    assert_eq!(classify(&closed(1001, "connection refused")).row, None, "1001 is not a code of that row");

    // The reason reaches the message: reading it is the whole instruction.
    let message = classify(&closed(1011, "connection refused")).message();
    assert!(message.contains("1011 connection refused"), "{message}");
}

/// Each message names the code and the reason as received, matched or not,
/// with no control character and within the relay's own cap.
#[test]
fn the_message_names_the_code_and_the_reason() {
    let unmatched = classify(&closed(4000, "x")).message();
    assert!(unmatched.contains("4000 x"), "{unmatched}");
    assert!(unmatched.contains("forward close set is unpublished"), "{unmatched}");
    let refusal = classify(&closed(1011, "connection refused")).message();
    assert!(refusal.contains("1011 connection refused"), "{refusal}");
    assert!(refusal.contains("spec line 192"), "{refusal}");
    let expired = classify(&closed(1001, "pair expired")).message();
    assert!(expired.contains("1001 pair expired"), "{expired}");
    let empty = classify(&closed(1001, "")).message();
    assert!(empty.contains("1001 (no reason)"), "{empty}");

    let noisy = classify(&closed(4001, "a\u{1b}]0;title\u{7}b\r\nc")).message();
    assert!(!noisy.chars().any(char::is_control), "{noisy:?}");
    let long = classify(&closed(4002, &"y".repeat(500))).message();
    assert!(long.contains(&"y".repeat(100)) && !long.contains(&"y".repeat(101)), "{long}");
}

#[test]
fn an_unpublished_close_is_reported_as_unmatched_and_never_forced_into_a_row() {
    // The relay publishes one close table, for the reverse path; a forward
    // close matches nothing, and is not forced into a reverse row.
    let forward_close = classify(&closed(1006, ""));
    assert_eq!(forward_close.row, None);
    assert_eq!(forward_close.session, SessionAction::Unknown);
    assert_eq!(forward_close.retry, Retry::Never);
    assert!(forward_close.message().contains("forward close set is unpublished"));
}

#[test]
fn the_observed_by_column_is_carried_and_the_node_exception_is_recorded() {
    let node_rows = CLOSE_ROWS.iter().filter(|r| r.observed_by == Leg::Node).count();
    let operator_rows = CLOSE_ROWS.iter().filter(|r| r.observed_by == Leg::Operator).count();
    let either_rows = CLOSE_ROWS.iter().filter(|r| r.observed_by == Leg::Either).count();
    assert_eq!(node_rows + operator_rows + either_rows, 25, "25 rows in Rust: one row has two codes");

    // A close that the relay makes on the node's socket for cause reaches the
    // operator's sessions too, so a row of the node can land on the operator.
    let data_before_ready = classify(&closed(1003, "data before ready"));
    assert_eq!(data_before_ready.row.unwrap().observed_by, Leg::Node);
    assert_eq!(data_before_ready.row.unwrap().spec_line, 177);
    assert!(
        data_before_ready.message().contains("possibly forwarded"),
        "the message says the node row can land on the operator too"
    );
}

#[test]
fn a_clean_close_and_an_abrupt_one_are_different_facts() {
    // `1006` is no close the relay sent, but the absence of one: `clean` tells
    // "the relay said goodbye" from "the socket went away".
    let clean: Classified = classify(&RelayClose { code: 1000, reason: "session ended".into(), clean: true });
    assert_eq!(clean.session, SessionAction::NormalEnd);
    let abrupt = RelayClose { code: 1006, reason: String::new(), clean: false };
    assert_eq!(classify(&abrupt).session, SessionAction::Unknown);
}
