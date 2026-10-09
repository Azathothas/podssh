//! Which closes of a link the resumable layer carries a session past
//! (T-153): each row of the relay's close table, and closes that match none.
#![cfg(feature = "pair")]

use podssh_relay::reverse::closes::{resumes, CLOSE_ROWS};
use podssh_relay::reverse::RelayClose;

fn close(code: u16, reason: &str) -> RelayClose {
    RelayClose { code, reason: reason.to_string(), clean: true }
}

/// Resume after a lost socket, a node that went away or was slow, and the
/// relay's own limits; stop on both `1001` rows and on each fault of
/// podssh's own bytes.
const EXPECTED: &[(u16, &str, bool)] = &[
    (1001, "operator stopped reverse relay", false),
    (1001, "pair expired", false),
    (1003, "unknown session id", false),
    (1003, "invalid control json", false),
    (1003, "invalid session id", false),
    (1003, "unknown control type", false),
    (1003, "bad multiplex id", false),
    (1003, "data before ready", false),
    (1003, "binary frames required", false),
    (1008, "unknown role", true),
    (1008, "wait for ready", false),
    (1009, "control frame byte cap", false),
    (1009, "bad multiplex frame", false),
    (1009, "session byte cap", true),
    (1009, "frame byte cap", false),
    (1011, "relay backpressure", true),
    (1011, "node unavailable", true),
    (1011, "node offline", true),
    (1011, "node disconnected", true),
    (1011, "socket error", true),
    (1013, "node open timeout", true),
    (1013, "reverse message rate cap", true),
    (1000, "node-supplied", true),
    (1011, "node-supplied", true),
    (1000, "session ended", true),
];

#[test]
fn each_row_of_the_table_resumes_or_stops() {
    for row in CLOSE_ROWS {
        let expected = EXPECTED
            .iter()
            .find(|(code, reason, _)| *code == row.code && *reason == row.reason)
            .unwrap_or_else(|| panic!("no expectation for {} {}", row.code, row.reason));
        assert_eq!(resumes(&close(row.code, row.reason)), expected.2, "{} {}", row.code, row.reason);
    }
    assert_eq!(EXPECTED.len(), CLOSE_ROWS.len(), "an expectation for a row that the table no longer has");
}

/// A planted policy that resumed after an expired pair would loop until the
/// deadline on a close that comes again each time.
#[test]
fn an_expired_pair_and_a_stop_are_never_resumed() {
    assert!(!resumes(&close(1001, "pair expired")));
    assert!(!resumes(&close(1001, "Operator stopped reverse relay ")));
}

#[test]
fn closes_that_match_no_row_resume_unless_they_name_a_fault() {
    for (code, reason, expected) in [
        (1006, "", true),
        (1011, "something new", true),
        (1012, "service restart", true),
        (1013, "try again later", true),
        (1001, "going away", false),
        (1002, "protocol error", false),
        (1007, "bad data", false),
        (1010, "extension", false),
        (4001, "custom", false),
    ] {
        assert_eq!(resumes(&close(code, reason)), expected, "{code} {reason}");
    }
}
