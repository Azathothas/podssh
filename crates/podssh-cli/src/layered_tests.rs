//! The tests of `layered`, apart for the length of that file.

use super::*;

const HOUR: i64 = 3_600_000;

#[test]
fn the_warning_comes_an_hour_before_the_expiry() {
    assert_eq!(expiry_wait(10 * HOUR, 0), Some(Duration::from_millis(9 * HOUR as u64)));
    assert_eq!(expiry_wait(HOUR + 1, 1), Some(Duration::ZERO));
}

#[test]
fn less_than_an_hour_left_is_said_at_once() {
    assert_eq!(expiry_wait(HOUR - 1, 0), Some(Duration::ZERO));
    assert_eq!(expiry_wait(5, 4), Some(Duration::ZERO));
}

#[test]
fn a_pair_that_expired_gets_no_warning() {
    assert_eq!(expiry_wait(100, 100), None);
    assert_eq!(expiry_wait(100, 200), None);
    assert_eq!(expiry_wait(i64::MIN, i64::MAX), None);
}

/// `--resume-deadline` (T-306): a whole number and a unit, from 1 minute
/// to the 72 h of a pair's life.
#[test]
fn a_resume_deadline_is_a_time_from_a_minute_to_72_h() {
    let secs = Duration::from_secs;
    assert_eq!(parse_deadline("90"), Ok(secs(90)));
    assert_eq!(parse_deadline("90s"), Ok(secs(90)));
    assert_eq!(parse_deadline("30m"), Ok(secs(1800)));
    assert_eq!(parse_deadline("8h"), Ok(secs(8 * 3600)));
    assert_eq!(parse_deadline("3d"), Ok(secs(72 * 3600)));
    for bad in ["", "h", "8 h", "+8h", "8x", "1.5h", "-1m", "99999999999999999999d"] {
        let why = parse_deadline(bad).unwrap_err();
        assert!(why.contains("a whole number, then s, m, h or d"), "{bad:?}: {why}");
    }
    for out in ["59", "0", "4d", "73h"] {
        let why = parse_deadline(out).unwrap_err();
        assert!(why.contains("from 1 minute to 72 h"), "{out:?}: {why}");
    }
}

/// A session that a signal cut, its `CLOSE` sent, is a clean end of a
/// session that the node took (T-586).
#[test]
fn a_session_cut_after_a_signal_is_a_clean_end() {
    let cut = Carried { why: None, leg: None, channel: None, signalled: true };
    assert_eq!(crate::operator::judged("lab", &cut), None);
    let unended = Carried { why: None, leg: None, channel: None, signalled: false };
    assert!(crate::operator::judged("lab", &unended).is_some(), "with no signal, the relay did not end it in time");
}

/// A halt of the pair's owner (T-647) is final for a new leg, as a refused
/// token is, so that the session ends with the owner's words; a planned
/// stop's `503` is not.
#[test]
fn a_halt_is_final_for_a_new_leg_and_a_restart_is_not() {
    let refused = |status, body: &str| ConnectError::Refused { status, body: body.into() };
    assert!(is_final(&refused(503, "reverse: the pair's owner halted it: a new disk\n")));
    assert!(!is_final(&refused(503, "reverse: relay restarting\n")));
    assert!(!is_final(&refused(503, "reverse: node unavailable\n")));
    assert!(is_final(&refused(403, "reverse: forbidden\n")));
}
