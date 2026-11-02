//! `--idle-warn SECONDS` (T-463), a module of `tests/ssh_args.rs`, whose own
//! file is near 500 lines: the lead of the warning before the relay's idle
//! cut, as typed, once, a whole number of seconds, and 0 for none.

use std::time::Duration;

use podssh_cli::ssh::idle_warn::lead_of;
use podssh_cli::tree::{parse, Parsed};

use super::ssh;

/// The value reaches the run as typed, before or after the host.
#[test]
fn idle_warn_takes_its_seconds_as_typed() {
    assert_eq!(ssh(&["--idle-warn", "45", "host"]).idle_warn.as_deref(), Some("45"));
    assert_eq!(ssh(&["host", "--idle-warn", "0"]).idle_warn.as_deref(), Some("0"));
    assert_eq!(ssh(&["host"]).idle_warn, None);
}

/// Whole seconds; 0 turns the warning off; a time with a unit is refused,
/// with the remedy.
#[test]
fn idle_warn_is_whole_seconds_and_0_is_none() {
    assert_eq!(lead_of(Some("45")), Ok(Some(Duration::from_secs(45))));
    assert_eq!(lead_of(Some("0")), Ok(Some(Duration::ZERO)));
    assert_eq!(lead_of(None), Ok(None));
    let why = lead_of(Some("30s")).unwrap_err();
    assert!(why.starts_with("--idle-warn \"30s\": give a whole number of seconds"), "{why}");
}

/// Given twice, it is refused, as each flag of one value is.
#[test]
fn idle_warn_is_given_once() {
    match parse(vec!["ssh", "--idle-warn", "10", "--idle-warn", "20", "host"]) {
        Parsed::Usage(m) => assert!(m.contains("--idle-warn was given 2 times"), "{m}"),
        other => panic!("not refused: {other:?}"),
    }
}
