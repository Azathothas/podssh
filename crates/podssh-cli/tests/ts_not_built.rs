//! `podssh ts` in a build without the `ts` feature: it still parses (help and
//! the man page list it), and every form refuses with a non-zero exit, an
//! empty stdout, and a message that names the feature to enable.
#![cfg(not(feature = "ts"))]

use podssh_cli::dispatch::{run, Streams};
use podssh_cli::exit_codes::EXIT_NOT_IMPLEMENTED;
use podssh_cli::tree::parse;

fn run_case(argv: &[&str]) -> (i32, String, String) {
    let p = parse(argv.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    (rc, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

#[test]
fn every_ts_form_refuses_and_names_the_feature() {
    for argv in [
        &["ts", "--timeout", "30s"][..],
        &["tailscale", "--timeout", "30s"][..],
        &["ts", "-W", "peer:22", "--timeout", "30s"][..],
        &["ts"][..],
    ] {
        let (rc, out, err) = run_case(argv);
        assert_eq!(rc, EXIT_NOT_IMPLEMENTED, "{argv:?}: stderr was {err}");
        assert!(out.is_empty(), "{argv:?}: stdout must stay empty, got {out:?}");
        assert!(err.contains("--features ts"), "{argv:?}: stderr was {err}");
    }
}

#[test]
fn ts_still_appears_in_help() {
    let (rc, out, _) = run_case(&["--help"]);
    assert_eq!(rc, 0);
    assert!(out.contains("ts "), "top-level help should still list ts:\n{out}");
}
