//! An iroh destination in a build without the feature `iroh` (T-162): each
//! form is refused before anything connects, with exit 70, an empty stdout
//! and a message that names the feature to build with.
#![cfg(not(feature = "iroh"))]

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
fn each_iroh_destination_refuses_and_names_the_feature() {
    for argv in
        [&["ssh", "iroh:endpointabc"][..], &["ssh", "user@iroh:endpointabc", "true"][..], &["ssh", "-v", "iroh:x"][..]]
    {
        let (rc, out, err) = run_case(argv);
        assert_eq!(rc, EXIT_NOT_IMPLEMENTED, "{argv:?}: stderr was {err}");
        assert!(out.is_empty(), "{argv:?}: stdout must stay empty, got {out:?}");
        assert!(err.contains("--features iroh"), "{argv:?}: stderr was {err}");
    }
}

#[test]
fn a_host_named_iroh_is_still_a_host() {
    // `iroh` with no colon is a host name, as `node` is.
    assert!(!podssh_cli::ssh::iroh::is_iroh("iroh"));
    assert!(!podssh_cli::ssh::iroh::is_iroh("user@iroh.example.org"));
    assert!(podssh_cli::ssh::iroh::is_iroh("iroh:abc"));
}
