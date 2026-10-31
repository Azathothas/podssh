//! A `warp://` destination in a build without the feature `warp` (T-352):
//! refused before anything connects, with exit 70, an empty stdout and a
//! message that names the feature to build with, by `ssh` and by `proxy`.
#![cfg(not(feature = "warp"))]

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
fn each_warp_destination_refuses_and_names_the_feature() {
    for argv in [&["ssh", "warp://github.com"][..], &["ssh", "-v", "warp://192.0.2.10:2222"][..]] {
        let (rc, out, err) = run_case(argv);
        assert_eq!(rc, EXIT_NOT_IMPLEMENTED, "{argv:?}: stderr was {err}");
        assert!(out.is_empty(), "{argv:?}: stdout must stay empty, got {out:?}");
        assert!(err.contains("--features warp"), "{argv:?}: stderr was {err}");
    }
}

#[test]
fn a_user_inside_the_scheme_refuses_too() {
    let (rc, out, err) = run_case(&["ssh", "warp://git@github.com", "true"]);
    assert_eq!(rc, EXIT_NOT_IMPLEMENTED, "stderr was {err}");
    assert!(out.is_empty() && err.contains("--features warp"), "{err}");
}

#[test]
fn podssh_proxy_refuses_and_names_the_feature() {
    let (rc, out, err) = run_case(&["proxy", "warp://github.com:22"]);
    assert_eq!(rc, EXIT_NOT_IMPLEMENTED, "stderr was {err}");
    assert!(out.is_empty(), "stdout must stay empty, got {out:?}");
    assert!(err.contains("--features warp"), "stderr was {err}");
}

#[test]
fn a_host_named_warp_is_still_a_host() {
    assert!(!podssh_cli::ssh::cloud::warp::is_warp("warp"));
    assert!(!podssh_cli::ssh::cloud::warp::is_warp("warp.example.org"));
    assert!(podssh_cli::ssh::cloud::warp::is_warp("warp://github.com"));
}
