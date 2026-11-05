//! The tests of `relay serve`'s own parts, apart from it so that each file
//! stays within 500 lines.

use super::*;

// T-629: the drop comes once, after the bind, on a listener that is
// bound; a bind that fails drops nothing; a drop that fails refuses the
// start and its words reach the first line.
#[test]
fn the_drop_happens_once_and_only_after_the_bind() {
    let mut seen = Vec::new();
    let (listener, words) = bind_then_drop("127.0.0.1:0", |bound| {
        seen.push(bound.local_addr().map(|a| a.port() != 0).unwrap_or(false));
        Ok(Some(", dropped".into()))
    })
    .unwrap();
    assert_eq!(seen, [true], "one drop, on a bound listener");
    assert_eq!(words.as_deref(), Some(", dropped"));
    let taken = listener.local_addr().unwrap().to_string();
    let mut called = false;
    let refused = bind_then_drop(&taken, |_| {
        called = true;
        Ok(None)
    })
    .unwrap_err();
    assert_eq!(refused.code, EX_UNAVAILABLE, "{refused:?}");
    assert!(!called, "a bind that failed dropped nothing");
    let refused = bind_then_drop("127.0.0.1:0", |_| Err(Refusal::config("capset after the bind: no"))).unwrap_err();
    assert_eq!((refused.code, refused.message.as_str()), (EX_CONFIG, "capset after the bind: no"));
}

// T-635: the ranges of --routes, strictly, never with --allow-private,
// and named in the first line.
#[test]
fn the_routes_are_read_strictly_and_never_beside_allow_private() {
    assert_eq!(routes_of(None, true), Ok(Vec::new()));
    let routes = routes_of(Some("10.4.0.9, 10.4.1.0/24"), false).unwrap();
    assert_eq!(inside_shown(false, &routes), ", the private targets in 10.4.0.9, 10.4.1.0/24 too");
    assert_eq!(inside_shown(false, &[]), "");
    assert_eq!(inside_shown(true, &[]), ", private targets too");
    let wide = routes_of(Some("10.0.0.5/8"), false).unwrap_err();
    assert_eq!(wide.code, crate::exit_codes::EXIT_USAGE);
    assert!(wide.message.starts_with("--routes 10.0.0.5/8: ") && wide.message.contains("10.0.0.0/8"), "{wide}");
    let both = routes_of(Some("10.4.0.9"), true).unwrap_err();
    assert!(both.code == crate::exit_codes::EXIT_USAGE && both.message.contains("--allow-private"), "{both}");
}
