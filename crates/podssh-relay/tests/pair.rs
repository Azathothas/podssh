//! Pairs of the reverse road (feature `pair`, T-078), offline. The answer has
//! the shape that the live relay gave on 2026-10-09 (each token 64 characters
//! of `[0-9a-z]`, the name 34 of `[-0-9a-z]`, `expires` in milliseconds),
//! with test strings in place of the tokens.
#![cfg(feature = "pair")]

use std::path::PathBuf;

use podssh_relay::pair::{self, PairError};
use podssh_relay::relay::Relay;

const NAME: &str = "podssh-test-pair-0123456789abcdef0";
const NODE: &str = "testonlynode0000000000000000000000000000000000000000000000000000";
const CONNECT: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";
const STOP: &str = "testonlystop0000000000000000000000000000000000000000000000000000";
const NOW: i64 = 1_791_500_000_000;
const HOURS_72: i64 = 72 * 3600 * 1000;

fn relay() -> Relay {
    Relay { host: "tcp.ssh.relay.ajam.dev".into(), port: 443 }
}

fn body(name: &str, node: &str, expires: i64) -> Vec<u8> {
    format!(
        r#"{{"name":"{name}","node_token":"{node}","connect_token":"{CONNECT}","stop_token":"{STOP}","expires":{expires}}}"#
    )
    .into_bytes()
}

fn good() -> pair::Pair {
    pair::parse(&relay(), &body(NAME, NODE, NOW + HOURS_72), NOW).expect("a pair")
}

/// No token, in any text of a pair or of its errors.
fn no_token(text: &str) {
    for token in [NODE, CONNECT, STOP] {
        assert!(!text.contains(token), "a token is in {text:?}");
    }
}

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-pair-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_tokens_were_test_strings_of_the_measured_shape() {
    for token in [NODE, CONNECT, STOP] {
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
    }
    assert_eq!(NAME.len(), 34);
}

#[test]
fn an_answer_of_the_relay_is_read() {
    let pair = good();
    assert_eq!((pair.name.as_str(), pair.expires_ms), (NAME, NOW + HOURS_72));
    assert_eq!((pair.node_token(), pair.connect_token(), pair.stop_token()), (NODE, CONNECT, STOP));
    assert_eq!(pair.relay, relay());
}

#[test]
fn an_answer_that_is_not_a_usable_pair_is_refused() {
    let cases: Vec<Vec<u8>> = vec![
        body("../etc", NODE, NOW + HOURS_72),
        body("a/b", NODE, NOW + HOURS_72),
        body("-x", NODE, NOW + HOURS_72),
        body(NAME, "has space in it, not a token", NOW + HOURS_72),
        body(NAME, "short", NOW + HOURS_72),
        br#"{"name":"x"}"#.to_vec(),
        b"not json".to_vec(),
    ];
    for case in cases {
        let error = pair::parse(&relay(), &case, NOW).expect_err(&String::from_utf8_lossy(&case));
        assert!(matches!(error, PairError::BadAnswer(_)), "{error:?}");
        no_token(&format!("{error} {error:?}"));
    }
}

#[test]
fn a_pair_with_less_than_ten_minutes_left_is_refused() {
    let error = pair::parse(&relay(), &body(NAME, NODE, NOW + 9 * 60 * 1000), NOW).expect_err("9 minutes");
    assert!(matches!(error, PairError::ShortLived { .. }), "{error:?}");
    assert!(pair::parse(&relay(), &body(NAME, NODE, NOW + 11 * 60 * 1000), NOW).is_ok(), "11 minutes");
}

#[test]
fn no_token_is_in_debug_or_in_an_error() {
    let pair = good();
    let debug = format!("{pair:?}");
    no_token(&debug);
    assert!(debug.contains(NAME) && debug.contains("<redacted>"), "{debug}");
    for error in [PairError::Forbidden, PairError::NotIssued { detail: String::new() }, PairError::BadAnswer("x"), PairError::ShortLived { left_ms: 1 }] {
        no_token(&format!("{error} {error:?}"));
    }
}

#[test]
fn a_pair_is_kept_in_a_private_file_under_its_label() {
    let dir = scratch("store");
    let dirs = vec![dir.clone()];
    let path = pair::store_in_first(&dirs, "lab", &good()).expect("stored");
    assert_eq!(path.file_name().unwrap(), "pair-lab.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let back = pair::load_from(&dirs, "lab").expect("readable").expect("stored");
    assert_eq!((back.node_token(), back.connect_token(), back.stop_token()), (NODE, CONNECT, STOP));
    assert_eq!((back.name.as_str(), back.expires_ms, &back.relay), (NAME, NOW + HOURS_72, &relay()));
    assert!(matches!(pair::store_in_first(&dirs, "../x", &good()), Err(PairError::BadLabel(_))));
    pair::remove_from(&dirs, "lab").unwrap();
    assert!(pair::load_from(&dirs, "lab").unwrap().is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_operator_file_is_new_private_and_has_the_connect_token_only() {
    let dir = scratch("operator");
    let path = dir.join("operator.json");
    pair::write_operator_file(&path, &good()).expect("written");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(CONNECT) && text.contains(NAME), "{text}");
    assert!(!text.contains(NODE) && !text.contains(STOP), "only the operator's part: {text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let again = pair::write_operator_file(&path, &good()).expect_err("an existing file is never replaced");
    assert_eq!(again.kind(), std::io::ErrorKind::AlreadyExists);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_pair_file_is_read_when_it_is_private() {
    let dir = scratch("file");
    let dirs = vec![dir.clone()];
    let path = pair::store_in_first(&dirs, "lab", &good()).expect("stored");
    let back = pair::read_file(&path).expect("a private pair file");
    assert_eq!((back.node_token(), back.connect_token(), back.stop_token()), (NODE, CONNECT, STOP));
    assert_eq!((back.name.as_str(), back.expires_ms), (NAME, NOW + HOURS_72));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let open = pair::read_file(&path).expect_err("others can read it");
        assert!(open.to_string().contains("chmod 600"), "{open}");
        no_token(&format!("{open} {open:?}"));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_file_that_is_not_a_pair_is_refused_with_what_it_is() {
    let dir = scratch("notpair");
    let operator = dir.join("operator.json");
    pair::write_operator_file(&operator, &good()).unwrap();
    let error = pair::read_file(&operator).expect_err("no node token");
    assert!(error.to_string().contains("operator's part"), "{error}");
    no_token(&format!("{error} {error:?}"));
    let junk = dir.join("junk.json");
    std::fs::write(&junk, b"not json").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(pair::read_file(&junk).expect_err("junk").to_string().contains("not readable"));
    assert!(pair::read_file(&dir.join("missing.json")).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_labels_of_the_store_are_listed_in_order() {
    let dir = scratch("labels");
    let dirs = vec![dir.clone()];
    for label in ["lab", "alpha"] {
        pair::store_in_first(&dirs, label, &good()).unwrap();
    }
    std::fs::write(dir.join("relay-token-example.json"), b"{}").unwrap();
    assert_eq!(pair::labels_from(&dirs), vec!["alpha".to_string(), "lab".to_string()]);
    pair::remove_from(&dirs, "alpha").unwrap();
    assert_eq!(pair::labels_from(&dirs), vec!["lab".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_operator_part_is_read_from_its_file_or_from_a_whole_pair() {
    let dir = scratch("operator-part");
    let operator = dir.join("operator.json");
    pair::write_operator_file(&operator, &good()).unwrap();
    let whole = pair::store_in_first(&[dir.clone()], "lab", &good()).unwrap();
    for path in [&operator, &whole] {
        let part = pair::read_operator_file(path).expect("an operator's part");
        assert_eq!((part.name.as_str(), part.connect_token(), part.expires_ms), (NAME, CONNECT, NOW + HOURS_72));
        assert_eq!(part.relay, relay());
        no_token(&format!("{part:?}"));
    }
    let junk = dir.join("junk.json");
    std::fs::write(&junk, br#"{"name":"x"}"#).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let error = pair::read_operator_file(&junk).expect_err("no operator's part");
    assert!(error.to_string().contains("no operator's part"), "{error}");
    let part = pair::OperatorPart::of(&good());
    assert_eq!(part.connect_token(), CONNECT);
    std::fs::remove_dir_all(&dir).unwrap();
}
