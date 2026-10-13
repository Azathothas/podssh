//! The tests of the hook of `PODSSH_ERROR_PROGRAM` (T-195) that need no
//! program: when a run is a failure, what a report holds, and the lines of
//! stderr that it keeps. `tests/error_program.rs` runs the binary.

use super::report::{mask, object, secrets, HIDDEN};
use super::*;

const TOKEN: &str = "podssh-test-token-0123456789abcdef";
const PROXY: &str = "http://alice:s3cr3t-pass@proxy.example:3128";

fn env(name: &str) -> Option<String> {
    match name {
        "PODSSH_RELAY_TOKEN" => Some(TOKEN.to_string()),
        "https_proxy" => Some(PROXY.to_string()),
        _ => None,
    }
}

/// A failure of podssh is each code but 0, a status passed on, and a stop
/// that the user asked for.
#[test]
fn only_a_failure_of_podssh_is_one() {
    for code in [1, 64, 66, 69, 70, 73, 75, 77, 78, 255] {
        assert!(failed(code, false), "{code}");
    }
    assert!(!failed(0, false));
    // A remote `exit 3`, or a remote 255, is the remote command's.
    assert!(!failed(3, true));
    assert!(!failed(255, true));
    assert!(!failed(130, false) && !failed(143, false));
}

/// Neither the token nor the proxy's user and password reach a message,
/// whatever the message holds; the proxy's URL does not either.
#[test]
fn a_message_never_holds_a_credential() {
    let secrets = secrets(env);
    let line = format!("podssh proxy: {TOKEN} through {PROXY}; alice; s3cr3t-pass; alice:s3cr3t-pass@proxy");
    let masked = mask(&line, &secrets);
    for secret in [TOKEN, "s3cr3t", "alice", PROXY] {
        assert!(!masked.contains(secret), "{secret}: {masked}");
    }
    assert!(masked.starts_with("podssh proxy: "), "{masked}");
    assert!(masked.contains(HIDDEN), "{masked}");
}

/// A URL that no variable names still loses its user and password; one
/// with neither stays as it is.
#[test]
fn each_url_loses_its_user_and_password() {
    let masked = mask("could not reach socks5h://bob:hunter22@p.example:1080/x, then https://relay.example/v1", &[]);
    assert_eq!(masked, format!("could not reach socks5h://{HIDDEN}@p.example:1080/x, then https://relay.example/v1"));
    assert_eq!(mask("podssh ssh: u@host.example: refused", &[]), "podssh ssh: u@host.example: refused");
}

/// The controls of a terminal never reach the program, as in doctor's lines.
#[test]
fn a_message_has_no_terminal_controls() {
    assert_eq!(mask("evil\u{1b}[2Jtext\r\nmore", &[]), "evil[2Jtext more");
}

/// A value too short to be a secret hides nothing, and the longest value
/// is replaced first.
#[test]
fn the_secrets_are_long_enough_and_longest_first() {
    let short = |name: &str| (name == "https_proxy").then(|| "http://a:b@p:1".to_string());
    assert_eq!(secrets(short), ["http://a:b@p:1", "a:b"]);
    let all = secrets(env);
    assert_eq!(all.first().map(String::as_str), Some(PROXY), "{all:?}");
    assert!(all.windows(2).all(|w| w[0].len() >= w[1].len()), "{all:?}");
}

/// The object's form: its fields, the command by its name, and the code.
#[test]
fn the_report_has_its_fields() {
    let said = vec!["podssh ssh: -o NoSuchKeyword: unknown option".to_string()];
    let report = object(Some("ssh"), 64, &said);
    assert_eq!(report["schema"], 1);
    assert_eq!(report["verb"], "ssh");
    assert_eq!(report["exit"], 64);
    assert_eq!(report["os"], std::env::consts::OS);
    assert_eq!(report["podssh"], crate::help::version());
    assert_eq!(report["messages"], serde_json::json!(said));
    let keys: Vec<&String> = report.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 8, "{keys:?}");
}

/// The manual's row names the limit and the bounds that the code uses.
#[test]
fn the_manual_names_the_limit_and_the_bounds() {
    let (_, text) = crate::man::facts::VARIABLES.iter().find(|(names, _)| names.contains(&ENV)).expect("its row");
    assert!(text.contains(&format!("after {} s", LIMIT.as_secs())), "{text}");
    assert!(text.contains(&format!("the last {} lines", podssh_ssh::said::LINES)), "{text}");
    assert!(text.contains(&format!("{} KiB at most", podssh_ssh::said::BYTES / 1024)), "{text}");
}

/// The tee passes each byte on, and keeps each whole line, and the last
/// one at its end.
#[test]
fn the_tee_passes_each_byte_and_keeps_the_lines() {
    podssh_ssh::said::start();
    let mut inner = Vec::new();
    {
        let mut tee = Tee::new(&mut inner);
        let _ = write!(tee, "podssh tee-test: first ");
        let _ = writeln!(tee, "line");
        let _ = write!(tee, "podssh tee-test: no break");
        tee.finish();
    }
    assert_eq!(inner, b"podssh tee-test: first line\npodssh tee-test: no break");
    let lines = podssh_ssh::said::lines();
    for want in ["podssh tee-test: first line", "podssh tee-test: no break"] {
        assert!(lines.iter().any(|l| l == want), "{want}: {lines:?}");
    }
}
