//! The unit tests of dispatch: the whole path, parse to exit code, with no
//! process and no pipe.

use super::*;

/// **Plant 6, as a unit test.** The shell assertion
/// `podssh example.org 2>/dev/null | wc -c` is the acceptance; this is the
/// same claim with both streams captured, so a `println!` on a refusal path
/// fails here as well.
#[test]
fn nothing_but_the_answer_reaches_stdout() {
    let cases: Vec<Vec<&str>> = vec![
        vec![],
        vec!["example.org"],
        vec!["user@example.org"],
        vec!["sttaus"],
        vec!["chatr"],
        vec!["xz"],
        vec!["ssh", "--StrictHostKeyChekcing=no", "host"],
        vec!["ssh", "-w", "0:0", "host"],
        vec!["--bogus"],
        vec!["-Z"],
    ];
    for c in cases {
        let p = crate::tree::parse(c.clone());
        assert!(p.needs_refusal(), "{c:?} should be a refusal");
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_eq!(rc, EXIT_USAGE, "{c:?} exit");
        assert!(out.is_empty(), "{c:?} wrote {} bytes to stdout", out.len());
        assert!(!err.is_empty(), "{c:?} wrote nothing to stderr");
    }
}

#[test]
fn the_refusal_text_goes_where_the_entry_says() {
    let p = crate::tree::parse(vec!["example.org"]);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    assert_eq!(rc, 64);
    let text = String::from_utf8(err).unwrap();
    assert!(text.contains("Try: podssh ssh example.org"), "{text}");
    // `doctor` is ON the printed subcommand list; what must not happen is
    // it being SUGGESTED. The only "Try:" line names ssh.
    let tries: Vec<&str> = text.lines().filter(|l| l.starts_with("Try:")).collect();
    assert_eq!(tries, vec!["Try: podssh ssh example.org"], "{text}");
}

#[test]
fn help_and_version_do_go_to_stdout() {
    for c in [vec!["--help"], vec!["ssh", "--help"], vec!["--version"]] {
        let p = crate::tree::parse(c.clone());
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_eq!(rc, 0, "{c:?}");
        assert!(!out.is_empty(), "{c:?} printed nothing to stdout");
    }
}

/// `chat` with nothing: in a pipe, the gate asks for `--timeout` first,
/// and a refusal never exits 0 nor writes to stdout.
#[test]
fn chat_with_nothing_refuses_and_is_not_zero() {
    let p = crate::tree::parse(vec!["chat"]);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    assert_eq!(rc, EXIT_USAGE);
    assert!(out.is_empty());
    assert!(String::from_utf8(err).unwrap().contains("--timeout"));
}

/// `-P` on ssh is the Tag of `Match tagged` (T-045): a tag that is a number
/// gets a note that `-p` is the port, and another tag none.
#[test]
fn minus_p_on_ssh_with_a_number_prints_a_notice() {
    for (tag, noted) in [("22", true), ("mytag", false)] {
        // A destination the relay cannot take: ssh stops before any network.
        let p = crate::tree::parse(vec!["ssh", "-P", tag, "invalid!host"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_ne!(rc, 0);
        let text = String::from_utf8(err).unwrap();
        assert_eq!(text.contains(&format!("-P {tag} is a Tag")), noted, "{text}");
        assert_eq!(text.contains("For a port use -p"), noted, "{text}");
    }
}

#[test]
fn a_refused_flag_names_its_replacement_on_stderr() {
    let p = crate::tree::parse(vec!["ssh", "-w", "0:0", "host"]);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    assert_eq!(rc, 64);
    let text = String::from_utf8(err).unwrap();
    assert!(text.contains("-w"), "{text}");
    assert!(text.contains("-W HOST:PORT"), "{text}");
    assert!(!text.contains("Usage:"), "no usage header: {text}");
    assert!(!text.contains("For more information"), "no clap trailer: {text}");
}

/// `man` is dispatched, not refused: with no terminal it writes the
/// whole manual to stdout and exits 0.
#[test]
fn man_writes_the_page_to_stdout_and_exits_zero() {
    let p = crate::tree::parse(vec!["man"]);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    // `run` and not `run_with`: the test entry point has no terminal, so
    // this can never page and never block.
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    assert_eq!(rc, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert_eq!(String::from_utf8(out).unwrap(), crate::man::page());
    assert!(err.is_empty(), "{:?}", String::from_utf8_lossy(&err));
}

/// The control for the refusal path: an unknown man section is a usage
/// error at exit **64**, with nothing on stdout.
#[test]
fn an_unknown_man_section_is_a_usage_error() {
    let p = crate::tree::parse(vec!["man", "nonsense"]);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    assert_eq!(rc, EXIT_USAGE);
    assert!(out.is_empty());
    assert!(String::from_utf8(err).unwrap().contains("nonsense"));
}

/// **The `--timeout` gate's check, as a unit test.** `run` uses `Tty::none`, which
/// is a pipe: `chat --send` with no `--timeout` would wait with nobody
/// there to stop it, so it is a usage error that names the verb and an
/// example of it.
#[test]
fn chat_without_timeout_in_a_pipe_is_refused_by_the_gate() {
    let p = crate::tree::parse(vec!["chat", "--send", "hi", "peer"]);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    let err = String::from_utf8(err).unwrap();
    assert_eq!(rc, EXIT_USAGE, "{err}");
    assert!(out.is_empty(), "a refusal writes nothing to stdout");
    assert!(err.starts_with("podssh chat: --timeout DURATION is required when"), "{err}");
    assert!(err.contains("Example: podssh chat --timeout 60s --send MESSAGE NAME"), "{err}");
}

/// The gate's message names its verb, one true reason, and an example of
/// that verb; no internal name and no other verb (GitHub #6).
#[test]
fn the_timeout_refusal_names_the_verb() {
    use crate::non_interactive::{require_timeout, Attachment};
    let m = require_timeout("ts", Attachment::Pipe, None).unwrap_err().message;
    assert!(m.starts_with("podssh ts: --timeout DURATION is required when stdin or stdout is not a terminal"), "{m}");
    assert!(m.contains("Example: podssh ts --timeout 30s -W HOST:PORT"), "{m}");
    assert!(!m.contains("chat") && !m.contains("Pipe") && !m.contains("hangs for ever"), "{m}");
    let m = require_timeout("ts", Attachment::Forced, None).unwrap_err().message;
    assert!(m.contains("when --jsonl was given"), "{m}");
}

/// A valid `--timeout` passes the gate, and `chat` itself says what its
/// command line lacks: here, the peer.
#[test]
fn chat_with_a_valid_timeout_passes_the_gate() {
    let p = crate::tree::parse(vec!["chat", "--send", "hi", "--timeout", "30s"]);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    let err = String::from_utf8(err).unwrap();
    assert_eq!(rc, EXIT_USAGE, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("missing PEER") && !err.contains("is required when"), "{err}");
}

/// `30x` is rejected at the gate, before anything is attempted.
#[test]
fn chat_with_a_garbage_timeout_is_usage_64_immediately() {
    let p = crate::tree::parse(vec!["chat", "--send", "hi", "--timeout", "30x", "peer"]);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    assert_eq!(rc, 64);
    assert!(String::from_utf8(err).unwrap().contains("--timeout"));
}

/// **Enforcement follows the flag's existence.** `ssh` has no
/// `--timeout` row, so a piped `ssh` run reaches ssh itself (here it stops
/// on a destination the relay cannot take, before any network) — the
/// gate must not invent a requirement the tree cannot satisfy.
#[test]
fn ssh_without_a_timeout_row_is_unaffected_by_the_gate() {
    let p = crate::tree::parse(vec!["ssh", "-l", "test", "invalid!host", "--", "true"]);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    let text = String::from_utf8(err).unwrap();
    assert_eq!(rc, EXIT_USAGE, "{text}");
    assert!(text.contains("invalid!host"), "ssh itself refused the destination: {text}");
    assert!(!text.contains("--timeout"), "the timeout gate must not apply to ssh: {text}");
}

/// The run's funnel with a retired name set (T-634), on the row of the
/// tests: `chat` stops with 78 before its own gate says a word, and stdout
/// stays empty.
#[test]
fn a_retired_variable_stops_the_run_before_anything_is_attempted() {
    use crate::retired::tests::{vars, ROW};
    let p = crate::tree::parse(vec!["chat"]);
    let (mut out, mut err): (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
    let set = vars(&[(ROW.name, "yes")]);
    let rc = run_unless_retired(&p, &mut Streams { out: &mut out, err: &mut err }, Tty::none(), &[ROW], &set);
    let text = String::from_utf8(err).unwrap();
    assert_eq!(rc, 78, "{text}");
    assert!(out.is_empty(), "{} bytes on stdout", out.len());
    assert!(text.starts_with("podssh: PODSSH_RETIRED_FOR_TESTS is no longer read"), "{text}");
    assert!(text.contains("use PODSSH_RELAY instead; remove it"), "{text}");
    assert!(!text.contains("--timeout"), "chat's own gate ran: {text}");
}

/// What only prints answers with a retired name set (T-634).
#[test]
fn a_retired_variable_does_not_stop_podssh_version() {
    use crate::retired::tests::{vars, ROW};
    let set = vars(&[(ROW.name, "yes")]);
    for c in [vec!["--version"], vec!["--help"], vec!["man", "environment", "--no-pager"]] {
        let p = crate::tree::parse(c.clone());
        let (mut out, mut err): (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
        let rc = run_unless_retired(&p, &mut Streams { out: &mut out, err: &mut err }, Tty::none(), &[ROW], &set);
        assert_eq!(rc, 0, "{c:?}: {}", String::from_utf8_lossy(&err));
        assert!(!out.is_empty() && err.is_empty(), "{c:?}");
    }
}

/// With no retired name set, or one set empty, or only an unknown name,
/// the run is as before: `chat`'s gate asks for `--timeout` (T-634).
#[test]
fn with_no_retired_variable_set_the_run_is_as_before() {
    use crate::retired::tests::{vars, ROW};
    let cases = [vars(&[]), vars(&[(ROW.name, "")]), vars(&[("PODSSH_NO_SUCH_THING", "1")])];
    for set in cases {
        let p = crate::tree::parse(vec!["chat"]);
        let (mut out, mut err): (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
        let rc = run_unless_retired(&p, &mut Streams { out: &mut out, err: &mut err }, Tty::none(), &[ROW], &set);
        let text = String::from_utf8(err).unwrap();
        assert_eq!(rc, EXIT_USAGE, "{set:?}: {text}");
        assert!(text.contains("--timeout") && !text.contains("no longer read"), "{set:?}: {text}");
        assert!(out.is_empty());
    }
}
