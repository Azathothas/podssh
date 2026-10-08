//! ⛔ **E33's audit table as tests, against the public API.**
//!
//! These exercise `podssh_cli::non_interactive` the way a caller does —
//! [`resolve`], [`parse_timeout`], [`require_timeout`], [`gate_prompt`] —
//! rather than the module's internals, so a refactor that keeps the contract
//! keeps the suite. The plants are named where they live: plant 4 (`30x`),
//! plants 1 and 3 (implicit detection, unconditional TOFU).

use std::time::Duration;

use podssh_cli::exitmap::Fault;
use podssh_cli::non_interactive::{
    force_interactive, gate_prompt, parse_timeout, refuse_jsonl_in_proxy, require_timeout,
    resolve, Attachment, PromptSite,
};

/// ⛔ **Both fds, not stdin alone.** `podssh chat '#c' < /dev/null >
/// log.txt` must not become an interactive client holding a device nobody
/// holds — stdin a terminal while stdout is a file is where a prompt lands
/// in a script's output.
#[test]
fn terminal_needs_both_fds() {
    assert_eq!(resolve(true, true, false), Attachment::Terminal);
    assert_eq!(resolve(true, false, false), Attachment::Pipe);
    assert_eq!(resolve(false, true, false), Attachment::Pipe);
    assert_eq!(resolve(false, false, false), Attachment::Pipe);
}

/// ⛔ **`--jsonl` forces non-interactive even on a terminal.** It is the
/// answer on stdout, and an answer with prompts mixed in is not parseable.
#[test]
fn jsonl_forces_non_interactive_even_on_a_terminal() {
    assert_eq!(resolve(true, true, true), Attachment::Forced);
    assert_eq!(resolve(false, false, true), Attachment::Forced);
}

/// ⛔ **The override in the dangerous direction is refused.** A flag
/// promising interaction podssh cannot deliver is a flag that hangs, so
/// the refusal names the fd that is not a TTY.
#[test]
fn forced_interactive_is_refused_unless_both_fds_are_ttys() {
    assert_eq!(
        force_interactive(true, true),
        Ok(Attachment::ForcedInteractive)
    );
    for (stdin, stdout) in [(true, false), (false, true), (false, false)] {
        let refusal = force_interactive(stdin, stdout).unwrap_err();
        assert_eq!(refusal.fault, Fault::Usage);
        assert!(
            refusal.message.contains("--interactive"),
            "must name the flag: {}",
            refusal.message
        );
    }
}

/// The whole-string forms, and what each means.
#[test]
fn parse_timeout_accepts_bare_seconds_and_suffixed_forms() {
    assert_eq!(parse_timeout("30").unwrap(), Duration::from_secs(30));
    assert_eq!(parse_timeout("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(parse_timeout("2m").unwrap(), Duration::from_secs(120));
    assert_eq!(parse_timeout("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_timeout("500ms").unwrap(), Duration::from_millis(500));
    assert_eq!(parse_timeout("007").unwrap(), Duration::from_secs(7));
}

/// ⛔ **Plant 4, as a test.** The sibling parses with `atoi`, so
/// `30x` is 0 and 0 means unbounded — the guard it was meant to set,
/// silently removed. Every one of these must be a usage error naming
/// `--timeout`, immediately, never a hang and never a zero.
#[test]
fn parse_timeout_rejects_trailing_garbage_and_empty_and_signs() {
    for raw in ["30x", "10sec", "s", "", "1.5s", "-5", "+30", "30 s", " 30", "ms"] {
        let refusal = parse_timeout(raw).unwrap_err();
        assert_eq!(refusal.fault, Fault::Usage, "{raw:?}");
        assert!(
            refusal.message.contains("--timeout"),
            "{raw:?} must name the flag: {}",
            refusal.message
        );
    }
}

/// `0` is not "no bound" and overflow is not a duration.
#[test]
fn parse_timeout_rejects_zero_and_overflow() {
    for raw in ["0", "0s", "0ms"] {
        let refusal = parse_timeout(raw).unwrap_err();
        assert_eq!(refusal.fault, Fault::Usage, "{raw:?}");
    }
    let refusal = parse_timeout("18446744073709551615h").unwrap_err();
    assert_eq!(refusal.fault, Fault::Usage);
    let refusal = parse_timeout("99999999999999999999999").unwrap_err();
    assert_eq!(refusal.fault, Fault::Usage);
}

/// ⛔ **A missing `--timeout` in a pipe is a USAGE error, not a hang.**
/// E33 Prove check 6: exit 64 naming `--timeout`.
#[test]
fn missing_timeout_outside_a_terminal_is_usage_64() {
    for attachment in [
        Attachment::Pipe,
        Attachment::Forced,
        Attachment::ForcedInteractive,
    ] {
        let refusal = require_timeout(attachment, None).unwrap_err();
        assert_eq!(refusal.fault, Fault::Usage, "{attachment:?}");
        assert_eq!(refusal.fault.code(), 64, "{attachment:?}");
        assert!(
            refusal.message.contains("--timeout"),
            "{attachment:?} must name the flag: {}",
            refusal.message
        );
    }
}

/// A terminal with no `--timeout` is unbounded — a human can interrupt.
#[test]
fn terminal_without_timeout_is_unbounded() {
    assert_eq!(require_timeout(Attachment::Terminal, None).unwrap(), None);
}

/// A provided value is parsed everywhere, even on a terminal.
#[test]
fn a_provided_timeout_is_always_parsed() {
    assert_eq!(
        require_timeout(Attachment::Pipe, Some("30s")).unwrap(),
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        require_timeout(Attachment::Terminal, Some("2m")).unwrap(),
        Some(Duration::from_secs(120))
    );
    let refusal = require_timeout(Attachment::Terminal, Some("30x")).unwrap_err();
    assert_eq!(refusal.fault, Fault::Usage);
}

/// ⛔ **Plants 1 and 3: the implicit detection is the whole entry.** If
/// `resolve` hardcoded `Terminal`, or the TOFU path prompted
/// unconditionally, a piped run would hang waiting on nobody. Every site
/// refuses outside a terminal, and every refusal names its remedy.
#[test]
fn every_prompt_site_refuses_outside_a_terminal_and_names_its_remedy() {
    let sites: Vec<(PromptSite, &str)> = vec![
        (
            PromptSite::UnknownHostKey { fingerprint: "SHA256:abc".into() },
            "--accept-new",
        ),
        (
            PromptSite::ChangedHostKey { fingerprint: "SHA256:abc".into() },
            "SHA256:abc",
        ),
        (PromptSite::TokenAbsent, "token"),
        (PromptSite::NoRelay, "--relay"),
        (PromptSite::Passphrase, "passphrase"),
        (
            PromptSite::KnownHostsUnreadable { path: "/nonexistent".into() },
            "/nonexistent",
        ),
        (PromptSite::ChannelKey { channel: "#chan".into() }, "#chan"),
        (PromptSite::NickInUse { nick: "podssh".into() }, "podssh"),
        (
            PromptSite::SendfileUnreadable { path: "./messages.txt".into(), errno: "ENOENT".into() },
            "./messages.txt",
        ),
    ];
    for attachment in [Attachment::Pipe, Attachment::Forced] {
        for (site, remedy) in &sites {
            let refusal = gate_prompt(attachment, site).unwrap_err();
            assert!(
                refusal.message.contains(remedy),
                "{attachment:?} {site:?} must name {remedy}: {}",
                refusal.message
            );
            assert_ne!(refusal.fault.code(), 0, "{site:?} must never exit 0");
        }
    }
}

/// ⛔ **Row 2 refuses always — never even on a TTY.** E13 never
/// auto-replaces; a prompt offers the operator an accident.
#[test]
fn a_changed_host_key_refuses_even_on_a_terminal() {
    let site = PromptSite::ChangedHostKey { fingerprint: "SHA256:abc".into() };
    let refusal = gate_prompt(Attachment::Terminal, &site).unwrap_err();
    assert!(refusal.message.contains("SHA256:abc"), "{}", refusal.message);
}

/// The other sites allow a terminal: a human is present to answer.
#[test]
fn other_sites_allow_a_terminal() {
    for site in [
        PromptSite::UnknownHostKey { fingerprint: "SHA256:abc".into() },
        PromptSite::TokenAbsent,
        PromptSite::NoRelay,
        PromptSite::Passphrase,
        PromptSite::NickInUse { nick: "podssh".into() },
    ] {
        assert!(gate_prompt(Attachment::Terminal, &site).is_ok(), "{site:?}");
    }
}

/// ⛔ **`--jsonl` in ProxyCommand is refused, never redirected.** Stdout is
/// the SSH stream; a JSON line lands mid-version-string.
#[test]
fn jsonl_is_refused_in_proxy_mode() {
    let refusal = refuse_jsonl_in_proxy();
    assert_eq!(refusal.fault, Fault::Usage);
    assert_eq!(refusal.fault.code(), 64);
    assert!(refusal.message.contains("--jsonl"), "{}", refusal.message);
}

/// A refusal is one diagnostic block naming the site and the remedy —
/// never a bare "refused", never a secret.
#[test]
fn a_refusal_names_the_site_and_the_remedy() {
    let refusal = gate_prompt(
        Attachment::Pipe,
        &PromptSite::UnknownHostKey { fingerprint: "SHA256:abc".into() },
    )
    .unwrap_err();
    assert!(refusal.message.contains("podssh"), "{}", refusal.message);
    assert!(refusal.message.contains("SHA256:abc"), "{}", refusal.message);
    assert!(refusal.message.contains("--accept-new"), "{}", refusal.message);
}

// ⛔ ─────────── the binary half: pipes, exit codes, both streams ───────────
//
// ⛔ Plant 6's lesson (`tests/binary_streams.rs:1-28`): a unit test calls
// `dispatch::run` with in-memory streams, and a defect on the real file
// descriptors walks straight past it. These run the actual executable with
// stdin nulled and stdout piped — deterministically a pipe, on any host.

use std::process::{Command, Stdio};

/// Run the real `podssh` with `args`, stdin from `/dev/null`, both streams
/// piped. Returns `(exit, stdout, stderr)`.
fn podssh(args: &[&str]) -> (i32, Vec<u8>, Vec<u8>) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(args)
        // No test may reach the network: a verb that would connect stops here.
        .env("PODSSH_OFFLINE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the podssh binary must be runnable by an integration test");
    (out.status.code().unwrap_or(-1), out.stdout, out.stderr)
}

/// ⛔ **E33 Prove check 6, against the process.** A missing `--timeout` in a
/// pipe is exit 64 naming the flag — never a hang. Wrapped in `timeout 10`
/// by the entry; here the assertion itself is the bound, because a hang
/// fails the suite instead of passing it.
#[test]
fn missing_timeout_in_a_pipe_is_64_naming_the_flag() {
    let (rc, out, err) = podssh(&["chat", "--send", "#chan hi"]);
    assert_eq!(rc, 64);
    assert!(out.is_empty(), "a refusal writes nothing to stdout");
    let err = String::from_utf8(err).unwrap();
    assert!(err.contains("--timeout"), "{err}");
}

/// `30x` is rejected by the binary before anything is attempted.
#[test]
fn garbage_timeout_is_64_immediately() {
    let (rc, _, err) = podssh(&["chat", "--send", "#chan hi", "--timeout", "30x"]);
    assert_eq!(rc, 64);
    assert!(String::from_utf8(err).unwrap().contains("--timeout"));
}

/// A valid `--timeout` passes the gate. `chat` itself is still E33's to
/// build, so the run lands on the unimplemented refusal (70) — ⛔ **not** on
/// 64, and never on 0, and never a hang.
#[test]
fn valid_timeout_passes_the_gate_and_reaches_the_unbuilt_verb() {
    let (rc, out, err) =
        podssh(&["chat", "--send", "#chan hi", "--timeout", "30s"]);
    assert_eq!(rc, 70, "chat parses but is not implemented yet");
    assert!(out.is_empty());
    assert!(String::from_utf8(err).unwrap().contains("not implemented yet"));
}

/// ⛔ **`--jsonl` under `proxy` names the SSH stream.** Not the generic
/// unknown-flag text: the message must say why JSON cannot go there.
#[test]
fn proxy_jsonl_names_the_ssh_stream() {
    let (rc, out, err) = podssh(&["proxy", "--jsonl", "host", "22"]);
    assert_eq!(rc, 64);
    assert!(out.is_empty());
    let err = String::from_utf8(err).unwrap();
    assert!(err.contains("--jsonl"), "{err}");
    assert!(err.contains("SSH"), "{err}");
}
