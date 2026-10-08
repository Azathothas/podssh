//! ⛔ **The tree's parse contract, from outside.**
//!
//! Moved out of `src/tree.rs` when the E33 wiring (carried `--timeout` and
//! `--jsonl`, the proxy pre-check) would have pushed that file over the
//! 500-line gate. Same assertions, one level further from the code —
//! `parse` and `Parsed` are the whole of what these touch.

use podssh_cli::{parse, Parsed};

fn args(s: &[&str]) -> Vec<std::ffi::OsString> {
    s.iter().map(std::ffi::OsString::from).collect()
}

#[test]
fn no_arguments_never_becomes_an_implicit_ssh() {
    assert!(matches!(parse(args(&[])), Parsed::NoArguments(_)));
}

#[test]
fn a_host_is_a_refusal_and_names_ssh() {
    let p = parse(args(&["example.org"]));
    let Parsed::UnknownVerb(m) = &p else { panic!("{p:?}") };
    assert!(m.contains("Try: podssh ssh example.org"), "{m}");
    // ⛔ **Not `!m.contains("doctor")` — and the reason matters.** The
    // refusal prints the subcommand list, and `doctor` is on it. ⛔ What
    // must not happen is `doctor` being *suggested*, so the assertion is
    // that the only `Try:` line names `ssh` and no other.
    let tries: Vec<&str> = m.lines().filter(|l| l.starts_with("Try:")).collect();
    assert_eq!(tries, vec!["Try: podssh ssh example.org"], "{m}");
    assert!(p.needs_refusal());
}

#[test]
fn a_typo_names_the_real_verb() {
    for (given, want) in [("sttaus", "status"), ("chatr", "chat")] {
        let Parsed::UnknownVerb(m) = parse(args(&[given])) else {
            panic!("{given} did not refuse");
        };
        assert!(m.contains(&format!("Try: podssh {want}")), "{given}: {m}");
    }
}

#[test]
fn an_alias_resolves_to_its_verb() {
    // ⛔ The entry's acceptance: `podssh irc --help` exits 0.
    assert_eq!(parse(args(&["irc", "--help"])), Parsed::Help("chat"));
    assert_eq!(parse(args(&["chat", "--help"])), Parsed::Help("chat"));
    assert_eq!(parse(args(&["scp", "--help"])), Parsed::Help("cp"));
    assert_eq!(parse(args(&["connect", "--help"])), Parsed::Help("ssh"));
}

#[test]
fn minus_p_is_a_tag_on_ssh_and_a_port_on_cp() {
    // ⛔ MEASURED, OpenSSH_10.3p1: ssh prints `[-P tag]`, scp `[-P port]`.
    let on_ssh = parse(args(&["ssh", "-P", "mytag", "host"]));
    let Parsed::Command { verb, refused, tag, .. } = &on_ssh else { panic!("{on_ssh:?}") };
    assert_eq!(*verb, "ssh");
    assert!(refused.is_empty(), "ssh must not refuse a real OpenSSH flag");
    assert_eq!(tag.as_deref(), Some("mytag"));

    let on_cp = parse(args(&["cp", "-P", "2222", "a", "b"]));
    let Parsed::Command { verb, refused, tag, .. } = &on_cp else { panic!("{on_cp:?}") };
    assert_eq!(*verb, "cp");
    assert!(refused.is_empty(), "cp must honour -P as the port");
    assert_eq!(tag, &None, "on cp, -P is the port and not a tag");
}

#[test]
fn a_refused_flag_names_its_replacement() {
    let p = parse(args(&["ssh", "-L", "8080:db:5432", "host"]));
    let Parsed::Command { refused, .. } = &p else { panic!("{p:?}") };
    assert_eq!(refused.len(), 1, "{p:?}");
    assert_eq!(refused[0].0, "-L SPEC");
    assert_eq!(refused[0].1, "-W HOST:PORT");
    assert!(p.needs_refusal());
}

#[test]
fn an_unknown_flag_is_never_silently_dropped() {
    // ⛔ **The spec's security bug, at `06-cli.md`:84-85: "A silently-dropped
    // `-o StrictHostKeyChecking=no` is a security bug that reports success."**
    // ⛔ Exit 0 on this input would be exactly that.
    let p = parse(args(&["ssh", "--StrictHostKeyChekcing=no", "host"]));
    assert!(p.needs_refusal(), "{p:?}");
    let Parsed::Usage(m) = &p else { panic!("{p:?}") };
    // ⛔ Names what was given…
    assert!(m.contains("StrictHostKeyChekcing"), "{m}");
    // ⛔ …and names the nearest real flag, which `strsim` found at
    // distance 2. This is the requirement at `06-cli.md`:84-85.
    assert!(m.contains("Did you mean"), "{m}");
    assert!(m.contains("StrictHostKeyChecking"), "must name the real flag: {m}");
    // ⛔ And no usage dump, which is the sibling's failure (`src/main.c:277`).
    assert!(!m.contains("Usage:"), "no usage header: {m}");
    assert!(!m.contains("For more information"), "no clap trailer: {m}");
    // ⛔ Four lines, not thirty.
    assert!(m.lines().count() <= 5, "{m}");
}

/// ⛔ **`-v` and `-q` are repeatable, in both spellings.**
///
/// ⛔ This is OpenSSH parity and not a preference: `06-cli.md`:65 lists
/// `-v`/`-q` as parity flags, the `-v` row's own help says *"repeatable"*,
/// and OpenSSH's manual says *"Multiple -q options increase the
/// quietness"*. ⛔ A second `-v` used to be refused as
/// `unknown flag '--verbose'` — a flag that is not unknown, only repeated —
/// because the `Count` arm was guarded on a `row.arg` neither of the two
/// rows has.
#[test]
fn verbose_and_quiet_are_repeatable_in_every_spelling() {
    for spelling in [
        vec!["-v", "-v", "-v"],
        vec!["-vvv"],
        vec!["-v", "-vv"],
        vec!["-vv"],
    ] {
        let mut argv = vec!["ssh"];
        argv.extend(spelling.iter().copied());
        argv.push("host");
        let p = parse(args(&argv));
        assert!(
            !p.is_error(),
            "{spelling:?} must parse: a repeated flag is not an unknown one: {p:?}"
        );
    }
    for spelling in [vec!["-q", "-q"], vec!["-qq"], vec!["-q", "-v", "-q"]] {
        let mut argv = vec!["ssh"];
        argv.extend(spelling.iter().copied());
        argv.push("host");
        let p = parse(args(&argv));
        assert!(!p.is_error(), "{spelling:?} must parse: {p:?}");
    }
    // ⛔ The control: one `-v` still parses, and it is not a refusal.
    let p = parse(args(&["ssh", "-v", "host"]));
    assert!(!p.needs_refusal(), "{p:?}");
}

#[test]
fn a_correct_command_line_parses_and_is_not_a_refusal() {
    let p = parse(args(&[
        "ssh", "-p", "2222", "-i", "~/.ssh/id_ed25519", "-4", "-T", "host", "--", "true",
    ]));
    let Parsed::Command { verb, refused, .. } = &p else { panic!("{p:?}") };
    assert_eq!(*verb, "ssh");
    assert!(refused.is_empty());
    assert!(!p.needs_refusal());
}

/// ⛔ **E33's carried values.** Verbs with `--timeout`/`--jsonl` rows hand
/// them to dispatch; verbs without the rows carry nothing, and the gate
/// enforces only where the tree could have supplied the flag.
#[test]
fn verbs_with_timeout_rows_carry_their_values() {
    let p = parse(args(&["chat", "--send", "#chan hi", "--timeout", "10s", "--jsonl"]));
    let Parsed::Command { timeout, jsonl, .. } = &p else { panic!("{p:?}") };
    assert_eq!(timeout.as_deref(), Some("10s"));
    assert!(*jsonl);

    let p = parse(args(&["chat", "--send", "#chan hi"]));
    let Parsed::Command { timeout, jsonl, .. } = &p else { panic!("{p:?}") };
    assert_eq!(timeout, &None);
    assert!(!jsonl);

    let p = parse(args(&["ssh", "host"]));
    let Parsed::Command { timeout, jsonl, .. } = &p else { panic!("{p:?}") };
    assert_eq!(timeout, &None, "ssh has no --timeout row to carry");
    assert!(!jsonl);
}

/// ⛔ **`--jsonl` under `proxy` is the specific refusal, not a generic
/// unknown-flag message.** Stdout there is the SSH byte stream; the message
/// must say so.
#[test]
fn proxy_jsonl_is_the_specific_refusal() {
    let p = parse(args(&["proxy", "--jsonl", "host", "22"]));
    let Parsed::Usage(m) = &p else { panic!("{p:?}") };
    assert!(m.contains("--jsonl"), "{m}");
    assert!(m.contains("SSH"), "{m}");
}

/// The three facts of `podssh man` survive the parse: the section, the pager
/// choice and the format. `man` must not arrive as a refusal.
#[test]
fn man_carries_its_section_its_pager_choice_and_its_format() {
    let bare = parse(args(&["man"]));
    assert_eq!(
        bare,
        Parsed::Man { section: None, no_pager: false, roff: false, json: false, refused: vec![] }
    );
    assert!(!bare.needs_refusal(), "man has behaviour and must not refuse");

    let paged_off = parse(args(&["man", "--no-pager"]));
    assert_eq!(
        paged_off,
        Parsed::Man { section: None, no_pager: true, roff: false, json: false, refused: vec![] }
    );

    let section = parse(args(&["man", "ssh"]));
    assert_eq!(
        section,
        Parsed::Man { section: Some("ssh".to_string()), no_pager: false, roff: false, json: false, refused: vec![] }
    );

    let roff = parse(args(&["man", "--roff", "proxy"]));
    assert_eq!(
        roff,
        Parsed::Man { section: Some("proxy".to_string()), no_pager: false, roff: true, json: false, refused: vec![] }
    );

    // `podssh man --help` is still help, not a page: the flag is checked
    // before the positional, as for every other verb.
    assert_eq!(parse(args(&["man", "--help"])), Parsed::Help("man"));
}

/// A known flag with no value names the flag in both spellings and the value
/// that it needs; a refused flag refuses as with a value (GitHub #8).
#[test]
fn a_missing_value_names_the_flag() {
    let cases: [(&[&str], &str); 8] = [
        (&["ssh", "--port"], "podssh ssh: -p (--port) needs a value: PORT."),
        (&["ssh", "-p"], "podssh ssh: -p (--port) needs a value: PORT."),
        (&["ssh", "host", "-p"], "podssh ssh: -p (--port) needs a value: PORT."),
        (&["ssh", "-o"], "podssh ssh: -o (--option) needs a value: NAME=VALUE."),
        (&["keygen", "-t", "ed25519", "-f"], "podssh keygen: -f (--file) needs a value: FILE."),
        (&["proxy", "--relay-host"], "podssh proxy: --relay-host needs a value: HOSTS."),
        (&["doctor", "--ca-file"], "podssh doctor: --ca-file needs a value: FILE."),
        // clap takes -x for a flag, so -l has no value: say so, and guess nothing.
        (&["ssh", "-l", "-x", "host"], "podssh ssh: -l (--login-name) needs a value: USER."),
    ];
    for (argv, want) in cases {
        let p = parse(args(argv));
        let Parsed::Usage(m) = &p else { panic!("{argv:?}: {p:?}") };
        assert!(m.starts_with(want), "{argv:?}: {m}");
        assert!(!m.contains("unknown flag"), "{argv:?}: {m}");
    }
    let Parsed::Usage(m) = parse(args(&["ssh", "-L"])) else { panic!("-L") };
    assert!(m.contains("-L SPEC is refused") && m.contains("Use -W HOST:PORT instead"), "{m}");
    // The control: a flag that does not exist is still an unknown flag.
    let Parsed::Usage(m) = parse(args(&["ssh", "--no-such-flag"])) else { panic!("control") };
    assert!(m.contains("unknown flag '--no-such-flag'"), "{m}");
}

/// `podssh --help` and `--version` answer or refuse each word after them;
/// `--help VERB` is the help of that verb (GitHub #10).
#[test]
fn the_top_level_help_drops_no_word() {
    assert_eq!(parse(args(&["--help"])), Parsed::Help(""));
    assert_eq!(parse(args(&["-h"])), Parsed::Help(""));
    assert_eq!(parse(args(&["--help", "ssh"])), Parsed::Help("ssh"));
    assert_eq!(parse(args(&["-h", "scp"])), Parsed::Help("cp"));
    assert_eq!(parse(args(&["--version"])), Parsed::Version);
    let refused: [&[&str]; 5] = [
        &["--help", "--json"],
        &["--help", "ssh", "extra"],
        &["--help", "--help"],
        &["--version", "--json"],
        &["-V", "example.org"],
    ];
    for argv in refused {
        let p = parse(args(argv));
        let Parsed::Usage(m) = &p else { panic!("{argv:?}: {p:?}") };
        let last = argv.last().unwrap();
        assert!(m.contains(&format!("takes no word '{last}'")), "{argv:?}: {m}");
    }
    let p = parse(args(&["--help", "sssh"]));
    let Parsed::UnknownVerb(m) = &p else { panic!("{p:?}") };
    assert!(m.contains("sssh"), "{m}");
}
