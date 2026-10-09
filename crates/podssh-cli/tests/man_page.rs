//! `podssh man`, run as a process: the bytes on stdout and stderr, the exit
//! codes, the environment, and a real man(7) renderer when the host has one.
//! The unit tests in `src/man/` prove the generator; only the binary proves
//! the pipes and the argument parsing in front of it.
//!
//! stdin and stdout are pipes in each test, never inherited: a test that
//! gave the child a terminal could not tell a pager that waits from one that
//! does not.

use std::process::{Command, Stdio};

/// Run the real podssh with `args`, stdin from nothing, and the environment
/// cleared and then set to `env`, or inherited when `env` is `None`.
fn podssh(args: &[&str], env: Option<&[(&str, &str)]>) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(vars) = env {
        cmd.env_clear();
        for (k, v) in vars {
            cmd.env(k, v);
        }
    }
    let out = cmd.output().expect("the podssh binary must run");
    let text = |b: Vec<u8>| String::from_utf8(b).expect("UTF-8");
    (out.status.code().unwrap_or(-1), text(out.stdout), text(out.stderr))
}

#[test]
fn no_pager_writes_the_whole_manual() {
    let (rc, out, err) = podssh(&["man", "--no-pager"], None);
    assert_eq!(rc, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    assert_eq!(out, podssh_cli::man::page(), "the binary's manual is not the library's");
    let first = out.lines().next().unwrap();
    assert!(first.starts_with("podssh "), "{first}");
    for heading in ["COMMAND REFERENCE", "ENVIRONMENT", "FILES", "THE RELAY", "EXIT STATUS", "EXAMPLES"] {
        assert!(out.lines().any(|l| l == heading), "no {heading}");
    }
}

/// With no terminal there is no pager: the whole manual, and the process
/// returns. A pager that waited for a key would hang here.
#[test]
fn with_no_terminal_the_whole_manual_is_written() {
    let (rc, out, err) = podssh(&["man"], None);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(out, podssh_cli::man::page());
    assert!(err.is_empty(), "{err}");
}

/// stdout carries the answer and nothing else, on each path of `man`.
#[test]
fn the_answer_is_the_only_thing_on_stdout() {
    for args in [
        vec!["man"],
        vec!["man", "ssh"],
        vec!["man", "--roff"],
        vec!["man", "environment"],
        vec!["man", "--roff", "exit"],
    ] {
        let (rc, out, err) = podssh(&args, None);
        assert_eq!(rc, 0, "{args:?}: {err}");
        assert!(err.is_empty(), "{args:?} wrote to stderr: {err}");
        assert!(!out.contains("-- more --"), "{args:?}: the pager's prompt reached stdout");
    }
}

/// The manual needs nothing from the host: with an empty environment it is
/// the same bytes.
#[test]
fn the_manual_needs_nothing_from_the_environment() {
    let (rc, out, err) = podssh(&["man", "--no-pager"], Some(&[]));
    assert_eq!(rc, 0, "{err}");
    assert_eq!(out, podssh_cli::man::page());
}

/// The manual shows no setting of this host: with a token, proxy
/// credentials and other settings in the environment, it is the same bytes,
/// and the values appear nowhere.
#[test]
fn the_manual_shows_no_setting_and_no_secret() {
    let token = "manual-test-token-0123456789";
    let password = "manual-test-password-4242";
    let proxy = format!("http://user:{password}@proxy.invalid:3128");
    let env: Vec<(&str, &str)> = vec![
        ("PODSSH_RELAY_TOKEN", token),
        ("HTTPS_PROXY", &proxy),
        ("PODSSH_RELAY", "relay-from-env.invalid"),
        ("HOME", "/home/manual-test-home"),
        ("USER", "manual-test-user"),
        ("PAGER", "manual-test-pager"),
    ];
    for args in [vec!["man", "--no-pager"], vec!["man", "--roff"]] {
        let (_, clean, _) = podssh(&args, Some(&[]));
        let (rc, set, err) = podssh(&args, Some(&env));
        assert_eq!(rc, 0, "{err}");
        assert_eq!(set, clean, "{args:?}: the environment changed the manual");
        for value in
            [token, password, "relay-from-env.invalid", "manual-test-home", "manual-test-user", "manual-test-pager"]
        {
            assert!(!set.contains(value), "{args:?}: the manual shows {value:?}");
        }
    }
}

#[test]
fn roff_writes_the_man_page() {
    let (rc, out, err) = podssh(&["man", "--roff"], None);
    assert_eq!(rc, 0, "{err}");
    assert!(out.starts_with(".TH PODSSH 1 "), "{}", &out[..out.len().min(60)]);
    assert_eq!(out, podssh_cli::man::roff_page());
}

/// An unknown section exits 64, writes nothing to stdout, and lists the
/// sections; a real section is the control.
#[test]
fn an_unknown_section_exits_64_and_lists_the_sections() {
    let (rc, out, err) = podssh(&["man", "nonsense"], None);
    assert_eq!(rc, 64, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("nonsense") && err.contains("environment") && err.contains("ssh"), "{err}");

    let (rc, out, _) = podssh(&["man", "keygen"], None);
    assert_eq!(rc, 0);
    assert!(out.starts_with("KEYGEN\n"), "{out}");
}

/// With no terminal, `PAGER` is not started: a pager that leaves a mark
/// leaves none, and the manual is whole.
#[cfg(unix)]
#[test]
fn with_no_terminal_no_pager_is_started() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("podssh-man-pager-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mark = dir.join("started");
    let pager = dir.join("pager.sh");
    std::fs::write(&pager, format!("#!/bin/sh\ntouch '{}'\ncat >/dev/null\n", mark.display())).unwrap();
    std::fs::set_permissions(&pager, std::fs::Permissions::from_mode(0o755)).unwrap();
    let pager_text = pager.display().to_string();
    let (rc, out, _) = podssh(&["man"], Some(&[("PAGER", pager_text.as_str()), ("TERM", "xterm")]));
    assert_eq!(rc, 0);
    assert_eq!(out, podssh_cli::man::page());
    assert!(!mark.exists(), "the pager was started with no terminal");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The roff page, rendered by groff or mandoc when the host has one: each
/// flag of each working command is in the rendered text. An `Fl` macro that
/// used `\$*` once printed these names blank under groff.
#[test]
fn a_real_renderer_shows_each_flag_name() {
    let renderers: [(&str, &[&str]); 2] =
        [("groff", &["-man", "-Tascii", "-rLL=300n"]), ("mandoc", &["-man", "-Tascii", "-Owidth=300"])];
    let mut ran = 0;
    for (program, args) in renderers {
        let Some(text) = render(program, args, &podssh_cli::man::roff_page()) else {
            eprintln!("{program}: not on this host; skipped");
            continue;
        };
        ran += 1;
        for verb in podssh_cli::flags::VERBS {
            if podssh_cli::flags::availability(verb) != podssh_cli::flags::Availability::Works {
                continue;
            }
            for row in verb.flags {
                let long = format!("--{}", row.long);
                assert!(text.contains(&long), "{program}: {} {long} is not in the rendered page", verb.name);
                if let Some(c) = row.short {
                    assert!(text.contains(&format!("-{c}, {long}")), "{program}: -{c} is not beside {long}");
                }
            }
        }
        assert!(text.contains("EXIT STATUS"), "{program}: no EXIT STATUS");
    }
    if ran == 0 {
        eprintln!("no man(7) renderer on this host: the rendering was not checked");
    }
}

/// `program args` with `input` on stdin, as plain text: overstrikes and
/// escape sequences removed. `None` when the program does not run.
fn render(program: &str, args: &[&str], input: &str) -> Option<String> {
    use std::io::Write;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(input.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        panic!("{program} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    let mut text = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // "X\bX" is bold and "_\bX" is underlined: keep the last character.
            '\u{8}' => {
                text.pop();
            }
            '\u{1b}' => {
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            '\u{2010}' | '\u{2212}' => text.push('-'),
            _ => text.push(c),
        }
    }
    Some(text)
}
