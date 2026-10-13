//! Snippets (T-187): the values quoted as one word each (the plant of the
//! entry, the values with no quotes, fails here, and with sh on Unix), the
//! refusals of a template and of the table of the settings file (78), the
//! command line of a snippet (64), and the question: only yes runs it, and
//! with nobody to ask it is refused (64) after it is shown. Through the
//! binary, with no terminal: the refusal before anything connects, and a
//! run of `ssh` and of `each` with `--yes` against the test's SSH server on
//! the loopback; on Unix, the answers of an askpass program. Against
//! OpenSSH and Dropbear it runs in the gate (`scripts/interop-snippets.sh`).

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use podssh_cli::snippets::{choose, confirm, expand, pieces, quote, shown, Asker, Asking, Piece, Values};
use podssh_cli::ssh::args::SshArgs;
use podssh_ssh::prompt::PromptError;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-snippets-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The command of `command` with `words` and the values of a connection.
fn filled(command: &str, words: &[&str]) -> String {
    let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    let values = Values { host: "db.example.org", user: "ops", port: 2222, words: &words };
    expand(&pieces(command).unwrap(), &values)
}

#[test]
fn each_value_is_one_quoted_word() {
    // The check of the entry: with no quotes, the touch would run.
    assert_eq!(filled("printf %s {{1}}", &["a'b; touch /tmp/inj"]), r"printf %s 'a'\''b; touch /tmp/inj'");
    assert_eq!(filled("ls {{1}} {{2}}", &["plain-name_1.2", ""]), "ls plain-name_1.2 ''");
    for hostile in ["$(id)", "`id`", "a b", "~root", "=ls", "x;y", "a\nb", "*", "\\", "\"", "\u{e9}", "a|b"] {
        assert_eq!(quote(hostile), format!("'{hostile}'"), "{hostile:?}");
    }
    assert_eq!(filled("echo {{user}}@{{host}}:{{port}}", &[]), "echo ops@db.example.org:2222");
    assert_eq!(filled("tail -n {{ 1 }} x", &["5"]), "tail -n 5 x");
    // Text that is no placeholder stays as written; \{{ is {{.
    assert_eq!(filled(r"docker ps --format '{{.Names}}' \{{1}}", &[]), "docker ps --format '{{.Names}}' {{1}}");
}

/// What sh makes of the command: each value comes back as it was, and the
/// command in it never runs.
#[cfg(unix)]
#[test]
fn sh_reads_each_value_as_one_word() {
    let dir = scratch("sh");
    let mark = dir.join("inj");
    let at = mark.display();
    let values = [format!("a'b; touch {at}"), format!("$(touch {at})"), "`id`".into(), "two  words".into(), "".into()];
    for value in values {
        let command = filled("printf %s {{1}}", &[value.as_str()]);
        let out = Command::new("sh").arg("-c").arg(&command).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), value, "{command}");
        assert!(!mark.exists(), "{command} ran a command of its value");
    }
}

#[test]
fn a_bad_template_is_refused_with_its_reason() {
    for (command, says) in [
        ("echo {{nope}}", "{{nope}} is not a placeholder"),
        ("echo {{10}}", "{{10}} is not a placeholder"),
        ("echo '{{1}}'", "{{1}} is inside the command's own quotes"),
        ("echo \"x {{host}}\"", "{{host}} is inside the command's own quotes"),
        ("echo 'a", "a quote does not close"),
    ] {
        let why = pieces(command).unwrap_err();
        assert!(why.contains(says), "{command}: {why}");
    }
    // Quotes that close before a placeholder, and an escaped quote, hold none.
    assert!(pieces("echo 'a' {{1}} \"b\" \\' {{2}}").is_ok());
    assert_eq!(pieces("a{{1}}b").unwrap(), [Piece::Text("a".into()), Piece::Word(1), Piece::Text("b".into())]);
}

#[test]
fn the_table_of_the_settings_file_and_its_faults() {
    let d = podssh_cli::settings::parse(include_str!("fixtures/snippets.settings"), "f", None).unwrap();
    assert_eq!((d.snippets["code"].text.as_str(), d.snippets["code"].at.as_str()), ("exit {{1}}", "f:7"));
    assert_eq!(d.snippets["who"].text, r"printf '%s@%s:%s #%s\n' {{user}} {{host}} {{port}} {{1}}");
    assert_eq!(d.snippets["up"].text, "uptime");
    assert!(d.relay_failover.is_some());
    for (text, says) in [
        ("[snippets]\nx echo {{nope}}\n", "f:2: the snippet x: {{nope}} is not a placeholder"),
        ("[snippets]\nx echo '{{1}}'\n", "f:2: the snippet x: {{1}} is inside"),
        // The file reads `#b'` as a comment, and the quote is left open.
        ("[snippets]\nx echo 'a #b'\n", "f:2: the snippet x: a quote does not close"),
        ("[snippets]\nx a\nx b\n", "f:3: the snippet x is given at f:2 already"),
        ("[snippets]\nRelayHost a\n", "f:2: RelayHost is a setting"),
        ("[snippets]\n-x a\n", "f:2: -x is not the name of a snippet"),
        ("[snippets]\nx\n", "f:2: x needs a value"),
        ("[macros]\n", "f:1: [macros] is not a table"),
    ] {
        let why = podssh_cli::settings::parse(text, "f", None).unwrap_err();
        assert!(why.contains(says), "{text:?}: {why}");
    }
    // Both tables, in either order.
    let d = podssh_cli::settings::parse("[snippets]\nup uptime\n[groups]\nweb a,b\n", "f", None).unwrap();
    assert!(d.snippets.contains_key("up") && d.groups.contains_key("web"));
}

#[test]
fn the_command_line_of_a_snippet() {
    let d = podssh_cli::settings::parse("[snippets]\nlogs journalctl -u {{1}} -n {{2}}\nup uptime\n", "f", None);
    let snippets = d.unwrap().snippets;
    let args = |snippet: Option<&str>, words: &[&str]| SshArgs {
        destination: Some("web1".into()),
        snippet: snippet.map(str::to_string),
        command: words.iter().map(|w| w.to_string()).collect(),
        ..SshArgs::default()
    };
    let (line, chosen) = choose(&args(Some("logs"), &["nginx", "50"]), &snippets).unwrap().unwrap();
    assert_eq!(line.command, ["journalctl -u {{1}} -n {{2}}"]);
    assert_eq!((chosen.name.as_str(), chosen.words.clone()), ("logs", vec!["nginx".to_string(), "50".into()]));
    assert!(choose(&args(None, &["uptime"]), &snippets).unwrap().is_none());
    for (given, says) in [
        (args(Some("nope"), &[]), "no snippet of that name in the settings file, which has logs, up"),
        (args(Some("logs"), &["nginx"]), "takes 2 words"),
        (args(Some("up"), &["now"]), "a word that no placeholder takes"),
        (SshArgs { no_command: true, ..args(Some("up"), &[]) }, "-N asks for none or another"),
        (SshArgs { yes: true, ..args(None, &["uptime"]) }, "no --snippet is given"),
    ] {
        let refusal = choose(&given, &snippets).unwrap_err();
        assert_eq!(refusal.code, 64, "{given:?}");
        assert!(refusal.message.contains(says), "{}", refusal.message);
    }
}

/// A test's answers, in order, and the questions that it got.
struct Answers {
    here: bool,
    answers: Vec<Result<String, PromptError>>,
    asked: Vec<String>,
}

impl Asker for Answers {
    fn can_ask(&self) -> bool {
        self.here
    }

    fn ask(&mut self, question: &str) -> Result<String, PromptError> {
        self.asked.push(question.to_string());
        self.answers.remove(0)
    }
}

fn answers(here: bool, answers: Vec<Result<String, PromptError>>) -> Answers {
    Answers { here, answers, asked: Vec::new() }
}

#[test]
fn only_yes_runs_it_and_with_nobody_to_ask_it_is_shown_and_refused() {
    let text = shown("say", &[("web1".to_string(), "printf %s 'a b'".to_string())]);
    assert_eq!(text, "the snippet say runs this on web1:\n  printf %s 'a b'\n");
    for (answer, runs) in [("y", true), ("YES", true), (" yes ", true), ("", false), ("n", false), ("yess", false)] {
        let mut asker = answers(true, vec![Ok(answer.to_string())]);
        let mut err: Vec<u8> = Vec::new();
        let ran = confirm("ssh", &text, Asking::default(), &mut asker, &mut err);
        assert_eq!(ran.is_ok(), runs, "{answer:?}");
        assert!(asker.asked[0].contains("printf %s 'a b'") && asker.asked[0].ends_with("Run it? [y/N] "));
        assert!(err.is_empty(), "the question goes where the answer comes from");
    }
    // Ctrl-C, or an askpass program that failed: not run.
    let mut asker = answers(true, vec![Err(PromptError::Cancelled)]);
    let mut err: Vec<u8> = Vec::new();
    assert_eq!(confirm("ssh", &text, Asking::default(), &mut asker, &mut err).unwrap_err().code, 64);
    // Nobody to ask, or BatchMode with a terminal: shown, then refused.
    for (here, batch) in [(false, false), (true, true)] {
        let mut asker = answers(here, Vec::new());
        let mut err: Vec<u8> = Vec::new();
        let asking = Asking { batch, ..Asking::default() };
        let refusal = confirm("ssh", &text, asking, &mut asker, &mut err).unwrap_err();
        let err = String::from_utf8(err).unwrap();
        assert_eq!(refusal.code, 64);
        assert!(refusal.message.contains("give --yes to run it unasked"), "{}", refusal.message);
        assert!(err.contains("podssh ssh:   printf %s 'a b'"), "{err}");
        assert!(asker.asked.is_empty());
    }
    // --yes: shown and run with no question; with -q, not shown.
    for quiet in [false, true] {
        let mut asker = answers(true, Vec::new());
        let mut err: Vec<u8> = Vec::new();
        confirm("each", &text, Asking { yes: true, quiet, batch: false }, &mut asker, &mut err).unwrap();
        let err = String::from_utf8(err).unwrap();
        assert_eq!(err.contains("podssh each: the snippet say runs this on web1:"), !quiet, "{err}");
        assert!(asker.asked.is_empty());
    }
    // Many hosts: one command once, or each host's own.
    let same = [("a".to_string(), "up".to_string()), ("b".into(), "up".into())];
    assert_eq!(shown("x", &same), "the snippet x runs this on 2 hosts, a, b:\n  up\n");
    let own = [("a".to_string(), "echo a".to_string()), ("b".into(), "echo\tb".into())];
    assert_eq!(shown("x", &own), "the snippet x runs on 2 hosts:\n  a: echo a\n  b: echo\\tb\n");
}

/// The fixture's settings file, in a directory of the user's own.
fn settings(home: &Path) -> PathBuf {
    let dir = home.join("conf");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let file = dir.join("settings");
    std::fs::write(&file, include_str!("fixtures/snippets.settings")).unwrap();
    file
}

/// `podssh ARGS` with the settings file `settings`, no ssh_config and no
/// agent, with no terminal and no askpass program but `askpass` (its path,
/// and its answer): (exit code, stdout, stderr).
fn podssh(home: &Path, settings: &Path, args: &[String], offline: bool, askpass: Option<(&Path, &str)>) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .current_dir(home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", settings)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "PODSSH_OFFLINE"] {
        cmd.env_remove(name);
    }
    for name in ["SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY", "WAYLAND_DISPLAY"] {
        cmd.env_remove(name);
    }
    if offline {
        cmd.env("PODSSH_OFFLINE", "1");
    }
    if let Some((program, answer)) = askpass {
        cmd.env("SSH_ASKPASS", program).env("SSH_ASKPASS_REQUIRE", "force").env("PODSSH_TEST_ANSWER", answer);
        cmd.env("PODSSH_TEST_ASKED", home.join("asked"));
    }
    detach(&mut cmd);
    let out = cmd.output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

type Run = (i32, String, String);

/// A new session has no controlling terminal, so `/dev/tty` cannot open.
#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setsid is async-signal-safe and touches no memory.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
}

/// A detached process has no console, so `CONIN$` cannot open.
#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    cmd.creation_flags(DETACHED_PROCESS);
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| w.to_string()).collect()
}

#[test]
fn the_refusals_come_before_anything_connects() {
    let home = scratch("refused");
    let settings = settings(&home);
    let dir = home.join("out").display().to_string();
    for (args, says) in [
        (&["ssh", "--snippet", "nope", "u@web1"][..], "which has code, logs, up, who"),
        (&["ssh", "--snippet", "logs", "u@web1"][..], "takes one word, {{1}}, after the host, and 0 came"),
        (&["ssh", "--snippet", "up", "u@web1", "now"][..], "a word that no placeholder takes"),
        (&["ssh", "--snippet", "up", "--snippet", "up", "u@web1"][..], "give one snippet"),
        (&["ssh", "--yes", "u@web1", "uptime"][..], "no --snippet is given"),
        (&["ssh", "-N", "--snippet", "up", "u@web1"][..], "-N asks for none or another"),
        // Nobody can answer: the command is shown, and nothing connects.
        (&["ssh", "--snippet", "code", "u@web1", "3"][..], "podssh ssh:   exit 3"),
        (&["each", "--snippet", "code", "--output-dir", dir.as_str(), "u@a,u@b", "3"][..], "podssh each:   exit 3"),
    ] {
        let (code, out, err) = podssh(&home, &settings, &words(args), true, None);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains(says) && out.is_empty(), "{args:?}: {err}");
    }
    assert!(!home.join("out").exists(), "a refusal made the files of --output-dir");
    // A bad table is the file's fault, also for a run that names no snippet.
    std::fs::write(&settings, "[snippets]\nx echo {{nope}}\n").unwrap();
    let (code, _, err) = podssh(&home, &settings, &words(&["ssh", "u@web1", "true"]), true, None);
    assert_eq!(code, 78, "{err}");
    assert!(err.contains(":2: the snippet x: {{nope}} is not a placeholder"), "{err}");
}

/// The test's server on a runtime of its own: its port, and the count of
/// the connections that it took.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16, Arc<AtomicUsize>) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (port, connections) = runtime.block_on(ssh_harness::start_counting(&key));
    (runtime, port, connections)
}

/// `VERB` and its flags on the loopback, then the rest.
fn direct(home: &Path, verb: &str, rest: &[&str]) -> Vec<String> {
    let known = home.join("known_hosts").display().to_string();
    let mut args = words(&[verb, "--direct", "-o", "StrictHostKeyChecking=accept-new", "-o"]);
    args.push(format!("UserKnownHostsFile={known}"));
    args.extend(words(rest));
    args
}

#[test]
fn yes_runs_the_command_with_its_value_after_it_is_shown() {
    let home = scratch("yes");
    let settings = settings(&home);
    let (_runtime, port, connections) = server(&home);
    let host = format!("a@127.0.0.1:{port}");
    // `exit 3` prints `out` and `err!`, and ends with 3 (the test's server).
    let args = direct(&home, "ssh", &["--yes", "--snippet", "code", &host, "3"]);
    let (code, out, err) = podssh(&home, &settings, &args, false, None);
    assert_eq!((code, out.as_str()), (3, "out\n"), "{err}");
    let said = format!("podssh ssh: the snippet code runs this on {host}:\npodssh ssh:   exit 3\n");
    assert!(err.contains(&said), "{err}");
    // No --yes and nobody to ask: shown, refused, and no connection.
    let before = connections.load(Ordering::SeqCst);
    let args = direct(&home, "ssh", &["--snippet", "code", &host, "3"]);
    let (code, _, err) = podssh(&home, &settings, &args, false, None);
    assert_eq!(code, 64, "{err}");
    assert_eq!(connections.load(Ordering::SeqCst), before, "a refused snippet connected");
    // each: one question for both hosts, one command shown once.
    let other = format!("b@127.0.0.1:{port}");
    let args = direct(&home, "each", &["--yes", "--snippet", "code", &format!("{host},{other}"), "3"]);
    let (code, out, err) = podssh(&home, &settings, &args, false, None);
    assert_eq!(code, 3, "{err}");
    let said = format!("podssh each: the snippet code runs this on 2 hosts, {host}, {other}:");
    assert!(err.contains(&said), "{err}");
    assert_eq!(err.matches("podssh each:   exit 3").count(), 1, "{err}");
    assert!(out.lines().any(|l| l == format!("{host}: out")), "{out}");
}

/// An askpass program that writes its question into PODSSH_TEST_ASKED and
/// answers PODSSH_TEST_ANSWER. A batch file cannot take the question's
/// lines on Windows (Rust refuses a line break in its arguments), so this
/// runs on Unix.
#[cfg(unix)]
#[test]
fn the_answer_of_askpass_decides() {
    use std::os::unix::fs::PermissionsExt;
    let home = scratch("askpass");
    let settings = settings(&home);
    let program = home.join("askpass");
    let script = "#!/bin/sh\nprintf '%s' \"$1\" >\"$PODSSH_TEST_ASKED\"\nprintf '%s\\n' \"$PODSSH_TEST_ANSWER\"\n";
    std::fs::write(&program, script).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_runtime, port, connections) = server(&home);
    let host = format!("a@127.0.0.1:{port}");
    let args = direct(&home, "ssh", &["--snippet", "code", &host, "3"]);
    let (code, _, err) = podssh(&home, &settings, &args, false, Some((program.as_path(), "y")));
    assert_eq!(code, 3, "{err}");
    let asked = std::fs::read_to_string(home.join("asked")).unwrap();
    assert!(asked.contains("exit 3\nRun it? [y/N]"), "{asked}");
    let before = connections.load(Ordering::SeqCst);
    let (code, _, err) = podssh(&home, &settings, &args, false, Some((program.as_path(), "n")));
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("not run: the answer was not yes"), "{err}");
    assert_eq!(connections.load(Ordering::SeqCst), before, "a declined snippet connected");
}
