//! `Match` in `ssh_config` (T-045), against what OpenSSH 10.3p1's `ssh -G`
//! printed for the same files and words (measured 2026-10-11, offline, the
//! local user written here as the test's, `envuser`). Each block adds an
//! `IdentityFile /m/NAME`, so that the lines show which blocks applied, in
//! their order: `+NAME` below. Nothing connects.

use std::path::PathBuf;

use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::dump;
use podssh_cli::ssh::resolve::{resolve_or_refuse, Env};
use podssh_cli::tree::{parse, Parsed};

fn ssh(words: &[&str]) -> SshArgs {
    let argv: Vec<std::ffi::OsString> = std::iter::once("ssh").chain(words.iter().copied()).map(Into::into).collect();
    match parse(argv) {
        Parsed::Command { verb: "ssh", ssh: Some(args), refused, .. } => {
            assert!(refused.is_empty(), "{words:?} was refused: {refused:?}");
            *args
        }
        other => panic!("{words:?} did not parse as ssh: {other:?}"),
    }
}

/// A scratch HOME of this test run, removed when dropped.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("podssh-match-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        podssh_relay::cache::private_dir(&dir).expect("a scratch home");
        Home(dir)
    }

    fn env(&self) -> Env {
        Env { home: Some(self.0.clone()), user: Some("envuser".into()), ..Default::default() }
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("a config file");
        path.display().to_string()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The lines of `-G` that show what applied, as the measurement kept them:
/// `+NAME` for `identityfile /m/NAME`, and no `port 22` or `sessiontype
/// default`.
fn shown(h: &Home, config: &str, words: &[&str]) -> Result<String, String> {
    let f = h.file("config", config);
    let mut all = vec!["-G", "-F", f.as_str()];
    all.extend_from_slice(words);
    let resolved = resolve_or_refuse(&ssh(&all), &h.env()).map_err(|e| e.message)?;
    const KEPT: [&str; 10] = [
        "user ",
        "hostname ",
        "port ",
        "sessiontype ",
        "remotecommand ",
        "tag ",
        "dynamicforward ",
        "localforward ",
        "remoteforward ",
        "sendenv ",
    ];
    let lines: Vec<String> = dump::lines(&resolved)
        .into_iter()
        .filter(|l| l != "port 22" && l != "sessiontype default")
        .filter_map(|l| match l.strip_prefix("identityfile /m/") {
            Some(name) => Some(format!("+{name}")),
            None => (KEPT.iter().any(|k| l.starts_with(k)) || l.starts_with("setenv ")).then_some(l),
        })
        .collect();
    Ok(lines.join(";"))
}

const BASICS: &str = "Match host h
  IdentityFile /m/host_h
Match host H
  IdentityFile /m/host_H
Match originalhost H
  IdentityFile /m/orig_H
Match host x,h
  IdentityFile /m/list
Match host *,!h
  IdentityFile /m/neglist
Match !host h
  IdentityFile /m/not_h
Match !host x
  IdentityFile /m/not_x
Match Host h
  IdentityFile /m/Host_kw
Match host h # a comment
  IdentityFile /m/comment
Match host \"h\"
  IdentityFile /m/quoted
Match host=h
  IdentityFile /m/eq
Match=host h
  IdentityFile /m/eq2
Match host h,
  IdentityFile /m/trailing_comma
Match host h host x
  IdentityFile /m/twice
";

const HOSTNAME: &str = "Match host real.example
  IdentityFile /m/before
Host h
  HostName real.example
Match host h
  IdentityFile /m/host_h
Match host real.example
  IdentityFile /m/host_real
Match originalhost h
  IdentityFile /m/orig_h
Match host REAL.example
  IdentityFile /m/host_REAL
";

const USERS: &str = "Match user alice
  IdentityFile /m/user_alice
Match user envuser
  IdentityFile /m/user_me
Match localuser envuser
  IdentityFile /m/localuser_me
Host h
  User alice
Match user alice
  IdentityFile /m/user_alice_after
Match user bob
  IdentityFile /m/user_bob
";

const TAGGED: &str = "Match tagged t1
  IdentityFile /m/tagged_t1
Match tagged \"\"
  IdentityFile /m/tagged_empty
Host h
  Tag t1
Match tagged t1
  IdentityFile /m/tagged_t1_after
Match !tagged t1
  IdentityFile /m/not_tagged_t1
";

const SESSIONS: &str = "Match sessiontype shell
  IdentityFile /m/st_shell
Match sessiontype exec
  IdentityFile /m/st_exec
Match sessiontype subsystem
  IdentityFile /m/st_subsystem
Match sessiontype none
  IdentityFile /m/st_none
Match sessiontype default
  IdentityFile /m/st_default
Match command \"ls*\"
  IdentityFile /m/cmd_ls
Match command \"ls -l\"
  IdentityFile /m/cmd_ls_l
Match command \"\"
  IdentityFile /m/cmd_empty
Match version OpenSSH_10*
  IdentityFile /m/version
Match version 10.3p1
  IdentityFile /m/version_num
";

/// Each case: its name, the file, the words of `ssh -G`, and what OpenSSH
/// 10.3p1 printed.
#[rustfmt::skip]
const CASES: &[(&str, &str, &[&str], &str)] = &[
    ("basics", BASICS, &["h"],
        "user envuser;hostname h;+host_h;+host_H;+orig_H;+list;+not_x;+Host_kw;+comment;+quoted;+eq;+eq2;+trailing_comma"),
    ("basics_upper", BASICS, &["H"],
        "user envuser;hostname h;+host_h;+host_H;+orig_H;+list;+not_x;+Host_kw;+comment;+quoted;+eq;+eq2;+trailing_comma"),
    ("hostname", HOSTNAME, &["h"], "user envuser;hostname real.example;+host_real;+orig_h;+host_REAL"),
    ("hostname_token", "Host h\n  HostName %h.example\nMatch host h.example\n  IdentityFile /m/host_hexample\n", &["h"],
        "user envuser;hostname h.example;+host_hexample"),
    ("hostname_set_in_match",
        "Match originalhost h\n  HostName real.example\nMatch originalhost real.example\n  IdentityFile /m/orig_after\n\
         Match host real.example\n  Port 2222\n", &["h"],
        "user envuser;hostname real.example;port 2222"),
    ("users", USERS, &["h"], "user alice;hostname h;+user_me;+localuser_me;+user_alice_after"),
    ("users_l", USERS, &["-l", "bob", "h"], "user bob;hostname h;+localuser_me;+user_bob"),
    ("users_at", USERS, &["bob@h"], "user bob;hostname h;+localuser_me;+user_bob"),
    ("users_and", "Match host h user alice\n  IdentityFile /m/and_yes\nMatch host h user bob\n  IdentityFile /m/and_no\n",
        &["-l", "alice", "h"], "user alice;hostname h;+and_yes"),
    ("tagged", TAGGED, &["h"], "user envuser;hostname h;tag t1;+tagged_empty;+tagged_t1_after"),
    ("tagged_p", TAGGED, &["-P", "t1", "h"], "user envuser;hostname h;tag t1;+tagged_t1;+tagged_t1_after"),
    ("tagged_p2", TAGGED, &["-P", "t2", "h"], "user envuser;hostname h;tag t2;+not_tagged_t1"),
    ("all", "Match all\n  IdentityFile /m/all\nMatch host h all\n  IdentityFile /m/host_all\nMatch !all\n  IdentityFile /m/not_all\n",
        &["h"], "user envuser;hostname h;+all;+host_all"),
    ("shell", SESSIONS, &["h"], "user envuser;hostname h;+st_shell;+cmd_empty;+version"),
    ("exec", SESSIONS, &["h", "ls", "-l"], "user envuser;hostname h;+st_exec;+cmd_ls;+cmd_ls_l;+version"),
    ("none", SESSIONS, &["-N", "h"], "user envuser;hostname h;sessiontype none;+st_none;+cmd_empty;+version"),
    ("subsystem", SESSIONS, &["-s", "h", "sftp"], "user envuser;hostname h;sessiontype subsystem;+st_subsystem;+version"),
    ("session_keyword", "Host h\n  SessionType none\nMatch sessiontype none\n  IdentityFile /m/st_none\n", &["h"],
        "user envuser;hostname h;sessiontype none;+st_none"),
    ("remote_command",
        "Host h\n  RemoteCommand uptime\nMatch sessiontype exec\n  IdentityFile /m/st_exec\n\
         Match sessiontype shell\n  IdentityFile /m/st_shell\nMatch command uptime\n  IdentityFile /m/cmd_uptime\n",
        &["h"], "user envuser;hostname h;remotecommand uptime;+st_shell"),
    // The final pass: every block read again, with the host after HostName.
    ("final_canonical",
        "Match canonical\n  IdentityFile /m/canonical\nMatch final\n  IdentityFile /m/final\nMatch !final\n  IdentityFile /m/not_final\n\
         Match !canonical\n  IdentityFile /m/not_canonical\nHost *\n  IdentityFile /m/star\n", &["h"],
        "user envuser;hostname h;+not_final;+not_canonical;+star;+canonical;+final"),
    ("canonical_alone", "Match canonical\n  IdentityFile /m/canonical\nMatch !final\n  IdentityFile /m/not_final\n", &["h"],
        "user envuser;hostname h;+not_final"),
    ("final_from_a_failing_line", "Match host nomatch final\n  IdentityFile /m/x1\nMatch canonical\n  IdentityFile /m/canon\n",
        &["h"], "user envuser;hostname h;+canon"),
    ("final_host",
        "Host h\n  HostName real.example\nMatch final host real.example\n  IdentityFile /m/final_host_real\n\
         Match final originalhost h\n  IdentityFile /m/final_orig_h\nHost real.example\n  IdentityFile /m/hostblock_real\n\
         Match final all\n  HostName final.example\n  Port 2399\n", &["h"],
        "user envuser;hostname real.example;port 2399;+final_host_real;+final_orig_h;+hostblock_real"),
    ("hostname_alone_is_no_final_pass", "Host h\n  HostName real.example\nHost real.example\n  Port 2300\n", &["h"],
        "user envuser;hostname real.example"),
    ("final_host_token", "Host h\n  HostName %h.example\nMatch final all\n  IdentityFile /m/f\nHost h.example\n  Port 2302\n",
        &["h"], "user envuser;hostname h.example;port 2302;+f"),
    ("final_hostname_late",
        "Match final all\n  HostName late.example\nHost late.example\n  Port 2301\nMatch final host late.example\n\
         IdentityFile /m/final_host_late\n", &["h"], "user envuser;hostname h"),
    ("final_lowercase", "Match final all\n  IdentityFile /m/f\nHost H\n  SendEnv HB\nHost h\n  SendEnv LB\n", &["H"],
        "user envuser;hostname h;+f;sendenv HB;sendenv LB"),
    ("final_user", "Match final all\n  User finaluser\n", &["h"], "user finaluser;hostname h"),
    ("final_user_l", "Match final all\n  User finaluser\n", &["-l", "cli", "h"], "user cli;hostname h"),
    ("final_match_user", "Host h\n  User fileuser\nMatch final user fileuser\n  IdentityFile /m/final_user_file\n", &["h"],
        "user fileuser;hostname h;+final_user_file"),
    // In the final pass, a key file, a forward and SetEnv are kept once, and
    // SendEnv is added again, as OpenSSH adds it.
    ("accumulate_final",
        "Host *\n  SendEnv FOO\n  SetEnv A=1\n  LocalForward 8080 db:80\n  RemoteForward 9090 web:80\n  DynamicForward 1080\n\
         IdentityFile /m/star\nMatch final all\n  IdentityFile /m/final\n", &["h"],
        "user envuser;hostname h;dynamicforward 1080;localforward 8080 [db]:80;remoteforward 9090 [web]:80;+star;+final;\
         sendenv FOO;sendenv FOO;setenv A=1"),
    ("setenv_first_line_whole", "Host *\n  SetEnv A=1\nHost h\n  SetEnv A=2 B=3\n", &["h"], "user envuser;hostname h;setenv A=1"),
];

#[test]
fn podssh_reads_match_as_openssh_10_3_reads_it() {
    let h = Home::new("cases");
    for (name, config, words, theirs) in CASES {
        let ours = shown(&h, config, words).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(ours, *theirs, "{name}");
    }
}

/// OpenSSH refused each of these lines; podssh refuses it with FILE:LINE
/// (78), before anything connects.
#[test]
fn a_bad_match_line_is_refused_with_file_and_line() {
    let h = Home::new("bad");
    for (config, says) in [
        ("Match all host h\n  Port 2222\n", ":1: Match all cannot be combined"),
        ("Match host\n  Port 2222\n", ":1: Match host needs patterns"),
        ("Port 2200\nMatch\n  Port 2222\n", ":2: Match needs a criterion"),
        ("Match host = h\n  Port 2222\n", ":1: Match h needs patterns"),
        ("Match bogus x\n  Port 2222\n", ":1: Match bogus: not a criterion"),
    ] {
        let f = h.file("bad", config);
        let err = resolve_or_refuse(&ssh(&["-F", &f, "h"]), &h.env()).unwrap_err();
        assert_eq!(err.code, 78, "{config:?}: {}", err.message);
        assert!(err.message.contains(&format!("{f}{says}")), "{config:?}: {}", err.message);
    }
}

/// `exec` and `localnetwork` are refused by name where they would decide,
/// and run nothing; where another criterion of the line fails, the block is
/// off whatever they would say, and the file is read.
#[test]
fn match_exec_runs_nothing_and_is_refused_where_it_decides() {
    let h = Home::new("exec");
    let ran = h.0.join("ran");
    let command = format!("Match exec \"echo x > {}\"\n  Port 2222\n", ran.display());
    for (config, says) in
        [(command.as_str(), "Match exec"), ("Match localnetwork 10.0.0.0/8\n  Port 2222\n", "Match localnetwork")]
    {
        let f = h.file("exec", config);
        let err = resolve_or_refuse(&ssh(&["-F", &f, "h"]), &h.env()).unwrap_err();
        assert_eq!(err.code, 78, "{}", err.message);
        assert!(err.message.contains(&format!("{f}:1: {says}")), "{}", err.message);
    }
    assert!(!ran.exists(), "the program of Match exec ran");
    let f = h.file("off", "Match host other exec \"exit 1\"\n  Port 2222\nHost h\n  Port 2223\n");
    let r = resolve_or_refuse(&ssh(&["-F", &f, "h"]), &h.env()).unwrap_or_else(|e| panic!("{}", e.message));
    assert_eq!(r.options.destination.port, 2223);
}

/// The sshping case (its PR #212): a `Match` block sets `HostName`, and a
/// later `Match host` sees the new name. Skipped, or matched against the
/// name as typed, the port would be 22.
#[test]
fn a_match_that_sets_host_name_changes_what_a_later_match_host_sees() {
    let h = Home::new("sshping");
    let f = h.file(
        "config",
        "Match originalhost alias\n  HostName server.example.org\nMatch host server.example.org\n  Port 2222\n  User deploy\n",
    );
    let r = resolve_or_refuse(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_or_else(|e| panic!("{}", e.message));
    assert_eq!(r.options.destination.host, "server.example.org");
    assert_eq!((r.options.destination.port, r.options.user.as_str()), (2222, "deploy"));
}
